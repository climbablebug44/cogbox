// Shelling out to nix for the plugin verb. Everything network-touching or
// store-touching goes through here: resolving a flake URL to a locked rev
// (metadata), checking the module contract (eval), reading the optional
// cogboxPlugin.networkRules output (eval), and pre-fetching the plugin's
// transitive inputs for offline restarts (archive).
//
// Experimental features are passed explicitly (the launcher does the same at
// cogbox-launch.sh's re-exec) so the verb works regardless of user nix.conf.

const std = @import("std");

pub const RunOut = struct {
	stdout: []u8,
	stderr: []u8,
	ok: bool,

	pub fn deinit(self: *RunOut, allocator: std.mem.Allocator) void {
		allocator.free(self.stdout);
		allocator.free(self.stderr);
	}
};

pub fn runNix(allocator: std.mem.Allocator, io: std.Io, args: []const []const u8) !RunOut {
	var argv: std.ArrayList([]const u8) = .empty;
	defer argv.deinit(allocator);
	try argv.appendSlice(allocator, &.{ "nix", "--extra-experimental-features", "nix-command flakes" });
	try argv.appendSlice(allocator, args);

	const res = try std.process.run(allocator, io, .{ .argv = argv.items });
	const ok = res.term == .exited and res.term.exited == 0;
	return .{ .stdout = res.stdout, .stderr = res.stderr, .ok = ok };
}

pub fn flakeMetadata(allocator: std.mem.Allocator, io: std.Io, url: []const u8) !RunOut {
	return runNix(allocator, io, &.{ "flake", "metadata", "--json", url });
}

pub fn flakeArchive(allocator: std.mem.Allocator, io: std.Io, url: []const u8) !RunOut {
	return runNix(allocator, io, &.{ "flake", "archive", "--json", url });
}

/// `nix eval URL#nixosModules --apply 'm: m ? "<attr>"' --json` ->
/// "true"/"false". A failed eval (no nixosModules output at all) reads as
/// missing. `attr` must satisfy name.isValidAttr (it is interpolated into a
/// nix expression).
pub fn evalHasNixosModule(allocator: std.mem.Allocator, io: std.Io, url: []const u8, attr: []const u8) !bool {
	const installable = try std.fmt.allocPrint(allocator, "{s}#nixosModules", .{url});
	defer allocator.free(installable);
	const apply = try std.fmt.allocPrint(allocator, "m: m ? \"{s}\"", .{attr});
	defer allocator.free(apply);
	var out = try runNix(allocator, io, &.{ "eval", installable, "--apply", apply, "--json" });
	defer out.deinit(allocator);
	if (!out.ok) return false;
	return std.mem.eql(u8, std.mem.trim(u8, out.stdout, " \t\r\n"), "true");
}

/// `nix eval URL#cogboxPlugin."<attr>".<leaf> --json` (or the flat path
/// `cogboxPlugin.<leaf>` when `attr` is null). `leaf` is `networkRules`
/// (L4 CIDR rules) or `l7Rules` (vhost rules). IFD is blocked: reading the
/// rules must never trigger a build of untrusted code at add time. `attr`
/// must satisfy name.isValidAttr; `leaf` is always caller-controlled.
pub fn evalPluginRules(allocator: std.mem.Allocator, io: std.Io, url: []const u8, attr: ?[]const u8, leaf: []const u8) !RunOut {
	const installable = if (attr) |a|
		try std.fmt.allocPrint(allocator, "{s}#cogboxPlugin.\"{s}\".{s}", .{ url, a, leaf })
	else
		try std.fmt.allocPrint(allocator, "{s}#cogboxPlugin.{s}", .{ url, leaf });
	defer allocator.free(installable);
	return runNix(allocator, io, &.{ "eval", installable, "--json", "--no-allow-import-from-derivation" });
}

/// Whether a failed eval's stderr means "that attribute just isn't there"
/// (fine: the output is optional) as opposed to a real evaluation error.
pub fn stderrSaysMissingAttribute(stderr: []const u8) bool {
	return std.mem.indexOf(u8, stderr, "does not provide attribute") != null or
		std.mem.indexOf(u8, stderr, "has no attribute") != null or
		std.mem.indexOf(u8, stderr, "missing attribute") != null;
}

pub const Meta = struct {
	locked_url: []const u8,
	rev: ?[]const u8,
	nar_hash: []const u8,

	pub fn deinit(self: *Meta, allocator: std.mem.Allocator) void {
		allocator.free(self.locked_url);
		if (self.rev) |r| allocator.free(r);
		allocator.free(self.nar_hash);
	}
};

pub const MetaError = error{
	BadMetadata,
	OutOfMemory,
};

/// Parse `nix flake metadata --json` output. `.url` is nix's locked URL; if
/// it doesn't already carry a narHash query param (github:/git+ refs don't),
/// `.locked.narHash` is appended (percent-encoded) so the URL alone pins the
/// content and resolves from the local store offline.
pub fn parseMetadata(allocator: std.mem.Allocator, json_text: []const u8) MetaError!Meta {
	const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch {
		return error.BadMetadata;
	};
	defer parsed.deinit();

	const root = parsed.value;
	if (root != .object) return error.BadMetadata;
	const url_v = root.object.get("url") orelse return error.BadMetadata;
	if (url_v != .string) return error.BadMetadata;
	const locked_v = root.object.get("locked") orelse return error.BadMetadata;
	if (locked_v != .object) return error.BadMetadata;
	const nar_v = locked_v.object.get("narHash") orelse return error.BadMetadata;
	if (nar_v != .string) return error.BadMetadata;

	var rev: ?[]const u8 = null;
	errdefer if (rev) |r| allocator.free(r);
	if (locked_v.object.get("rev")) |rv| {
		if (rv == .string) rev = try allocator.dupe(u8, rv.string);
	}

	const nar_hash = try allocator.dupe(u8, nar_v.string);
	errdefer allocator.free(nar_hash);

	const locked_url = blk: {
		if (std.mem.indexOf(u8, url_v.string, "narHash=") != null) {
			break :blk try allocator.dupe(u8, url_v.string);
		}
		const sep: u8 = if (std.mem.indexOfScalar(u8, url_v.string, '?') != null) '&' else '?';
		var buf: std.ArrayList(u8) = .empty;
		defer buf.deinit(allocator);
		try buf.appendSlice(allocator, url_v.string);
		try buf.append(allocator, sep);
		try buf.appendSlice(allocator, "narHash=");
		try appendPercentEncoded(allocator, &buf, nar_v.string);
		break :blk try buf.toOwnedSlice(allocator);
	};

	return .{ .locked_url = locked_url, .rev = rev, .nar_hash = nar_hash };
}

/// Percent-encode a query param value (narHash carries `+`, `/`, `=`).
fn appendPercentEncoded(allocator: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
	for (s) |c| {
		const safe = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~';
		if (safe) {
			try out.append(allocator, c);
		} else {
			var hex: [3]u8 = undefined;
			_ = std.fmt.bufPrint(&hex, "%{X:0>2}", .{c}) catch unreachable;
			try out.appendSlice(allocator, &hex);
		}
	}
}

/// The trailing lines of nix's stderr, for error messages. Drops the
/// progress noise but keeps the actual failure.
pub fn stderrTail(stderr: []const u8) []const u8 {
	const trimmed = std.mem.trim(u8, stderr, " \t\r\n");
	const max = 600;
	if (trimmed.len <= max) return trimmed;
	const cut = trimmed[trimmed.len - max ..];
	// Start at the next line boundary so we don't emit half a line.
	if (std.mem.indexOfScalar(u8, cut, '\n')) |i| return cut[i + 1 ..];
	return cut;
}
