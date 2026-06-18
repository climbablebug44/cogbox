// `cogbox secret` verb. Binds operator-held credentials by NAME into the
// host-only secret store (see store.zig). Plugins REQUEST a secret by name +
// audience; the operator binds the actual value here. Values arrive only via
// --from-file or --from-stdin -- never on argv, which would leak into the
// process table / shell history.
//
//   cogbox secret add <name> --from-file F | --from-stdin
//                            [--audience HOST] [--kind bearer|cookie]
//   cogbox secret ls
//   cogbox secret rm <name>

const std = @import("std");
pub const store = @import("store.zig");

pub fn dispatch(
	allocator: std.mem.Allocator,
	io: std.Io,
	secrets_dir: []const u8,
	argv: []const []const u8,
) !void {
	if (argv.len == 0) {
		return die(allocator, io, "usage: cogbox secret <add|ls|rm> ...", .{}, 64);
	}
	const sub = argv[0];
	const rest = argv[1..];
	if (eql(sub, "add")) return cmdAdd(allocator, io, secrets_dir, rest);
	if (eql(sub, "ls") or eql(sub, "list")) return cmdList(allocator, io, secrets_dir, rest);
	if (eql(sub, "rm") or eql(sub, "del") or eql(sub, "delete")) return cmdRm(allocator, io, secrets_dir, rest);
	return die(allocator, io, "unknown subcommand '{s}' (expected add|ls|rm)", .{sub}, 64);
}

fn cmdAdd(allocator: std.mem.Allocator, io: std.Io, secrets_dir: []const u8, argv: []const []const u8) !void {
	var name: ?[]const u8 = null;
	var from_file: ?[]const u8 = null;
	var from_stdin = false;
	var audience: ?[]const u8 = null;
	var kind: []const u8 = "bearer";

	var i: usize = 0;
	while (i < argv.len) : (i += 1) {
		const a = argv[i];
		if (flagValue(a, "--from-file", argv, &i)) |v| {
			from_file = v;
		} else if (eql(a, "--from-stdin")) {
			from_stdin = true;
		} else if (flagValue(a, "--audience", argv, &i)) |v| {
			audience = v;
		} else if (flagValue(a, "--kind", argv, &i)) |v| {
			kind = v;
		} else if (std.mem.startsWith(u8, a, "-")) {
			return die(allocator, io, "unknown flag '{s}'", .{a}, 64);
		} else if (name == null) {
			name = a;
		} else {
			return die(allocator, io, "unexpected argument '{s}'", .{a}, 64);
		}
	}

	const nm = name orelse return die(allocator, io, "secret add requires a <name>", .{}, 64);
	if (!store.validName(nm)) {
		return die(allocator, io, "invalid secret name '{s}' (use [A-Za-z0-9_-], max 64)", .{nm}, 65);
	}
	if (!eql(kind, "bearer") and !eql(kind, "cookie")) {
		return die(allocator, io, "invalid --kind '{s}' (expected bearer|cookie)", .{kind}, 65);
	}
	if (from_file != null and from_stdin) {
		return die(allocator, io, "--from-file and --from-stdin are mutually exclusive", .{}, 64);
	}

	const raw = blk: {
		if (from_file) |f| break :blk readFileAll(allocator, io, f) catch {
			return die(allocator, io, "cannot read --from-file {s}", .{f}, 66);
		};
		if (from_stdin) break :blk try readStdinAll(allocator, io);
		return die(allocator, io, "secret add needs a value source: --from-file F or --from-stdin", .{}, 64);
	};
	defer allocator.free(raw);
	const value = trimTrailingNewline(raw);
	if (value.len == 0) {
		return die(allocator, io, "refusing to bind an empty secret value", .{}, 65);
	}

	const meta: store.Meta = .{
		.audience = audience,
		.kind = kind,
		.tier = "durable",
		.bound_at = null,
	};
	store.add(allocator, io, secrets_dir, nm, value, meta) catch |err| {
		return die(allocator, io, "failed to bind secret '{s}': {s}", .{ nm, @errorName(err) }, 73);
	};

	if (audience) |aud| {
		try announce(allocator, io, "Bound secret '{s}' (kind={s}, audience={s}).", .{ nm, kind, aud });
	} else {
		try announce(allocator, io, "Bound secret '{s}' (kind={s}). NOTE: no --audience set -> not injectable until you set one (cogbox secret add '{s}' --audience HOST ...).", .{ nm, kind, nm });
	}
}

fn cmdRm(allocator: std.mem.Allocator, io: std.Io, secrets_dir: []const u8, argv: []const []const u8) !void {
	if (argv.len != 1 or std.mem.startsWith(u8, argv[0], "-")) {
		return die(allocator, io, "usage: cogbox secret rm <name>", .{}, 64);
	}
	const nm = argv[0];
	if (!store.validName(nm)) return die(allocator, io, "invalid secret name '{s}'", .{nm}, 65);
	const existed = store.remove(allocator, io, secrets_dir, nm) catch |err| {
		return die(allocator, io, "failed to remove secret '{s}': {s}", .{ nm, @errorName(err) }, 73);
	};
	if (existed) {
		try announce(allocator, io, "Removed secret '{s}'.", .{nm});
	} else {
		try announce(allocator, io, "No secret named '{s}'.", .{nm});
	}
}

fn cmdList(allocator: std.mem.Allocator, io: std.Io, secrets_dir: []const u8, argv: []const []const u8) !void {
	_ = argv;
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);

	const cwd = std.Io.Dir.cwd();
	var dir = cwd.openDir(io, secrets_dir, .{ .iterate = true }) catch |err| switch (err) {
		error.FileNotFound => {
			try writeStdout(io, "No secrets bound.\n");
			return;
		},
		else => return err,
	};
	defer dir.close(io);

	var count: usize = 0;
	var iter = dir.iterate();
	while (try iter.next(io)) |entry| {
		if (entry.kind != .file) continue;
		// The value file is the secret; skip its .meta sidecar and any .tmp.
		if (std.mem.endsWith(u8, entry.name, ".meta")) continue;
		if (std.mem.endsWith(u8, entry.name, ".tmp")) continue;
		if (!store.validName(entry.name)) continue;

		const resolved = (try store.lookup(allocator, io, secrets_dir, entry.name)) orelse continue;
		count += 1;
		try out.appendSlice(allocator, entry.name);
		try out.appendSlice(allocator, "  kind=");
		try out.appendSlice(allocator, resolved.meta.kind);
		try out.appendSlice(allocator, " audience=");
		try out.appendSlice(allocator, resolved.meta.audience orelse "(unset, not injectable)");
		if (!resolved.bound) try out.appendSlice(allocator, " [MISSING VALUE]");
		try out.append(allocator, '\n');
	}

	if (count == 0) {
		try writeStdout(io, "No secrets bound.\n");
		return;
	}
	try writeStdout(io, out.items);
}

// --- small helpers ---------------------------------------------------------

fn eql(a: []const u8, b: []const u8) bool {
	return std.mem.eql(u8, a, b);
}

/// Match `--flag value` or `--flag=value`. Advances `*i` past the consumed
/// value form. Returns the value, or null if `arg` isn't this flag.
fn flagValue(arg: []const u8, comptime flag: []const u8, argv: []const []const u8, i: *usize) ?[]const u8 {
	if (eql(arg, flag)) {
		if (i.* + 1 < argv.len) {
			i.* += 1;
			return argv[i.*];
		}
		return null;
	}
	if (std.mem.startsWith(u8, arg, flag ++ "=")) {
		return arg[flag.len + 1 ..];
	}
	return null;
}

fn trimTrailingNewline(s: []const u8) []const u8 {
	var end = s.len;
	while (end > 0 and (s[end - 1] == '\n' or s[end - 1] == '\r')) end -= 1;
	return s[0..end];
}

fn readFileAll(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
	const cwd = std.Io.Dir.cwd();
	const f = try cwd.openFile(io, path, .{});
	defer f.close(io);
	var rbuf: [4096]u8 = undefined;
	var r = f.reader(io, &rbuf);
	return r.interface.allocRemaining(allocator, .limited(1 << 20));
}

fn readStdinAll(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
	const stdin = std.Io.File.stdin();
	var sbuf: [4096]u8 = undefined;
	var r = stdin.readerStreaming(io, &sbuf);
	return r.interface.allocRemaining(allocator, .limited(1 << 20));
}

fn writeStdout(io: std.Io, bytes: []const u8) !void {
	const stdout = std.Io.File.stdout();
	var buf: [4096]u8 = undefined;
	var w = stdout.writer(io, &buf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

fn writeStderr(io: std.Io, bytes: []const u8) !void {
	const stderr = std.Io.File.stderr();
	var buf: [4096]u8 = undefined;
	var w = stderr.writer(io, &buf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

fn announce(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype) !void {
	const msg = try std.fmt.allocPrint(allocator, fmt ++ "\n", args);
	defer allocator.free(msg);
	try writeStdout(io, msg);
}

fn die(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype, code: u8) noreturn {
	const msg = std.fmt.allocPrint(allocator, "cogbox secret: error: " ++ fmt ++ "\n", args) catch "cogbox secret: error: (message too long)\n";
	writeStderr(io, msg) catch {};
	std.process.exit(code);
}
