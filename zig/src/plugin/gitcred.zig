// Single-fetch git credential injection for `cogbox plugin add/update
// --git-credential-stdin`. cogworx hands the
// ACTING user's delegated OAuth token to cogbox over STDIN -- never in argv or
// any env var -- as ONE tab-separated line:
//
//     <host>\t<user>\t<token>\n
//
// We materialize that into a temp 0700 dir holding a 0600 netrc and a gitconfig
// that clears any inherited credential helper, then run the single nix fetch
// with a per-fetch environment pointing git/curl at those files (HOME = temp
// dir, GIT_CONFIG_GLOBAL/SYSTEM, GIT_TERMINAL_PROMPT=0). The dir is deleted
// right after the fetch. The token never lands in argv, in a persisted config,
// in the nix store, or in any log.

const std = @import("std");

pub const Error = error{
	EmptyCredential,
	MalformedCredential,
};

/// The parsed credential fields. They borrow from the stdin buffer the caller
/// owns; nothing here is duplicated.
pub const Cred = struct {
	host: []const u8,
	user: []const u8,
	token: []const u8,
};

/// Parse the single `host\tuser\ttoken` line. Trailing CR/LF is trimmed; the
/// fields themselves may not be empty and may not contain a tab (they never do:
/// host is a URL host, user a fixed convention, token an opaque bearer). Only
/// the first line is read -- anything after the first newline is ignored.
pub fn parseLine(raw: []const u8) Error!Cred {
	// Take the first line only.
	const nl = std.mem.indexOfScalar(u8, raw, '\n');
	const line0 = if (nl) |i| raw[0..i] else raw;
	const line = std.mem.trim(u8, line0, " \t\r");
	if (line.len == 0) return error.EmptyCredential;

	var it = std.mem.splitScalar(u8, line, '\t');
	const host = it.next() orelse return error.MalformedCredential;
	const user = it.next() orelse return error.MalformedCredential;
	const token = it.next() orelse return error.MalformedCredential;
	if (it.next() != null) return error.MalformedCredential; // exactly three fields
	if (host.len == 0 or user.len == 0 or token.len == 0) return error.MalformedCredential;
	return .{ .host = host, .user = user, .token = token };
}

/// Read the whole of stdin (bounded) so parseLine can pick the first line.
/// Returns an allocated buffer the caller frees.
pub fn readStdin(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
	const stdin = std.Io.File.stdin();
	var buf: [4096]u8 = undefined;
	var r = stdin.reader(io, &buf);
	// A token line is small; 64 KiB is a generous ceiling.
	return r.interface.allocRemaining(allocator, .limited(64 * 1024));
}

/// A materialized per-fetch credential: the temp dir + the replacement
/// environment for the single nix exec. Build with setup(); always call
/// deinit() (it removes the temp dir AND frees the env). The env clones the
/// parent so nix/git keep PATH etc., with only the credential-relevant keys
/// overridden.
pub const FetchEnv = struct {
	allocator: std.mem.Allocator,
	io: std.Io,
	dir: []u8, // absolute path of the temp dir (0700), owned
	env: std.process.Environ.Map, // replacement env for the fetch exec

	/// Materialize netrc + gitconfig from `cred`, under a fresh 0700 temp dir,
	/// and build the per-fetch env (a clone of `parent` with HOME / GIT_CONFIG_*
	/// / GIT_TERMINAL_PROMPT overridden). On any error the temp dir is removed.
	pub fn setup(
		allocator: std.mem.Allocator,
		io: std.Io,
		parent: *const std.process.Environ.Map,
		cred: Cred,
	) !FetchEnv {
		const dir = try makeTempDir(allocator, io, parent);
		errdefer {
			std.Io.Dir.cwd().deleteTree(io, dir) catch {};
			allocator.free(dir);
		}

		// netrc (0600): the basic-auth credential for exactly this host.
		const netrc_path = try std.fs.path.join(allocator, &.{ dir, ".netrc" });
		defer allocator.free(netrc_path);
		const netrc = try std.fmt.allocPrint(
			allocator,
			"machine {s}\n  login {s}\n  password {s}\n",
			.{ cred.host, cred.user, cred.token },
		);
		defer allocator.free(netrc);
		try writeFile0600(io, netrc_path, netrc);

		// gitconfig: clear any inherited credential helper so a host-level
		// credential store cannot inject another identity into this clone.
		const gitconfig_path = try std.fs.path.join(allocator, &.{ dir, "gitconfig" });
		defer allocator.free(gitconfig_path);
		try writeFile0600(io, gitconfig_path, "[credential]\n\thelper = \"\"\n");

		var env = try cloneEnv(allocator, parent);
		errdefer env.deinit();
		// HOME points git/curl at the temp ~/.netrc (the file we just wrote).
		try env.put("HOME", dir);
		try env.put("GIT_CONFIG_GLOBAL", gitconfig_path);
		try env.put("GIT_CONFIG_SYSTEM", "/dev/null"); // ignore system helper
		try env.put("GIT_TERMINAL_PROMPT", "0"); // never prompt; fail closed

		return .{ .allocator = allocator, .io = io, .dir = dir, .env = env };
	}

	/// The replacement env to hand nix for the fetch.
	pub fn map(self: *const FetchEnv) *const std.process.Environ.Map {
		return &self.env;
	}

	/// Remove the temp dir (netrc + gitconfig) and free the env. Idempotent
	/// enough for a defer; a missing dir is not an error.
	pub fn deinit(self: *FetchEnv) void {
		std.Io.Dir.cwd().deleteTree(self.io, self.dir) catch {};
		self.allocator.free(self.dir);
		self.env.deinit();
	}
};

/// Clone an Environ.Map: every key/value is copied (Map.put dupes internally).
fn cloneEnv(allocator: std.mem.Allocator, src: *const std.process.Environ.Map) !std.process.Environ.Map {
	var out = std.process.Environ.Map.init(allocator);
	errdefer out.deinit();
	const ks = src.keys();
	const vs = src.values();
	for (ks, vs) |k, v| try out.put(k, v);
	return out;
}

/// Create a fresh 0700 temp dir under $TMPDIR (or /tmp) and return its absolute
/// path (owned by the caller).
fn makeTempDir(allocator: std.mem.Allocator, io: std.Io, parent: *const std.process.Environ.Map) ![]u8 {
	const base = parent.get("TMPDIR") orelse "/tmp";
	var rnd: [12]u8 = undefined;
	io.random(&rnd);
	var hex: [24]u8 = undefined;
	_ = std.fmt.bufPrint(&hex, "{x}", .{&rnd}) catch unreachable;
	const dir = try std.fmt.allocPrint(allocator, "{s}/cogbox-gitcred-{s}", .{ base, hex });
	errdefer allocator.free(dir);
	// createDirPathOpen makes the path and lets us set 0700 on the leaf.
	var d = try std.Io.Dir.cwd().createDirPathOpen(io, dir, .{
		.permissions = std.Io.File.Permissions.fromMode(0o700),
	});
	d.close(io);
	return dir;
}

/// Write `bytes` to `path` with mode 0600 (creating/truncating).
fn writeFile0600(io: std.Io, path: []const u8, bytes: []const u8) !void {
	const cwd = std.Io.Dir.cwd();
	const f = try cwd.createFile(io, path, .{
		.truncate = true,
		.permissions = std.Io.File.Permissions.fromMode(0o600),
	});
	defer f.close(io);
	var wbuf: [4096]u8 = undefined;
	var w = f.writer(io, &wbuf);
	try w.interface.writeAll(bytes);
	try w.flush();
	try f.sync(io);
}

// --- Tests ---

const t = std.testing;

test "parseLine: well-formed line" {
	const c = try parseLine("git.example.com\toauth2\tsecret-token\n");
	try t.expectEqualStrings("git.example.com", c.host);
	try t.expectEqualStrings("oauth2", c.user);
	try t.expectEqualStrings("secret-token", c.token);
}

test "parseLine: trailing CRLF trimmed, only first line used" {
	const c = try parseLine("h\tu\ttok\r\nIGNORED-SECOND-LINE\n");
	try t.expectEqualStrings("h", c.host);
	try t.expectEqualStrings("u", c.user);
	try t.expectEqualStrings("tok", c.token);
}

test "parseLine: no trailing newline" {
	const c = try parseLine("h\tu\ttok");
	try t.expectEqualStrings("tok", c.token);
}

test "parseLine: empty / malformed" {
	try t.expectError(error.EmptyCredential, parseLine(""));
	try t.expectError(error.EmptyCredential, parseLine("\n"));
	try t.expectError(error.MalformedCredential, parseLine("only-host\n"));
	try t.expectError(error.MalformedCredential, parseLine("host\tuser\n")); // missing token
	try t.expectError(error.MalformedCredential, parseLine("h\tu\tt\textra\n"));
	try t.expectError(error.MalformedCredential, parseLine("h\t\ttok\n")); // empty user
}

// setup() materializes a 0600 netrc + clear-helper gitconfig under a fresh 0700
// temp dir, builds the per-fetch env (HOME=dir, GIT_CONFIG_*/GIT_TERMINAL_PROMPT
// overridden), and deinit() removes the temp dir. Offline-feasible end-to-end
// for the file/env shape (a real private clone needs staging -- see the report).
test "FetchEnv: netrc 0600 under temp HOME, env overrides, cleaned up" {
	const allocator = t.allocator;
	var threaded: std.Io.Threaded = .init(allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	// A self-made base dir (relative to cwd) standing in for $TMPDIR, so the
	// per-fetch temp dir lands inside the test sandbox.
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	const base = try std.fmt.allocPrint(allocator, "zig-gitcred-test-{s}", .{hexb});
	defer allocator.free(base);
	try cwd.createDirPath(io, base);
	defer cwd.deleteTree(io, base) catch {};

	// Parent env carries TMPDIR (-> base) and a PATH we expect to survive the clone.
	var parent = std.process.Environ.Map.init(allocator);
	defer parent.deinit();
	try parent.put("TMPDIR", base);
	try parent.put("PATH", "/run/current-system/sw/bin");

	const cred = try parseLine("git.example.com\toauth2\tsupersecret\n");
	var fe = try FetchEnv.setup(allocator, io, &parent, cred);

	// The env replaces HOME with the temp dir and sets the fetch knobs.
	try t.expectEqualStrings(fe.dir, fe.env.get("HOME").?);
	try t.expectEqualStrings("0", fe.env.get("GIT_TERMINAL_PROMPT").?);
	try t.expectEqualStrings("/dev/null", fe.env.get("GIT_CONFIG_SYSTEM").?);
	// The clone preserved an inherited key (PATH).
	try t.expectEqualStrings("/run/current-system/sw/bin", fe.env.get("PATH").?);
	// GIT_CONFIG_GLOBAL points inside the temp dir, and the temp dir is under base.
	try t.expect(std.mem.startsWith(u8, fe.env.get("GIT_CONFIG_GLOBAL").?, fe.dir));
	try t.expect(std.mem.startsWith(u8, fe.dir, base));

	// The netrc exists with mode 0600 and the right content.
	const netrc_path = try std.fs.path.join(allocator, &.{ fe.dir, ".netrc" });
	defer allocator.free(netrc_path);
	{
		const f = try cwd.openFile(io, netrc_path, .{});
		defer f.close(io);
		const md = try f.stat(io);
		try t.expectEqual(@as(u64, 0o600), md.permissions.toMode() & 0o777);
		var rbuf: [512]u8 = undefined;
		var r = f.reader(io, &rbuf);
		const content = try r.interface.allocRemaining(allocator, .limited(4096));
		defer allocator.free(content);
		try t.expect(std.mem.indexOf(u8, content, "machine git.example.com") != null);
		try t.expect(std.mem.indexOf(u8, content, "login oauth2") != null);
		try t.expect(std.mem.indexOf(u8, content, "password supersecret") != null);
	}

	// The temp dir must be at 0700 (not group/other readable).
	{
		var d = try cwd.openDir(io, fe.dir, .{});
		defer d.close(io);
		const dmd = try d.stat(io);
		try t.expectEqual(@as(u64, 0o700), dmd.permissions.toMode() & 0o777);
	}

	// Capture the dir path, then deinit -> the temp dir is gone.
	const dir_copy = try allocator.dupe(u8, fe.dir);
	defer allocator.free(dir_copy);
	fe.deinit();
	try t.expectError(error.FileNotFound, cwd.access(io, dir_copy, .{}));
}
