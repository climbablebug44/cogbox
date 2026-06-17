// `cogbox ssh` - connect to a running instance via SSH.
//
// Reads the live host:port from <runtime>/ssh-endpoint (written by the
// launch script when the VM comes up). Disables host-key checking
// because the guest's root disk is ephemeral and host keys regenerate
// on every boot.

const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	p: *const paths.Paths,
	argv: []const []const u8,
) !void {
	const flags = [_]parse.Flag{
		.{ .long = "name", .short = 'n', .kind = .value },
		.{ .long = "help", .short = 'h', .kind = .bool },
	};
	var parsed = parse.parse(allocator, io, .{
		.verb = "ssh",
		.flags = &flags,
		.allow_trailing = true,
		.terminate_on_positional = true,
	}, argv);
	defer parsed.deinit();

	if (parsed.isSet("help")) {
		try help.print(io, help.SSH);
		return;
	}

	const name = nameFlag(&parsed, allocator, io);

	const inst_runtime = try paths.instanceRuntime(allocator, p, name);
	defer allocator.free(inst_runtime);

	const pid_path = try std.fs.path.join(allocator, &.{ inst_runtime, "pid" });
	defer allocator.free(pid_path);
	if (!isRunning(allocator, io, pid_path)) {
		const eff = name orelse "default";
		const hint_name: []const u8 = if (name) |n|
			try std.fmt.allocPrint(allocator, " --name {s}", .{n})
		else
			try allocator.dupe(u8, "");
		defer allocator.free(hint_name);
		try util.writeStderr(io,
			try std.fmt.allocPrint(allocator,
				"cogbox ssh: error: instance \"{s}\" is not running.\nStart it with: cogbox start{s}\n",
				.{ eff, hint_name },
			),
		);
		std.process.exit(exit_codes.software);
	}

	const endpoint = readEndpoint(allocator, io, inst_runtime) catch |err| switch (err) {
		error.Missing => util.die(allocator, io, "ssh", exit_codes.software, "missing {s}/ssh-endpoint (instance launched by an older cogbox?). Restart the instance to repopulate it.", .{inst_runtime}),
		error.Malformed => util.die(allocator, io, "ssh", exit_codes.software, "ssh-endpoint is malformed in {s}. Restart the instance to repopulate it.", .{inst_runtime}),
		error.OutOfMemory => return error.OutOfMemory,
	};
	defer endpoint.deinit(allocator);

	// Forward everything after the verb (and any `--`) to the remote as the
	// command/args. With terminate_on_positional both land in `trailing`, but
	// fold `positional` in too for parity.
	var extra: std.ArrayList([]const u8) = .empty;
	defer extra.deinit(allocator);
	for (parsed.trailing.items) |t| try extra.append(allocator, t);
	for (parsed.positional.items) |t| try extra.append(allocator, t);

	const identity = defaultIdentity(allocator, io, p);
	defer if (identity) |id| allocator.free(id);

	try exec(allocator, endpoint, identity, extra.items);
}

/// SSH host:port for a running instance, read from <runtime>/ssh-endpoint.
/// Both fields are owned by the caller; free via `deinit`.
pub const Endpoint = struct {
	port: []const u8,
	host: []const u8,

	pub fn deinit(self: Endpoint, allocator: std.mem.Allocator) void {
		allocator.free(self.port);
		allocator.free(self.host);
	}
};

pub const EndpointError = error{ Missing, Malformed, OutOfMemory };

/// Parse <inst_runtime>/ssh-endpoint ("PORT HOST", written by the launch
/// script when the VM comes up). Returns duped fields. `error.Missing` if the
/// file is absent/unreadable; `error.Malformed` if it lacks a port or host.
pub fn readEndpoint(allocator: std.mem.Allocator, io: std.Io, inst_runtime: []const u8) EndpointError!Endpoint {
	const endpoint_path = std.fs.path.join(allocator, &.{ inst_runtime, "ssh-endpoint" }) catch return error.OutOfMemory;
	defer allocator.free(endpoint_path);
	const text = readSmall(allocator, io, endpoint_path) catch return error.Missing;
	defer allocator.free(text);

	var iter = std.mem.tokenizeAny(u8, text, " \t\r\n");
	const port = iter.next() orelse return error.Malformed;
	const host = iter.next() orelse return error.Malformed;

	const port_d = allocator.dupe(u8, port) catch return error.OutOfMemory;
	errdefer allocator.free(port_d);
	const host_d = allocator.dupe(u8, host) catch return error.OutOfMemory;
	return .{ .port = port_d, .host = host_d };
}

/// Replace this process with `ssh` pointed at `endpoint`. `extra` is appended
/// after the `root@host` target (remote command and/or extra ssh args). Host
/// key checking is disabled because the guest's root disk is ephemeral and its
/// host keys regenerate on every boot.
///
/// When `identity` is non-null it is passed as `-i <identity>`: cogbox's own
/// managed key (see `defaultIdentity`). This is additive -- ssh still offers the
/// user's agent and default keys -- so a user who authorized their own key keeps
/// working even if the cogbox key is absent from authorized_keys.
///
/// A `-t` is inserted before the target for a fully interactive remote command
/// (a command is present and both local stdin and stdout are ttys) so remote
/// TUIs get a PTY; see `wantPty` for the gating rationale.
///
/// ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
///     -o LogLevel=ERROR [-i <identity>] -p <port> [-t] root@<host> [extra...]
pub fn exec(allocator: std.mem.Allocator, endpoint: Endpoint, identity: ?[]const u8, extra: []const []const u8) !void {
	// The two isatty() calls are this function's only impurity; evaluate them
	// here and delegate the decision to the pure, unit-tested `wantPty`.
	const force_pty = wantPty(
		extra,
		std.c.isatty(std.posix.STDIN_FILENO) != 0,
		std.c.isatty(std.posix.STDOUT_FILENO) != 0,
	);

	var ssh_argv: std.ArrayList([]const u8) = .empty;
	defer ssh_argv.deinit(allocator);
	try buildArgv(allocator, &ssh_argv, endpoint, identity, extra, force_pty);

	try execvpAlloc(allocator, ssh_argv.items);
}

/// Whether to request a remote PTY (a single `ssh -t`) for this invocation.
/// True only for a *fully interactive* remote command: a command is present
/// (`extra.len > 0`) AND both local stdin and stdout are terminals.
///
/// Without `-t`, `ssh host cmd` runs cmd over pipes (no tty) and screen apps
/// like htop / claude-code refuse to start. The command gate keeps the
/// no-command interactive login -- which ssh already gives a PTY -- on its
/// existing path (so `cogbox start` auto-ssh, which passes empty `extra`, is
/// untouched). Requiring BOTH ends be ttys is what protects
/// `cogbox ssh host cat f | downstream` and `... > file`: a shell pipeline
/// redirects only stdout while stdin stays a tty, so gating on stdin alone
/// would still force a PTY and let its line discipline mangle the bytes
/// (LF->CRLF, control cooking). A single `-t` (never `-tt`) is deliberate --
/// `-tt` would force a PTY even with no local tty at all.
fn wantPty(extra: []const []const u8, stdin_is_tty: bool, stdout_is_tty: bool) bool {
	return extra.len > 0 and stdin_is_tty and stdout_is_tty;
}

/// Append the full `ssh ...` argv for `endpoint` into `argv`. When `force_pty`
/// is set a single `-t` is inserted just before the `root@host` target (an ssh
/// option must precede the host) so ssh allocates a remote PTY; see `wantPty`
/// for when `force_pty` is set. The target string and the list's backing are
/// owned by `allocator`; on the normal path `exec` hands `argv` straight to
/// execvp, so they live until this process is replaced. Split out from `exec`
/// so the `-t` placement is unit-testable without a real exec or a local tty.
fn buildArgv(
	allocator: std.mem.Allocator,
	argv: *std.ArrayList([]const u8),
	endpoint: Endpoint,
	identity: ?[]const u8,
	extra: []const []const u8,
	force_pty: bool,
) !void {
	const target = try std.fmt.allocPrint(allocator, "root@{s}", .{endpoint.host});
	try argv.append(allocator, "ssh");
	try argv.append(allocator, "-o");
	try argv.append(allocator, "StrictHostKeyChecking=no");
	try argv.append(allocator, "-o");
	try argv.append(allocator, "UserKnownHostsFile=/dev/null");
	try argv.append(allocator, "-o");
	try argv.append(allocator, "LogLevel=ERROR");
	if (identity) |id| {
		try argv.append(allocator, "-i");
		try argv.append(allocator, id);
	}
	try argv.append(allocator, "-p");
	try argv.append(allocator, endpoint.port);
	if (force_pty) try argv.append(allocator, "-t");
	try argv.append(allocator, target);
	for (extra) |t| try argv.append(allocator, t);
}

/// Path to cogbox's managed SSH identity (`<data>/cogbox_ed25519`), or null if
/// it does not exist. The launch script generates it host-side and unions its
/// pubkey into each VM's authorized_keys, so passing it as the default `-i`
/// makes `cogbox ssh` work without the user's personal keys. Best-effort: any
/// error (alloc, missing file) yields null so ssh falls back to its defaults.
/// The returned slice is owned by the caller.
pub fn defaultIdentity(allocator: std.mem.Allocator, io: std.Io, p: *const paths.Paths) ?[]const u8 {
	const key_path = std.fs.path.join(allocator, &.{ p.base_data, "cogbox_ed25519" }) catch return null;
	const cwd = std.Io.Dir.cwd();
	cwd.access(io, key_path, .{}) catch {
		allocator.free(key_path);
		return null;
	};
	return key_path;
}

fn nameFlag(parsed: *const parse.Parsed, allocator: std.mem.Allocator, io: std.Io) ?[]const u8 {
	if (parsed.get("name")) |n| {
		if (std.mem.eql(u8, n, "default")) {
			util.die(allocator, io, "ssh", exit_codes.dataerr, "'default' is reserved. Omit --name to use the default instance.", .{});
		}
		if (!parse.isValidName(n)) {
			util.die(allocator, io, "ssh", exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
		}
		return n;
	}
	return null;
}

fn readSmall(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
	const cwd = std.Io.Dir.cwd();
	const file = try cwd.openFile(io, path, .{});
	defer file.close(io);
	var buf: [256]u8 = undefined;
	var reader = file.reader(io, &buf);
	return try reader.interface.allocRemaining(allocator, .limited(4096));
}

fn isRunning(allocator: std.mem.Allocator, io: std.Io, pid_path: []const u8) bool {
	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(io, pid_path, .{}) catch return false;
	defer file.close(io);
	var buf: [64]u8 = undefined;
	var reader = file.reader(io, &buf);
	const data = reader.interface.allocRemaining(allocator, .limited(64)) catch return false;
	defer allocator.free(data);
	const trimmed = std.mem.trim(u8, data, " \t\r\n");
	const pid = std.fmt.parseInt(std.posix.pid_t, trimmed, 10) catch return false;
	const sig_zero: std.posix.SIG = @enumFromInt(0);
	std.posix.kill(pid, sig_zero) catch return false;
	return true;
}

extern "c" fn execvp(file: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;

/// execvp via libc: replaces the current process. Allocates null-terminated
/// strings for the argv array.
pub fn execvpAlloc(allocator: std.mem.Allocator, argv: []const []const u8) !void {
	const argv_z = try allocator.alloc(?[*:0]const u8, argv.len + 1);
	defer allocator.free(argv_z);
	for (argv, 0..) |a, i| {
		const z = try allocator.dupeZ(u8, a);
		argv_z[i] = z.ptr;
	}
	argv_z[argv.len] = null;

	const prog = try allocator.dupeZ(u8, argv[0]);
	const argv_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(argv_z.ptr);
	_ = execvp(prog.ptr, argv_ptr);
	// If execvp returns, it failed.
	return error.ExecvpFailed;
}

const testing = std.testing;

fn argvCount(argv: []const []const u8, needle: []const u8) usize {
	var n: usize = 0;
	for (argv) |a| {
		if (std.mem.eql(u8, a, needle)) n += 1;
	}
	return n;
}

fn argvIndex(argv: []const []const u8, needle: []const u8) ?usize {
	for (argv, 0..) |a, i| {
		if (std.mem.eql(u8, a, needle)) return i;
	}
	return null;
}

test "buildArgv adds a single -t before the target only when force_pty" {
	var arena = std.heap.ArenaAllocator.init(testing.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	const ep: Endpoint = .{ .port = "2222", .host = "10.0.2.15" };

	// Interactive remote command -> exactly one `-t`, placed before root@host,
	// with the remote command still trailing the target.
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgv(a, &argv, ep, null, &.{"tty"}, true);
		try testing.expectEqual(@as(usize, 1), argvCount(argv.items, "-t"));
		const t_i = argvIndex(argv.items, "-t").?;
		const host_i = argvIndex(argv.items, "root@10.0.2.15").?;
		try testing.expect(t_i < host_i);
		try testing.expect(argvIndex(argv.items, "tty").? > host_i);
	}

	// Piped / non-interactive (force_pty=false) -> no `-t`, command still sent.
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgv(a, &argv, ep, null, &.{"tty"}, false);
		try testing.expectEqual(@as(usize, 0), argvCount(argv.items, "-t"));
		try testing.expect(argvIndex(argv.items, "tty") != null);
	}

	// Interactive login (no remote command) -> caller passes empty extra and
	// force_pty=false; no `-t` (ssh allocates the login PTY itself) and the
	// target is the last argv element.
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgv(a, &argv, ep, null, &.{}, false);
		try testing.expectEqual(@as(usize, 0), argvCount(argv.items, "-t"));
		try testing.expectEqualStrings("root@10.0.2.15", argv.items[argv.items.len - 1]);
	}

	// Identity is forwarded as `-i <path>`.
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgv(a, &argv, ep, "/data/cogbox_ed25519", &.{}, false);
		const i_i = argvIndex(argv.items, "-i").?;
		try testing.expectEqualStrings("/data/cogbox_ed25519", argv.items[i_i + 1]);
	}

	// A multi-element command is appended in order as the argv tail, immediately
	// after the target (and after `-t` when a PTY is forced).
	{
		var argv: std.ArrayList([]const u8) = .empty;
		const cmd = [_][]const u8{ "uname", "-a" };
		try buildArgv(a, &argv, ep, null, &cmd, true);
		const host_i = argvIndex(argv.items, "root@10.0.2.15").?;
		try testing.expectEqual(cmd.len, argv.items.len - (host_i + 1));
		for (cmd, 0..) |want, j| {
			try testing.expectEqualStrings(want, argv.items[host_i + 1 + j]);
		}
	}
}

test "wantPty: only a remote command with both stdin+stdout ttys forces a PTY" {
	// No remote command -> never (even with both ttys); ssh gives the
	// no-command login its own PTY, and `cogbox start` auto-ssh passes empty.
	try testing.expect(!wantPty(&.{}, true, true));
	// Fully interactive remote command (terminal on both ends) -> yes.
	try testing.expect(wantPty(&.{"htop"}, true, true));
	// Output piped/redirected (`cmd | downstream`, `cmd > file`) -> no, so the
	// remote PTY's line discipline cannot mangle the bytes.
	try testing.expect(!wantPty(&.{"cat"}, true, false));
	// Input piped (`printf '' | cogbox ssh host cmd`) -> no.
	try testing.expect(!wantPty(&.{"cat"}, false, true));
	// Fully non-interactive (scripted) -> no.
	try testing.expect(!wantPty(&.{"cat"}, false, false));
}
