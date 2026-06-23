// Argument parsing for cogbox-rules. Shape:
//   cogbox-rules --config CFG --runtime RT list
//   cogbox-rules --config CFG --runtime RT add allow|deny [tcp|udp] CIDR[:PORT] [--at N]
//   cogbox-rules --config CFG --runtime RT del INDEX
//   cogbox-rules --config CFG --runtime RT set       # reads stdin

const std = @import("std");
const rule = @import("rule.zig");

pub const Cmd = union(enum) {
	list,
	add: AddArgs,
	del: DelArgs,
	set,
};

pub const AddArgs = struct {
	action: rule.Action,
	proto: ?[]const u8 = null, // optional "tcp"/"udp" qualifier; null = any proto
	cidr: []const u8, // CIDR, optionally with a :PORT suffix
	pos: ?usize = null, // 1-based; null = append
	// --plugin NAME: tag the inserted rule with `"plugin": "<name>"` so a later
	// `plugin del <name>` removes exactly it. Used by the control plane when an
	// admin approves a deferred plugin-contributed rule.
	plugin: ?[]const u8 = null,
};

pub const DelArgs = struct {
	index: usize, // 1-based
};

pub const Args = struct {
	config_path: []const u8,
	runtime_path: []const u8,
	cmd: Cmd,
};

pub const ParseError = error{
	MissingConfig,
	MissingRuntime,
	MissingSubcommand,
	UnknownSubcommand,
	InvalidArgs,
	InvalidAction,
	InvalidIndex,
};

/// Parse argv (excluding argv[0]).
pub fn parse(argv: []const []const u8) ParseError!Args {
	var config: ?[]const u8 = null;
	var runtime: ?[]const u8 = null;
	var i: usize = 0;

	while (i < argv.len) : (i += 1) {
		const a = argv[i];
		if (std.mem.eql(u8, a, "--config")) {
			i += 1;
			if (i >= argv.len) return error.InvalidArgs;
			config = argv[i];
		} else if (std.mem.eql(u8, a, "--runtime")) {
			i += 1;
			if (i >= argv.len) return error.InvalidArgs;
			runtime = argv[i];
		} else if (std.mem.startsWith(u8, a, "--")) {
			return error.InvalidArgs;
		} else {
			break;
		}
	}

	const cfg_path = config orelse return error.MissingConfig;
	const rt_path = runtime orelse return error.MissingRuntime;
	if (i >= argv.len) return error.MissingSubcommand;

	const sub = argv[i];
	i += 1;
	const sub_args = argv[i..];

	if (std.mem.eql(u8, sub, "list")) {
		if (sub_args.len != 0) return error.InvalidArgs;
		return .{ .config_path = cfg_path, .runtime_path = rt_path, .cmd = .list };
	}
	if (std.mem.eql(u8, sub, "set")) {
		if (sub_args.len != 0) return error.InvalidArgs;
		return .{ .config_path = cfg_path, .runtime_path = rt_path, .cmd = .set };
	}
	if (std.mem.eql(u8, sub, "add")) return parseAdd(cfg_path, rt_path, sub_args);
	if (std.mem.eql(u8, sub, "del")) return parseDel(cfg_path, rt_path, sub_args);
	return error.UnknownSubcommand;
}

fn parseAdd(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	if (args.len < 2) return error.InvalidArgs;
	const action = parseAction(args[0]) orelse return error.InvalidAction;

	// An optional proto qualifier ("tcp"/"udp") may precede the CIDR, mirroring
	// the runtime rule-file grammar (`allow|deny [tcp|udp] CIDR[:PORT]`) and
	// `cogbox rules set`. A leading "tcp"/"udp" is unambiguous since no CIDR
	// begins that way. The port, if any, rides in the CIDR token as :PORT.
	var idx: usize = 1;
	var proto: ?[]const u8 = null;
	if (isProtoToken(args[idx])) {
		proto = args[idx];
		idx += 1;
	}
	if (idx >= args.len) return error.InvalidArgs; // proto given but no CIDR
	const cidr = args[idx];
	idx += 1;

	var pos: ?usize = null;
	var plugin: ?[]const u8 = null;
	var i: usize = idx;
	while (i < args.len) : (i += 1) {
		if (std.mem.eql(u8, args[i], "--at")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			pos = std.fmt.parseInt(usize, args[i], 10) catch return error.InvalidIndex;
			if (pos.? == 0) return error.InvalidIndex;
		} else if (std.mem.eql(u8, args[i], "--plugin")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			plugin = args[i];
		} else {
			return error.InvalidArgs;
		}
	}

	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .{ .add = .{ .action = action, .proto = proto, .cidr = cidr, .pos = pos, .plugin = plugin } },
	};
}

fn isProtoToken(s: []const u8) bool {
	return std.mem.eql(u8, s, "tcp") or std.mem.eql(u8, s, "udp");
}

fn parseDel(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	if (args.len != 1) return error.InvalidArgs;
	const idx = std.fmt.parseInt(usize, args[0], 10) catch return error.InvalidIndex;
	if (idx == 0) return error.InvalidIndex;
	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .{ .del = .{ .index = idx } },
	};
}

fn parseAction(s: []const u8) ?rule.Action {
	if (std.mem.eql(u8, s, "allow")) return .allow;
	if (std.mem.eql(u8, s, "deny")) return .deny;
	return null;
}
