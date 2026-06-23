const std = @import("std");
const cli = @import("cli.zig");

const t = std.testing;

fn argv(comptime items: []const []const u8) []const []const u8 {
	return items;
}

test "list parses with --config and --runtime" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "list" }));
	try t.expectEqualStrings("/c", a.config_path);
	try t.expectEqualStrings("/r", a.runtime_path);
	try t.expect(a.cmd == .list);
}

test "missing --config errors" {
	try t.expectError(error.MissingConfig, cli.parse(argv(&.{ "--runtime", "/r", "list" })));
}

test "missing --runtime errors" {
	try t.expectError(error.MissingRuntime, cli.parse(argv(&.{ "--config", "/c", "list" })));
}

test "missing subcommand errors" {
	try t.expectError(error.MissingSubcommand, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r" })));
}

test "unknown subcommand errors" {
	try t.expectError(error.UnknownSubcommand, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "blast" })));
}

test "add allow without --at" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "10.0.0.0/8" }));
	try t.expect(a.cmd == .add);
	try t.expect(a.cmd.add.action == .allow);
	try t.expectEqualStrings("10.0.0.0/8", a.cmd.add.cidr);
	try t.expect(a.cmd.add.pos == null);
}

test "add deny with --at" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "deny", "10.0.0.0/8", "--at", "3" }));
	try t.expect(a.cmd.add.action == .deny);
	try t.expectEqual(@as(?usize, 3), a.cmd.add.pos);
}

test "add without proto leaves proto null (backward compat)" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "10.0.0.0/8" }));
	try t.expect(a.cmd.add.proto == null);
	try t.expectEqualStrings("10.0.0.0/8", a.cmd.add.cidr);
}

test "add with :PORT suffix in the CIDR token" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "deny", "0.0.0.0/0:25" }));
	try t.expect(a.cmd.add.proto == null);
	try t.expectEqualStrings("0.0.0.0/0:25", a.cmd.add.cidr);
}

test "add with proto qualifier" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "tcp", "10.0.0.0/8" }));
	try t.expectEqualStrings("tcp", a.cmd.add.proto.?);
	try t.expectEqualStrings("10.0.0.0/8", a.cmd.add.cidr);
	try t.expect(a.cmd.add.pos == null);
}

test "add with proto + :PORT + --at" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "udp", "1.2.3.4/32:53", "--at", "2" }));
	try t.expectEqualStrings("udp", a.cmd.add.proto.?);
	try t.expectEqualStrings("1.2.3.4/32:53", a.cmd.add.cidr);
	try t.expectEqual(@as(?usize, 2), a.cmd.add.pos);
}

test "add with proto but no CIDR errors" {
	try t.expectError(error.InvalidArgs, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "tcp" })));
	try t.expectError(error.InvalidArgs, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "tcp", "--at", "1" })));
}

test "add rejects invalid action" {
	try t.expectError(error.InvalidAction, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "block", "10.0.0.0/8" })));
}

test "add rejects --at 0" {
	try t.expectError(error.InvalidIndex, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "10.0.0.0/8", "--at", "0" })));
}

test "add with --plugin tag" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "203.0.113.0/24", "--plugin", "obs-plugin" }));
	try t.expectEqualStrings("obs-plugin", a.cmd.add.plugin.?);
	try t.expectEqualStrings("203.0.113.0/24", a.cmd.add.cidr);
	// Default is no tag (backward compat).
	const b = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "203.0.113.0/24" }));
	try t.expect(b.cmd.add.plugin == null);
	// Combines with proto + --at.
	const c = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "tcp", "203.0.113.0/24:443", "--plugin", "p", "--at", "2" }));
	try t.expectEqualStrings("p", c.cmd.add.plugin.?);
	try t.expectEqual(@as(?usize, 2), c.cmd.add.pos);
	// --plugin without a value errors.
	try t.expectError(error.InvalidArgs, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "203.0.113.0/24", "--plugin" })));
}

test "del with valid index" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "del", "5" }));
	try t.expect(a.cmd == .del);
	try t.expectEqual(@as(usize, 5), a.cmd.del.index);
}

test "del rejects 0 and missing arg" {
	try t.expectError(error.InvalidIndex, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "del", "0" })));
	try t.expectError(error.InvalidArgs, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "del" })));
}

test "set takes no extra args" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "set" }));
	try t.expect(a.cmd == .set);
	try t.expectError(error.InvalidArgs, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "set", "extra" })));
}
