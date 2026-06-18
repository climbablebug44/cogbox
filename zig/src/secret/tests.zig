// Unit tests for the secret store's PURE layer (validName + meta
// serialize/parse). The IO layer (add/lookup/remove on disk) is covered by the
// launcher + NixOS VM integration tests, mirroring how rules/config_test.zig
// leaves load/save IO to integration coverage. refAllDecls forces the verb
// dispatch code (main.zig) to type-check here too.

const std = @import("std");
const store = @import("store.zig");
const main = @import("main.zig");
const t = std.testing;

test {
	std.testing.refAllDecls(main);
	std.testing.refAllDecls(store);
}

test "validName accepts valid names, rejects traversal/charset/length" {
	try t.expect(store.validName("api-bearer"));
	try t.expect(store.validName("app_session"));
	try t.expect(store.validName("a"));
	try t.expect(store.validName("A0-_z"));
	try t.expect(!store.validName(""));
	try t.expect(!store.validName("has.dot")); // '.' excluded so <name>.meta is unambiguous
	try t.expect(!store.validName("has/slash"));
	try t.expect(!store.validName(".."));
	try t.expect(!store.validName("../etc/passwd"));
	try t.expect(!store.validName("with space"));
	try t.expect(!store.validName("x" ** 65)); // > 64 chars
}

test "buildMeta/parseMeta round-trip" {
	const a = t.allocator;
	const m: store.Meta = .{ .audience = "api.example.com", .kind = "bearer", .tier = "durable", .bound_at = 1234 };
	const json = try store.buildMeta(a, m);
	defer a.free(json);

	var arena = std.heap.ArenaAllocator.init(a);
	defer arena.deinit();
	const parsed = try store.parseMeta(arena.allocator(), json);
	try t.expectEqualStrings("api.example.com", parsed.audience.?);
	try t.expectEqualStrings("bearer", parsed.kind);
	try t.expectEqualStrings("durable", parsed.tier);
	try t.expectEqual(@as(i64, 1234), parsed.bound_at.?);
}

test "parseMeta handles null audience and missing fields with defaults" {
	const a = t.allocator;
	var arena = std.heap.ArenaAllocator.init(a);
	defer arena.deinit();
	const parsed = try store.parseMeta(arena.allocator(), "{\"audience\": null, \"kind\": \"cookie\"}");
	try t.expect(parsed.audience == null);
	try t.expectEqualStrings("cookie", parsed.kind);
	try t.expectEqualStrings("durable", parsed.tier); // default kept
	try t.expect(parsed.bound_at == null);
}

test "parseMeta tolerates malformed json -> defaults (fail safe)" {
	const a = t.allocator;
	var arena = std.heap.ArenaAllocator.init(a);
	defer arena.deinit();
	const parsed = try store.parseMeta(arena.allocator(), "not json{");
	try t.expect(parsed.audience == null);
	try t.expectEqualStrings("bearer", parsed.kind);
}

test "buildMeta emits null audience/bound_at literally" {
	const a = t.allocator;
	const m: store.Meta = .{ .audience = null, .kind = "cookie", .tier = "derived", .bound_at = null };
	const json = try store.buildMeta(a, m);
	defer a.free(json);
	try t.expect(std.mem.indexOf(u8, json, "\"audience\": null") != null);
	try t.expect(std.mem.indexOf(u8, json, "\"kind\": \"cookie\"") != null);
	try t.expect(std.mem.indexOf(u8, json, "\"tier\": \"derived\"") != null);
	try t.expect(std.mem.indexOf(u8, json, "\"bound_at\": null") != null);
}
