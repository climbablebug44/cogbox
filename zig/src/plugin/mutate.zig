// Pure config-tree mutations for the plugin verb: the .plugins array and the
// plugin-tagged entries in .network.rules. All inserted values are duplicated
// into the document's arena so they free with the tree.
//
// Plugin-contributed rules carry a `"plugin": "<name>"` field; that tag is
// how del/update remove or replace exactly the rules a plugin brought in,
// and it's preserved through save because config.zig keeps unknown fields.

const std = @import("std");
const rules_module = @import("rules_module");
const rule = rules_module.rule;

pub const Entry = struct {
	name: []const u8,
	url: []const u8, // flake ref WITHOUT the #attr fragment
	attr: ?[]const u8 = null, // nixosModules attr; null means "default"
	locked_url: []const u8,
	rev: ?[]const u8,
	nar_hash: []const u8,
};

/// Ensure root has a .plugins array and return it.
pub fn pluginsArray(root: *std.json.Value, arena: std.mem.Allocator) !*std.json.Array {
	if (root.* != .object) return error.InvalidJson;
	if (root.object.getPtr("plugins") == null) {
		try root.object.put(arena, try arena.dupe(u8, "plugins"), .{ .array = std.json.Array.init(arena) });
	}
	const v = root.object.getPtr("plugins").?;
	if (v.* != .array) return error.InvalidJson;
	return &v.array;
}

/// .plugins array if present, without creating it.
pub fn existingPluginsArray(root: *std.json.Value) ?*std.json.Array {
	if (root.* != .object) return null;
	const v = root.object.getPtr("plugins") orelse return null;
	if (v.* != .array) return null;
	return &v.array;
}

pub fn findPlugin(arr: *std.json.Array, plugin_name: []const u8) ?usize {
	for (arr.items, 0..) |item, i| {
		if (item != .object) continue;
		const n = item.object.get("name") orelse continue;
		if (n == .string and std.mem.eql(u8, n.string, plugin_name)) return i;
	}
	return null;
}

pub fn entryField(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
	const v = obj.get(key) orelse return null;
	if (v != .string) return null;
	return v.string;
}

pub fn appendPlugin(arena: std.mem.Allocator, arr: *std.json.Array, e: Entry) !void {
	var obj: std.json.ObjectMap = .empty;
	try obj.put(arena, try arena.dupe(u8, "name"), .{ .string = try arena.dupe(u8, e.name) });
	try obj.put(arena, try arena.dupe(u8, "url"), .{ .string = try arena.dupe(u8, e.url) });
	if (e.attr) |a| {
		try obj.put(arena, try arena.dupe(u8, "attr"), .{ .string = try arena.dupe(u8, a) });
	}
	try putLockFields(arena, &obj, e);
	try arr.append(.{ .object = obj });
}

/// First plugin entry with the given (fragment-less) url, if any. Used to
/// reuse an installed flake's pin when enabling another of its modules:
/// versioning is per flake, so siblings share one rev.
pub fn findByUrl(arr: *std.json.Array, url: []const u8) ?*std.json.Value {
	for (arr.items) |*item| {
		if (item.* != .object) continue;
		const u = entryField(item.object, "url") orelse continue;
		if (std.mem.eql(u8, u, url)) return item;
	}
	return null;
}

/// Refresh lockedUrl/rev/narHash on an existing entry (plugin update).
pub fn relockPlugin(arena: std.mem.Allocator, item: *std.json.Value, e: Entry) !void {
	if (item.* != .object) return error.InvalidJson;
	_ = item.object.orderedRemove("lockedUrl");
	_ = item.object.orderedRemove("rev");
	_ = item.object.orderedRemove("narHash");
	try putLockFields(arena, &item.object, e);
}

fn putLockFields(arena: std.mem.Allocator, obj: *std.json.ObjectMap, e: Entry) !void {
	try obj.put(arena, try arena.dupe(u8, "lockedUrl"), .{ .string = try arena.dupe(u8, e.locked_url) });
	if (e.rev) |r| {
		try obj.put(arena, try arena.dupe(u8, "rev"), .{ .string = try arena.dupe(u8, r) });
	}
	try obj.put(arena, try arena.dupe(u8, "narHash"), .{ .string = try arena.dupe(u8, e.nar_hash) });
}

pub const RuleError = error{
	NotAnObject,
	BadAction,
	InvalidCidr,
	OutOfMemory,
};

/// Validate one plugin-declared rule: an object with exactly one of
/// allow/deny keyed to a valid CIDR. Extra fields (comment, ...) are fine.
pub fn validatePluginRule(v: std.json.Value) RuleError!void {
	if (v != .object) return error.NotAnObject;
	const has_allow = v.object.get("allow") != null;
	const has_deny = v.object.get("deny") != null;
	if (has_allow == has_deny) return error.BadAction; // both or neither
	const p = rule.ruleAction(v.object) orelse return error.BadAction;
	var line_buf: [128]u8 = undefined;
	if (!rule.validateActionCidr(p.action, p.cidr, &line_buf)) return error.InvalidCidr;
}

/// Prepend `incoming` as a contiguous block at the head of the rules array
/// (first match wins; a plugin's allows must precede the seeded RFC1918
/// denies to be reachable). Each rule is deep-copied into the document arena
/// and tagged with `"plugin": tag` (overwriting any tag the flake declared).
pub fn prependTaggedRules(
	arena: std.mem.Allocator,
	rules_arr: *std.json.Array,
	tag: []const u8,
	incoming: []const std.json.Value,
) !void {
	// Insert in reverse so the block lands in declared order.
	var i = incoming.len;
	while (i > 0) {
		i -= 1;
		var copied = try deepCopy(arena, incoming[i]);
		_ = copied.object.orderedRemove("plugin");
		try copied.object.put(arena, try arena.dupe(u8, "plugin"), .{ .string = try arena.dupe(u8, tag) });
		try rules_arr.insert(0, copied);
	}
}

/// Remove every rule tagged with `tag`. Returns how many were dropped.
pub fn removeTaggedRules(rules_arr: *std.json.Array, tag: []const u8) usize {
	var removed: usize = 0;
	var i: usize = 0;
	while (i < rules_arr.items.len) {
		if (ruleTag(rules_arr.items[i])) |t| {
			if (std.mem.eql(u8, t, tag)) {
				_ = rules_arr.orderedRemove(i);
				removed += 1;
				continue;
			}
		}
		i += 1;
	}
	return removed;
}

pub fn countTaggedRules(rules_arr: *const std.json.Array, tag: []const u8) usize {
	var n: usize = 0;
	for (rules_arr.items) |item| {
		if (ruleTag(item)) |t| {
			if (std.mem.eql(u8, t, tag)) n += 1;
		}
	}
	return n;
}

pub fn ruleTag(v: std.json.Value) ?[]const u8 {
	if (v != .object) return null;
	const t = v.object.get("plugin") orelse return null;
	if (t != .string) return null;
	return t.string;
}

/// Deep-copy a JSON value into `arena` (rule objects from the eval'd plugin
/// output live in a different parse tree than the config document).
pub fn deepCopy(arena: std.mem.Allocator, v: std.json.Value) std.mem.Allocator.Error!std.json.Value {
	switch (v) {
		.null, .bool, .integer, .float => return v,
		.number_string => |s| return .{ .number_string = try arena.dupe(u8, s) },
		.string => |s| return .{ .string = try arena.dupe(u8, s) },
		.array => |arr| {
			var out = std.json.Array.init(arena);
			try out.ensureTotalCapacity(arr.items.len);
			for (arr.items) |item| {
				out.appendAssumeCapacity(try deepCopy(arena, item));
			}
			return .{ .array = out };
		},
		.object => |obj| {
			var out: std.json.ObjectMap = .empty;
			var it = obj.iterator();
			while (it.next()) |entry| {
				try out.put(
					arena,
					try arena.dupe(u8, entry.key_ptr.*),
					try deepCopy(arena, entry.value_ptr.*),
				);
			}
			return .{ .object = out };
		},
	}
}
