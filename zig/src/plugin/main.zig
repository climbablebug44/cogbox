// `cogbox plugin` verb dispatcher. Manages the `.plugins` array in
// config.json: each entry is a flake (resolved + pinned by nix at add time)
// whose nixosModules.default gets folded into the guest via the generated
// composition flake. A plugin may also suggest firewall rules through the
// optional `cogboxPlugin.networkRules` flake output; those merge into
// .network.rules tagged with the plugin's name (shown for confirmation, and
// removed/replaced exactly by del/update).
//
// Module changes need an instance restart; merged rules hot-reload through
// the shared rules_module path like every other rules-table edit.

const std = @import("std");
pub const cli = @import("cli.zig");
pub const name_mod = @import("name.zig");
pub const compose = @import("compose.zig");
pub const mutate = @import("mutate.zig");
pub const nix = @import("nix.zig");

const rules_module = @import("rules_module");
const config = rules_module.config;
const rule = rules_module.rule;

pub fn dispatch(
	allocator: std.mem.Allocator,
	io: std.Io,
	instance: ?[]const u8,
	config_path: []const u8,
	runtime_path: []const u8,
	user_flake_dir: []const u8,
	plugins_flake_dir: []const u8,
	rest: []const []const u8,
) !void {
	const cmd = cli.parse(rest) catch |err| {
		const msg = switch (err) {
			error.MissingSubcommand => "missing subcommand (list, add, del, update)",
			error.UnknownSubcommand => "unknown subcommand (expected list, add, del, update)",
			error.MissingUrl => "add requires a FLAKE_URL",
			error.MissingPlugin => "del requires a plugin name",
			error.InvalidArgs => "invalid arguments",
		};
		die(allocator, io, "{s}", .{msg}, 64);
	};

	var loaded = config.load(allocator, io, config_path) catch |err| switch (err) {
		error.FileNotFound => return die(allocator, io, "no config found at {s}", .{config_path}, 66),
		error.InvalidJson => return die(allocator, io, "invalid JSON in {s}", .{config_path}, 65),
		else => return err,
	};
	defer loaded.deinit();

	const ctx: Ctx = .{
		.allocator = allocator,
		.io = io,
		.instance = instance,
		.config_path = config_path,
		.runtime_path = runtime_path,
		.user_flake_dir = user_flake_dir,
		.plugins_flake_dir = plugins_flake_dir,
	};

	switch (cmd) {
		.list => try cmdList(ctx, &loaded),
		.add => |a| try cmdAdd(ctx, &loaded, a),
		.del => |d| try cmdDel(ctx, &loaded, d),
		.update => |u| try cmdUpdate(ctx, &loaded, u),
	}
}

const Ctx = struct {
	allocator: std.mem.Allocator,
	io: std.Io,
	instance: ?[]const u8,
	config_path: []const u8,
	runtime_path: []const u8,
	user_flake_dir: []const u8,
	plugins_flake_dir: []const u8,
};

// --- list ---------------------------------------------------------------

fn cmdList(ctx: Ctx, loaded: *config.Loaded) !void {
	const arr = mutate.existingPluginsArray(loaded.root());
	if (arr == null or arr.?.items.len == 0) {
		try announce(ctx, "(no plugins)", .{});
		return;
	}

	const rules_arr = rulesOrNull(loaded);
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(ctx.allocator);

	for (arr.?.items) |item| {
		if (item != .object) continue;
		const n = mutate.entryField(item.object, "name") orelse "?";
		const u = mutate.entryField(item.object, "url") orelse "?";
		const rules_n = if (rules_arr) |ra| mutate.countTaggedRules(ra, n) else 0;
		const frag: []const u8 = if (mutate.entryField(item.object, "attr")) |a| a else "";
		const line = try std.fmt.allocPrint(
			ctx.allocator,
			"{s}  {s}{s}{s}  rev={s}  rules={d}\n",
			.{ n, u, if (frag.len > 0) "#" else "", frag, shortRev(item.object), rules_n },
		);
		defer ctx.allocator.free(line);
		try out.appendSlice(ctx.allocator, line);
	}
	try writeStdout(ctx.io, out.items);
}

/// Display pin: short rev when there is one, else a narHash prefix
/// (dirty path: flakes have no rev).
fn shortRev(obj: std.json.ObjectMap) []const u8 {
	if (mutate.entryField(obj, "rev")) |r| {
		return r[0..@min(r.len, 7)];
	}
	if (mutate.entryField(obj, "narHash")) |h| {
		const stripped = if (std.mem.startsWith(u8, h, "sha256-")) h[7..] else h;
		return stripped[0..@min(stripped.len, 8)];
	}
	return "?";
}

// --- add ----------------------------------------------------------------

fn cmdAdd(ctx: Ctx, loaded: *config.Loaded, a: cli.AddArgs) !void {
	const allocator = ctx.allocator;
	const io = ctx.io;

	// `URL#attr` selects nixosModules.<attr>; bare URL means `default`.
	const split = name_mod.splitFragment(a.url) catch |err| switch (err) {
		error.EmptyFragment => die(allocator, io, "empty #fragment in '{s}'", .{a.url}, 65),
		error.InvalidAttr => die(allocator, io, "invalid module attr in '{s}' (allowed: [a-zA-Z0-9_-])", .{a.url}, 65),
	};
	const ref = split.ref;
	// An explicit `#default` is the same as no fragment.
	const attr: ?[]const u8 = if (split.attr) |sa|
		(if (std.mem.eql(u8, sa, "default")) null else sa)
	else
		null;

	const plugin_name: []const u8 = blk: {
		if (a.as) |as| {
			if (!name_mod.isValidPluginName(as)) {
				die(allocator, io, "invalid plugin name '{s}' (must start with a letter, [a-zA-Z0-9-], max 64; 'user' is reserved)", .{as}, 65);
			}
			break :blk try allocator.dupe(u8, as);
		}
		if (attr) |at| {
			break :blk name_mod.deriveNameFromAttr(allocator, at) catch {
				die(allocator, io, "cannot derive a plugin name from attr '{s}'; pass --as NAME", .{at}, 65);
			};
		}
		break :blk name_mod.deriveName(allocator, ref) catch {
			die(allocator, io, "cannot derive a plugin name from '{s}'; pass --as NAME", .{ref}, 65);
		};
	};
	defer allocator.free(plugin_name);

	const plugins_arr = mutate.pluginsArray(loaded.root(), loaded.treeAllocator()) catch {
		die(allocator, io, "invalid JSON in {s} (.plugins is not an array)", .{ctx.config_path}, 65);
	};
	if (mutate.findPlugin(plugins_arr, plugin_name) != null) {
		die(allocator, io, "plugin '{s}' already exists (choose another name with --as)", .{plugin_name}, 65);
	}

	// Flake-level versioning: if another module of this same flake URL is
	// already installed, reuse its pin instead of resolving the tip again,
	// so all plugins from one flake stay at one rev (`update` moves them
	// together). A different rev can still be forced by pinning it in the
	// URL itself, which makes the URL string distinct.
	var meta: nix.Meta = blk: {
		if (mutate.findByUrl(plugins_arr, ref)) |sibling| {
			const locked = mutate.entryField(sibling.object, "lockedUrl");
			const hash = mutate.entryField(sibling.object, "narHash");
			if (locked != null and hash != null) {
				try announce(ctx, "Reusing pin of installed flake '{s}' ({s}).", .{ ref, shortRev(sibling.object) });
				break :blk .{
					.locked_url = try allocator.dupe(u8, locked.?),
					.rev = if (mutate.entryField(sibling.object, "rev")) |r| try allocator.dupe(u8, r) else null,
					.nar_hash = try allocator.dupe(u8, hash.?),
				};
			}
		}
		try announce(ctx, "Resolving '{s}'...", .{ref});
		break :blk resolveFlake(ctx, ref);
	};
	defer meta.deinit(allocator);

	const module_attr = attr orelse "default";
	const has_module = try nix.evalHasNixosModule(allocator, io, meta.locked_url, module_attr);
	if (!has_module) {
		die(allocator, io, "plugin flake does not expose nixosModules.{s} (see docs/plugins.md)", .{module_attr}, 65);
	}

	archiveFlake(ctx, meta.locked_url);

	// Optional suggested firewall rules.
	var rules_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (rules_parsed) |*p| p.deinit();
	const incoming: []const std.json.Value = blk: {
		rules_parsed = evalRules(ctx, meta.locked_url, attr);
		const p = rules_parsed orelse break :blk &.{};
		break :blk p.value.array.items;
	};

	var merged = false;
	if (incoming.len > 0) {
		if (rulesOrNull(loaded)) |rules_arr| {
			try announce(ctx, "Suggested network rules from '{s}':", .{plugin_name});
			for (incoming) |r| try printRuleLine(ctx, "+", r);
			const prompt = try std.fmt.allocPrint(allocator, "Merge these {d} rule(s) at the top of the rule list?", .{incoming.len});
			defer allocator.free(prompt);
			if (!a.yes and !try confirm(ctx, prompt)) {
				try announce(ctx, "Aborted.", .{});
				return;
			}
			try mutate.prependTaggedRules(loaded.treeAllocator(), rules_arr, plugin_name, incoming);
			merged = true;
		} else {
			try warn(ctx, "instance is not in rules mode; skipping {d} suggested network rule(s)", .{incoming.len});
		}
	}

	try mutate.appendPlugin(loaded.treeAllocator(), plugins_arr, .{
		.name = plugin_name,
		.url = ref,
		.attr = attr,
		.locked_url = meta.locked_url,
		.rev = meta.rev,
		.nar_hash = meta.nar_hash,
	});

	try config.save(allocator, io, ctx.config_path, loaded.root().*);
	try regenComposition(ctx, plugins_arr);
	if (merged) try rules_module.maybeReload(allocator, io, ctx.runtime_path, loaded);

	try announce(ctx, "Plugin '{s}' added at {s}.", .{ plugin_name, pinLabel(&meta) });
	try printRestartHint(ctx, "to load its NixOS module");
}

// --- del ----------------------------------------------------------------

fn cmdDel(ctx: Ctx, loaded: *config.Loaded, d: cli.DelArgs) !void {
	const allocator = ctx.allocator;
	const io = ctx.io;

	const plugins_arr = mutate.existingPluginsArray(loaded.root()) orelse {
		die(allocator, io, "no such plugin '{s}'", .{d.plugin}, 65);
	};
	const idx = mutate.findPlugin(plugins_arr, d.plugin) orelse {
		die(allocator, io, "no such plugin '{s}'", .{d.plugin}, 65);
	};

	const rules_arr = rulesOrNull(loaded);
	const tagged = if (rules_arr) |ra| mutate.countTaggedRules(ra, d.plugin) else 0;

	const prompt = try std.fmt.allocPrint(allocator, "Remove plugin '{s}' and its {d} network rule(s)?", .{ d.plugin, tagged });
	defer allocator.free(prompt);
	if (!d.yes and !try confirm(ctx, prompt)) {
		try announce(ctx, "Aborted.", .{});
		return;
	}

	_ = plugins_arr.orderedRemove(idx);
	const removed = if (rules_arr) |ra| mutate.removeTaggedRules(ra, d.plugin) else 0;

	try config.save(allocator, io, ctx.config_path, loaded.root().*);
	try regenComposition(ctx, plugins_arr);
	if (removed > 0) try rules_module.maybeReload(allocator, io, ctx.runtime_path, loaded);

	try announce(ctx, "Plugin '{s}' removed ({d} network rule(s) dropped).", .{ d.plugin, removed });
	try printRestartHint(ctx, "to unload its NixOS module");
}

// --- update -------------------------------------------------------------

fn cmdUpdate(ctx: Ctx, loaded: *config.Loaded, u: cli.UpdateArgs) !void {
	const allocator = ctx.allocator;
	const io = ctx.io;

	const plugins_arr = mutate.existingPluginsArray(loaded.root()) orelse {
		if (u.plugin) |p| die(allocator, io, "no such plugin '{s}'", .{p}, 65);
		try announce(ctx, "(no plugins)", .{});
		return;
	};
	if (u.plugin) |p| {
		if (mutate.findPlugin(plugins_arr, p) == null) {
			die(allocator, io, "no such plugin '{s}'", .{p}, 65);
		}
	} else if (plugins_arr.items.len == 0) {
		try announce(ctx, "(no plugins)", .{});
		return;
	}

	var changed = false;
	var rules_touched = false;
	var failed = false;

	// Versioning is per flake: resolve each distinct URL once per run and
	// apply the same pin to every plugin that came from it, so siblings
	// can't drift apart across an update.
	var resolved: std.ArrayList(struct { url: []const u8, meta: nix.Meta }) = .empty;
	defer {
		for (resolved.items) |*r| r.meta.deinit(allocator);
		resolved.deinit(allocator);
	}

	for (plugins_arr.items) |*item| {
		if (item.* != .object) continue;
		const n = mutate.entryField(item.object, "name") orelse {
			try warn(ctx, "skipping malformed plugin entry (no name)", .{});
			failed = true;
			continue;
		};
		if (u.plugin) |p| {
			if (!std.mem.eql(u8, p, n)) continue;
		}
		const url = mutate.entryField(item.object, "url") orelse {
			try warn(ctx, "{s}: malformed entry (no url); re-add it", .{n});
			failed = true;
			continue;
		};
		const attr = mutate.entryField(item.object, "attr");
		if (attr) |at| {
			if (!name_mod.isValidAttr(at)) {
				try warn(ctx, "{s}: malformed entry (bad attr); re-add it", .{n});
				failed = true;
				continue;
			}
		}
		const old_hash = mutate.entryField(item.object, "narHash") orelse "";

		const meta: *nix.Meta = blk: {
			for (resolved.items) |*r| {
				if (std.mem.eql(u8, r.url, url)) break :blk &r.meta;
			}
			var meta_out = nix.flakeMetadata(allocator, io, url) catch {
				die(allocator, io, "failed to run nix (is it on PATH?)", .{}, 70);
			};
			defer meta_out.deinit(allocator);
			if (!meta_out.ok) {
				try warn(ctx, "{s}: could not resolve '{s}': {s}", .{ n, url, nix.stderrTail(meta_out.stderr) });
				failed = true;
				break :blk null;
			}
			const m = nix.parseMetadata(allocator, meta_out.stdout) catch {
				try warn(ctx, "{s}: unexpected nix flake metadata output", .{n});
				failed = true;
				break :blk null;
			};
			try resolved.append(allocator, .{ .url = url, .meta = m });
			break :blk &resolved.items[resolved.items.len - 1].meta;
		} orelse continue;

		if (std.mem.eql(u8, meta.nar_hash, old_hash)) {
			try announce(ctx, "{s}: up to date ({s})", .{ n, pinLabel(meta) });
			continue;
		}

		archiveFlake(ctx, meta.locked_url);

		var rules_parsed: ?std.json.Parsed(std.json.Value) = null;
		defer if (rules_parsed) |*p| p.deinit();
		const incoming: []const std.json.Value = blk: {
			rules_parsed = evalRules(ctx, meta.locked_url, attr);
			const p = rules_parsed orelse break :blk &.{};
			break :blk p.value.array.items;
		};

		if (rulesOrNull(loaded)) |rules_arr| {
			const old_count = mutate.countTaggedRules(rules_arr, n);
			if (old_count > 0 or incoming.len > 0) {
				try announce(ctx, "{s}: network rules", .{n});
				for (rules_arr.items) |r| {
					if (mutate.ruleTag(r)) |tag| {
						if (std.mem.eql(u8, tag, n)) try printRuleLine(ctx, "-", r);
					}
				}
				for (incoming) |r| try printRuleLine(ctx, "+", r);
				_ = mutate.removeTaggedRules(rules_arr, n);
				try mutate.prependTaggedRules(loaded.treeAllocator(), rules_arr, n, incoming);
				rules_touched = true;
			}
		} else if (incoming.len > 0) {
			try warn(ctx, "{s}: instance is not in rules mode; skipping {d} suggested network rule(s)", .{ n, incoming.len });
		}

		try mutate.relockPlugin(loaded.treeAllocator(), item, .{
			.name = n,
			.url = url,
			.locked_url = meta.locked_url,
			.rev = meta.rev,
			.nar_hash = meta.nar_hash,
		});
		changed = true;
		try announce(ctx, "{s}: updated to {s}", .{ n, pinLabel(meta) });
	}

	if (changed) {
		try config.save(allocator, io, ctx.config_path, loaded.root().*);
		if (rules_touched) try rules_module.maybeReload(allocator, io, ctx.runtime_path, loaded);
	}
	// Regenerate even without changes: update doubles as the self-heal for
	// a missing/stale composition flake (it is a pure function of config).
	try regenComposition(ctx, plugins_arr);
	if (changed) try printRestartHint(ctx, "to load the updated NixOS modules");
	if (failed) std.process.exit(65);
}

// --- shared helpers ------------------------------------------------------

/// nix flake metadata + parse, with fatal errors on failure.
fn resolveFlake(ctx: Ctx, url: []const u8) nix.Meta {
	var out = nix.flakeMetadata(ctx.allocator, ctx.io, url) catch {
		die(ctx.allocator, ctx.io, "failed to run nix (is it on PATH?)", .{}, 70);
	};
	defer out.deinit(ctx.allocator);
	if (!out.ok) {
		die(ctx.allocator, ctx.io, "could not resolve flake '{s}':\n{s}", .{ url, nix.stderrTail(out.stderr) }, 65);
	}
	return nix.parseMetadata(ctx.allocator, out.stdout) catch {
		die(ctx.allocator, ctx.io, "unexpected nix flake metadata output for '{s}'", .{url}, 70);
	};
}

/// Pre-fetch the plugin and its transitive inputs into the store so later
/// (offline) starts resolve the pinned URLs locally. Failure is non-fatal:
/// the plugin still works, the first start just needs network.
fn archiveFlake(ctx: Ctx, locked_url: []const u8) void {
	var out = nix.flakeArchive(ctx.allocator, ctx.io, locked_url) catch return;
	defer out.deinit(ctx.allocator);
	if (!out.ok) {
		warn(ctx, "could not pre-fetch flake inputs (offline starts may fail): {s}", .{nix.stderrTail(out.stderr)}) catch {};
	}
}

/// Evaluate the plugin's suggested rules: cogboxPlugin."<attr>".networkRules,
/// with the flat legacy path cogboxPlugin.networkRules as fallback for the
/// default module. Returns the parsed tree when the output exists and is a
/// valid rule list; null when the flake doesn't declare it. Invalid rule
/// entries are fatal (the plugin is malformed).
fn evalRules(ctx: Ctx, locked_url: []const u8, attr: ?[]const u8) ?std.json.Parsed(std.json.Value) {
	const allocator = ctx.allocator;
	var out = nix.evalNetworkRules(allocator, ctx.io, locked_url, attr orelse "default") catch return null;
	if (!out.ok and attr == null and nix.stderrSaysMissingAttribute(out.stderr)) {
		// No cogboxPlugin.default -- fall back to the flat form.
		out.deinit(allocator);
		out = nix.evalNetworkRules(allocator, ctx.io, locked_url, null) catch return null;
	}
	defer out.deinit(allocator);
	if (!out.ok) {
		if (!nix.stderrSaysMissingAttribute(out.stderr)) {
			warn(ctx, "could not read cogboxPlugin.networkRules: {s}", .{nix.stderrTail(out.stderr)}) catch {};
		}
		return null;
	}

	const parsed = std.json.parseFromSlice(std.json.Value, allocator, out.stdout, .{}) catch {
		die(allocator, ctx.io, "cogboxPlugin.networkRules did not evaluate to JSON", .{}, 65);
	};
	if (parsed.value != .array) {
		die(allocator, ctx.io, "cogboxPlugin.networkRules must be a list of rule objects", .{}, 65);
	}
	for (parsed.value.array.items, 0..) |r, i| {
		mutate.validatePluginRule(r) catch |err| {
			const what: []const u8 = switch (err) {
				error.NotAnObject => "not an object",
				error.BadAction => "must have exactly one of allow/deny",
				error.InvalidCidr => "invalid CIDR",
				error.OutOfMemory => "out of memory",
			};
			die(allocator, ctx.io, "invalid cogboxPlugin.networkRules[{d}]: {s}", .{ i, what }, 65);
		};
	}
	return parsed;
}

/// Regenerate (or remove, when no plugins are left) the composition flake
/// from the current .plugins array. Pure function of config.json, rebuilt on
/// every mutation, so a crash between config save and this write self-heals
/// on the next plugin command.
fn regenComposition(ctx: Ctx, plugins_arr: *std.json.Array) !void {
	const allocator = ctx.allocator;
	if (plugins_arr.items.len == 0) {
		try compose.removeCompositionFlake(allocator, ctx.io, ctx.plugins_flake_dir);
		return;
	}

	var refs: std.ArrayList(compose.PluginRef) = .empty;
	defer refs.deinit(allocator);
	for (plugins_arr.items) |item| {
		if (item != .object) continue;
		const n = mutate.entryField(item.object, "name") orelse continue;
		const locked = mutate.entryField(item.object, "lockedUrl") orelse continue;
		const attr = mutate.entryField(item.object, "attr") orelse "default";
		// The attr lands quoted inside the generated flake; never emit one
		// that fails the safe-charset check (hand-edited config).
		if (!name_mod.isValidAttr(attr)) continue;
		try refs.append(allocator, .{ .name = n, .locked_url = locked, .attr = attr });
	}

	const rendered = compose.render(allocator, ctx.instance orelse "default", ctx.user_flake_dir, refs.items) catch |err| switch (err) {
		error.NoPlugins => {
			try compose.removeCompositionFlake(allocator, ctx.io, ctx.plugins_flake_dir);
			return;
		},
		else => return err,
	};
	defer allocator.free(rendered);
	try compose.writeCompositionFlake(allocator, ctx.io, ctx.plugins_flake_dir, rendered);
}

fn pinLabel(meta: *const nix.Meta) []const u8 {
	if (meta.rev) |r| return r[0..@min(r.len, 7)];
	const h = meta.nar_hash;
	const stripped = if (std.mem.startsWith(u8, h, "sha256-")) h[7..] else h;
	return stripped[0..@min(stripped.len, 8)];
}

fn printRuleLine(ctx: Ctx, sign: []const u8, r: std.json.Value) !void {
	if (r != .object) return;
	const p = rule.ruleAction(r.object) orelse return;
	const action = switch (p.action) {
		.allow => "allow",
		.deny => "deny",
	};
	if (rule.ruleComment(r.object)) |c| {
		try announce(ctx, "  {s} {s} {s}  # {s}", .{ sign, action, p.cidr, c });
	} else {
		try announce(ctx, "  {s} {s} {s}", .{ sign, action, p.cidr });
	}
}

fn printRestartHint(ctx: Ctx, why: []const u8) !void {
	if (!isRunning(ctx)) {
		try announce(ctx, "It will take effect at the next start.", .{});
		return;
	}
	if (ctx.instance) |n| {
		try announce(ctx, "Restart the instance ('cogbox restart -n {s}') {s}.", .{ n, why });
	} else {
		try announce(ctx, "Restart the instance ('cogbox restart') {s}.", .{why});
	}
}

fn isRunning(ctx: Ctx) bool {
	const pid_path = std.fs.path.join(ctx.allocator, &.{ ctx.runtime_path, "pid" }) catch return false;
	defer ctx.allocator.free(pid_path);

	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(ctx.io, pid_path, .{}) catch return false;
	defer file.close(ctx.io);
	var buf: [64]u8 = undefined;
	var reader = file.reader(ctx.io, &buf);
	const text = reader.interface.allocRemaining(ctx.allocator, .limited(64)) catch return false;
	defer ctx.allocator.free(text);
	const pid = std.fmt.parseInt(std.posix.pid_t, std.mem.trim(u8, text, " \t\r\n"), 10) catch return false;

	const sig_zero: std.posix.SIG = @enumFromInt(0);
	std.posix.kill(pid, sig_zero) catch return false;
	return true;
}

/// Interactive confirmation. Non-tty stdin auto-confirms, matching the
/// launcher's behavior for its own prompts (scripted/test use).
fn confirm(ctx: Ctx, prompt: []const u8) !bool {
	const stdin = std.Io.File.stdin();
	const tty = stdin.isTty(ctx.io) catch false;
	if (!tty) return true;

	const msg = try std.fmt.allocPrint(ctx.allocator, "{s} [y/N] ", .{prompt});
	defer ctx.allocator.free(msg);
	try writeStdout(ctx.io, msg);

	var buf: [256]u8 = undefined;
	var reader = stdin.readerStreaming(ctx.io, &buf);
	const line = (reader.interface.takeDelimiter('\n') catch return false) orelse return false;
	const trimmed = std.mem.trim(u8, line, " \t\r\n");
	return trimmed.len > 0 and (trimmed[0] == 'y' or trimmed[0] == 'Y');
}

fn rulesOrNull(loaded: *config.Loaded) ?*std.json.Array {
	return loaded.rules() catch null;
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

fn announce(ctx: Ctx, comptime fmt: []const u8, args: anytype) !void {
	const msg = try std.fmt.allocPrint(ctx.allocator, fmt ++ "\n", args);
	defer ctx.allocator.free(msg);
	try writeStdout(ctx.io, msg);
}

fn warn(ctx: Ctx, comptime fmt: []const u8, args: anytype) !void {
	const msg = try std.fmt.allocPrint(ctx.allocator, "cogbox plugin: warning: " ++ fmt ++ "\n", args);
	defer ctx.allocator.free(msg);
	try writeStderr(ctx.io, msg);
}

fn die(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype, code: u8) noreturn {
	const msg = std.fmt.allocPrint(allocator, "cogbox plugin: error: " ++ fmt ++ "\n", args) catch "cogbox plugin: error: (message too long)\n";
	writeStderr(io, msg) catch {};
	std.process.exit(code);
}
