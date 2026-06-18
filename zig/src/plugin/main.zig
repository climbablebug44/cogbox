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
const l7_module = @import("l7_module");
const l7_rule = l7_module.rule;

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
	const l7_arr = l7RulesOrNull(loaded);
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(ctx.allocator);

	for (arr.?.items) |item| {
		if (item != .object) continue;
		const n = mutate.entryField(item.object, "name") orelse "?";
		const u = mutate.entryField(item.object, "url") orelse "?";
		const rules_n = (if (rules_arr) |ra| mutate.countTaggedRules(ra, n) else 0) +
			(if (l7_arr) |la| mutate.countTaggedRules(la, n) else 0);
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

	// A git/hg lock without a rev is a dirty worktree: the locked URL can't
	// carry a narHash (the fetcher would hand it to the remote) and has no
	// rev, so nothing pins it -- the guest module floats with the worktree
	// across restarts.
	if (meta.rev == null and nix.isGitOrHgUrl(meta.locked_url)) {
		try warn(ctx, "source tree is dirty: the lock has no rev, so the plugin floats with the worktree (commit, then `cogbox plugin update`, to pin)", .{});
	}

	const module_attr = attr orelse "default";
	switch (try nix.evalHasNixosModule(allocator, io, meta.locked_url, module_attr)) {
		.present => {},
		.missing => die(allocator, io, "plugin flake does not expose nixosModules.{s} (see docs/plugins.md)", .{module_attr}, 65),
		.failed => |stderr| die(allocator, io, "could not evaluate flake '{s}':\n{s}", .{ meta.locked_url, nix.stderrTail(stderr) }, 65),
	}

	archiveFlake(ctx, meta.locked_url);

	// Optional plugin contributions: L4 CIDR + L7 vhost rules, plus credential
	// injection requests -- one confirmation. Injection gets its own louder
	// section: granting a host-side credential is a different kind of trust
	// than a firewall rule.
	var l4_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (l4_parsed) |*p| p.deinit();
	const incoming_l4: []const std.json.Value = blk: {
		l4_parsed = evalRules(ctx, meta.locked_url, attr);
		const p = l4_parsed orelse break :blk &.{};
		break :blk p.value.array.items;
	};
	var l7_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (l7_parsed) |*p| p.deinit();
	const incoming_l7: []const std.json.Value = blk: {
		l7_parsed = evalL7Rules(ctx, meta.locked_url, attr);
		const p = l7_parsed orelse break :blk &.{};
		break :blk p.value.array.items;
	};
	var inject_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (inject_parsed) |*p| p.deinit();
	const incoming_inject: []const std.json.Value = blk: {
		inject_parsed = evalInjectSpecs(ctx, meta.locked_url, attr);
		const p = inject_parsed orelse break :blk &.{};
		break :blk p.value.array.items;
	};

	var merged = false;
	var merged_inject = false;
	const total = incoming_l4.len + incoming_l7.len + incoming_inject.len;
	if (total > 0) {
		if (rulesOrNull(loaded)) |rules_arr| {
			if (incoming_l4.len + incoming_l7.len > 0) {
				try announce(ctx, "Suggested network rules from '{s}':", .{plugin_name});
				for (incoming_l4) |r| try printRuleLine(ctx, "+", r);
				for (incoming_l7) |r| try printL7RuleLine(ctx, "+", r);
			}
			if (incoming_inject.len > 0) {
				try announce(ctx, "Credential injection requests from '{s}' (host-side; the secret stays OUT of the guest):", .{plugin_name});
				for (incoming_inject) |s| try printInjectLine(ctx, "+", s);
			}
			const prompt = try std.fmt.allocPrint(allocator, "Apply these {d} change(s) at the top of the lists?", .{total});
			defer allocator.free(prompt);
			if (!a.yes and !try confirm(ctx, prompt)) {
				try announce(ctx, "Aborted.", .{});
				return;
			}
			if (incoming_l4.len > 0) {
				try mutate.prependTaggedRules(loaded.treeAllocator(), rules_arr, plugin_name, incoming_l4);
			}
			if (incoming_l7.len > 0) {
				const l7_arr = try ensureL7Rules(loaded);
				try mutate.prependTaggedRules(loaded.treeAllocator(), l7_arr, plugin_name, incoming_l7);
			}
			if (incoming_inject.len > 0) {
				const inj_arr = try ensureInjectSpecs(loaded);
				try mutate.prependTaggedRules(loaded.treeAllocator(), inj_arr, plugin_name, incoming_inject);
				merged_inject = true;
			}
			merged = true;
		} else {
			try warn(ctx, "instance is not in rules mode; skipping {d} suggested change(s)", .{total});
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
	if (merged_inject) try printBindChecklist(ctx, incoming_inject);
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
	const l7_arr = l7RulesOrNull(loaded);
	const inject_arr = injectSpecsOrNull(loaded);
	const tagged = (if (rules_arr) |ra| mutate.countTaggedRules(ra, d.plugin) else 0) +
		(if (l7_arr) |la| mutate.countTaggedRules(la, d.plugin) else 0) +
		(if (inject_arr) |ia| mutate.countTaggedRules(ia, d.plugin) else 0);

	const prompt = try std.fmt.allocPrint(allocator, "Remove plugin '{s}' and its {d} contributed rule(s)/inject spec(s)?", .{ d.plugin, tagged });
	defer allocator.free(prompt);
	if (!d.yes and !try confirm(ctx, prompt)) {
		try announce(ctx, "Aborted.", .{});
		return;
	}

	_ = plugins_arr.orderedRemove(idx);
	var removed = if (rules_arr) |ra| mutate.removeTaggedRules(ra, d.plugin) else 0;
	removed += if (l7_arr) |la| mutate.removeTaggedRules(la, d.plugin) else 0;
	removed += if (inject_arr) |ia| mutate.removeTaggedRules(ia, d.plugin) else 0;

	try config.save(allocator, io, ctx.config_path, loaded.root().*);
	try regenComposition(ctx, plugins_arr);
	if (removed > 0) try rules_module.maybeReload(allocator, io, ctx.runtime_path, loaded);

	try announce(ctx, "Plugin '{s}' removed ({d} contributed entr(ies) dropped).", .{ d.plugin, removed });
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

		var l4_parsed: ?std.json.Parsed(std.json.Value) = null;
		defer if (l4_parsed) |*p| p.deinit();
		const incoming_l4: []const std.json.Value = blk: {
			l4_parsed = evalRules(ctx, meta.locked_url, attr);
			const p = l4_parsed orelse break :blk &.{};
			break :blk p.value.array.items;
		};
		var l7_parsed: ?std.json.Parsed(std.json.Value) = null;
		defer if (l7_parsed) |*p| p.deinit();
		const incoming_l7: []const std.json.Value = blk: {
			l7_parsed = evalL7Rules(ctx, meta.locked_url, attr);
			const p = l7_parsed orelse break :blk &.{};
			break :blk p.value.array.items;
		};
		var inject_parsed: ?std.json.Parsed(std.json.Value) = null;
		defer if (inject_parsed) |*p| p.deinit();
		const incoming_inject: []const std.json.Value = blk: {
			inject_parsed = evalInjectSpecs(ctx, meta.locked_url, attr);
			const p = inject_parsed orelse break :blk &.{};
			break :blk p.value.array.items;
		};

		if (rulesOrNull(loaded)) |rules_arr| {
			const old_l7 = l7RulesOrNull(loaded);
			const old_inject = injectSpecsOrNull(loaded);
			const old_count = mutate.countTaggedRules(rules_arr, n) +
				(if (old_l7) |la| mutate.countTaggedRules(la, n) else 0) +
				(if (old_inject) |ia| mutate.countTaggedRules(ia, n) else 0);
			if (old_count > 0 or incoming_l4.len + incoming_l7.len + incoming_inject.len > 0) {
				try announce(ctx, "{s}: contributed rules + inject specs", .{n});
				for (rules_arr.items) |r| {
					if (mutate.ruleTag(r)) |tag| {
						if (std.mem.eql(u8, tag, n)) try printRuleLine(ctx, "-", r);
					}
				}
				if (old_l7) |la| {
					for (la.items) |r| {
						if (mutate.ruleTag(r)) |tag| {
							if (std.mem.eql(u8, tag, n)) try printL7RuleLine(ctx, "-", r);
						}
					}
				}
				if (old_inject) |ia| {
					for (ia.items) |r| {
						if (mutate.ruleTag(r)) |tag| {
							if (std.mem.eql(u8, tag, n)) try printInjectLine(ctx, "-", r);
						}
					}
				}
				for (incoming_l4) |r| try printRuleLine(ctx, "+", r);
				for (incoming_l7) |r| try printL7RuleLine(ctx, "+", r);
				for (incoming_inject) |s| try printInjectLine(ctx, "+", s);
				_ = mutate.removeTaggedRules(rules_arr, n);
				try mutate.prependTaggedRules(loaded.treeAllocator(), rules_arr, n, incoming_l4);
				if (old_l7) |la| _ = mutate.removeTaggedRules(la, n);
				if (incoming_l7.len > 0) {
					const l7_arr = try ensureL7Rules(loaded);
					try mutate.prependTaggedRules(loaded.treeAllocator(), l7_arr, n, incoming_l7);
				}
				if (old_inject) |ia| _ = mutate.removeTaggedRules(ia, n);
				if (incoming_inject.len > 0) {
					const inj_arr = try ensureInjectSpecs(loaded);
					try mutate.prependTaggedRules(loaded.treeAllocator(), inj_arr, n, incoming_inject);
				}
				rules_touched = true;
			}
		} else if (incoming_l4.len + incoming_l7.len + incoming_inject.len > 0) {
			try warn(ctx, "{s}: instance is not in rules mode; skipping {d} suggested change(s)", .{ n, incoming_l4.len + incoming_l7.len + incoming_inject.len });
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

/// Evaluate one of the plugin's suggested-rule lists:
/// cogboxPlugin."<attr>".<leaf>, with the flat path cogboxPlugin.<leaf> as
/// fallback for the default module. Returns the parsed tree when the output
/// exists and is a JSON list; null when the flake doesn't declare it.
fn evalRuleList(ctx: Ctx, locked_url: []const u8, attr: ?[]const u8, leaf: []const u8) ?std.json.Parsed(std.json.Value) {
	const allocator = ctx.allocator;
	var out = nix.evalPluginRules(allocator, ctx.io, locked_url, attr orelse "default", leaf) catch return null;
	if (!out.ok and attr == null and nix.stderrSaysMissingAttribute(out.stderr)) {
		// No cogboxPlugin.default -- fall back to the flat form.
		out.deinit(allocator);
		out = nix.evalPluginRules(allocator, ctx.io, locked_url, null, leaf) catch return null;
	}
	defer out.deinit(allocator);
	if (!out.ok) {
		if (!nix.stderrSaysMissingAttribute(out.stderr)) {
			warn(ctx, "could not read cogboxPlugin.{s}: {s}", .{ leaf, nix.stderrTail(out.stderr) }) catch {};
		}
		return null;
	}

	const parsed = std.json.parseFromSlice(std.json.Value, allocator, out.stdout, .{}) catch {
		die(allocator, ctx.io, "cogboxPlugin.{s} did not evaluate to JSON", .{leaf}, 65);
	};
	if (parsed.value != .array) {
		die(allocator, ctx.io, "cogboxPlugin.{s} must be a list of rule objects", .{leaf}, 65);
	}
	return parsed;
}

/// L4 CIDR rules (cogboxPlugin.<attr>.networkRules), validated.
fn evalRules(ctx: Ctx, locked_url: []const u8, attr: ?[]const u8) ?std.json.Parsed(std.json.Value) {
	const parsed = evalRuleList(ctx, locked_url, attr, "networkRules") orelse return null;
	for (parsed.value.array.items, 0..) |r, i| {
		mutate.validatePluginRule(r) catch |err| {
			const what: []const u8 = switch (err) {
				error.NotAnObject => "not an object",
				error.BadAction => "must have exactly one of allow/deny",
				error.InvalidCidr => "invalid CIDR",
				error.OutOfMemory => "out of memory",
			};
			die(ctx.allocator, ctx.io, "invalid cogboxPlugin.networkRules[{d}]: {s}", .{ i, what }, 65);
		};
	}
	return parsed;
}

/// L7 vhost rules (cogboxPlugin.<attr>.l7Rules), validated with the same
/// constraints `l7 add` enforces.
fn evalL7Rules(ctx: Ctx, locked_url: []const u8, attr: ?[]const u8) ?std.json.Parsed(std.json.Value) {
	const parsed = evalRuleList(ctx, locked_url, attr, "l7Rules") orelse return null;
	for (parsed.value.array.items, 0..) |r, i| {
		mutate.validatePluginL7Rule(r) catch |err| {
			const what: []const u8 = switch (err) {
				error.NotAnObject => "not an object",
				error.BadAction => "must have exactly one of allow/deny",
				error.InvalidHost => "invalid host pattern",
				error.BadPath => "path must be a string starting with /",
				error.BadFlag => "tier flags must be booleans",
				error.ConflictingTier => "passthrough excludes terminate/path/insecure_upstream",
				error.OutOfMemory => "out of memory",
			};
			die(ctx.allocator, ctx.io, "invalid cogboxPlugin.l7Rules[{d}]: {s}", .{ i, what }, 65);
		};
	}
	return parsed;
}

/// Credential injection specs (cogboxPlugin.<attr>.inject), validated:
/// name-only, exact audience host, no inline secret material.
fn evalInjectSpecs(ctx: Ctx, locked_url: []const u8, attr: ?[]const u8) ?std.json.Parsed(std.json.Value) {
	const parsed = evalRuleList(ctx, locked_url, attr, "inject") orelse return null;
	for (parsed.value.array.items, 0..) |s, i| {
		mutate.validatePluginInjectSpec(s) catch |err| {
			const what: []const u8 = switch (err) {
				error.NotAnObject => "not an object",
				error.MissingHost => "missing/empty host",
				error.InvalidHost => "invalid host pattern",
				error.WildcardHost => "host must be exact (no wildcard)",
				error.BadStyle => "style must be \"bearer\" or \"cookie\"",
				error.BadStub => "stub must be a string",
				error.MissingSecret => "missing secret name",
				error.BadSecretName => "secret name must be [A-Za-z0-9_-] (max 64)",
				error.MissingCookieName => "cookie style requires a non-empty cookieName",
				error.BadCookieName => "invalid cookieName",
				error.InlineSecretForbidden => "may not inline a value or a path (path/cred_file/token/refresh/...); name a secret instead",
				error.OutOfMemory => "out of memory",
			};
			die(ctx.allocator, ctx.io, "invalid cogboxPlugin.inject[{d}]: {s}", .{ i, what }, 65);
		};
	}
	return parsed;
}

/// .network.l7.rules, created on demand (merge path; rules mode is already
/// established by the caller).
fn ensureL7Rules(loaded: *config.Loaded) !*std.json.Array {
	const net = try loaded.network();
	const l7 = try l7_module.ensureL7Object(net, loaded.treeAllocator());
	return &l7.object.getPtr("rules").?.array;
}

/// .network.l7.inject.specs, created on demand (merge path). Coerces a legacy
/// bool `.network.l7.inject` into the object form { enabled, specs } -- only
/// ever reached on an explicit `plugin add` that brings inject specs, so the
/// bool->object migration happens on a verb, never on a plain start/read.
fn ensureInjectSpecs(loaded: *config.Loaded) !*std.json.Array {
	const arena = loaded.treeAllocator();
	const net = try loaded.network();
	const l7 = try l7_module.ensureL7Object(net, arena);

	if (l7.object.getPtr("inject")) |inj| {
		if (inj.* == .bool) {
			const enabled = inj.bool;
			var obj: std.json.ObjectMap = .empty;
			try obj.put(arena, try arena.dupe(u8, "enabled"), .{ .bool = enabled });
			try obj.put(arena, try arena.dupe(u8, "specs"), .{ .array = std.json.Array.init(arena) });
			try l7.object.put(arena, try arena.dupe(u8, "inject"), .{ .object = obj });
		}
	} else {
		var obj: std.json.ObjectMap = .empty;
		try obj.put(arena, try arena.dupe(u8, "enabled"), .{ .bool = true });
		try obj.put(arena, try arena.dupe(u8, "specs"), .{ .array = std.json.Array.init(arena) });
		try l7.object.put(arena, try arena.dupe(u8, "inject"), .{ .object = obj });
	}

	const inj = l7.object.getPtr("inject").?;
	if (inj.* != .object) return error.InvalidJson;
	if (inj.object.getPtr("specs") == null) {
		try inj.object.put(arena, try arena.dupe(u8, "specs"), .{ .array = std.json.Array.init(arena) });
	}
	if (inj.object.getPtr("specs").?.* != .array) return error.InvalidJson;
	return &inj.object.getPtr("specs").?.array;
}

/// .network.l7.inject.specs if it already exists (del/update/count path);
/// null when inject is absent or still in the legacy bool form.
fn injectSpecsOrNull(loaded: *config.Loaded) ?*std.json.Array {
	const net = loaded.network() catch return null;
	const l7 = net.object.getPtr("l7") orelse return null;
	if (l7.* != .object) return null;
	const inj = l7.object.getPtr("inject") orelse return null;
	if (inj.* != .object) return null;
	const specs = inj.object.getPtr("specs") orelse return null;
	if (specs.* != .array) return null;
	return &specs.array;
}

/// .network.l7.rules if it already exists; never creates it (del/list path).
fn l7RulesOrNull(loaded: *config.Loaded) ?*std.json.Array {
	const net = loaded.network() catch return null;
	const l7 = net.object.getPtr("l7") orelse return null;
	if (l7.* != .object) return null;
	const r = l7.object.getPtr("rules") orelse return null;
	if (r.* != .array) return null;
	return &r.array;
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

fn printL7RuleLine(ctx: Ctx, sign: []const u8, r: std.json.Value) !void {
	if (r != .object) return;
	const p = l7_rule.ruleAction(r.object) orelse return;
	const action = switch (p.action) {
		.allow => "allow",
		.deny => "deny",
	};

	var suffix: std.ArrayList(u8) = .empty;
	defer suffix.deinit(ctx.allocator);
	var is_terminate = false;
	if (r.object.get("path")) |pv| {
		if (pv == .string) {
			try suffix.append(ctx.allocator, ' ');
			try suffix.appendSlice(ctx.allocator, pv.string);
			is_terminate = true;
		}
	}
	if (r.object.get("terminate")) |tv| {
		if (tv == .bool and tv.bool) is_terminate = true;
	}
	var is_insecure = false;
	if (r.object.get("insecure_upstream")) |iv| {
		if (iv == .bool and iv.bool) {
			is_insecure = true;
			is_terminate = true;
		}
	}
	var is_passthrough = false;
	if (r.object.get("passthrough")) |pv| {
		if (pv == .bool and pv.bool) is_passthrough = true;
	}
	if (is_passthrough) {
		try suffix.appendSlice(ctx.allocator, " [passthrough]");
	} else {
		if (is_terminate) try suffix.appendSlice(ctx.allocator, " [terminate]");
		if (is_insecure) try suffix.appendSlice(ctx.allocator, " [insecure]");
	}

	if (l7_rule.ruleComment(r.object)) |c| {
		try announce(ctx, "  {s} l7 {s} {s}{s}  # {s}", .{ sign, action, p.host, suffix.items, c });
	} else {
		try announce(ctx, "  {s} l7 {s} {s}{s}", .{ sign, action, p.host, suffix.items });
	}
}

fn printInjectLine(ctx: Ctx, sign: []const u8, s: std.json.Value) !void {
	if (s != .object) return;
	const host = blk: {
		const h = s.object.get("host") orelse return;
		if (h != .string) return;
		break :blk h.string;
	};
	const style = if (s.object.get("style")) |sv| (if (sv == .string) sv.string else "bearer") else "bearer";
	const secret = if (s.object.get("secret")) |sv| (if (sv == .string) sv.string else "?") else "?";
	if (std.mem.eql(u8, style, "cookie")) {
		const cn = if (s.object.get("cookieName")) |cv| (if (cv == .string) cv.string else "?") else "?";
		try announce(ctx, "  {s} inject {s} cookie({s}) secret={s}", .{ sign, host, cn, secret });
	} else {
		try announce(ctx, "  {s} inject {s} {s} secret={s}", .{ sign, host, style, secret });
	}
}

/// After merging inject specs, tell the operator exactly which secrets to bind
/// host-side. We don't (yet) check bound state here -- the point is the
/// command to run; an unbound secret simply renders no conf and injection
/// stays inert (fail closed) until bound.
fn printBindChecklist(ctx: Ctx, specs: []const std.json.Value) !void {
	if (specs.len == 0) return;
	try announce(ctx, "Bind these secrets host-side so injection takes effect (they stay OUT of the guest):", .{});
	for (specs) |s| {
		if (s != .object) continue;
		const secret = if (s.object.get("secret")) |sv| (if (sv == .string) sv.string else continue) else continue;
		const host = if (s.object.get("host")) |hv| (if (hv == .string) hv.string else "?") else "?";
		const kind = if (s.object.get("style")) |sv| (if (sv == .string) sv.string else "bearer") else "bearer";
		try announce(ctx, "  cogbox secret add {s} --from-file FILE --audience {s} --kind {s}", .{ secret, host, kind });
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
