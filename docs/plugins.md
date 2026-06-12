# Plugins

Plugins package the [per-instance extension pattern](extensions.md) into something installable: a git repo (or any flake source) that carries one or more NixOS modules plus, optionally, the firewall rules they need. `cogbox plugin add` is the CLI workflow for what previously required hand-editing the instance flake and hand-merging rules.

```sh
cogbox plugin add github:myorg/myplugin?dir=flake            # install into the default instance
cogbox plugin add 'github:org/observability#loki' -n work   # one module of a multi-plugin flake
cogbox plugin update                                        # re-resolve and re-pin everything
cogbox plugin del myplugin                                  # remove module + its firewall rules
```

## The contract

A plugin is a NixOS module exposed by a flake. One flake can carry any number of plugins, and any subset of them can be enabled per instance:

- `nixosModules.<attr>` -- the plugin module, selected by the URL fragment (`URL#attr`); a bare URL means `nixosModules.default`. Folded into the guest like the per-instance flake's module. `pkgs` resolves to cogbox's nixpkgs (the same caveat as the [extension scaffold](extensions.md#which-nixpkgs-pkgs-is): declare a differently-named input to use your own).
- `cogboxPlugin.<attr>.networkRules` (optional) -- a list of rule objects in `config.json`'s `.network.rules` schema for that module (L4 CIDR allows/denies). For the default module the flat form `cogboxPlugin.networkRules` also works.
- `cogboxPlugin.<attr>.l7Rules` (optional) -- a list of [L7 vhost rules](network-filtering.md#l7-host-filtering) in the `.network.l7.rules` schema: `allow`/`deny` keyed to a host pattern, plus the optional tier fields `terminate`, `passthrough`, `path`, `insecure_upstream` (same constraints as `cogbox l7 add`). Flat form `cogboxPlugin.l7Rules` for the default module. Prefer these over IP allows when the plugin's backend sits behind a shared LB or reverse proxy: an L7 allow reaches exactly that vhost, not its siblings on the same IP.

A minimal multi-plugin flake:

```nix
{
    outputs = { self }: {
        nixosModules.default = { pkgs, ... }: {
            environment.systemPackages = with pkgs; [ mimir-helpers ];
        };
        nixosModules.loki = { pkgs, ... }: {
            environment.systemPackages = with pkgs; [ loki-helpers ];
        };
        cogboxPlugin.networkRules = [
            { allow = "10.0.0.1/32"; comment = "mimir backend"; }
        ];
        cogboxPlugin.loki.l7Rules = [
            { allow = "loki.internal.example"; terminate = true; comment = "loki vhost on the shared LB"; }
        ];
    };
}
```

`FLAKE_URL` can be anything nix accepts: `github:owner/repo`, `git+https://...`, `path:/abs/dir`, with `?dir=` for flakes in a subdirectory. The `#attr` fragment is restricted to `[a-zA-Z0-9_-]` (it is interpolated into nix attr paths). Plugin names follow the instance-name grammar; `user` is reserved.

## Pinning and updates

Versioning is per flake, not per plugin. `add` resolves the URL with `nix flake metadata`, records the locked URL, rev, and narHash in `config.json` (`.plugins`), and runs `nix flake archive` so the plugin and its transitive inputs land in the local store -- subsequent starts resolve the pins offline.

Enabling another module of an already-installed flake **reuses the existing pin**, so all plugins from one flake stay at one rev; `update` resolves each distinct URL once and moves all of its plugins together. To hold a flake at a specific rev, pin it in the URL itself (`...?rev=<sha>` or `github:owner/repo/<sha>`) -- a distinct URL pins independently.

The clone-less model means there is no working copy to manage: `update` re-resolves the *original* URL (network) and re-pins only when the content changed.

A `.plugins` entry in `config.json` looks like:

```json
{
    "name": "loki",
    "url": "github:org/observability",
    "attr": "loki",
    "lockedUrl": "github:org/observability/<rev>?narHash=sha256-...",
    "rev": "<rev>",
    "narHash": "sha256-..."
}
```

`url` is exactly what you typed (minus the fragment) and is what `update` re-resolves; `lockedUrl` carries the rev and narHash so the composition flake's inputs are deterministic and offline-substitutable. `attr` is omitted for the default module. Dirty `path:` flakes have no `rev`; the narHash is the canonical change detector.

## Network rules

If the plugin declares network rules (L4 and/or L7) and the instance is in `rules` mode, `add` shows them all and asks once before merging (auto-confirmed with `-y` or when stdin is not a tty). Merged rules are inserted **at the top of their respective rule list** -- both lists are first-match-wins, and the seeded L4 ruleset is "RFC1918/bogon denies, then `allow 0.0.0.0/0`", so a plugin's allows for private backend IPs only work ahead of the denies. Review the prompt: a malicious plugin could suggest `allow 0.0.0.0/0`, or an L7 `allow *`.

Each merged rule carries a `"plugin": "<name>"` field, which is how `del` and `update` remove or replace exactly the rules that plugin brought in (your own edits to the same CIDRs or hosts are untouched). Rule changes hot-reload into a running instance through the same path as `cogbox rules`/`l7` edits; module changes need a `cogbox restart`. Note that merging a plugin's first `l7Rules` into an instance activates [L7 filtering](network-filtering.md#l7-host-filtering) for it, with everything that implies (80/443 funneled through the host-side proxy, QUIC/IPv6 denied).

Instances not in `rules` mode still get the module; the suggested rules are skipped with a warning.

## The composition flake

Plugin state is materialized as a generated flake at `~/.config/cogbox/instances/<name>/plugins-flake/flake.nix` (marked DO NOT EDIT; regenerated from `config.json` by every `plugin` command, `update` included -- run `cogbox plugin update` if it ever goes missing). It declares one pinned input per plugin plus the instance's own `flake/` as input `user`, and exposes a single `nixosModules.default` importing all of them, user module last:

```nix
# GENERATED by 'cogbox plugin' -- DO NOT EDIT.
{
	inputs = {
		user.url = "path:/home/me/.config/cogbox/instances/default/flake";
		"p-mimir".url = "github:org/observability/<rev>?narHash=sha256-...";
		"p-loki".url = "github:org/observability/<rev>?narHash=sha256-...";
	};

	outputs = { self, user, ... }@inputs: {
		nixosModules.default = {
			imports = [
				inputs."p-mimir".nixosModules."default"
				inputs."p-loki".nixosModules."loki"
				user.nixosModules.default
			];
		};
	};
}
```

At launch, when `.plugins` is non-empty, the wrapper points `--override-input userExtensions` at this flake instead of the plain instance flake (the [same re-exec mechanism](extensions.md#how-it-works) the manual extension path uses), so plugins and manual flake.nix edits compose. Two plugins from the same flake become two pinned inputs that resolve to the same store path. No `flake.lock` is generated: the composition is only ever consumed as an input, and rev+narHash-pinned inputs leave nothing for a lock file to decide.

Because the inputs are pinned by narHash and pre-fetched by `nix flake archive` at add time, restarts of a plugin-bearing instance work offline once the runner has been built.

## Trust

Adding a plugin evaluates third-party nix code at add time (pure eval, IFD disabled) and *builds* it into the guest at the next start. Treat `cogbox plugin add` like installing software: only add flakes you trust. The suggested-rules prompt exists so a plugin cannot silently widen the instance's egress policy.

## Plugin verb reference

| Form | Description |
|---|---|
| `cogbox plugin list [-n NAME]` | List installed plugins with their pinned revision and rule count |
| `cogbox plugin add FLAKE_URL[#ATTR] [--as PLUGIN] [-y] [-n NAME]` | Resolve, pin, and install a plugin. `#ATTR` selects `nixosModules.<attr>` (default: `default`). `--as` overrides the derived name (the attr, the `?dir=` basename, or the repo name); `-y` skips the rule-merge confirmation. |
| `cogbox plugin del PLUGIN [-y] [-n NAME]` | Remove a plugin and exactly the network rules it brought in |
| `cogbox plugin update [PLUGIN] [-n NAME]` | Re-resolve the original URL(s), re-pin, and replace the plugins' tagged rules. Without a name, updates every plugin. |
