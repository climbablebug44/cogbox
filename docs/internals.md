# Internals

How cogbox wires a per-user, per-instance sandbox out of a single prebuilt VM image. Useful when debugging, or when extending cogbox itself.

## Directory layout

Each instance has its own config dir under `~/.config/cogbox/instances/<name>/`. The default instance uses the reserved name `default`, so the config layout mirrors the data layout:

```
~/.config/cogbox/
  authorized_keys              # shared SSH keys (fallback for all instances)
  instances/
    default/
      config.json              # default instance settings (sshPort 2222)
      flake/
        flake.nix              # per-instance NixOS extensions (no-op default)
      plugins-flake/
        flake.nix              # GENERATED plugin composition (only with plugins)
      l7-ca/                   # per-instance L7 terminate CA (key never leaves host)
    work/
      config.json              # auto-generated with unique ports
      flake/
        flake.nix
      authorized_keys          # optional per-instance SSH keys
```

SSH keys fall back to the shared top-level `authorized_keys` unless a per-instance file exists.

Data (VM state, overlays) is stored per-instance under `~/.local/share/cogbox/instances/<name>/`. All instances are siblings, so a default-instance boot does not 9p-share named-instance state into the default guest:

```
~/.local/share/cogbox/
  instances/
    default/
      harness-overlay.img      # shared ext4 overlay for all harnesses
      .config/active-harnesses # newline-separated list of active harnesses
    work/
      harness-overlay.img
```

## Runtime directory and 9p shares

QEMU's 9p share sources must be absolute paths known at build time. The wrapper creates a per-instance symlink directory pointing to the user's actual paths, so the built VM image works for any user. Runtime state lives under `$XDG_RUNTIME_DIR/cogbox` (typically `/run/user/$UID/cogbox`); named instances append a `-<name>` suffix. Each has its own symlinks and PID lock:

```
$XDG_RUNTIME_DIR/cogbox[-<name>]/
  data/                  -> $COGBOX_DATA/instances/<name>
  claude-code-config     -> $COGBOX_CLAUDE_CONFIG
  claude-code-auth       -> $COGBOX_CLAUDE_AUTH
  opencode-config        -> $COGBOX_OPENCODE_CONFIG
  opencode-data          -> $COGBOX_OPENCODE_DATA
  codex-home             -> $COGBOX_CODEX_HOME
  .harness-stubs/        # empty stubs for inactive harnesses (so QEMU
                         # 9p sources resolve even when the host has no
                         # state for a given harness)
  console.sock           # guest serial console (Unix socket)
  monitor.sock           # QEMU HMP monitor (Unix socket)
  netfilter-rules        # rendered L4 + remap runtime rules
  l7-rules               # rendered L7 runtime rules
  console.log            # captured guest serial output
  cogbox.log             # daemon stdout/stderr (passt, QEMU warnings)
```

If `$XDG_RUNTIME_DIR` is unset and `/run/user/$UID` doesn't exist (no active logind session), the wrapper falls back to `/tmp/cogbox-runtime-$UID/` per the XDG spec.

## Launch-time patching

Runtime settings (vcpu, memory, ports) are applied by patching the microvm runner script's QEMU arguments at launch time. Settings that affect the guest (overlay sizes, SSH keys) are written to the instance's data directory where systemd services inside the VM pick them up at boot. The wrapper patches the QEMU runner's 9p share source paths to point at the instance-specific runtime directory, so the same VM image serves all instances.

Single-file injections (harness auth tokens, the L7 CA certificate) go through QEMU's `fw_cfg` instead of 9p: the wrapper passes `-fw_cfg name=opt/<tag>,file=<source>` and a guest systemd service copies the blob out of `/sys/firmware/qemu_fw_cfg` at boot.

## Guest extension re-exec

Two sources of guest extension share one mechanism, `--override-input userExtensions`:

1. With [plugins](plugins.md) installed (`.plugins` non-empty in config.json), the wrapper re-execs `nix run` with `userExtensions` pointing at the generated `plugins-flake/`, which composes every plugin module plus the user flake.
2. Otherwise, if the [per-instance flake](extensions.md) differs from the scaffold, `userExtensions` points at `flake/` directly. A pristine scaffold skips the re-exec entirely (the closure would be identical to the baked-in one, and re-evaluating the cogbox flake needs its inputs fetchable).

`COGBOX_REEXECED` breaks the loop after one hop. Non-launch verbs never re-exec.

## Network enforcement

In `rules` network mode, the wrapper loads a Zig shared library (`libnetfilter.so`) into passt via `LD_PRELOAD`. The library intercepts outbound socket calls (`connect`, `sendto`, `sendmsg`, `sendmmsg`) and checks destination addresses against the configured CIDR rules; denied connections receive `ENETUNREACH`. It initializes via `.init_array` (before `main()`) so all file I/O for rule loading completes before passt activates its seccomp-bpf sandbox. Rules hot-reload via `SIGUSR1`; the L7 proxy reloads via `SIGHUP`. Details, including the remap/SOCKS5 layer and the L7 proxy architecture, are in [network filtering](network-filtering.md).

The `cogbox rules`/`remap`/`l7`/`plugin` verbs all edit `config.json`, regenerate the runtime rules files, and signal the running processes, so policy changes take effect without restarting the VM. The CLI shares the on-disk rule format parser with the LD_PRELOAD filter, so the formats stay in sync.

## Host-side path overrides

Override where data lives on the host with environment variables:

| Variable | Default | Description |
|---|---|---|
| `COGBOX_DATA` | `$XDG_DATA_HOME/cogbox` (i.e. `~/.local/share/cogbox`) | Persistent data root. Each instance lives at `$COGBOX_DATA/instances/<name>/`. |
| `COGBOX_CLAUDE_CONFIG` | `$HOME/.claude` | Host claude-code config (overlay lower in VM) |
| `COGBOX_CLAUDE_AUTH` | `$HOME/.claude.json` | claude-code auth token for the VM |
| `COGBOX_OPENCODE_CONFIG` | `$XDG_CONFIG_HOME/opencode` | Host opencode config (overlay lower in VM) |
| `COGBOX_OPENCODE_DATA` | `$XDG_DATA_HOME/opencode` | Host opencode data (auth lives here as `auth.json`) |
| `COGBOX_CODEX_HOME` | `$HOME/.codex` | Host codex home (config, auth, sessions; overlay lower in VM) |

```sh
COGBOX_DATA=/mnt/fast/cogbox nix run .
```
