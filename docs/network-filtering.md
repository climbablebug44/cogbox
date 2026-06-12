# Network filtering

cogbox restricts what the sandboxed agent can reach on the network. Filtering is layered: a network *mode* selects the overall posture, L4 CIDR rules filter by destination IP, a remap table can redirect TCP flows into a proxy, and L7 rules filter individual virtual hosts behind shared IPs. This document covers all of it, including the threat model and the enforcement internals.

- [Network modes](#network-modes)
- [L4 CIDR rules](#l4-cidr-rules)
- [TCP destination remap](#tcp-destination-remap)
- [L7 host filtering](#l7-host-filtering)

## Network modes

Three modes are available. `full` and `rules` use [passt](https://passt.top/) for networking, which supports all IP protocols including ICMP. `none` uses QEMU's built-in SLIRP with `restrict=on`. None of them need extra privileges.

| Mode | Posture |
|---|---|
| `full` | Unrestricted networking via passt. All IP protocols (TCP, UDP, ICMP, etc.) work. |
| `none` | SLIRP `restrict=on` blocks all outbound traffic. SSH and HTTP port forwards from the host still work. |
| `rules` (default) | Ordered CIDR allow/deny rules enforced via an LD_PRELOAD filter on passt. First match wins; default policy is deny. All IP protocols are subject to the rules. |

The mode is chosen at init (`--network MODE`) and stored in `config.json` as `.network`: the string `"full"` or `"none"`, or an object `{"rules": [...]}` for rules mode.

Note for `none` mode: every supported harness needs access to a model provider's API. In `none` mode they won't function unless API access is provided through another channel (e.g. SSH port forwarding).

## L4 CIDR rules

### The seeded ruleset

A new rules-mode instance is seeded with deny rules for private (RFC1918), link-local (including cloud metadata `169.254.169.254`), and bogon ranges, followed by `allow 0.0.0.0/0` for the public internet. Net effect: working internet out of the box, with LAN and metadata services blocked. Rule objects may optionally carry a `comment` field; it's preserved through edits and shown by `rules list` but ignored by the filter.

```json
{
    "network": {
        "rules": [
            {"deny":  "0.0.0.0/8",       "comment": "this network (RFC 1122)"},
            {"deny":  "10.0.0.0/8",      "comment": "RFC1918 private"},
            {"deny":  "100.64.0.0/10",   "comment": "carrier-grade NAT (RFC 6598)"},
            {"deny":  "169.254.0.0/16",  "comment": "link-local incl. cloud metadata 169.254.169.254"},
            {"deny":  "172.16.0.0/12",   "comment": "RFC1918 private"},
            {"deny":  "192.0.0.0/24",    "comment": "IETF protocol assignments (RFC 6890)"},
            {"deny":  "192.0.2.0/24",    "comment": "TEST-NET-1 documentation (RFC 5737)"},
            {"deny":  "192.168.0.0/16",  "comment": "RFC1918 private"},
            {"deny":  "198.18.0.0/15",   "comment": "benchmark testing (RFC 2544)"},
            {"deny":  "198.51.100.0/24", "comment": "TEST-NET-2 documentation (RFC 5737)"},
            {"deny":  "203.0.113.0/24",  "comment": "TEST-NET-3 documentation (RFC 5737)"},
            {"deny":  "224.0.0.0/4",     "comment": "multicast (RFC 5771)"},
            {"deny":  "240.0.0.0/4",     "comment": "reserved/broadcast incl. 255.255.255.255"},
            {"allow": "0.0.0.0/0",       "comment": "public internet"}
        ]
    }
}
```

### How rules are evaluated and edited

Rules are evaluated top-to-bottom on every outbound packet; the first matching rule wins, and a packet that matches no rule is denied. **Position matters**: a rule only fires if no earlier rule matches the same address first.

The `rules add` command **appends by default** -- the new rule lands at the bottom of the list, after the seeded `allow 0.0.0.0/0` catch-all. That position is almost always wrong: the catch-all matches everything public, so an appended `deny` or `allow` for a public address is unreachable. Pass `--at N` to insert at 1-based position `N`, shifting existing rules down. To see current positions, run `rules list`.

Two practical patterns:

**Allow a specific LAN host** -- insert the allow ahead of the matching deny. Use `rules list` to find the right index for the deny:

```sh
cogbox rules list
# ...
# 8: deny 192.168.0.0/16  # RFC1918 private
# ...
cogbox rules add allow 192.168.1.50/32 --at 8
```

**Block a specific public address** -- insert the deny ahead of the trailing `allow 0.0.0.0/0`. Easiest is `--at 1` so it runs before all existing rules:

```sh
cogbox rules add deny 8.8.8.8/32 --at 1
```

Implicit rules (applied before user rules, not configurable):

- **DNS (port 53)** is always allowed so hostname resolution works
- **Loopback (127.0.0.0/8, ::1)** is always denied to prevent the VM from accessing host services via passt's gateway-to-loopback mapping

### Rule format

CIDR rules accept optional `tcp`/`udp` and `:PORT` qualifiers when hand-edited in `config.json` (the CLI currently only emits the unqualified form). The runtime file format is:

```
allow 10.0.0.0/8                 # any proto, any port
allow tcp 10.0.0.0/8             # tcp, any port
deny  0.0.0.0/0:25               # any proto, port 25
allow tcp 0.0.0.0/0:443          # tcp, port 443
```

### Rules verb reference

| Form | Description |
|---|---|
| `cogbox rules list [-n NAME]` | List current rules with 1-based indices |
| `cogbox rules add allow\|deny CIDR [--at N] [-n NAME]` | Add a rule. Appends by default; `--at N` inserts at 1-based position N. |
| `cogbox rules del INDEX [-n NAME]` | Delete a rule by index |
| `cogbox rules set [-n NAME]` | Replace all rules from stdin |

If the instance is running, rule changes take effect immediately: the runtime rules file is regenerated and passt receives `SIGUSR1` to reload.

### Enforcement internals

The filter works by intercepting passt's outbound `connect()`, `sendto()`, `sendmsg()`, and `sendmmsg()` syscalls. Since passt is the VM's only network path, this is a complete enforcement point. The filter is a Zig shared library (`libnetfilter.so`) loaded via `LD_PRELOAD`; it initializes via `.init_array` (before `main()`) so that all file I/O for rule loading completes before passt activates its seccomp-bpf sandbox. Denied connections receive `ENETUNREACH`.

The `cogbox rules` subcommands edit `config.json`, regenerate the runtime rules file, and signal the running passt, so rule changes take effect without restarting the VM. The CLI shares the on-disk rule format parser with the LD_PRELOAD filter, so the formats stay in sync.

One known boundary: traffic handled internally by passt (ARP, DHCP, gateway ping responses) never reaches the intercepted syscalls and is not subject to user rules. The implicit loopback deny prevents access to host services via the passt gateway.

## TCP destination remap

A second, independent table redirects outbound TCP connects from specific `(cidr, port)` destinations to a loopback target on the host. When a match fires, the shim drives a SOCKS5 v5 CONNECT handshake on the connecting fd, carrying the original `(ip, port)` to the target proxy -- so the downstream proxy sees the guest's real intended destination. v1 supports TCP only; the target must be a single host.

| Form | Description |
|---|---|
| `cogbox remap list [-n NAME]` | List current remap rules with 1-based indices |
| `cogbox remap add FROM TO [--at N] [-n NAME]` | Add a rule. `FROM` and `TO` are single quoted args, e.g. `"tcp 0.0.0.0/0:443"` and `"tcp 127.0.0.1:18080"`. |
| `cogbox remap del INDEX [-n NAME]` | Delete a rule by index |
| `cogbox remap set [-n NAME]` | Replace all rules from stdin (one `FROM -> TO` per line) |

Example: send every outbound TCP/443 connection through a SOCKS5 proxy running on `127.0.0.1:18080`:

```sh
cogbox remap add "tcp 0.0.0.0/0:443" "tcp 127.0.0.1:18080"
```

The CIDR + remap tables share one runtime rules file; edits to either verb rewrite both sections cleanly without dropping the other layer. Like L4 rules, remap edits hot-reload into a running instance.

The remap table is also the substrate for [L7 host filtering](#l7-host-filtering): enabling L7 auto-injects remaps that funnel guest web traffic into the host-side proxy.

## L7 host filtering

L4 rules whitelist a destination *IP*. That is not enough when several virtual hosts share one load-balancer IP: allowing the LB lets the sandbox reach **every** backend on it by guessing the `Host`/SNI. The `l7` layer whitelists individual vhosts instead.

### The model

When `.network.l7` has any rule, cogbox starts a small host-side proxy and funnels **all** guest 80/443 traffic to it (via an auto-injected `remap`). For each connection the proxy reads the vhost from the TLS **SNI** (HTTPS) or **Host** header (HTTP), checks it against your `allow`/`deny` list (first match, default deny; patterns are exact / `*.suffix` / `*`), and on allow **re-resolves that name itself, host-side**, then splices the bytes through. Re-resolution is the point: the guest's chosen IP is discarded, so

- allowing one vhost does **not** expose siblings on the same IP, and
- DNS-based load balancing (rotating/shared IPs) keeps working, because the proxy always resolves the allowed name fresh.

```sh
cogbox l7 add allow api.example.com        # only this vhost on its LB
```

L7 rules live under `.network.l7` and require the instance's network mode to be `rules`. Edits hot-reload the proxy (`SIGHUP`) and passt (`SIGUSR1`).

### How L7 composes with L4

The proxy re-resolves the allowed name **host-side** (it never trusts the guest's IP or a guest-supplied Host/SNI as a destination), so an L7 rule refines the L4 IP policy by name. For each re-resolved IP, on funneled web traffic:

| vhost vs. L7 rules | decision |
|---|---|
| explicitly **allowed** | **dial** -- supersedes an L4 IP *block* |
| explicitly **denied** | **drop** -- supersedes an L4 IP *allow* |
| **not in any rule** | defer to L4 (dial if the IP is allowed, drop if blocked) |

...and a **non-overridable hard floor** (loopback, this-network `0.0.0.0/8`, and link-local incl. cloud metadata `169.254.169.254`) is *always* dropped, even for an allowed vhost.

**Path constraints fail closed.** When an `allow` rule names a host but adds a path prefix (`allow api.example.com /v1/`), a request to that host on an *uncovered* path (e.g. `/v2/`) is **dropped**, not deferred to L4 -- otherwise the constraint would be silently bypassed whenever the IP is independently L4-allowed (the usual "allow the internet at L4, restrict vhosts at L7" setup). A `deny` rule with a path (`deny api.example.com /admin/`) only blocks that prefix and leaves other paths to L4, since you're carving out a hole, not whitelisting. On HTTPS this is enforced by the terminate tier; on cleartext HTTP the proxy enforces it inline from the request line.

So to reach an internal vhost on a private LB, you just allow the **name** -- no L4 IP rule, and you never open that IP for anything else:

```sh
# 10.10.10.10 hosts a.internal and b.internal; reach ONLY a.internal:
cogbox l7 add allow a.internal          # leave 10.10.10.10 blocked (default deny 10/8)
# a.internal -> allowed -> dialed;  b.internal -> unlisted -> IP blocked -> dropped
```

Conversely, sibling isolation only applies where the LB's **IP is blocked**. On a public LB reachable via `allow 0.0.0.0/0`, an unlisted sibling falls back to L4 and is allowed; block the IP (or `l7 add deny sibling`) to restrict it.

> **Wildcard caveat.** A `*.suffix` allow trusts that whole domain's DNS -- if an attacker can create `evil.suffix` pointing at an internal IP, it would be dialed (metadata/loopback/link-local still blocked by the hard floor). Exact-name allows have no such exposure (you control that name's DNS); only wildcard a suffix whose DNS you trust.

### Tiers: terminate and passthrough

There are two tiers, chosen per host. **Terminate is the default**:

- **Terminate (default)** -- the proxy MITMs the host's TLS via a per-instance CA so it can enforce `Host == SNI` and URL paths -- see [the terminate tier](#the-terminate-tier). This breaks cert-pinned clients, so opt those out with `--passthrough`.
- **Passthrough** (`--passthrough` per host, or `l7 mode passthrough` for the whole instance) -- TLS is *not* intercepted, so cert pinning is preserved, but the proxy trusts the SNI it sees: a shared ingress that routes by the inner `Host:`/HTTP-2 `:authority` could still be steered to a sibling on a single connection, and URL paths can't be inspected on HTTPS.

**Harness API endpoints auto-passthrough.** Because terminate is the default, the in-guest agents' own control-plane endpoints (`api.anthropic.com`, `api.openai.com`, `chatgpt.com`, ...) are automatically kept in passthrough, so the harnesses keep working out of the box (notably rustls clients that may not honor the injected CA) and their API tokens stay end-to-end. An explicit `--terminate` on such a host overrides it; provider-agnostic harnesses (e.g. opencode) should `--passthrough` their configured provider host.

### The terminate tier

By default every allowed host is routed through a TLS-terminating proxy ([mitmproxy](https://mitmproxy.org/)) so cogbox can see inside HTTPS (use `--passthrough` to opt a host out, or a `--path` prefix to add path enforcement). This closes the passthrough gaps:

- enforces `Host == SNI` (a connection whose decrypted `Host:`/`:authority` disagrees with the negotiated SNI is rejected with `403`), and
- enforces **URL path prefixes** (`--path /v1/`), boundary-aware and applied to the normalized, percent-decoded path.

```sh
cogbox l7 add allow git.example.com --path /myorg/   # only this path prefix
cogbox l7 mode terminate                             # terminate every L7 host
```

How it works: every rules-mode instance runs mitmproxy with a **per-instance CA** (auto-generated under `~/.config/cogbox/instances/<name>/l7-ca/`, key stays host-side at mode `0600`) -- started at every boot, even with no L7 rules yet, so that hot-added rules terminate immediately and the CA is in the guest trust store from the start (it can only be injected at launch). The CA **certificate** (never the key) is injected into the guest at boot via `fw_cfg` and assembled into `/run/cogbox/ca-bundle.crt`; the harness launchers and login shells point `SSL_CERT_FILE`/`CURL_CA_BUNDLE`/`GIT_SSL_CAINFO`/`REQUESTS_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS` at it. The Zig proxy still does all SSRF/CIDR vetting and hands mitmproxy only a pre-vetted IP; mitmproxy mints a per-SNI leaf, applies the rules, and re-originates upstream TLS validated against the *real* system trust.

**Upstream cert verification (`--insecure-upstream`).** Because the proxy re-originates TLS, it -- not the guest -- validates the upstream certificate (against the real system trust, by SNI). The guest's `curl -k` can't relax this: `-k` only covers the guest<->proxy leg, which is the always-valid minted leaf. So a terminate host whose upstream has a self-signed or name-mismatched cert fails with mitmproxy's `502 Bad Gateway -- Certificate verify failed` (common for internal services). Mark such a host `--insecure-upstream` to skip verification on **its** proxy<->upstream leg only -- the operator's per-host equivalent of `curl -k`:

```sh
cogbox l7 add allow internal.svc --insecure-upstream    # MITM, don't verify its upstream cert
cogbox l7 add allow internal.svc --path /v1/ --insecure-upstream
```

Verification stays **on** for every other host (fail closed); the flag is a deliberate per-target exception. If you only need to *whitelist* a bad-cert host (no path/`Host` enforcement), prefer passthrough instead -- there the guest keeps end-to-end TLS and its own `curl -k`.

Terminate caveats:

- This is an **intentional MITM**: for terminate hosts the proxy sees plaintext (host-process-only, never persisted). Cert pinning is **broken** for those hosts -- clients that pin a specific cert/CA (some Go and mobile apps) will fail; leave them on passthrough.
- Clients that ship their **own** trust store and ignore the OS store + env vars (e.g. Rust `rustls` pinned to the bundled `webpki-roots` crate) won't trust the instance CA. The `codex` harness is Rust and uses `rustls`, but it links `rustls-native-certs`/`native-tls` and references `SSL_CERT_FILE` with **no** bundled `webpki-roots` (per binary inspection of 0.139.0), so it loads system roots and should honor the injected CA -- worth a quick runtime check. Passthrough is unaffected regardless.
- HTTP/2 to the client is disabled (http/1.1 only) so every request's authority is checked against the SNI.

### Per-instance ports

The proxy and its mitmproxy terminate backend bind **per-instance** loopback ports (a contiguous triple from each instance's `l7PortBase` in config.json, default 18443: TLS funnel / HTTP funnel / terminate hop), so several L7-enabled instances run on one host without one instance's guest traffic funnelling into another's proxy. Named instances auto-assign disjoint triples at init. If the proxy can't bind its ports (a stale proxy or another process holding them), `cogbox start` **aborts** rather than booting a VM whose funnel can't reach its proxy.

### L7 verb reference

| Form | Description |
|---|---|
| `cogbox l7 list [-n NAME]` | List current L7 rules and the instance mode |
| `cogbox l7 add allow\|deny HOST [--passthrough \| --path P \| --terminate [--insecure-upstream]] [--at N] [-n NAME]` | Add a rule. `HOST` is an exact name, a `*.suffix` wildcard, or a bare `*`. Hosts **terminate by default**; `--passthrough` opts a host out (SNI-only, for cert-pinned clients). `--path`/`--terminate` force terminate; `--insecure-upstream` skips upstream cert verification (implies terminate). |
| `cogbox l7 del INDEX [-n NAME]` | Delete a rule by index |
| `cogbox l7 set [-n NAME]` | Replace all rules from stdin (one `allow\|deny HOST` per line) |
| `cogbox l7 mode passthrough\|terminate [-n NAME]` | Set the instance default tier (terminate if unset) |

```sh
cogbox l7 add allow api.example.com                       # terminate (default)
cogbox l7 add allow pinned.example.com --passthrough      # SNI-only (cert pinned)
cogbox l7 add allow api.example.com --path /v1/           # terminate + path
cogbox l7 add deny '*' --at 1                             # explicit default-deny for vhosts
```

### L7 caveats

Documented, not silently assumed safe:

- **QUIC / UDP-443 and all guest IPv6** are denied while L7 is active (the funnel is IPv4/TCP-only), so clients fall back to inspectable IPv4 TCP. DNS (port 53) still works.
- Loopback, this-network, and link-local/metadata vhosts are never reachable through the proxy (the hard floor) -- consistent with the sandbox's LAN posture for those specific ranges.
