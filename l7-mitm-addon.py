"""cogbox L7 terminate-tier enforcement addon for mitmproxy.

The Zig proxy (cogbox __l7proxy) hands terminate-marked hosts to mitmproxy
over SOCKS5, carrying the already-SSRF/CIDR-VETTED upstream IP as the CONNECT
target. mitmproxy mints a per-SNI leaf from the instance CA and decrypts; this
addon then, on every decrypted request:

  1. forces the upstream TLS SNI to the client's negotiated SNI -- we were
     handed a bare IP, so without this mitmproxy would send the IP as SNI and
     upstream cert validation would fail;
  2. enforces Host == SNI (anti-fronting / HTTP-2 cross-authority);
  3. allow/deny by host pattern + boundary-aware path prefix, first match,
     default deny -- mirroring filter.zig's L7RuleSet ENFORCEMENT semantics
     (tier selection -- terminate vs passthrough -- stays in the Zig proxy,
     so the `terminate`/`passthrough` rule tokens are ignored here).

Separately, on the upstream TLS handshake (`tls_start_server`), it disables
proxy->upstream cert verification for hosts explicitly marked `insecure` in
the rules -- the operator's per-host equivalent of `curl -k` on the
proxy<->upstream leg, for internal services with self-signed/mismatched certs.
Every other host keeps the default verification (fail closed).

SSRF/CIDR vetting is NOT repeated here; it stayed authoritative in the Zig
proxy. Rules are read from the same l7-rules file (path in COGBOX_L7_RULES)
and hot-reloaded on mtime change, so `cogbox l7 add/del` takes effect without
restarting mitmproxy.
"""

import json
import os
import urllib.parse

try:
    from mitmproxy import http, ctx
except ImportError:  # allow importing the pure helpers without mitmproxy
    http = None
    ctx = None

RULES_PATH = os.environ.get("COGBOX_L7_RULES", "")
# Host-side credential injection (keeps tokens out of the guest). Path to a
# JSON inject-conf written by cogbox-launch.sh; absent/empty => injection off,
# preserving the legacy "guest carries its own token end-to-end" behavior.
INJECT_CONF_PATH = os.environ.get("COGBOX_L7_INJECT_CONF", "")


class Rules:
    def __init__(self):
        self.mtime = None
        self.mode_terminate = False
        self.rules = []  # list of (action, host_pattern, path_or_None, insecure_bool)

    def maybe_reload(self):
        try:
            mtime = os.stat(RULES_PATH).st_mtime
        except OSError:
            self.rules, self.mode_terminate, self.mtime = [], False, None
            return
        if mtime == self.mtime:
            return
        self.mtime = mtime
        rules, mode_t = [], False
        try:
            with open(RULES_PATH) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    toks = line.split()
                    if toks[0] == "mode":
                        mode_t = len(toks) > 1 and toks[1] == "terminate"
                        continue
                    if toks[0] not in ("allow", "deny") or len(toks) < 2:
                        continue
                    action, host, path, insecure = toks[0], toks[1], None, False
                    for tk in toks[2:]:
                        if tk.startswith("/"):
                            path = tk
                        elif tk == "insecure":
                            insecure = True
                    rules.append((action, host, path, insecure))
        except OSError:
            pass
        self.rules, self.mode_terminate = rules, mode_t


def host_match(pattern, host):
    host = host.rstrip(".").lower()
    pattern = pattern.lower()
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        # >=1 subdomain label, matched at a dot boundary
        return host.endswith("." + suffix) and len(host) > len(suffix) + 1
    return host == pattern


def path_match(rule_path, req_path):
    # Boundary-aware left-anchored prefix (mirrors filter.pathPrefixMatches).
    if not req_path.startswith(rule_path):
        return False
    if len(req_path) == len(rule_path):
        return True
    if rule_path.endswith("/"):
        return True
    return req_path[len(rule_path)] == "/"


def normalize_path(p):
    # Strip query/fragment, percent-decode, collapse '.'/'..'/empty segments
    # (mirrors l7proxy/http.zig normalizePath, incl. trailing-slash handling).
    p = p.split("?", 1)[0].split("#", 1)[0]
    p = urllib.parse.unquote(p)
    if not p.startswith("/"):
        p = "/" + p
    trailing = p.endswith("/")
    parts = []
    for seg in p.split("/"):
        if seg == "" or seg == ".":
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    if not parts:
        return "/"
    out = "/" + "/".join(parts)
    if trailing:
        out += "/"
    return out


def evaluate(rules, host, path):
    h = host.rstrip(".")
    for action, pattern, rpath, _insecure in rules.rules:
        if not host_match(pattern, h):
            continue
        if rpath is not None and not path_match(rpath, path):
            continue
        return action
    return "deny"


def host_insecure(rules, host):
    """True if `host` matches an `allow` rule flagged insecure-upstream.

    Upstream cert verification is a host-level property (it governs the
    proxy<->upstream TLS leg, independent of the request path), so we match on
    the host pattern only -- the `request` hook already enforced allow + path.
    """
    h = host.rstrip(".")
    for action, pattern, rpath, insecure in rules.rules:
        if action == "allow" and insecure and host_match(pattern, h):
            return True
    return False


RULES = Rules()


# --- Host-side credential injection ---------------------------------------
# The terminate tier decrypts a harness's TLS to its model-provider host, so
# this addon can REPLACE the request's auth header with the real token read
# from a host-side cred file -- the guest then only ever holds a stub. The
# real (long-lived refresh) token never enters the sandbox. The inject-conf
# and cred files live host-side; nothing here is shared into the guest, and
# tokens are never logged.

ANTHROPIC_OAUTH_BETA = "oauth-2025-04-20"


def json_path_get(obj, dotted):
    """Fetch a string leaf at a dotted path (e.g. claudeAiOauth.accessToken).
    Returns the string, or None if any segment is missing or the leaf isn't a
    string. Mirrors the cred-file shapes in docs/harnesses.md."""
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur if isinstance(cur, str) else None


def merge_beta(existing, marker):
    """Add `marker` to a comma-separated anthropic-beta header if absent,
    preserving any feature betas the guest already sent (order-stable)."""
    toks = [t.strip() for t in (existing or "").split(",") if t.strip()]
    if marker not in toks:
        toks.append(marker)
    return ",".join(toks)


def apply_injection(headers, style, token, account_id=None):
    """Mutate `headers` in place to carry the real `token` per `style`. Always
    SET (never append) the credential header so a guest-supplied placeholder is
    overwritten and never reaches the upstream as-is. `headers` is a mitmproxy
    Headers multidict (case-insensitive) or any dict-like with the same API."""
    if style == "anthropic-oauth":
        headers["authorization"] = "Bearer " + token
        if "x-api-key" in headers:
            del headers["x-api-key"]
        headers["anthropic-beta"] = merge_beta(
            headers.get("anthropic-beta"), ANTHROPIC_OAUTH_BETA
        )
    elif style == "anthropic-apikey":
        headers["x-api-key"] = token
        if "authorization" in headers:
            del headers["authorization"]
    elif style == "openai-chatgpt":
        headers["authorization"] = "Bearer " + token
        if account_id:
            headers["chatgpt-account-id"] = account_id
    else:  # "bearer" and any unknown style: plain Bearer
        headers["authorization"] = "Bearer " + token


class CredStore:
    """Maps a request host to the real token read from a host cred file,
    hot-reloaded on mtime change -- mirroring Rules.maybe_reload(). So when the
    refresh sidecar (or the host's own CLI) rotates the on-disk access token,
    the next request picks it up with no addon restart. Refresh tokens are
    never read here -- only the short-lived access token / account id."""

    def __init__(self, path):
        self.path = path
        self.conf_mtime = None
        self.specs = {}  # host(lower) -> spec dict
        self._file_cache = {}  # cred_file -> (mtime, parsed_json | None)

    def _load_conf(self):
        if not self.path:
            self.specs, self.conf_mtime = {}, None
            return
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError:
            self.specs, self.conf_mtime = {}, None
            return
        if mtime == self.conf_mtime:
            return
        self.conf_mtime = mtime
        specs = {}
        try:
            with open(self.path) as f:
                data = json.load(f)
            for spec in data:
                host = (spec.get("host") or "").rstrip(".").lower()
                if host and spec.get("cred_file") and spec.get("token_path"):
                    specs[host] = spec
        except (OSError, ValueError):
            specs = {}
        self.specs = specs

    def _read_json(self, cred_file):
        try:
            mtime = os.stat(cred_file).st_mtime
        except OSError:
            self._file_cache.pop(cred_file, None)
            return None
        cached = self._file_cache.get(cred_file)
        if cached is not None and cached[0] == mtime:
            return cached[1]
        try:
            with open(cred_file) as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = None
        self._file_cache[cred_file] = (mtime, data)
        return data

    def spec_for(self, host):
        self._load_conf()
        return self.specs.get(host.rstrip(".").lower())

    def value_for(self, spec, path_key):
        dotted = spec.get(path_key)
        if not dotted:
            return None
        data = self._read_json(spec.get("cred_file"))
        if data is None:
            return None
        return json_path_get(data, dotted)


CREDS = CredStore(INJECT_CONF_PATH)


def _deny(flow, msg):
    flow.response = http.Response.make(
        403, ("cogbox-l7: " + msg + "\n").encode(), {"Content-Type": "text/plain"}
    )


def request(flow):
    RULES.maybe_reload()

    sni = flow.client_conn.sni
    # We connected to the upstream by vetted IP, so use the client's SNI for
    # the upstream TLS handshake + cert validation.
    if sni:
        flow.server_conn.sni = sni

    host = flow.request.pretty_host
    if sni and host and sni.rstrip(".").lower() != host.rstrip(".").lower():
        _deny(flow, "host/sni mismatch")
        return

    path = normalize_path(flow.request.path)
    if evaluate(RULES, host, path) != "allow":
        _deny(flow, "denied")
        return

    # Credential injection runs LAST, only on an allowed + host==SNI request,
    # so a denied/fronted request never gets a real token stamped on it.
    spec = CREDS.spec_for(host)
    if spec is not None:
        token = CREDS.value_for(spec, "token_path")
        if not token:
            # Injection is configured for this host but the host-side token is
            # unreadable: fail closed rather than forward the guest's stub as
            # if it were real auth. (Atomic-rename writeback means this is not
            # a transient race -- the file is always whole.)
            _deny(flow, "credential unavailable")
            return
        account_id = CREDS.value_for(spec, "account_id_path")
        apply_injection(
            flow.request.headers, spec.get("style", "bearer"), token, account_id
        )


def tls_start_server(data):
    """Per-host upstream cert verification toggle.

    mitmproxy's built-in TlsConfig decides proxy->upstream verification purely
    from the global `ssl_insecure` option, and -- because ScriptLoader is
    registered ahead of TlsConfig -- this hook runs FIRST, before that option
    is read. We flip it per connection keyed on the client SNI so that only
    hosts explicitly marked `insecure` skip upstream verification; every other
    flow keeps the default VERIFY_PEER. We (re)assign on every call, so the
    toggle never leaks to a subsequent connection.

    Fail-safe: if a future mitmproxy ever ran this hook AFTER TlsConfig, the
    option flip would simply have no effect on the already-built connection --
    insecure hosts would 502 (verification stays on), never silently weaker.
    """
    if ctx is None:
        return
    RULES.maybe_reload()
    client = data.context.client if data.context else None
    sni = (client.sni if client else None) or getattr(data.conn, "sni", None) or ""
    want = bool(sni) and host_insecure(RULES, sni)
    if ctx.options.ssl_insecure != want:
        ctx.options.ssl_insecure = want
