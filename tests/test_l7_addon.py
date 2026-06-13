#!/usr/bin/env python3
"""Parity unit tests for the mitmproxy L7 addon's pure helpers.

These must match filter.zig's L7 semantics (host pattern, boundary-aware path
prefix, path normalization) so HTTPS-terminate enforcement behaves identically
to the Zig proxy's HTTP/passthrough enforcement. Run: python3 test_l7_addon.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON = os.path.join(HERE, "..", "l7-mitm-addon.py")
spec = importlib.util.spec_from_file_location("l7addon", ADDON)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)


# host_match: exact / *.suffix / *
check(m.host_match("vhost-a.test", "vhost-a.test"), "exact")
check(m.host_match("vhost-a.test", "VHOST-A.TEST"), "case-insensitive")
check(m.host_match("vhost-a.test", "vhost-a.test."), "trailing dot")
check(not m.host_match("vhost-a.test", "vhost-b.test"), "sibling denied")
check(m.host_match("*.cdn.test", "x.cdn.test"), "wildcard one label")
check(m.host_match("*.cdn.test", "a.b.cdn.test"), "wildcard multi label")
check(not m.host_match("*.cdn.test", "cdn.test"), "wildcard needs subdomain")
check(not m.host_match("*.cdn.test", "evilcdn.test"), "wildcard boundary")
check(m.host_match("*", "anything.test"), "bare star")

# path_match: boundary-aware prefix
check(m.path_match("/api", "/api"), "path eq")
check(m.path_match("/api", "/api/"), "path slash boundary")
check(m.path_match("/api", "/api/v1"), "path subpath")
check(not m.path_match("/api", "/apifoo"), "path no false prefix")
check(m.path_match("/v1/", "/v1/x"), "path trailing slash rule")
check(not m.path_match("/v1/", "/v1"), "path trailing slash strict")

# normalize_path: percent-decode + dot-segment collapse + query strip
check(m.normalize_path("/v1/x?q=1") == "/v1/x", "strip query")
check(m.normalize_path("/api/../%61dmin/./x") == "/admin/x", "normalize+decode")
check(m.normalize_path("/v1/%2e%2e/secret") == "/secret", "%2e%2e traversal")
check(m.normalize_path("/v1/") == "/v1/", "trailing slash preserved")
check(m.normalize_path("//a") == "/a", "collapse double slash")
check(m.normalize_path("/../..") == "/", "pop past root")


# evaluate: first-match, default-deny, path-gated
class _R:
    def __init__(self, rules, mode_terminate=False):
        self.rules = rules
        self.mode_terminate = mode_terminate


rs = _R([
    ("allow", "api.example.com", "/v1/", False),
    ("allow", "plain.test", None, False),
    ("deny", "*", None, False),
])
check(m.evaluate(rs, "api.example.com", "/v1/x") == "allow", "path allow")
check(m.evaluate(rs, "api.example.com", "/v2/x") == "deny", "path deny")
check(m.evaluate(rs, "plain.test", "/anything") == "allow", "host allow")
check(m.evaluate(rs, "other.test", "/") == "deny", "default deny via catch-all")
check(m.evaluate(_R([("allow", "only.test", None, False)]), "x.test", "/") == "deny", "default deny")

# host_insecure: only allow-rules flagged insecure match; host-level (path-independent)
ri = _R([
    ("allow", "internal.svc", "/api/", True),
    ("allow", "secure.svc", None, False),
    ("deny", "nope.svc", None, True),
    ("allow", "*.lab.test", None, True),
])
check(m.host_insecure(ri, "internal.svc"), "insecure host flagged")
check(m.host_insecure(ri, "internal.svc."), "insecure host flagged (trailing dot)")
check(not m.host_insecure(ri, "secure.svc"), "non-insecure host not flagged")
check(not m.host_insecure(ri, "nope.svc"), "deny rule never insecure-allows")
check(not m.host_insecure(ri, "unlisted.svc"), "unlisted host not insecure")
check(m.host_insecure(ri, "box.lab.test"), "insecure wildcard host")

# --- credential injection (host-side; keeps tokens out of the guest) ---

# Case-insensitive header shim mirroring mitmproxy's Headers multidict, so the
# tests catch case bugs in apply_injection (a guest may send `X-Api-Key`).
class CIDict:
    def __init__(self, init=None):
        self._d = {}
        for k, v in (init or {}).items():
            self[k] = v

    def __setitem__(self, k, v):
        self._d[k.lower()] = v

    def __getitem__(self, k):
        return self._d[k.lower()]

    def __delitem__(self, k):
        del self._d[k.lower()]

    def __contains__(self, k):
        return k.lower() in self._d

    def get(self, k, default=None):
        return self._d.get(k.lower(), default)


# json_path_get: dotted-path string-leaf fetch
check(m.json_path_get({"a": {"b": "x"}}, "a.b") == "x", "json_path nested")
check(m.json_path_get({"a": {"b": "x"}}, "a.c") is None, "json_path missing leaf")
check(m.json_path_get({"a": "x"}, "a.b") is None, "json_path descend non-dict")
check(m.json_path_get({"a": {"b": 5}}, "a.b") is None, "json_path non-string leaf")
check(
    m.json_path_get({"claudeAiOauth": {"accessToken": "sk-ant-oat01-Z"}},
                    "claudeAiOauth.accessToken") == "sk-ant-oat01-Z",
    "json_path claude shape",
)

# merge_beta: append oauth marker, idempotent, trim, preserve feature betas
check(m.merge_beta(None, "oauth-2025-04-20") == "oauth-2025-04-20", "beta from None")
check(m.merge_beta("", "oauth-2025-04-20") == "oauth-2025-04-20", "beta from blank")
check(
    m.merge_beta("claude-code-20250219", "oauth-2025-04-20")
    == "claude-code-20250219,oauth-2025-04-20",
    "beta append",
)
check(
    m.merge_beta("a, oauth-2025-04-20 ,b", "oauth-2025-04-20") == "a,oauth-2025-04-20,b",
    "beta idempotent + trim",
)

# apply_injection: anthropic-oauth replaces stub Bearer, drops x-api-key, merges beta
h = CIDict({"Authorization": "Bearer PLACEHOLDER", "X-Api-Key": "guest-key",
            "anthropic-beta": "claude-code-20250219"})
m.apply_injection(h, "anthropic-oauth", "REAL-OAT")
check(h["authorization"] == "Bearer REAL-OAT", "oauth sets real bearer")
check("x-api-key" not in h, "oauth drops x-api-key")
check(h["anthropic-beta"] == "claude-code-20250219,oauth-2025-04-20", "oauth merges beta")

# anthropic-apikey: sets x-api-key, drops Authorization
h = CIDict({"Authorization": "Bearer guest"})
m.apply_injection(h, "anthropic-apikey", "REAL-KEY")
check(h["x-api-key"] == "REAL-KEY", "apikey sets x-api-key")
check("authorization" not in h, "apikey drops authorization")

# openai-chatgpt: sets bearer + chatgpt-account-id
h = CIDict({"Authorization": "Bearer stub"})
m.apply_injection(h, "openai-chatgpt", "REAL-ACC", account_id="acct_123")
check(h["authorization"] == "Bearer REAL-ACC", "chatgpt sets bearer")
check(h["chatgpt-account-id"] == "acct_123", "chatgpt sets account id")
h = CIDict({})
m.apply_injection(h, "openai-chatgpt", "T")  # no account id -> header omitted
check("chatgpt-account-id" not in h, "chatgpt omits account id when absent")

# bearer (and unknown style) -> plain Bearer replace
h = CIDict({"Authorization": "Bearer stub"})
m.apply_injection(h, "bearer", "T")
check(h["authorization"] == "Bearer T", "bearer style")
h = CIDict({})
m.apply_injection(h, "weird-unknown", "T")
check(h["authorization"] == "Bearer T", "unknown style falls back to bearer")

# CredStore: conf + cred file, host normalization, mtime hot-reload, fail-closed
import json as _json
import tempfile

_d = tempfile.mkdtemp()
_cred = os.path.join(_d, "creds.json")
_conf = os.path.join(_d, "inject.json")


def _write(path, obj, mtime):
    with open(path, "w") as f:
        _json.dump(obj, f)
    os.utime(path, (mtime, mtime))


_write(_cred, {"claudeAiOauth": {"accessToken": "OAT-1"}}, 1000)
_write(_conf, [{"host": "api.anthropic.com", "style": "anthropic-oauth",
                "cred_file": _cred, "token_path": "claudeAiOauth.accessToken"}], 1000)
cs = m.CredStore(_conf)
spec = cs.spec_for("api.anthropic.com")
check(spec is not None, "credstore spec found")
check(cs.spec_for("API.ANTHROPIC.COM.") is not None, "credstore host case/dot normalize")
check(cs.spec_for("other.host") is None, "credstore no spec for unlisted host")
check(cs.value_for(spec, "token_path") == "OAT-1", "credstore reads token v1")
check(cs.value_for(spec, "account_id_path") is None, "credstore missing path key -> None")
_write(_cred, {"claudeAiOauth": {"accessToken": "OAT-2"}}, 2000)  # rotate
check(cs.value_for(spec, "token_path") == "OAT-2", "credstore hot-reloads rotated token")
check(m.CredStore("").spec_for("api.anthropic.com") is None, "credstore disabled when no conf")
_write(_conf, [{"host": "x.test", "style": "bearer",
                "cred_file": os.path.join(_d, "nope.json"), "token_path": "k"}], 3000)
cs2 = m.CredStore(_conf)
sp2 = cs2.spec_for("x.test")
check(sp2 is not None, "credstore spec for a host whose cred file is missing")
check(cs2.value_for(sp2, "token_path") is None, "credstore missing cred file -> None (fail closed)")


if fails:
    print("FAIL:", *fails, sep="\n  ")
    sys.exit(1)
print("all addon parity tests passed")
