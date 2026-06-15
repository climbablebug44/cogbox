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

# should_inject: with a stub_token, inject ONLY over that stub (or an absent
# credential); pass a secondary credential the guest legitimately holds straight
# through (e.g. claude-code Remote Control's per-session worker_jwt on
# /v1/code/sessions/<id>/worker -- clobbering it yields 401/worker_register_failed).
STUB = "sk-ant-oat01-cogbox-host-injected-placeholder"
check(m.should_inject(CIDict({"Authorization": "Bearer " + STUB}), "anthropic-oauth", STUB),
      "should_inject: inject over the stub bearer")
check(not m.should_inject(CIDict({"Authorization": "Bearer eyJ.worker.jwt"}), "anthropic-oauth", STUB),
      "should_inject: pass through a non-stub bearer (RC worker_jwt)")
check(m.should_inject(CIDict({}), "anthropic-oauth", STUB),
      "should_inject: inject when no credential present")
check(m.should_inject(CIDict({"Authorization": "Bearer " + STUB}), "anthropic-oauth", None),
      "should_inject: no stub_token -> legacy always-inject")
check(m.should_inject(CIDict({"Authorization": "Bearer whatever"}), "anthropic-oauth", None),
      "should_inject: no stub_token -> inject even a non-stub cred")
check(m.should_inject(CIDict({"X-Api-Key": STUB}), "anthropic-apikey", STUB),
      "should_inject: apikey inject over stub key")
check(not m.should_inject(CIDict({"X-Api-Key": "real-secondary"}), "anthropic-apikey", STUB),
      "should_inject: apikey pass through non-stub key")

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


# --- json_path_raw / json_path_set (refresh write-back helpers) ----------
check(m.json_path_raw({"a": {"b": 5}}, "a.b") == 5, "json_path_raw numeric leaf")
check(m.json_path_raw({"a": {"b": "x"}}, "a.b") == "x", "json_path_raw string leaf")
check(m.json_path_raw({"a": {"b": 5}}, "a.c") is None, "json_path_raw missing")
check(m.json_path_raw({"a": "x"}, "a.b") is None, "json_path_raw descend non-dict")

_o = {"claudeAiOauth": {"accessToken": "OLD", "expiresAt": 1}}
check(m.json_path_set(_o, "claudeAiOauth.accessToken", "NEW") and
      _o["claudeAiOauth"]["accessToken"] == "NEW", "json_path_set existing leaf")
check(m.json_path_set(_o, "claudeAiOauth.expiresAt", 99) and
      _o["claudeAiOauth"]["expiresAt"] == 99, "json_path_set numeric leaf")
# refuses to fabricate structure on a malformed/missing intermediate
_bad = {"claudeAiOauth": "not-a-dict"}
check(m.json_path_set(_bad, "claudeAiOauth.accessToken", "X") is False, "json_path_set non-dict intermediate -> False")
check(_bad == {"claudeAiOauth": "not-a-dict"}, "json_path_set no mutation on failure")
check(m.json_path_set({"a": {}}, "a.b.c", "X") is False, "json_path_set missing intermediate -> False")

# --- host-side token refresh (ensure_fresh) ------------------------------
import time as _time

# Keep the cross-process lock out of the shared system temp dir during tests.
m.CRED_LOCK_DIR = os.path.join(_d, "locks")
m.REFRESH_WINDOW_SEC = 600


def _now_ms(delta_sec=0):
    return int((_time.time() + delta_sec) * 1000)


def _mk_cred(name, expires_at_ms, access="OLD-ACCESS", refresh="OLD-REFRESH"):
    p = os.path.join(_d, name)
    with open(p, "w") as f:
        _json.dump({"claudeAiOauth": {
            "accessToken": access, "refreshToken": refresh,
            "expiresAt": expires_at_ms,
            "scopes": ["user:inference"], "subscriptionType": "max"}}, f)
    return p


_REFRESH = {
    "refresh_token_path": "claudeAiOauth.refreshToken",
    "expires_at_path": "claudeAiOauth.expiresAt",
    "token_url": "https://example.invalid/oauth/token",
    "client_id": "CID",
    "expires_at_unit": "ms",
}


def _spec_for(path, refresh=True):
    s = {"host": "api.anthropic.com", "style": "anthropic-oauth",
         "cred_file": path, "token_path": "claudeAiOauth.accessToken"}
    if refresh:
        s["refresh"] = dict(_REFRESH)
    return s


def _load(path):
    with open(path) as f:
        return _json.load(f)["claudeAiOauth"]


posts = []


def _ok_post(url, payload, timeout, user_agent=None):
    posts.append((url, payload, timeout, user_agent))
    return {"access_token": "NEW-ACCESS", "refresh_token": "NEW-REFRESH", "expires_in": 28800}


cs_r = m.CredStore("")
m._http_post_json = _ok_post

# 1. Fresh token -> no POST, file unchanged
posts.clear()
p = _mk_cred("fresh.json", _now_ms(10000))
cs_r.ensure_fresh(_spec_for(p))
check(len(posts) == 0, "refresh: fresh token makes no POST")
check(_load(p)["accessToken"] == "OLD-ACCESS", "refresh: fresh token unchanged")

# 2. Near-expiry token -> refresh, correct payload, rotation, others preserved
posts.clear()
p = _mk_cred("near.json", _now_ms(60))
cs_r.ensure_fresh(_spec_for(p))
check(len(posts) == 1, "refresh: near-expiry triggers one POST")
check(posts[0][0] == "https://example.invalid/oauth/token", "refresh: posts to token_url")
check(posts[0][1] == {"grant_type": "refresh_token", "refresh_token": "OLD-REFRESH", "client_id": "CID"},
      "refresh: correct grant payload")
check(posts[0][3] == m.DEFAULT_REFRESH_UA, "refresh: sends a harness-like UA (stock urllib UA is WAF-banned)")
d = _load(p)
check(d["accessToken"] == "NEW-ACCESS", "refresh: access token rotated")
check(d["refreshToken"] == "NEW-REFRESH", "refresh: refresh token rotated")
check(_now_ms(28000) < d["expiresAt"] < _now_ms(29000), "refresh: expiresAt set from expires_in (ms)")
check(d["subscriptionType"] == "max" and d["scopes"] == ["user:inference"], "refresh: preserves other fields")
check(not os.path.exists(p + ".cogbox-bak"), "refresh: no token-bearing backup file written")

# 3. Already-expired token still refreshes (refresh token long-lived)
posts.clear()
p = _mk_cred("expired.json", _now_ms(-100))
cs_r.ensure_fresh(_spec_for(p))
check(len(posts) == 1 and _load(p)["accessToken"] == "NEW-ACCESS", "refresh: expired token refreshes")

# 4. No refresh config -> never touches anything
posts.clear()
p = _mk_cred("norefresh.json", _now_ms(60))
cs_r.ensure_fresh(_spec_for(p, refresh=False))
check(len(posts) == 0 and _load(p)["accessToken"] == "OLD-ACCESS", "refresh: no config is a no-op")

# 5. HTTP failure -> file untouched (fail-safe)
posts.clear()


def _boom(url, payload, timeout, user_agent=None):
    raise OSError("network down")


m._http_post_json = _boom
p = _mk_cred("httpfail.json", _now_ms(60))
cs_r.ensure_fresh(_spec_for(p))
d = _load(p)
check(d["accessToken"] == "OLD-ACCESS" and d["refreshToken"] == "OLD-REFRESH", "refresh: HTTP failure leaves file untouched")

# 6. Bad response (missing fields) -> file untouched
m._http_post_json = lambda url, payload, timeout, user_agent=None: {"error": "invalid_grant"}
p = _mk_cred("badresp.json", _now_ms(60))
cs_r.ensure_fresh(_spec_for(p))
check(_load(p)["accessToken"] == "OLD-ACCESS", "refresh: bad response leaves file untouched")

# 7. Response without a rotated refresh token -> keep the existing one
m._http_post_json = lambda url, payload, timeout, user_agent=None: {"access_token": "NEW2", "expires_in": 100}
p = _mk_cred("norotate.json", _now_ms(60))
cs_r.ensure_fresh(_spec_for(p))
d = _load(p)
check(d["accessToken"] == "NEW2" and d["refreshToken"] == "OLD-REFRESH", "refresh: missing rotated token keeps old refresh token")

# 8. No refresh token on disk -> no POST (cannot refresh)
posts.clear()
m._http_post_json = _ok_post
p = os.path.join(_d, "nortok.json")
with open(p, "w") as f:
    _json.dump({"claudeAiOauth": {"accessToken": "A", "expiresAt": _now_ms(60), "subscriptionType": "max"}}, f)
cs_r.ensure_fresh(_spec_for(p))
check(len(posts) == 0 and _load(p)["accessToken"] == "A", "refresh: no on-disk refresh token -> no POST")

# 9. Non-numeric/absent expiry -> never refreshes (cannot judge freshness)
posts.clear()
p = os.path.join(_d, "noexp.json")
with open(p, "w") as f:
    _json.dump({"claudeAiOauth": {"accessToken": "A", "refreshToken": "R", "subscriptionType": "max"}}, f)
cs_r.ensure_fresh(_spec_for(p))
check(len(posts) == 0, "refresh: missing expiresAt -> no POST")

# 10. No token-bearing write-temp is left in the cred dir after a successful refresh
import glob as _glob
m._http_post_json = _ok_post
p = _mk_cred("clean.json", _now_ms(60))
cs_r.ensure_fresh(_spec_for(p))
check(_glob.glob(os.path.join(_d, m.CRED_TMP_PREFIX + "*.tmp")) == [],
      "refresh: no write-temp left in cred dir after success")

# 11. A stale write-temp (crash residue) is swept on the next refresh
p = _mk_cred("sweep.json", _now_ms(60))
stale = os.path.join(_d, m.CRED_TMP_PREFIX + "deadbeef.tmp")
with open(stale, "w") as f:
    f.write('{"claudeAiOauth":{"refreshToken":"LEAKED"}}')
cs_r.ensure_fresh(_spec_for(p))
check(not os.path.exists(stale), "refresh: stale write-temp swept from cred dir")

# 12. Cooldown: a failed attempt throttles the next attempt within the window
calls = []


def _count_fail(url, payload, timeout, user_agent=None):
    calls.append(1)
    raise OSError("down")


m._http_post_json = _count_fail
p = _mk_cred("cooldown.json", _now_ms(60))
cs_r.ensure_fresh(_spec_for(p))  # attempts, fails, records attempt
cs_r.ensure_fresh(_spec_for(p))  # within cooldown -> must not POST again
check(len(calls) == 1, "refresh: cooldown throttles repeat attempts after a failure")

# 13. Clobber guard: a rotation that lands DURING our POST is not overwritten
p = _mk_cred("clobber.json", _now_ms(60))
_mt0 = os.stat(p).st_mtime


def _post_then_rotate(url, payload, timeout, user_agent=None):
    # simulate the host CLI rotating the file mid-POST
    with open(p, "w") as f:
        _json.dump({"claudeAiOauth": {"accessToken": "CLI-ACCESS", "refreshToken": "CLI-REFRESH",
                                      "expiresAt": _now_ms(28800), "subscriptionType": "max"}}, f)
    os.utime(p, (_mt0 + 10, _mt0 + 10))  # guarantee a distinct mtime
    return {"access_token": "ADDON-ACCESS", "refresh_token": "ADDON-REFRESH", "expires_in": 28800}


m._http_post_json = _post_then_rotate
cs_r.ensure_fresh(_spec_for(p))
check(_load(p)["accessToken"] == "CLI-ACCESS", "refresh: concurrent rotation not clobbered")

# 14. Write-back preserves the cred file's owner (no-op rootless; guards the
# sudo case where a root-owned rewrite would lock out the user's own CLI).
m._http_post_json = _ok_post
p = _mk_cred("owner.json", _now_ms(60))
_uid_before = os.stat(p).st_uid
cs_r.ensure_fresh(_spec_for(p))
check(_load(p)["accessToken"] == "NEW-ACCESS" and os.stat(p).st_uid == _uid_before,
      "refresh: write-back preserves cred file owner")


if fails:
    print("FAIL:", *fails, sep="\n  ")
    sys.exit(1)
print("all addon parity tests passed")
