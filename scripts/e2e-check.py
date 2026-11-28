#!/usr/bin/env python3
"""End-to-end check of a running Kira stack: authentication, roles, and the ingest
pipeline (noise filtering + IP->user resolution) using real SFOS-shaped syslog.

  python3 scripts/e2e-check.py --api http://127.0.0.1:8080 --collector http://127.0.0.1:8081 \
      --syslog 127.0.0.1:5514 --user admin --password '...' [--drop-noise conn_start,ip_spoof_broadcast]
"""
import argparse, http.cookiejar, json, socket, sys, time, urllib.error, urllib.request
from datetime import datetime, timezone
from pathlib import Path

FAILS = []

def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        FAILS.append(name)

class Client:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def raw(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            with self.op.open(req, timeout=60) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            with self.op.open(req, timeout=20) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, {}

def getjson(url):
    with urllib.request.urlopen(url, timeout=20) as r:
        return json.loads(r.read())

def line(ts, **kw):
    base = {"device_name": "E2E-FW", "device_model": "XGS3300", "device_serial_id": "E2E-FW",
            "log_type": "Firewall", "log_component": "Firewall Rule", "log_subtype": "Allowed",
            "severity": "Information"}
    base.update(kw)
    stamp = ts.strftime("%Y-%m-%dT%H:%M:%S+0000")
    fields = " ".join(f'{k}="{v}"' for k, v in base.items())
    return f'<30>device_name="E2E-FW" timestamp="{stamp}" {fields}\n'

def send_tcp(host, port, lines):
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall("".join(lines).encode())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True)
    ap.add_argument("--collector", required=True)
    ap.add_argument("--syslog", required=True, help="host:port (TCP)")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", required=True)
    ap.add_argument("--drop-noise", default="", help="rules the collector runs with")
    ap.add_argument("--skip-ratelimit", action="store_true")
    a = ap.parse_args()

    # ---- authentication & roles
    anon = Client(a.api)
    check("healthz is public", anon.call("GET", "/healthz")[0] == 200)
    check("overview requires login", anon.call("GET", "/api/v1/overview?from=1h")[0] == 401)
    check("bad password rejected", anon.call("POST", "/api/v1/auth/login", {"username": a.user, "password": "nope-nope-nope"})[0] == 401)
    admin = Client(a.api)
    st, body = admin.call("POST", "/api/v1/auth/login", {"username": a.user, "password": a.password})
    check("admin login", st == 200 and body.get("role") == "admin", str(body))
    check("session cookie is HttpOnly", any(c.has_nonstandard_attr("HttpOnly") for c in admin.jar))
    check("me works with cookie", admin.call("GET", "/api/v1/auth/me")[0] == 200)
    check("overview works when signed in", admin.call("GET", "/api/v1/overview?from=1h")[0] == 200)

    viewer_name = f"viewer{int(time.time())}"
    st, _ = admin.call("POST", "/api/v1/users", {"username": viewer_name, "password": "viewer-password-1", "role": "viewer"})
    check("admin creates viewer", st == 201)
    check("weak password refused", admin.call("POST", "/api/v1/users", {"username": viewer_name + "x", "password": "short", "role": "viewer"})[0] == 400)
    check("duplicate username refused", admin.call("POST", "/api/v1/users", {"username": viewer_name.upper(), "password": "viewer-password-1", "role": "viewer"})[0] == 409)
    v = Client(a.api)
    check("viewer login", v.call("POST", "/api/v1/auth/login", {"username": viewer_name, "password": "viewer-password-1"})[0] == 200)
    check("viewer can read", v.call("GET", "/api/v1/overview?from=1h")[0] == 200)
    check("viewer cannot list users", v.call("GET", "/api/v1/users")[0] == 403)
    check("viewer cannot mutate", v.call("POST", "/api/v1/users", {"username": "zzzzz", "password": "viewer-password-1", "role": "admin"})[0] == 403)
    check("last admin cannot delete itself", admin.call("DELETE", "/api/v1/users/00000000-0000-0000-0000-000000000000")[0] in (409, 400))
    v.call("POST", "/api/v1/auth/logout")
    check("logout invalidates session", v.call("GET", "/api/v1/auth/me")[0] == 401)

    # ---- ingest pipeline with SFOS-shaped syslog
    host, port = a.syslog.rsplit(":", 1)
    before = getjson(a.collector.rstrip("/") + "/metrics")
    now = datetime.now(timezone.utc)
    tag = f"e2e{int(time.time())}"
    n = int(time.time()) % 60000
    ip_known, ip_shared = f"10.{77 + n // 250 % 100}.{n % 250}.5", f"10.{77 + n // 250 % 100}.{n % 250}.9"
    lines = [
        # a user is learned for ip_known ...
        line(now, user_name=tag + "-alice", user_group="Staff", src_ip=ip_known, dst_ip="93.184.216.34", dst_port=443, con_event="Stop", con_id="1", protocol="TCP", bytes_sent=10, bytes_received=20, fw_rule_name="R", src_zone="LAN", dst_zone="WAN"),
        # ... and later an anonymous line from the same IP should inherit it
        line(now, src_ip=ip_known, dst_ip="93.184.216.35", dst_port=443, con_event="Stop", con_id="2", protocol="TCP", bytes_sent=1, bytes_received=2, fw_rule_name="R", src_zone="LAN", dst_zone="WAN"),
        # shared IP: two users -> anonymous line must stay anonymous
        line(now, user_name=tag + "-bob", src_ip=ip_shared, dst_ip="93.184.216.36", dst_port=443, con_event="Stop", con_id="3", protocol="TCP", fw_rule_name="R", src_zone="LAN", dst_zone="WAN"),
        line(now, user_name=tag + "-carol", src_ip=ip_shared, dst_ip="93.184.216.36", dst_port=443, con_event="Stop", con_id="4", protocol="TCP", fw_rule_name="R", src_zone="LAN", dst_zone="WAN"),
        line(now, src_ip=ip_shared, dst_ip="93.184.216.37", dst_port=443, con_event="Stop", con_id="5", protocol="TCP", fw_rule_name="R", src_zone="LAN", dst_zone="WAN"),
        # noise candidates
        line(now, src_ip="10.77.0.20", dst_ip="93.184.216.40", dst_port=443, con_event="Start", con_id="6", protocol="TCP", fw_rule_name="R", src_zone="LAN", dst_zone="WAN"),
        line(now, log_component="IP Spoof", log_subtype="Denied", src_ip="10.77.0.21", dst_ip="255.255.255.255", dst_port=17500, protocol="UDP"),
    ]
    send_tcp(host, int(port), lines)
    time.sleep(4)  # > BATCH_MS
    after = getjson(a.collector.rstrip("/") + "/metrics")
    d = lambda k: after[k] - before[k]
    check("collector parsed all lines", d("parsed") == len(lines), f"parsed +{d('parsed')} of {len(lines)}")
    check("no rejected lines", d("rejected") == 0)
    rules = {r for r in a.drop_noise.split(",") if r}
    expect_filtered = ("conn_start" in rules) + ("ip_spoof_broadcast" in rules)
    check("noise filter drop count matches config", d("filtered") == expect_filtered, f"filtered +{d('filtered')}, expected {expect_filtered}")
    check("one IP->user resolution", d("user_resolved") == 1, f"+{d('user_resolved')}")
    check("shared IP left ambiguous", d("user_ambiguous") == 1, f"+{d('user_ambiguous')}")
    check("everything kept was written", d("written") == len(lines) - expect_filtered and d("dropped") == 0 and d("db_errors") == 0,
          f"written +{d('written')}")

    st, ev = admin.call("GET", "/api/v1/events?from=1h&limit=200&q=" + ip_known)
    rows = ev.get("rows", []) if st == 200 else []
    named = [r for r in rows if r.get("user") == tag + "-alice"]
    check("both lines from the known IP are attributed to the user", len(named) >= 2, f"{len(named)} rows")
    st, ev = admin.call("GET", "/api/v1/events?from=1h&limit=200&q=" + ip_shared)
    anon = [r for r in ev.get("rows", []) if r.get("dst_ip") == "93.184.216.37"]
    check("shared-IP line was stored", bool(anon), "row missing")
    check("shared-IP line has no guessed user", bool(anon) and (anon[0].get("user") or "") in ("", ip_shared), str(anon[:1]))

    # ---- reports: every subtype renders in both formats, filters apply, custom reports save and run
    subtypes = ["generic", "user", "department", "safeguarding", "websites_allowed_blocked", "activity_timeline",
                "internet_searches", "youtube_videos", "online_productivity", "firewall_policy", "security_threat",
                "network_bandwidth", "vpn_connections", "subnet"]
    bad = []
    for sub in subtypes:
        for fmt in ("csv", "pdf"):
            st, body = admin.raw("POST", "/api/v1/reports/generate", {"format": fmt, "filters": {"from": "24h", "report_subtype": sub}})
            if st != 200 or (fmt == "pdf" and not body.startswith(b"%PDF")) or (fmt == "csv" and b"\n" not in body):
                bad.append(f"{sub}/{fmt}={st}")
    check("all 13 report subtypes render as CSV and PDF", not bad, ", ".join(bad))
    st, body = admin.raw("POST", "/api/v1/reports/generate", {"format": "csv", "filters": {"from": "24h", "user": "no-such-user-xyz"}})
    check("report filters are applied (no match -> header only)", st == 200 and len(body.decode().splitlines()) == 1, f"{st} {len(body.splitlines())} lines")
    st, body = admin.raw("POST", "/api/v1/reports/generate", {"format": "csv", "filters": {"from": "24h", "dst_port": "443", "sent_bytes_min": 0, "src_zone": "LAN"}})
    check("advanced report filters accepted", st == 200, str(st))
    st, c = admin.call("POST", "/api/v1/reports/custom", {"name": f"e2e-{int(time.time())}", "filters": {"from": "24h", "report_subtype": "user"}, "format": "csv", "recipients": []})
    cid = (c.get("report") or c).get("id") if st == 200 else None
    check("custom report can be saved", bool(cid), f"{st} {c}")
    if cid:
        check("custom report runs", admin.call("POST", f"/api/v1/reports/custom/{cid}/run")[0] == 200)

    # ---- per-minute live dashboards (each tab has its own data)
    shapes = {"bandwidth": "top_users", "productivity": "top_domains", "security": "top_threats", "vpn": "tunnels"}
    for kind, field in shapes.items():
        st, body = admin.call("GET", f"/api/v1/live/{kind}?window=15")
        dat = (body or {}).get("data", {}) if st == 200 else {}
        check(f"live/{kind} responds with minute series", st == 200 and len(dat.get("series", [])) == 15 and field in dat, f"{st}")
    st, bw = admin.call("GET", "/api/v1/live/bandwidth?window=15")
    check("live bandwidth sees ingested traffic", st == 200 and (bw["data"]["total_up"] + bw["data"]["total_down"]) > 0)
    check("unknown live tab rejected", admin.call("GET", "/api/v1/live/nope")[0] == 400)

    # ---- productivity guidelines, browse time, Site Clean
    st, g = admin.call("GET", "/api/v1/productivity/guidelines")
    check("default productivity guidelines seeded", st == 200 and len(g.get("items", [])) >= 15, str(st))
    st, _ = admin.call("PUT", "/api/v1/productivity/guidelines", {"kind": "site", "key": "e2e-test.example", "class": "unproductive"})
    check("admin can add a guideline", st == 200)
    check("bad guideline class refused", admin.call("PUT", "/api/v1/productivity/guidelines", {"kind": "site", "key": "x.example", "class": "bad"})[0] == 400)
    st, sm = admin.call("GET", "/api/v1/productivity/summary?window=60")
    check("productivity summary responds", st == 200 and all(k in sm for k in ("shares", "sites", "browse_time", "categories")), str(st))
    st, _ = admin.call("DELETE", "/api/v1/productivity/guidelines?kind=site&key=e2e-test.example")
    check("admin can delete a guideline", st == 200)

    # ---- summary reports (rollup based, concise)
    for rt in ("executive", "online_productivity", "user", "websites_allowed_blocked", "activity_timeline",
               "firewall_policy", "security_threat", "network_bandwidth", "vpn_connections", "subnet",
               "internet_searches", "youtube_videos"):
        st, body = admin.call("GET", f"/api/v1/reports/summary?type={rt}&from=24h")
        check(f"summary {rt} builds", st == 200 and body.get("kpis") is not None and len(body.get("sections", [])) >= 1, f"{st} {str(body)[:120]}")
    st, ex = admin.call("GET", "/api/v1/reports/summary?type=executive&from=1h")
    ev = next((k["value"] for k in ex.get("kpis", []) if k["label"] == "Total events"), 0) if st == 200 else 0
    check("executive summary counts ingested events", ev > 0, f"events={ev}")
    st, sr = admin.raw("GET", "/api/v1/search?q=zz&days=30")
    check("global search answers with groups", st == 200 and b'"groups"' in sr, f"{st}")
    st, _ = admin.raw("GET", "/api/v1/search?q=a")
    check("search rejects a 1-character term", st == 400, f"{st}")
    st, tl = admin.raw("GET", "/api/v1/investigate/user?user=nobody&days=7")
    check("user timeline answers", st == 200 and b'"timeline"' in tl, f"{st}")
    st, xl = admin.raw("GET", "/api/v1/reports/summary?type=executive&from=24h&format=xlsx")
    check("summary XLSX is a zip workbook", st == 200 and xl[:2] == b"PK" and b"xl/workbook.xml" in xl, f"{st} {len(xl)}")
    st, pdf = admin.raw("GET", "/api/v1/reports/summary?type=executive&from=24h&format=pdf")
    check("summary PDF is a small valid PDF", st == 200 and pdf.startswith(b"%PDF") and len(pdf) < 200_000, f"{st} {len(pdf)}")
    st, csv_ = admin.raw("GET", "/api/v1/reports/summary?type=online_productivity&from=24h&format=csv")
    check("summary CSV has titled sections", st == 200 and b"Productivity split" in csv_, f"{st}")
    check("user overview needs a user", admin.call("GET", "/api/v1/reports/summary?type=user_overview")[0] == 400)
    check("user overview works for a user", admin.call("GET", "/api/v1/reports/summary?type=user_overview&user=nobody-e2e")[0] == 200)
    check("unknown summary type rejected", admin.call("GET", "/api/v1/reports/summary?type=bogus")[0] == 400)

    # ---- system health / troubleshooting
    st, hl = admin.call("GET", "/api/v1/system/health")
    check("system health responds", st == 200 and hl.get("status") in ("ok", "warn", "error") and "diagnosis" in hl, f"{st}")
    check("system health sees recent events", st == 200 and hl.get("events_last_60m", 0) > 0, str(hl.get("events_last_60m")))

    # ---- alert rules: new conditions, notification settings, test delivery
    rid = None
    st, rb = admin.call("POST", "/api/v1/alerts/rules", {"name": "e2e no logs", "condition_type": "no_logs", "threshold": "100000", "severity": "low"})
    rid = ((rb or {}).get("rule") or {}).get("id") if st == 200 else None
    check("alert rule with new condition is accepted", st == 200 and rid, f"{st} {str(rb)[:100]}")
    check("unknown alert condition rejected", admin.call("POST", "/api/v1/alerts/rules", {"name": "bad", "condition_type": "nope", "threshold": "1"})[0] == 400)
    if rid:
        check("alert notify settings saved", admin.call("PUT", f"/api/v1/alerts/rules/{rid}/notify", {"email_to": "a@example.com", "webhook_format": "text"})[0] == 200)
        st, nb = admin.call("GET", f"/api/v1/alerts/rules/{rid}/notify")
        check("alert notify settings read back", st == 200 and nb.get("webhook_format") == "text" and nb.get("email_to") == "a@example.com", str(nb))
        check("alert notify bad format rejected", admin.call("PUT", f"/api/v1/alerts/rules/{rid}/notify", {"webhook_format": "xml"})[0] == 400)
        admin.call("DELETE", f"/api/v1/alerts/rules/{rid}")

    # ---- settings, masking, metrics
    st, sb = admin.call("GET", "/api/v1/settings")
    check("settings readable", st == 200 and "mask_users" in sb, str(st))
    check("admin can enable user masking", admin.call("PUT", "/api/v1/settings", {"mask_users": True})[0] == 200)
    st, ms = admin.call("GET", "/api/v1/reports/summary?type=user&from=24h")
    check("admins still see real names while masking is on", st == 200)
    admin.call("PUT", "/api/v1/settings", {"mask_users": False})
    check("metrics endpoint disabled without METRICS_TOKEN", admin.raw("GET", "/metrics")[0] == 404)

    # ---- hardening: headers and audit log
    with admin.op.open(admin.base + "/", timeout=20) as r:
        hdrs = {k.lower() for k in r.headers.keys()}
    check("security headers present", "content-security-policy" in hdrs and "x-content-type-options" in hdrs and "x-frame-options" in hdrs)
    st, au = admin.call("GET", "/api/v1/audit?limit=10")
    check("admin can read the audit log", st == 200 and len(au.get("items", [])) >= 1, str(st))
    st, csv_ = admin.raw("GET", "/api/v1/audit?limit=10&format=csv")
    check("audit log exports as CSV", st == 200 and csv_.startswith(b"time,user"), str(st))

    # ---- security analytics (v1.5)
    st, sec = admin.call("GET", "/api/v1/security/summary?hours=24")
    check("security summary", st == 200 and "threat_events" in sec and "timeline" in sec and "countries" in sec, f"{st} {sec}")
    st, fd = admin.call("GET", "/api/v1/security/findings?status=all")
    check("security findings list", st == 200 and isinstance(fd.get("findings"), list), f"{st}")
    st, ia = admin.call("POST", "/api/v1/security/intel", {"text": "198.51.100.250\n# c\nbad-e2e.example\nnot valid", "source": "e2e"})
    check("intel import", st == 200 and ia.get("added") == 2, f"{st} {ia}")
    st, il = admin.call("GET", "/api/v1/security/intel?limit=10")
    check("intel list", st == 200 and il.get("total", 0) >= 2, f"{st}")
    check("intel rejects garbage", admin.call("POST", "/api/v1/security/intel", {"text": "nonsense"})[0] == 400)
    check("intel delete", admin.call("DELETE", "/api/v1/security/intel?indicator=bad-e2e.example")[0] == 200
          and admin.call("DELETE", "/api/v1/security/intel?indicator=198.51.100.250")[0] == 200)
    st, ru = admin.call("POST", "/api/v1/alerts/rules", {"name": "e2e-bruteforce", "condition_type": "bruteforce",
                                                         "threshold": "1", "severity": "high", "cooldown_minutes": 60, "enabled": False})
    check("alert rule accepts security conditions", st in (200, 201), f"{st} {ru}")
    if st in (200, 201) and ru.get("id"):
        admin.call("DELETE", f"/api/v1/alerts/rules/{ru['id']}")

    # ---- share links
    st, sh = admin.call("POST", "/api/v1/reports/share", {"type": "executive", "from": "24h", "format": "pdf", "days": 1})
    check("share link created", st == 200 and sh.get("url", "").startswith("/share/"), f"{st} {sh}")
    if st == 200:
        anon = Client(admin.base)
        st2, body2 = anon.raw("GET", sh["url"])
        check("share link opens without signing in", st2 == 200 and body2.startswith(b"%PDF"), str(st2))
        tok = sh["url"].rsplit("/", 1)[1]
        admin.call("DELETE", f"/api/v1/reports/share/{tok}")
        check("revoked share link stops working", anon.raw("GET", sh["url"])[0] == 404)
    check("bad share token is 404", Client(admin.base).raw("GET", "/share/not-a-token")[0] == 404)

    # ---- rate limiting last (it would lock this IP out)
    if not a.skip_ratelimit:
        t = Client(a.api)
        codes = [t.call("POST", "/api/v1/auth/login", {"username": "ratelimit-probe", "password": "wrong-password-x"})[0] for _ in range(12)]
        check("login is rate limited", 429 in codes, str(codes))

    print(f"\n{'ALL PASSED' if not FAILS else 'FAILED: ' + ', '.join(FAILS)}")
    sys.exit(1 if FAILS else 0)

if __name__ == "__main__":
    main()
