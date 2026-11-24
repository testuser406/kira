#!/usr/bin/env python3
"""Replay a captured Sophos syslog file into a Kira collector and report what happened.

Use it with an export of REAL firewall logs (keep that file out of git) to check that every
line parses, nothing is rejected/dropped, and to see how much the noise filter removes:

  python3 scripts/replay-real-log.py capture.log --host 127.0.0.1 --port 5514 \
      --collector http://127.0.0.1:8081 --rate 3000 --rebase
"""
import argparse, json, re, socket, time, urllib.request
from collections import Counter
from datetime import datetime, timezone

TS = re.compile(r'timestamp="([^"]+)"')

def metrics(url):
    with urllib.request.urlopen(url.rstrip("/") + "/metrics", timeout=15) as r:
        return json.loads(r.read())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5514)
    ap.add_argument("--collector", default="http://127.0.0.1:8081")
    ap.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    ap.add_argument("--rate", type=int, default=2000, help="lines per second (0 = as fast as possible)")
    ap.add_argument("--limit", type=int, default=0, help="stop after N lines")
    ap.add_argument("--rebase", action="store_true", help="shift timestamps so the newest line is 'now' (keeps them inside the retention window)")
    a = ap.parse_args()

    lines = [l for l in open(a.file, encoding="utf-8", errors="replace").read().splitlines() if l.strip() and not l.startswith("#")]
    if a.limit:
        lines = lines[: a.limit]
    shift = None
    if a.rebase:
        stamps = [datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S%z") for l in lines if (m := TS.search(l))]
        if stamps:
            shift = datetime.now(timezone.utc) - max(stamps)
    kinds = Counter()
    for l in lines:
        m = re.search(r'log_type="([^"]*)".*?log_component="([^"]*)"', l)
        kinds[m.groups() if m else ("?", "?")] += 1

    before = metrics(a.collector)
    sock = socket.create_connection((a.host, a.port), timeout=15) if a.proto == "tcp" else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t0, sent = time.time(), 0
    for l in lines:
        if shift is not None:
            l = TS.sub(lambda m: 'timestamp="%s"' % (datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S%z") + shift).strftime("%Y-%m-%dT%H:%M:%S%z"), l, count=1)
        data = (l + "\n").encode()
        sock.sendall(data) if a.proto == "tcp" else sock.sendto(data, (a.host, a.port))
        sent += 1
        if a.rate and sent % 100 == 0:
            ahead = sent / a.rate - (time.time() - t0)
            if ahead > 0:
                time.sleep(ahead)
    sock.close()
    secs = max(time.time() - t0, 0.001)

    after = before
    for _ in range(40):  # wait for the writer to flush
        time.sleep(1)
        after = metrics(a.collector)
        if after["queue_depth"] == 0 and after["written"] + after.get("filtered", 0) - before["written"] - before.get("filtered", 0) >= after["parsed"] - before["parsed"]:
            break
    d = {k: after.get(k, 0) - before.get(k, 0) for k in ("lines", "parsed", "rejected", "filtered", "user_resolved", "user_ambiguous", "written", "dropped", "db_errors")}
    print(f"sent {sent} lines in {secs:.1f}s ({sent / secs:.0f}/s) over {a.proto}")
    for k, v in d.items():
        print(f"  {k:15} {v}")
    print("  log kinds:", ", ".join(f"{t}/{c}={n}" for (t, c), n in kinds.most_common(8)))
    ok = d["rejected"] == 0 and d["dropped"] == 0 and d["db_errors"] == 0 and d["written"] + d["filtered"] == d["parsed"]
    if a.proto == "udp":
        ok = ok and d["parsed"] == sent
    print("RESULT:", "OK" if ok else "PROBLEM (see rejected/dropped/db_errors; run the collector with RUST_LOG=debug)")
    raise SystemExit(0 if ok else 1)

if __name__ == "__main__":
    main()
