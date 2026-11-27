#!/usr/bin/env python3
"""Send synthetic Sophos-style syslog over UDP and report the ingest rate.

    python scripts/loadtest.py --host 127.0.0.1 --port 5514 --eps 2000 --seconds 20
"""
import argparse, datetime, random, socket, time

TEMPLATE = ('date={date} time={time} timezone="UTC" device_name="SFW" log_id=010101600001 log_type="Content Filtering" '
            'log_component="HTTP" log_subtype="Allowed" status="Allowed" user_name="load{user}" src_ip=10.{a}.{b}.{c} '
            'dst_ip=93.184.{d}.{e} protocol="TCP" src_port={sp} dst_port=80 url="http://site{site}.example.com/page" '
            'domain="site{site}.example.com" category="General Business" sent_bytes={sb} recv_bytes={rb}')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, default=5514)
    ap.add_argument("--eps", type=int, default=1000); ap.add_argument("--seconds", type=int, default=10)
    ap.add_argument("--metrics", default="http://127.0.0.1:8081/metrics")
    a = ap.parse_args()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent, start = 0, time.time()
    while time.time() - start < a.seconds:
        tick = time.time()
        for _ in range(a.eps // 10):
            now = datetime.datetime.now(datetime.timezone.utc)
            msg = TEMPLATE.format(date=now.strftime('%Y-%m-%d'), time=now.strftime('%H:%M:%S'), user=random.randint(1, 300), a=random.randint(0, 3), b=random.randint(0, 255), c=random.randint(1, 254),
                                  d=random.randint(0, 255), e=random.randint(1, 254), sp=random.randint(1024, 65000),
                                  site=random.randint(1, 400), sb=random.randint(100, 5000), rb=random.randint(100, 500000))
            s.sendto(msg.encode(), (a.host, a.port)); sent += 1
        time.sleep(max(0, 0.1 - (time.time() - tick)))
    dur = time.time() - start
    print(f"sent {sent} datagrams in {dur:.1f}s ({sent / dur:.0f}/s)")
    try:
        import json, urllib.request
        time.sleep(3)
        m = json.load(urllib.request.urlopen(a.metrics, timeout=5))
        print({k: m[k] for k in ("datagrams", "parsed", "written", "dropped", "db_errors", "queue_high_water") if k in m})
    except Exception as e:  # noqa: BLE001
        print("could not read collector metrics:", e)

if __name__ == "__main__":
    main()
