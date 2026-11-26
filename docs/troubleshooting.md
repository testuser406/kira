# Troubleshooting: logs are not arriving

Work top to bottom; stop when data flows again. Each step shows the **command line** way and the **GUI** way.

## 0. Let Kira check itself
- GUI: dashboard → **System** tab (updates every 10 s, shows diagnosis cards with fixes).
- CLI: `.\scripts\windows\kira.ps1 doctor` (add `-Fix` to restart services and open the firewall).

## 1. Is everything running?
- CLI: `.\scripts\windows\kira.ps1 status` → PostgreSQL, ingest and api must say *running*.
  Not running → `.\scripts\windows\kira.ps1 start`; read `.runtime\logs\ingest*.err.log` / `api*.err.log`.
- GUI: Task Manager → *Details* → `postgres.exe`, `sfos-ingest.exe`, `sfos-api.exe`.

## 2. Is the collector listening on 5514?
- CLI: `Get-NetUDPEndpoint -LocalPort 5514` (and `Get-NetTCPConnection -LocalPort 5514 -State Listen`).
  Another program on the port → stop it or change `SYSLOG_UDP_ADDR` in `kira.env`.
- GUI: Resource Monitor → Network → *Listening Ports*.

## 3. Windows Firewall and network profile
- CLI (Administrator): `.\scripts\windows\kira.ps1 firewall`; check the profile with `Get-NetConnectionProfile`.
  A **Public** network ignores Kira's rules: `Set-NetConnectionProfile -InterfaceIndex <n> -NetworkCategory Private`.
- GUI: Settings → Network & internet → your connection → *Network profile = Private*;
  Windows Security → Firewall & network protection → *Advanced settings* → *Inbound Rules* → `Kira Syslog UDP 5514` enabled.

## 4. Is Sophos sending to this PC?
- GUI (Sophos Firewall): *System services → Log settings → Syslog servers*: this PC's IP (`ipconfig`), port **5514**, **UDP**,
  format **Device standard**; tick the log categories; enable *Log traffic* on the firewall rules you care about.
- CLI (from another machine on the LAN): `Test-NetConnection <kira-ip> -Port 5514` only tests TCP; for UDP watch the counter below.

## 5. Counters
- CLI: `Invoke-RestMethod http://127.0.0.1:8081/metrics` (or `kira.ps1 status`).
- GUI: System tab → *Collector counters*.

| Counter | Meaning / fix |
| --- | --- |
| `datagrams` stays 0 | Nothing reaches the PC: steps 2–4. |
| `denied_sources` > 0 | Sender IP not in `ALLOWED_SOURCES` (kira.env); add it or leave the list empty, restart. |
| `rejected` grows, `parsed` 0 | Wrong format: use *Device standard*. |
| `db_errors` / `dropped` > 0 | Database write problem: step 6. |

## 6. Database and disk
- CLI: `Select-String .runtime\logs\ingest*.err.log -Pattern 'failed|rollup|dropp' | select -Last 20`; `Get-PSDrive C` (free space).
  Restart: `.\scripts\windows\kira.ps1 stop; .\scripts\windows\kira.ps1 start`.
- GUI: File Explorer → This PC (free space); Task Manager → Performance (disk/CPU at 100 %).

## 7. Data arrives but the dashboard looks empty
- Newest event in the **future**: firewall clock/time zone differs → set `DEFAULT_TZ_OFFSET_MINUTES` in `kira.env`
  (e.g. `300` for UTC+5) and fix the time zone under Sophos *Administration → Time*, then restart.
- Wrong tenant selected in the dashboard header, or the browser is showing an old build: stop, `kira.ps1 build`, start, hard-refresh (Ctrl+F5).

## 8. Still stuck
Run `kira.ps1 doctor`, then send its output plus the last 30 lines of `.runtime\logs\ingest*.err.log`.
