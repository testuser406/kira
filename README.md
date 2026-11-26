# Kira — The Sophos Reporter

Self-hosted, live reporting for **Sophos Firewall (SFOS)**: a Rust syslog collector, Postgres storage and a
React dashboard. It covers the internet-usage and network-visibility side of Fastvue Reporter for Sophos, as a
small service that runs inside your own network. Log data never leaves your server.

Status: working core (collection, dashboards, reports, alerts, login). Not yet at Fastvue parity — see the
[roadmap](#roadmap) for what is missing (user directory sync, Site Clean, browse time, safeguarding data).

---

## What works today

**Collection and storage**
- Syslog over UDP and TCP (port `5514`), optional source allow-list, bounded queue, batched `COPY` into Postgres.
- Parser for SFOS firewall, content filtering/web, application control, IPS, anti-virus, ATP, authentication, VPN and
  system logs (classic `device="SFW" date=…` and SFOS 21 `<pri>device_name=… timestamp="…+0500"` formats).
- Connection-aware counts: `Start`/`Stop` firewall records are counted once.
- **Ingest pipeline** (new): drop noise before it is stored (`DROP_NOISE`), and **resolve users** — lines the firewall
  could not attribute get the user last seen on the same source IP (`RESOLVE_USERS`). Shared IPs (two users inside the
  window) are deliberately left anonymous rather than guessed.
- Hourly raw partitions with configurable retention; compact hourly rollups are kept long-term.
- Multi-tenant routing (several firewalls/sites on one collector).

**Dashboard and API**
- **Login** (new): local users, argon2 password hashes, server-side sessions in an HttpOnly cookie, `admin` /
  `viewer` (read-only) roles, failed-login rate limiting, audit log table, password change and user management in the UI.
- Live dashboards, overview charts, top users/domains/categories/policies/threats/applications/countries/devices.
- Event explorer with filters and CSV export.

**Reports and alerts**
- Report schedules (cron) with PDF/CSV output, e-mail delivery over SMTP, run history and download.
- Custom reports with a visual filter builder and templates for 13 report types (user, department, safeguarding,
  allowed/blocked websites, activity timeline, searches, YouTube, productivity, firewall policy, security/threat,
  bandwidth, VPN, subnet). Several of these need data Sophos only logs with HTTPS inspection or directory sync; the
  templates exist, the data enrichment is on the roadmap.
- Alert rules (threat, blocked category, large transfer) with webhook delivery and a delivery log. The webhook is a
  generic JSON POST, so it works with Zulip, Slack, Mattermost or Teams endpoints.

---

## Install and run on Windows (no Docker)

Kira runs as three native programs: PostgreSQL, the collector (`sfos-ingest`) and the API/dashboard
(`sfos-api`, port **8080**). `scripts\windows\kira.ps1` builds and controls all of them. Use a normal
PowerShell window in the repository folder unless a step says Administrator.

### 1. Install the prerequisites (once)

| Tool | Install | Why |
| --- | --- | --- |
| Git | `winget install Git.Git` | get and update the code |
| Rust (MSVC) | `winget install Rustlang.Rustup`, then in a new window `rustup default stable` | compile the services |
| C++ build tools | `winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"` | Rust needs the MSVC linker |
| Node.js 22 LTS | `winget install OpenJS.NodeJS.LTS` | build the dashboard |
| PostgreSQL 16 or 17 | `winget install PostgreSQL.PostgreSQL.17` (or unzip the EDB binaries into `.runtime\postgres\`) | event storage |

Open a **new** PowerShell afterwards and check: `git --version; cargo --version; node --version; where.exe initdb`
(if `initdb` is not found that is fine: the script looks in `PATH`, `C:\Program Files\PostgreSQL\*\bin` and `.runtime\postgres\*\bin`; otherwise set `PG_BIN` in `kira.env`).
Kira keeps its own database cluster on port 55432 inside `.runtime\`, so it does not touch an existing PostgreSQL service.

### 2. Get the code

```powershell
git clone https://github.com/testuser406/kira.git
cd kira
```

If PowerShell blocks the script, run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

### 3. Configure

```powershell
copy kira.env.example kira.env
notepad kira.env
```

At minimum set `ADMIN_PASSWORD` (10+ characters) and `TENANT_NAME`. Everything else has a sensible default
(dashboard on `0.0.0.0:8080`, syslog on `5514`, `DEFAULT_TZ_OFFSET_MINUTES=300` for Pakistan,
`DROP_NOISE=conn_start,ip_spoof_broadcast`). `kira.env` holds passwords and is ignored by git.

### 4. Build (first time takes several minutes)

```powershell
.\scripts\windows\kira.ps1 build
```

This runs `cargo build --release --locked` and builds the dashboard into `web\dist`.

### 5. Create the database (once)

```powershell
.\scripts\windows\kira.ps1 init
```

### 6. Open the Windows firewall (once, Administrator PowerShell)

```powershell
.\scripts\windows\kira.ps1 firewall
```

It opens TCP 8080 (dashboard) and TCP/UDP 5514 (syslog) for the **Domain and Private** profiles only, never Public.

### 7. Start

```powershell
.\scripts\windows\kira.ps1 start
```

Open `http://<this-computer>:8080` and sign in with `ADMIN_USERNAME` / `ADMIN_PASSWORD`. Then point Sophos at this
computer's address on port 5514 (see [Configure Sophos Firewall](#configure-sophos-firewall)).

### Everyday commands

| Command | What it does |
| --- | --- |
| `.\scripts\windows\kira.ps1 status` | what is running, plus the collector counters |
| `.\scripts\windows\kira.ps1 stop` | stop API, collector and PostgreSQL |
| `.\scripts\windows\kira.ps1 autostart` | start Kira when this user logs on |
| `Get-Content .runtime\logs\api.err.log -Tail 50` | API log (`ingest.err.log` for the collector; `.out.log` files hold stdout) |

**Update to a new version:** `git pull`, then `kira.ps1 stop`, `kira.ps1 build`, `kira.ps1 start`. Database migrations run
automatically on start. **Start fresh:** `kira.ps1 stop`, delete the `.runtime\pgdata` folder, run `init` again.

**Moving from the old `kira-main` folder:** that folder's PostgreSQL may still be running and holding the log file
(`pg_ctl: another server might be running`, `Permission denied`). Stop it first with its own `stop-kira.ps1`, or
`Get-Process postgres, sfos-api, sfos-ingest | Stop-Process -Force`. Raw events are only kept for hours anyway, so
starting with a new database is usually simplest.

Linux/macOS: `scripts/dev.sh start` builds and runs the same stack with a bundled PostgreSQL.

---

## Configure Sophos Firewall

1. **System → Logging → Syslog Servers → Add**
   - Server address: the host running the collector.
   - Port: `5514`, protocol **UDP** (or **TCP** if you prefer delivery confirmation).
   - Format: **Device standard format** (the `key=value` payload this parser expects).
   - Facility: any; it is ignored.
2. **System → Logging → Log Settings** — enable at least *Firewall*, *Content Filtering*,
   *Intrusion Prevention*, *Anti-Virus*, *ATP*, *Authentication* and *VPN*.
3. **User names** — `user_name` is only present when Sophos can attribute a connection to a person.
   Enable authentication (AD/LDAP, STAS/SSO or captive portal) and make sure the relevant firewall
   rules and web-filter policies log it. Without it the user panels show *unidentified*.
4. Confirm data is arriving:

   ```bash
   curl -s http://<reporter>:8081/metrics
   # {"datagrams":812,"lines":812,"parsed":812,"rejected":0,...,"written":812}
   ```

`rejected` should stay at zero. A rising counter usually means another device is sending to the
same port, or the firewall is set to *Legacy format*.

### Time zones

SFOS writes a `timezone="..."` abbreviation per message. Common abbreviations are mapped; if a
device uses one that is not recognised, set `DEFAULT_TZ_OFFSET_MINUTES` to that device's offset
(e.g. `330` for IST) so events land on the right minute.

---

---

## Testing with real Sophos syslog

1. Point the firewall's syslog server at the Kira host (above) and watch the collector counters:
   `curl.exe -s http://<host>:8081/metrics` — `parsed` must rise, `rejected`, `dropped` and `db_errors` must stay 0.
2. Replay a capture instead of waiting for traffic (keep real captures out of git; `fw1_samples.log` in this repo is sanitized):

   ```bash
   python3 scripts/replay-real-log.py capture.log --port 5514 --collector http://127.0.0.1:8081 --rate 3000 --rebase
   ```
   It reports parsed / rejected / filtered / resolved-user / written / dropped counts and exits non-zero on any problem.
   Set `RUST_LOG=debug` in `kira.env` and restart to log why a line was rejected.
3. `scripts/e2e-check.py` exercises login, roles, rate limiting and the ingest pipeline end to end; CI runs it against
   the native binaries on every push. `KIRA_USER` / `KIRA_PASSWORD` make the older `smoke-test.py`, `verify-samples.py`,
   `verify-retention.py` and `load-test.py` sign in automatically.

---

## Architecture

```
 Sophos Firewall ──syslog :5514──► sfos-ingest ──COPY──► Postgres ◄── sfos-api (Axum) ◄── browser (React)
                                     parse → noise filter → IP→user    hourly partitions + rollups   login, reports, alerts
```

- `crates/sfos-core` — SFOS tokenizer, timestamps, event normalisation, allow/block derivation.
- `crates/sfos-store` — migrations (`0001`–`0015`), tenants, partitions, COPY writer, auth/session store.
- `crates/sfos-ingest` — listeners, tenant routing, pipeline (noise filter, IP→user), batch writer, maintenance, metrics.
- `crates/sfos-api` — JSON API, authentication middleware, report/alert scheduler, static dashboard hosting.
- `web/` — React 19, TypeScript, Tailwind 4, Recharts.

Storage sizing, measured throughput and backup/restore procedures: [docs/capacity-and-storage.md](docs/capacity-and-storage.md).

---

## Configuration

All settings live in `kira.env` (copy of `kira.env.example`, every variable is explained there). The important ones:

| Variable | Default | Purpose |
| --- | --- | --- |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / — | First administrator, created only when no users exist. Without a password a random one is generated and written once to `.runtime\logs\api.err.log` |
| `API_ADDR` | `0.0.0.0:8080` | Dashboard address and port |
| `SYSLOG_UDP_ADDR` / `SYSLOG_TCP_ADDR` | `0.0.0.0:5514` | Syslog listeners |
| `HEALTH_ADDR` | `0.0.0.0:8081` | Collector `/healthz` and `/metrics` |
| `DROP_NOISE` | *(empty)* | `conn_start`, `ip_spoof_broadcast`, `dns` (comma separated). Recommended: `conn_start,ip_spoof_broadcast` |
| `RESOLVE_USERS` / `IP_USER_TTL_MINUTES` | `true` / `240` | IP→user resolution and its window |
| `RETENTION_HOURS` | `6` | Raw-event window; rollups outlive it |
| `DEFAULT_TZ_OFFSET_MINUTES` | `0` | Offset for timezone abbreviations the collector does not know (`300` = UTC+5) |
| `ALLOWED_SOURCES` | *(empty)* | Only accept syslog from these IPs/CIDRs |
| `TENANT_MAP` | *(empty)* | `CIDR=slug,…` routing to sites |
| `SMTP_*` | *(empty)* | Report and alert e-mail |
| `COOKIE_SECURE` / `TRUST_PROXY` | `false` | Set both to `true` behind an HTTPS reverse proxy |
| `AUTH_DISABLED` | `false` | Turns the login off entirely. Never on a reachable host |

Further tuning (`BATCH_SIZE`, `BATCH_MS`, `QUEUE_CAPACITY`, `DB_POOL_SIZE`, `PARTITIONS_AHEAD_HOURS`,
`KEEP_EXTENDED_ATTRIBUTES`, `API_STATEMENT_TIMEOUT_MS`, `API_MAX_CONCURRENT_QUERIES`, `RETENTION_ADMIN_TOKEN`,
`SESSION_HOURS`) can be added to `kira.env` the same way.

### Security notes

- The dashboard and API require login; viewers are read-only and cannot manage users. Put TLS in front
  (Caddy, nginx, Traefik) and set `COOKIE_SECURE=true`. Do not expose the dashboard to the internet.
- The syslog port has no authentication: restrict it with `ALLOWED_SOURCES` and the host firewall.
- `kira.ps1 firewall` opens the ports for Domain/Private only; do not open them on the Public profile.
- The "unidentified" share of traffic depends on Sophos authentication (AD/STAS/captive portal); the IP→user
  resolver only fills gaps from other lines of the same IP.

---

## API

All `/api/v1/*` endpoints except `POST /auth/login` require a session cookie. Time bounds accept RFC3339, epoch
seconds or relative windows (`1h`, `24h`, `7d`); `tenant=<slug>` selects a site.

| Area | Endpoints |
| --- | --- |
| Health | `GET /healthz` (public) |
| Auth | `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `POST /auth/password` |
| Users (admin) | `GET/POST /users`, `DELETE /users/{id}`, `PUT /users/{id}/password` |
| Data | `/meta`, `/overview`, `/top?dimension=…`, `/dashboard/live`, `/events`, `/events/export` |
| Reports | `/reports/schedules[/{id}[/generate\|results]]`, `/reports/generate`, `/reports/templates[/{id}]`, `/reports/custom[/{id}[/run]]` |
| Alerts | `/alerts/rules[/{id}]`, `/alerts/instances`, `/alerts/instances/{id}/acknowledge`, `/webhook/test` |
| Retention | `GET/PUT /retention` (PUT needs `RETENTION_ADMIN_TOKEN`) |

---

## Multi-tenant / MSP use

A single collector can receive from several firewalls and separate their data:

```env
TENANT_MAP=192.0.2.0/24=acme,198.51.100.0/24=branch
TENANT_SLUG=default
```

- Longest prefix wins; unmatched sources fall through to `TENANT_SLUG`.
- Tenants are created automatically the first time a mapped source sends a log.
- Query any site with `?tenant=acme`; the dashboard shows a site selector when more than one
  tenant exists.

This is routing, not isolation: all tenants share one database and one API keyless surface. Add
per-tenant API credentials and row-level authorization before exposing it to customers.

---

---

## Development

```bash
cargo test --workspace --locked          # unit tests; set TEST_DATABASE_URL to also run the Postgres migration test
npm --prefix web ci && npm --prefix web run typecheck && npm --prefix web run build
scripts/dev.sh start                      # Linux/macOS local stack; Windows: scripts\\windows\\kira.ps1
```

CI (`.github/workflows/ci.yml`) runs the Rust tests against a Postgres service, the web typecheck/build
and an end-to-end job that builds the release binaries, starts them against a Postgres service, replays the sanitized capture and runs
`scripts/e2e-check.py`.

---

## Troubleshooting

**Logs not arriving? Start here.**

- **Dashboard:** open the **System** tab. It shows the last event, events per minute, the collector counters and, if something
  is wrong, a diagnosis card with the exact command-line *and* Windows/Sophos screen steps to fix it.
- **Command line:** `.\scripts\windows\kira.ps1 doctor` checks services, ports, firewall rules, network profile
  (Public blocks the rules), live counters (two samples), newest stored event, recent log errors and disk space.
  `doctor -Fix` restarts Kira and (as Administrator) re-opens the firewall.
- Full guide: [docs/troubleshooting.md](docs/troubleshooting.md).

| Symptom | Check |
| --- | --- |
| Dashboard empty, no errors | `curl.exe :8081/metrics`; `parsed` must increase. Confirm the firewall targets this host's LAN IP on `5514` and *Device standard format*. The collector must listen on `0.0.0.0` (default; check with `ss -lunp | grep 5514`), and the host firewall must allow UDP 5514. |
| Dashboard shows demo values | Synthetic seed data was loaded. Run `scripts/reset-data.sh` (or `--demo-only`) and let real logs refill. |
| `rejected` counter rising | Another syslog source shares the port, or the payload is Sophos UTM/Cyberoam legacy format (not supported yet). `RUST_LOG=debug` samples rejected lines. |
| Users show “unidentified” | Authentication/SSO must be active and the rule logging usernames; web-filter logs include `user_name` only then. |
| Times are offset | Set `DEFAULT_TZ_OFFSET_MINUTES` for abbreviations not in the built-in table. |
| Health says `ingest_stale: true` | No event in the last 15 minutes — firewall stopped logging or delivery is blocked. |
| Postgres disk growth | Run `scripts/diagnose-storage.sh`. Confirm the hourly migration completed and `RETENTION_HOURS` is set as intended. |

For real deployments, restrict `ALLOWED_SOURCES` to the firewall or relay IPs that should be
sending logs. The collector accepts any source by default when the allow-list is empty.

---

---

## Roadmap

Done: baseline and verification (Release 0), correct Sophos data (1), storage controls and retention (2), web/user
reporting and CSV export (3), scheduled reports, alerts, custom reports (5), **login, noise filtering and IP→user
resolution (6)**.

Next, in priority order:
1. **Identity**: Active Directory/LDAP (or Entra ID) sync for display names, groups and departments; Sophos STAS /
   captive-portal / RADIUS for Wi-Fi and server subnets (Wi-Fi is currently 100% unidentified).
2. **Site Clean and browse time**: filter ads/CDN/telemetry/background requests, estimate time spent per site.
3. **Report data**: department report (uses `user_department_map`), search terms and YouTube titles (needs SSL/TLS
   inspection on the firewall), safeguarding report, productivity categories.
4. **Delivery**: report templates as files, alert throttling, Zulip-formatted alert payloads.
5. **Operations**: run as a real Windows service, automated backups, `/metrics` in Prometheus format, ClickHouse option for
   very high volumes, spill-to-disk queue so a database outage loses nothing.
