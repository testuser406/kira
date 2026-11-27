# Changelog

All notable changes to Kira. Versions follow [Semantic Versioning](https://semver.org/); each release is
tagged `vX.Y.Z` on GitHub and the Windows package is attached to the release. The plan for upcoming
versions is the release roadmap (v1.0.0 = Fastvue Reporter parity from firewall logs).

## [Unreleased]

## [1.0.1]

### Fixed
- UDP syslog socket now requests a large receive buffer (`UDP_RCVBUF_MB`, default 32; the effective size is logged and a warning shows if the OS caps it too low).
- Default ingest queue raised to 100,000 events (`QUEUE_CAPACITY`) so bursts are absorbed while a batch is being written.
- Default productivity guidelines now include more real Sophos categories (General Business, Computing & Internet, Web Hosting, Reference, CDNs, Advertisements).
- `scripts/loadtest.py` uses the current time so generated data shows up in reports.

## [1.0.0]

### Added
- **Report share links:** Reports tab > *Share link* creates an expiring (7 day) link to a PDF snapshot of the selected report; anyone with the link can open it without signing in. Masking is honoured; links can be revoked (`DELETE /api/v1/reports/share/{token}`), expired links are purged. Creation is audited.

### Security
- Updated `lettre` (0.11.24, SMTP injection/DoS advisories), `url` and `ctutils`; documented the remaining `chrono` advisory (no fix released).

## [0.9.0]

### Added
- Security headers on every response (CSP, frame denial, nosniff, referrer and permissions policy).
- Audit log viewer (System tab, administrators) and CSV export: `GET /api/v1/audit`.
- `scripts/loadtest.py` synthetic syslog load generator, `docs/security.md` (HTTPS reverse proxy, network, secrets).
- Informational CI job: `npm audit` and `cargo audit`.

## [0.8.0]

### Added
- **Disk spill:** if PostgreSQL is unavailable, batches are parked in `.runtime\spill` (cap `SPILL_MAX_MB`, default 500) and replayed automatically every 15 s; counters `spilled`, `replayed`, `spill_files_pending`.
- **Backups:** `kira.ps1 backup` (pg_dump, keeps the newest 14 in `.runtime\backups`) and `kira.ps1 restore -File <dump>`.
- **Prometheus:** `GET /metrics` with `Authorization: Bearer $METRICS_TOKEN` (disabled when the token is unset).
- **Privacy setting:** hide user names and IPs from non-admin viewers (stable aliases) in reports, live tabs and productivity; admins always see real names. `GET/PUT /api/v1/settings`.

## [0.7.0]

### Added
- Alert rules are evaluated on the per-minute rollups (cheap, independent of the 6-hour raw-event retention).
- New alert conditions: **no logs received** (collector/firewall silence), **single-user bandwidth**, **site visits** (`site:count`).
- Notifications: e-mail recipients per rule (uses `SMTP_*`), webhook format `json` or `text` (Zulip, Slack, Mattermost: `{"text": ...}`), and a **Test** button that sends a test through the rule's channels.
- Migration 0022 widens the alert condition constraint.
- `GET/PUT /api/v1/alerts/rules/{id}/notify`, `POST /api/v1/alerts/rules/{id}/test`.

## [0.6.0]

### Added
- **Internet searches** report: search terms decoded from Google, Bing, DuckDuckGo, Yahoo, Yandex, Baidu, Ecosia, Brave, Startpage, Ask and YouTube search URLs. KPIs, trend, top terms, users, engines and recent searches; optional user filter.
- **YouTube videos** report: video ids from watch, youtu.be, shorts, embed and live URLs with views, users, last seen and links.
- Both are stored in `web_searches` / `web_videos` (kept 90 days), available in the Reports tab, exports (PDF/CSV) and as scheduled reports.
- `doctor` waits for a freshly started collector before reporting the syslog port as closed.

### Notes
- URLs are only visible for HTTP, or HTTPS with SSL/TLS inspection enabled on the firewall.

## [0.5.4]

### Fixed
- `kira.env` inline comments (`ALLOWED_SOURCES=1.2.3.4   # note`) made the collector exit with "invalid CIDR" and receive no logs. `kira.ps1` now strips inline comments, the collector tolerates them, and the example file keeps comments on their own lines.
- `kira.ps1 doctor` reports an invalid ALLOWED_SOURCES from the ingest log; `doctor -Fix` no longer stops a healthy PostgreSQL, and `start` retries PostgreSQL once and prints its log on failure.

## [0.5.3]

### Added
- **System** tab and `GET /api/v1/system/health`: last event age, events per minute, collector counters and automatic diagnosis cards with command-line and GUI fix steps.
- `kira.ps1 doctor [-Fix]`: automatic troubleshooting for services, ports, firewall, network profile, counters, newest event, logs and disk space.
- `docs/troubleshooting.md`.

### Changed
- Dashboard is code-split (lazy tabs, separate charts chunk): no more large-chunk build warning.

## [0.5.2]

### Fixed
- A failing live/report rollup can no longer cause raw events to be dropped: rollups run in a savepoint and errors are logged without losing the batch.

## [0.5.1]

### Added
- Allowed and Blocked columns next to requests in top sites, users by browse time, categories, applications and users tables.
- KPI cards show the change versus the previous period of equal length (dashboard and PDF).
- Reports tab: custom date range, sortable columns, filter box, "show all", and click a user to open their User overview.

## [0.5.0]

### Added
- Summary reports built from long-term hourly rollups (`hourly_activity`, kept 400 days) instead of raw logs:
  executive summary, online productivity, user overview (per-user drill-down), users, allowed/blocked
  websites, security & threats, bandwidth, VPN, firewall policy, subnets, activity timeline.
- Each report has KPIs, trend chart and top-N tables (Top N 10-100). Export to a compact PDF (charts, data bars,
  typically 2-5 pages) or a sectioned CSV; `GET /api/v1/reports/summary`.
- New Reports tab in the dashboard with period (24h-90d), report type, user and Top N selectors.
- Minute rollups gained user-site, user-category, policy, country and subnet dimensions.

### Changed
- On-demand and scheduled reports of these types now use the summary engine (small files, any period up to 366 days).
- Raw detail reports are capped at 5,000 rows (was 100,000).

## [0.4.0]

### Added
- Site Clean: `sfos_site()` merges sub-domains into the registrable site and `sfos_is_noise_site()` removes ad,
  tracker, CDN and OS-update noise; cleaned `sites` are rolled up per minute.
- Productivity guidelines (category/application/site -> productive, neutral, unproductive) with defaults
  seeded per tenant; `GET/PUT/DELETE /api/v1/productivity/guidelines` (writes are admin-only).
- Browse time: minutes with web activity per user, and per site (`GET /api/v1/productivity/summary`).
- New Productivity tab: productivity split, browse time per user, cleaned top sites, guideline editor.

## [0.3.0]

### Added
- Per-minute rollups (`minute_rollups`, kept 7 days), maintained in the same transaction as event writes.
- `GET /api/v1/live/{bandwidth|productivity|security|vpn}?window=5..1440` minute-resolution API.
- Live tabs rebuilt: each shows its own data (bandwidth rate/peak/top users+apps, web requests/categories/sites,
  threat events/top threats+sources, active VPN tunnels/users/traffic), 5m/15m/1h/6h window, 15s refresh.

### Fixed
- Unknown `/api/*` routes now return 404 instead of the dashboard HTML; live tabs explain when the API is outdated.
- Release workflow no longer passes an empty argument to `gh release create`.

### Changed
- Live tabs no longer run the heavy raw-events dashboard query; tab refresh pauses while the page is hidden.

## [0.2.0]

### Added
- Dashboard login: local users, argon2 password hashes, server-side sessions, `admin` and `viewer` roles,
  login rate limiting, audit log, user management in the UI.
- Ingest pipeline: `DROP_NOISE` filter and IP-to-user resolution (`RESOLVE_USERS`).
- Native Windows install (`scripts/windows/kira.ps1`: build, init, start, stop, status, firewall, autostart).
- `scripts/replay-real-log.py` and `scripts/e2e-check.py` for testing with real Sophos syslog.
- Report subtypes migration, default report templates seeded per site.
- CI: Rust tests against Postgres, web build, Linux end-to-end, Windows end-to-end, clippy and fmt enforced.

### Fixed
- Custom reports could not be saved (empty cron rejected by a database constraint).
- On-demand PDF/CSV reports failed with HTTP 500.
- Scheduled and custom report filters were read but never applied.
- Subtype reports crashed CSV/PDF generation; PDF is now multi-page.
- CSV exports neutralise spreadsheet formula injection.
- Test fixtures were missing, which made CI fail from the start.

### Removed
- Docker files and `.kilo` planning notes (the product is installed natively).

## [0.1.0]

### Added
- Syslog collector, SFOS parser, Postgres storage with hourly partitions and rollups.
- Dashboards, event explorer with filters, CSV export, retention controls.
- Multi-tenant routing, report schedules and alert rules (first version).

[Unreleased]: https://github.com/testuser406/kira/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/testuser406/kira/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/testuser406/kira/releases/tag/v0.1.0
