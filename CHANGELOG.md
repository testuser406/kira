# Changelog

All notable changes to Kira. Versions follow [Semantic Versioning](https://semver.org/); each release is
tagged `vX.Y.Z` on GitHub and the Windows package is attached to the release. The plan for upcoming
versions is the release roadmap (v1.0.0 = Fastvue Reporter parity from firewall logs).

## [Unreleased]

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
