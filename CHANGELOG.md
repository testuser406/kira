# Changelog

All notable changes to Kira. Versions follow [Semantic Versioning](https://semver.org/); each release is
tagged `vX.Y.Z` on GitHub and the Windows package is attached to the release. The plan for upcoming
versions is the release roadmap (v1.0.0 = Fastvue Reporter parity from firewall logs).

## [Unreleased]

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
