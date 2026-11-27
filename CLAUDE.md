# Kira: working notes for Claude (read this first)

Self-hosted Sophos Firewall log reporter, aiming past Fastvue Reporter. Repo: github.com/testuser406/kira. Current version: see `Cargo.toml` (workspace) and `CHANGELOG.md`.
The owner writes Roman Urdu/English; reply in the same mix, short, and token-efficient (no long recaps, don't re-read old chat or whole files).

## Stack
- Rust workspace: `sfos-core` (parser, webextract), `sfos-store` (Postgres, migrations 0001-0026 registered in `src/store.rs`), `sfos-ingest` (UDP/TCP syslog collector, writer, spill, metrics, maintenance), `sfos-api` (axum 0.8: reports, live, productivity, alerts, settings, share, search/investigate, system health, /metrics).
- Web: `web/` React 19 + TS + Tailwind 4 + Recharts + Vite. Shell in `components/Shell.tsx` (sidebar nav, hash routing `#/page`), pages lazy-loaded from `App.tsx`.
- Data layers: raw `events` (hourly partitions, ~6 h) -> `minute_rollups` (7 d) -> `hourly_activity` (400 d). Reports/search read the rollups. Summary engine in `sfos-api/src/summary.rs` renders JSON, CSV, XLSX, PDF.
- Windows native deployment (no Docker): `scripts/windows/kira.ps1` (build/init/start/stop/status/doctor [-Fix]/backup/restore/firewall/autostart), config `kira.env`. Dashboard :8080, syslog UDP/TCP :5514, collector metrics :8081.

## Release workflow (always)
1. Code + tests; `cargo fmt`; `cargo clippy --workspace --all-targets` (CI clippy is newer than local); `cd web && npx tsc --noEmit -p .`; `DATABASE_URL=... cargo test --workspace`.
2. Bump `version` in root `Cargo.toml`, add a `CHANGELOG.md` entry, run `cargo update -w` and commit the lockfile.
3. Conventional commit; push to main. CI (Rust tests with Postgres, web build, Linux e2e `scripts/e2e-check.py`, Windows e2e) must be green; `release.yml` publishes the tag/release on a version bump. Check with `gh run list`. In the Claude session sandbox, git tag push and GitHub API writes are blocked (the workflow does them).
4. Add e2e checks for new endpoints; keep Windows steps robust (retry, print the log tail on failure).

## Done (v0.3 - v1.4)
Live per-minute dashboards, productivity/Site Clean/browse time, 13 report types with deltas, searches/YouTube, alerts + e-mail/webhook delivery, privacy masking, audit log, spill-to-disk, Prometheus metrics, share links, hardening, enterprise UI shell + light theme (beta), faster writer (5000 events/s no loss), UDP drop detection, XLSX export, global search + user timeline, robust collector start.

## Next (full list: the "Kira Release Roadmap" doc, tab "Next Releases (post v1.0)")
- **v1.5 Security analytics (do next):** anomaly detection (traffic spike, new country, new device, unusual hours) from per-user baselines in `hourly_activity`; alert rules on baselines; threat-intel enrichment; IPS/ATP/malware dashboard with attack timeline; brute-force and port-scan detection; geo map.
- Then: multi-firewall/tenants + roles + API tokens + Zulip/Teams (v1.6), safeguarding/watchlists + per-device/MAC (v1.7), platform ops: service installer, auto-update, HTTPS, archive, HA (v1.8), identity last (AD/LDAP/Entra, Wi-Fi identity; the owner has not chosen the method yet).
- Leftovers from the old v1.1 plan: Windows service installer (needs testing on Windows), disk-space warnings, report caching.

## Known facts / gotchas
- Windows UDP "Receive Errors" is a cumulative system-wide counter: only deltas matter.
- `kira.env` inline `#` comments are stripped by both PowerShell and Rust.
- rustfmt reflows code; re-inspect before scripted string replacements.
- Planner trap fixed in v1.2: keep `OFFSET 0` fence in `MINUTE_ROLLUP_BATCH_SQL` subquery, otherwise site/user expressions are re-inlined per dimension (13x slower).
- Masked (non-admin) viewers must never see real user names (search, timelines, reports); use `settings::masks_for`.
- Local debug DB used in sessions: `postgres://postgres:pw@localhost:5432/dbg` (not in repo).
