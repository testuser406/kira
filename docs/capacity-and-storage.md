# Capacity planning, storage and recovery

Measurements and procedures moved out of the README. Figures are specific to the hosts and log mixes described.

This Release 0 baseline was measured on a host reporting a 4-vCPU Intel Xeon Silver 4210R,
7.8 GiB RAM, and a 150 GB virtual disk. It is a reproducible reference environment, not a
minimum hardware recommendation.

Run `scripts/diagnose-storage.sh` while the Compose database is running to report database
footprint, retained event count, approximate ingestion rate, storage per event, projected daily
event storage and largest daily partitions. The event count requires a sequential scan and may
take time on a large database; the script is read-only and has a 120-second statement timeout.
Use `docker system df -v` to see Docker volume, image and build-cache usage separately.
Run `scripts/verify-release0.sh` for an isolated clean-install test. It starts a separate Compose
project bound to loopback-only test ports, replays the seven anonymized captured samples plus two
clearly labeled synthetic threat/authentication events, checks raw API rows and hourly dashboard
aggregates, measures a deterministic load, restores a backup into a scratch database, and removes
the test volume. The replay rebases sample timestamps to the current time so the configured
six-hour raw window does not hide them. Use `--keep` to retain the isolated stack for browser
inspection; remove it with the command printed at completion.

API database statements have a 10-second timeout by default (`API_STATEMENT_TIMEOUT_MS`, configurable
from 1 to 120000 ms). Overview/top/event-search requests are limited to at most two concurrent
analytical requests, leaving spare pool capacity for health and metadata calls under the default
pool size. A busy API returns HTTP 503 rather than queuing unlimited expensive work. Query timeouts
also return HTTP 503. Fresh empty databases mark
their rollups ready automatically; populated databases are not marked ready without a verified
backfill, and startup logs a warning when dashboard aggregates may still use raw events. The
`/events?q=` filter remains substring search; timeouts and concurrency limits bound its impact but
do not replace a measured search index.

The repeatable benchmark sends 10,001 synthetic events: 7,000 web, 2,000 firewall, 500 threat,
300 authentication, 200 VPN, and one relayed firewall event. It uses the default 5,000-event /
2-second batching configuration and reports persistence throughput plus partition storage growth
including indexes. On the documented 4-vCPU, 7.8-GiB host, one isolated run persisted all 10,001
events in 3.317 seconds (3,015 events/second), with 5,373,952 bytes of partition growth including
indexes (537.3 bytes/event), a 5,001-event queue high-water mark against 20,000 capacity, and no
drops or database write errors. This is a single controlled run, not a sustained-capacity guarantee.
Record the emitted JSON together with the hardware and actual Compose configuration when refreshing
capacity measurements.

On 2026-10-20, an observed database snapshot contained 1,515,841 events received over 43 minutes.
The database occupied 1.74 GB and its Docker volume 2.65 GB, including 688 MB of WAL. The largest
daily partition occupied 1.73 GB including indexes, or about 1.2 KB per event. The measured
average was about 583 events/second, with peak minutes above 75,000 events. If sustained, that
workload implies roughly 2.5 GB/hour or 56 GiB/day (about 60 GB/day) for event partitions alone;
WAL, backups, and filesystem overhead add to this. Treat this as a measured high-volume sample, not a universal
Sophos rate. This inspection did not find a 14 GB current Compose database; verify the exact
directory or volume before removing anything.

During a later overload, the database held 1,407,431 events (about 1.6 GB including indexes)
received in under an hour. `EXPLAIN` showed dashboard totals and top-category queries using parallel
sequential scans over the active daily partition. The dashboard previously launched six database-
backed requests together every five seconds, repeatedly aggregating those same raw rows. It now
runs dashboard requests sequentially and waits 60 seconds after each completed refresh; the manual
Refresh control still works immediately. This reduces overlapping query pressure but does not
replace the planned compact rollups: raw-event aggregation cost still grows with the selected
time range and event volume. The 1,407,431 accumulated event rows were then truncated while
retaining the schema and default tenant. After a PostgreSQL checkpoint, the database measured
about 8.5 MB and event partitions about 240 KB; the volume still held about 640 MB of reusable WAL.
No backup was made for this cleanup; older Release 0 backup/restore verification covered the
earlier dataset, not these subsequently received events. Never delete files from `pg_wal` manually.

A live check later on 2026-10-20 observed about 1.21 million events in the active partition
(roughly 1.4 GB including indexes), with 50,000–58,000 events in each of several recent full
minutes. That is around 900 events/second and about 1.1 KB/event, or close to 90 GB/day of event
partition growth if sustained. PostgreSQL CPU briefly reached about 285% in one sample, then later
samples were 6–16%; the host had about 5 GB RAM available and 79 GB disk free. The collector
reported zero database errors and drops at the later sample. Its cumulative queued/written counters
temporarily differed by about 13,000 events (the queue capacity is 20,000), so monitor backlog as
well as drop/error counters. This ingest rate, not refresh frequency alone, is the immediate
storage risk; current daily partitions cannot protect a disk from filling within a day.

The same live investigation found a more direct dashboard overload source: `/api/v1/meta` was
grouping the full 24-hour event table by computed device name/ID and sorting the groups. The
frontend polled metadata every 60 seconds without waiting for the previous request to finish.
PostgreSQL showed multiple copies of this query, several minutes old and writing temporary sort
files; cumulative `pg_stat_database.temp_bytes` reached about 71 GB. That is historical temp-file
I/O, not 71 GB of retained database data. The stale queries were cancelled. Metadata now aggregates
only the last five minutes, and the browser schedules the next metadata refresh five minutes after
the previous one completes. This is a protective bound; a small device registry updated during
ingestion is the durable replacement for querying raw events.

The initial overview and top-dimension queries also scanned raw events for the selected range.
They now read only the compact hourly rollups, which are updated in the same transaction as each
ingest batch; event-detail searches continue to use the six-hour raw window. This avoids rescanning
millions of raw rows on dashboard refresh. Aggregate charts use whole-hour buckets; the current
hour reflects events received so far, and partial range edges include their full hour bucket.
Event details retain event-level timestamps.

After clearing that historical event set, a controlled 10,001-event TCP replay on the same host
stored all events without collector database errors or drops. The current-day partition grew by
about 5.1 MiB including indexes (about **536 bytes/event** for this sample mix). Receive timestamps
spanned 10.36 seconds, or roughly **966 events/second**. Seven-request API checks over the resulting
dataset had median response times of 67 ms for overview, 20 ms for top categories, and 5 ms for the
event list. The fixture smoke test also passed all 26 assertions. These figures are specific to
the test mix and one small dataset; repeat this benchmark on the actual deployment before setting
capacity limits.

The pre-clean backup was restored to a scratch database and its event count matched exactly:
**1,515,841 rows**. The compressed archive was 89 MB. The scratch database and temporary backup
were removed after verification. The old event rows were then truncated; the database now has
zero event rows. PostgreSQL reduced relation storage to about 30 MB but retained roughly 1 GB of
reusable WAL segments near its configured 1 GB `max_wal_size`. WAL is not retained event data and
is reused by PostgreSQL; never delete files from `pg_wal` manually.

Every accepted syslog line is stored as an event row. By default, unmodeled fields in JSONB `attrs`
are discarded except `device_model` and `firmware_version`, which feed the device summary. Set
`KEEP_EXTENDED_ATTRIBUTES=true` to retain every unmodeled Sophos field; this increases storage and
may retain vendor data not used by reports. Storage varies substantially with log mix: the historical sample used about 1.2 KB/event while
the controlled replay used about 536 bytes/event. At the historical sample size, a 14 GB event
database would represent roughly 12 million events. Size requirements depend on actual log rate
and fields; measure the deployment before choosing retention.

In the live sample, `attrs` averaged about 794 bytes in sampled rows. It contains vendor fields
that are not modeled as report columns (such as interfaces, MAC addresses, and rule/application
metadata); it is not a second copy of every normalized field. New compact ingestion reduces new
row size but does not rewrite existing rows.

Dashboard identities now use the source IP when a log has no username, and the top-destinations
panel includes both website domains and application names. The parser also maps `http_user_agent`
to its typed field and no longer retains `device_serial_id` a second time in `attrs`.

Raw event rows use a global retention window (default 6 hours, with up to one extra hour at hourly
partition boundaries). It is editable in the dashboard using a server-configured bearer token; it
is not a per-site setting. Before applying a choice, the dashboard shows the current database size
and approximate projected sizes based on recent PostgreSQL partition statistics. The estimate is
not a capacity guarantee. The collector applies a saved change during maintenance within about five
minutes. The collector refreshes each expiring hour's rollups before dropping that raw partition.
Overview and top-dimension reports use hourly rollups across the full selected range; event detail
search is limited to retained raw rows. Rollup refresh and raw-partition removal are separate,
repeatable operations so a failed refresh cannot discard its source partition.

Rollups are retained independently from raw-event details, so trend summaries survive detail
expiry. The catch-all `events_default` partition is not dropped by hourly retention and should be
monitored if logs can arrive with timestamps outside the pre-created partition range. Optional
compressed event-level exports are deferred: they require additional archive storage and a separate
restore workflow; database backup and restore procedures remain the supported recovery path.

### Upgrade an existing daily-partition database

Existing installs still have the original daily partition layout and must be converted before
starting the new collector. Keep the API and ingest services stopped, leave PostgreSQL running,
ensure sufficient free disk for a logical backup and migration work, then run:

```sh
bash scripts/migrate-hourly-retention.sh /absolute/path/to/sfos-before-hourly.dump
```

The script refuses to overwrite a backup, creates a custom-format `pg_dump`, migrates historical
events into hourly rollups, copies the selected recent raw window into new hourly partitions,
checks summarized and retained row counts, and only then replaces the daily raw table. The backup
is intentionally retained. This operation takes an exclusive table lock and can be I/O intensive;
do not run it while the collector or API is active. The cutover was run against the live database
on 2026-10-20 after a 413 MB custom-format backup was created and validated. The transaction
verified the retained raw count and total summarized event count before swapping tables.

Keep these storage sources distinct when investigating disk use:

- PostgreSQL database and WAL in the Compose volume.
- Native PostgreSQL data under `.runtime/pgdata` when using `scripts/dev.sh`.
- Rust build artifacts under `target/`, Docker images, and Docker build cache.

They are separate copies or build artifacts; measuring the database alone does not account for
all project disk usage. At the same inspection, this workspace also had a separate 4.1 GB native
`.runtime` database directory and 1.9 GB of Rust build artifacts. These should not be mistaken for
the Compose database, and should not be deleted until their contents are confirmed disposable.

For a backup, use a non-TTY stream so custom-format dumps remain intact:

```bash
docker compose exec -T db pg_dump -U sfos -Fc sfos > backup.dump
```

Test restoration into a separate scratch database, after confirming there is enough free space
for both the backup file and restored data. The script below creates a temporary custom-format
backup, restores it into a scratch database, compares event counts, then removes only its scratch
database and temporary archive:

```bash
scripts/verify-backup-restore.sh
```

Do not restore over the production database as a test. The scratch restore temporarily duplicates
database storage; on a small disk, perform it on a separate machine or volume.

---
