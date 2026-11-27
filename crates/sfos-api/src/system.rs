//! System health: is data arriving, and if not, what to do about it (CLI and GUI steps).

use axum::extract::State;
use axum::Json;
use chrono::Utc;
use serde_json::{json, Value};

use crate::api::{ApiError, AppState};

fn hint(severity: &str, title: &str, detail: &str, cli: &[&str], gui: &[&str]) -> Value {
    json!({ "severity": severity, "title": title, "detail": detail, "cli": cli, "gui": gui })
}

async fn ingest_metrics() -> Option<Value> {
    let url = std::env::var("INGEST_METRICS_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8081/metrics".into());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .ok()?;
    client
        .get(url)
        .send()
        .await
        .ok()?
        .json::<Value>()
        .await
        .ok()
}

pub async fn health(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let db_ok = state.store.ping().await.is_ok();
    let tenant = match state.default_slug.as_deref() {
        Some(slug) => state.store.tenant_by_slug(slug).await.ok().flatten(),
        None => state.store.default_tenant().await.ok().flatten(),
    };
    let now = Utc::now();
    let mut last_event = None;
    let (mut per_minute, mut db_size, mut last_rollup) = (Vec::<Value>::new(), 0i64, None);
    if let (true, Some(t)) = (db_ok, &tenant) {
        last_event = state.store.last_event_at(t.id).await.unwrap_or(None);
        let client = state.store.pool().get().await?;
        let rows = client
            .query(
                "SELECT bucket, events FROM minute_rollups
                 WHERE tenant_id = $1 AND dimension = 'overview' AND key = ''
                   AND bucket > now() - interval '60 minutes' ORDER BY bucket",
                &[&t.id],
            )
            .await?;
        for r in &rows {
            per_minute.push(
                json!({"t": r.get::<_, chrono::DateTime<Utc>>(0), "events": r.get::<_, i64>(1)}),
            );
        }
        last_rollup = client
            .query_one(
                "SELECT max(bucket) FROM minute_rollups WHERE tenant_id = $1",
                &[&t.id],
            )
            .await?
            .get::<_, Option<chrono::DateTime<Utc>>>(0);
        db_size = client
            .query_one("SELECT pg_database_size(current_database())", &[])
            .await?
            .get(0);
    }
    let sum_last = |mins: i64| -> i64 {
        let cut = now - chrono::Duration::minutes(mins);
        per_minute
            .iter()
            .filter(|p| {
                p["t"]
                    .as_str()
                    .and_then(|s| s.parse::<chrono::DateTime<Utc>>().ok())
                    .is_some_and(|t| t > cut)
            })
            .filter_map(|p| p["events"].as_i64())
            .sum()
    };
    let (ev1, ev5, ev60) = (sum_last(2), sum_last(5), sum_last(60));
    let age = last_event.map(|t| (now - t).num_seconds());
    let ingest = ingest_metrics().await;

    let mut hints: Vec<Value> = Vec::new();
    if !db_ok {
        hints.push(hint(
            "error",
            "Database is not reachable",
            "Kira cannot talk to PostgreSQL, so nothing can be stored or shown.",
            &[
                r".\scripts\windows\kira.ps1 status",
                r".\scripts\windows\kira.ps1 stop",
                r".\scripts\windows\kira.ps1 start",
                r"Get-Content .runtime\logs\postgres*.log -Tail 40",
            ],
            &[
                "Task Manager > Details: look for postgres.exe",
                "Check free disk space (File Explorer > This PC)",
                "If it keeps failing, read the newest .runtime\\logs\\postgres*.log",
            ],
        ));
    }
    match &ingest {
        None => hints.push(hint("error", "Collector (sfos-ingest) is not running",
            "The API cannot reach the collector's metrics port, so no syslog is being received.",
            &[r".\scripts\windows\kira.ps1 start", r"Get-Content .runtime\logs\ingest*.err.log -Tail 40", "Get-NetUDPEndpoint -LocalPort 5514   # port already used by another program?"],
            &["Task Manager > Details: sfos-ingest.exe should be running", "If the log says the port is in use, close the other syslog program or change SYSLOG_UDP_ADDR in kira.env"])),
        Some(m) => {
            let g = |k: &str| m[k].as_u64().unwrap_or(0);
            if g("datagrams") == 0 && g("lines") == 0 {
                hints.push(hint("error", "No syslog has reached the collector since it started",
                    "Most common causes: Windows Firewall rule missing or the network profile is Public; Sophos is not sending to this PC's IP/port; wrong protocol.",
                    &[r".\scripts\windows\kira.ps1 firewall   # run as Administrator", "Get-NetConnectionProfile   # must be Private or DomainAuthenticated, not Public", "Get-NetUDPEndpoint -LocalPort 5514", "ipconfig   # confirm this PC's IP is the one Sophos sends to"],
                    &["Windows Security > Firewall & network protection > Advanced settings > Inbound Rules: 'Kira Syslog UDP 5514' must be enabled",
                      "Settings > Network & internet > your connection > set Network profile to Private",
                      "Sophos Firewall: System services > Log settings > Syslog servers: this PC's IP, port 5514, UDP, format 'Device standard'",
                      "Sophos Firewall: enable logging on the firewall rules you want to see and tick the log categories to send"]));
            }
            if g("denied_sources") > 0 {
                hints.push(hint("error", "Syslog is arriving from a source that is not allowed",
                    "ALLOWED_SOURCES in kira.env does not include the firewall's IP, so its logs are discarded.",
                    &["notepad kira.env   # add the Sophos IP to ALLOWED_SOURCES, or leave it empty to allow all", r".\scripts\windows\kira.ps1 stop; .\scripts\windows\kira.ps1 start"],
                    &["Open kira.env in the Kira folder, edit ALLOWED_SOURCES, save, then restart Kira"]));
            }
            if g("rejected") > 0 && g("parsed") == 0 {
                hints.push(hint("warn", "Logs arrive but cannot be parsed",
                    "The collector expects Sophos 'Device standard' syslog format key=value lines.",
                    &[r"Get-Content .runtime\logs\ingest*.err.log -Tail 40"],
                    &["Sophos Firewall > Log settings > Syslog server: set Format to 'Device standard' (not 'Standard syslog')"]));
            }
            if g("db_errors") > 0 || g("dropped") > 0 {
                hints.push(hint("error", "Logs are received but writing to the database fails",
                    &format!("{} database errors, {} events dropped. Look for 'failed to write batch' or 'minute rollup failed' in the ingest log.", g("db_errors"), g("dropped")),
                    &[r"Select-String -Path .runtime\logs\ingest*.err.log -Pattern 'failed|rollup|dropp' | Select-Object -Last 20", r".\scripts\windows\kira.ps1 stop; .\scripts\windows\kira.ps1 start", "Get-PSDrive C   # free disk space"],
                    &["Check free disk space", "Restart Kira (Start menu > PowerShell > the stop/start commands above)", "Send the error lines from .runtime\\logs to support"]));
            }
            if g("os_udp_drops") > 0 {
                hints.push(hint("warn", "The operating system is dropping syslog packets",
                    &format!("{} UDP datagrams were discarded before Kira could read them (receive buffer full). Logs are being lost.", g("os_udp_drops")),
                    &["notepad kira.env   # raise UDP_RCVBUF_MB (default 32), then restart", "netstat -s -p udp   # 'Receive Errors' counts drops (Windows)"],
                    &["Make the firewall send over TCP instead of UDP", "Raise UDP_RCVBUF_MB in kira.env and restart Kira", "If the queue is also full, the database is the bottleneck: check disk speed"]));
            }
            if m["queue_utilization_percent"].as_f64().unwrap_or(0.0) > 80.0 {
                hints.push(hint("warn", "Collector queue is almost full",
                    "Logs arrive faster than the database accepts them; events may be dropped.",
                    &["Check disk speed and CPU; consider raising DB_POOL_SIZE in kira.env"],
                    &["Task Manager > Performance: look for disk or CPU at 100%"]));
            }
        }
    }
    if let Some(t) = last_event {
        if t - now > chrono::Duration::minutes(5) {
            hints.push(hint("warn", "Events carry timestamps in the future",
                "The firewall clock or time zone differs from Kira's DEFAULT_TZ_OFFSET_MINUTES, so new logs look like they come from later. Dashboards for 'now' will look empty.",
                &["Compare Windows time (Get-Date) with the firewall time", "notepad kira.env   # set DEFAULT_TZ_OFFSET_MINUTES to the firewall time zone offset (e.g. 300 for UTC+5), then restart Kira"],
                &["Sophos Firewall > Administration > Time: set the correct time zone and NTP server", "Or set DEFAULT_TZ_OFFSET_MINUTES in kira.env to match the firewall, then restart Kira"]));
        } else if age.unwrap_or(0) > 600 && ingest.is_some() && db_ok {
            hints.push(hint("warn", "No new events stored for over 10 minutes",
                "Check the collector counters below: if 'datagrams' is not growing, nothing is arriving; if it grows but 'written' does not, see the database hints.",
                &[r".\scripts\windows\kira.ps1 doctor"], &["Reload this page in a minute and compare the counters"]));
        }
    } else if db_ok {
        hints.push(hint(
            "info",
            "No events stored yet",
            "Once the firewall sends logs they appear here within a minute.",
            &[r".\scripts\windows\kira.ps1 doctor"],
            &[],
        ));
    }

    let status = if !db_ok || hints.iter().any(|h| h["severity"] == "error") {
        "error"
    } else if hints.iter().any(|h| h["severity"] == "warn") || age.map(|a| a > 300).unwrap_or(true)
    {
        "warn"
    } else {
        "ok"
    };
    Ok(Json(json!({
        "status": status,
        "generated_at": now,
        "database": { "ok": db_ok, "size_bytes": db_size },
        "last_event_at": last_event,
        "last_event_age_secs": age,
        "last_minute_rollup": last_rollup,
        "events_last_1m": ev1, "events_last_5m": ev5, "events_last_60m": ev60,
        "per_minute": per_minute,
        "ingest": ingest,
        "diagnosis": hints,
    })))
}

/// Prometheus text exposition. Requires `METRICS_TOKEN` (Bearer); disabled (404) when it is not set.
pub async fn prometheus(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let Ok(token) = std::env::var("METRICS_TOKEN") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let given = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if token.is_empty() || given != token {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(Json(h)) = health(State(state)).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut out = String::new();
    let mut g = |name: &str, help: &str, v: f64| {
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}\n"
        ));
    };
    g(
        "kira_database_up",
        "1 when PostgreSQL is reachable",
        if h["database"]["ok"] == true {
            1.0
        } else {
            0.0
        },
    );
    g(
        "kira_database_size_bytes",
        "Database size",
        h["database"]["size_bytes"].as_f64().unwrap_or(0.0),
    );
    g(
        "kira_last_event_age_seconds",
        "Seconds since the newest stored event",
        h["last_event_age_secs"].as_f64().unwrap_or(-1.0),
    );
    g(
        "kira_events_last_minute",
        "Events stored in the last 2 minutes",
        h["events_last_1m"].as_f64().unwrap_or(0.0),
    );
    g(
        "kira_events_last_hour",
        "Events stored in the last hour",
        h["events_last_60m"].as_f64().unwrap_or(0.0),
    );
    g(
        "kira_collector_up",
        "1 when the collector answers",
        if h["ingest"].is_object() { 1.0 } else { 0.0 },
    );
    if let Some(m) = h["ingest"].as_object() {
        for (k, v) in m {
            if let Some(n) = v.as_f64() {
                g(&format!("kira_collector_{k}"), "Collector counter", n);
            }
        }
    }
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        out,
    )
        .into_response()
}
