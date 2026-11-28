//! v1.5 security analytics: baseline anomaly detection, brute-force / port-scan detection,
//! threat-intel matching, and the security dashboard API.
//!
//! Detectors run every few minutes from the scheduler. Baselines come from `hourly_activity`
//! (14-30 days), the current hour from `minute_rollups`; brute-force, port-scan and IP intel
//! matching read the short-lived raw `events` window. Results are upserted into
//! `security_findings` (one row per kind + subject + UTC day).

use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::{resolve_tenant, ApiError, AppState};

pub const ANOMALY_KINDS: [&str; 4] = ["traffic_spike", "new_country", "new_host", "unusual_hours"];
pub const INTEL_KINDS: [&str; 2] = ["intel_ip", "intel_domain"];

const MIN_BASELINE_DAYS: i64 = 7;
const SPIKE_MIN_BYTES: i64 = 100_000_000;
const BRUTE_FORCE_MIN: i64 = 10;
const PORT_SCAN_PORTS: i64 = 20;
const PORT_SCAN_HOSTS: i64 = 50;
const MAX_INTEL_PER_TENANT: i64 = 200_000;
const MAX_INTEL_PER_REQUEST: usize = 50_000;

struct Finding {
    kind: &'static str,
    severity: &'static str,
    subject: String,
    detail: String,
    count: i64,
}

async fn upsert(
    client: &deadpool_postgres::Client,
    tenant: Uuid,
    now: DateTime<Utc>,
    f: &Finding,
) -> Result<(), ApiError> {
    let day = now.date_naive();
    client
        .execute(
            "INSERT INTO security_findings
                 (tenant_id, kind, severity, subject, detail, day, first_seen, last_seen, count)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8)
             ON CONFLICT (tenant_id, kind, subject, day) DO UPDATE SET
                 last_seen = EXCLUDED.last_seen,
                 detail = EXCLUDED.detail,
                 severity = EXCLUDED.severity,
                 count = GREATEST(security_findings.count, EXCLUDED.count)",
            &[
                &tenant,
                &f.kind,
                &f.severity,
                &f.subject,
                &f.detail,
                &day,
                &now,
                &f.count,
            ],
        )
        .await?;
    Ok(())
}

fn fmt_mb(b: i64) -> String {
    crate::summary::fmt_bytes(b as f64)
}

/// Runs every detector for one tenant. Each detector fails independently.
pub async fn run_detectors(state: &AppState, tenant: Uuid, now: DateTime<Utc>) {
    let client = match state.store.pool().get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(%e, "security detectors: no db connection");
            return;
        }
    };
    let results = [
        ("traffic_spike", traffic_spikes(&client, tenant, now).await),
        (
            "new_country",
            new_keys(&client, tenant, now, "countries", "new_country").await,
        ),
        (
            "new_host",
            new_keys(&client, tenant, now, "users", "new_host").await,
        ),
        ("unusual_hours", unusual_hours(&client, tenant, now).await),
        ("brute_force", brute_force(&client, tenant, now).await),
        ("port_scan", port_scans(&client, tenant, now).await),
        ("intel", intel_matches(&client, tenant, now).await),
    ];
    for (name, r) in results {
        if let Err(e) = r {
            tracing::warn!(detector = name, %e, "security detector failed");
        }
    }
    // Findings older than a year are not useful.
    let _ = client
        .execute(
            "DELETE FROM security_findings WHERE tenant_id = $1 AND last_seen < now() - interval '365 days'",
            &[&tenant],
        )
        .await;
}

/// Mean + 4 sigma (and at least 3x the mean) over per-hour byte totals of the last 14 days.
async fn traffic_spikes(
    client: &deadpool_postgres::Client,
    tenant: Uuid,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let rows = client
        .query(
            "WITH base AS (
                 SELECT key, avg(b) AS m, stddev_samp(b) AS sd FROM (
                     SELECT key, hour, sum(bytes_up + bytes_down)::float8 AS b
                     FROM hourly_activity
                     WHERE tenant_id = $1 AND dimension = 'users'
                       AND hour >= $2::timestamptz - interval '14 days' AND hour < date_trunc('hour', $2::timestamptz) - interval '2 hours'
                     GROUP BY key, hour) h
                 GROUP BY key HAVING count(*) >= 24),
             cur AS (
                 SELECT key, sum(bytes_up + bytes_down)::bigint AS b
                 FROM minute_rollups
                 WHERE tenant_id = $1 AND dimension = 'users' AND bucket >= $2::timestamptz - interval '60 minutes'
                 GROUP BY key)
             SELECT cur.key, cur.b, base.m
             FROM cur JOIN base USING (key)
             WHERE cur.b >= $3 AND cur.b::float8 > base.m + 4 * COALESCE(base.sd, 0) AND cur.b::float8 > 3 * base.m
             ORDER BY cur.b DESC LIMIT 50",
            &[&tenant, &now, &SPIKE_MIN_BYTES],
        )
        .await?;
    for r in rows {
        let (user, b, mean): (String, i64, f64) = (r.get(0), r.get(1), r.get(2));
        let f = Finding {
            kind: "traffic_spike",
            severity: if b as f64 > 10.0 * mean {
                "high"
            } else {
                "medium"
            },
            detail: format!(
                "{} in the last hour vs a typical {} per hour",
                fmt_mb(b),
                fmt_mb(mean as i64)
            ),
            subject: user,
            count: 1,
        };
        upsert(client, tenant, now, &f).await?;
    }
    Ok(())
}

/// A country / user-or-host key active in the last hour that never appeared in the previous
/// 30 days. Needs at least a week of history, otherwise everything would look new.
async fn new_keys(
    client: &deadpool_postgres::Client,
    tenant: Uuid,
    now: DateTime<Utc>,
    dimension: &'static str,
    kind: &'static str,
) -> Result<(), ApiError> {
    let min_events: i64 = if dimension == "countries" { 1 } else { 20 };
    let rows = client
        .query(
            "SELECT c.key, c.ev FROM (
                 SELECT key, sum(events)::bigint AS ev FROM minute_rollups
                 WHERE tenant_id = $1 AND dimension = $3 AND bucket >= $2::timestamptz - interval '60 minutes'
                 GROUP BY key HAVING sum(events) >= $4::bigint) c
             WHERE (SELECT count(DISTINCT date_trunc('day', hour)) FROM hourly_activity
                    WHERE tenant_id = $1 AND dimension = $3 AND hour >= $2::timestamptz - interval '30 days') >= $5
               AND NOT EXISTS (
                    SELECT 1 FROM hourly_activity h
                    WHERE h.tenant_id = $1 AND h.dimension = $3 AND h.key = c.key
                      AND h.hour >= $2::timestamptz - interval '30 days'
                      AND h.hour < date_trunc('hour', $2::timestamptz) - interval '2 hours')
               AND c.key NOT IN ('R1', 'R2', 'Reserved')
             ORDER BY c.ev DESC LIMIT 50",
            &[&tenant, &now, &dimension, &min_events, &MIN_BASELINE_DAYS],
        )
        .await?;
    for r in rows {
        let (key, ev): (String, i64) = (r.get(0), r.get(1));
        let (severity, detail) = if kind == "new_country" {
            (
                "medium",
                format!("First traffic to {key} in 30 days ({ev} events in the last hour)"),
            )
        } else {
            (
                "low",
                format!("First activity from {key} in 30 days ({ev} events in the last hour)"),
            )
        };
        upsert(
            client,
            tenant,
            now,
            &Finding {
                kind,
                severity,
                subject: key,
                detail,
                count: ev,
            },
        )
        .await?;
    }
    Ok(())
}

/// Busy now, but never (>=20 events) in this UTC hour-of-day during the last 14 days.
async fn unusual_hours(
    client: &deadpool_postgres::Client,
    tenant: Uuid,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let rows = client
        .query(
            "WITH act AS (
                 SELECT key, sum(events)::bigint AS ev FROM minute_rollups
                 WHERE tenant_id = $1 AND dimension = 'users' AND bucket >= $2::timestamptz - interval '60 minutes'
                 GROUP BY key HAVING sum(events) >= 100),
             hist AS (
                 SELECT key,
                        count(DISTINCT date_trunc('day', hour)) AS active_days,
                        count(DISTINCT date_trunc('day', hour)) FILTER (
                            WHERE extract(hour FROM hour) = extract(hour FROM date_trunc('hour', $2::timestamptz))
                              AND events >= 20) AS same_hour_days
                 FROM hourly_activity
                 WHERE tenant_id = $1 AND dimension = 'users'
                   AND hour >= $2::timestamptz - interval '14 days' AND hour < date_trunc('hour', $2::timestamptz) - interval '2 hours'
                   AND key IN (SELECT key FROM act)
                 GROUP BY key)
             SELECT act.key, act.ev FROM act JOIN hist USING (key)
             WHERE hist.active_days >= 5 AND hist.same_hour_days = 0
             ORDER BY act.ev DESC LIMIT 50",
            &[&tenant, &now],
        )
        .await?;
    for r in rows {
        let (user, ev): (String, i64) = (r.get(0), r.get(1));
        let f = Finding {
            kind: "unusual_hours",
            severity: "low",
            detail: format!(
                "{ev} events at {:02}:00 UTC, an hour this user was not active in the last 14 days",
                chrono::Timelike::hour(&now)
            ),
            subject: user,
            count: ev,
        };
        upsert(client, tenant, now, &f).await?;
    }
    Ok(())
}

/// Many failed authentications from one source in 15 minutes (spraying if several accounts).
async fn brute_force(
    client: &deadpool_postgres::Client,
    tenant: Uuid,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let since = now - Duration::minutes(15);
    let rows = client
        .query(
            "SELECT host(src_ip), count(*)::bigint, count(DISTINCT user_name)::bigint
             FROM events
             WHERE tenant_id = $1 AND ts >= $2 AND category_group = 'auth' AND src_ip IS NOT NULL
               AND (action = 'blocked' OR status ILIKE '%fail%' OR log_subtype ILIKE '%fail%'
                    OR reason ILIKE '%fail%')
             GROUP BY 1 HAVING count(*) >= $3
             ORDER BY 2 DESC LIMIT 50",
            &[&tenant, &since, &BRUTE_FORCE_MIN],
        )
        .await?;
    for r in rows {
        let (ip, n, users): (String, i64, i64) = (r.get(0), r.get(1), r.get(2));
        let spray = users >= 5;
        let f = Finding {
            kind: "brute_force",
            severity: if n >= 50 { "high" } else { "medium" },
            detail: if spray {
                format!(
                    "{n} failed logins across {users} accounts in 15 minutes (password spraying)"
                )
            } else {
                format!("{n} failed logins in 15 minutes")
            },
            subject: ip,
            count: n,
        };
        upsert(client, tenant, now, &f).await?;
    }
    Ok(())
}

/// One source hitting many distinct blocked ports (vertical) or hosts (horizontal) in 10 minutes.
async fn port_scans(
    client: &deadpool_postgres::Client,
    tenant: Uuid,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let since = now - Duration::minutes(10);
    let rows = client
        .query(
            "SELECT host(src_ip), count(*)::bigint, count(DISTINCT dst_port)::bigint,
                    count(DISTINCT dst_ip)::bigint
             FROM events
             WHERE tenant_id = $1 AND ts >= $2 AND category_group = 'firewall' AND action = 'blocked'
               AND src_ip IS NOT NULL AND dst_port IS NOT NULL
             GROUP BY 1
             HAVING count(DISTINCT dst_port) >= $3 OR count(DISTINCT dst_ip) >= $4
             ORDER BY 2 DESC LIMIT 50",
            &[&tenant, &since, &PORT_SCAN_PORTS, &PORT_SCAN_HOSTS],
        )
        .await?;
    for r in rows {
        let (ip, n, ports, hosts): (String, i64, i64, i64) =
            (r.get(0), r.get(1), r.get(2), r.get(3));
        let f = Finding {
            kind: "port_scan",
            severity: if ports >= 100 || hosts >= 200 {
                "high"
            } else {
                "medium"
            },
            detail: format!(
                "{n} blocked connections to {ports} ports on {hosts} hosts in 10 minutes"
            ),
            subject: ip,
            count: n,
        };
        upsert(client, tenant, now, &f).await?;
    }
    Ok(())
}

/// Matches imported indicators against the last 15 minutes of traffic.
async fn intel_matches(
    client: &deadpool_postgres::Client,
    tenant: Uuid,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let have: Vec<String> = client
        .query(
            "SELECT DISTINCT kind FROM threat_intel WHERE tenant_id = $1",
            &[&tenant],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let since = now - Duration::minutes(15);
    if have.iter().any(|k| k == "ip") {
        for (col, dir) in [("dst_ip", "contacted"), ("src_ip", "connected in from")] {
            let sql = format!(
                "SELECT t.indicator, count(*)::bigint FROM events e
                 JOIN threat_intel t ON t.tenant_id = e.tenant_id AND t.kind = 'ip'
                                    AND t.indicator = host(e.{col})
                 WHERE e.tenant_id = $1 AND e.ts >= $2 AND e.{col} IS NOT NULL
                 GROUP BY 1 ORDER BY 2 DESC LIMIT 100"
            );
            for r in client.query(sql.as_str(), &[&tenant, &since]).await? {
                let (ip, n): (String, i64) = (r.get(0), r.get(1));
                let f = Finding {
                    kind: "intel_ip",
                    severity: "high",
                    detail: format!(
                        "{n} connections {dir} a listed malicious IP in the last 15 minutes"
                    ),
                    subject: ip,
                    count: n,
                };
                upsert(client, tenant, now, &f).await?;
            }
        }
    }
    if have.iter().any(|k| k == "domain") {
        let rows = client
            .query(
                "SELECT t.indicator, sum(m.events)::bigint
                 FROM minute_rollups m
                 JOIN threat_intel t ON t.tenant_id = m.tenant_id AND t.kind = 'domain'
                                    AND (t.indicator = lower(m.key) OR lower(m.key) LIKE '%.' || t.indicator)
                 WHERE m.tenant_id = $1 AND m.dimension = 'domains' AND m.bucket >= $2
                 GROUP BY 1 ORDER BY 2 DESC LIMIT 100",
                &[&tenant, &since],
            )
            .await?;
        for r in rows {
            let (d, n): (String, i64) = (r.get(0), r.get(1));
            let f = Finding {
                kind: "intel_domain",
                severity: "high",
                detail: format!("{n} requests to a listed malicious domain in the last 15 minutes"),
                subject: d,
                count: n,
            };
            upsert(client, tenant, now, &f).await?;
        }
    }
    Ok(())
}

/// Alert-rule hook: message when at least `threshold` findings of these kinds were seen in the
/// last hour (acknowledged findings are ignored).
pub async fn alert_message(
    client: &deadpool_postgres::Client,
    tenant: Uuid,
    kinds: &[&str],
    threshold: i64,
    now: DateTime<Utc>,
) -> Result<Option<String>, ApiError> {
    let kinds: Vec<String> = kinds.iter().map(|k| (*k).to_string()).collect();
    let since = now - Duration::hours(1);
    let rows = client
        .query(
            "SELECT kind, subject FROM security_findings
             WHERE tenant_id = $1 AND kind = ANY($2) AND last_seen >= $3 AND NOT acknowledged
             ORDER BY last_seen DESC LIMIT 5",
            &[&tenant, &kinds, &since],
        )
        .await?;
    let total: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM security_findings
             WHERE tenant_id = $1 AND kind = ANY($2) AND last_seen >= $3 AND NOT acknowledged",
            &[&tenant, &kinds, &since],
        )
        .await?
        .get(0);
    if total < threshold.max(1) {
        return Ok(None);
    }
    let sample: Vec<String> = rows
        .iter()
        .map(|r| format!("{}: {}", r.get::<_, String>(0), r.get::<_, String>(1)))
        .collect();
    Ok(Some(format!(
        "{total} security finding(s) in the last hour ({})",
        sample.join("; ")
    )))
}

// ---------- API ----------

#[derive(Debug, Deserialize)]
pub struct SecurityQuery {
    pub tenant: Option<String>,
    pub hours: Option<i32>,
    pub status: Option<String>,
    pub kind: Option<String>,
    pub limit: Option<i64>,
}

fn user_based(kind: &str) -> bool {
    matches!(kind, "traffic_spike" | "new_host" | "unusual_hours")
}

/// GET /api/v1/security/summary?hours=24 - IPS/ATP/malware dashboard, attack timeline, geo.
pub async fn summary(
    State(state): State<AppState>,
    axum::Extension(cu): axum::Extension<crate::auth::CurrentUser>,
    Query(q): Query<SecurityQuery>,
) -> Result<Json<Value>, ApiError> {
    let _permit = crate::api::acquire_query_permit(
        &state.query_semaphore,
        "query capacity is busy; retry shortly",
    )?;
    let tenant = resolve_tenant(&state, q.tenant.as_deref()).await?;
    let hours = q.hours.unwrap_or(24).clamp(1, 168);
    let masked = crate::settings::masks_for(&state, &cu).await;
    let client = state.store.pool().get().await?;
    let since = Utc::now() - Duration::hours(i64::from(hours));

    let totals = client
        .query_one(
            "SELECT COALESCE(sum(events), 0)::bigint, COALESCE(sum(blocked), 0)::bigint
             FROM minute_rollups
             WHERE tenant_id = $1 AND dimension = 'group' AND key = 'threat' AND bucket >= $2",
            &[&tenant.id, &since],
        )
        .await?;
    let timeline = client
        .query(
            "SELECT date_trunc('hour', bucket) AS t, key, sum(events)::bigint
             FROM minute_rollups
             WHERE tenant_id = $1 AND dimension = 'threat_types' AND bucket >= $2
             GROUP BY 1, 2 ORDER BY 1, 2",
            &[&tenant.id, &since],
        )
        .await?;
    let ranked = |dim: &'static str, limit: i64| {
        let client = &client;
        let tid = tenant.id;
        async move {
            client
                .query(
                    "SELECT key, sum(events)::bigint, sum(blocked)::bigint
                     FROM minute_rollups
                     WHERE tenant_id = $1 AND dimension = $2 AND bucket >= $3
                     GROUP BY key ORDER BY 2 DESC, 1 LIMIT $4",
                    &[&tid, &dim, &since, &limit],
                )
                .await
        }
    };
    let to_json = |rows: Vec<tokio_postgres::Row>| -> Vec<Value> {
        rows.iter()
            .map(|r| json!({"key": r.get::<_, String>(0), "events": r.get::<_, i64>(1), "blocked": r.get::<_, i64>(2)}))
            .collect()
    };
    let types = to_json(ranked("threat_types", 10).await?);
    let threats = to_json(ranked("threats", 10).await?);
    let sources = if masked {
        Vec::new()
    } else {
        to_json(ranked("threat_sources", 10).await?)
    };
    let countries = to_json(ranked("countries", 60).await?);

    let sev = client
        .query(
            "SELECT severity, count(*)::bigint FROM security_findings
             WHERE tenant_id = $1 AND NOT acknowledged AND last_seen >= $2 GROUP BY 1",
            &[&tenant.id, &since],
        )
        .await?;
    let mut open = json!({"low": 0, "medium": 0, "high": 0, "critical": 0});
    for r in &sev {
        open[r.get::<_, String>(0)] = json!(r.get::<_, i64>(1));
    }
    let points: Vec<Value> = timeline
        .iter()
        .map(|r| {
            json!({
                "t": r.get::<_, DateTime<Utc>>(0),
                "type": r.get::<_, String>(1),
                "events": r.get::<_, i64>(2),
            })
        })
        .collect();
    Ok(Json(json!({
        "hours": hours,
        "threat_events": totals.get::<_, i64>(0),
        "threat_blocked": totals.get::<_, i64>(1),
        "open_findings": open,
        "timeline": points,
        "types": types,
        "top_threats": threats,
        "top_sources": sources,
        "countries": countries,
        "sources_masked": masked,
    })))
}

/// GET /api/v1/security/findings?status=open|all&kind=&hours=168&limit=100
pub async fn findings(
    State(state): State<AppState>,
    axum::Extension(cu): axum::Extension<crate::auth::CurrentUser>,
    Query(q): Query<SecurityQuery>,
) -> Result<Json<Value>, ApiError> {
    let tenant = resolve_tenant(&state, q.tenant.as_deref()).await?;
    let masked = crate::settings::masks_for(&state, &cu).await;
    let hours = q.hours.unwrap_or(168).clamp(1, 24 * 365);
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let since = Utc::now() - Duration::hours(i64::from(hours));
    let only_open = q.status.as_deref().unwrap_or("open") != "all";
    let kind = q.kind.clone().unwrap_or_default();
    let client = state.store.pool().get().await?;
    let rows = client
        .query(
            "SELECT id, kind, severity, subject, detail, first_seen, last_seen, count, acknowledged
             FROM security_findings
             WHERE tenant_id = $1 AND last_seen >= $2 AND ($3 = '' OR kind = $3)
               AND (NOT $4 OR NOT acknowledged)
             ORDER BY last_seen DESC LIMIT $5",
            &[&tenant.id, &since, &kind, &only_open, &limit],
        )
        .await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            let k: String = r.get(1);
            let hide = masked && (user_based(&k) || k == "brute_force" || k == "port_scan");
            json!({
                "id": r.get::<_, Uuid>(0),
                "kind": k,
                "severity": r.get::<_, String>(2),
                "subject": if hide { "(masked)".to_string() } else { r.get::<_, String>(3) },
                "detail": if hide { String::new() } else { r.get::<_, String>(4) },
                "first_seen": r.get::<_, DateTime<Utc>>(5),
                "last_seen": r.get::<_, DateTime<Utc>>(6),
                "count": r.get::<_, i64>(7),
                "acknowledged": r.get::<_, bool>(8),
            })
        })
        .collect();
    Ok(Json(json!({ "findings": items })))
}

/// POST /api/v1/security/findings/{id}/ack
pub async fn ack_finding(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let client = state.store.pool().get().await?;
    let n = client
        .execute(
            "UPDATE security_findings SET acknowledged = true WHERE id = $1",
            &[&id],
        )
        .await?;
    if n == 0 {
        return Err(ApiError::not_found("finding not found"));
    }
    Ok(Json(json!({ "ok": true })))
}

// ---------- threat intel ----------

/// Parses a pasted feed: one indicator per line (IP or domain), `#` comments, hosts-file lines
/// (`0.0.0.0 evil.example`), URLs and CSV (`indicator,notes`). Returns (indicator, kind).
pub fn parse_indicators(text: &str) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut toks = line.split(|c: char| c.is_whitespace() || c == ',' || c == ';');
        let mut tok = toks.find(|t| !t.is_empty()).unwrap_or("");
        if matches!(tok, "0.0.0.0" | "127.0.0.1" | "::1") {
            if let Some(next) = toks.find(|t| !t.is_empty()) {
                tok = next;
            }
        }
        let mut t = tok.trim().to_ascii_lowercase();
        if let Some(rest) = t.split_once("://").map(|(_, r)| r.to_string()) {
            t = rest;
        }
        let t = t
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .trim_end_matches('.')
            .trim_start_matches("*.")
            .to_string();
        if t.is_empty() || t.len() > 253 {
            continue;
        }
        let item = if let Ok(ip) = t.parse::<std::net::IpAddr>() {
            if ip.is_unspecified() || ip.is_loopback() {
                continue;
            }
            Some((ip.to_string(), "ip"))
        } else if t.contains('.')
            && !t.starts_with('.')
            && !t.contains("..")
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            && t.chars().any(|c| c.is_ascii_alphabetic())
        {
            Some((t, "domain"))
        } else {
            None
        };
        if let Some((ind, kind)) = item {
            if seen.insert(ind.clone()) {
                out.push((ind, kind));
            }
        }
    }
    out
}

/// GET /api/v1/security/intel
pub async fn intel_list(
    State(state): State<AppState>,
    Query(q): Query<SecurityQuery>,
) -> Result<Json<Value>, ApiError> {
    let tenant = resolve_tenant(&state, q.tenant.as_deref()).await?;
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let client = state.store.pool().get().await?;
    let total: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM threat_intel WHERE tenant_id = $1",
            &[&tenant.id],
        )
        .await?
        .get(0);
    let rows = client
        .query(
            "SELECT indicator, kind, source, added_at FROM threat_intel
             WHERE tenant_id = $1 ORDER BY added_at DESC, indicator LIMIT $2",
            &[&tenant.id, &limit],
        )
        .await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "indicator": r.get::<_, String>(0),
                "kind": r.get::<_, String>(1),
                "source": r.get::<_, String>(2),
                "added_at": r.get::<_, DateTime<Utc>>(3),
            })
        })
        .collect();
    Ok(Json(json!({ "total": total, "items": items })))
}

#[derive(Debug, Deserialize)]
pub struct IntelBody {
    pub text: Option<String>,
    pub url: Option<String>,
    pub source: Option<String>,
}

/// POST /api/v1/security/intel - add indicators from pasted text and/or a feed URL (admin).
pub async fn intel_add(
    State(state): State<AppState>,
    axum::Extension(cu): axum::Extension<crate::auth::CurrentUser>,
    Query(q): Query<SecurityQuery>,
    Json(body): Json<IntelBody>,
) -> Result<Json<Value>, ApiError> {
    let tenant = resolve_tenant(&state, q.tenant.as_deref()).await?;
    let mut text = body.text.clone().unwrap_or_default();
    let mut source = body
        .source
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "manual".into());
    if let Some(url) = body.url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(ApiError::bad_request(
                "feed URL must start with http:// or https://",
            ));
        }
        let resp = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| ApiError::internal(e.into()))?
            .get(url)
            .send()
            .await
            .map_err(|e| ApiError::bad_request(format!("could not fetch feed: {e}")))?;
        if !resp.status().is_success() {
            return Err(ApiError::bad_request(format!(
                "feed returned HTTP {}",
                resp.status().as_u16()
            )));
        }
        if resp.content_length().is_some_and(|n| n > 10_000_000) {
            return Err(ApiError::bad_request("feed is larger than 10 MB"));
        }
        let fetched = resp
            .text()
            .await
            .map_err(|e| ApiError::bad_request(format!("could not read feed: {e}")))?;
        if fetched.len() > 10_000_000 {
            return Err(ApiError::bad_request("feed is larger than 10 MB"));
        }
        text.push('\n');
        text.push_str(&fetched);
        if body.source.as_deref().is_none_or(|s| s.trim().is_empty()) {
            source = url.chars().take(200).collect();
        }
    }
    source.truncate(200);
    let mut parsed = parse_indicators(&text);
    if parsed.is_empty() {
        return Err(ApiError::bad_request(
            "no valid IP or domain indicators found",
        ));
    }
    if parsed.len() > MAX_INTEL_PER_REQUEST {
        parsed.truncate(MAX_INTEL_PER_REQUEST);
    }
    let client = state.store.pool().get().await?;
    let existing: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM threat_intel WHERE tenant_id = $1",
            &[&tenant.id],
        )
        .await?
        .get(0);
    if existing + parsed.len() as i64 > MAX_INTEL_PER_TENANT {
        return Err(ApiError::bad_request(format!(
            "indicator limit of {MAX_INTEL_PER_TENANT} would be exceeded"
        )));
    }
    let inds: Vec<String> = parsed.iter().map(|(i, _)| i.clone()).collect();
    let kinds: Vec<String> = parsed.iter().map(|(_, k)| (*k).to_string()).collect();
    let added = client
        .execute(
            "INSERT INTO threat_intel (tenant_id, indicator, kind, source)
             SELECT $1, i, k, $4 FROM UNNEST($2::text[], $3::text[]) AS u(i, k)
             ON CONFLICT (tenant_id, indicator) DO NOTHING",
            &[&tenant.id, &inds, &kinds, &source],
        )
        .await?;
    state
        .store
        .audit(
            Some(&cu.0.username),
            "intel_add",
            &format!("{added} new of {} indicators from {source}", parsed.len()),
            None,
        )
        .await;
    Ok(Json(json!({ "parsed": parsed.len(), "added": added })))
}

#[derive(Debug, Deserialize)]
pub struct IntelDelete {
    pub tenant: Option<String>,
    pub indicator: Option<String>,
    pub all: Option<bool>,
}

/// DELETE /api/v1/security/intel?indicator=x or ?all=true (admin).
pub async fn intel_delete(
    State(state): State<AppState>,
    axum::Extension(cu): axum::Extension<crate::auth::CurrentUser>,
    Query(q): Query<IntelDelete>,
) -> Result<Json<Value>, ApiError> {
    let tenant = resolve_tenant(&state, q.tenant.as_deref()).await?;
    let client = state.store.pool().get().await?;
    let n = if q.all.unwrap_or(false) {
        client
            .execute(
                "DELETE FROM threat_intel WHERE tenant_id = $1",
                &[&tenant.id],
            )
            .await?
    } else if let Some(ind) = q
        .indicator
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
    {
        client
            .execute(
                "DELETE FROM threat_intel WHERE tenant_id = $1 AND indicator = $2",
                &[&tenant.id, &ind],
            )
            .await?
    } else {
        return Err(ApiError::bad_request("indicator or all=true is required"));
    };
    state
        .store
        .audit(
            Some(&cu.0.username),
            "intel_delete",
            &format!("{n} indicators"),
            None,
        )
        .await;
    Ok(Json(json!({ "deleted": n })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mixed_feed_formats() {
        let feed = "# comment\n1.2.3.4\n0.0.0.0 Bad.Example.com\nhttps://evil.test/path?x=1\n\
                    *.wild.test\n5.6.7.8,botnet,high\n127.0.0.1\nnot_a_domain\n1.2.3.4\n2001:db8::1";
        let got = parse_indicators(feed);
        assert_eq!(
            got,
            vec![
                ("1.2.3.4".to_string(), "ip"),
                ("bad.example.com".to_string(), "domain"),
                ("evil.test".to_string(), "domain"),
                ("wild.test".to_string(), "domain"),
                ("5.6.7.8".to_string(), "ip"),
                ("2001:db8::1".to_string(), "ip"),
            ]
        );
    }

    #[test]
    fn rejects_garbage_and_numeric_only_names() {
        assert!(parse_indicators("hello\n300.300.300.300\n...\n1.2.3").is_empty());
    }

    #[test]
    fn user_based_kinds() {
        assert!(user_based("traffic_spike"));
        assert!(!user_based("new_country"));
    }
    /// Runs only when TEST_DATABASE_URL points at a throwaway Postgres (CI provides one).
    #[tokio::test]
    async fn detectors_raise_findings_from_seeded_data() {
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            eprintln!("TEST_DATABASE_URL not set; skipping");
            return;
        };
        let store = sfos_store::Store::connect(&url, 4).expect("connect");
        store.migrate().await.expect("migrate");
        // Without hourly partitions the rows would land in the default partition and block later partition creation.
        store.ensure_partitions(2).await.expect("partitions");
        let tenant = store
            .ensure_tenant("sec-test", "Sec test")
            .await
            .expect("tenant");
        let c = store.pool().get().await.expect("client");
        let t = tenant.id;
        for tbl in [
            "events",
            "minute_rollups",
            "hourly_activity",
            "security_findings",
            "threat_intel",
        ] {
            c.execute(&format!("DELETE FROM {tbl} WHERE tenant_id = $1"), &[&t])
                .await
                .expect("clean");
        }
        let now = Utc::now();

        // Brute force: 12 failed logins from one source; port scan: 25 blocked ports from another.
        c.execute(
            "INSERT INTO events (tenant_id, ts, log_type, category_group, action, status, src_ip, user_name)
             SELECT $1, $2, 'Authentication', 'auth', 'blocked', 'Failed', '203.0.113.9', 'u' || (g % 6)
             FROM generate_series(1, 12) g",
            &[&t, &now],
        )
        .await
        .expect("auth events");
        c.execute(
            "INSERT INTO events (tenant_id, ts, log_type, category_group, action, src_ip, dst_ip, dst_port)
             SELECT $1, $2, 'Firewall', 'firewall', 'blocked', '198.51.100.7', '10.0.0.5', 1000 + g
             FROM generate_series(1, 25) g",
            &[&t, &now],
        )
        .await
        .expect("scan events");
        c.execute(
            "INSERT INTO events (tenant_id, ts, log_type, category_group, action, src_ip, dst_ip, dst_port)
             SELECT $1, $2, 'Firewall', 'firewall', 'allowed', '10.0.0.8', '192.0.2.66', 443
             FROM generate_series(1, 3) g",
            &[&t, &now],
        )
        .await
        .expect("intel events");
        c.execute(
            "INSERT INTO threat_intel (tenant_id, indicator, kind) VALUES
             ($1, '192.0.2.66', 'ip'), ($1, 'evil.test', 'domain')",
            &[&t],
        )
        .await
        .expect("intel");
        c.execute(
            "INSERT INTO minute_rollups (tenant_id, bucket, dimension, key, events)
             VALUES ($1, date_trunc('minute', $2::timestamptz), 'domains', 'cdn.evil.test', 4)",
            &[&t, &now],
        )
        .await
        .expect("domain rollup");

        // Baselines: 10 days of history for USA and alice (1 MB/hour); now RUS and 500 MB.
        c.execute(
            "INSERT INTO hourly_activity (tenant_id, hour, dimension, key, events, bytes_down)
             SELECT $1, date_trunc('hour', $2::timestamptz) - make_interval(hours => h), d.dimension, d.key, 50, 1000000
             FROM generate_series(3, 240) h,
                  (VALUES ('countries', 'USA'), ('users', 'alice')) AS d(dimension, key)",
            &[&t, &now],
        )
        .await
        .expect("baseline");
        c.execute(
            "INSERT INTO minute_rollups (tenant_id, bucket, dimension, key, events, bytes_down) VALUES
             ($1, date_trunc('minute', $2::timestamptz), 'countries', 'RUS', 5, 0),
             ($1, date_trunc('minute', $2::timestamptz), 'users', 'alice', 500, 500000000)",
            &[&t, &now],
        )
        .await
        .expect("current");

        brute_force(&c, t, now).await.expect("brute");
        port_scans(&c, t, now).await.expect("scan");
        intel_matches(&c, t, now).await.expect("intel");
        traffic_spikes(&c, t, now).await.expect("spike");
        new_keys(&c, t, now, "countries", "new_country")
            .await
            .expect("country");
        unusual_hours(&c, t, now).await.expect("hours");
        // Re-running is idempotent (upsert per day).
        brute_force(&c, t, now).await.expect("brute again");

        let rows = c
            .query(
                "SELECT kind, subject, count FROM security_findings WHERE tenant_id = $1 ORDER BY kind, subject",
                &[&t],
            )
            .await
            .expect("findings");
        let got: Vec<(String, String)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
        let want = |k: &str, s: &str| got.contains(&(k.to_string(), s.to_string()));
        assert!(want("brute_force", "203.0.113.9"), "{got:?}");
        assert!(want("port_scan", "198.51.100.7"), "{got:?}");
        assert!(want("intel_ip", "192.0.2.66"), "{got:?}");
        assert!(want("intel_domain", "evil.test"), "{got:?}");
        assert!(want("traffic_spike", "alice"), "{got:?}");
        assert!(want("new_country", "RUS"), "{got:?}");
        assert!(!want("new_country", "USA"), "{got:?}");
        assert_eq!(got.iter().filter(|(k, _)| k == "brute_force").count(), 1);

        let msg = alert_message(&c, t, &ANOMALY_KINDS, 1, now)
            .await
            .expect("alert");
        assert!(msg.is_some_and(|m| m.contains("traffic_spike")));
        assert!(alert_message(&c, t, &["unusual_hours"], 1, now)
            .await
            .expect("none")
            .is_none());
    }
}
