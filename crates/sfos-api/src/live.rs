//! Minute-resolution live dashboards backed by `minute_rollups`.
//! Each tab (bandwidth, productivity, security, vpn) returns its own data.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::{acquire_query_permit, resolve_tenant, ApiError, AppState};

#[derive(Debug, Deserialize)]
pub struct LiveQuery {
    pub tenant: Option<String>,
    /// Window in minutes (clamped to 5..=1440).
    pub window: Option<i32>,
}

async fn series(
    client: &deadpool_postgres::Client,
    tenant: Uuid,
    window: i32,
    group: Option<&str>,
) -> Result<Vec<Value>, ApiError> {
    let dim = if group.is_some() { "group" } else { "overview" };
    let key = group.unwrap_or("");
    let rows = client
        .query(
            "SELECT g.t,
                    COALESCE(m.events, 0)::bigint AS events,
                    COALESCE(m.allowed, 0)::bigint AS allowed,
                    COALESCE(m.blocked, 0)::bigint AS blocked,
                    COALESCE(m.bytes_up, 0)::bigint AS bytes_up,
                    COALESCE(m.bytes_down, 0)::bigint AS bytes_down
             FROM generate_series(
                    date_trunc('minute', now()) - make_interval(mins => $2 - 1),
                    date_trunc('minute', now()),
                    interval '1 minute') AS g(t)
             LEFT JOIN minute_rollups m
               ON m.tenant_id = $1 AND m.bucket = g.t AND m.dimension = $3 AND m.key = $4
             ORDER BY g.t",
            &[&tenant, &window, &dim, &key],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            json!({
                "t": r.get::<_, chrono::DateTime<chrono::Utc>>("t"),
                "events": r.get::<_, i64>("events"),
                "allowed": r.get::<_, i64>("allowed"),
                "blocked": r.get::<_, i64>("blocked"),
                "bytes_up": r.get::<_, i64>("bytes_up"),
                "bytes_down": r.get::<_, i64>("bytes_down"),
            })
        })
        .collect())
}

async fn top(
    client: &deadpool_postgres::Client,
    tenant: Uuid,
    window: i32,
    dimension: &str,
    by_bytes: bool,
    limit: i64,
) -> Result<Vec<Value>, ApiError> {
    let order = if by_bytes { "bytes" } else { "events" };
    let sql = format!(
        "SELECT key, sum(events)::bigint AS events, sum(blocked)::bigint AS blocked,
                sum(bytes_up)::bigint AS bytes_up, sum(bytes_down)::bigint AS bytes_down,
                sum(bytes_up + bytes_down)::bigint AS bytes
         FROM minute_rollups
         WHERE tenant_id = $1 AND dimension = $2
           AND bucket > now() - make_interval(mins => $3)
         GROUP BY key ORDER BY {order} DESC, key LIMIT $4"
    );
    let rows = client
        .query(&sql, &[&tenant, &dimension, &window, &limit])
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            json!({
                "key": r.get::<_, String>("key"),
                "events": r.get::<_, i64>("events"),
                "blocked": r.get::<_, i64>("blocked"),
                "bytes_up": r.get::<_, i64>("bytes_up"),
                "bytes_down": r.get::<_, i64>("bytes_down"),
                "bytes": r.get::<_, i64>("bytes"),
            })
        })
        .collect())
}

fn sum(points: &[Value], field: &str) -> i64 {
    points.iter().filter_map(|p| p[field].as_i64()).sum()
}

pub async fn live(
    State(state): State<AppState>,
    Path(kind): Path<String>,
    Query(q): Query<LiveQuery>,
) -> Result<Json<Value>, ApiError> {
    let _permit = acquire_query_permit(
        &state.query_semaphore,
        "dashboard query capacity is busy; retry shortly",
    )?;
    let tenant = resolve_tenant(&state, q.tenant.as_deref()).await?;
    let window = q.window.unwrap_or(15).clamp(5, 1440);
    let client = state.store.pool().get().await?;
    let id = tenant.id;

    let body = match kind.as_str() {
        "bandwidth" => {
            let s = series(&client, id, window, None).await?;
            // Rate from the last complete minute (the current one is partial).
            let last = s.len().saturating_sub(2);
            let (up, down) = s
                .get(last)
                .map(|p| {
                    (
                        p["bytes_up"].as_i64().unwrap_or(0),
                        p["bytes_down"].as_i64().unwrap_or(0),
                    )
                })
                .unwrap_or((0, 0));
            let peak = s
                .iter()
                .map(|p| {
                    p["bytes_up"].as_i64().unwrap_or(0) + p["bytes_down"].as_i64().unwrap_or(0)
                })
                .max()
                .unwrap_or(0);
            json!({
                "now_bps_up": up * 8 / 60,
                "now_bps_down": down * 8 / 60,
                "peak_bytes_per_min": peak,
                "total_up": sum(&s, "bytes_up"),
                "total_down": sum(&s, "bytes_down"),
                "series": s,
                "top_users": top(&client, id, window, "users", true, 10).await?,
                "top_applications": top(&client, id, window, "applications", true, 10).await?,
            })
        }
        "productivity" => {
            let s = series(&client, id, window, Some("web")).await?;
            json!({
                "web_requests": sum(&s, "events"),
                "blocked": sum(&s, "blocked"),
                "series": s,
                "top_categories": top(&client, id, window, "categories", false, 10).await?,
                "top_domains": top(&client, id, window, "domains", false, 10).await?,
                "top_users": top(&client, id, window, "users", false, 10).await?,
            })
        }
        "security" => {
            let s = series(&client, id, window, Some("threat")).await?;
            let overview = series(&client, id, window, None).await?;
            json!({
                "threats": sum(&s, "events"),
                "blocked_traffic": sum(&overview, "blocked"),
                "series": s,
                "blocked_series": overview.iter().map(|p| json!({"t": p["t"], "blocked": p["blocked"]})).collect::<Vec<_>>(),
                "top_threats": top(&client, id, window, "threats", false, 10).await?,
                "top_sources": top(&client, id, window, "threat_sources", false, 10).await?,
            })
        }
        "vpn" => {
            let s = series(&client, id, window, Some("vpn")).await?;
            let tunnels = top(&client, id, window, "vpn_tunnels", true, 20).await?;
            let users = top(&client, id, window, "vpn_users", true, 20).await?;
            json!({
                "active_tunnels": tunnels.len(),
                "active_users": users.len(),
                "total_up": sum(&s, "bytes_up"),
                "total_down": sum(&s, "bytes_down"),
                "series": s,
                "tunnels": tunnels,
                "users": users,
            })
        }
        _ => return Err(ApiError::bad_request("unknown live dashboard")),
    };

    Ok(Json(
        json!({ "kind": kind, "window_min": window, "generated_at": chrono::Utc::now(), "data": body }),
    ))
}
