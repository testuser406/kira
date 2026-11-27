//! Investigation tools: global search across all dimensions and a per-user/host timeline,
//! both served from the hourly aggregates (400 days).

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::{acquire_query_permit, resolve_tenant, ApiError, AppState};

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub tenant: Option<String>,
    pub q: Option<String>,
    pub days: Option<i32>,
    pub user: Option<String>,
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

const SEARCH_DIMS: [(&str, &str); 11] = [
    ("users", "Users and hosts"),
    ("sites", "Sites"),
    ("domains", "Domains"),
    ("applications", "Applications"),
    ("categories", "Categories"),
    ("policies", "Firewall rules"),
    ("countries", "Countries"),
    ("subnets", "Subnets"),
    ("threats", "Threats"),
    ("threat_sources", "Threat sources"),
    ("vpn_users", "VPN users"),
];

/// GET /api/v1/search?q=term&days=30 - matches grouped by what they are.
pub async fn search(
    State(state): State<AppState>,
    axum::Extension(cu): axum::Extension<crate::auth::CurrentUser>,
    Query(q): Query<SearchQuery>,
) -> Result<Json<Value>, ApiError> {
    let term = q.q.as_deref().unwrap_or("").trim().to_string();
    if term.chars().count() < 2 {
        return Err(ApiError::bad_request("type at least 2 characters"));
    }
    if term.len() > 100 {
        return Err(ApiError::bad_request("search term is too long"));
    }
    let _permit = acquire_query_permit(
        &state.query_semaphore,
        "search capacity is busy; retry shortly",
    )?;
    let tenant = resolve_tenant(&state, q.tenant.as_deref()).await?;
    let days = q.days.unwrap_or(30).clamp(1, 400);
    let masked = crate::settings::masks_for(&state, &cu).await;
    let dims: Vec<String> = SEARCH_DIMS
        .iter()
        .filter(|(d, _)| !(masked && ["users", "threat_sources", "vpn_users"].contains(d)))
        .map(|(d, _)| (*d).to_string())
        .collect();
    let pattern = format!("%{}%", like_escape(&term));
    let client = state.store.pool().get().await?;
    let rows = client
        .query(
            "SELECT dimension, key, events, blocked, bytes, last_seen FROM (
                SELECT dimension, key, sum(events)::bigint AS events, sum(blocked)::bigint AS blocked,
                       sum(bytes_up + bytes_down)::bigint AS bytes, max(hour) AS last_seen,
                       row_number() OVER (PARTITION BY dimension ORDER BY sum(events) DESC, key) AS rn
                FROM hourly_activity
                WHERE tenant_id = $1 AND dimension = ANY($2) AND key ILIKE $3
                  AND hour > now() - make_interval(days => $4)
                GROUP BY dimension, key) t
             WHERE rn <= 10 ORDER BY dimension, rn",
            &[&tenant.id, &dims, &pattern, &days],
        )
        .await?;
    let mut groups: Vec<Value> = Vec::new();
    for (dim, label) in SEARCH_DIMS {
        let items: Vec<Value> = rows
            .iter()
            .filter(|r| r.get::<_, String>(0) == dim)
            .map(|r| {
                json!({
                    "key": r.get::<_, String>(1),
                    "events": r.get::<_, i64>(2),
                    "blocked": r.get::<_, i64>(3),
                    "bytes": r.get::<_, i64>(4),
                    "last_seen": r.get::<_, chrono::DateTime<chrono::Utc>>(5),
                })
            })
            .collect();
        if !items.is_empty() {
            groups.push(json!({ "dimension": dim, "label": label, "items": items }));
        }
    }
    Ok(Json(json!({ "q": term, "days": days, "groups": groups })))
}

/// GET /api/v1/investigate/user?user=alice&days=7 - activity timeline, top sites and categories.
pub async fn user_timeline(
    State(state): State<AppState>,
    axum::Extension(cu): axum::Extension<crate::auth::CurrentUser>,
    Query(q): Query<SearchQuery>,
) -> Result<Json<Value>, ApiError> {
    let user = q.user.as_deref().unwrap_or("").trim().to_string();
    if user.is_empty() || user.len() > 200 {
        return Err(ApiError::bad_request("user is required"));
    }
    if crate::settings::masks_for(&state, &cu).await {
        return Err(ApiError::bad_request(
            "user names are masked for this account; individual timelines are not available",
        ));
    }
    let _permit = acquire_query_permit(
        &state.query_semaphore,
        "query capacity is busy; retry shortly",
    )?;
    let tenant = resolve_tenant(&state, q.tenant.as_deref()).await?;
    let days = q.days.unwrap_or(7).clamp(1, 400);
    let unit = if days <= 3 { "hour" } else { "day" };
    let prefix = format!("{user}\t");
    let client = state.store.pool().get().await?;

    let timeline = client
        .query(
            "SELECT date_trunc($4, hour) AS t,
                    sum(events) FILTER (WHERE dimension = 'users')::bigint,
                    sum(allowed) FILTER (WHERE dimension = 'users')::bigint,
                    sum(blocked) FILTER (WHERE dimension = 'users')::bigint,
                    sum(bytes_up) FILTER (WHERE dimension = 'users')::bigint,
                    sum(bytes_down) FILTER (WHERE dimension = 'users')::bigint,
                    sum(minutes) FILTER (WHERE dimension = 'web_users')::bigint
             FROM hourly_activity
             WHERE tenant_id = $1 AND dimension IN ('users', 'web_users') AND key = $2
               AND hour > now() - make_interval(days => $3)
             GROUP BY 1 ORDER BY 1",
            &[&tenant.id, &user, &days, &unit],
        )
        .await?;
    let points: Vec<Value> = timeline
        .iter()
        .map(|r| {
            let g = |i: usize| r.get::<_, Option<i64>>(i).unwrap_or(0);
            json!({
                "t": r.get::<_, chrono::DateTime<chrono::Utc>>(0),
                "events": g(1), "allowed": g(2), "blocked": g(3),
                "bytes_up": g(4), "bytes_down": g(5), "browse_minutes": g(6),
            })
        })
        .collect();

    let ranked = |dim: &'static str| {
        let client = &client;
        let tid = tenant.id;
        let prefix = prefix.clone();
        async move {
            client
                .query(
                    "SELECT substr(key, length($3) + 1) AS item, sum(events)::bigint, sum(blocked)::bigint,
                            sum(bytes_up + bytes_down)::bigint
                     FROM hourly_activity
                     WHERE tenant_id = $1 AND dimension = $2 AND starts_with(key, $3)
                       AND hour > now() - make_interval(days => $4)
                     GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 15",
                    &[&tid, &dim, &prefix, &days],
                )
                .await
        }
    };
    let to_json = |rows: Vec<tokio_postgres::Row>| -> Vec<Value> {
        rows.iter()
            .map(|r| json!({"key": r.get::<_, String>(0), "events": r.get::<_, i64>(1), "blocked": r.get::<_, i64>(2), "bytes": r.get::<_, i64>(3)}))
            .collect()
    };
    let sites = to_json(ranked("user_sites").await?);
    let categories = to_json(ranked("user_categories").await?);

    let sum = |k: &str| {
        points
            .iter()
            .map(|p| p[k].as_i64().unwrap_or(0))
            .sum::<i64>()
    };
    Ok(Json(json!({
        "user": user, "days": days, "unit": unit,
        "totals": {
            "events": sum("events"), "allowed": sum("allowed"), "blocked": sum("blocked"),
            "bytes_up": sum("bytes_up"), "bytes_down": sum("bytes_down"),
            "browse_minutes": sum("browse_minutes"),
        },
        "timeline": points, "top_sites": sites, "top_categories": categories,
    })))
}
