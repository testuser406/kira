//! Productivity guidelines, browse time and cleaned sites (Site Clean), from `minute_rollups`.

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::{acquire_query_permit, resolve_tenant, ApiError, AppState};

#[derive(Debug, Deserialize)]
pub struct TenantQuery {
    pub tenant: Option<String>,
    pub window: Option<i32>,
    pub kind: Option<String>,
    pub key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GuidelineBody {
    pub kind: String,
    pub key: String,
    pub class: String,
}

pub async fn list_guidelines(
    State(state): State<AppState>,
    Query(q): Query<TenantQuery>,
) -> Result<Json<Value>, ApiError> {
    let tenant = resolve_tenant(&state, q.tenant.as_deref()).await?;
    let client = state.store.pool().get().await?;
    let rows = client
        .query(
            "SELECT kind, key, class FROM productivity_guidelines
             WHERE tenant_id = $1 ORDER BY class, kind, key",
            &[&tenant.id],
        )
        .await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| json!({"kind": r.get::<_, String>(0), "key": r.get::<_, String>(1), "class": r.get::<_, String>(2)}))
        .collect();
    Ok(Json(json!({ "items": items })))
}

pub async fn put_guideline(
    State(state): State<AppState>,
    Query(q): Query<TenantQuery>,
    Json(b): Json<GuidelineBody>,
) -> Result<Json<Value>, ApiError> {
    if !["category", "application", "site"].contains(&b.kind.as_str()) {
        return Err(ApiError::bad_request(
            "kind must be category, application or site",
        ));
    }
    if !["productive", "neutral", "unproductive"].contains(&b.class.as_str()) {
        return Err(ApiError::bad_request(
            "class must be productive, neutral or unproductive",
        ));
    }
    let key = b.key.trim();
    if key.is_empty() || key.len() > 200 {
        return Err(ApiError::bad_request("key must be 1-200 characters"));
    }
    let tenant = resolve_tenant(&state, q.tenant.as_deref()).await?;
    let client = state.store.pool().get().await?;
    client
        .execute(
            "INSERT INTO productivity_guidelines (tenant_id, kind, key, class)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, kind, key) DO UPDATE SET class = EXCLUDED.class",
            &[&tenant.id, &b.kind, &key, &b.class],
        )
        .await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_guideline(
    State(state): State<AppState>,
    Query(q): Query<TenantQuery>,
) -> Result<Json<Value>, ApiError> {
    let (Some(kind), Some(key)) = (q.kind.as_deref(), q.key.as_deref()) else {
        return Err(ApiError::bad_request("kind and key are required"));
    };
    let tenant = resolve_tenant(&state, q.tenant.as_deref()).await?;
    let client = state.store.pool().get().await?;
    let n = client
        .execute(
            "DELETE FROM productivity_guidelines WHERE tenant_id = $1 AND kind = $2 AND key = $3",
            &[&tenant.id, &kind, &key],
        )
        .await?;
    Ok(Json(json!({ "deleted": n })))
}

pub async fn summary(
    State(state): State<AppState>,
    axum::Extension(cu): axum::Extension<crate::auth::CurrentUser>,
    Query(q): Query<TenantQuery>,
) -> Result<Json<Value>, ApiError> {
    let _permit = acquire_query_permit(
        &state.query_semaphore,
        "dashboard query capacity is busy; retry shortly",
    )?;
    let tenant = resolve_tenant(&state, q.tenant.as_deref()).await?;
    let window = q.window.unwrap_or(1440).clamp(5, 10080);
    let client = state.store.pool().get().await?;
    let id = tenant.id;

    // Share of web requests per class (categories without a guideline count as neutral).
    let share = client
        .query(
            "SELECT COALESCE(g.class, 'neutral') AS class,
                    sum(m.events)::bigint AS events, sum(m.bytes_up + m.bytes_down)::bigint AS bytes
             FROM minute_rollups m
             LEFT JOIN productivity_guidelines g
               ON g.tenant_id = m.tenant_id AND g.kind = 'category' AND g.key = m.key
             WHERE m.tenant_id = $1 AND m.dimension = 'categories'
               AND m.bucket > now() - make_interval(mins => $2)
             GROUP BY 1",
            &[&id, &window],
        )
        .await?;
    let mut shares = json!({"productive": 0, "neutral": 0, "unproductive": 0});
    for r in &share {
        shares[r.get::<_, String>("class")] = json!(r.get::<_, i64>("events"));
    }

    // Cleaned sites with active minutes and any site-level guideline.
    let sites = client
        .query(
            "SELECT m.key, sum(m.events)::bigint AS events, count(DISTINCT m.bucket)::bigint AS minutes,
                    sum(m.bytes_up + m.bytes_down)::bigint AS bytes, g.class
             FROM minute_rollups m
             LEFT JOIN productivity_guidelines g
               ON g.tenant_id = m.tenant_id AND g.kind = 'site' AND g.key = m.key
             WHERE m.tenant_id = $1 AND m.dimension = 'sites'
               AND m.bucket > now() - make_interval(mins => $2)
             GROUP BY m.key, g.class ORDER BY events DESC, m.key LIMIT 25",
            &[&id, &window],
        )
        .await?;
    let sites: Vec<Value> = sites
        .iter()
        .map(|r| {
            json!({"key": r.get::<_, String>("key"), "events": r.get::<_, i64>("events"),
                   "minutes": r.get::<_, i64>("minutes"), "bytes": r.get::<_, i64>("bytes"),
                   "class": r.get::<_, Option<String>>("class")})
        })
        .collect();

    // Browse time: distinct minutes with web activity per user.
    let users = client
        .query(
            "SELECT key, count(DISTINCT bucket)::bigint AS minutes, sum(events)::bigint AS events
             FROM minute_rollups
             WHERE tenant_id = $1 AND dimension = 'web_users'
               AND bucket > now() - make_interval(mins => $2)
             GROUP BY key ORDER BY minutes DESC, key LIMIT 25",
            &[&id, &window],
        )
        .await?;
    let users: Vec<Value> = users
        .iter()
        .map(|r| {
            json!({"key": r.get::<_, String>("key"), "minutes": r.get::<_, i64>("minutes"),
                        "events": r.get::<_, i64>("events")})
        })
        .collect();

    let cats = client
        .query(
            "SELECT m.key, sum(m.events)::bigint AS events, COALESCE(g.class, 'neutral') AS class
             FROM minute_rollups m
             LEFT JOIN productivity_guidelines g
               ON g.tenant_id = m.tenant_id AND g.kind = 'category' AND g.key = m.key
             WHERE m.tenant_id = $1 AND m.dimension = 'categories'
               AND m.bucket > now() - make_interval(mins => $2)
             GROUP BY m.key, g.class ORDER BY events DESC, m.key LIMIT 20",
            &[&id, &window],
        )
        .await?;
    let cats: Vec<Value> = cats
        .iter()
        .map(|r| {
            json!({"key": r.get::<_, String>("key"), "events": r.get::<_, i64>("events"),
                        "class": r.get::<_, String>("class")})
        })
        .collect();

    let mut users = users;
    if crate::settings::masks_for(&state, &cu).await {
        crate::settings::mask_ranked(&mut users);
    }
    Ok(Json(json!({
        "window_min": window, "shares": shares, "sites": sites,
        "browse_time": users, "categories": cats
    })))
}
