//! Where does unclassified traffic go? Destination view and manual labels for networks where
//! DPI is off. Only counts are returned (never user names), so masking does not apply.

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sfos_core::classify;

use crate::api::{resolve_tenant, ApiError, AppState};

#[derive(Debug, Deserialize)]
pub struct DestQuery {
    pub tenant: Option<String>,
    pub minutes: Option<i64>,
    pub limit: Option<i64>,
    pub unclassified: Option<bool>,
}

/// GET /api/v1/traffic/destinations
pub async fn destinations(
    State(state): State<AppState>,
    Query(q): Query<DestQuery>,
) -> Result<Json<Value>, ApiError> {
    let tenant = resolve_tenant(&state, q.tenant.as_deref()).await?;
    let minutes = q.minutes.unwrap_or(60).clamp(1, 360);
    let items = state
        .store
        .top_destinations(
            tenant.id,
            minutes,
            q.limit.unwrap_or(100),
            q.unclassified.unwrap_or(false),
        )
        .await?;
    Ok(Json(json!({ "minutes": minutes, "items": items })))
}

#[derive(Debug, Deserialize)]
pub struct LabelBody {
    pub ip: String,
    pub app: String,
    pub category: Option<String>,
}

/// POST /api/v1/traffic/labels - name a destination address by hand (admin).
pub async fn set_label(
    State(state): State<AppState>,
    axum::Extension(cu): axum::Extension<crate::auth::CurrentUser>,
    Json(body): Json<LabelBody>,
) -> Result<Json<Value>, ApiError> {
    let ip = body.ip.trim().to_string();
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(ApiError::bad_request("ip must be a valid address"));
    }
    if !classify::is_public_ip(&ip) {
        return Err(ApiError::bad_request(
            "only public addresses can be labelled",
        ));
    }
    let app = body.app.trim();
    if app.is_empty() || app.len() > 80 {
        return Err(ApiError::bad_request(
            "app name is required (max 80 characters)",
        ));
    }
    let category = body
        .category
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .unwrap_or("Custom");
    state
        .store
        .save_ip_label(&ip, None, app, category, "manual")
        .await?;
    state
        .store
        .audit(
            Some(&cu.0.username),
            "traffic_label_set",
            &format!("{ip} = {app}"),
            None,
        )
        .await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
pub struct LabelDelete {
    pub ip: String,
}

/// DELETE /api/v1/traffic/labels?ip=x (admin).
pub async fn delete_label(
    State(state): State<AppState>,
    axum::Extension(cu): axum::Extension<crate::auth::CurrentUser>,
    Query(q): Query<LabelDelete>,
) -> Result<Json<Value>, ApiError> {
    let n = state.store.delete_ip_label(q.ip.trim()).await?;
    state
        .store
        .audit(
            Some(&cu.0.username),
            "traffic_label_delete",
            q.ip.trim(),
            None,
        )
        .await;
    Ok(Json(json!({ "deleted": n })))
}
