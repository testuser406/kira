//! Expiring share links: `POST /api/v1/reports/share` returns `/share/<token>`, which anyone holding the
//! link can open without signing in (a fixed-period snapshot request rendered on demand).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::{resolve_tenant, ApiError, AppState};
use crate::auth::CurrentUser;

#[derive(Debug, Deserialize)]
pub struct ShareBody {
    pub tenant: Option<String>,
    #[serde(rename = "type")]
    pub report_type: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub user: Option<String>,
    pub top: Option<i64>,
    pub format: Option<String>,
    pub days: Option<i64>,
}

fn token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

pub async fn create(
    State(state): State<AppState>,
    Extension(cu): Extension<CurrentUser>,
    Json(b): Json<ShareBody>,
) -> Result<Json<Value>, ApiError> {
    if !crate::summary::supports(&b.report_type) {
        return Err(ApiError::bad_request("unknown report type"));
    }
    let format = b.format.as_deref().unwrap_or("pdf");
    if format != "pdf" && format != "csv" {
        return Err(ApiError::bad_request("format must be pdf or csv"));
    }
    let user = b
        .user
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(String::from);
    if b.report_type == "user_overview" && user.is_none() {
        return Err(ApiError::bad_request("user_overview needs a user"));
    }
    let tenant = resolve_tenant(&state, b.tenant.as_deref()).await?;
    let now = Utc::now();
    let range = crate::query::RangeQuery {
        tenant: Some(tenant.slug.clone()),
        from: Some(b.from.clone().unwrap_or_else(|| "7d".into())),
        to: Some(b.to.clone().unwrap_or_else(|| "now".into())),
        interval: None,
    }
    .resolve(now)
    .map_err(|e| ApiError::bad_request(format!("invalid time range: {e}")))?;
    let days = b.days.unwrap_or(7).clamp(1, 30);
    let masked = crate::settings::get_bool(&state, "mask_users").await;
    let token = token();
    let expires = now + Duration::days(days);
    let client = state.store.pool().get().await?;
    client
        .execute(
            "INSERT INTO report_shares (token, tenant_id, report_type, from_ts, to_ts, user_key, top_n, format, masked, created_by, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            &[&token, &tenant.id, &b.report_type, &range.from, &range.to, &user, &(b.top.unwrap_or(15).clamp(5, 100) as i32), &format, &masked, &cu.0.username, &expires],
        )
        .await?;
    state
        .store
        .audit(
            Some(&cu.0.username),
            "report_share_created",
            &format!(
                "{} {} expires {}",
                b.report_type,
                format,
                expires.format("%Y-%m-%d")
            ),
            None,
        )
        .await;
    Ok(Json(
        json!({ "url": format!("/share/{token}"), "expires_at": expires }),
    ))
}

pub async fn revoke(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let client = state.store.pool().get().await?;
    let n = client
        .execute("DELETE FROM report_shares WHERE token = $1", &[&token])
        .await?;
    Ok(Json(json!({ "deleted": n })))
}

pub async fn open(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    let not_found = || {
        (
            StatusCode::NOT_FOUND,
            "This link is invalid or has expired.",
        )
            .into_response()
    };
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return not_found();
    }
    let Ok(client) = state.store.pool().get().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(Some(row)) = client
        .query_opt(
            "SELECT s.tenant_id, t.name, s.report_type, s.from_ts, s.to_ts, s.user_key, s.top_n, s.format, s.masked
             FROM report_shares s JOIN tenants t ON t.id = s.tenant_id
             WHERE s.token = $1 AND s.expires_at > now()",
            &[&token],
        )
        .await
    else {
        return not_found();
    };
    let (tenant_id, name, rtype, from, to, user, top, format, masked): (
        uuid::Uuid,
        String,
        String,
        _,
        _,
        Option<String>,
        i32,
        String,
        bool,
    ) = (
        row.get(0),
        row.get(1),
        row.get(2),
        row.get(3),
        row.get(4),
        row.get(5),
        row.get(6),
        row.get(7),
        row.get(8),
    );
    let Ok(mut summary) = crate::summary::build(
        &client,
        tenant_id,
        &name,
        &rtype,
        from,
        to,
        user,
        i64::from(top),
    )
    .await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if masked {
        crate::settings::mask_summary(&mut summary);
    }
    let Ok((content, ct, ext)) = crate::summary::render(&format, &summary) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    (
        StatusCode::OK,
        [
            ("content-type", ct.to_string()),
            (
                "content-disposition",
                format!("inline; filename=\"kira-{rtype}.{ext}\""),
            ),
            ("cache-control", "no-store".to_string()),
        ],
        content,
    )
        .into_response()
}
