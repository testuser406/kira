//! Runtime settings (admin-editable) and privacy masking of user names for non-admin viewers.

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::{ApiError, AppState};
use crate::auth::CurrentUser;
use crate::summary::Summary;

pub async fn get_bool(state: &AppState, key: &str) -> bool {
    let Ok(client) = state.store.pool().get().await else {
        return false;
    };
    client
        .query_opt("SELECT value FROM app_settings WHERE key = $1", &[&key])
        .await
        .ok()
        .flatten()
        .is_some_and(|r| r.get::<_, String>(0) == "true")
}

/// True when this viewer must not see real user names.
pub async fn masks_for(state: &AppState, user: &CurrentUser) -> bool {
    user.0.role != "admin" && get_bool(state, "mask_users").await
}

/// Stable pseudonym (same name -> same alias) so rankings stay meaningful.
pub fn alias(name: &str) -> String {
    let mut h: u32 = 0x811c_9dc5;
    for b in name.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    format!("user-{h:08x}")
}

pub fn mask_summary(s: &mut Summary) {
    if s.user.is_some() {
        s.user = s.user.as_deref().map(alias);
    }
    if s.report_type == "user_overview" {
        s.title = "User Overview".into();
    }
    for sec in &mut s.sections {
        let cols: Vec<usize> = sec
            .columns
            .iter()
            .enumerate()
            .filter(|(_, c)| c.name == "User" || c.name == "Source IP")
            .map(|(i, _)| i)
            .collect();
        for row in &mut sec.rows {
            for &i in &cols {
                if let Some(v) = row.get_mut(i).and_then(|v| v.as_str().map(alias)) {
                    row[i] = Value::String(v);
                }
            }
        }
    }
}

pub fn mask_ranked(items: &mut [Value]) {
    for it in items {
        if let Some(k) = it["key"].as_str().map(alias) {
            it["key"] = Value::String(k);
        }
    }
}

pub async fn get_settings(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        json!({ "mask_users": get_bool(&state, "mask_users").await }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct SettingsBody {
    pub mask_users: Option<bool>,
}

pub async fn put_settings(
    State(state): State<AppState>,
    Json(b): Json<SettingsBody>,
) -> Result<Json<Value>, ApiError> {
    // Non-GET requests already require the administrator role (auth middleware).
    let client = state.store.pool().get().await?;
    if let Some(m) = b.mask_users {
        client
            .execute(
                "INSERT INTO app_settings (key, value) VALUES ('mask_users', $1)
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                &[&if m { "true" } else { "false" }],
            )
            .await?;
    }
    Ok(Json(json!({ "ok": true })))
}

/// Log API requests slower than `SLOW_REQUEST_MS` (default 2000) so slow reports are easy to find.
pub async fn slow_log(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    static LIMIT_MS: std::sync::OnceLock<u128> = std::sync::OnceLock::new();
    let limit = *LIMIT_MS.get_or_init(|| {
        std::env::var("SLOW_REQUEST_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2000)
    });
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let start = std::time::Instant::now();
    let res = next.run(req).await;
    let ms = start.elapsed().as_millis();
    if ms >= limit {
        tracing::warn!(%method, %path, status = res.status().as_u16(), elapsed_ms = ms as u64, "slow request");
    }
    res
}

/// Baseline browser hardening for every response.
pub async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    for (k, v) in [
        ("content-security-policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("permissions-policy", "camera=(), microphone=(), geolocation=()"),
    ] {
        h.insert(k, axum::http::HeaderValue::from_static(v));
    }
    res
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub limit: Option<i64>,
    pub format: Option<String>,
}

/// Recent audit entries (administrators only; JSON or CSV).
pub async fn audit(
    State(state): State<AppState>,
    axum::Extension(cu): axum::Extension<CurrentUser>,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;
    if cu.0.role != "admin" {
        return Ok((
            axum::http::StatusCode::FORBIDDEN,
            Json(json!({"error": "administrator role required"})),
        )
            .into_response());
    }
    let limit = q.limit.unwrap_or(200).clamp(1, 5000);
    let client = state.store.pool().get().await?;
    let rows = client
        .query(
            "SELECT ts, username, action, detail, ip FROM audit_log ORDER BY ts DESC LIMIT $1",
            &[&limit],
        )
        .await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| json!({"ts": r.get::<_, chrono::DateTime<chrono::Utc>>(0), "user": r.get::<_, Option<String>>(1), "action": r.get::<_, String>(2), "detail": r.get::<_, Option<String>>(3), "ip": r.get::<_, Option<String>>(4)}))
        .collect();
    if q.format.as_deref() == Some("csv") {
        let esc = |s: &str| {
            let s = if s.starts_with(['=', '+', '-', '@']) {
                format!("'{s}")
            } else {
                s.to_string()
            };
            format!("\"{}\"", s.replace('"', "\"\""))
        };
        let mut out = String::from("time,user,action,detail,ip\n");
        for i in &items {
            out.push_str(&format!(
                "{},{},{},{},{}\n",
                esc(i["ts"].as_str().unwrap_or("")),
                esc(i["user"].as_str().unwrap_or("")),
                esc(i["action"].as_str().unwrap_or("")),
                esc(i["detail"].as_str().unwrap_or("")),
                esc(i["ip"].as_str().unwrap_or(""))
            ));
        }
        return Ok((
            axum::http::StatusCode::OK,
            [
                ("content-type", "text/csv; charset=utf-8"),
                (
                    "content-disposition",
                    "attachment; filename=\"kira-audit.csv\"",
                ),
            ],
            out,
        )
            .into_response());
    }
    Ok(Json(json!({ "items": items })).into_response())
}
