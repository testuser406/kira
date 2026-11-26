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
