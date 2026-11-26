//! Alert conditions (evaluated on per-minute rollups) and notification delivery.

use axum::extract::{Path, State};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sfos_store::{AlertRule, WebhookDelivery};
use uuid::Uuid;

use crate::api::{send_email, ApiError, AppState};

pub const CONDITIONS: [&str; 6] = [
    "threat",
    "blocked_category",
    "large_transfer",
    "user_bandwidth",
    "site_visits",
    "no_logs",
];

/// Returns a message when the rule's condition holds right now.
pub async fn check(
    client: &deadpool_postgres::Client,
    tenant: Uuid,
    rule: &AlertRule,
    now: DateTime<Utc>,
) -> Result<Option<String>, ApiError> {
    let since = now - Duration::hours(1);
    let num = |s: &str, default: i64| s.trim().parse::<i64>().unwrap_or(default);
    let sum = |sql: &'static str| async move {
        Ok::<i64, ApiError>(
            client
                .query_one(sql, &[&tenant, &since])
                .await?
                .get::<_, Option<i64>>(0)
                .unwrap_or(0),
        )
    };
    Ok(match rule.condition_type.as_str() {
        "threat" => {
            let t = num(&rule.threshold, 1);
            let n = sum("SELECT sum(events)::bigint FROM minute_rollups WHERE tenant_id = $1 AND dimension = 'group' AND key = 'threat' AND bucket >= $2").await?;
            (n >= t).then(|| format!("{n} threat events in the last hour (threshold {t})"))
        }
        "large_transfer" => {
            let t = num(&rule.threshold, 1_000_000);
            let n = sum("SELECT sum(bytes_up + bytes_down)::bigint FROM minute_rollups WHERE tenant_id = $1 AND dimension = 'overview' AND bucket >= $2").await?;
            (n >= t).then(|| {
                format!(
                    "{} transferred in the last hour (threshold {})",
                    crate::summary::fmt_bytes(n as f64),
                    crate::summary::fmt_bytes(t as f64)
                )
            })
        }
        "blocked_category" => {
            let (cat, t) = rule
                .threshold
                .rsplit_once(':')
                .map_or((rule.threshold.as_str(), 1), |(c, n)| (c, num(n, 1)));
            let n: i64 = client
                .query_one("SELECT sum(blocked)::bigint FROM minute_rollups WHERE tenant_id = $1 AND dimension = 'categories' AND key = $2 AND bucket >= $3", &[&tenant, &cat.trim(), &since])
                .await?
                .get::<_, Option<i64>>(0)
                .unwrap_or(0);
            (n >= t).then(|| {
                format!(
                    "{n} blocked requests in category '{}' in the last hour (threshold {t})",
                    cat.trim()
                )
            })
        }
        "user_bandwidth" => {
            let t = num(&rule.threshold, 1_000_000_000);
            let row = client
                .query_opt("SELECT key, sum(bytes_up + bytes_down)::bigint AS b FROM minute_rollups WHERE tenant_id = $1 AND dimension = 'users' AND bucket >= $2 GROUP BY key ORDER BY b DESC LIMIT 1", &[&tenant, &since])
                .await?;
            row.and_then(|r| {
                let (u, b): (String, i64) = (r.get(0), r.get(1));
                (b >= t).then(|| {
                    format!(
                        "{u} transferred {} in the last hour (threshold {})",
                        crate::summary::fmt_bytes(b as f64),
                        crate::summary::fmt_bytes(t as f64)
                    )
                })
            })
        }
        "site_visits" => {
            let (site, t) = rule
                .threshold
                .rsplit_once(':')
                .map_or((rule.threshold.as_str(), 1), |(c, n)| (c, num(n, 1)));
            let n: i64 = client
                .query_one("SELECT sum(events)::bigint FROM minute_rollups WHERE tenant_id = $1 AND dimension = 'sites' AND key = sfos_site($2) AND bucket >= $3", &[&tenant, &site.trim(), &since])
                .await?
                .get::<_, Option<i64>>(0)
                .unwrap_or(0);
            (n >= t).then(|| {
                format!(
                    "{n} requests to {} in the last hour (threshold {t})",
                    site.trim()
                )
            })
        }
        "no_logs" => {
            let mins = num(&rule.threshold, 15).max(1);
            let last: Option<DateTime<Utc>> = client
                .query_one("SELECT max(bucket) FROM minute_rollups WHERE tenant_id = $1 AND dimension = 'overview'", &[&tenant])
                .await?
                .get(0);
            // Only alert once logs have been seen before (a fresh install is not an outage).
            last.filter(|l| now - *l > Duration::minutes(mins))
                .map(|l| {
                    format!(
                        "No firewall logs received for {} minutes (last at {} UTC)",
                        (now - l).num_minutes(),
                        l.format("%Y-%m-%d %H:%M")
                    )
                })
        }
        _ => None,
    })
}

async fn notify_settings(state: &AppState, rule_id: Uuid) -> (String, String) {
    let Ok(client) = state.store.pool().get().await else {
        return (String::new(), "json".into());
    };
    client
        .query_opt(
            "SELECT email_to, webhook_format FROM alert_notify WHERE rule_id = $1",
            &[&rule_id],
        )
        .await
        .ok()
        .flatten()
        .map(|r| (r.get(0), r.get(1)))
        .unwrap_or_else(|| (String::new(), "json".into()))
}

async fn post_webhook(
    url: &str,
    format: &str,
    rule: &str,
    severity: &str,
    message: &str,
    at: DateTime<Utc>,
) -> Result<(u16, String), String> {
    let payload = if format == "text" {
        json!({ "text": format!("**[{}] {}** - {}", severity.to_uppercase(), rule, message) })
    } else {
        json!({ "rule_name": rule, "message": message, "severity": severity, "triggered_at": at.to_rfc3339() })
    };
    let res = reqwest::Client::new()
        .post(url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("webhook request failed: {e}"))?;
    let status = res.status().as_u16();
    let body = res.text().await.unwrap_or_default();
    if (200..300).contains(&status) {
        Ok((status, body))
    } else {
        Err(format!("webhook returned status {status}: {body}"))
    }
}

/// Fire-and-forget delivery of an alert by webhook and e-mail. `instance` links the delivery log.
pub fn notify(
    state: &AppState,
    rule: &AlertRule,
    instance: Uuid,
    message: &str,
    at: DateTime<Utc>,
) {
    let (state, rule, message) = (state.clone(), rule.clone(), message.to_string());
    tokio::spawn(async move {
        let _ = deliver(&state, &rule, Some(instance), &message, at).await;
    });
}

async fn deliver(
    state: &AppState,
    rule: &AlertRule,
    instance: Option<Uuid>,
    message: &str,
    at: DateTime<Utc>,
) -> Vec<String> {
    let (email_to, format) = notify_settings(state, rule.id).await;
    let mut results = Vec::new();
    if let Some(url) = rule.webhook_url.as_deref().filter(|u| !u.is_empty()) {
        let outcome = post_webhook(url, &format, &rule.name, &rule.severity, message, at).await;
        results.push(match &outcome {
            Ok((c, _)) => format!("webhook ok ({c})"),
            Err(e) => format!("webhook failed: {e}"),
        });
        if let Some(instance) = instance {
            let (status, code, body, err) = match outcome {
                Ok((c, b)) => ("sent".to_string(), Some(c as i32), Some(b), None),
                Err(e) => ("failed".to_string(), None, None, Some(e)),
            };
            let _ = state
                .store
                .create_webhook_delivery(&WebhookDelivery {
                    id: Uuid::new_v4(),
                    alert_instance_id: instance,
                    webhook_url: url.to_string(),
                    status,
                    response_status_code: code,
                    response_body: body,
                    error_message: err,
                    delivered_at: at,
                })
                .await;
        }
    }
    let to: Vec<String> = email_to
        .split([',', ';'])
        .map(|s| s.trim().to_string())
        .filter(|s| s.contains('@'))
        .collect();
    if !to.is_empty() {
        let st = state.clone();
        let subject = format!("[Kira {}] {}", rule.severity.to_uppercase(), rule.name);
        let body = format!(
            "{message}\n\nTime: {} UTC\nRule: {}\n",
            at.format("%Y-%m-%d %H:%M:%S"),
            rule.name
        );
        let r =
            tokio::task::spawn_blocking(move || send_email(&st, &to, &subject, &body, None)).await;
        results.push(match r {
            Ok(Ok(())) => "email sent".to_string(),
            Ok(Err(e)) => format!("email failed: {e}"),
            Err(e) => format!("email failed: {e}"),
        });
    }
    if results.is_empty() {
        results.push("no webhook URL or e-mail recipient is configured for this rule".into());
    }
    results
}

pub async fn get_notify(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let (email_to, format) = notify_settings(&state, id).await;
    Ok(Json(
        json!({ "email_to": email_to, "webhook_format": format }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct NotifyBody {
    pub email_to: Option<String>,
    pub webhook_format: Option<String>,
}

pub async fn put_notify(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(b): Json<NotifyBody>,
) -> Result<Json<Value>, ApiError> {
    let format = b.webhook_format.unwrap_or_else(|| "json".into());
    if format != "json" && format != "text" {
        return Err(ApiError::bad_request("webhook_format must be json or text"));
    }
    let email = b.email_to.unwrap_or_default();
    if email.len() > 500 {
        return Err(ApiError::bad_request("email_to is too long"));
    }
    if state.store.get_alert_rule(id).await?.is_none() {
        return Err(ApiError::not_found("alert rule not found"));
    }
    let client = state.store.pool().get().await?;
    client
        .execute(
            "INSERT INTO alert_notify (rule_id, email_to, webhook_format) VALUES ($1, $2, $3)
             ON CONFLICT (rule_id) DO UPDATE SET email_to = EXCLUDED.email_to, webhook_format = EXCLUDED.webhook_format",
            &[&id, &email.trim(), &format],
        )
        .await?;
    Ok(Json(json!({ "ok": true })))
}

/// Send a test notification for a rule through its configured channels.
pub async fn test_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let Some(rule) = state.store.get_alert_rule(id).await? else {
        return Err(ApiError::not_found("alert rule not found"));
    };
    let results = deliver(
        &state,
        &rule,
        None,
        "This is a test notification from Kira.",
        Utc::now(),
    )
    .await;
    Ok(Json(json!({ "results": results })))
}
