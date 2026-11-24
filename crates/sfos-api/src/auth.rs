//! Dashboard authentication: local users with argon2 password hashes, opaque
//! server-side sessions in an HttpOnly cookie, roles (admin / viewer), a login
//! rate limiter and an audit trail.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use chrono::{Duration as ChronoDuration, Utc};
use serde::Deserialize;
use serde_json::json;
use sfos_store::{AppUser, Store};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::api::AppState;

pub const COOKIE_NAME: &str = "kira_session";
const MAX_FAILURES: u32 = 10;
/// Per-IP ceiling across all usernames (higher: many people can share one NAT address).
const MAX_FAILURES_PER_IP: u32 = 50;
const FAILURE_WINDOW: Duration = Duration::from_secs(600);

#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// `AUTH_DISABLED=true`: every request is treated as an admin. Development/CI only.
    pub disabled: bool,
    /// `COOKIE_SECURE=true` adds the `Secure` flag (set when served over HTTPS).
    pub cookie_secure: bool,
    pub session_hours: i64,
    /// `TRUST_PROXY=true` reads the client IP from `X-Forwarded-For` (reverse proxy deployments).
    pub trust_proxy: bool,
}

impl AuthConfig {
    pub fn from_env() -> Self {
        let flag = |k: &str| {
            matches!(
                std::env::var(k).as_deref(),
                Ok("1" | "true" | "TRUE" | "yes")
            )
        };
        Self {
            disabled: flag("AUTH_DISABLED"),
            cookie_secure: flag("COOKIE_SECURE"),
            session_hours: std::env::var("SESSION_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(12)
                .clamp(1, 24 * 30),
            trust_proxy: flag("TRUST_PROXY"),
        }
    }
}

pub struct AuthState {
    pub cfg: AuthConfig,
    failures: Mutex<HashMap<String, (u32, Instant)>>,
}

impl AuthState {
    pub fn new(cfg: AuthConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            failures: Mutex::new(HashMap::new()),
        })
    }

    fn blocked(&self, key: &str, limit: u32) -> bool {
        let mut map = self.failures.lock().unwrap();
        match map.get(key) {
            Some((n, since)) if since.elapsed() < FAILURE_WINDOW => *n >= limit,
            Some(_) => {
                map.remove(key);
                false
            }
            None => false,
        }
    }

    fn record_failure(&self, key: &str) {
        let mut map = self.failures.lock().unwrap();
        if map.len() > 10_000 {
            map.retain(|_, (_, since)| since.elapsed() < FAILURE_WINDOW);
        }
        let e = map.entry(key.to_string()).or_insert((0, Instant::now()));
        if e.1.elapsed() >= FAILURE_WINDOW {
            *e = (0, Instant::now());
        }
        e.0 += 1;
    }

    fn clear_failures(&self, key: &str) {
        self.failures.lock().unwrap().remove(key);
    }
}

fn json_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

// ---------- primitives ----------

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow!("password hashing failed: {e}"))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

/// Hash of a throwaway password, verified against when the username is unknown so
/// that response time does not reveal which usernames exist.
fn dummy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| hash_password("kira-dummy-password").expect("hash"))
}

pub fn new_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

pub fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers.get_all(header::COOKIE).iter().find_map(|v| {
        v.to_str().ok()?.split(';').find_map(|part| {
            let (k, val) = part.trim().split_once('=')?;
            (k == COOKIE_NAME && !val.is_empty()).then(|| val.to_string())
        })
    })
}

fn session_cookie(cfg: &AuthConfig, token: &str, max_age_secs: i64) -> String {
    let secure = if cfg.cookie_secure { "; Secure" } else { "" };
    format!(
        "{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age_secs}{secure}"
    )
}

fn client_ip(cfg: &AuthConfig, headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if cfg.trust_proxy {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return ip.to_string();
        }
    }
    peer.map(|p| p.ip().to_string())
        .unwrap_or_else(|| "unknown".into())
}

pub fn valid_username(u: &str) -> bool {
    (3..=64).contains(&u.len())
        && u.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
}

pub fn valid_password(p: &str) -> bool {
    (10..=128).contains(&p.chars().count())
}

fn synthetic_admin() -> AppUser {
    AppUser {
        id: Uuid::nil(),
        username: "(auth disabled)".into(),
        role: "admin".into(),
        disabled: false,
        created_at: Utc::now(),
        last_login_at: None,
    }
}

// ---------- bootstrap ----------

/// Create the first admin when no users exist. The password comes from
/// `ADMIN_PASSWORD`, or is generated and logged once.
pub async fn bootstrap_admin(store: &Store) -> Result<()> {
    if store.count_users().await? > 0 {
        return Ok(());
    }
    let username = std::env::var("ADMIN_USERNAME").unwrap_or_else(|_| "admin".into());
    if !valid_username(&username) {
        return Err(anyhow!(
            "ADMIN_USERNAME must be 3-64 characters (letters, digits, . _ - @)"
        ));
    }
    let (password, generated) = match std::env::var("ADMIN_PASSWORD")
        .ok()
        .filter(|p| !p.is_empty())
    {
        Some(p) if valid_password(&p) => (p, false),
        Some(_) => return Err(anyhow!("ADMIN_PASSWORD must be 10-128 characters")),
        None => (new_token()[..20].to_string(), true),
    };
    let hash = tokio::task::spawn_blocking({
        let p = password.clone();
        move || hash_password(&p)
    })
    .await??;
    store.create_user(&username, &hash, "admin").await?;
    if generated {
        tracing::warn!(
            username = %username,
            password = %password,
            "no users existed: created an admin account with a generated password. \
             Sign in and change it; this message is shown only once"
        );
    } else {
        tracing::info!(username = %username, "created initial admin account from ADMIN_PASSWORD");
    }
    Ok(())
}

// ---------- middleware ----------

#[derive(Clone)]
pub struct CurrentUser(pub AppUser);

/// Guards `/api/*` (except login). Viewers are read-only; `/api/v1/users*` is admin-only.
pub async fn require_auth(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if !path.starts_with("/api/") || path == "/api/v1/auth/login" {
        return next.run(req).await;
    }
    let user = if state.auth.cfg.disabled {
        synthetic_admin()
    } else {
        let Some(token) = cookie_token(req.headers()) else {
            return json_error(StatusCode::UNAUTHORIZED, "authentication required");
        };
        match state.store.session_user(&token_hash(&token)).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                return json_error(StatusCode::UNAUTHORIZED, "session expired, sign in again")
            }
            Err(err) => {
                tracing::error!(%err, "session lookup failed");
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
            }
        }
    };
    let read_only = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let self_service = path == "/api/v1/auth/logout" || path == "/api/v1/auth/password";
    if user.role != "admin" && !self_service && (!read_only || path.starts_with("/api/v1/users")) {
        return json_error(StatusCode::FORBIDDEN, "administrator role required");
    }
    req.extensions_mut().insert(CurrentUser(user));
    next.run(req).await
}

// ---------- handlers ----------

#[derive(Deserialize)]
pub struct LoginBody {
    username: String,
    password: String,
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Response {
    let ip = client_ip(&state.auth.cfg, &headers, Some(peer));
    let key = format!("{ip}|{}", body.username.to_lowercase());
    if state.auth.blocked(&key, MAX_FAILURES) || state.auth.blocked(&ip, MAX_FAILURES_PER_IP) {
        state
            .store
            .audit(
                Some(&body.username),
                "login_blocked",
                "rate limited",
                Some(&ip),
            )
            .await;
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed attempts, try again in a few minutes",
        );
    }
    let found = match state.store.user_with_hash(&body.username).await {
        Ok(f) => f,
        Err(err) => {
            tracing::error!(%err, "login lookup failed");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
        }
    };
    let (hash, user) = match &found {
        Some(f) => (f.password_hash.clone(), Some(f.user.clone())),
        None => (dummy_hash().to_string(), None),
    };
    let password = body.password.clone();
    let ok = tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .unwrap_or(false);
    let Some(user) = user.filter(|u| ok && !u.disabled) else {
        state.auth.record_failure(&key);
        state.auth.record_failure(&ip);
        state
            .store
            .audit(
                Some(&body.username),
                "login_failed",
                "bad credentials",
                Some(&ip),
            )
            .await;
        return json_error(StatusCode::UNAUTHORIZED, "invalid username or password");
    };
    state.auth.clear_failures(&key);

    let token = new_token();
    let ttl = ChronoDuration::hours(state.auth.cfg.session_hours);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(200).collect::<String>());
    if let Err(err) = state
        .store
        .create_session(
            user.id,
            &token_hash(&token),
            Utc::now() + ttl,
            Some(&ip),
            ua.as_deref(),
        )
        .await
    {
        tracing::error!(%err, "session create failed");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
    }
    let _ = state.store.record_login(user.id).await;
    state
        .store
        .audit(Some(&user.username), "login", "ok", Some(&ip))
        .await;

    let cookie = session_cookie(&state.auth.cfg, &token, ttl.num_seconds());
    let mut res = Json(json!({ "username": user.username, "role": user.role })).into_response();
    res.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("cookie"),
    );
    res
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(CurrentUser(user)): Extension<CurrentUser>,
) -> Response {
    if let Some(token) = cookie_token(&headers) {
        let _ = state.store.delete_session(&token_hash(&token)).await;
    }
    state
        .store
        .audit(Some(&user.username), "logout", "", None)
        .await;
    let mut res = Json(json!({ "ok": true })).into_response();
    let expired = session_cookie(&state.auth.cfg, "", 0);
    res.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&expired).expect("cookie"),
    );
    res
}

pub async fn me(
    State(state): State<AppState>,
    Extension(CurrentUser(user)): Extension<CurrentUser>,
) -> Response {
    Json(json!({
        "username": user.username,
        "role": user.role,
        "auth_disabled": state.auth.cfg.disabled,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct ChangePasswordBody {
    current_password: String,
    new_password: String,
}

pub async fn change_own_password(
    State(state): State<AppState>,
    Extension(CurrentUser(user)): Extension<CurrentUser>,
    Json(body): Json<ChangePasswordBody>,
) -> Response {
    if state.auth.cfg.disabled {
        return json_error(StatusCode::BAD_REQUEST, "authentication is disabled");
    }
    if !valid_password(&body.new_password) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "new password must be 10-128 characters",
        );
    }
    let Ok(Some(current)) = state.store.password_hash_for(user.id).await else {
        return json_error(StatusCode::NOT_FOUND, "user not found");
    };
    let new_pw = body.new_password.clone();
    let cur_pw = body.current_password.clone();
    let result = tokio::task::spawn_blocking(move || {
        verify_password(&cur_pw, &current).then(|| hash_password(&new_pw))
    })
    .await
    .ok()
    .flatten();
    match result {
        None => json_error(StatusCode::FORBIDDEN, "current password is incorrect"),
        Some(Err(err)) => {
            tracing::error!(%err, "hash failed");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
        }
        Some(Ok(hash)) => match state.store.set_password(user.id, &hash).await {
            Ok(_) => {
                state
                    .store
                    .audit(Some(&user.username), "password_changed", "self", None)
                    .await;
                let mut res = Json(json!({ "ok": true, "reauthenticate": true })).into_response();
                let expired = session_cookie(&state.auth.cfg, "", 0);
                res.headers_mut().insert(
                    header::SET_COOKIE,
                    HeaderValue::from_str(&expired).expect("cookie"),
                );
                res
            }
            Err(err) => {
                tracing::error!(%err, "set password failed");
                json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            }
        },
    }
}

pub async fn list_users(State(state): State<AppState>) -> Response {
    match state.store.list_users().await {
        Ok(users) => Json(json!({ "rows": users })).into_response(),
        Err(err) => {
            tracing::error!(%err, "list users failed");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
        }
    }
}

#[derive(Deserialize)]
pub struct CreateUserBody {
    username: String,
    password: String,
    role: String,
}

pub async fn create_user(
    State(state): State<AppState>,
    Extension(CurrentUser(actor)): Extension<CurrentUser>,
    Json(body): Json<CreateUserBody>,
) -> Response {
    if !valid_username(&body.username) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "username must be 3-64 characters (letters, digits, . _ - @)",
        );
    }
    if !valid_password(&body.password) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "password must be 10-128 characters",
        );
    }
    if !matches!(body.role.as_str(), "admin" | "viewer") {
        return json_error(StatusCode::BAD_REQUEST, "role must be admin or viewer");
    }
    let pw = body.password.clone();
    let hash = match tokio::task::spawn_blocking(move || hash_password(&pw)).await {
        Ok(Ok(h)) => h,
        _ => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error"),
    };
    match state
        .store
        .create_user(&body.username, &hash, &body.role)
        .await
    {
        Ok(user) => {
            state
                .store
                .audit(
                    Some(&actor.username),
                    "user_created",
                    &format!("{} ({})", user.username, user.role),
                    None,
                )
                .await;
            (StatusCode::CREATED, Json(user)).into_response()
        }
        Err(err)
            if err
                .downcast_ref::<tokio_postgres::Error>()
                .and_then(|e| e.code())
                == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) =>
        {
            json_error(StatusCode::CONFLICT, "username already exists")
        }
        Err(err) => {
            tracing::error!(%err, "create user failed");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
        }
    }
}

pub async fn delete_user(
    State(state): State<AppState>,
    Extension(CurrentUser(actor)): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
) -> Response {
    if id == actor.id {
        return json_error(
            StatusCode::BAD_REQUEST,
            "you cannot delete your own account",
        );
    }
    match state.store.delete_user(id).await {
        Ok(true) => {
            state
                .store
                .audit(Some(&actor.username), "user_deleted", &id.to_string(), None)
                .await;
            Json(json!({ "ok": true })).into_response()
        }
        Ok(false) => json_error(
            StatusCode::CONFLICT,
            "user not found, or it is the last administrator",
        ),
        Err(err) => {
            tracing::error!(%err, "delete user failed");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
        }
    }
}

#[derive(Deserialize)]
pub struct ResetPasswordBody {
    password: String,
}

pub async fn reset_password(
    State(state): State<AppState>,
    Extension(CurrentUser(actor)): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Json(body): Json<ResetPasswordBody>,
) -> Response {
    if !valid_password(&body.password) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "password must be 10-128 characters",
        );
    }
    let pw = body.password.clone();
    let hash = match tokio::task::spawn_blocking(move || hash_password(&pw)).await {
        Ok(Ok(h)) => h,
        _ => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error"),
    };
    match state.store.set_password(id, &hash).await {
        Ok(true) => {
            state
                .store
                .audit(
                    Some(&actor.username),
                    "password_reset",
                    &id.to_string(),
                    None,
                )
                .await;
            Json(json!({ "ok": true })).into_response()
        }
        Ok(false) => json_error(StatusCode::NOT_FOUND, "user not found"),
        Err(err) => {
            tracing::error!(%err, "reset password failed");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_roundtrip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2"));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong", &h));
        assert!(!verify_password("x", "not-a-hash"));
    }

    #[test]
    fn tokens_are_unique_long_and_hash_is_stable() {
        let (a, b) = (new_token(), new_token());
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert_eq!(token_hash("abc"), token_hash("abc"));
        assert_eq!(token_hash("abc").len(), 64);
        assert_eq!(
            token_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn parses_session_cookie_among_others() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; kira_session=tok123; b=2"),
        );
        assert_eq!(cookie_token(&h).as_deref(), Some("tok123"));
        let mut empty = HeaderMap::new();
        empty.insert(
            header::COOKIE,
            HeaderValue::from_static("kira_session=; x=y"),
        );
        assert_eq!(cookie_token(&empty), None);
        assert_eq!(cookie_token(&HeaderMap::new()), None);
    }

    #[test]
    fn cookie_flags() {
        let cfg = AuthConfig {
            disabled: false,
            cookie_secure: true,
            session_hours: 12,
            trust_proxy: false,
        };
        let c = session_cookie(&cfg, "t", 60);
        assert!(c.contains("HttpOnly") && c.contains("SameSite=Strict") && c.contains("Secure"));
        let plain = session_cookie(
            &AuthConfig {
                cookie_secure: false,
                ..cfg
            },
            "t",
            60,
        );
        assert!(!plain.contains("Secure"));
    }

    #[test]
    fn validation_rules() {
        assert!(
            valid_username("ali.khan@corp") && !valid_username("a") && !valid_username("bad name")
        );
        assert!(valid_password("0123456789") && !valid_password("short"));
    }

    #[test]
    fn rate_limiter_blocks_after_max_failures_and_clears() {
        let s = AuthState::new(AuthConfig {
            disabled: false,
            cookie_secure: false,
            session_hours: 1,
            trust_proxy: false,
        });
        for _ in 0..MAX_FAILURES {
            assert!(!s.blocked("k", MAX_FAILURES));
            s.record_failure("k");
        }
        assert!(s.blocked("k", MAX_FAILURES));
        assert!(!s.blocked("other", MAX_FAILURES));
        assert!(!s.blocked("k", MAX_FAILURES_PER_IP));
        s.clear_failures("k");
        assert!(!s.blocked("k", MAX_FAILURES));
    }

    #[test]
    fn proxy_header_only_trusted_when_enabled() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.9, 10.0.0.1"),
        );
        let peer: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let mut cfg = AuthConfig {
            disabled: false,
            cookie_secure: false,
            session_hours: 1,
            trust_proxy: false,
        };
        assert_eq!(client_ip(&cfg, &h, Some(peer)), "10.0.0.1");
        cfg.trust_proxy = true;
        assert_eq!(client_ip(&cfg, &h, Some(peer)), "203.0.113.9");
    }
}
