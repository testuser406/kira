//! Dashboard users, sessions and audit log.
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::store::Store;

#[derive(Debug, Clone, Serialize)]
pub struct AppUser {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub disabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct UserWithHash {
    pub user: AppUser,
    pub password_hash: String,
}

const USER_COLS: &str = "id, username, role, disabled, created_at, last_login_at";

fn user_from(row: &tokio_postgres::Row) -> AppUser {
    AppUser {
        id: row.get(0),
        username: row.get(1),
        role: row.get(2),
        disabled: row.get(3),
        created_at: row.get(4),
        last_login_at: row.get(5),
    }
}

impl Store {
    pub async fn count_users(&self) -> Result<i64> {
        let c = self.pool.get().await?;
        Ok(c.query_one("SELECT count(*) FROM app_users", &[])
            .await?
            .get(0))
    }

    pub async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
    ) -> Result<AppUser> {
        let c = self.pool.get().await?;
        let row = c
            .query_one(
                &format!(
                    "INSERT INTO app_users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING {USER_COLS}"
                ),
                &[&username, &password_hash, &role],
            )
            .await?;
        Ok(user_from(&row))
    }

    pub async fn user_with_hash(&self, username: &str) -> Result<Option<UserWithHash>> {
        let c = self.pool.get().await?;
        let row = c
            .query_opt(
                &format!("SELECT {USER_COLS}, password_hash FROM app_users WHERE lower(username) = lower($1)"),
                &[&username],
            )
            .await?;
        Ok(row.map(|r| UserWithHash {
            user: user_from(&r),
            password_hash: r.get(6),
        }))
    }

    pub async fn password_hash_for(&self, id: Uuid) -> Result<Option<String>> {
        let c = self.pool.get().await?;
        Ok(
            c.query_opt("SELECT password_hash FROM app_users WHERE id = $1", &[&id])
                .await?
                .map(|r| r.get(0)),
        )
    }

    pub async fn list_users(&self) -> Result<Vec<AppUser>> {
        let c = self.pool.get().await?;
        let rows = c
            .query(
                &format!("SELECT {USER_COLS} FROM app_users ORDER BY lower(username)"),
                &[],
            )
            .await?;
        Ok(rows.iter().map(user_from).collect())
    }

    /// Delete a user unless that would remove the last enabled admin.
    pub async fn delete_user(&self, id: Uuid) -> Result<bool> {
        let c = self.pool.get().await?;
        let n = c
            .execute(
                "DELETE FROM app_users WHERE id = $1 AND (
                    role <> 'admin' OR disabled
                    OR (SELECT count(*) FROM app_users WHERE role = 'admin' AND NOT disabled) > 1)",
                &[&id],
            )
            .await?;
        Ok(n > 0)
    }

    /// Replace a password and revoke the user's existing sessions.
    pub async fn set_password(&self, id: Uuid, password_hash: &str) -> Result<bool> {
        let c = self.pool.get().await?;
        let n = c
            .execute(
                "UPDATE app_users SET password_hash = $2 WHERE id = $1",
                &[&id, &password_hash],
            )
            .await?;
        if n > 0 {
            c.execute("DELETE FROM app_sessions WHERE user_id = $1", &[&id])
                .await?;
        }
        Ok(n > 0)
    }

    pub async fn record_login(&self, id: Uuid) -> Result<()> {
        let c = self.pool.get().await?;
        c.execute(
            "UPDATE app_users SET last_login_at = now() WHERE id = $1",
            &[&id],
        )
        .await?;
        Ok(())
    }

    pub async fn create_session(
        &self,
        user_id: Uuid,
        token_hash: &str,
        expires_at: DateTime<Utc>,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<()> {
        let c = self.pool.get().await?;
        c.execute(
            "INSERT INTO app_sessions (token_hash, user_id, expires_at, ip, user_agent) VALUES ($1, $2, $3, $4, $5)",
            &[&token_hash, &user_id, &expires_at, &ip, &user_agent],
        )
        .await?;
        Ok(())
    }

    /// The user owning a live (unexpired) session whose account is enabled.
    pub async fn session_user(&self, token_hash: &str) -> Result<Option<AppUser>> {
        let c = self.pool.get().await?;
        let row = c
            .query_opt(
                "SELECT u.id, u.username, u.role, u.disabled, u.created_at, u.last_login_at
                 FROM app_sessions s JOIN app_users u ON u.id = s.user_id
                 WHERE s.token_hash = $1 AND s.expires_at > now() AND NOT u.disabled",
                &[&token_hash],
            )
            .await?;
        Ok(row.as_ref().map(user_from))
    }

    pub async fn delete_session(&self, token_hash: &str) -> Result<()> {
        let c = self.pool.get().await?;
        c.execute(
            "DELETE FROM app_sessions WHERE token_hash = $1",
            &[&token_hash],
        )
        .await?;
        Ok(())
    }

    pub async fn purge_expired_sessions(&self) -> Result<u64> {
        let c = self.pool.get().await?;
        Ok(
            c.execute("DELETE FROM app_sessions WHERE expires_at <= now()", &[])
                .await?,
        )
    }

    pub async fn audit(
        &self,
        username: Option<&str>,
        action: &str,
        detail: &str,
        ip: Option<&str>,
    ) {
        let res = async {
            let c = self.pool.get().await?;
            c.execute(
                "INSERT INTO audit_log (username, action, detail, ip) VALUES ($1, $2, $3, $4)",
                &[&username, &action, &detail, &ip],
            )
            .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(err) = res {
            tracing::warn!(%err, "failed to write audit log");
        }
    }
}
