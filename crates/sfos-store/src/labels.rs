//! Destination labels (`ip_labels`) and the "where does unclassified traffic go" report.

use anyhow::Result;
use serde::Serialize;
use sfos_core::classify;
use uuid::Uuid;

use crate::store::Store;

#[derive(Debug, Clone, Serialize)]
pub struct Destination {
    pub ip: String,
    pub host: Option<String>,
    pub app: Option<String>,
    pub category: Option<String>,
    pub source: Option<String>,
    pub country: Option<String>,
    pub port: Option<i32>,
    pub protocol: Option<String>,
    pub service: Option<String>,
    pub connections: i64,
    pub bytes: i64,
    pub users: i64,
}

impl Store {
    pub async fn load_ip_labels(&self) -> Result<Vec<(String, String, String)>> {
        let client = self.pool().get().await?;
        let rows = client
            .query("SELECT ip, app, category FROM ip_labels", &[])
            .await?;
        Ok(rows
            .iter()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .collect())
    }

    /// Insert or refresh a label. Learners never replace a `manual` label.
    pub async fn save_ip_label(
        &self,
        ip: &str,
        host: Option<&str>,
        app: &str,
        category: &str,
        source: &str,
    ) -> Result<()> {
        let client = self.pool().get().await?;
        client
            .execute(
                "INSERT INTO ip_labels (ip, host, app, category, source, seen_at)
                 VALUES ($1, $2, $3, $4, $5, now())
                 ON CONFLICT (ip) DO UPDATE
                 SET host = EXCLUDED.host, app = EXCLUDED.app, category = EXCLUDED.category,
                     source = EXCLUDED.source, seen_at = now()
                 WHERE ip_labels.source <> 'manual' OR EXCLUDED.source = 'manual'",
                &[&ip, &host, &app, &category, &source],
            )
            .await?;
        Ok(())
    }

    pub async fn delete_ip_label(&self, ip: &str) -> Result<u64> {
        let client = self.pool().get().await?;
        Ok(client
            .execute("DELETE FROM ip_labels WHERE ip = $1", &[&ip])
            .await?)
    }

    /// Learn address -> host from web-filter lines (they carry both the domain and the address).
    /// Uses the web category the firewall already assigned when there is one.
    pub async fn learn_ip_labels_from_web(&self, minutes: i64) -> Result<usize> {
        let client = self.pool().get().await?;
        let rows = client
            .query(
                "SELECT host(dst_ip), domain, max(NULLIF(category, ''))
                 FROM events
                 WHERE category_group = 'Web' AND dst_ip IS NOT NULL AND domain IS NOT NULL
                   AND domain <> '' AND ts >= now() - make_interval(mins => $1::int)
                 GROUP BY 1, 2 LIMIT 5000",
                &[&(minutes.clamp(1, 360) as i32)],
            )
            .await?;
        let mut n = 0;
        for r in rows {
            let ip: String = r.get(0);
            let domain: String = r.get(1);
            let fw_category: Option<String> = r.get(2);
            if !classify::is_public_ip(&ip) {
                continue;
            }
            let (app, category) = match classify::classify_host(&domain) {
                Some((a, c)) => (a.to_string(), c.to_string()),
                None => (
                    classify::registrable_domain(&domain),
                    fw_category.unwrap_or_else(|| "Unclassified (web)".into()),
                ),
            };
            self.save_ip_label(&ip, Some(&domain), &app, &category, "web")
                .await?;
            n += 1;
        }
        Ok(n)
    }

    /// Public destination addresses seen in the last `minutes` that still have no label,
    /// biggest talkers first.
    pub async fn unlabelled_destinations(&self, minutes: i64, limit: i64) -> Result<Vec<String>> {
        let client = self.pool().get().await?;
        let rows = client
            .query(
                "SELECT host(e.dst_ip) FROM events e
                 WHERE e.category_group = 'Firewall' AND e.dst_ip IS NOT NULL
                   AND e.ts >= now() - make_interval(mins => $1::int)
                   AND NOT EXISTS (SELECT 1 FROM ip_labels l WHERE l.ip = host(e.dst_ip))
                 GROUP BY 1
                 ORDER BY sum(coalesce(e.sent_bytes, 0) + coalesce(e.recv_bytes, 0)) DESC
                 LIMIT $2",
                &[&(minutes.clamp(1, 360) as i32), &limit.clamp(1, 1000)],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|r| r.get::<_, String>(0))
            .filter(|ip| classify::is_public_ip(ip))
            .collect())
    }

    pub async fn prune_ip_labels(&self, days: i32) -> Result<u64> {
        let client = self.pool().get().await?;
        Ok(client
            .execute(
                "DELETE FROM ip_labels WHERE source <> 'manual' AND seen_at < now() - make_interval(days => $1)",
                &[&days],
            )
            .await?)
    }

    /// Top firewall destinations in the raw event window, joined to the learned labels.
    /// `unclassified_only` keeps rows the firewall did not name (no application) and that have no label.
    pub async fn top_destinations(
        &self,
        tenant: Uuid,
        minutes: i64,
        limit: i64,
        unclassified_only: bool,
    ) -> Result<Vec<Destination>> {
        let client = self.pool().get().await?;
        let rows = client
            .query(
                "SELECT host(e.dst_ip) AS ip, l.host, l.app, l.category, l.source,
                        max(e.dst_country), e.dst_port, max(e.protocol),
                        count(*), sum(coalesce(e.sent_bytes, 0) + coalesce(e.recv_bytes, 0))::bigint,
                        count(DISTINCT e.user_name)
                 FROM events e
                 LEFT JOIN ip_labels l ON l.ip = host(e.dst_ip)
                 WHERE e.tenant_id = $1 AND e.category_group = 'Firewall' AND e.dst_ip IS NOT NULL
                   AND e.ts >= now() - make_interval(mins => $2::int)
                   AND ($4 = false OR (l.ip IS NULL AND coalesce(e.application, '') = ''))
                 GROUP BY 1, 2, 3, 4, 5, e.dst_port
                 ORDER BY 10 DESC
                 LIMIT $3",
                &[
                    &tenant,
                    &(minutes.clamp(1, 360) as i32),
                    &limit.clamp(1, 500),
                    &unclassified_only,
                ],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|r| {
                let ip: String = r.get(0);
                let port: Option<i32> = r.get(6);
                let protocol: Option<String> = r.get(7);
                let service = port
                    .and_then(|p| classify::service_for_port(protocol.as_deref(), p))
                    .map(|(a, _)| a.to_string());
                Destination {
                    ip,
                    host: r.get(1),
                    app: r.get(2),
                    category: r.get(3),
                    source: r.get(4),
                    country: r.get(5),
                    port,
                    protocol,
                    service,
                    connections: r.get(8),
                    bytes: r.get(9),
                    users: r.get(10),
                }
            })
            .collect())
    }
}
