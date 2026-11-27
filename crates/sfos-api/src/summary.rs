//! Summary reports built from `hourly_activity`: top-N tables, trends and KPIs instead of raw logs.
//! One `Summary` renders to JSON (dashboard), CSV (tables only) and PDF (with charts).

use chrono::{DateTime, Duration, NaiveDateTime, Timelike, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::ApiError;

pub const TYPES: [&str; 13] = [
    "internet_searches",
    "youtube_videos",
    "executive",
    "user",
    "user_overview",
    "online_productivity",
    "websites_allowed_blocked",
    "activity_timeline",
    "firewall_policy",
    "security_threat",
    "network_bandwidth",
    "vpn_connections",
    "subnet",
];

pub fn supports(subtype: &str) -> bool {
    TYPES.contains(&subtype)
}

#[derive(Serialize, Clone)]
pub struct Kpi {
    pub label: String,
    pub value: f64,
    pub unit: &'static str, // count | bytes | minutes | percent
    /// Change versus the previous period of equal length (percent; points for percent KPIs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<f64>,
}

#[derive(Serialize, Clone)]
pub struct Column {
    pub name: String,
    pub unit: &'static str, // text | count | bytes | minutes | percent
}

#[derive(Serialize, Clone)]
pub struct Dataset {
    pub name: String,
    pub values: Vec<f64>,
}

#[derive(Serialize, Clone)]
pub struct Chart {
    pub unit: &'static str,
    pub labels: Vec<String>,
    pub datasets: Vec<Dataset>,
}

#[derive(Serialize, Clone)]
pub struct Section {
    pub title: String,
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<Value>>,
    pub chart: Option<Chart>,
    pub note: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct Summary {
    pub report_type: String,
    pub title: String,
    pub tenant: String,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub generated: DateTime<Utc>,
    pub granularity: &'static str,
    pub user: Option<String>,
    pub kpis: Vec<Kpi>,
    pub sections: Vec<Section>,
}

#[derive(Default, Clone)]
struct Agg {
    key: String,
    events: i64,
    allowed: i64,
    blocked: i64,
    up: i64,
    down: i64,
    minutes: i64,
}
impl Agg {
    fn bytes(&self) -> i64 {
        self.up + self.down
    }
}

struct Ctx<'a> {
    client: &'a tokio_postgres::Client,
    tenant: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    user: Option<String>,
    day: bool,
}

const AGG_COLS: &str = "sum(events)::bigint, sum(allowed)::bigint, sum(blocked)::bigint, \
    sum(bytes_up)::bigint, sum(bytes_down)::bigint, sum(minutes)::bigint";
const FILTER: &str =
    "tenant_id = $1 AND hour >= date_trunc('hour', $2::timestamptz) AND hour < $3 \
    AND dimension = $4 AND ($5::text IS NULL OR starts_with(key, $5))";

fn row_agg(r: &tokio_postgres::Row, key: String) -> Agg {
    let g = |i: usize| r.get::<_, Option<i64>>(i).unwrap_or(0);
    Agg {
        key,
        events: g(1),
        allowed: g(2),
        blocked: g(3),
        up: g(4),
        down: g(5),
        minutes: g(6),
    }
}

impl Ctx<'_> {
    fn prefix(&self, scoped: bool) -> Option<String> {
        if scoped {
            self.user.as_ref().map(|u| format!("{u}\t"))
        } else {
            None
        }
    }

    async fn top_n(
        &self,
        dim: &str,
        scoped: bool,
        order: &str,
        limit: i64,
    ) -> Result<Vec<Agg>, ApiError> {
        let ord = match order {
            "blocked" => "sum(blocked)",
            "allowed" => "sum(allowed)",
            "bytes" => "(sum(bytes_up) + sum(bytes_down))",
            "minutes" => "sum(minutes)",
            _ => "sum(events)",
        };
        let prefix = self.prefix(scoped);
        let sql = format!(
            "SELECT key, {AGG_COLS} FROM hourly_activity WHERE {FILTER} GROUP BY key ORDER BY {ord} DESC, key LIMIT $6"
        );
        let rows = self
            .client
            .query(
                &sql,
                &[&self.tenant, &self.from, &self.to, &dim, &prefix, &limit],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|r| {
                let key: String = r.get(0);
                let key = match &prefix {
                    Some(p) => key.strip_prefix(p.as_str()).unwrap_or(&key).to_string(),
                    None => key,
                };
                row_agg(r, key)
            })
            .collect())
    }

    async fn total(&self, dim: &str, key: Option<&str>) -> Result<Agg, ApiError> {
        let sql = format!(
            "SELECT '' , {AGG_COLS} FROM hourly_activity WHERE {FILTER} AND ($6::text IS NULL OR key = $6)"
        );
        let none: Option<String> = None;
        let r = self
            .client
            .query_one(
                &sql,
                &[&self.tenant, &self.from, &self.to, &dim, &none, &key],
            )
            .await?;
        Ok(row_agg(&r, String::new()))
    }

    /// Distinct keys in a dimension for the range (e.g. active users).
    async fn distinct(&self, dim: &str) -> Result<i64, ApiError> {
        let r = self
            .client
            .query_one(
                "SELECT count(DISTINCT key)::bigint FROM hourly_activity WHERE tenant_id = $1
             AND hour >= date_trunc('hour', $2::timestamptz) AND hour < $3 AND dimension = $4",
                &[&self.tenant, &self.from, &self.to, &dim],
            )
            .await?;
        Ok(r.get(0))
    }

    /// Per-bucket series (hourly, or daily for long ranges), gaps filled with zeros.
    async fn series(&self, dim: &str, key: &str) -> Result<Vec<(String, Agg)>, ApiError> {
        let gran = if self.day { "day" } else { "hour" };
        let sql = format!(
            "SELECT date_trunc('{gran}', hour AT TIME ZONE 'UTC') AS t, {AGG_COLS}
             FROM hourly_activity
             WHERE tenant_id = $1 AND hour >= date_trunc('hour', $2::timestamptz) AND hour < $3
               AND dimension = $4 AND key = $5 GROUP BY 1 ORDER BY 1"
        );
        let rows = self
            .client
            .query(&sql, &[&self.tenant, &self.from, &self.to, &dim, &key])
            .await?;
        let mut map = std::collections::HashMap::new();
        for r in &rows {
            let t: NaiveDateTime = r.get(0);
            map.insert(t, row_agg(r, String::new()));
        }
        let step = if self.day {
            Duration::days(1)
        } else {
            Duration::hours(1)
        };
        let mut t = self.from.naive_utc();
        t = if self.day {
            t.date().and_hms_opt(0, 0, 0).unwrap_or(t)
        } else {
            t.with_minute(0)
                .and_then(|x| x.with_second(0))
                .and_then(|x| x.with_nanosecond(0))
                .unwrap_or(t)
        };
        let end = self.to.naive_utc();
        let mut out = Vec::new();
        while t < end && out.len() < 400 {
            let label = if self.day {
                t.format("%b %d").to_string()
            } else {
                t.format("%d %H:00").to_string()
            };
            out.push((label, map.remove(&t).unwrap_or_default()));
            t += step;
        }
        Ok(out)
    }
}

fn col(name: &str, unit: &'static str) -> Column {
    Column {
        name: name.to_string(),
        unit,
    }
}

type Getter = fn(&Agg) -> i64;

fn chart_of(series: &[(String, Agg)], unit: &'static str, sets: &[(&str, Getter)]) -> Chart {
    Chart {
        unit,
        labels: series.iter().map(|(l, _)| l.clone()).collect(),
        datasets: sets
            .iter()
            .map(|(name, f)| Dataset {
                name: name.to_string(),
                values: series.iter().map(|(_, a)| f(a) as f64).collect(),
            })
            .collect(),
    }
}

fn pct(part: i64, total: i64) -> f64 {
    if total <= 0 {
        0.0
    } else {
        ((part as f64 / total as f64) * 1000.0).round() / 10.0
    }
}

fn section(title: &str, columns: Vec<Column>, rows: Vec<Vec<Value>>) -> Section {
    Section {
        title: title.to_string(),
        columns,
        rows,
        chart: None,
        note: None,
    }
}

/// Table of top keys: label, then selected metrics.
fn ranked(title: &str, label: &str, items: &[Agg], total: &Agg, metrics: &[&str]) -> Section {
    let mut cols = vec![col(label, "text")];
    for m in metrics {
        cols.push(match *m {
            "events" => col("Requests", "count"),
            "allowed" => col("Allowed", "count"),
            "blocked" => col("Blocked", "count"),
            "bytes" => col("Traffic", "bytes"),
            "up" => col("Upload", "bytes"),
            "down" => col("Download", "bytes"),
            "minutes" => col("Active time", "minutes"),
            _ => col("Share", "percent"),
        });
    }
    let rows = items
        .iter()
        .map(|a| {
            let mut r = vec![json!(a.key)];
            for m in metrics {
                r.push(match *m {
                    "events" => json!(a.events),
                    "allowed" => json!(a.allowed),
                    "blocked" => json!(a.blocked),
                    "bytes" => json!(a.bytes()),
                    "up" => json!(a.up),
                    "down" => json!(a.down),
                    "minutes" => json!(a.minutes),
                    _ => json!(pct(a.events, total.events)),
                });
            }
            r
        })
        .collect();
    section(title, cols, rows)
}

async fn class_split(ctx: &Ctx<'_>, dim: &str, scoped: bool) -> Result<Section, ApiError> {
    let keyexpr = if scoped {
        "split_part(h.key, E'\\t', 2)"
    } else {
        "h.key"
    };
    let sql = format!(
        "SELECT COALESCE(g.class, 'neutral'), sum(h.events)::bigint, sum(h.bytes_up + h.bytes_down)::bigint
         FROM hourly_activity h LEFT JOIN productivity_guidelines g
           ON g.tenant_id = h.tenant_id AND g.kind = 'category' AND g.key = {keyexpr}
         WHERE h.tenant_id = $1 AND h.hour >= date_trunc('hour', $2::timestamptz) AND h.hour < $3
           AND h.dimension = $4 AND ($5::text IS NULL OR starts_with(h.key, $5)) GROUP BY 1"
    );
    let prefix = ctx.prefix(scoped);
    let rows = ctx
        .client
        .query(&sql, &[&ctx.tenant, &ctx.from, &ctx.to, &dim, &prefix])
        .await?;
    let mut m = std::collections::HashMap::new();
    let mut total = 0i64;
    for r in &rows {
        let (c, e, b): (String, i64, i64) = (
            r.get(0),
            r.get::<_, Option<i64>>(1).unwrap_or(0),
            r.get::<_, Option<i64>>(2).unwrap_or(0),
        );
        total += e;
        m.insert(c, (e, b));
    }
    let out = ["productive", "neutral", "unproductive"]
        .iter()
        .map(|c| {
            let (e, b) = m.get(*c).copied().unwrap_or((0, 0));
            vec![json!(c), json!(e), json!(pct(e, total)), json!(b)]
        })
        .collect();
    Ok(section(
        "Productivity split",
        vec![
            col("Class", "text"),
            col("Requests", "count"),
            col("Share", "percent"),
            col("Traffic", "bytes"),
        ],
        out,
    ))
}

fn kpi(label: &str, value: i64, unit: &'static str) -> Kpi {
    Kpi {
        label: label.to_string(),
        value: value as f64,
        unit,
        delta: None,
    }
}

fn productive_pct(split: &Section) -> f64 {
    split
        .rows
        .first()
        .and_then(|r| r[2].as_f64())
        .unwrap_or(0.0)
}

#[allow(clippy::too_many_arguments)]
async fn build_one(
    client: &tokio_postgres::Client,
    tenant: Uuid,
    tenant_name: &str,
    report_type: &str,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    user: Option<String>,
    top: i64,
) -> Result<Summary, ApiError> {
    let user = user.map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
    if report_type == "internet_searches" || report_type == "youtube_videos" {
        return build_web(
            client,
            tenant,
            tenant_name,
            report_type,
            from,
            to,
            user,
            top.clamp(5, 100),
        )
        .await;
    }
    if report_type == "user_overview" && user.is_none() {
        return Err(ApiError::bad_request("user_overview needs a user"));
    }
    let top = top.clamp(5, 100);
    let ctx = Ctx {
        client,
        tenant,
        from,
        to,
        user: user.clone(),
        day: (to - from) > Duration::hours(72),
    };
    let ov = ctx.total("overview", Some("")).await?;
    let web = ctx.total("group", Some("web")).await?;
    let threat = ctx.total("group", Some("threat")).await?;
    let web_minutes = ctx.total("web_users", None).await?.minutes;

    let mut kpis: Vec<Kpi> = Vec::new();
    let mut sections: Vec<Section> = Vec::new();
    let title: &str;

    match report_type {
        "executive" => {
            title = "Executive Summary";
            let split = class_split(&ctx, "categories", false).await?;
            kpis.extend([
                kpi("Total events", ov.events, "count"),
                kpi("Web requests", web.events, "count"),
                kpi("Blocked", ov.blocked, "count"),
                kpi("Threat events", threat.events, "count"),
                kpi("Traffic", ov.bytes(), "bytes"),
                kpi(
                    "Active web users",
                    ctx.distinct("web_users").await?,
                    "count",
                ),
                kpi("Browse time", web_minutes, "minutes"),
                Kpi {
                    label: "Productive share".into(),
                    value: productive_pct(&split),
                    unit: "percent",
                    delta: None,
                },
            ]);
            let s = ctx.series("overview", "").await?;
            let mut trend = section("Activity over time", vec![], vec![]);
            trend.chart = Some(chart_of(
                &s,
                "count",
                &[("Allowed", |a| a.allowed), ("Blocked", |a| a.blocked)],
            ));
            sections.push(trend);
            sections.push(split);
            let t = ctx.total("web_users", None).await?;
            sections.push(ranked(
                "Top users by browse time",
                "User",
                &ctx.top_n("web_users", false, "minutes", top).await?,
                &t,
                &["minutes", "events", "allowed", "blocked"],
            ));
            let t = ctx.total("sites", None).await?;
            sections.push(ranked(
                "Top sites",
                "Site",
                &ctx.top_n("sites", false, "minutes", top).await?,
                &t,
                &["minutes", "events", "allowed", "blocked", "bytes"],
            ));
            let t = ctx.total("categories", None).await?;
            sections.push(ranked(
                "Top categories",
                "Category",
                &ctx.top_n("categories", false, "events", top).await?,
                &t,
                &["events", "allowed", "blocked", "share"],
            ));
            let t = ctx.total("threats", None).await?;
            sections.push(ranked(
                "Top threats",
                "Threat",
                &ctx.top_n("threats", false, "events", top.min(10)).await?,
                &t,
                &["events"],
            ));
            let t = ctx.total("applications", None).await?;
            sections.push(ranked(
                "Top applications by traffic",
                "Application",
                &ctx.top_n("applications", false, "bytes", top).await?,
                &t,
                &["bytes", "events", "allowed", "blocked"],
            ));
        }
        "online_productivity" => {
            title = "Online Productivity";
            let split = class_split(&ctx, "categories", false).await?;
            kpis.extend([
                kpi("Web requests", web.events, "count"),
                kpi("Browse time", web_minutes, "minutes"),
                Kpi {
                    label: "Productive share".into(),
                    value: productive_pct(&split),
                    unit: "percent",
                    delta: None,
                },
                kpi("Blocked by web filter", web.blocked, "count"),
            ]);
            let s = ctx.series("group", "web").await?;
            let mut trend = section("Web requests over time", vec![], vec![]);
            trend.chart = Some(chart_of(
                &s,
                "count",
                &[("Allowed", |a| a.allowed), ("Blocked", |a| a.blocked)],
            ));
            sections.push(trend);
            sections.push(split);
            let t = ctx.total("web_users", None).await?;
            sections.push(ranked(
                "Users by browse time",
                "User",
                &ctx.top_n("web_users", false, "minutes", top).await?,
                &t,
                &["minutes", "events", "allowed", "blocked"],
            ));
            let t = ctx.total("sites", None).await?;
            sections.push(ranked(
                "Sites by browse time",
                "Site",
                &ctx.top_n("sites", false, "minutes", top).await?,
                &t,
                &["minutes", "events", "allowed", "blocked", "bytes"],
            ));
            let t = ctx.total("categories", None).await?;
            sections.push(ranked(
                "Categories",
                "Category",
                &ctx.top_n("categories", false, "events", top).await?,
                &t,
                &["events", "allowed", "blocked", "share"],
            ));
        }
        "user" => {
            title = "User Report";
            kpis.extend([
                kpi("Users", ctx.distinct("users").await?, "count"),
                kpi("Total traffic", ov.bytes(), "bytes"),
                kpi("Blocked", ov.blocked, "count"),
                kpi("Browse time", web_minutes, "minutes"),
            ]);
            let t = ctx.total("users", None).await?;
            sections.push(ranked(
                "Top users by traffic",
                "User",
                &ctx.top_n("users", false, "bytes", top).await?,
                &t,
                &["bytes", "events", "allowed", "blocked", "share"],
            ));
            let t = ctx.total("web_users", None).await?;
            sections.push(ranked(
                "Top users by browse time",
                "User",
                &ctx.top_n("web_users", false, "minutes", top).await?,
                &t,
                &["minutes", "events", "allowed", "blocked"],
            ));
        }
        "user_overview" => {
            let u = user.clone().unwrap_or_default();
            title = "User Overview";
            let t = ctx.total("users", Some(&u)).await?;
            let wt = ctx.total("web_users", Some(&u)).await?;
            let split = class_split(&ctx, "user_categories", true).await?;
            kpis.extend([
                kpi("Requests", t.events, "count"),
                kpi("Blocked", t.blocked, "count"),
                kpi("Traffic", t.bytes(), "bytes"),
                kpi("Browse time", wt.minutes, "minutes"),
                Kpi {
                    label: "Productive share".into(),
                    value: productive_pct(&split),
                    unit: "percent",
                    delta: None,
                },
            ]);
            let s = ctx.series("users", &u).await?;
            let mut trend = section("Activity over time", vec![], vec![]);
            trend.chart = Some(chart_of(&s, "count", &[("Requests", |a| a.events)]));
            sections.push(trend);
            sections.push(split);
            let st = ctx.total("user_sites", None).await?;
            sections.push(ranked(
                "Top sites",
                "Site",
                &ctx.top_n("user_sites", true, "minutes", top).await?,
                &st,
                &["minutes", "events", "allowed", "blocked", "bytes"],
            ));
            sections.push(ranked(
                "Top categories",
                "Category",
                &ctx.top_n("user_categories", true, "events", top).await?,
                &st,
                &["events", "allowed", "blocked"],
            ));
        }
        "websites_allowed_blocked" => {
            title = "Allowed & Blocked Websites";
            kpis.extend([
                kpi("Allowed", web.allowed, "count"),
                kpi("Blocked", web.blocked, "count"),
            ]);
            let t = ctx.total("domains", None).await?;
            sections.push(ranked(
                "Most visited websites",
                "Website",
                &ctx.top_n("domains", false, "allowed", top).await?,
                &t,
                &["allowed", "blocked", "bytes"],
            ));
            sections.push(ranked(
                "Most blocked websites",
                "Website",
                &ctx.top_n("domains", false, "blocked", top).await?,
                &t,
                &["blocked", "allowed"],
            ));
            let s = ctx.series("group", "web").await?;
            let mut trend = section("Allowed vs blocked over time", vec![], vec![]);
            trend.chart = Some(chart_of(
                &s,
                "count",
                &[("Allowed", |a| a.allowed), ("Blocked", |a| a.blocked)],
            ));
            sections.insert(0, trend);
        }
        "activity_timeline" => {
            title = "Activity Timeline";
            kpis.extend([
                kpi("Events", ov.events, "count"),
                kpi("Active minutes", ov.minutes, "minutes"),
            ]);
            let s = ctx.series("overview", "").await?;
            let mut trend = section("Activity over time", vec![], vec![]);
            trend.chart = Some(chart_of(
                &s,
                "count",
                &[("Allowed", |a| a.allowed), ("Blocked", |a| a.blocked)],
            ));
            sections.push(trend);
            let rows = s
                .iter()
                .map(|(l, a)| {
                    vec![
                        json!(l),
                        json!(a.events),
                        json!(a.blocked),
                        json!(a.minutes),
                        json!(a.bytes()),
                    ]
                })
                .collect();
            sections.push(section(
                "Per period",
                vec![
                    col("Period", "text"),
                    col("Events", "count"),
                    col("Blocked", "count"),
                    col("Active time", "minutes"),
                    col("Traffic", "bytes"),
                ],
                rows,
            ));
        }
        "firewall_policy" => {
            title = "Firewall Policy";
            kpis.extend([
                kpi("Events", ov.events, "count"),
                kpi("Allowed", ov.allowed, "count"),
                kpi("Blocked", ov.blocked, "count"),
            ]);
            let t = ctx.total("policies", None).await?;
            sections.push(ranked(
                "Policies by hits",
                "Policy",
                &ctx.top_n("policies", false, "events", top).await?,
                &t,
                &["events", "allowed", "blocked", "bytes"],
            ));
        }
        "security_threat" => {
            title = "Security & Threats";
            kpis.extend([
                kpi("Threat events", threat.events, "count"),
                kpi("Blocked traffic", ov.blocked, "count"),
            ]);
            let s = ctx.series("group", "threat").await?;
            let mut trend = section("Threat events over time", vec![], vec![]);
            trend.chart = Some(chart_of(&s, "count", &[("Threats", |a| a.events)]));
            sections.push(trend);
            let t = ctx.total("threats", None).await?;
            sections.push(ranked(
                "Top threats",
                "Threat",
                &ctx.top_n("threats", false, "events", top).await?,
                &t,
                &["events", "blocked", "share"],
            ));
            let t = ctx.total("threat_sources", None).await?;
            sections.push(ranked(
                "Top threat sources",
                "Source IP",
                &ctx.top_n("threat_sources", false, "events", top).await?,
                &t,
                &["events", "share"],
            ));
        }
        "network_bandwidth" => {
            title = "Network Bandwidth";
            kpis.extend([
                kpi("Total traffic", ov.bytes(), "bytes"),
                kpi("Download", ov.down, "bytes"),
                kpi("Upload", ov.up, "bytes"),
            ]);
            let s = ctx.series("overview", "").await?;
            let mut trend = section("Traffic over time", vec![], vec![]);
            trend.chart = Some(chart_of(
                &s,
                "bytes",
                &[("Download", |a| a.down), ("Upload", |a| a.up)],
            ));
            sections.push(trend);
            for (name, dim, label) in [
                ("Top users", "users", "User"),
                ("Top applications", "applications", "Application"),
                ("Top destination countries", "countries", "Country"),
            ] {
                let t = ctx.total(dim, None).await?;
                sections.push(ranked(
                    name,
                    label,
                    &ctx.top_n(dim, false, "bytes", top).await?,
                    &t,
                    &["bytes", "down", "up"],
                ));
            }
        }
        "vpn_connections" => {
            title = "VPN Connections";
            let vpn = ctx.total("group", Some("vpn")).await?;
            kpis.extend([
                kpi("VPN users", ctx.distinct("vpn_users").await?, "count"),
                kpi("Tunnels", ctx.distinct("vpn_tunnels").await?, "count"),
                kpi("VPN traffic", vpn.bytes(), "bytes"),
            ]);
            let s = ctx.series("group", "vpn").await?;
            let mut trend = section("VPN traffic over time", vec![], vec![]);
            trend.chart = Some(chart_of(
                &s,
                "bytes",
                &[("Download", |a| a.down), ("Upload", |a| a.up)],
            ));
            sections.push(trend);
            let t = ctx.total("vpn_users", None).await?;
            sections.push(ranked(
                "VPN users",
                "User",
                &ctx.top_n("vpn_users", false, "bytes", top).await?,
                &t,
                &["minutes", "bytes", "events"],
            ));
            let t = ctx.total("vpn_tunnels", None).await?;
            sections.push(ranked(
                "Tunnels",
                "Tunnel",
                &ctx.top_n("vpn_tunnels", false, "bytes", top).await?,
                &t,
                &["minutes", "bytes", "events"],
            ));
        }
        "subnet" => {
            title = "Subnets";
            kpis.extend([kpi("Total traffic", ov.bytes(), "bytes")]);
            let t = ctx.total("subnets", None).await?;
            sections.push(ranked(
                "Traffic by source subnet (/24)",
                "Subnet",
                &ctx.top_n("subnets", false, "bytes", top).await?,
                &t,
                &["bytes", "events", "allowed", "blocked"],
            ));
        }
        other => {
            return Err(ApiError::bad_request(format!(
                "unknown summary report {other:?}"
            )))
        }
    }

    let empty = ov.events == 0;
    if empty {
        if let Some(s) = sections.first_mut() {
            s.note = Some("No data in this range yet. Summary reports use data collected since v0.3.0, at hourly resolution.".into());
        }
    }
    Ok(Summary {
        report_type: report_type.to_string(),
        title: match &user {
            Some(u) if report_type == "user_overview" => format!("{title}: {u}"),
            _ => title.to_string(),
        },
        tenant: tenant_name.to_string(),
        from,
        to,
        generated: Utc::now(),
        granularity: if ctx.day { "day" } else { "hour" },
        user,
        kpis,
        sections,
    })
}

fn ts_label(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M").to_string()
}

/// Searches and YouTube views come from the (90-day) event extracts, not the rollups.
#[allow(clippy::too_many_arguments)]
async fn build_web(
    client: &tokio_postgres::Client,
    tenant: Uuid,
    tenant_name: &str,
    report_type: &str,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    user: Option<String>,
    top: i64,
) -> Result<Summary, ApiError> {
    let videos = report_type == "youtube_videos";
    let table = if videos { "web_videos" } else { "web_searches" };
    let item = if videos { "video_id" } else { "term" };
    let day = (to - from) > Duration::hours(72);
    let gran = if day { "day" } else { "hour" };
    let w = "tenant_id = $1 AND ts >= $2 AND ts < $3 AND ($4::text IS NULL OR user_key = $4)";
    let p: [&(dyn tokio_postgres::types::ToSql + Sync); 4] = [&tenant, &from, &to, &user];

    let tot = client
        .query_one(
            &format!("SELECT count(*)::bigint, count(DISTINCT user_key)::bigint, count(DISTINCT {item})::bigint, count(*) FILTER (WHERE blocked)::bigint FROM {table} WHERE {w}"),
            &p,
        )
        .await?;
    let (n, users, distinct, blocked): (i64, i64, i64, i64) =
        (tot.get(0), tot.get(1), tot.get(2), tot.get(3));
    let (what, uniq) = if videos {
        ("Video views", "Distinct videos")
    } else {
        ("Searches", "Distinct terms")
    };
    let kpis = vec![
        kpi(what, n, "count"),
        kpi("Users", users, "count"),
        kpi(uniq, distinct, "count"),
        kpi("Blocked", blocked, "count"),
    ];

    // Trend with gaps filled.
    let rows = client
        .query(
            &format!("SELECT date_trunc('{gran}', ts AT TIME ZONE 'UTC'), count(*)::bigint FROM {table} WHERE {w} GROUP BY 1 ORDER BY 1"),
            &p,
        )
        .await?;
    let mut map = std::collections::HashMap::new();
    for r in &rows {
        map.insert(r.get::<_, NaiveDateTime>(0), r.get::<_, i64>(1));
    }
    let step = if day {
        Duration::days(1)
    } else {
        Duration::hours(1)
    };
    let mut t = from.naive_utc();
    t = if day {
        t.date().and_hms_opt(0, 0, 0).unwrap_or(t)
    } else {
        t.with_minute(0)
            .and_then(|x| x.with_second(0))
            .and_then(|x| x.with_nanosecond(0))
            .unwrap_or(t)
    };
    let (mut labels, mut values) = (Vec::new(), Vec::new());
    while t < to.naive_utc() && labels.len() < 400 {
        labels.push(if day {
            t.format("%b %d").to_string()
        } else {
            t.format("%d %H:00").to_string()
        });
        values.push(map.remove(&t).unwrap_or(0) as f64);
        t += step;
    }
    let mut trend = section(&format!("{what} over time"), vec![], vec![]);
    trend.chart = Some(Chart {
        unit: "count",
        labels,
        datasets: vec![Dataset {
            name: what.to_string(),
            values,
        }],
    });
    let mut sections = vec![trend];

    // Top items.
    let item_label = if videos { "Video" } else { "Search term" };
    let q = client
        .query(
            &format!("SELECT {item}, count(*)::bigint, count(DISTINCT user_key)::bigint, count(*) FILTER (WHERE blocked)::bigint, max(ts) FROM {table} WHERE {w} GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT $5"),
            &[&tenant, &from, &to, &user, &top],
        )
        .await?;
    let rows = q
        .iter()
        .map(|r| {
            let key: String = r.get(0);
            let shown = if videos {
                format!("youtu.be/{key}")
            } else {
                key
            };
            vec![
                json!(shown),
                json!(r.get::<_, i64>(1)),
                json!(r.get::<_, i64>(2)),
                json!(r.get::<_, i64>(3)),
                json!(ts_label(r.get(4))),
            ]
        })
        .collect();
    sections.push(section(
        &format!("Top {}", if videos { "videos" } else { "search terms" }),
        vec![
            col(item_label, "text"),
            col(if videos { "Views" } else { "Searches" }, "count"),
            col("Users", "count"),
            col("Blocked", "count"),
            col("Last seen", "text"),
        ],
        rows,
    ));

    // Top users.
    let q = client
        .query(
            &format!("SELECT user_key, count(*)::bigint, count(DISTINCT {item})::bigint, count(*) FILTER (WHERE blocked)::bigint FROM {table} WHERE {w} GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT $5"),
            &[&tenant, &from, &to, &user, &top],
        )
        .await?;
    let rows = q
        .iter()
        .map(|r| {
            vec![
                json!(r.get::<_, String>(0)),
                json!(r.get::<_, i64>(1)),
                json!(r.get::<_, i64>(2)),
                json!(r.get::<_, i64>(3)),
            ]
        })
        .collect();
    sections.push(section(
        if videos {
            "Users by views"
        } else {
            "Users by searches"
        },
        vec![
            col("User", "text"),
            col(if videos { "Views" } else { "Searches" }, "count"),
            col(uniq, "count"),
            col("Blocked", "count"),
        ],
        rows,
    ));

    // Engines (searches only) and the most recent activity.
    if !videos {
        let q = client
            .query(&format!("SELECT engine, count(*)::bigint, count(DISTINCT user_key)::bigint FROM {table} WHERE {w} GROUP BY 1 ORDER BY 2 DESC"), &p)
            .await?;
        let rows = q
            .iter()
            .map(|r| {
                vec![
                    json!(r.get::<_, String>(0)),
                    json!(r.get::<_, i64>(1)),
                    json!(r.get::<_, i64>(2)),
                ]
            })
            .collect();
        sections.push(section(
            "Search engines",
            vec![
                col("Engine", "text"),
                col("Searches", "count"),
                col("Users", "count"),
            ],
            rows,
        ));
    }
    let recent_sql = if videos {
        format!("SELECT ts, user_key, video_id, blocked FROM {table} WHERE {w} ORDER BY ts DESC LIMIT $5")
    } else {
        format!("SELECT ts, user_key, engine || ': ' || term, blocked FROM {table} WHERE {w} ORDER BY ts DESC LIMIT $5")
    };
    let q = client
        .query(&recent_sql, &[&tenant, &from, &to, &user, &top.max(25)])
        .await?;
    let rows = q
        .iter()
        .map(|r| {
            let what: String = r.get(2);
            let what = if videos {
                format!("youtu.be/{what}")
            } else {
                what
            };
            vec![
                json!(ts_label(r.get(0))),
                json!(r.get::<_, String>(1)),
                json!(what),
                json!(if r.get::<_, bool>(3) {
                    "blocked"
                } else {
                    "allowed"
                }),
            ]
        })
        .collect();
    sections.push(section(
        "Most recent activity",
        vec![
            col("Time (UTC)", "text"),
            col("User", "text"),
            col(if videos { "Video" } else { "Search" }, "text"),
            col("Result", "text"),
        ],
        rows,
    ));
    if n == 0 {
        sections[0].note = Some("No searches or videos found. URLs are only visible for HTTP or for HTTPS with SSL/TLS inspection enabled on the firewall; extracts are kept 90 days.".into());
    }
    Ok(Summary {
        report_type: report_type.to_string(),
        title: if videos {
            "YouTube Videos".into()
        } else {
            "Internet Searches".into()
        },
        tenant: tenant_name.to_string(),
        from,
        to,
        generated: Utc::now(),
        granularity: gran,
        user,
        kpis,
        sections,
    })
}

/// Build a report and annotate KPIs with the change versus the previous period.
#[allow(clippy::too_many_arguments)]
pub async fn build(
    client: &tokio_postgres::Client,
    tenant: Uuid,
    tenant_name: &str,
    report_type: &str,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    user: Option<String>,
    top: i64,
) -> Result<Summary, ApiError> {
    let mut cur = build_one(
        client,
        tenant,
        tenant_name,
        report_type,
        from,
        to,
        user.clone(),
        top,
    )
    .await?;
    let span = to - from;
    if span > Duration::zero() {
        if let Ok(prev) = build_one(
            client,
            tenant,
            tenant_name,
            report_type,
            from - span,
            from,
            user,
            5,
        )
        .await
        {
            for k in &mut cur.kpis {
                if let Some(p) = prev.kpis.iter().find(|p| p.label == k.label) {
                    k.delta = if k.unit == "percent" {
                        (p.value > 0.0).then(|| ((k.value - p.value) * 10.0).round() / 10.0)
                    } else {
                        (p.value > 0.0)
                            .then(|| (((k.value - p.value) / p.value) * 1000.0).round() / 10.0)
                    };
                }
            }
        }
    }
    Ok(cur)
}

pub fn row_count(s: &Summary) -> i64 {
    s.sections.iter().map(|x| x.rows.len() as i64).sum()
}

// ---------- formatting ----------

pub fn fmt_bytes(v: f64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let (mut x, mut i) = (v, 0);
    while x >= 1024.0 && i < units.len() - 1 {
        x /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{x:.0} B")
    } else {
        format!("{x:.1} {}", units[i])
    }
}

pub fn fmt_minutes(v: f64) -> String {
    let m = v as i64;
    if m >= 60 {
        format!("{}h {:02}m", m / 60, m % 60)
    } else {
        format!("{m}m")
    }
}

fn fmt_count(v: f64) -> String {
    let s = (v as i64).to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 && c != '-' {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn fmt_unit(v: f64, unit: &str) -> String {
    match unit {
        "bytes" => fmt_bytes(v),
        "minutes" => fmt_minutes(v),
        "percent" => format!("{v:.1}%"),
        _ => fmt_count(v),
    }
}

fn fmt_cell(v: &Value, unit: &str) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => fmt_unit(n.as_f64().unwrap_or(0.0), unit),
        other => other.to_string(),
    }
}

// ---------- CSV ----------

fn csv_field(s: &str) -> String {
    // Guard against spreadsheet formula injection from log-derived text.
    let s = if s.starts_with(['=', '+', '-', '@']) && s.parse::<f64>().is_err() {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

pub fn render_csv(s: &Summary) -> Vec<u8> {
    let mut out = String::from("\u{feff}");
    out.push_str(&format!(
        "{}\n{} to {} (UTC), generated {}\n\n",
        csv_field(&s.title),
        s.from.format("%Y-%m-%d %H:%M"),
        s.to.format("%Y-%m-%d %H:%M"),
        s.generated.format("%Y-%m-%d %H:%M")
    ));
    out.push_str("Summary\n");
    for k in &s.kpis {
        out.push_str(&format!("{},{}\n", csv_field(&k.label), k.value));
    }
    for sec in &s.sections {
        if sec.columns.is_empty() {
            continue;
        }
        out.push_str(&format!("\n{}\n", csv_field(&sec.title)));
        out.push_str(
            &sec.columns
                .iter()
                .map(|c| csv_field(&c.name))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
        for r in &sec.rows {
            let cells: Vec<String> = r
                .iter()
                .map(|v| match v {
                    Value::String(x) => csv_field(x),
                    o => o.to_string(),
                })
                .collect();
            out.push_str(&cells.join(","));
            out.push('\n');
        }
    }
    out.into_bytes()
}

// ---------- PDF ----------

type Rgb = (f64, f64, f64);
const INK: Rgb = (0.10, 0.13, 0.20);
const MUTED: Rgb = (0.42, 0.46, 0.53);
const ACCENT: Rgb = (0.05, 0.55, 0.85);
const PALETTE: [Rgb; 4] = [
    (0.05, 0.55, 0.85),
    (0.93, 0.35, 0.40),
    (0.20, 0.70, 0.50),
    (0.95, 0.65, 0.15),
];
const LEFT: f64 = 36.0;
const RIGHT: f64 = 576.0;
const TOP: f64 = 750.0;
const BOTTOM: f64 = 52.0;

struct Pdf {
    pages: Vec<String>,
    y: f64,
}

impl Pdf {
    fn new() -> Self {
        Pdf {
            pages: vec![String::new()],
            y: TOP,
        }
    }
    fn page(&mut self) -> &mut String {
        self.pages.last_mut().expect("page")
    }
    fn need(&mut self, h: f64) -> bool {
        if self.y - h < BOTTOM {
            self.pages.push(String::new());
            self.y = TOP;
            true
        } else {
            false
        }
    }
    fn text(&mut self, font: u8, size: f64, x: f64, y: f64, s: &str, c: Rgb) {
        let t = crate::report::pdf_text(s, 140);
        self.page().push_str(&format!(
            "BT /F{font} {size} Tf {:.2} {:.2} {:.2} rg {x:.1} {y:.1} Td ({t}) Tj ET\n",
            c.0, c.1, c.2
        ));
    }
    fn text_right(&mut self, font: u8, size: f64, xr: f64, y: f64, s: &str, c: Rgb) {
        let w = s.chars().count() as f64 * size * 0.52;
        self.text(font, size, xr - w, y, s, c);
    }
    fn rect(&mut self, x: f64, y: f64, w: f64, h: f64, c: Rgb) {
        self.page().push_str(&format!(
            "{:.2} {:.2} {:.2} rg {x:.1} {y:.1} {:.1} {:.1} re f\n",
            c.0,
            c.1,
            c.2,
            w.max(0.0),
            h.max(0.0)
        ));
    }
}

fn pdf_kpis(p: &mut Pdf, kpis: &[Kpi]) {
    let per_row = 4usize;
    let w = (RIGHT - LEFT - 9.0 * (per_row as f64 - 1.0)) / per_row as f64;
    for chunk in kpis.chunks(per_row) {
        p.need(52.0);
        let top = p.y;
        for (i, k) in chunk.iter().enumerate() {
            let x = LEFT + i as f64 * (w + 9.0);
            p.rect(x, top - 42.0, w, 42.0, (0.95, 0.96, 0.98));
            p.rect(x, top - 42.0, 3.0, 42.0, ACCENT);
            p.text(1, 7.5, x + 10.0, top - 14.0, &k.label.to_uppercase(), MUTED);
            if let Some(d) = k.delta {
                let txt = if k.unit == "percent" {
                    format!("{d:+.1} pts")
                } else {
                    format!("{d:+.1}%")
                };
                p.text_right(
                    1,
                    7.5,
                    x + w - 6.0,
                    top - 34.0,
                    &format!("{txt} vs prev"),
                    MUTED,
                );
            }
            p.text(
                2,
                15.0,
                x + 10.0,
                top - 34.0,
                &fmt_unit(k.value, k.unit),
                INK,
            );
        }
        p.y = top - 52.0;
    }
}

fn pdf_chart(p: &mut Pdf, title: &str, ch: &Chart) {
    let h = 100.0;
    p.need(h + 42.0);
    p.text(2, 11.0, LEFT, p.y - 12.0, title, INK);
    let mut lx = RIGHT;
    for (i, d) in ch.datasets.iter().enumerate().rev() {
        let w = d.name.chars().count() as f64 * 4.4 + 18.0;
        lx -= w;
        p.rect(lx, p.y - 11.0, 7.0, 7.0, PALETTE[i % 4]);
        p.text(1, 8.0, lx + 10.0, p.y - 10.0, &d.name, MUTED);
    }
    let base = p.y - 24.0 - h;
    let n = ch.labels.len().max(1);
    let stacks: Vec<f64> = (0..n)
        .map(|i| {
            ch.datasets
                .iter()
                .map(|d| d.values.get(i).copied().unwrap_or(0.0))
                .sum()
        })
        .collect();
    let max = stacks.iter().cloned().fold(0.0, f64::max).max(1.0);
    p.rect(LEFT + 40.0, base, RIGHT - LEFT - 40.0, 0.5, MUTED);
    p.text(1, 7.0, LEFT, base + h - 6.0, &fmt_unit(max, ch.unit), MUTED);
    p.text(
        1,
        7.0,
        LEFT,
        base + h / 2.0 - 3.0,
        &fmt_unit(max / 2.0, ch.unit),
        MUTED,
    );
    let area = RIGHT - LEFT - 44.0;
    let slot = area / n as f64;
    let bw = (slot * 0.78).clamp(1.0, 26.0);
    for i in 0..n {
        let x = LEFT + 44.0 + i as f64 * slot + (slot - bw) / 2.0;
        let mut y = base + 0.5;
        for (di, d) in ch.datasets.iter().enumerate() {
            let hh = d.values.get(i).copied().unwrap_or(0.0) / max * (h - 8.0);
            if hh > 0.05 {
                p.rect(x, y, bw, hh, PALETTE[di % 4]);
                y += hh;
            }
        }
    }
    if let (Some(first), Some(last)) = (ch.labels.first(), ch.labels.last()) {
        p.text(1, 7.0, LEFT + 44.0, base - 10.0, first, MUTED);
        p.text_right(1, 7.0, RIGHT, base - 10.0, last, MUTED);
    }
    p.y = base - 24.0;
}

fn pdf_table(p: &mut Pdf, sec: &Section) {
    let label_w = 175.0;
    let bar_w = 70.0;
    let nums: Vec<usize> = (1..sec.columns.len()).collect();
    let num_area = RIGHT - LEFT - label_w - bar_w - 6.0;
    let per = if nums.is_empty() {
        0.0
    } else {
        num_area / nums.len() as f64
    };
    let max = sec
        .rows
        .iter()
        .filter_map(|r| r.get(1).and_then(|v| v.as_f64()))
        .fold(0.0, f64::max)
        .max(1e-9);

    let header = |p: &mut Pdf, first: bool| {
        p.need(if first { 44.0 } else { 20.0 });
        if first {
            p.text(2, 11.0, LEFT, p.y - 12.0, &sec.title, INK);
            p.y -= 20.0;
        }
        p.rect(LEFT, p.y - 13.0, RIGHT - LEFT, 14.0, (0.92, 0.94, 0.97));
        p.text(2, 8.0, LEFT + 4.0, p.y - 9.0, &sec.columns[0].name, MUTED);
        for (k, i) in nums.iter().enumerate() {
            let xr = LEFT + label_w + bar_w + 6.0 + per * (k as f64 + 1.0) - 4.0;
            p.text_right(2, 8.0, xr, p.y - 9.0, &sec.columns[*i].name, MUTED);
        }
        p.y -= 16.0;
    };
    header(p, true);
    for (ri, r) in sec.rows.iter().enumerate() {
        if p.need(13.0) {
            header(p, false);
        }
        if ri % 2 == 1 {
            p.rect(LEFT, p.y - 10.0, RIGHT - LEFT, 12.0, (0.975, 0.98, 0.99));
        }
        let label = fmt_cell(&r[0], "text");
        p.text(1, 8.5, LEFT + 4.0, p.y - 7.0, &label, INK);
        if let Some(v) = r.get(1).and_then(|v| v.as_f64()) {
            p.rect(
                LEFT + label_w,
                p.y - 8.0,
                (v / max) * (bar_w - 8.0),
                5.0,
                ACCENT,
            );
        }
        for (k, i) in nums.iter().enumerate() {
            let xr = LEFT + label_w + bar_w + 6.0 + per * (k as f64 + 1.0) - 4.0;
            let s = fmt_cell(&r[*i], sec.columns[*i].unit);
            p.text_right(1, 8.5, xr, p.y - 7.0, &s, INK);
        }
        p.y -= 12.0;
    }
    if sec.rows.is_empty() {
        p.text(1, 8.5, LEFT + 4.0, p.y - 8.0, "No data", MUTED);
        p.y -= 14.0;
    }
    p.y -= 12.0;
}

pub fn render_pdf(s: &Summary) -> Vec<u8> {
    let mut p = Pdf::new();
    p.rect(0.0, 722.0, 612.0, 70.0, (0.08, 0.12, 0.20));
    p.text(2, 20.0, LEFT, 760.0, &s.title, (1.0, 1.0, 1.0));
    p.text(
        1,
        9.0,
        LEFT,
        740.0,
        &format!(
            "{}  |  {} to {} UTC  |  {} resolution",
            s.tenant,
            s.from.format("%Y-%m-%d %H:%M"),
            s.to.format("%Y-%m-%d %H:%M"),
            s.granularity
        ),
        (0.75, 0.82, 0.92),
    );
    p.y = 706.0;
    pdf_kpis(&mut p, &s.kpis);
    for sec in &s.sections {
        if let Some(n) = &sec.note {
            p.need(20.0);
            p.text(1, 9.0, LEFT, p.y - 10.0, n, MUTED);
            p.y -= 20.0;
        }
        if let Some(ch) = &sec.chart {
            pdf_chart(&mut p, &sec.title, ch);
        } else if !sec.columns.is_empty() {
            pdf_table(&mut p, sec);
        }
    }
    let total = p.pages.len();
    for (i, page) in p.pages.iter_mut().enumerate() {
        let footer = format!(
            "Kira summary report  |  generated {}  |  page {} of {}",
            s.generated.format("%Y-%m-%d %H:%M UTC"),
            i + 1,
            total
        );
        let t = crate::report::pdf_text(&footer, 140);
        page.push_str(&format!(
            "BT /F1 7.5 Tf 0.42 0.46 0.53 rg {LEFT} 28 Td ({t}) Tj ET\n"
        ));
    }
    assemble(&p.pages)
}

fn assemble(pages: &[String]) -> Vec<u8> {
    let n = pages.len();
    let mut objs: Vec<Vec<u8>> = vec![b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()];
    let kids: Vec<String> = (0..n).map(|i| format!("{} 0 R", 6 + i * 2)).collect();
    objs.push(format!("<< /Type /Pages /Kids [{}] /Count {n} >>", kids.join(" ")).into_bytes());
    objs.push(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
            .to_vec(),
    );
    objs.push(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
            .to_vec(),
    );
    objs.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>".to_vec());
    for (i, content) in pages.iter().enumerate() {
        objs.push(format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents {} 0 R >>", 7 + i * 2).into_bytes());
        let mut st = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
        st.extend_from_slice(content.as_bytes());
        st.extend_from_slice(b"endstream");
        objs.push(st);
    }
    let mut pdf = b"%PDF-1.4\n".to_vec();
    let mut offs = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offs.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        pdf.extend_from_slice(o);
        pdf.extend_from_slice(b"\nendobj\n");
    }
    let xref = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offs {
        pdf.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objs.len() + 1
        )
        .as_bytes(),
    );
    pdf
}

// ---------- XLSX ----------

fn xml_esc(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect::<String>()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn xlsx_col(mut n: usize) -> String {
    let mut s = String::new();
    loop {
        s.insert(0, (b'A' + (n % 26) as u8) as char);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    s
}

fn xlsx_cell(row: usize, col: usize, v: &Value, style: u8) -> String {
    let r = format!("{}{}", xlsx_col(col), row + 1);
    match v {
        Value::Number(n) => format!("<c r=\"{r}\" s=\"{style}\"><v>{n}</v></c>"),
        Value::Null => String::new(),
        Value::String(x) => format!(
            "<c r=\"{r}\" s=\"{style}\" t=\"inlineStr\"><is><t xml:space=\"preserve\">{}</t></is></c>",
            xml_esc(x)
        ),
        o => format!(
            "<c r=\"{r}\" s=\"{style}\" t=\"inlineStr\"><is><t>{}</t></is></c>",
            xml_esc(&o.to_string())
        ),
    }
}

fn xlsx_sheet(rows: &[(Vec<Value>, u8)], widths: &[f64]) -> String {
    let mut x = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">",
    );
    if !widths.is_empty() {
        x.push_str("<cols>");
        for (i, w) in widths.iter().enumerate() {
            x.push_str(&format!(
                "<col min=\"{0}\" max=\"{0}\" width=\"{1}\" customWidth=\"1\"/>",
                i + 1,
                w
            ));
        }
        x.push_str("</cols>");
    }
    x.push_str("<sheetData>");
    for (ri, (cells, style)) in rows.iter().enumerate() {
        x.push_str(&format!("<row r=\"{}\">", ri + 1));
        for (ci, v) in cells.iter().enumerate() {
            x.push_str(&xlsx_cell(ri, ci, v, *style));
        }
        x.push_str("</row>");
    }
    x.push_str("</sheetData></worksheet>");
    x
}

/// Excel workbook: a Summary sheet (title, period, KPIs) plus one sheet per table section.
/// Numbers stay numeric so they can be sorted and charted; styles: 0 normal, 1 bold header, 2 title.
pub fn render_xlsx(s: &Summary) -> Vec<u8> {
    use std::io::Write;
    let mut sheets: Vec<(String, String)> = Vec::new();
    let mut used: Vec<String> = Vec::new();
    let mut unique = |raw: &str| -> String {
        let mut base: String = raw
            .chars()
            .map(|c| if "[]:*?/\\".contains(c) { ' ' } else { c })
            .collect::<String>()
            .trim()
            .chars()
            .take(28)
            .collect();
        if base.is_empty() {
            base = "Sheet".into();
        }
        let mut name = base.clone();
        let mut n = 2;
        while used.iter().any(|u| u.eq_ignore_ascii_case(&name)) {
            name = format!("{base} {n}");
            n += 1;
        }
        used.push(name.clone());
        name
    };
    let mut rows: Vec<(Vec<Value>, u8)> = vec![
        (vec![Value::String(s.title.clone())], 2),
        (
            vec![Value::String(format!(
                "{} to {} (UTC), generated {}",
                s.from.format("%Y-%m-%d %H:%M"),
                s.to.format("%Y-%m-%d %H:%M"),
                s.generated.format("%Y-%m-%d %H:%M")
            ))],
            0,
        ),
        (vec![], 0),
        (
            vec![
                Value::String("Metric".into()),
                Value::String("Value".into()),
                Value::String("Unit".into()),
                Value::String("Change vs previous".into()),
            ],
            1,
        ),
    ];
    for k in &s.kpis {
        rows.push((
            vec![
                Value::String(k.label.clone()),
                serde_json::Number::from_f64(k.value)
                    .map(Value::Number)
                    .unwrap_or(Value::Null),
                Value::String(k.unit.to_string()),
                k.delta
                    .and_then(serde_json::Number::from_f64)
                    .map(Value::Number)
                    .unwrap_or(Value::Null),
            ],
            0,
        ));
    }
    sheets.push((
        unique("Summary"),
        xlsx_sheet(&rows, &[34.0, 18.0, 12.0, 20.0]),
    ));
    for sec in &s.sections {
        if sec.columns.is_empty() {
            continue;
        }
        let mut r: Vec<(Vec<Value>, u8)> = vec![(
            sec.columns
                .iter()
                .map(|c| {
                    Value::String(match c.unit {
                        "bytes" | "minutes" | "percent" => format!("{} ({})", c.name, c.unit),
                        _ => c.name.clone(),
                    })
                })
                .collect(),
            1,
        )];
        for row in &sec.rows {
            r.push((row.clone(), 0));
        }
        let widths: Vec<f64> = (0..sec.columns.len())
            .map(|i| {
                let longest = sec
                    .rows
                    .iter()
                    .take(200)
                    .filter_map(|row| row.get(i))
                    .map(|v| v.as_str().map(|x| x.chars().count()).unwrap_or(12))
                    .max()
                    .unwrap_or(10)
                    .max(sec.columns[i].name.chars().count());
                (longest as f64 + 2.0).clamp(10.0, 60.0)
            })
            .collect();
        sheets.push((unique(&sec.title), xlsx_sheet(&r, &widths)));
    }

    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        let mut put = |name: &str, body: &str| {
            let _ = z.start_file(name, opts);
            let _ = z.write_all(body.as_bytes());
        };
        let mut ct = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/><Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>");
        let mut wb = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets>");
        let mut rels = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">");
        for (i, (name, _)) in sheets.iter().enumerate() {
            let n = i + 1;
            ct.push_str(&format!("<Override PartName=\"/xl/worksheets/sheet{n}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>"));
            wb.push_str(&format!(
                "<sheet name=\"{}\" sheetId=\"{n}\" r:id=\"rId{n}\"/>",
                xml_esc(name)
            ));
            rels.push_str(&format!("<Relationship Id=\"rId{n}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet{n}.xml\"/>"));
        }
        let sid = sheets.len() + 1;
        rels.push_str(&format!("<Relationship Id=\"rId{sid}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/></Relationships>"));
        ct.push_str("</Types>");
        wb.push_str("</sheets></workbook>");
        put("[Content_Types].xml", &ct);
        put("_rels/.rels", "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>");
        put("xl/workbook.xml", &wb);
        put("xl/_rels/workbook.xml.rels", &rels);
        put("xl/styles.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><fonts count=\"3\"><font><sz val=\"11\"/><name val=\"Calibri\"/></font><font><b/><sz val=\"11\"/><name val=\"Calibri\"/></font><font><b/><sz val=\"16\"/><name val=\"Calibri\"/></font></fonts><fills count=\"3\"><fill><patternFill patternType=\"none\"/></fill><fill><patternFill patternType=\"gray125\"/></fill><fill><patternFill patternType=\"solid\"><fgColor rgb=\"FFDCE6F2\"/></patternFill></fill></fills><borders count=\"1\"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs><cellXfs count=\"3\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/><xf numFmtId=\"0\" fontId=\"1\" fillId=\"2\" borderId=\"0\" xfId=\"0\" applyFont=\"1\" applyFill=\"1\"/><xf numFmtId=\"0\" fontId=\"2\" fillId=\"0\" borderId=\"0\" xfId=\"0\" applyFont=\"1\"/></cellXfs><cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles></styleSheet>");
        for (i, (_, xml)) in sheets.iter().enumerate() {
            put(&format!("xl/worksheets/sheet{}.xml", i + 1), xml);
        }
        let _ = z.finish();
    }
    buf.into_inner()
}

pub fn render(format: &str, s: &Summary) -> Result<(Vec<u8>, &'static str, &'static str), String> {
    match format {
        "csv" => Ok((render_csv(s), "text/csv; charset=utf-8", "csv")),
        "pdf" => Ok((render_pdf(s), "application/pdf", "pdf")),
        "xlsx" => Ok((
            render_xlsx(s),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "xlsx",
        )),
        other => Err(format!(
            "unsupported format {other:?} (use csv, xlsx or pdf)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Summary {
        let rows: Vec<Vec<Value>> = (0..120)
            .map(|i| {
                vec![
                    json!(format!("site{i}.example (x)")),
                    json!(1000 - i),
                    json!(i),
                ]
            })
            .collect();
        let mut chart = section("Trend", vec![], vec![]);
        chart.chart = Some(Chart {
            unit: "count",
            labels: (0..48).map(|i| format!("{i}")).collect(),
            datasets: vec![Dataset {
                name: "A".into(),
                values: (0..48).map(|i| i as f64).collect(),
            }],
        });
        Summary {
            report_type: "executive".into(),
            title: "Test".into(),
            tenant: "t".into(),
            from: Utc::now() - Duration::days(1),
            to: Utc::now(),
            generated: Utc::now(),
            granularity: "hour",
            user: None,
            kpis: vec![
                kpi("Events", 12345, "count"),
                kpi("Traffic", 5_000_000_000, "bytes"),
            ],
            sections: vec![
                chart,
                section(
                    "Top",
                    vec![
                        col("Site", "text"),
                        col("Requests", "count"),
                        col("Blocked", "count"),
                    ],
                    rows,
                ),
            ],
        }
    }

    #[test]
    fn pdf_is_compact_and_valid() {
        let pdf = render_pdf(&sample());
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        let pages = String::from_utf8_lossy(&pdf)
            .matches("/Type /Page ")
            .count();
        assert!((2..=5).contains(&pages), "pages {pages}");
    }

    #[test]
    fn csv_has_sections_and_neutralises_formulas() {
        let mut s = sample();
        s.sections[1].rows[0][0] = json!("=HYPERLINK(1)");
        let csv = String::from_utf8(render_csv(&s)).unwrap();
        assert!(csv.contains("Top\nSite,Requests,Blocked"));
        assert!(csv.contains("'=HYPERLINK(1)"));
    }

    #[test]
    fn formatting() {
        assert_eq!(fmt_bytes(1536.0), "1.5 KB");
        assert_eq!(fmt_minutes(125.0), "2h 05m");
        assert_eq!(fmt_count(1234567.0), "1,234,567");
        assert_eq!(pct(1, 4), 25.0);
    }
}

// ---------- HTTP ----------

use crate::api::{acquire_query_permit, resolve_tenant, AppState};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, serde::Deserialize)]
pub struct SummaryQuery {
    pub tenant: Option<String>,
    #[serde(rename = "type")]
    pub report_type: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub user: Option<String>,
    pub top: Option<i64>,
    pub format: Option<String>,
}

/// `GET /api/v1/reports/summary?type=&from=&to=&user=&top=&format=json|csv|pdf`
pub async fn summary_report(
    State(state): State<AppState>,
    axum::Extension(cu): axum::Extension<crate::auth::CurrentUser>,
    Query(q): Query<SummaryQuery>,
) -> Result<Response, ApiError> {
    let _permit = acquire_query_permit(
        &state.query_semaphore,
        "report capacity is busy; retry shortly",
    )?;
    let tenant = resolve_tenant(&state, q.tenant.as_deref()).await?;
    let now = Utc::now();
    let range = crate::query::RangeQuery {
        tenant: Some(tenant.slug.clone()),
        from: Some(q.from.clone().unwrap_or_else(|| "24h".into())),
        to: Some(q.to.clone().unwrap_or_else(|| "now".into())),
        interval: None,
    }
    .resolve(now)
    .map_err(|e| ApiError::bad_request(format!("invalid time range: {e}")))?;
    let report_type = q.report_type.as_deref().unwrap_or("executive");
    // Make sure the newest hours are rolled up (throttled; idempotent).
    static LAST_ROLL: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    let last = LAST_ROLL.load(std::sync::atomic::Ordering::Relaxed);
    if now.timestamp() - last > 15 {
        LAST_ROLL.store(now.timestamp(), std::sync::atomic::Ordering::Relaxed);
        if let Err(err) = state.store.roll_hourly(2).await {
            tracing::warn!(%err, "on-demand hourly rollup failed");
        }
    }
    let client = state.store.pool().get().await?;
    let summary = build(
        &client,
        tenant.id,
        &tenant.name,
        report_type,
        range.from,
        range.to,
        q.user.clone(),
        q.top.unwrap_or(15),
    )
    .await?;
    let mut summary = summary;
    let masked = crate::settings::masks_for(&state, &cu).await;
    if masked {
        crate::settings::mask_summary(&mut summary);
    }
    match q.format.as_deref().unwrap_or("json") {
        "json" => Ok(axum::Json(&summary).into_response()),
        f => {
            let (content, ct, ext) = render(f, &summary).map_err(ApiError::bad_request)?;
            let name = format!("kira-{}-{}.{}", report_type, now.format("%Y%m%d-%H%M"), ext);
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", ct)
                .header(
                    "Content-Disposition",
                    format!("attachment; filename=\"{name}\""),
                )
                .body(axum::body::Body::from(content))
                .map_err(|e| ApiError::internal(anyhow::anyhow!("failed to build response: {e}")))
        }
    }
}
