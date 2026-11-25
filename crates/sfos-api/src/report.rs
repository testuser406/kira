//! Report generation shared by scheduled, custom and on-demand reports: one query builder that
//! applies the report filters, and CSV / multi-page PDF renderers that work for any column set.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::Value;
use tokio_postgres::types::{ToSql, Type};
use uuid::Uuid;

pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

/// SQL for each report subtype. Every query takes `$1 tenant`, `$2 from`, `$3 to`; filter
/// conditions are appended after `ts < $3` with parameters starting at `$4`.
fn subtype_sql(subtype: &str) -> (&'static str, bool) {
    let sql: &'static str = match subtype {
        "user" => "SELECT COALESCE(NULLIF(user_name, ''), host(src_ip))::text AS user_key,
                            count(*)::bigint AS events,
                            count(*) FILTER (WHERE action = 'blocked')::bigint AS blocked,
                            COALESCE(sum(sent_bytes + recv_bytes), 0)::bigint AS bytes,
                            COALESCE(sum(sent_bytes), 0)::bigint AS bytes_up,
                            COALESCE(sum(recv_bytes), 0)::bigint AS bytes_down
                     FROM events
                     WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
                     GROUP BY 1 ORDER BY events DESC LIMIT 50",
        "department" => "SELECT COALESCE(udm.department, 'Unknown')::text AS department_key,
                            count(*)::bigint AS events,
                            count(*) FILTER (WHERE action = 'blocked')::bigint AS blocked,
                            COALESCE(sum(sent_bytes + recv_bytes), 0)::bigint AS bytes,
                            COALESCE(sum(sent_bytes), 0)::bigint AS bytes_up,
                            COALESCE(sum(recv_bytes), 0)::bigint AS bytes_down
                     FROM events e
                     LEFT JOIN user_department_map udm ON udm.tenant_id = e.tenant_id AND udm.user_identifier = COALESCE(NULLIF(e.user_name, ''), host(e.src_ip))
                     WHERE e.tenant_id = $1 AND e.ts >= $2 AND e.ts < $3
                     GROUP BY 1 ORDER BY events DESC LIMIT 50",
        "safeguarding" => "SELECT ts, COALESCE(NULLIF(user_name, ''), host(src_ip)) AS user,
                    domain, url, category, category_type,
                    COALESCE(threat_name, reason, message) AS detail,
                    action
             FROM events
             WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
               AND (category ILIKE '%social%' OR category ILIKE '%video%' OR category ILIKE '%game%' OR category ILIKE '%chat%' OR category ILIKE '%search%' OR category ILIKE '%adult%' OR category ILIKE '%violence%' OR category ILIKE '%gambling%' OR category ILIKE '%drug%' OR category ILIKE '%weapon%' OR category ILIKE '%hate%' OR category ILIKE '%proxy%' OR category ILIKE '%vpn%' OR category ILIKE '%anonymiz%')
             ORDER BY ts DESC LIMIT 200",
        "websites_allowed_blocked" => "SELECT domain, action, count(*)::bigint AS events,
                    COALESCE(sum(sent_bytes + recv_bytes), 0)::bigint AS bytes
             FROM events
             WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
               AND domain IS NOT NULL AND domain <> ''
             GROUP BY 1, 2 ORDER BY events DESC LIMIT 100",
        "activity_timeline" => "SELECT date_trunc('minute', ts) AS minute,
                    COALESCE(NULLIF(user_name, ''), host(src_ip)) AS user,
                    log_type, action, domain, url, category,
                    COALESCE(sent_bytes, 0) + COALESCE(recv_bytes, 0) AS bytes
             FROM events
             WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
             ORDER BY ts ASC LIMIT 5000",
        "internet_searches" => "SELECT ts, COALESCE(NULLIF(user_name, ''), host(src_ip)) AS user,
                    url, domain, category, COALESCE(category_type, attrs->>'http_category_type', attrs->>'category_type') AS category_type
             FROM events
             WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
               AND category ILIKE '%search%'
             ORDER BY ts DESC LIMIT 500",
        "youtube_videos" => "SELECT ts, COALESCE(NULLIF(user_name, ''), host(src_ip)) AS user,
                    url, domain, application, sent_bytes, recv_bytes
             FROM events
             WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
               AND (domain ILIKE '%youtube.com' OR domain ILIKE '%youtu.be' OR application ILIKE '%YouTube%')
             ORDER BY ts DESC LIMIT 500",
        "online_productivity" => "SELECT COALESCE(NULLIF(user_name, ''), host(src_ip)) AS user,
                    CASE WHEN category ILIKE '%productiv%' OR category ILIKE '%business%' OR category ILIKE '%work%' OR category ILIKE '%office%' OR category ILIKE '%education%' OR category ILIKE '%reference%' THEN 'productive'
                         WHEN category ILIKE '%social%' OR category ILIKE '%game%' OR category ILIKE '%video%' OR category ILIKE '%chat%' OR category ILIKE '%entertain%' OR category ILIKE '%stream%' THEN 'non-productive'
                         ELSE 'neutral' END AS productivity_class,
                    count(*)::bigint AS events,
                    COALESCE(sum(sent_bytes + recv_bytes), 0)::bigint AS bytes
             FROM events
             WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
             GROUP BY 1, 2 ORDER BY 1, events DESC",
        "firewall_policy" => "SELECT COALESCE(NULLIF(fw_rule_name, ''), 'unknown') AS policy,
                    count(*)::bigint AS events,
                    count(*) FILTER (WHERE action = 'blocked')::bigint AS blocked,
                    count(*) FILTER (WHERE action = 'allowed')::bigint AS allowed,
                    COALESCE(sum(sent_bytes + recv_bytes), 0)::bigint AS bytes
             FROM events
             WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
             GROUP BY 1 ORDER BY events DESC LIMIT 50",
        "security_threat" => "SELECT COALESCE(NULLIF(threat_name, ''), NULLIF(reason, ''), log_type) AS threat,
                    count(*)::bigint AS events,
                    count(*) FILTER (WHERE action = 'blocked')::bigint AS blocked,
                    COALESCE(sum(sent_bytes + recv_bytes), 0)::bigint AS bytes
             FROM events
             WHERE tenant_id = $1 AND ts >= $2 AND ts < $3 AND category_group = 'threat'
             GROUP BY 1 ORDER BY events DESC LIMIT 50",
        "network_bandwidth" => "SELECT COALESCE(NULLIF(application, ''), COALESCE(NULLIF(category, ''), 'direct'))::text AS bw_key,
                    COALESCE(sum(sent_bytes), 0)::bigint AS bytes_up,
                    COALESCE(sum(recv_bytes), 0)::bigint AS bytes_down,
                    COALESCE(sum(sent_bytes + recv_bytes), 0)::bigint AS bytes_total,
                    count(*)::bigint AS events
             FROM events
             WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
             GROUP BY 1 ORDER BY bytes_total DESC LIMIT 50",
        "vpn_connections" => "SELECT COALESCE(NULLIF(vpn_user, ''), 'unknown')::text AS vpn_user,
                    COALESCE(NULLIF(vpn_tunnel, ''), 'unknown')::text AS vpn_tunnel,
                    count(*)::bigint AS connections,
                    COALESCE(sum(sent_bytes), 0)::bigint AS bytes_up,
                    COALESCE(sum(recv_bytes), 0)::bigint AS bytes_down,
                    max(ts) AS last_seen
             FROM events
             WHERE tenant_id = $1 AND ts >= $2 AND ts < $3 AND category_group = 'vpn'
             GROUP BY 1, 2 ORDER BY last_seen DESC LIMIT 50",
        "subnet" => "SELECT COALESCE(host(src_ip), 'unknown') AS src_subnet,
                    COALESCE(host(dst_ip), 'unknown') AS dst_subnet,
                    count(*)::bigint AS events,
                    COALESCE(sum(sent_bytes), 0)::bigint AS bytes_up,
                    COALESCE(sum(recv_bytes), 0)::bigint AS bytes_down,
                    COALESCE(sum(sent_bytes + recv_bytes), 0)::bigint AS bytes_total
             FROM events
             WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
             GROUP BY 1, 2 ORDER BY bytes_total DESC LIMIT 100",
        _ => return (GENERIC_SQL, true),
    };
    (sql, false)
}

const GENERIC_SQL: &str = "SELECT ts, log_type, log_component, category_group, action, display_user,
                    destination, application, category, category_type,
                    url, src_ip, dst_ip, fw_rule_name,
                    sent_bytes, recv_bytes, threat_name, message, device_name
             FROM (
                 SELECT tenant_id, id, ts, category_group, action, log_type, log_component, device_name,
                        host(src_ip) AS src_ip, host(dst_ip) AS dst_ip,
                        domain, COALESCE(domain, host(dst_ip)) AS destination,
                        COALESCE(NULLIF(user_name, ''), host(src_ip)) AS display_user,
                        url, application, category,
                        COALESCE(category_type, attrs->>'http_category_type', attrs->>'category_type') AS category_type,
                        fw_rule_name, sent_bytes, recv_bytes, threat_name, message,
                        protocol, src_port, dst_port, src_country, dst_country, src_zone, dst_zone,
                        user_group, policy_type, fw_rule_id, vpn_user, vpn_tunnel
                 FROM events
             ) e
             WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
             ORDER BY ts ASC
             LIMIT 5000";

enum Param {
    Text(String),
    I64(i64),
    I32(i32),
}

fn as_text(filters: &Value, key: &str) -> Option<String> {
    filters.get(key).and_then(|v| match v {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn as_i64(filters: &Value, key: &str) -> Option<i64> {
    filters.get(key).and_then(|v| match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    })
}

/// Build ` AND ...` conditions for the filters the report UI offers. `sub` is true for the
/// generic query, whose outer SELECT sees already-formatted text columns (`display_user`,
/// textual `src_ip`); other report queries read the raw `events` columns.
fn filter_sql(filters: &Value, sub: bool) -> (String, Vec<Param>) {
    let user_expr = if sub {
        "display_user"
    } else {
        "COALESCE(NULLIF(user_name, ''), host(src_ip))"
    };
    let src_ip = if sub { "src_ip" } else { "host(src_ip)" };
    let dst_ip = if sub { "dst_ip" } else { "host(dst_ip)" };
    let mut sql = String::new();
    let mut params: Vec<Param> = Vec::new();
    let mut next = 4usize;
    let mut add =
        |sql: &mut String, params: &mut Vec<Param>, cond: &dyn Fn(usize) -> String, p: Param| {
            sql.push_str(" AND ");
            sql.push_str(&cond(next));
            params.push(p);
            next += 1;
        };

    if let Some(q) = as_text(filters, "q") {
        add(
            &mut sql,
            &mut params,
            &|n| {
                format!(
            "({user_expr} ILIKE '%' || ${n} || '%' OR domain ILIKE '%' || ${n} || '%' OR url ILIKE '%' || ${n} || '%' \
             OR message ILIKE '%' || ${n} || '%' OR threat_name ILIKE '%' || ${n} || '%' \
             OR category ILIKE '%' || ${n} || '%' OR category_type ILIKE '%' || ${n} || '%' \
             OR fw_rule_name ILIKE '%' || ${n} || '%' OR {src_ip} = ${n})")
            },
            Param::Text(q),
        );
    }
    // exact-match text columns
    for (key, col) in [
        ("action", "action"),
        ("group", "category_group"),
        ("protocol", "protocol"),
        ("src_country", "src_country"),
        ("dst_country", "dst_country"),
        ("src_zone", "src_zone"),
        ("dst_zone", "dst_zone"),
        ("policy_type", "policy_type"),
    ] {
        if let Some(v) = as_text(filters, key) {
            add(
                &mut sql,
                &mut params,
                &|n| format!("{col} = ${n}"),
                Param::Text(v),
            );
        }
    }
    // case-insensitive "contains" on one column
    for (key, col) in [
        ("category_type", "category_type"),
        ("application", "application"),
        ("fw_rule_name", "fw_rule_name"),
        ("threat", "threat_name"),
        ("threat_name", "threat_name"),
        ("message_contains", "message"),
        ("url_contains", "url"),
        ("domain_contains", "domain"),
        ("user_group", "user_group"),
        ("vpn_user", "vpn_user"),
        ("vpn_tunnel", "vpn_tunnel"),
        ("device", "device_name"),
    ] {
        if let Some(v) = as_text(filters, key) {
            add(
                &mut sql,
                &mut params,
                &|n| format!("{col} ILIKE '%' || ${n} || '%'"),
                Param::Text(v),
            );
        }
    }
    if let Some(v) = as_text(filters, "user") {
        add(
            &mut sql,
            &mut params,
            &|n| format!("{user_expr} ILIKE '%' || ${n} || '%'"),
            Param::Text(v),
        );
    }
    if let Some(v) = as_text(filters, "category") {
        add(
            &mut sql,
            &mut params,
            &|n| {
                format!(
                    "(category ILIKE '%' || ${n} || '%' OR category_type ILIKE '%' || ${n} || '%')"
                )
            },
            Param::Text(v),
        );
    }
    if let Some(v) = as_text(filters, "src_ip") {
        add(
            &mut sql,
            &mut params,
            &|n| format!("{src_ip} = ${n}"),
            Param::Text(v),
        );
    }
    if let Some(v) = as_text(filters, "dst_ip") {
        add(
            &mut sql,
            &mut params,
            &|n| format!("{dst_ip} = ${n}"),
            Param::Text(v),
        );
    }
    for (key, col) in [("src_port", "src_port"), ("dst_port", "dst_port")] {
        if let Some(v) = as_i64(filters, key).and_then(|v| i32::try_from(v).ok()) {
            add(
                &mut sql,
                &mut params,
                &|n| format!("{col} = ${n}"),
                Param::I32(v),
            );
        }
    }
    if let Some(v) = as_i64(filters, "fw_rule_id") {
        add(
            &mut sql,
            &mut params,
            &|n| format!("fw_rule_id = ${n}"),
            Param::I64(v),
        );
    }
    for (key, col, op) in [
        ("sent_bytes_min", "sent_bytes", ">="),
        ("sent_bytes_max", "sent_bytes", "<="),
        ("recv_bytes_min", "recv_bytes", ">="),
        ("recv_bytes_max", "recv_bytes", "<="),
    ] {
        if let Some(v) = as_i64(filters, key) {
            add(
                &mut sql,
                &mut params,
                &|n| format!("{col} {op} ${n}"),
                Param::I64(v),
            );
        }
    }
    (sql, params)
}

fn cell(row: &tokio_postgres::Row, i: usize) -> String {
    let ty = row.columns()[i].type_();
    match *ty {
        Type::TEXT | Type::VARCHAR | Type::NAME | Type::BPCHAR => {
            row.get::<_, Option<String>>(i).unwrap_or_default()
        }
        Type::INT2 => row
            .get::<_, Option<i16>>(i)
            .map(|v| v.to_string())
            .unwrap_or_default(),
        Type::INT4 => row
            .get::<_, Option<i32>>(i)
            .map(|v| v.to_string())
            .unwrap_or_default(),
        Type::INT8 => row
            .get::<_, Option<i64>>(i)
            .map(|v| v.to_string())
            .unwrap_or_default(),
        Type::FLOAT4 => row
            .get::<_, Option<f32>>(i)
            .map(|v| v.to_string())
            .unwrap_or_default(),
        Type::FLOAT8 => row
            .get::<_, Option<f64>>(i)
            .map(|v| v.to_string())
            .unwrap_or_default(),
        Type::BOOL => row
            .get::<_, Option<bool>>(i)
            .map(|v| v.to_string())
            .unwrap_or_default(),
        Type::TIMESTAMPTZ => row
            .get::<_, Option<DateTime<Utc>>>(i)
            .map(|v| v.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_default(),
        _ => row
            .try_get::<_, Option<String>>(i)
            .ok()
            .flatten()
            .unwrap_or_default(),
    }
}

/// Run a report query with the filters applied.
pub async fn run(
    client: &tokio_postgres::Client,
    tenant: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    subtype: &str,
    filters: &Value,
) -> Result<Table> {
    let (base, sub) = subtype_sql(subtype);
    let (clause, extra) = filter_sql(filters, sub);
    let sql = base.replacen("ts < $3", &format!("ts < $3{clause}"), 1);
    let mut refs: Vec<&(dyn ToSql + Sync)> = vec![&tenant, &from, &to];
    for p in &extra {
        refs.push(match p {
            Param::Text(v) => v,
            Param::I64(v) => v,
            Param::I32(v) => v,
        });
    }
    let rows = client.query(&sql, &refs).await?;
    let columns: Vec<String> = match rows.first() {
        Some(r) => r.columns().iter().map(|c| c.name().to_string()).collect(),
        None => {
            // No rows: still report the column names.
            let stmt = client.prepare(&sql).await?;
            stmt.columns()
                .iter()
                .map(|c| c.name().to_string())
                .collect()
        }
    };
    let rows = rows
        .iter()
        .map(|r| (0..columns.len()).map(|i| cell(r, i)).collect())
        .collect();
    Ok(Table { columns, rows })
}

// ---------- rendering ----------

/// Neutralise spreadsheet formula injection (`=`, `+`, `@`, and `-` that is not a number).
fn csv_cell(value: &str) -> String {
    let mut v = value.to_string();
    let dangerous = match v.chars().next() {
        Some('=') | Some('+') | Some('@') | Some('\t') | Some('\r') => true,
        Some('-') => v.parse::<f64>().is_err(),
        _ => false,
    };
    if dangerous {
        v.insert(0, '\'');
    }
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v
    }
}

pub fn render_csv(table: &Table) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(
        &table
            .columns
            .iter()
            .map(|c| csv_cell(c))
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push('\n');
    for row in &table.rows {
        out.push_str(
            &row.iter()
                .map(|c| csv_cell(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
    }
    out.into_bytes()
}

const PAGE_LINES: usize = 70;
const MAX_PAGES: usize = 40;
const LINE_CHARS: usize = 112;
const PDF_PREFERRED: [&str; 9] = [
    "ts",
    "action",
    "display_user",
    "destination",
    "category",
    "application",
    "fw_rule_name",
    "threat_name",
    "events",
];

pub(crate) fn pdf_text(s: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in s.chars().take(max) {
        out.push(match ch {
            '\\' | '(' | ')' => ' ',
            c if (' '..='~').contains(&c) => c,
            _ => '?',
        });
    }
    out
}

/// Build a PDF from pages of fixed-width text lines (Courier 7pt).
fn build_pdf(pages: &[Vec<String>]) -> Vec<u8> {
    let n = pages.len();
    // object numbers: 1 catalog, 2 pages, 3 font, then (page, content) pairs
    let mut objects: Vec<Vec<u8>> = Vec::new();
    objects.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
    let kids: Vec<String> = (0..n).map(|i| format!("{} 0 R", 4 + i * 2)).collect();
    objects.push(format!("<< /Type /Pages /Kids [{}] /Count {n} >>", kids.join(" ")).into_bytes());
    objects.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>".to_vec());
    for (i, lines) in pages.iter().enumerate() {
        let mut content = String::from("BT /F1 7 Tf 9 TL 36 756 Td\n");
        for line in lines {
            content.push_str(&format!("({}) Tj T*\n", line));
        }
        content.push_str("ET\n");
        objects.push(
            format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {} 0 R >>", 5 + i * 2)
                .into_bytes(),
        );
        let mut stream = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
        stream.extend_from_slice(content.as_bytes());
        stream.extend_from_slice(b"endstream");
        objects.push(stream);
    }
    let mut pdf = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::new();
    for (i, obj) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        pdf.extend_from_slice(obj);
        pdf.extend_from_slice(b"\nendobj\n");
    }
    let xref = pdf.len();
    pdf.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for off in offsets {
        pdf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    pdf
}

pub fn render_pdf(title: &str, tenant: &str, generated: DateTime<Utc>, table: &Table) -> Vec<u8> {
    // Choose the columns that fit on a page.
    let mut idx: Vec<usize> = PDF_PREFERRED
        .iter()
        .filter_map(|p| table.columns.iter().position(|c| c == p))
        .collect();
    if table.columns.len() <= 8 || idx.len() < 3 {
        idx = (0..table.columns.len()).collect();
    }
    idx.truncate(9);
    let n = idx.len().max(1);
    let mut widths: Vec<usize> = idx
        .iter()
        .map(|&i| {
            table
                .rows
                .iter()
                .take(200)
                .map(|r| r[i].chars().count())
                .chain([table.columns[i].chars().count()])
                .max()
                .unwrap_or(4)
                .clamp(4, 40)
        })
        .collect();
    let avail = LINE_CHARS.saturating_sub(n - 1);
    while widths.iter().sum::<usize>() > avail {
        let (j, _) = widths.iter().enumerate().max_by_key(|(_, w)| **w).unwrap();
        if widths[j] <= 5 {
            break;
        }
        widths[j] -= 1;
    }
    let fmt_row = |cells: Vec<&str>| -> String {
        cells
            .iter()
            .zip(&widths)
            .map(|(c, w)| format!("{:<w$}", pdf_text(c, *w), w = *w))
            .collect::<Vec<_>>()
            .join(" ")
            .trim_end()
            .to_string()
    };
    let header = fmt_row(idx.iter().map(|&i| table.columns[i].as_str()).collect());
    let rule = "-".repeat(header.len().min(LINE_CHARS));
    let shown = table
        .rows
        .len()
        .min((MAX_PAGES * (PAGE_LINES - 8)).saturating_sub(10));
    let intro = vec![
        pdf_text(&format!("Kira report: {title}"), LINE_CHARS),
        pdf_text(
            &format!(
                "Site: {tenant}    Generated: {}",
                generated.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            ),
            LINE_CHARS,
        ),
        pdf_text(
            &if shown < table.rows.len() {
                format!(
                    "Rows: {} (first {shown} shown; download the CSV for all rows)",
                    table.rows.len()
                )
            } else {
                format!("Rows: {}", table.rows.len())
            },
            LINE_CHARS,
        ),
        String::new(),
    ];
    let mut pages: Vec<Vec<String>> = Vec::new();
    let mut cur: Vec<String> = intro;
    cur.push(header.clone());
    cur.push(rule.clone());
    for row in table.rows.iter().take(shown) {
        if cur.len() >= PAGE_LINES {
            pages.push(std::mem::take(&mut cur));
            cur.push(header.clone());
            cur.push(rule.clone());
        }
        cur.push(fmt_row(idx.iter().map(|&i| row[i].as_str()).collect()));
    }
    if table.rows.is_empty() {
        cur.push("(no rows match this report)".into());
    }
    pages.push(cur);
    build_pdf(&pages)
}

/// Render in the requested format: `(bytes, content type, file extension)`.
pub fn render(
    format: &str,
    title: &str,
    tenant: &str,
    now: DateTime<Utc>,
    table: &Table,
) -> Result<(Vec<u8>, &'static str, &'static str), String> {
    match format {
        "csv" => Ok((render_csv(table), "text/csv", "csv")),
        "pdf" => Ok((
            render_pdf(title, tenant, now, table),
            "application/pdf",
            "pdf",
        )),
        other => Err(format!("unsupported format {other:?} (use csv or pdf)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn table(rows: usize, cols: usize) -> Table {
        Table {
            columns: (0..cols).map(|c| format!("col{c}")).collect(),
            rows: (0..rows)
                .map(|r| (0..cols).map(|c| format!("r{r}c{c} (x)\\y")).collect())
                .collect(),
        }
    }

    #[test]
    fn csv_quotes_and_neutralises_formulas() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_cell("-5"), "-5");
        assert_eq!(csv_cell("-cmd"), "'-cmd");
        assert_eq!(csv_cell("@SUM(A1)"), "'@SUM(A1)");
    }

    #[test]
    fn csv_has_header_and_one_line_per_row() {
        let csv = String::from_utf8(render_csv(&table(3, 2))).unwrap();
        assert_eq!(csv.lines().count(), 4);
        assert!(csv.starts_with("col0,col1\n"));
    }

    fn assert_valid_pdf(pdf: &[u8], pages: usize) {
        let text = String::from_utf8_lossy(pdf);
        assert!(text.starts_with("%PDF-1.4"));
        assert!(text.trim_end().ends_with("%%EOF"));
        let startxref: usize = text
            .rsplit("startxref\n")
            .next()
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(text[startxref..].starts_with("xref\n"));
        let entries: Vec<&str> = text[startxref..]
            .lines()
            .skip(3)
            .take_while(|l| l.ends_with(" n "))
            .collect();
        assert_eq!(entries.len(), 3 + pages * 2);
        for (i, e) in entries.iter().enumerate() {
            let off: usize = e[..10].parse().unwrap();
            assert!(
                text[off..].starts_with(&format!("{} 0 obj", i + 1)),
                "object {} offset wrong",
                i + 1
            );
        }
        assert!(text.contains(&format!("/Count {pages}")));
    }

    #[test]
    fn pdf_is_structurally_valid_for_empty_small_and_multipage() {
        let now = Utc::now();
        assert_valid_pdf(&render_pdf("t", "site", now, &table(0, 3)), 1);
        assert_valid_pdf(&render_pdf("t", "site", now, &table(5, 3)), 1);
        let big = render_pdf("t", "site", now, &table(500, 12));
        let pages = String::from_utf8_lossy(&big)
            .matches("/Type /Page ")
            .count();
        assert!(pages > 3, "500 rows should span several pages, got {pages}");
        assert_valid_pdf(&big, pages);
    }

    #[test]
    fn pdf_text_is_safe_for_pdf_syntax_and_latin1() {
        assert_eq!(pdf_text("a(b)c\\d", 20), "a b c d");
        assert_eq!(pdf_text("caf\u{e9}", 20), "caf?");
        assert_eq!(pdf_text("abcdef", 3), "abc");
    }

    #[test]
    fn filter_sql_numbers_parameters_in_order() {
        let (sql, params) = filter_sql(
            &json!({"action": "blocked", "user": "ali", "dst_port": "443", "sent_bytes_min": 10}),
            false,
        );
        assert_eq!(params.len(), 4);
        assert!(
            sql.contains("action = $4")
                && sql.contains("ILIKE '%' || $5 || '%'")
                && sql.contains("dst_port = $6")
                && sql.contains("sent_bytes >= $7")
        );
        let (none, p) = filter_sql(
            &json!({"from": "24h", "report_subtype": "user", "limit": 5}),
            true,
        );
        assert!(none.is_empty() && p.is_empty());
        let (sub, _) = filter_sql(&json!({"user": "x"}), true);
        assert!(sub.contains("display_user"));
    }
}
