//! Event pipeline stages that run between parsing and the database writer:
//! noise filtering (drop events that add storage cost but no reporting value)
//! and IP→user resolution (fill `user_name` on lines the firewall could not
//! attribute, using what other lines from the same IP told us).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::{bail, Result};
use sfos_core::{classify, CategoryGroup, Event};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoiseRule {
    /// Firewall connection `Start` records (the `Stop` record carries the totals).
    ConnStart,
    /// IP-spoof denials whose destination is broadcast/multicast (e.g. NetBIOS/UPnP chatter).
    IpSpoofBroadcast,
    /// Firewall-rule events to port 53 (DNS). Opt-in: removes DNS from bandwidth/user activity.
    Dns,
}

impl NoiseRule {
    pub fn parse_list(raw: &str) -> Result<Vec<NoiseRule>> {
        let mut out = Vec::new();
        for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            out.push(match part {
                "conn_start" => NoiseRule::ConnStart,
                "ip_spoof_broadcast" => NoiseRule::IpSpoofBroadcast,
                "dns" => NoiseRule::Dns,
                other => bail!(
                    "unknown DROP_NOISE rule {other:?} (use conn_start, ip_spoof_broadcast, dns)"
                ),
            });
        }
        Ok(out)
    }

    fn matches(self, ev: &Event) -> bool {
        let fw_rule =
            ev.log_type == "Firewall" && ev.log_component.as_deref() == Some("Firewall Rule");
        match self {
            NoiseRule::ConnStart => fw_rule && ev.con_event.as_deref() == Some("Start"),
            NoiseRule::IpSpoofBroadcast => {
                ev.log_component.as_deref() == Some("IP Spoof")
                    && ev.dst_ip.as_deref().is_some_and(is_broadcast_or_multicast)
            }
            NoiseRule::Dns => fw_rule && ev.dst_port == Some(53),
        }
    }
}

fn is_broadcast_or_multicast(ip: &str) -> bool {
    if ip == "255.255.255.255" || ip.to_ascii_lowercase().starts_with("ff") && ip.contains(':') {
        return true;
    }
    ip.split('.')
        .next()
        .and_then(|o| o.parse::<u8>().ok())
        .is_some_and(|o| (224..=239).contains(&o))
}

#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub drop_noise: Vec<NoiseRule>,
    pub resolve_users: bool,
    pub ip_user_ttl_secs: i64,
    /// Name firewall connections that have no application (no DPI) from destination labels and
    /// the port table.
    pub classify_traffic: bool,
}

/// Destination address -> (application, category), refreshed in the background.
pub type IpLabels = Arc<RwLock<HashMap<String, (String, String)>>>;

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Keep,
    Filtered,
    /// Kept; `user_name` was filled from an earlier line for the same IP.
    ResolvedUser,
    /// Kept without a user because that IP was recently used by several users.
    Ambiguous,
}

struct Entry {
    user: String,
    group: Option<String>,
    last_seen: i64,
    ambiguous_until: i64,
}

const MAX_ENTRIES: usize = 500_000;

pub struct Pipeline {
    cfg: PipelineConfig,
    ips: HashMap<(Uuid, String), Entry>,
    since_purge: usize,
    labels: IpLabels,
}

impl Pipeline {
    pub fn new(cfg: PipelineConfig) -> Self {
        Self {
            cfg,
            ips: HashMap::new(),
            since_purge: 0,
            labels: IpLabels::default(),
        }
    }

    pub fn with_labels(mut self, labels: IpLabels) -> Self {
        self.labels = labels;
        self
    }

    /// Fill `application`/`application_category` on firewall connections the firewall did not
    /// classify. Learned destination labels win over the port table; the source is recorded in
    /// `attrs["classified_by"]` so reports can tell inferred from firewall-provided names.
    fn classify(&self, ev: &mut Event) {
        if ev.category_group != CategoryGroup::Firewall
            || ev.application.as_deref().is_some_and(|a| !a.is_empty())
        {
            return;
        }
        if let Some(ip) = ev.dst_ip.as_deref().filter(|ip| classify::is_public_ip(ip)) {
            if let Some((app, cat)) = self.labels.read().ok().and_then(|m| m.get(ip).cloned()) {
                ev.application = Some(app);
                ev.application_category = Some(cat);
                ev.attrs
                    .insert("classified_by".into(), "destination".into());
                return;
            }
        }
        if let Some(port) = ev.dst_port {
            if let Some((app, cat)) = classify::service_for_port(ev.protocol.as_deref(), port) {
                ev.application = Some(app.to_string());
                ev.application_category = Some(cat.to_string());
                ev.attrs.insert("classified_by".into(), "port".into());
            }
        }
    }

    /// Inspect (and possibly modify) an event. Uses the event's own timestamp,
    /// not the wall clock, so replays of old captures behave identically.
    pub fn process(&mut self, tenant: Uuid, ev: &mut Event) -> Outcome {
        if self.cfg.drop_noise.iter().any(|r| r.matches(ev)) {
            return Outcome::Filtered;
        }
        if self.cfg.classify_traffic {
            self.classify(ev);
        }
        if !self.cfg.resolve_users {
            return Outcome::Keep;
        }
        let Some(ip) = ev.src_ip.clone() else {
            return Outcome::Keep;
        };
        let ts = ev.ts.timestamp();
        let ttl = self.cfg.ip_user_ttl_secs;
        match ev.user_name.as_deref().filter(|u| !u.is_empty()) {
            Some(user) => {
                self.learn(tenant, ip, user, ev.user_group.as_deref(), ts, ttl);
                Outcome::Keep
            }
            None => match self.ips.get(&(tenant, ip)) {
                Some(e) if (ts - e.last_seen).abs() <= ttl => {
                    if ts < e.ambiguous_until {
                        Outcome::Ambiguous
                    } else {
                        ev.user_name = Some(e.user.clone());
                        if ev.user_group.as_deref().is_none_or(str::is_empty) {
                            ev.user_group = e.group.clone();
                        }
                        Outcome::ResolvedUser
                    }
                }
                _ => Outcome::Keep,
            },
        }
    }

    fn learn(
        &mut self,
        tenant: Uuid,
        ip: String,
        user: &str,
        group: Option<&str>,
        ts: i64,
        ttl: i64,
    ) {
        self.since_purge += 1;
        if self.since_purge >= 100_000 || self.ips.len() > MAX_ENTRIES {
            self.purge(ts, ttl);
        }
        let group = group.filter(|g| !g.is_empty()).map(str::to_string);
        match self.ips.get_mut(&(tenant, ip.clone())) {
            Some(e) => {
                if e.user != user && (ts - e.last_seen).abs() <= ttl {
                    // Two users on one IP (shared PC, NAT, DHCP reuse): stop guessing for a while.
                    e.ambiguous_until = ts + ttl;
                }
                e.user = user.to_string();
                e.group = group;
                e.last_seen = ts;
            }
            None => {
                self.ips.insert(
                    (tenant, ip),
                    Entry {
                        user: user.to_string(),
                        group,
                        last_seen: ts,
                        ambiguous_until: 0,
                    },
                );
            }
        }
    }

    fn purge(&mut self, now: i64, ttl: i64) {
        self.since_purge = 0;
        self.ips.retain(|_, e| (now - e.last_seen).abs() <= ttl);
        if self.ips.len() > MAX_ENTRIES {
            self.ips.clear();
        }
    }

    #[cfg(test)]
    pub fn tracked_ips(&self) -> usize {
        self.ips.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn cfg(rules: &[NoiseRule]) -> PipelineConfig {
        PipelineConfig {
            drop_noise: rules.to_vec(),
            resolve_users: true,
            ip_user_ttl_secs: 3600,
            classify_traffic: false,
        }
    }

    fn ev(ts: i64, ip: &str, user: Option<&str>) -> Event {
        Event {
            ts: Utc.timestamp_opt(ts, 0).unwrap(),
            log_type: "Firewall".into(),
            log_component: Some("Firewall Rule".into()),
            src_ip: Some(ip.into()),
            user_name: user.map(Into::into),
            ..Default::default()
        }
    }

    #[test]
    fn parses_rule_list_and_rejects_unknown() {
        assert_eq!(
            NoiseRule::parse_list("conn_start, dns").unwrap(),
            vec![NoiseRule::ConnStart, NoiseRule::Dns]
        );
        assert!(NoiseRule::parse_list("nope").is_err());
        assert!(NoiseRule::parse_list("").unwrap().is_empty());
    }

    #[test]
    fn filters_conn_start_but_keeps_stop() {
        let mut p = Pipeline::new(cfg(&[NoiseRule::ConnStart]));
        let t = Uuid::nil();
        let mut start = ev(0, "10.0.0.1", None);
        start.con_event = Some("Start".into());
        let mut stop = ev(0, "10.0.0.1", None);
        stop.con_event = Some("Stop".into());
        assert_eq!(p.process(t, &mut start), Outcome::Filtered);
        assert_eq!(p.process(t, &mut stop), Outcome::Keep);
    }

    #[test]
    fn filters_only_broadcast_ip_spoof() {
        let mut p = Pipeline::new(cfg(&[NoiseRule::IpSpoofBroadcast]));
        let t = Uuid::nil();
        let mut bcast = ev(0, "10.0.0.1", None);
        bcast.log_component = Some("IP Spoof".into());
        bcast.dst_ip = Some("255.255.255.255".into());
        let mut mcast = bcast.clone();
        mcast.dst_ip = Some("239.255.255.250".into());
        let mut real = bcast.clone();
        real.dst_ip = Some("8.8.8.8".into());
        assert_eq!(p.process(t, &mut bcast), Outcome::Filtered);
        assert_eq!(p.process(t, &mut mcast), Outcome::Filtered);
        assert_eq!(p.process(t, &mut real), Outcome::Keep);
    }

    #[test]
    fn filters_dns_only_when_enabled() {
        let t = Uuid::nil();
        let mut dns = ev(0, "10.0.0.1", None);
        dns.dst_port = Some(53);
        assert_eq!(
            Pipeline::new(cfg(&[])).process(t, &mut dns.clone()),
            Outcome::Keep
        );
        assert_eq!(
            Pipeline::new(cfg(&[NoiseRule::Dns])).process(t, &mut dns),
            Outcome::Filtered
        );
    }

    #[test]
    fn resolves_user_from_earlier_line_within_ttl() {
        let mut p = Pipeline::new(cfg(&[]));
        let t = Uuid::nil();
        let mut known = ev(1000, "10.0.0.5", Some("alice"));
        known.user_group = Some("Staff".into());
        assert_eq!(p.process(t, &mut known), Outcome::Keep);
        let mut anon = ev(1500, "10.0.0.5", None);
        assert_eq!(p.process(t, &mut anon), Outcome::ResolvedUser);
        assert_eq!(anon.user_name.as_deref(), Some("alice"));
        assert_eq!(anon.user_group.as_deref(), Some("Staff"));
        // outside TTL: not resolved
        let mut late = ev(1000 + 7200, "10.0.0.5", None);
        assert_eq!(p.process(t, &mut late), Outcome::Keep);
        assert!(late.user_name.is_none());
    }

    #[test]
    fn does_not_guess_for_shared_ips_or_cross_tenant() {
        let mut p = Pipeline::new(cfg(&[]));
        let t = Uuid::nil();
        p.process(t, &mut ev(100, "10.0.0.9", Some("alice")));
        p.process(t, &mut ev(200, "10.0.0.9", Some("bob")));
        let mut anon = ev(300, "10.0.0.9", None);
        assert_eq!(p.process(t, &mut anon), Outcome::Ambiguous);
        assert!(anon.user_name.is_none());
        let mut other = ev(300, "10.0.0.9", None);
        assert_eq!(p.process(Uuid::from_u128(1), &mut other), Outcome::Keep);
    }

    #[test]
    fn disabled_resolver_never_fills() {
        let mut c = cfg(&[]);
        c.resolve_users = false;
        let mut p = Pipeline::new(c);
        let t = Uuid::nil();
        p.process(t, &mut ev(1, "10.0.0.1", Some("alice")));
        let mut anon = ev(2, "10.0.0.1", None);
        assert_eq!(p.process(t, &mut anon), Outcome::Keep);
        assert_eq!(p.tracked_ips(), 0);
    }

    #[test]
    fn classifies_unnamed_firewall_traffic_by_label_then_port() {
        let labels = IpLabels::default();
        labels.write().unwrap().insert(
            "142.250.1.1".into(),
            ("YouTube".into(), "Streaming Media".into()),
        );
        let mut c = cfg(&[]);
        c.classify_traffic = true;
        let mut p = Pipeline::new(c).with_labels(labels);
        let t = Uuid::nil();
        let mk = |dst: &str, port: i32, proto: &str| Event {
            category_group: CategoryGroup::Firewall,
            dst_ip: Some(dst.into()),
            dst_port: Some(port),
            protocol: Some(proto.into()),
            ..Default::default()
        };
        let mut a = mk("142.250.1.1", 443, "TCP");
        p.process(t, &mut a);
        assert_eq!(a.application.as_deref(), Some("YouTube"));
        assert_eq!(
            a.attrs.get("classified_by").map(String::as_str),
            Some("destination")
        );
        let mut b = mk("8.8.4.4", 443, "UDP");
        p.process(t, &mut b);
        assert_eq!(b.application.as_deref(), Some("QUIC"));
        assert_eq!(
            b.attrs.get("classified_by").map(String::as_str),
            Some("port")
        );
        // Firewall-provided names are never overwritten; private destinations skip labels.
        let mut c2 = mk("142.250.1.1", 443, "TCP");
        c2.application = Some("Netflix".into());
        p.process(t, &mut c2);
        assert_eq!(c2.application.as_deref(), Some("Netflix"));
        let mut d = mk("10.0.0.5", 445, "TCP");
        p.process(t, &mut d);
        assert_eq!(d.application.as_deref(), Some("SMB"));
    }
}
