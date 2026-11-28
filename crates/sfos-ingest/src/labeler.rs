//! Background tasks that keep destination labels current so firewall connections can be named
//! without DPI: refresh the in-memory map, learn from web-filter lines, and (optionally)
//! reverse-resolve the busiest unlabelled public addresses.

use std::{net::IpAddr, sync::Arc, time::Duration};

use sfos_core::classify;
use sfos_store::Store;
use tokio::sync::Semaphore;

use crate::pipeline::IpLabels;

pub fn spawn(store: Store, labels: IpLabels, ptr_lookup: bool) {
    // Refresh the shared map every minute (also once right away).
    {
        let (store, labels) = (store.clone(), labels.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                match store.load_ip_labels().await {
                    Ok(rows) => {
                        let map = rows.into_iter().map(|(ip, a, c)| (ip, (a, c))).collect();
                        if let Ok(mut guard) = labels.write() {
                            *guard = map;
                        }
                    }
                    Err(err) => tracing::warn!(%err, "loading destination labels failed"),
                }
            }
        });
    }
    // Learn from web-filter lines; prune stale labels hourly.
    {
        let store = store.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(120));
            let mut round = 0u32;
            loop {
                tick.tick().await;
                if let Err(err) = store.learn_ip_labels_from_web(20).await {
                    tracing::warn!(%err, "learning destination labels failed");
                }
                round += 1;
                if round.is_multiple_of(30) {
                    let _ = store.prune_ip_labels(30).await;
                }
            }
        });
    }
    if ptr_lookup {
        tokio::spawn(async move {
            let gate = Arc::new(Semaphore::new(8));
            let mut tick = tokio::time::interval(Duration::from_secs(180));
            loop {
                tick.tick().await;
                let ips = match store.unlabelled_destinations(30, 60).await {
                    Ok(ips) => ips,
                    Err(err) => {
                        tracing::warn!(%err, "listing unlabelled destinations failed");
                        continue;
                    }
                };
                let mut jobs = Vec::new();
                for ip in ips {
                    let permit = gate.clone().acquire_owned().await;
                    let store = store.clone();
                    jobs.push(tokio::spawn(async move {
                        let _permit = permit;
                        resolve_and_save(&store, &ip).await;
                    }));
                }
                for job in jobs {
                    let _ = job.await;
                }
            }
        });
    }
}

async fn resolve_and_save(store: &Store, ip: &str) {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return;
    };
    let lookup = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&addr)),
    )
    .await;
    // Remember misses too, so the same address is not asked again every round.
    let host = match lookup {
        Ok(Ok(Ok(host))) if host != ip => Some(host),
        _ => None,
    };
    let (app, category) = match host.as_deref() {
        Some(h) => match classify::classify_host(h) {
            Some((a, c)) => (a.to_string(), c.to_string()),
            None => (
                classify::registrable_domain(h),
                "Unclassified (host)".into(),
            ),
        },
        None => ("Unknown host".into(), "Unclassified".into()),
    };
    if let Err(err) = store
        .save_ip_label(ip, host.as_deref(), &app, &category, "ptr")
        .await
    {
        tracing::warn!(%err, "saving destination label failed");
    }
}
