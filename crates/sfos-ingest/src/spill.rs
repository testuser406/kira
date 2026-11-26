//! Disk spill: when the database is unavailable, batches are parked as JSON-lines files and replayed
//! automatically once it is back, so a database outage does not lose logs.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::OnceLock;

use sfos_core::model::Event;
use sfos_store::Store;
use uuid::Uuid;

use crate::metrics::SharedMetrics;

struct Config {
    dir: PathBuf,
    max_bytes: u64,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

pub fn init(dir: Option<String>, max_mb: u64) {
    if let Some(d) = dir.filter(|d| !d.trim().is_empty()) {
        let dir = PathBuf::from(d);
        if std::fs::create_dir_all(&dir).is_ok() {
            tracing::info!(dir = %dir.display(), max_mb, "disk spill enabled");
            let _ = CONFIG.set(Config {
                dir,
                max_bytes: max_mb * 1024 * 1024,
            });
        } else {
            tracing::warn!(dir = %dir.display(), "cannot create spill directory; spill disabled");
        }
    }
}

fn used_bytes(dir: &PathBuf) -> u64 {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

/// Park a batch on disk. Returns false when spill is disabled, full, or fails.
pub fn write(tenant: Uuid, events: &[Event]) -> bool {
    let Some(cfg) = CONFIG.get() else {
        return false;
    };
    if used_bytes(&cfg.dir) >= cfg.max_bytes {
        tracing::error!("spill directory is full; dropping batch");
        return false;
    }
    let mut body = String::new();
    for e in events {
        match serde_json::to_string(e) {
            Ok(l) => {
                body.push_str(&l);
                body.push('\n');
            }
            Err(err) => tracing::warn!(%err, "cannot serialise event for spill"),
        }
    }
    let name = format!(
        "spill-{:020}-{tenant}",
        chrono::Utc::now().timestamp_micros()
    );
    let tmp = cfg.dir.join(format!("{name}.tmp"));
    let fin = cfg.dir.join(format!("{name}.jsonl"));
    match std::fs::write(&tmp, body).and_then(|_| std::fs::rename(&tmp, &fin)) {
        Ok(()) => true,
        Err(err) => {
            tracing::error!(%err, "failed to write spill file");
            false
        }
    }
}

/// Replay the oldest spill files (at most a few per call) into the database.
pub async fn replay(store: &Store, metrics: &SharedMetrics) {
    let Some(cfg) = CONFIG.get() else { return };
    let mut files: Vec<PathBuf> = match std::fs::read_dir(&cfg.dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .collect(),
        Err(_) => return,
    };
    files.sort();
    for path in files.into_iter().take(5) {
        let tenant = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.get(s.len().saturating_sub(36)..))
            .and_then(|t| Uuid::parse_str(t).ok());
        let (Some(tenant), Ok(text)) = (tenant, std::fs::read_to_string(&path)) else {
            let _ = std::fs::rename(&path, path.with_extension("bad"));
            continue;
        };
        let events: Vec<Event> = text
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        if events.is_empty() {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        match store.copy_events(tenant, &events).await {
            Ok(rows) => {
                metrics.written.fetch_add(rows, Ordering::Relaxed);
                metrics.replayed.fetch_add(rows, Ordering::Relaxed);
                let _ = std::fs::remove_file(&path);
                tracing::info!(rows, file = %path.display(), "replayed spilled batch");
            }
            Err(err) => {
                tracing::warn!(%err, "database still unavailable; spill replay postponed");
                return;
            }
        }
    }
}

pub fn pending_files() -> usize {
    CONFIG
        .get()
        .and_then(|c| std::fs::read_dir(&c.dir).ok())
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|x| x == "jsonl"))
                .count()
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spill_roundtrip_serialises_events() {
        let e = Event {
            user_name: Some("a".into()),
            ..Default::default()
        };
        let line = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<Event>(&line).unwrap(), e);
    }
}
