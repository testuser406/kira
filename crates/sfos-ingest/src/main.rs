mod config;
mod listener;
mod metrics;
mod pipeline;
mod sources;
mod spill;
mod writer;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use sfos_store::Store;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::metrics::{Metrics, SharedMetrics};
use crate::sources::SourceMap;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::from_env()?;
    tracing::info!(
        udp = %cfg.udp_addr,
        tcp = %cfg.tcp_addr,
        tenant = %cfg.tenant_slug,
        "starting Sophos syslog collector"
    );

    let store = Store::connect_with_password(
        &cfg.database_url,
        cfg.database_password.as_deref(),
        cfg.db_pool_size,
    )?;
    store.migrate().await.context("database migration failed")?;

    let default_tenant = store
        .ensure_tenant(&cfg.tenant_slug, &cfg.tenant_name)
        .await?;
    store
        .initialize_global_retention(cfg.retention_hours)
        .await?;
    let retention_hours = store.global_retention_hours().await?;
    let mut entries = Vec::new();
    for (net, slug) in &cfg.tenant_map {
        let tenant = store.ensure_tenant(slug, slug).await?;
        entries.push((*net, tenant.id));
    }
    let sources = Arc::new(SourceMap::new(
        default_tenant.id,
        entries,
        cfg.allowed_sources.clone(),
    ));

    store
        .ensure_partitions(cfg.partitions_ahead_hours)
        .await
        .context("failed to create event partitions")?;
    store.drop_old_partitions(retention_hours).await?;
    if let Err(err) = store.roll_hourly(144).await {
        tracing::warn!(%err, "initial hourly rollup failed");
    }

    let metrics: SharedMetrics = Arc::new(Metrics::default());
    metrics
        .udp_port
        .store(cfg.udp_addr.port(), std::sync::atomic::Ordering::Relaxed);
    let (tx, rx) = mpsc::channel(cfg.queue_capacity);

    let udp = bind_udp(cfg.udp_addr)
        .with_context(|| format!("cannot bind UDP syslog socket on {}", cfg.udp_addr))?;
    let tcp = TcpListener::bind(cfg.tcp_addr)
        .await
        .with_context(|| format!("cannot bind TCP syslog socket on {}", cfg.tcp_addr))?;

    let udp_task = tokio::spawn(listener::run_udp(
        udp,
        sources.clone(),
        tx.clone(),
        metrics.clone(),
        cfg.default_tz_offset_minutes,
        cfg.keep_extended_attributes,
    ));
    let tcp_task = tokio::spawn(listener::run_tcp(
        tcp,
        sources,
        tx.clone(),
        metrics.clone(),
        cfg.default_tz_offset_minutes,
        cfg.keep_extended_attributes,
        cfg.max_line,
    ));
    spill::init(
        std::env::var("SPILL_DIR").ok(),
        std::env::var("SPILL_MAX_MB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(500),
    );
    {
        let (store, metrics) = (store.clone(), metrics.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                tick.tick().await;
                spill::replay(&store, &metrics).await;
            }
        });
    }
    let writer_task = tokio::spawn(writer::run(
        store.clone(),
        rx,
        cfg.batch_size,
        cfg.batch_ms,
        metrics.clone(),
        pipeline::Pipeline::new(cfg.pipeline.clone()),
    ));
    let maintenance_task = tokio::spawn(maintenance(
        store.clone(),
        cfg.retention_hours,
        cfg.partitions_ahead_hours,
        cfg.maintenance_interval_secs,
    ));
    let health_task = tokio::spawn(health_server(
        cfg.health_addr,
        store.clone(),
        metrics.clone(),
        tx.clone(),
    ));

    shutdown_signal().await;
    tracing::info!("shutting down, writing queued events");

    // Close the channel first so listeners get send errors and exit gracefully,
    // then wait for them to finish. This preserves in-flight parsed events.
    drop(tx);

    // Give listeners a moment to notice the closed channel and exit
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), udp_task).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tcp_task).await;
    health_task.abort();
    let _ = health_task.await;

    let drain = tokio::time::timeout(std::time::Duration::from_secs(15), writer_task).await;
    if drain.is_err() {
        tracing::warn!("writer did not finish within 15s; some queued events may be lost");
    }
    maintenance_task.abort();

    tracing::info!(
        written = metrics.written.load(Ordering::Relaxed),
        rejected = metrics.rejected.load(Ordering::Relaxed),
        "collector stopped"
    );
    Ok(())
}

async fn maintenance(
    store: Store,
    initial_retention_hours: i64,
    partitions_ahead_hours: i64,
    interval_secs: u64,
) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if let Err(err) = store.ensure_partitions(partitions_ahead_hours).await {
            tracing::error!(%err, "failed to create partitions");
        }
        match store.global_retention_hours().await {
            Ok(retention_hours) => {
                if let Err(err) = store.drop_old_partitions(retention_hours).await {
                    tracing::error!(%err, "failed to apply retention policy");
                }
            }
            Err(err) => tracing::error!(
                %err,
                fallback_retention_hours = initial_retention_hours,
                "failed to read global retention setting"
            ),
        }
        if let Err(err) = store.drop_old_device_activity().await {
            tracing::error!(%err, "failed to prune device activity");
        }
        if let Err(err) = store.drop_old_minute_rollups().await {
            tracing::error!(%err, "failed to prune minute rollups");
        }
        if let Err(err) = store.roll_hourly(48).await {
            tracing::error!(%err, "failed to roll up hourly activity");
        }
        if let Err(err) = store.drop_old_web_extracts().await {
            tracing::error!(%err, "failed to prune searches/videos");
        }
        if let Err(err) = store.drop_old_shares().await {
            tracing::error!(%err, "failed to prune report shares");
        }
        if let Err(err) = store.drop_old_hourly().await {
            tracing::error!(%err, "failed to prune hourly activity");
        }
    }
}

async fn health_server(
    addr: std::net::SocketAddr,
    store: Store,
    metrics: SharedMetrics,
    tx: mpsc::Sender<listener::Incoming>,
) {
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_handler))
        .with_state((store, metrics, tx));
    match TcpListener::bind(addr).await {
        Ok(listener) => {
            if let Err(err) = axum::serve(listener, app).await {
                tracing::error!(%err, "health server stopped");
            }
        }
        Err(err) => tracing::error!(%err, %addr, "cannot bind health server"),
    }
}

async fn healthz(
    State((store, _, _)): State<(Store, SharedMetrics, mpsc::Sender<listener::Incoming>)>,
) -> impl IntoResponse {
    match store.ping().await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "degraded", "error": err.to_string()})),
        ),
    }
}

async fn metrics_handler(
    State((_, metrics, tx)): State<(Store, SharedMetrics, mpsc::Sender<listener::Incoming>)>,
) -> Json<serde_json::Value> {
    let capacity = tx.max_capacity();
    let depth = capacity - tx.capacity();
    Json(metrics.snapshot(depth, capacity))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

/// Bind the syslog UDP socket with a large receive buffer so bursts are not dropped by the OS
/// (`UDP_RCVBUF_MB`, default 32; the OS may cap it, the effective size is logged).
fn bind_udp(addr: std::net::SocketAddr) -> anyhow::Result<UdpSocket> {
    use socket2::{Domain, Socket, Type};
    let mb: usize = std::env::var("UDP_RCVBUF_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, None)?;
    let _ = socket.set_recv_buffer_size(mb * 1024 * 1024);
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    let effective = socket.recv_buffer_size().unwrap_or(0);
    if effective < 4 * 1024 * 1024 {
        tracing::warn!(
            effective_kb = effective / 1024,
            "UDP receive buffer is small; bursts may be dropped (raise net.core.rmem_max on Linux)"
        );
    } else {
        tracing::info!(effective_mb = effective / 1024 / 1024, "UDP receive buffer");
    }
    Ok(UdpSocket::from_std(socket.into())?)
}
