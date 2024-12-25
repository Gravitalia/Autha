use axum::{
    extract::{MatchedPath, Request},
    middleware::Next,
    response::IntoResponse,
};
use metrics::{gauge, Unit};
use metrics_exporter_prometheus::{BuildError, Matcher, PrometheusBuilder, PrometheusHandle};
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};
use tokio::time::sleep;

/// Create recorder for Prometheus metrics.
pub fn setup_metrics_recorder() -> Result<PrometheusHandle, BuildError> {
    const EXPONENTIAL_SECONDS: &[f64] = &[
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];

    metrics::describe_gauge!(
        "process_cpu_usage",
        Unit::Percent,
        "CPU usage of the process in percentage."
    );
    metrics::describe_gauge!(
        "process_memory_used_bytes",
        Unit::Bytes,
        "Total process memory in bytes."
    );

    let mut system = System::new_all();
    let pid = Pid::from_u32(std::process::id());

    tokio::spawn(async move {
        loop {
            system.refresh_all();

            if let Some(process) = system.process(pid) {
                let memory_used = process.memory() as f64;
                let cpu_usage = process.cpu_usage() as f64;

                let mem_gauge = gauge!("process_memory_used_bytes");
                mem_gauge.set(memory_used);
                let cpu_gauge = gauge!("process_cpu_usage");
                cpu_gauge.set(cpu_usage);
            }

            sleep(Duration::from_secs(5)).await;
        }
    });

    PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("http_requests_duration_seconds".to_string()),
            EXPONENTIAL_SECONDS,
        )?
        .install_recorder()
}

/// Track every metrics into one function. Cool.
pub async fn track_metrics(req: Request, next: Next) -> impl IntoResponse {
    let start = Instant::now();
    let path = if let Some(matched_path) = req.extensions().get::<MatchedPath>() {
        matched_path.as_str().to_owned()
    } else {
        req.uri().path().to_owned()
    };
    let method = req.method().clone();

    let response = next.run(req).await;

    let latency = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    let labels = [
        ("method", method.to_string()),
        ("path", path),
        ("status", status),
    ];

    metrics::counter!("http_requests_total", &labels).increment(1);
    metrics::histogram!("http_requests_duration_seconds", &labels).record(latency);

    response
}
