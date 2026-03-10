//! Telemetry setup: tracing, metrics, logging.

use std::time::Duration;

use metrics::{Unit, gauge};
use metrics_exporter_prometheus::{
    BuildError, Matcher, PrometheusBuilder, PrometheusHandle,
};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{ExporterBuildError, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::{SdkLogger, SdkLoggerProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use sysinfo::{
    Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System,
};
use tokio::time::sleep;

fn resources() -> Resource {
    Resource::builder().with_service_name("autha").build()
}

/// Create tracer for OTLP.
pub fn setup_tracer() -> Result<SdkTracerProvider, ExporterBuildError> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()?;

    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resources())
        .build())
}

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

    let mut system = System::new_with_specifics(RefreshKind::nothing());
    let pid = Pid::from_u32(std::process::id());

    tokio::spawn(async move {
        loop {
            system.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[pid]),
                true,
                ProcessRefreshKind::nothing().with_memory().with_cpu(),
            );

            if let Some(process) = system.process(pid) {
                gauge!("process_memory_used_bytes")
                    .set(process.memory() as f64);
                gauge!("process_cpu_usage").set(process.cpu_usage() as f64);
            }

            sleep(Duration::from_secs(10)).await;
        }
    });

    PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("http_requests_duration_seconds".to_string()),
            EXPONENTIAL_SECONDS,
        )?
        .install_recorder()
}

/// Create OTLP exporter for logs.
pub fn setup_logging(
    endpoint: &str,
) -> Result<
    OpenTelemetryTracingBridge<SdkLoggerProvider, SdkLogger>,
    ExporterBuildError,
> {
    let exporter = opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    let provider = SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resources())
        .build();

    Ok(OpenTelemetryTracingBridge::new(&provider))
}
