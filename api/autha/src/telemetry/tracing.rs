use opentelemetry::{trace::TraceError, KeyValue};
use opentelemetry_sdk::{
    runtime,
    trace::{config, Tracer},
    Resource,
};

/// Inits jaeger tracing globally.
///
/// This function is using deprecated function to eliminate the needs of OTLP.
#[allow(deprecated)]
pub fn init(url: String) -> Result<Tracer, TraceError> {
    opentelemetry_jaeger::new_agent_pipeline()
        .with_endpoint(url) // "jaeger:6831"
        .with_service_name("autha")
        .with_trace_config(config().with_resource(Resource::new(vec![
            KeyValue::new("service.name", "autha"),
            KeyValue::new("service.namespace", "gravitalia"),
            KeyValue::new("exporter", "jaeger"),
        ])))
        .install_batch(runtime::Tokio)
}
