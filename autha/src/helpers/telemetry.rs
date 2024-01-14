use opentelemetry::{
    global,
    trace::{TraceContextExt, TraceError, Tracer},
    KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{runtime, trace as sdktrace, Resource};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts, Registry,
};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref HTTP_REQUESTS: IntCounter =
        IntCounter::new("http_requests", "Incoming HTTP Requests")
            .expect("http_requests metric could not be created");
    pub static ref RESPONSE_TIME_COLLECTOR: HistogramVec =
        HistogramVec::new(HistogramOpts::new("response_time", "Response Times"), &[])
            .expect("response_time metric could not be created");
    pub static ref RESPONSE_CODE_COLLECTOR: IntCounterVec = IntCounterVec::new(
        Opts::new("response_code", "Response Codes"),
        &["statuscode", "type"]
    )
    .expect("response_code metric could not be created");
}

/// Initiates gRPC connection to Jaeger. Data is sent under OpenTelemetry Protocol.
#[inline]
pub fn init_tracer() -> Result<opentelemetry_sdk::trace::Tracer, TraceError> {
    opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint("http://localhost:4317"),
        )
        .with_trace_config(sdktrace::config().with_resource(Resource::new(vec![
            KeyValue::new("service.name", "autha"),
            KeyValue::new("service.namespace", "gravitalia"),
            KeyValue::new("exporter", "jaeger"),
        ])))
        .install_batch(runtime::Tokio)
}

/// Create custom metrics.
#[inline]
pub fn register_custom_metrics() {
    REGISTRY
        .register(Box::new(HTTP_REQUESTS.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(RESPONSE_TIME_COLLECTOR.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(RESPONSE_CODE_COLLECTOR.clone()))
        .expect("collector can be registered");
}

/// Transforms metrics into plain text, then sends them via Warp.
#[inline]
pub async fn metrics_handler() -> Result<impl warp::Reply, warp::Rejection> {
    let encoder = prometheus::TextEncoder::new();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&REGISTRY.gather(), &mut buffer) {
        log::error!("could not encode custom metrics: {}", e);
    };
    let mut res = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            log::error!("custom metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        log::error!("could not encode prometheus metrics: {}", e);
    };
    let res_custom = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            log::error!("prometheus metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();

    res.push_str(&res_custom);

    Ok(res)
}
