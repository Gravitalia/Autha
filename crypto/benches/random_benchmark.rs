use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use crypto::{random_bytes, random_string};

fn random_bytes_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Bytes(200));
    group.bench_function("random_bytes 200", |b| b.iter(|| random_bytes(200)));
    group.finish();
}

fn random_string_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Bytes(200));
    group
        .bench_function("random_string 200", |b| b.iter(|| random_string(200)));
    group.finish();
}

criterion_group!(benches, random_bytes_benchmark, random_string_benchmark,);
criterion_main!(benches);
