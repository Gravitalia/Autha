use autha::helpers::crypto::*;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

fn random_string_benchmark(c: &mut Criterion) {
    c.bench_function("random_string 20", |b| b.iter(|| random_string(20)));
}

fn hash_benchmark(c: &mut Criterion) {
    c.bench_function("hash", |b| b.iter(|| hash("password".as_bytes(), b"test")));
}

fn sha256_digest_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Bytes(256));
    group.bench_function("sha256_digest", |b| {
        b.iter(|| sha256_digest(b"Internet Protocol"))
    });
    group.finish();
}

criterion_group! {
    name = basics;
    config = Criterion::default().significance_level(0.1).sample_size(500);
    targets = random_string_benchmark, sha256_digest_benchmark
}
criterion_group! {
    name = consumers;
    config = Criterion::default().significance_level(0.2).sample_size(20);
    targets = hash_benchmark
}
criterion_main!(basics, consumers);
