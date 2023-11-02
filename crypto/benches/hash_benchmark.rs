use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use crypto::hash::*;

fn hash_benchmark(c: &mut Criterion) {
    c.bench_function("hash", |b| {
        b.iter(|| argon2("password".as_bytes(), b"test"))
    });
}

fn sha256_digest_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Bytes(256));
    group.bench_function("sha256_digest", |b| b.iter(|| sha256(b"Internet Protocol")));
    group.finish();
}

criterion_group! {
    name = basics;
    config = Criterion::default().significance_level(0.1).sample_size(500);
    targets = sha256_digest_benchmark,
}
criterion_group! {
    name = consumers;
    config = Criterion::default().significance_level(0.2).sample_size(20);
    targets = hash_benchmark,
}
criterion_main!(basics, consumers);
