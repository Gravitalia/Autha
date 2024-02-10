use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use crypto::hash::*;

fn hash_benchmark(c: &mut Criterion) {
    let config = Argon2Configuration {
        memory_cost: 262144,
        round: 1,
        lanes: 8,
        secret: "KEY".to_string(),
        hash_length: 16,
    };

    c.bench_function("argon2id", |b| {
        b.iter(|| argon2(config.clone(), "password".as_bytes(), Some(b"test")))
    });
}

fn sha256_digest_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Bytes(32));
    group.bench_function("sha256_digest", |b| {
        b.iter(|| sha256(b"Internet Protocol"))
    });
    group.finish();
}

fn sha1_digest_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Bytes(20));
    group.bench_function("sha1_digest", |b| {
        b.iter(|| sha1(b"Internet Protocol"))
    });
    group.finish();
}

criterion_group! {
    name = basics;
    config = Criterion::default().significance_level(0.1).sample_size(500);
    targets = sha256_digest_benchmark, sha1_digest_benchmark,
}
criterion_group! {
    name = consumers;
    config = Criterion::default().significance_level(0.2).sample_size(20);
    targets = hash_benchmark,
}
criterion_main!(basics, consumers);
