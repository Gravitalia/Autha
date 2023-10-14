use autha::helpers::crypto::*;
use criterion::{criterion_group, criterion_main, Criterion};

fn random_string_benchmark(c: &mut Criterion) {
    c.bench_function(
        "random_string 20",
        |b| b.iter(|| {
            random_string(20)
        })
    );
}

fn hash_benchmark(c: &mut Criterion) {
    c.bench_function(
        "hash",
        |b| b.iter(|| {
            hash("password".as_bytes(), b"test")
        })
    );
}

criterion_group!(benches, random_string_benchmark, hash_benchmark);
criterion_main!(benches);
