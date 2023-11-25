use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use crypto::decrypt::chacha20_poly1305 as chacha20_poly1305_decrypt;
use crypto::encrypt::*;

fn chacha20_poly1305_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Bytes(116));
    group.bench_function("chacha20_poly1305 encrypt", |b| {
        b.iter(|| chacha20_poly1305(b"Sensitive data such as birthdate or phone.".to_vec()))
    });
    group.finish();

    let encrypted =
        chacha20_poly1305(b"Sensitive data such as birthdate or phone.".to_vec()).unwrap();
    let nonce: [u8; 12] = hex::decode(encrypted.0)
        .unwrap_or_default()
        .try_into()
        .unwrap_or_default();
    let chabits = hex::decode(encrypted.1).unwrap_or_default();

    c.bench_with_input(
        BenchmarkId::new("chacha20_poly1305 decrypt", 1),
        &(&nonce, &chabits),
        |b, &d| {
            b.iter(|| chacha20_poly1305_decrypt(*d.0, d.1.to_vec()));
        },
    );
}

fn fpe_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Bytes(36));
    group.bench_function("fpe encrypt", |b| {
        b.iter(|| format_preserving_encryption("john.doe@email.com".encode_utf16().collect()))
    });
    group.finish();
}

criterion_group!(benches, chacha20_poly1305_benchmark, fpe_benchmark,);
criterion_main!(benches);
