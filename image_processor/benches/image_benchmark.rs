use criterion::{criterion_group, criterion_main, Criterion};
use image_processor::resizer::resize;

fn resize_benchmark(c: &mut Criterion) {
    let buffer = &std::fs::read("benches/image.jpg").unwrap();

    c.bench_function("resize ~100KB 100w", |b| {
        b.iter(|| resize(buffer, Some(100), None))
    });
}

criterion_group!(benches, resize_benchmark,);
criterion_main!(benches);
