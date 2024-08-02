use criterion::{criterion_group, criterion_main, Criterion};
use image_processor::resizer::{resize, Encode, Encoder, Lossless};

fn resize_benchmark(c: &mut Criterion) {
    let buffer = &std::fs::read("benches/image.jpg").unwrap();

    c.bench_function("resize JPEG to PNG ~100KB 100w", |b| {
        b.iter(|| {
            resize(
                buffer,
                Encoder {
                    encoder: Encode::Lossless(Lossless::Png),
                    width: Some(100),
                    height: None,
                    speed: None,
                },
            )
        })
    });

    c.bench_function("resize JPEG to WebP ~100KB 100w", |b| {
        b.iter(|| {
            resize(
                buffer,
                Encoder {
                    encoder: Encode::Lossless(Lossless::WebP),
                    width: Some(100),
                    height: None,
                    speed: None,
                },
            )
        })
    });

    c.bench_function("resize JPEG to AVIF ~100KB 100w", |b| {
        b.iter(|| {
            resize(
                buffer,
                Encoder {
                    encoder: Encode::Lossless(Lossless::Avif),
                    width: Some(100),
                    height: None,
                    speed: None,
                },
            )
        })
    });
}

criterion_group!(benches, resize_benchmark,);
criterion_main!(benches);
