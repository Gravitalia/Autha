use anyhow::Result;
use image::EncodableLayout;
use webp::Encoder;

/// Re-encode image into a WebP one.
pub fn encode_webp(buffer: &[u8], quality: Option<f32>) -> Result<Vec<u8>> {
    let img = image::load_from_memory(buffer)?;

    let encoder = Encoder::from_image(&img).unwrap();
    let encoded_webp = encoder.encode(quality.unwrap_or(90.0));

    Ok(encoded_webp.as_bytes().to_vec())
}
