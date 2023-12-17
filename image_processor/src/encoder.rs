use image::EncodableLayout;
use webp::Encoder;
use anyhow::Result;

/// Encode JPEG image into WebP one.
pub fn encode_webp(buffer: &[u8]) -> Result<Vec<u8>> {
	let img = image::load_from_memory(buffer)?;

    let encoder = Encoder::from_image(&img).unwrap();
    let encoded_webp = encoder.encode(65f32);

	Ok(encoded_webp.as_bytes().to_vec())
}