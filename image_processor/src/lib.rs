//! # image_processor
//!
//! fast and efficient image resizer and encoder (WebP only).
//! can also upload result image to variety of providers:
//! - Cloudinary; and
//! - S3.
//!
//! # Resize, optimize and upload image
//!
//! ```no_run
//! let buffer = std::fs::read("example/image.jpg").unwrap();
//! let id = image_processor::resize_and_upload(
//!     &buffer,
//!     Some(256),
//!     None,
//!     Some(80.0),
//!     image_processor::host::cloudinary::Credentials {
//!         key: "111111111111111".to_string(),
//!         cloud_name: "aaaaa1234".to_string(),
//!         secret: "SECRET_KEY".to_string(),
//!     },
//! );
//! ```
pub mod encoder;
pub mod exif;
pub mod host;
pub mod resizer;

use anyhow::Result;

/// Resize, encode and then upload to Cloudinary the image buffer.
///
/// # Returns
/// SHA1 encoded image result (after resize and encode).
pub async fn resize_and_upload(
    buffer: &[u8],
    width: Option<u32>,
    height: Option<u32>,
    quality: Option<f32>,
    credentials: host::cloudinary::Credentials,
) -> Result<String> {
    let resized = resizer::resize(buffer, width, height)?;
    let encoded = encoder::encode_webp(resized.buffer(), quality)?;
    let public_id = host::cloudinary::upload(credentials, &encoded).await?;

    Ok(public_id)
}