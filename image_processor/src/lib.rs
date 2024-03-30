#![forbid(unsafe_code)]
#![deny(
    dead_code,
    unused_imports,
    unused_mut,
    missing_docs,
    missing_debug_implementations
)]

//! # image_processor
//!
//! fast and efficient image resizer and encoder (WebP only).
//! can also upload result image to variety of providers:
//! - Cloudinary; and
//! - S3.
//!
//! # Resize, optimize and upload image
//!
//! ```rust
//! let buffer = std::fs::read("./benches/image.jpg").unwrap();
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

/// Publish an image into a selected host.
/// Hosts are: Cloudinary, S3.
pub mod host;
/// Resize image fastly and well.
pub mod resizer;

use image::ImageError as ImgError;
use resizer::{Encode, Encoder, Lossless, Lossy};
use std::{error::Error, fmt, io::Error as IoError};

/// Error type.
#[derive(Debug)]
pub enum ImageError {
    /// Error from `image` crate.
    Image(ImgError),
    /// Error from `std::io` (Input/Output).
    FailedIo(IoError),
    /// Error when transcoding image to another format.
    FailedEncode,
    /// Failed uploading.
    FailedUpload,
    /// Error when transcoding image to another format.
    MissingWidthOrHeight,
    /// An error with absolutely no details.
    Unspecified,
    /// Format is not supported by encoder.
    UnsupportedFormat,
}

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ImageError::Image(error) => write!(f, "{}", error),
            ImageError::FailedIo(error) => write!(f, "{}", error),
            ImageError::FailedEncode => {
                write!(f, "Error during transcoding to JPEG")
            },
            ImageError::FailedUpload => {
                write!(f, "Cannot upload to the platform")
            },
            ImageError::MissingWidthOrHeight => {
                write!(f, "You must add width or height")
            },
            ImageError::Unspecified => write!(f, "Unknown error"),
            ImageError::UnsupportedFormat => {
                write!(f, "Unsupported image format")
            },
        }
    }
}

impl Error for ImageError {}

/// Resize, encode and then upload to Cloudinary the image buffer.
///
/// Supported formats:
/// - avif
/// - jpeg
/// - png
/// - webp
///
/// # Returns
/// SHA1 encoded image result (after resize and encode).
pub async fn resize_and_upload(
    buffer: &[u8],
    width: Option<u32>,
    height: Option<u32>,
    format: String,
    credentials: host::cloudinary::Credentials,
) -> Result<String, ImageError> {
    let encoder = match format.as_str() {
        "avif" | "image/avif" => Encoder {
            encoder: Encode::Lossless(Lossless::Avif),
            width,
            height,
            speed: None,
        },
        "jpeg" | "jpg" | "image/jpeg" => Encoder {
            encoder: Encode::Lossy(Lossy::Jpeg(80)),
            width,
            height,
            speed: None,
        },
        "png" | "image/png" => Encoder {
            encoder: Encode::Lossless(Lossless::Png),
            width,
            height,
            speed: None,
        },
        "webp" | "image/webp" => Encoder {
            encoder: Encode::Lossless(Lossless::WebP),
            width,
            height,
            speed: None,
        },
        _ => return Err(ImageError::UnsupportedFormat),
    };
    let resized = resizer::resize(buffer, encoder)?;
    let public_id = host::cloudinary::upload(credentials, &resized).await?;

    Ok(public_id)
}
