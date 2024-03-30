use crate::ImageError;
use image::{
    imageops::FilterType::Lanczos3, load_from_memory, DynamicImage, ImageFormat,
};
use std::io::Cursor;

/// Lossless compression algorithms.
#[derive(Debug)]
pub enum Lossless {
    /// Avif encoder. More performant than WebP.
    Avif,
    /// PNG encoder.
    Png,
    /// WebP encoder.
    WebP,
}

/// Lossy compression algorithms.
#[derive(Debug)]
pub enum Lossy {
    /// Jpeg encoder.
    Jpeg(u8),
}

/// Type of algorithm to choose for compression.
#[derive(Debug)]
pub enum Encode {
    /// Lossless, high-quality compression.
    Lossless(Lossless),
    /// Lossy compression, lightweight result.
    Lossy(Lossy),
}

/// Data required for compression.
#[derive(Debug)]
pub struct Encoder {
    /// Algorithm used for compression.
    pub encoder: Encode,
    /// Width of the output image.
    pub width: Option<u32>,
    /// Height of the output image.
    pub height: Option<u32>,
    /// AVIF only.
    /// `rav1e` speed parameter.
    pub speed: Option<u8>,
}

fn image_encoder(
    image: DynamicImage,
    width: u32,
    height: u32,
    _quality: Option<u8>,
    format: ImageFormat,
) -> Result<Vec<u8>, ImageError> {
    let mut output: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    image
        .resize(width, height, Lanczos3)
        .write_to(&mut output, format)
        .map_err(|_| ImageError::FailedEncode)?;

    Ok(output.into_inner())
}

/// Image resizer.
///
/// # Example
/// ```no_run
/// use std::io::Write;
/// use image_processor::resizer::{Encode, Encoder, Lossless};
///
/// let mut file = std::fs::File::create("example/processed.jpg").unwrap();
/// let buff = image_processor::resizer::resize(
///     &std::fs::read("example/image.jpg").unwrap(),
///     Encoder {
///         encoder: Encode::Lossless(Lossless::Png),
///         width: Some(256),
///         height: None,
///         speed: None
///     },
/// );
///
/// file.write_all(buff.unwrap().buffer()).unwrap();
/// file.sync_all().unwrap();
/// ```
///
/// # Returns
///
/// Resized image buffer.
pub fn resize(buffer: &[u8], options: Encoder) -> Result<Vec<u8>, ImageError> {
    if options.width.is_none() && options.width.is_none() {
        return Err(ImageError::MissingWidthOrHeight);
    }

    let img = load_from_memory(buffer).map_err(ImageError::Image)?;

    let mut img_width = img.width();
    let mut img_height = img.height();

    // Proportion the right size according to the data to maintain a good ratio.
    if options.width.is_some() && options.height.is_none() {
        img_height = (f64::from(options.width.unwrap_or_default())
            / f64::from(img_width)
            * f64::from(img_height)) as u32;
    } else if options.width.is_none() && options.height.is_some() {
        img_width = (f64::from(options.height.unwrap_or_default())
            / f64::from(img_height)
            * f64::from(img_width)) as u32;
    }

    match options.encoder {
        crate::resizer::Encode::Lossy(encoder) => match encoder {
            crate::resizer::Lossy::Jpeg(quality) => image_encoder(
                img,
                img_width,
                img_height,
                Some(quality),
                ImageFormat::Jpeg,
            ),
        },
        crate::resizer::Encode::Lossless(encoder) => match encoder {
            crate::resizer::Lossless::Avif => image_encoder(
                img,
                img_width,
                img_height,
                None,
                ImageFormat::Avif,
            ),
            crate::resizer::Lossless::Png => image_encoder(
                img,
                img_width,
                img_height,
                None,
                ImageFormat::Png,
            ),
            crate::resizer::Lossless::WebP => image_encoder(
                img,
                img_width,
                img_height,
                None,
                ImageFormat::WebP,
            ),
        },
    }
}
