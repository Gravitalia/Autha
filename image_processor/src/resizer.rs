use anyhow::{bail, Result};
use fast_image_resize as fr;
use image::codecs::jpeg::JpegEncoder;
use image::{ColorType, ImageEncoder};
use std::io::BufWriter;
use std::num::NonZeroU32;

/// Image resizer.
///
/// # Example
/// ```no_run
/// use std::io::Write;
///
/// let mut file = std::fs::File::create("example/processed.jpg").unwrap();
/// let buff = image_processor::resizer::resize(
///     &std::fs::read("example/image.jpg").unwrap(),
///     Some(256),
///     None,
/// );
///
/// file.write_all(buff.unwrap().buffer()).unwrap();
/// file.sync_all().unwrap();
/// ```
///
/// # Returns
///
/// Resized image buffer as JPEG.
pub fn resize(
    buffer: &[u8],
    mut width: Option<u32>,
    mut height: Option<u32>,
) -> Result<BufWriter<Vec<u8>>> {
    if width.is_none() && height.is_none() {
        bail!("missing width or height")
    }

    let img = image::load_from_memory(buffer)?;

    let img_width = img.width();
    let img_height = img.height();

    // Proportion the right size according to the data to maintain a good ratio.
    if width.is_some() && height.is_none() {
        height = Some(
            (f64::from(width.unwrap_or_default()) / f64::from(img_width) * f64::from(img_height))
                as u32,
        );
    } else if width.is_none() && height.is_some() {
        width = Some(
            (f64::from(height.unwrap_or_default()) / f64::from(img_height) * f64::from(img_width))
                as u32,
        );
    }

    // If resized image is squared but not original one, warn user.
    if img_width != img_height && width == height {
        log::warn!("For the moment, there is no cropping to remove excess parts. The final rendered square will represent the squashed original image.");
    }

    let mut src_image = fr::Image::from_vec_u8(
        NonZeroU32::new(img_width).unwrap(),
        NonZeroU32::new(img_height).unwrap(),
        img.to_rgba8().into_raw(),
        fr::PixelType::U8x4,
    )?;

    // Multiple RGB channels of source image by alpha channel.
    let alpha_mul_div = fr::MulDiv::default();
    alpha_mul_div.multiply_alpha_inplace(&mut src_image.view_mut())?;

    // Create container for data of destination image
    let dst_width = NonZeroU32::new(width.unwrap_or_default()).unwrap();
    let dst_height = NonZeroU32::new(height.unwrap_or_default()).unwrap();
    let mut dst_image = fr::Image::new(dst_width, dst_height, src_image.pixel_type());

    // Get mutable view of destination image data.
    let mut dst_view = dst_image.view_mut();

    // Create Resizer instance and resize source image
    // into buffer of destination image.
    let mut resizer = fr::Resizer::new(fr::ResizeAlg::Convolution(fr::FilterType::Lanczos3));
    resizer.resize(&src_image.view(), &mut dst_view)?;

    // Divide RGB channels of destination image by alpha.
    alpha_mul_div.divide_alpha_inplace(&mut dst_view)?;

    // Convert into JPEG.
    let mut result_buf = BufWriter::new(Vec::new());
    JpegEncoder::new(&mut result_buf).write_image(
        dst_image.buffer(),
        dst_width.get(),
        dst_height.get(),
        ColorType::Rgba8,
    )?;

    Ok(result_buf)
}
