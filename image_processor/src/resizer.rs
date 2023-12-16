#![allow(unused_imports)]
#![allow(dead_code)]
use fast_image_resize as fr;
use image::codecs::png::PngEncoder;
use image::io::Reader as ImageReader;
use image::{ColorType, ImageEncoder};
use std::io::BufWriter;
use std::num::NonZeroU32;

pub fn resize(_width: usize, _height: usize) {}
