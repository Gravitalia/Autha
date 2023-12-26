use anyhow::Result;
use cloudinary::upload::{Source::Path, Upload, UploadOptions};
use crypto::hash::sha1;
use std::io::Write;
use tempfile::NamedTempFile;

/// Cloudinary credentials structure to upload images.
pub struct Credentials {
    /// Cloudinary API key.
    pub key: String,
    /// Cloudinary cloud name.
    pub cloud_name: String,
    /// Cloudinary API secret.
    /// Should never be shared!
    pub secret: String,
}

/// Upload image buffer into Cloudinary.
///
/// # Example
/// ```rust
/// let credentials = image_processor::host::cloudinary::Credentials {
///     key: "111111111111111".to_string(),
///     cloud_name: "aaaaa1234".to_string(),
///     secret: "SECRET_KEY".to_string(),
/// };
/// let buffer = std::fs::read("example/image.webp").unwrap();
/// 
/// let _ = image_processor::host::cloudinary::upload(credentials, &buffer);
///
/// // Log public ID.
/// /*println!(
///     "Public ID: {}",
///     image_processor::host::cloudinary::upload(credentials, buffer)
///         .await
///         .unwrap()
/// );*/
/// ```
/// 
/// # Returns
/// SHA1 buffer hash.
pub async fn upload(credentials: Credentials, buffer: &[u8]) -> Result<String> {
    // Hash buffer image to obtain unique identifier.
    let hash = sha1(buffer)?;

    // Set public ID.
    let options = UploadOptions::new().set_public_id(hash.clone());

    // Set credentials.
    let upload = Upload::new(credentials.key, credentials.cloud_name, credentials.secret);

    // Create temporary file into the memory and write on it.
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(buffer)?;

    // Then, get Pathbuf of the file.
    let path_buf = temp_file.path().to_path_buf();

    // Upload image on Cloudinary.
    upload.image(Path(path_buf), &options).await?;

    Ok(hash)
}
