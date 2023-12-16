use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub fn remove_exif(path: &Path) -> Result<(), exif::Error> {
    let file = File::open(path)?;
    let exif = exif::Reader::new().read_from_container(&mut BufReader::new(&file))?;

    println!("{}", path.display());
    for f in exif.fields() {
        println!(
            "  {}/{}: {}",
            f.ifd_num.index(),
            f.tag,
            f.display_value().with_unit(&exif)
        );
        println!("      {:?}", f.value);
    }

    Ok(())
}
