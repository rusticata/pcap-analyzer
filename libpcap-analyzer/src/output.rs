use libpcap_tools::Config;
use std::fs::File;
use std::io::Error;
use std::path::PathBuf;

/// Get the base prefix of output directory (or "." if not specified)
pub fn get_output_dir(config: &Config) -> &str {
    config.get("output_dir").unwrap_or(".")
}

/// Create a file to output data
pub fn create_file<P: AsRef<str>>(base: &str, filename: P) -> Result<File, Error> {
    let mut path = PathBuf::from(base);
    path.push(filename.as_ref());
    File::create(path)
}
