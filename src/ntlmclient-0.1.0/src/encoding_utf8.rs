//! UTF-8 encoding functions. Used on operating systems other than Windows.
//!
//! Other operating systems do not have a concept of the ANSI character set. While a custom
//! character set may be chosen, the absolute majority of systems use UTF-8.


/// Converts the given ANSI string into a Rust string.
pub fn ansi_string_to_rust(ansi_string: &[u8]) -> Option<String> {
    // naive UTF-8 conversion
    String::from_utf8(Vec::from(ansi_string)).ok()
}


/// Converts the given Rust string into an ANSI string.
pub fn rust_string_to_ansi(rust_str: &str) -> Option<Vec<u8>> {
    // naive UTF-8 conversion
    Some(Vec::from(rust_str.as_bytes()))
}
