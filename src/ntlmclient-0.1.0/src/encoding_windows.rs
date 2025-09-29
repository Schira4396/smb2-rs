//! Windows-specific encoding functions.
//!
//! On Windows, legacy programs use the configured ANSI character set and the operating system
//! provides functions to convert between this character set and Unicode. We use these to convert
//! between ANSI strings (represented as `Vec<u8>`) and Rust strings (decoded from UTF-16).


use windows::Win32::Globalization::{
    CP_ACP, MB_ERR_INVALID_CHARS, MB_PRECOMPOSED, MultiByteToWideChar, WC_COMPOSITECHECK,
    WideCharToMultiByte,
};


/// Converts the given ANSI string into a Rust string.
pub fn ansi_string_to_rust(ansi_string: &[u8]) -> Option<String> {
    if ansi_string.len() == 0 {
        // okay, this is easy
        return Some(String::new());
    }

    // first, obtain Unicode (UTF-16) string from the ANSI string

    // how many characters will we require?
    let wide_char_count = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            MB_ERR_INVALID_CHARS | MB_PRECOMPOSED,
            ansi_string,
            None,
        )
    };
    let wide_char_usize: usize = wide_char_count.try_into().ok()?;
    if wide_char_usize == 0 {
        return None;
    }

    let mut buf = vec![0u16; wide_char_usize];
    let chars_written = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            MB_ERR_INVALID_CHARS | MB_PRECOMPOSED,
            ansi_string,
            Some(buf.as_mut_slice()),
        )
    };
    let chars_written_usize: usize = chars_written.try_into().ok()?;
    if chars_written_usize == 0 {
        return None;
    }
    buf.truncate(chars_written_usize);

    // now, convert from UTF-16 to a Rust string
    String::from_utf16(&buf).ok()
}


/// Converts the given Rust string into an ANSI string.
pub fn rust_string_to_ansi(rust_str: &str) -> Option<Vec<u8>> {
    if rust_str.len() == 0 {
        return Some(Vec::new());
    }

    // first, obtain Unicode (UTF-16) string from the Rust string
    let unicode: Vec<u16> = rust_str.encode_utf16().collect();

    // then, convert to the ANSI codepage
    // how many bytes will we require?
    let byte_count = unsafe {
        WideCharToMultiByte(
            CP_ACP,
            WC_COMPOSITECHECK,
            &unicode,
            None,
            None,
            None,
        )
    };
    let byte_count_usize: usize = byte_count.try_into().ok()?;
    if byte_count_usize == 0 {
        return None;
    }

    let mut buf = vec![0u8; byte_count_usize];
    let bytes_written = unsafe {
        WideCharToMultiByte(
            CP_ACP,
            WC_COMPOSITECHECK,
            &unicode,
            Some(buf.as_mut_slice()),
            None,
            None,
        )
    };
    let bytes_written_usize: usize = bytes_written.try_into().ok()?;
    if bytes_written_usize == 0 {
        return None;
    }
    buf.truncate(bytes_written_usize);

    Some(buf)
}
