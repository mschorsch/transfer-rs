// inspired by https://github.com/parshap/node-sanitize-filename
//
use regex::Regex;

lazy_static! {
// illegal characters / ? < > \ : * | "
// https://kb.acronis.com/content/39790
    static ref ILLEGAL_RE: Regex = Regex::new(r"[\x{002F}\x{003F}\x{003C}\x{003E}\x{005C}\x{003A}\x{002A}\x{007C}\x{0022}]").unwrap();

// Unicode Control codes
// C0 0x00-0x1f & C1 (0x80-0x9f)
// http://en.wikipedia.org/wiki/C0_and_C1_control_codes
    static ref CONTROL_RE: Regex = Regex::new(r"[\x00-\x1f\x80-\x9f]").unwrap();

// Reserved filenames on Unix-based systems (".", "..")
    static ref RESERVED_RE: Regex = Regex::new(r"^\.+$").unwrap();

//  Reserved filenames in Windows ("CON", "PRN", "AUX", "NUL", "COM1",
//  "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
//  "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", and
//  "LPT9")
    static ref WINDOWS_RESERVED_RE: Regex = Regex::new(r"^(?i)(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$").unwrap();
    static ref WINDOWS_TRAILING_RE: Regex = Regex::new(r"[\. ]+$").unwrap();
}

pub fn sanitize_filename(filename: &str) -> String {
    let sanitized = ILLEGAL_RE.replace_all(&filename, "");
    let sanitized = CONTROL_RE.replace_all(&sanitized, "");
    let sanitized = RESERVED_RE.replace_all(&sanitized, "");
    let sanitized = WINDOWS_RESERVED_RE.replace_all(&sanitized, "");
    let mut sanitized = WINDOWS_TRAILING_RE.replace_all(&sanitized, "");

    // capped at 255 characters
    // http://unix.stackexchange.com/questions/32795/what-is-the-maximum-allowed-filename-and-folder-size-with-ecryptfs
    sanitized.truncate(255);

    return sanitized;
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_sanitize_filename1() {
        assert_eq!(sanitize_filename("../../file.txt"), "....file.txt");
    }

    #[test]
    fn test_sanitize_filename2() {
        assert_eq!(sanitize_filename("../../fileÊ.txt"), "....fileÊ.txt");
    }

    #[test]
    fn test_sanitize_filename3() {
        assert_eq!(sanitize_filename("normal.a"), "normal.a");
    }

    #[test]
    fn test_sanitize_filename4() {
        assert_eq!(sanitize_filename("..\normal.a\\."), "..ormal.a");
    }

    #[test]
    fn test_sanitize_filename5() {
        assert_eq!(sanitize_filename("*my.txt*"), "my.txt");
        assert_eq!(sanitize_filename("*my.t?xt*"), "my.txt");
    }
}