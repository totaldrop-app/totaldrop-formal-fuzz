#![no_main]
// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! Windows selection path parser invariants: unconditional idempotence across
//! extended and unprefixed forms, strict rejection of device namespaces, dot
//! traversal segments, NTFS alternate data streams, and DOS reserved stems,
//! UTF-16 length cap enforcement (`<= 32,766`), and safe display sanitization.

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use totaldrop_l10n::is_hidden;
use totaldrop_windows_bridge::activation::{
    LEGACY_MAX_PATH_THRESHOLD_UTF16, MAX_WINDOWS_PATH_UTF16,
};
use totaldrop_windows_bridge::{WindowsRootKind, WindowsSelectionPath};

const RESERVED_DOS_STEMS: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

const FORBIDDEN_SEGMENT_CHARS: [char; 9] = ['/', '\\', ':', '<', '>', '"', '|', '?', '*'];

const STRUCTURED_PROBE_LIMIT: usize = 4_096;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(parsed) = WindowsSelectionPath::parse(s) {
        check_accepted(parsed);
    }

    if s.len() <= STRUCTURED_PROBE_LIMIT {
        for probe in [
            format!(r"C:\{s}"),
            format!(r"\\?\C:\{s}"),
            format!(r"\\srv\shr\{s}"),
            format!(r"\\?\UNC\srv\shr\{s}"),
        ] {
            if let Ok(parsed) = WindowsSelectionPath::parse(&probe) {
                check_accepted(parsed);
            }
        }

        // Mandatory security rejections that must never parse as valid paths.
        for forbidden in [
            format!(r"\\.\{s}"),
            format!(r"\\?\GLOBALROOT\{s}"),
            format!(r"C:\{s}\..\file.txt"),
            format!(r"C:\a\{s}:stream"),
            format!(r"C:\{s}\CON.txt"),
            format!(r"C:\{s}\lpt1"),
        ] {
            assert!(
                WindowsSelectionPath::parse(&forbidden).is_err(),
                "path validator accepted forbidden input: {forbidden:?}"
            );
        }
    }
});

fn check_accepted(path: WindowsSelectionPath) {
    // 1. Unconditional idempotence across extended, unprefixed, and serde string forms.
    assert_eq!(
        WindowsSelectionPath::parse(path.extended_path()),
        Ok(path.clone())
    );
    assert_eq!(
        WindowsSelectionPath::parse(path.unprefixed_path()),
        Ok(path.clone())
    );
    assert_eq!(
        WindowsSelectionPath::try_from(String::from(path.clone())),
        Ok(path.clone())
    );

    // 2. Device namespace prefix `\\.\` must never appear.
    assert!(!path.extended_path().starts_with(r"\\.\"));
    assert!(!path.unprefixed_path().starts_with(r"\\.\"));

    // 3. Exact Drive / UNC root structure and per-segment invariants.
    match path.root_kind() {
        WindowsRootKind::Drive => {
            let ext_body = path
                .extended_path()
                .strip_prefix(r"\\?\")
                .expect("drive extended path must start with \\\\?\\");
            assert_eq!(ext_body, path.unprefixed_path());
            let mut chars = path.unprefixed_path().chars();
            let drive = chars
                .next()
                .expect("drive path must start with drive letter");
            assert!(drive.is_ascii_uppercase());
            assert_eq!(chars.next(), Some(':'));
            assert_eq!(chars.next(), Some('\\'));
            let rest = chars.as_str();
            // Guard `C:\` root where `rest` is empty (`"".split('\\')` yields `[""]`).
            if !rest.is_empty() {
                for segment in rest.split('\\') {
                    check_segment(segment);
                }
            }
        }
        WindowsRootKind::Unc => {
            let ext_body = path
                .extended_path()
                .strip_prefix(r"\\?\UNC\")
                .expect("UNC extended path must start with \\\\?\\UNC\\");
            let unp_body = path
                .unprefixed_path()
                .strip_prefix(r"\\")
                .expect("UNC unprefixed path must start with \\\\");
            assert_eq!(ext_body, unp_body);
            let segments: Vec<&str> = unp_body.split('\\').collect();
            assert!(segments.len() >= 2);
            assert_ne!(segments[0], ".");
            assert_ne!(segments[0], "?");
            for segment in segments {
                check_segment(segment);
            }
        }
    }

    // 4. UTF-16 length cap and legacy MAX_PATH threshold consistency.
    let ext_utf16 = path.extended_path().encode_utf16().count();
    let unp_utf16 = path.unprefixed_path().encode_utf16().count();
    assert_eq!(path.utf16_len(), ext_utf16);
    assert!(path.utf16_len() <= MAX_WINDOWS_PATH_UTF16);
    assert!(unp_utf16 < ext_utf16);
    assert_eq!(
        path.exceeds_legacy_max_path(),
        unp_utf16 >= LEGACY_MAX_PATH_THRESHOLD_UTF16
    );

    // 5. No C0/DEL/C1 control characters and no hidden controls in safe display output.
    assert!(!path.extended_path().chars().any(is_disallowed_control));
    let safe_display = path.safe_display_path();
    assert!(!safe_display.chars().any(is_hidden));

    // 6. Deduplication key and `AsRef<Path>` consistency.
    assert_eq!(
        path.deduplication_key(),
        path.extended_path().to_lowercase()
    );
    let as_path: &Path = path.as_ref();
    assert_eq!(as_path, Path::new(path.extended_path()));
}

fn check_segment(segment: &str) {
    assert!(!segment.is_empty());
    assert_ne!(segment, ".");
    assert_ne!(segment, "..");
    assert!(!segment.ends_with('.'));
    assert!(!segment.ends_with(' '));
    assert!(
        !segment
            .chars()
            .any(|ch| FORBIDDEN_SEGMENT_CHARS.contains(&ch)),
        "accepted segment contains forbidden character: {segment:?}"
    );
    assert!(!segment.chars().any(is_disallowed_control));
    assert!(
        !is_reserved_dos_segment(segment),
        "accepted segment is a DOS reserved stem: {segment:?}"
    );
}

fn is_disallowed_control(ch: char) -> bool {
    let code = u32::from(ch);
    code <= 0x1F || (0x7F..=0x9F).contains(&code)
}

fn is_reserved_dos_segment(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or("").trim_end();
    let upper = stem.to_ascii_uppercase();
    RESERVED_DOS_STEMS.contains(&upper.as_str())
        || matches!(
            upper.as_str(),
            "COM\u{00B9}"
                | "COM\u{00B2}"
                | "COM\u{00B3}"
                | "LPT\u{00B9}"
                | "LPT\u{00B2}"
                | "LPT\u{00B3}"
        )
}
