// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exhaustive error-variant integration tests for the pure-Rust Windows bridge
//! parsers (`AGENTS.md` Rule 2), covering every `ActivationError`,
//! `WindowsSelectionPath`, `UriValidationError`, NDJSON, and
//! `totaldrop_core::relay::check_url` rejection variant.

use std::error::Error as StdError;

use totaldrop_core::relay::check_url;
use totaldrop_windows_bridge::activation::{MAX_SELECTION_ITEMS, MAX_WINDOWS_PATH_UTF16};
use totaldrop_windows_bridge::{
    ActivationEnvelope, ActivationError, ScreenTarget, UriValidationError, ValidatedCode,
    WinUiBridgeMessage, WindowsSelectionPath, decode_ndjson_stream, parse_launch_args,
};

type TestResult = Result<(), Box<dyn StdError>>;

#[test]
fn activation_envelope_and_ndjson_reject_invalid_json_variants() -> TestResult {
    assert!(matches!(
        ActivationEnvelope::from_json_bytes(b"{not-valid-json"),
        Err(ActivationError::InvalidJson(_))
    ));
    assert!(matches!(
        ActivationEnvelope::from_json_bytes(b""),
        Err(ActivationError::InvalidJson(_))
    ));
    // Single-shot `decode_ipc_frame([0, 0, 0, 0])` forwards an empty payload to
    // `from_json_bytes(&[])` and returns `InvalidJson`.
    assert!(matches!(
        ActivationEnvelope::decode_ipc_frame(&[0, 0, 0, 0]),
        Err(ActivationError::InvalidJson(_))
    ));

    // NDJSON single-line parser must reject empty, multiline, interior CR, and
    // malformed JSON payloads with `ActivationError::InvalidJson`.
    let valid_line = WinUiBridgeMessage::mark_animation_state(true, true).to_ndjson_line()?;
    let trimmed = valid_line.trim_end_matches('\n');
    let two_lines_lf = format!("{trimmed}\n{trimmed}");
    let two_lines_cr = format!("{trimmed}\r{trimmed}");

    for bad_line in [
        "",
        "\n",
        "\r\n",
        "{not-json}",
        two_lines_lf.as_str(),
        two_lines_cr.as_str(),
    ] {
        assert!(
            matches!(
                WinUiBridgeMessage::from_ndjson_line(bad_line),
                Err(ActivationError::InvalidJson(_))
            ),
            "expected InvalidJson for NDJSON line {bad_line:?}"
        );
    }

    assert!(matches!(
        decode_ndjson_stream("{malformed\n"),
        Err(ActivationError::InvalidJson(_))
    ));
    let mixed_stream = format!("{valid_line}{{broken-second-line}}\n");
    assert!(matches!(
        decode_ndjson_stream(&mixed_stream),
        Err(ActivationError::InvalidJson(_))
    ));
    Ok(())
}

#[test]
fn explorer_selection_rejects_empty_and_over_limit_selections() {
    assert_eq!(
        ActivationEnvelope::explorer_send(Vec::<&str>::new(), None),
        Err(ActivationError::EmptyExplorerSelection)
    );
    assert_eq!(
        parse_launch_args(["--explorer-send"]),
        Err(ActivationError::EmptyExplorerSelection)
    );
    let empty_explorer_json =
        br#"{"version":1,"initiator_pid":null,"payload":{"kind":"explorer_send","paths":[]}}"#;
    assert_eq!(
        ActivationEnvelope::from_json_bytes(empty_explorer_json),
        Err(ActivationError::EmptyExplorerSelection)
    );

    let over_limit = MAX_SELECTION_ITEMS.saturating_add(1);
    let many_paths: Vec<String> = (0..over_limit)
        .map(|idx| format!(r"C:\Bulk\item_{idx}.bin"))
        .collect();
    assert_eq!(
        ActivationEnvelope::explorer_send(&many_paths, Some(42)),
        Err(ActivationError::TooManyItems { count: over_limit })
    );
    assert_eq!(
        ActivationEnvelope::share_target(&many_paths, None, Some(42)),
        Err(ActivationError::TooManyItems { count: over_limit })
    );

    // Confirm valid non-empty screen envelopes remain unaffected.
    let valid_screen = ActivationEnvelope::open_screen(ScreenTarget::Settings, None);
    assert_eq!(valid_screen.version, 1);
}

#[test]
fn windows_selection_path_reports_all_eight_error_variants() {
    // 1. EmptyPath
    assert_eq!(
        WindowsSelectionPath::parse(""),
        Err(ActivationError::EmptyPath)
    );
    assert_eq!(
        WindowsSelectionPath::parse(r"\\?\"),
        Err(ActivationError::EmptyPath)
    );

    // 2. ControlCharacter (C0, DEL, C1)
    for bad in [
        "   \t  ",
        "C:\\Users\\file\0.txt",
        "C:\\Users\\file\n.txt",
        "C:\\Users\\file\r.txt",
        "C:\\Users\\file\x7F.txt",
        "C:\\Users\\file\u{0085}.txt",
    ] {
        assert_eq!(
            WindowsSelectionPath::parse(bad),
            Err(ActivationError::ControlCharacter),
            "expected ControlCharacter for {bad:?}"
        );
    }

    // 3. PathTooLong (> MAX_WINDOWS_PATH_UTF16 = 32_766 UTF-16 code units)
    let mut long_path = String::from(r"C:\");
    let segment = "a".repeat(200);
    while long_path.encode_utf16().count() <= MAX_WINDOWS_PATH_UTF16 {
        long_path.push_str(&segment);
        long_path.push('\\');
    }
    long_path.push_str("tail.bin");
    match WindowsSelectionPath::parse(&long_path) {
        Err(ActivationError::PathTooLong { utf16_len }) => {
            assert!(utf16_len > MAX_WINDOWS_PATH_UTF16);
        }
        other => assert!(
            matches!(other, Err(ActivationError::PathTooLong { .. })),
            "expected PathTooLong, got {other:?}"
        ),
    }

    // 4. NotAbsoluteWindowsPath
    for bad in [
        r"relative\file.txt",
        r"C:relative.txt",
        r"\root-relative.txt",
        r"\\server-only",
        r"\\server\",
        r"1:\numeric-drive.txt",
    ] {
        assert_eq!(
            WindowsSelectionPath::parse(bad),
            Err(ActivationError::NotAbsoluteWindowsPath),
            "expected NotAbsoluteWindowsPath for {bad:?}"
        );
    }

    // 5. DeviceNamespaceForbidden (device prefixes + DOS reserved stems)
    for bad in [
        r"\\.\PhysicalDrive0",
        r"\\.\pipe\totaldrop",
        r"\\?\GLOBALROOT\Device\Harddisk0\DR0",
        r"\\?\Volume{00000000-0000-0000-0000-000000000000}\file.txt",
        r"C:\Users\CON",
        r"C:\Users\CON.txt",
        r"C:\Users\prn.tar.gz",
        r"C:\Users\aux",
        r"C:\Users\NUL.log",
        r"C:\Users\COM1",
        r"C:\Users\lpt9.bin",
        "C:\\Users\\COM\u{00B9}.txt",
        "C:\\Users\\LPT\u{00B3}",
    ] {
        assert_eq!(
            WindowsSelectionPath::parse(bad),
            Err(ActivationError::DeviceNamespaceForbidden),
            "expected DeviceNamespaceForbidden for {bad:?}"
        );
    }

    // 6. DotTraversalSegment
    for bad in [
        r"C:\Users\..\secret.txt",
        r"C:\Users\.\file.txt",
        r"\\fileserver\share\..\secret.txt",
    ] {
        assert_eq!(
            WindowsSelectionPath::parse(bad),
            Err(ActivationError::DotTraversalSegment),
            "expected DotTraversalSegment for {bad:?}"
        );
    }

    // 7. ForbiddenSegmentCharacter (including NTFS ADS `:`)
    for (bad, expected_ch) in [
        (r"C:\Users\doc.txt:Zone.Identifier", ':'),
        (r"C:\Users\a<b.txt", '<'),
        (r"C:\Users\a>b.txt", '>'),
        ("C:\\Users\\a\"b.txt", '"'),
        (r"C:\Users\a|b.txt", '|'),
        (r"C:\Users\a?b.txt", '?'),
        (r"C:\Users\a*b.txt", '*'),
    ] {
        assert_eq!(
            WindowsSelectionPath::parse(bad),
            Err(ActivationError::ForbiddenSegmentCharacter(expected_ch)),
            "expected ForbiddenSegmentCharacter({expected_ch:?}) for {bad:?}"
        );
    }

    // 8. TrailingDotOrSpace
    for bad in [
        r"C:\Users\file.txt.",
        r"C:\Users\file.txt ",
        r"C:\Users\dir \file.txt",
        r"\\fileserver\share\folder.\file.txt",
    ] {
        assert_eq!(
            WindowsSelectionPath::parse(bad),
            Err(ActivationError::TrailingDotOrSpace),
            "expected TrailingDotOrSpace for {bad:?}"
        );
    }
}

#[test]
fn clipboard_code_extraction_reports_no_code_found_in_text() {
    for text in [
        "\u{2068}\u{2069}",
        "   \u{2068}\u{2069}   ",
        "Hello team, please review the release checklist before noon.",
        "Order #42 shipped via express courier.",
    ] {
        let err = ValidatedCode::from_clipboard_text(text);
        assert_eq!(
            err,
            Err(UriValidationError::NoCodeFoundInText),
            "expected NoCodeFoundInText for {text:?}"
        );
    }
    assert_eq!(
        UriValidationError::NoCodeFoundInText.l10n_key(),
        "errorInvalidCode"
    );
}

#[test]
fn core_relay_check_url_rejects_userinfo_empty_authority_and_non_loopback_ws() {
    for rejected in [
        // Userinfo (`@`) in authority
        "wss://user@rendezvous.totaldrop.app",
        "wss://@rendezvous.totaldrop.app",
        "ws://localhost@evil.example",
        "ws://127.0.0.1:4000@evil.example",
        // Empty authority
        "wss://",
        "wss:///path",
        "ws://",
        "ws:///path",
        "ws://:8080",
        // Non-loopback plaintext ws://
        "ws://rendezvous.totaldrop.app",
        "ws://127.0.0.2:4000",
        "ws://localhost.evil.example",
        "ws://192.168.1.10:4000",
        // Non-WebSocket or uppercase schemes
        "http://127.0.0.1:4000",
        "https://rendezvous.totaldrop.app",
        "ftp://example.com",
        "WSS://rendezvous.totaldrop.app",
        "WS://localhost:4000",
    ] {
        assert!(
            check_url(rejected).is_err(),
            "expected relay::check_url to reject {rejected:?}"
        );
    }

    for accepted in [
        "wss://rendezvous.totaldrop.app",
        "wss://relay.totaldrop.app/v1",
        "ws://localhost:4000",
        "ws://127.0.0.1:4000",
        "ws://[::1]:8080",
    ] {
        assert!(
            check_url(accepted).is_ok(),
            "expected relay::check_url to accept {accepted:?}"
        );
    }
}
