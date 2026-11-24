#![no_main]
// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! Windows activation URI, interactive transfer code, and clipboard extraction
//! invariants: exact equivalence with `totaldrop_proto::TransferCode`, ASCII
//! canonical/display/URI outputs, bidirectional LTR isolation, single-pass
//! percent-decoding, and strict rejection of trailing queries/paths and double
//! percent-encoding.

use libfuzzer_sys::fuzz_target;
use totaldrop_proto::{MAX_LINK_BYTES, TransferCode, strip_invisible_format};
use totaldrop_windows_bridge::{UriValidationError, ValidatedCode};

fuzz_target!(|data: &[u8]| {
    // Deterministically synthesize a valid 2- or 3-word numeric transfer code
    // from arbitrary bytes so random fuzz inputs continuously exercise all
    // round-trip and single/double percent-escape invariants.
    if data.len() >= 8 {
        let raw_nameplate = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let nameplate = if raw_nameplate == 0 { 1 } else { raw_nameplate };
        let w1 = u16::from_le_bytes([data[4], data[5]]) & 0x07FF;
        let w2 = u16::from_le_bytes([data[6], data[7]]) & 0x07FF;
        let synthesized = if (data[4] & 0x80) != 0 && data.len() >= 10 {
            let w3 = u16::from_le_bytes([data[8], data[9]]) & 0x07FF;
            format!("{nameplate}-{w1}-{w2}-{w3}")
        } else {
            format!("{nameplate}-{w1}-{w2}")
        };
        let validated = ValidatedCode::from_user_input(&synthesized)
            .expect("synthesized valid transfer code must parse");
        assert_eq!(validated.nameplate, nameplate);
        assert_validated_invariants(&validated);
    }

    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    check_input(s);

    if s.len() <= MAX_LINK_BYTES + 32 {
        for wrapped in [
            format!("totaldrop://r/{s}"),
            format!("https://totaldrop.app/r#{s}"),
            format!("totaldrop:{s}"),
        ] {
            check_activation_uri(&wrapped);
        }
    }
});

fn check_activation_uri(s: &str) {
    let uri_res = ValidatedCode::from_activation_uri(s);
    let proto_link = TransferCode::from_link(s).map(|c| ValidatedCode::from_proto(&c));
    assert_eq!(uri_res.as_ref().ok().cloned(), proto_link);

    match &uri_res {
        Ok(validated) => assert_validated_invariants(validated),
        Err(err) => {
            assert!(!err.l10n_key().is_empty());
            assert!(!err.to_string().is_empty());
            if s.len() > MAX_LINK_BYTES {
                assert_eq!(
                    *err,
                    UriValidationError::LinkTooLong {
                        byte_len: s.len(),
                        limit: MAX_LINK_BYTES,
                    }
                );
            } else if strip_invisible_format(s).trim().is_empty() {
                assert_eq!(*err, UriValidationError::Empty);
            } else {
                assert_eq!(*err, UriValidationError::InvalidActivationLink);
            }
        }
    }
}

fn check_input(s: &str) {
    check_activation_uri(s);

    // 2. Interactive user input equivalence: `from_link(s)` or `parse(s)`.
    let user_res = ValidatedCode::from_user_input(s);
    let expected_user = TransferCode::from_link(s)
        .or_else(|| TransferCode::parse(s).ok())
        .map(|c| ValidatedCode::from_proto(&c));
    assert_eq!(user_res.as_ref().ok().cloned(), expected_user);

    match &user_res {
        Ok(validated) => assert_validated_invariants(validated),
        Err(err) => {
            assert!(!err.l10n_key().is_empty());
            assert!(!err.to_string().is_empty());
            let stripped = strip_invisible_format(s);
            let trimmed = stripped.trim();
            if trimmed.is_empty() {
                assert_eq!(*err, UriValidationError::Empty);
            } else if trimmed.starts_with("totaldrop:")
                || trimmed.starts_with("https://")
                || trimmed.starts_with("http://")
            {
                assert_eq!(*err, UriValidationError::InvalidActivationLink);
            } else {
                let code_err = TransferCode::parse(s)
                    .expect_err("from_user_input error on non-link must fail TransferCode::parse");
                assert_eq!(*err, UriValidationError::from(code_err));
            }
        }
    }

    // 3. Clipboard extraction exact invariants (strict superset of `TransferCode::find`
    //    with token-embedded link precedence).
    let clip_res = ValidatedCode::from_clipboard_text(s);
    let trimmed = s.trim();
    assert_eq!(
        trimmed.is_empty(),
        clip_res == Err(UriValidationError::Empty)
    );

    let link_trimmed = TransferCode::from_link(trimmed).map(|c| ValidatedCode::from_proto(&c));
    let found = TransferCode::find(s).map(|c| ValidatedCode::from_proto(&c));

    if let Some(expected) = &link_trimmed {
        assert_eq!(clip_res.as_ref().ok(), Some(expected));
    }
    if found.is_some() {
        assert!(clip_res.is_ok());
    }

    match &clip_res {
        Ok(validated) => {
            assert_validated_invariants(validated);
            if link_trimmed.is_none() && found.as_ref() != Some(validated) {
                let has_token_link = trimmed.split_whitespace().any(|token| {
                    let clean = token
                        .trim_matches(|c: char| matches!(c, '(' | ')' | '<' | '>' | '"' | '.'));
                    (clean.starts_with("https://totaldrop.app/r#")
                        || clean.starts_with("http://totaldrop.app/r#")
                        || clean.starts_with("totaldrop://r/"))
                        && TransferCode::from_link(clean)
                            .map(|c| ValidatedCode::from_proto(&c))
                            .as_ref()
                            == Some(validated)
                });
                assert!(
                    has_token_link,
                    "clipboard accepted {validated:?} without matching link or find for {s:?}"
                );
            }
        }
        Err(err) => {
            assert!(!err.l10n_key().is_empty());
            assert!(!err.to_string().is_empty());
            assert!(link_trimmed.is_none());
            assert!(found.is_none());
            if trimmed.is_empty() {
                assert_eq!(*err, UriValidationError::Empty);
            } else {
                assert_eq!(*err, UriValidationError::NoCodeFoundInText);
            }
        }
    }
}

fn assert_validated_invariants(v: &ValidatedCode) {
    assert!(v.nameplate > 0);
    assert!(matches!(v.word_count, 2 | 3));
    assert_eq!(v.is_strong(), v.word_count == 3);
    assert!(v.canonical.is_ascii());
    assert!(v.display_english.is_ascii());
    assert!(v.protocol_uri.is_ascii());
    assert!(v.web_uri.is_ascii());
    assert_eq!(
        v.protocol_uri,
        format!("totaldrop://r/{}", v.display_english)
    );
    assert_eq!(
        v.web_uri,
        format!("https://totaldrop.app/r#{}", v.display_english)
    );
    assert_eq!(
        v.ltr_isolated,
        format!("\u{2068}{}\u{2069}", v.display_english)
    );

    // Round-trip stability across all three public entry points.
    assert_eq!(
        ValidatedCode::from_activation_uri(&v.protocol_uri),
        Ok(v.clone())
    );
    assert_eq!(
        ValidatedCode::from_activation_uri(&v.web_uri),
        Ok(v.clone())
    );
    assert_eq!(
        ValidatedCode::from_activation_uri(&v.display_english),
        Ok(v.clone())
    );
    assert_eq!(
        ValidatedCode::from_activation_uri(&v.canonical),
        Ok(v.clone())
    );

    assert_eq!(
        ValidatedCode::from_user_input(&v.protocol_uri),
        Ok(v.clone())
    );
    assert_eq!(ValidatedCode::from_user_input(&v.web_uri), Ok(v.clone()));
    assert_eq!(
        ValidatedCode::from_user_input(&v.display_english),
        Ok(v.clone())
    );
    assert_eq!(ValidatedCode::from_user_input(&v.canonical), Ok(v.clone()));
    assert_eq!(
        ValidatedCode::from_user_input(&v.ltr_isolated),
        Ok(v.clone())
    );

    assert_eq!(
        ValidatedCode::from_clipboard_text(&v.protocol_uri),
        Ok(v.clone())
    );
    assert_eq!(
        ValidatedCode::from_clipboard_text(&v.web_uri),
        Ok(v.clone())
    );
    assert_eq!(
        ValidatedCode::from_clipboard_text(&v.ltr_isolated),
        Ok(v.clone())
    );
    assert_eq!(
        ValidatedCode::from_clipboard_text(&format!("Open TotalDrop: ({}).", v.web_uri)),
        Ok(v.clone())
    );

    // Strict boundary and single-pass percent-decoding checks.
    assert_eq!(
        ValidatedCode::from_activation_uri(&format!("{}?x=1", v.protocol_uri)),
        Err(UriValidationError::InvalidActivationLink)
    );
    assert_eq!(
        ValidatedCode::from_activation_uri(&format!("{}/extra", v.protocol_uri)),
        Err(UriValidationError::InvalidActivationLink)
    );
    let once = percent_escape(&v.display_english);
    assert_eq!(
        ValidatedCode::from_activation_uri(&format!("totaldrop://r/{once}")),
        Ok(v.clone())
    );
    assert_eq!(
        ValidatedCode::from_activation_uri(&format!("totaldrop://r/{}", percent_escape(&once))),
        Err(UriValidationError::InvalidActivationLink)
    );
}

fn percent_escape(s: &str) -> String {
    s.bytes().map(|b| format!("%{b:02X}")).collect()
}
