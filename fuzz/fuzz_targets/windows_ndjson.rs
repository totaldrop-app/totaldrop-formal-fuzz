#![no_main]
// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! Windows NDJSON view-model stream codec and `totaldrop_core::relay::check_url`
//! policy invariants: panic-freedom on arbitrary UTF-8 streams, single-line and
//! multi-variant batch round-trip idempotence, CRLF/blank-line tolerance, and
//! strict rejection of `@` userinfo, empty authorities, and non-loopback `ws://`.

use libfuzzer_sys::fuzz_target;
use totaldrop_core::relay::check_url;
use totaldrop_windows_bridge::{
    ActivationError, BridgeNetworkConfig, LocalizedTransferError, RegionalPercent, RouterDecision,
    ScreenTarget, TransferViewEvent, ValidatedCode, WinUiBridgeMessage, WinUiFlowDirection,
    WindowsSelectionPath, WindowsUiBundle, decode_ndjson_stream, encode_ndjson_batch,
    sanitize_peer_text,
};

const SYNTHESIS_LIMIT: usize = 8_192;
const URL_MUTATION_LIMIT: usize = 4_096;

fuzz_target!(|data: &[u8]| {
    // 1. Empty batch invariants.
    assert_eq!(encode_ndjson_batch(&[]), Ok(String::new()));
    assert_eq!(decode_ndjson_stream(""), Ok(Vec::new()));

    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // 2. Arbitrary NDJSON stream decoding and round-trip idempotence.
    if let Ok(batch) = decode_ndjson_stream(s) {
        let encoded = encode_ndjson_batch(&batch).expect("decoded NDJSON batch must encode");
        if batch.is_empty() {
            assert!(encoded.is_empty());
        } else {
            assert_eq!(encoded.lines().count(), batch.len());
            assert!(encoded.ends_with('\n'));
        }
        let round_tripped =
            decode_ndjson_stream(&encoded).expect("encoded NDJSON batch must decode");
        assert_eq!(round_tripped, batch);
        assert_eq!(encode_ndjson_batch(&round_tripped), Ok(encoded.clone()));

        let with_crlf = format!("\r\n  \n{}\r\n\t\n", encoded.replace('\n', "\r\n\n"));
        assert_eq!(decode_ndjson_stream(&with_crlf), Ok(batch));
    }

    // 3. Single-line NDJSON parser invariants.
    let trimmed = s.trim_end_matches(['\r', '\n']);
    let line_res = WinUiBridgeMessage::from_ndjson_line(s);
    if trimmed.is_empty() || trimmed.contains('\n') || trimmed.contains('\r') {
        assert!(matches!(line_res, Err(ActivationError::InvalidJson(_))));
    }
    if let Ok(msg) = line_res {
        let encoded = msg
            .to_ndjson_line()
            .expect("decoded WinUiBridgeMessage must encode");
        assert!(encoded.ends_with('\n'));
        let body = encoded.strip_suffix('\n').expect("trailing LF");
        assert!(!body.contains('\n') && !body.contains('\r'));
        assert_eq!(
            WinUiBridgeMessage::from_ndjson_line(&encoded),
            Ok(msg.clone())
        );
        assert_eq!(decode_ndjson_stream(&encoded), Ok(vec![msg]));
    }

    // 4. Structured multi-variant synthesis covering all 5 `WinUiBridgeMessage`
    //    variants with arbitrary UTF-8 payloads (including raw newlines/quotes/Bidi).
    if s.len() <= SYNTHESIS_LIMIT {
        let batch = synthesize_all_variants(s, data);
        let encoded = encode_ndjson_batch(&batch).expect("synthesized batch must encode");
        assert_eq!(encoded.lines().count(), batch.len());
        assert!(encoded.ends_with('\n'));
        assert_eq!(decode_ndjson_stream(&encoded), Ok(batch.clone()));
        assert_eq!(encode_ndjson_batch(&batch), Ok(encoded.clone()));
        let with_crlf = format!("\r\n\n{}\r\n  \n", encoded.replace('\n', "\r\n\n"));
        assert_eq!(decode_ndjson_stream(&with_crlf), Ok(batch));
    }

    // 5. `totaldrop_core::relay::check_url` security policy invariants.
    check_url_invariants(s);
});

fn synthesize_all_variants(s: &str, raw: &[u8]) -> Vec<WinUiBridgeMessage> {
    let b0 = raw.first().copied().unwrap_or(0);
    let b1 = raw.get(1).copied().unwrap_or(1);
    let flag = (b0 & 1) != 0;
    let pid = if flag { Some(u32::from(b1) + 1) } else { None };
    let screen = match b0 & 3 {
        0 => ScreenTarget::Send,
        1 => ScreenTarget::Clipboard,
        2 => ScreenTarget::Receive,
        _ => ScreenTarget::Settings,
    };

    let split_idx = floor_char_boundary(s, s.len() / 2);
    let (part_a, part_b) = s.split_at(split_idx);

    let bundle = WindowsUiBundle {
        language_tag: part_a.to_owned(),
        region_tag: part_b.to_owned(),
        flow_direction: if flag {
            WinUiFlowDirection::RightToLeft
        } else {
            WinUiFlowDirection::LeftToRight
        },
        has_draft_translations: flag,
        explorer_send_with: s.to_owned(),
        app_tagline: part_a.to_owned(),
        send_title: part_b.to_owned(),
        send_add_files: s.to_owned(),
        send_drop_here: part_a.to_owned(),
        send_drop_hint: part_b.to_owned(),
        send_strong_code: part_a.to_owned(),
        send_strong_code_hint: part_b.to_owned(),
        send_create_code: part_a.to_owned(),
        send_your_code: part_b.to_owned(),
        send_copy: part_a.to_owned(),
        send_share: part_b.to_owned(),
        receive_title: part_a.to_owned(),
        receive_code_label: part_b.to_owned(),
        receive_code_hint: "7-harbor-rocket".to_owned(),
        receive_paste: part_a.to_owned(),
        receive_connect: part_b.to_owned(),
        receive_accept: part_a.to_owned(),
        receive_decline: part_b.to_owned(),
        verification_title: part_a.to_owned(),
        verification_hint: part_b.to_owned(),
        settings_title: part_a.to_owned(),
        cancel: part_b.to_owned(),
        keep_awake_reason: s.to_owned(),
        version_label: part_a.to_owned(),
    };

    let mut batch = vec![
        WinUiBridgeMessage::UiBundleReady(Box::new(bundle)),
        WinUiBridgeMessage::RouteDecision(RouterDecision::RejectBusy {
            localized_banner: s.to_owned(),
        }),
        WinUiBridgeMessage::RouteDecision(RouterDecision::SwitchScreen {
            screen,
            initiator_pid: pid,
        }),
        WinUiBridgeMessage::RouteDecision(RouterDecision::NavigateSendText {
            raw_text: s.to_owned(),
            sanitized_preview: sanitize_peer_text(s),
            initiator_pid: pid,
        }),
        WinUiBridgeMessage::TransferEvent(TransferViewEvent::Waiting {
            caption: s.to_owned(),
        }),
        WinUiBridgeMessage::TransferEvent(TransferViewEvent::Connected {
            verification_words: vec![part_a.to_owned(), part_b.to_owned()],
            joined_words_ltr: s.to_owned(),
        }),
        WinUiBridgeMessage::TransferEvent(TransferViewEvent::Progress {
            done_bytes: u64::from(b0),
            total_bytes: u64::from(b0) + u64::from(b1),
            formatted_done: part_a.to_owned(),
            formatted_total: part_b.to_owned(),
            percent: RegionalPercent {
                whole: b0 % 101,
                formatted: part_a.to_owned(),
            },
        }),
        WinUiBridgeMessage::TransferFailed(LocalizedTransferError {
            summary: s.to_owned(),
            cause_detail: if flag { Some(part_b.to_owned()) } else { None },
            technical_english: part_a.to_owned(),
        }),
        WinUiBridgeMessage::mark_animation_state(flag, !flag),
        WinUiBridgeMessage::MarkAnimationState {
            animate: flag,
            hex_light: part_a.to_owned(),
            hex_dark: part_b.to_owned(),
            cycle_ms: u32::from(b1) * 100,
        },
    ];

    if let Ok(path) = WindowsSelectionPath::parse(s) {
        batch.push(WinUiBridgeMessage::RouteDecision(
            RouterDecision::NavigateSendFiles {
                paths: vec![path],
                initiator_pid: pid,
            },
        ));
    } else if let Ok(sample_path) = WindowsSelectionPath::parse(r"C:\Users\TotalDrop\sample.bin") {
        batch.push(WinUiBridgeMessage::RouteDecision(
            RouterDecision::NavigateSendFiles {
                paths: vec![sample_path],
                initiator_pid: pid,
            },
        ));
    }

    if let Ok(code) = ValidatedCode::from_user_input(s) {
        batch.push(WinUiBridgeMessage::RouteDecision(
            RouterDecision::NavigateReceiveCode {
                code,
                initiator_pid: pid,
            },
        ));
    } else if let Ok(sample_code) = ValidatedCode::from_user_input("7-harbor-rocket") {
        batch.push(WinUiBridgeMessage::RouteDecision(
            RouterDecision::NavigateReceiveCode {
                code: sample_code,
                initiator_pid: pid,
            },
        ));
    }

    batch
}

fn floor_char_boundary(s: &str, mut index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    while index > 0 && !s.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn check_url_invariants(s: &str) {
    if check_url(s).is_ok() {
        let after_scheme = if let Some(rest) = s.strip_prefix("wss://") {
            rest
        } else if let Some(rest) = s.strip_prefix("ws://") {
            rest
        } else {
            panic!("relay::check_url accepted non-ws(s) scheme: {s:?}");
        };
        let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
        assert!(
            !authority.is_empty(),
            "relay::check_url accepted empty authority: {s:?}"
        );
        assert!(
            !authority.contains('@'),
            "relay::check_url accepted '@' userinfo in authority: {s:?}"
        );
        if s.starts_with("ws://") {
            let host = if authority.starts_with('[') {
                authority
                    .find(']')
                    .map_or(authority, |end| &authority[..=end])
            } else {
                authority.split(':').next().unwrap_or("")
            };
            assert!(
                matches!(host, "localhost" | "127.0.0.1" | "[::1]"),
                "relay::check_url accepted non-loopback ws:// host {host:?} in {s:?}"
            );
        }
    }

    if s.len() <= URL_MUTATION_LIMIT {
        for rejected in [
            format!("wss://user@{s}"),
            format!("ws://localhost@{s}"),
            format!("ws://127.0.0.1:4000@{s}"),
            format!("wss:///{s}"),
            format!("ws:///{s}"),
            format!("ws://example.com/{s}"),
            format!("http://{s}"),
            format!("https://{s}"),
        ] {
            assert!(
                check_url(&rejected).is_err(),
                "relay::check_url failed to reject adversarial URL: {rejected:?}"
            );
        }
    }

    for rejected in [
        "wss://",
        "ws://",
        "ws://:8080",
        "ws://127.0.0.2",
        "ws://localhost.evil.com",
    ] {
        assert!(check_url(rejected).is_err());
    }
    for accepted in [
        "wss://rendezvous.totaldrop.app",
        "ws://localhost:4000",
        "ws://127.0.0.1:4000",
        "ws://[::1]:8080",
    ] {
        assert!(check_url(accepted).is_ok());
    }

    // Exercise `BridgeNetworkConfig::is_valid_rendezvous_url` for panic-freedom
    // only (the vendored `d3c2cb96` snapshot predates delegating it to
    // `totaldrop_core::relay::check_url`).
    let _ = BridgeNetworkConfig::is_valid_rendezvous_url(s);
}
