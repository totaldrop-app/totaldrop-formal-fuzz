#![no_main]
// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! Win32 command-line quoting, `CommandLineToArgvW` splitting, launch argument
//! parsing, and Explorer invocation planning invariants: exact control-char
//! rejection, lossless quote-join-split round-trip on arbitrary UTF-8 vectors,
//! `skip_executable` equivalence, and panic-freedom.

use libfuzzer_sys::fuzz_target;
use totaldrop_windows_bridge::activation::{ENVELOPE_SCHEMA_VERSION, MAX_COMMAND_LINE_UTF16};
use totaldrop_windows_bridge::{
    ActivationEnvelope, ActivationError, ExplorerLaunchTransport, MAX_IPC_FRAME_BYTES,
    parse_launch_args, plan_explorer_invocation, quote_win32_arg, session_named_pipe_path,
    split_win32_command_line,
};

const SAMPLE_EXE_PATH: &str = r"C:\Program Files\TotalDrop\totaldrop-winui.exe";

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // 1. Raw command-line splitting and `skip_executable` equivalence.
    let with_exe = split_win32_command_line(s, false);
    let without_exe = split_win32_command_line(s, true);
    if s.contains('\0') {
        assert_eq!(with_exe, Err(ActivationError::MalformedCommandLine));
        assert_eq!(without_exe, Err(ActivationError::MalformedCommandLine));
    }

    match (&with_exe, &without_exe) {
        (Ok(all), Ok(rest)) => {
            let expected_rest: Vec<String> = all.iter().skip(1).cloned().collect();
            assert_eq!(rest, &expected_rest);

            // Re-quoting round-trip holds whenever input contains no `\r`/`\n`
            // (which `split_win32_command_line` allows but `quote_win32_arg`
            // intentionally rejects).
            if !s.contains('\r') && !s.contains('\n') {
                let requoted: Vec<String> = all
                    .iter()
                    .map(|tok| quote_win32_arg(tok).expect("control-free token must quote"))
                    .collect();
                let rejoined = requoted.join(" ");
                assert_eq!(split_win32_command_line(&rejoined, false), Ok(all.clone()));
                assert_eq!(split_win32_command_line(&rejoined, true), Ok(rest.clone()));
            }

            check_launch_args(all);
        }
        (Err(e1), Err(e2)) => assert_eq!(e1, e2),
        _ => panic!("skip_executable divergence: {with_exe:?} vs {without_exe:?}"),
    }

    // 2. Arbitrary argument vector quoting, splitting, and launch-arg parsing.
    let empty_vec: Vec<&str> = Vec::new();
    check_arg_vector(&empty_vec);
    check_arg_vector(&[s]);
    let split_args: Vec<&str> = s.split('\u{1f}').collect();
    check_arg_vector(&split_args);
});

fn check_arg_vector(raw_args: &[&str]) {
    // Exact iff for `quote_win32_arg` control-character rejection.
    for &arg in raw_args {
        let has_forbidden = arg.chars().any(|c| matches!(c, '\0' | '\r' | '\n'));
        match quote_win32_arg(arg) {
            Ok(quoted) => {
                assert!(!has_forbidden);
                assert!(!quoted.contains('\0'));
                assert!(!quoted.contains('\r'));
                assert!(!quoted.contains('\n'));
            }
            Err(ActivationError::ControlCharacter) => assert!(has_forbidden),
            Err(other) => panic!("unexpected quote_win32_arg error: {other:?}"),
        }
    }

    // `parse_launch_args` must never panic even when raw args contain controls.
    let raw_owned: Vec<String> = raw_args.iter().map(|&a| a.to_owned()).collect();
    check_launch_args(&raw_owned);

    // Strip only `\0`, `\r`, `\n` so every fuzz input exercises lossless
    // multi-argument round-tripping across quotes, backslashes, and spaces.
    let clean_args: Vec<String> = raw_args
        .iter()
        .map(|a| {
            a.chars()
                .filter(|c| !matches!(c, '\0' | '\r' | '\n'))
                .collect()
        })
        .collect();
    let quoted: Vec<String> = clean_args
        .iter()
        .map(|arg| quote_win32_arg(arg).expect("clean argument must quote"))
        .collect();
    let joined = quoted.join(" ");
    assert_eq!(
        split_win32_command_line(&joined, false),
        Ok(clean_args.clone())
    );
    let expected_skip: Vec<String> = clean_args.iter().skip(1).cloned().collect();
    assert_eq!(split_win32_command_line(&joined, true), Ok(expected_skip));
}

fn check_launch_args(tokens: &[String]) {
    if let Ok(Some(env)) = parse_launch_args(tokens) {
        assert_eq!(env.version, ENVELOPE_SCHEMA_VERSION);
        assert_eq!(env.initiator_pid, None);

        for window_already_open in [false, true] {
            match plan_explorer_invocation(SAMPLE_EXE_PATH, &env, 1, window_already_open) {
                Ok(ExplorerLaunchTransport::DirectCommandLine {
                    command_line,
                    utf16_len,
                }) => {
                    assert!(!window_already_open);
                    assert_eq!(utf16_len, command_line.encode_utf16().count());
                    assert!(utf16_len <= MAX_COMMAND_LINE_UTF16);
                    let argv = split_win32_command_line(&command_line, true)
                        .expect("planned command line must split cleanly");
                    assert_eq!(parse_launch_args(&argv), Ok(Some(env.clone())));
                }
                Ok(ExplorerLaunchTransport::NamedPipeIpc {
                    pipe_path,
                    cold_start_command_line,
                    ipc_frame,
                }) => {
                    assert_eq!(pipe_path, session_named_pipe_path(1));
                    assert_eq!(
                        ActivationEnvelope::decode_ipc_frame(&ipc_frame),
                        Ok(env.clone())
                    );
                    let argv = split_win32_command_line(&cold_start_command_line, true)
                        .expect("cold-start command line must split cleanly");
                    assert_eq!(parse_launch_args(&argv), Ok(None));
                }
                Err(ActivationError::EnvelopeTooLarge { byte_len }) => {
                    assert!(byte_len > MAX_IPC_FRAME_BYTES);
                }
                Err(other) => {
                    panic!("unexpected plan_explorer_invocation error: {other:?}");
                }
            }
        }
    }
}
