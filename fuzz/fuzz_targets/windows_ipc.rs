#![no_main]
// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! Windows Named Pipe IPC frame decoder and `ActivationEnvelope` JSON parser
//! invariants: arbitrary chunk splits match full-buffer streaming, oversized
//! frame headers reject on byte 4 without pre-allocating payload memory
//! (`payload_capacity() == 0`), single-shot and streaming decoders obey their
//! exact 8-case partition, and every accepted envelope round-trips cleanly.

use libfuzzer_sys::fuzz_target;
use totaldrop_windows_bridge::{
    ActivationEnvelope, ActivationError, IpcFrameDecoder, MAX_IPC_FRAME_BYTES,
};

const SINGLE_BYTE_STREAM_LIMIT: usize = 8_192;

fuzz_target!(|data: &[u8]| {
    let single = ActivationEnvelope::decode_ipc_frame(data);

    let full_schedule = [data.len().max(1)];
    let mut var_schedule = [1usize, 2, 3, 5, 11];
    for (slot, byte) in var_schedule.iter_mut().zip(data.iter().copied()) {
        *slot = usize::from(byte & 0x0F) + 1;
    }

    let stream = decode_stream(data, &full_schedule);
    assert_eq!(stream, decode_stream(data, &[7]));
    assert_eq!(stream, decode_stream(data, &[3]));
    assert_eq!(stream, decode_stream(data, &var_schedule));
    if data.len() <= SINGLE_BYTE_STREAM_LIMIT {
        assert_eq!(stream, decode_stream(data, &[1]));
    }

    // Verify exact 8-case partition between single-shot `decode_ipc_frame` and
    // streaming `IpcFrameDecoder`.
    if data.is_empty() {
        assert_eq!(single, Err(ActivationError::MalformedIpcFrame));
        assert_eq!(stream, Ok(Vec::new()));
    } else if data.len() < 4 {
        assert_eq!(single, Err(ActivationError::MalformedIpcFrame));
        assert_eq!(stream, Err(ActivationError::MalformedIpcFrame));
    } else {
        let declared = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let payload_len = data.len() - 4;

        if declared > MAX_IPC_FRAME_BYTES {
            assert_eq!(
                single,
                Err(ActivationError::EnvelopeTooLarge { byte_len: declared })
            );
            assert_eq!(
                stream,
                Err(ActivationError::EnvelopeTooLarge { byte_len: declared })
            );
            verify_oversized_header_prealloc_guard(&data[..4], declared);
        } else if declared == 0 && payload_len == 0 {
            assert!(matches!(single, Err(ActivationError::InvalidJson(_))));
            assert_eq!(stream, Err(ActivationError::MalformedIpcFrame));
        } else if declared == 0 || payload_len < declared {
            // Case 5 (`declared == 0` with trailing bytes) and Case 6
            // (truncated frame) both return `MalformedIpcFrame` on both
            // single-shot and streaming decoders.
            assert_eq!(single, Err(ActivationError::MalformedIpcFrame));
            assert_eq!(stream, Err(ActivationError::MalformedIpcFrame));
        } else if payload_len == declared {
            match (&single, &stream) {
                (Ok(env), Ok(envs)) => assert_eq!(envs.as_slice(), std::slice::from_ref(env)),
                (Err(e1), Err(e2)) => assert_eq!(e1, e2),
                _ => panic!("single/stream mismatch on exact frame: {single:?} vs {stream:?}"),
            }
        } else {
            // Trailing bytes / coalesced multi-frame stream.
            assert_eq!(single, Err(ActivationError::MalformedIpcFrame));
            if let Ok(envs) = &stream {
                assert!(envs.len() >= 2);
            }
        }
    }

    if let Ok(env) = &single {
        assert_eq!(
            stream.as_ref().ok().map(Vec::as_slice),
            Some(std::slice::from_ref(env))
        );
        check_round_trip(env);
    }
    if let Ok(envs) = &stream {
        if envs.len() == 1 {
            assert_eq!(single.as_ref().ok(), envs.first());
        } else {
            assert_eq!(single, Err(ActivationError::MalformedIpcFrame));
        }
        for env in envs {
            check_round_trip(env);
        }
    }

    // Direct JSON fuzzing + synthetic validly length-prefixed framing so
    // libFuzzer reaches `serde_json` and `validate_invariants` without having
    // to guess the 4-byte LE header first.
    let direct_json = ActivationEnvelope::from_json_bytes(data);
    if !data.is_empty() && data.len() <= MAX_IPC_FRAME_BYTES {
        let len_u32 = u32::try_from(data.len()).expect("payload length <= MAX_IPC_FRAME_BYTES");
        let mut framed = Vec::with_capacity(4 + data.len());
        framed.extend_from_slice(&len_u32.to_le_bytes());
        framed.extend_from_slice(data);
        assert_eq!(ActivationEnvelope::decode_ipc_frame(&framed), direct_json);
        let schedule: &[usize] = if framed.len() <= SINGLE_BYTE_STREAM_LIMIT {
            &[1]
        } else {
            &[7]
        };
        let streamed = decode_stream(&framed, schedule);
        match (&direct_json, &streamed) {
            (Ok(env), Ok(envs)) => assert_eq!(envs.as_slice(), std::slice::from_ref(env)),
            (Err(e1), Err(e2)) => assert_eq!(e1, e2),
            _ => panic!("synthetic frame mismatch: {direct_json:?} vs {streamed:?}"),
        }
    }
    if let Ok(env) = &direct_json {
        check_round_trip(env);
    }
});

fn decode_stream(
    data: &[u8],
    schedule: &[usize],
) -> Result<Vec<ActivationEnvelope>, ActivationError> {
    let mut decoder = IpcFrameDecoder::new();
    let mut envelopes = Vec::new();
    if data.is_empty() {
        let empty = decoder.push_bytes(&[])?;
        assert!(empty.is_empty());
    }
    let mut offset = 0usize;
    let mut step = 0usize;
    while offset < data.len() {
        let chunk_len = schedule[step % schedule.len()].max(1);
        let end = (offset + chunk_len).min(data.len());
        match decoder.push_bytes(&data[offset..end]) {
            Ok(mut batch) => envelopes.append(&mut batch),
            Err(err) => {
                assert!(!decoder.has_partial_frame());
                assert_eq!(decoder.buffered_bytes(), 0);
                assert_eq!(decoder.payload_capacity(), 0);
                return Err(err);
            }
        }
        offset = end;
        step += 1;
    }
    match decoder.finish_eof() {
        Ok(()) => {
            assert!(!decoder.has_partial_frame());
            assert_eq!(decoder.buffered_bytes(), 0);
            Ok(envelopes)
        }
        Err(err) => {
            assert!(!decoder.has_partial_frame());
            assert_eq!(decoder.buffered_bytes(), 0);
            assert_eq!(decoder.payload_capacity(), 0);
            Err(err)
        }
    }
}

fn verify_oversized_header_prealloc_guard(header: &[u8], declared: usize) {
    let mut decoder = IpcFrameDecoder::new();
    for byte in &header[..3] {
        let out = decoder
            .push_bytes(std::slice::from_ref(byte))
            .expect("first 3 bytes of oversized header must buffer cleanly");
        assert!(out.is_empty());
        assert!(decoder.has_partial_frame());
        assert_eq!(decoder.payload_capacity(), 0);
    }
    let reject = decoder.push_bytes(&header[3..4]);
    assert_eq!(
        reject,
        Err(ActivationError::EnvelopeTooLarge { byte_len: declared })
    );
    assert_eq!(decoder.payload_capacity(), 0);
    assert!(!decoder.has_partial_frame());
    assert_eq!(decoder.buffered_bytes(), 0);
}

fn check_round_trip(env: &ActivationEnvelope) {
    match env.encode_ipc_frame() {
        Ok(frame) => {
            assert_eq!(
                ActivationEnvelope::decode_ipc_frame(&frame),
                Ok(env.clone())
            );
            let schedule: &[usize] = if frame.len() <= SINGLE_BYTE_STREAM_LIMIT {
                &[1]
            } else {
                &[7]
            };
            assert_eq!(decode_stream(&frame, schedule), Ok(vec![env.clone()]));
        }
        Err(ActivationError::EnvelopeTooLarge { byte_len }) => {
            assert!(byte_len > MAX_IPC_FRAME_BYTES);
        }
        Err(other) => panic!("validated envelope failed to re-encode: {other:?}"),
    }
}
