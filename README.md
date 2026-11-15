# TotalDrop Formal Verification & Fuzzing (`01-formal-fuzz`)

Standalone symbolic security verification and coverage-guided property fuzzing suite extracted from [`totaldrop-app/totaldrop`](https://github.com/totaldrop-app/totaldrop) at upstream commit `ebe2b19` (`v0.2.0-beta.5`).

This repository pairs two complementary assurance methods:
1. **`formal/`** — Symbolic Dolev-Yao protocol proofs in **Tamarin Prover 1.12.0** (with Maude 3.5.1) backed by automated mutation testing (`formal/mutants.py`) to verify that breaking any security rule produces a concrete counterexample trace.
2. **`fuzz/`** — Coverage-guided `libFuzzer` (`cargo-fuzz` / `libfuzzer-sys`) harnesses exercising every untrusted wire decoder, share-link/code parser, path validator, router port-mapping parser, relay frame codec, and ICU localization parser against arbitrary byte streams.

---

## Repository Layout

| Path | License | Description |
| --- | --- | --- |
| `formal/` | `GPL-3.0-or-later` | 6 Tamarin `.spthy` models (**61 lemmas** total), `formal/check.sh` per-lemma prover driver, `formal/mutants.py` (**27 mutants**), and detailed model notes in [`formal/README.md`](formal/README.md). |
| `fuzz/` | `MIT OR Apache-2.0` | Standalone `cargo-fuzz` package (`exclude = ["fuzz"]` from the root workspace) with **6 fuzz targets** under `fuzz/fuzz_targets/`. |
| `crates/` | `MIT OR Apache-2.0` | Protocol and localization crates under test (`totaldrop-crypto`, `totaldrop-proto`, `totaldrop-core`, `totaldrop-l10n`) plus compile-time `l10n/` catalogs. |

---

## 1. Symbolic Formal Verification (`formal/`)

The Tamarin models verify the Hayalet Halka (Ghost Ring) multi-device account architecture before implementation, modeling a full Dolev-Yao network adversary, independent compromise of hybrid `Ed25519` + `ML-DSA-65` management key halves (`AK`), device identity keys (`IK`), ring epoch KEM secrets (`r_e`), and 24-word recovery phrases (`RK`).

### Models, Lemmas (61 Total), and Mutation Suite (27 Mutants)

| Piece | Theory File | Lemmas | Mutants | Verified Properties |
| --- | --- | ---: | ---: | --- |
| **A1** | `ghost-ring-chain.spthy` | 7 | 6 | Membership chain (`create`, `add`, `remove`, `rotate`), hybrid `Ed25519` + `ML-DSA-65` `AK` binding (**P1**), previous-head anti-replay, `IK`-scoped rotation. |
| **A2** | `ghost-ring-log.spthy` | 8 | 4 | Multi-valued witnessed transparency log (**P2**), enforced inclusion, single-view membership (`no_split_view_membership`), old-head removal lockout (**H3**), and discovery of the `rotate`-branch survival trace. |
| **A3** | `ghost-ring-freshness.spthy` | 5 | 2 | `rotate` settling window `D` + writer root freshness closing A2's `rotate`-branch gap (`no_rotate_branch_past_removal`). |
| **A3b** | `ghost-ring-privacy.spthy` | 14 | 5 | Epoch KEM confidentiality (`sent_head_key_secret`), contact send/receive log freshness (**P3**), offer authenticity, and post-rotation removal safety. |
| **A4a** | `ghost-ring-recovery.spthy` | 13 | 4 | 24-word `RK` recovery bound to membership periods (**P7**), mandatory pending wait, unconditional `recovery_reject` priority, double-recovery fork halt, and out-of-band contact word re-verification. |
| **A4b** | `ghost-ring-strict-mode.spthy` | 14 | 6 | Multi-layer approval (strict mode): settled change proposals, stolen-device veto vs `RK + staying member` removal override, and single-view change resolution. |
| **Total** | **6 `.spthy` models** | **61** | **27** | Full specification and abstraction notes in [`formal/README.md`](formal/README.md). |

### Running Formal Proofs & Mutant Checks

Requires `tamarin-prover` `1.12.0` and `maude` `3.5.1` on `PATH`:

```sh
# Prove all 61 lemmas individually (default LEMMA_TIMEOUT=600s per lemma)
./formal/check.sh

# Prove a single model
FORMAL_MODELS=ghost-ring-strict-mode.spthy ./formal/check.sh

# Run all 27 negative mutation checks (each must yield a verified attack trace)
./formal/mutants.py
```

To validate all 6 `.spthy` files, count all 61 lemmas, and verify that all 27 `mutants.py` structural edits and rule-drops apply cleanly without requiring `tamarin-prover` installed locally:

```sh
python3 -B -c '
import glob, re, sys
sys.path.insert(0, "formal")
import mutants
models = sorted(glob.glob("formal/*.spthy"))
lemmas = sum(len(re.findall(r"^lemma\s+\w+", open(m).read(), re.M)) for m in models)
for mut in mutants.MUTANTS:
    out = mutants.mutate(open(mut["model"]).read(), mut)
    assert "lemma attack" in out and out.endswith("end\n")
print(f"Verified {len(models)} models, {lemmas} lemmas, and {len(mutants.MUTANTS)} mutants.")
'
```

---

## 2. Coverage-Guided Property Fuzzing (`fuzz/`)

Each harness in `fuzz/fuzz_targets/` enforces both **crash/panic freedom** and **algebraic round-trip or security invariants**:

| Target | Source | Security & Round-Trip Invariants Checked |
| --- | --- | --- |
| `code` | `fuzz/fuzz_targets/code.rs` | `TransferCode::parse`, `find`, and **`from_link`** (`ebe2b19` `#445`): invariance under `strip_invisible_format` and `ascii_digits`; `MAX_LINK_BYTES` (1024 B) rejection; round-trip of `totaldrop://r/<code>` and `%XX`-escaped `https://totaldrop.app/r#<code>`; rejection of double-escaped links (`%25XX`) and trailing query strings (`?x`); ASCII-only `canonical()` / `to_english()` output for CPace. |
| `path` | `fuzz/fuzz_targets/path.rs` | `validate_path` NFC normalization idempotence (`validate_path(safe.segments()) == Ok(safe)`) and rejection of traversal, control/bidi characters, and Windows reserved device names. |
| `wire` | `fuzz/fuzz_targets/wire.rs` | Deterministic CBOR decode-then-encode round-trip equality across `ClientMessage`, `ServerMessage`, `Control`, `Certificate`, `Hints`, `DataHeader`, and streaming `LengthDecoder`. |
| `relay` | `fuzz/fuzz_targets/relay.rs` | Bijective parsing and serialization of relay `challenge`, `hello`, datagram `Batch` frames, `pair_name`, STUN binding packets, and backpressure `probe` frames (ensuring probes never parse as data frames). |
| `portmap` | `fuzz/fuzz_targets/portmap.rs` | PCP (`parse_pcp_map`) and NAT-PMP (`parse_pmp_address`, `parse_pmp_map`) gateway response parsers: request nonce/port correlation and non-zero/non-unspecified external mapping invariants. |
| `message` | `fuzz/fuzz_targets/message.rs` | Untrusted contributor ICU message parser (`totaldrop_l10n::message::Message::parse`) and plural/argument formatter panic freedom. |

### Checking & Running Fuzz Targets

```sh
# Run workspace unit and integration tests
RUSTUP_TOOLCHAIN=stable cargo test --workspace --offline

# Type-check and compile-check all 6 fuzz targets on stable Rust
RUSTUP_TOOLCHAIN=stable cargo check --manifest-path fuzz/Cargo.toml --bins --offline

# Run a fuzz target with cargo-fuzz (requires nightly libFuzzer instrumentation)
cargo +nightly fuzz run code
```
