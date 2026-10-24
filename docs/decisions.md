# Decisions log

Decisions made where `architecture.md` was silent. Newest last.

| Date | Decision | Why |
|---|---|---|
| 2026-10-24 | Toolchain pinned to 1.97.1 (local stable); `rust-version = 1.85` floor | Reproducible CI; `is_none_or` needs 1.82+ |
| 2026-10-24 | Spans carry `Arc<str>` id and label, not `&str` with a lifetime | Serializable and sendable across the WASM boundary without tying spans to the engine's lifetime; clone is a refcount bump |
| 2026-10-24 | Validators are `fn(&str) -> bool` pointers looked up by name, not a trait | No state, no allocation, trivially testable; a trait object would buy nothing here |
| 2026-10-24 | Context window = 40 bytes each side, lower-cased substring match | Simple, fast, good enough for labels like "SSN:"; tokenising would cost more than it saves |
| 2026-10-24 | Confidence: validator pass OR context word → High; else Medium; Low unused in v1 | Keeps the model two-valued in practice while leaving room for weaker heuristics later |
| 2026-10-24 | `require_context` for `\d{9}` / `\d{10}` rules (SSN unformatted, NPI, ABA) | A bare digit run that passes a 1-in-10 check digit is not evidence; the label is |
| 2026-10-24 | Overlap: longest > severity > earliest rule, global greedy by that order | Deterministic and matches the spec's priority; documented trap in CLAUDE.md |
| 2026-10-24 | Numbered placeholders are stable per (label, value) within one call; map has one entry per placeholder | Enables exact `restore()`; cross-call stability belongs to the hosted tier |
| 2026-10-24 | Mask style masks alphanumerics only, keeps separators | `***-**-6789` reads better than `***********` and still hides the value |
| 2026-10-24 | Hash = first 8 hex of SHA-256 of the raw match | Stable pseudonym across calls, short enough for logs |
| 2026-10-24 | WASM API is strings and JSON (`serde_json`), not `serde-wasm-bindgen` | Smaller glue, no extra dependency, the TS wrapper owns the types |
| 2026-10-24 | `RedactOptions` deserialised through a flat `RawOptions` with `TryFrom` | serde cannot default an internally-tagged flattened enum; explicit conversion also gives a clear "unknown style" error |
| 2026-10-24 | regex crate with `default-features = false` + `unicode-case`, `unicode-perl`, selected `perf-*` | Shrinks the wasm from 475 KB to 373 KB gzipped; both unicode features are required for `(?i)` and `\b` to compile |
| 2026-10-24 | wasm target built with `opt-level=z` + `wasm-opt -Oz`, native release stays `opt-level=3` | Size matters in the browser, speed matters in the CLI |
| 2026-10-24 | npm wrapper ships `nodejs` and `bundler` targets; a `web` (init()) target is a follow-up | Spec named these two; `web` is a one-line addition when a no-bundler consumer appears |
| 2026-10-24 | CLI `--fail-on` exits 2, usage/IO errors exit 1 | Lets CI distinguish "found a secret" from "could not run" |
| 2026-10-24 | Packs version `2026.10`; `pii.ipv6` matches only the full 8-group form | Compressed IPv6 needs lookaround-free tricks that over-match; deferred |
| 2026-10-24 | CI installs wasm-pack via the rustwasm installer script | Fastest on a cold runner; `cargo install` would add minutes |
