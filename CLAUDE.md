# Veilkit — Project Instructions

Rust library + WASM + CLI that detects and redacts PII, US PHI, secrets and
financial identifiers using regex rules with checksum validators. **Not ML.**
Public repo, Apache-2.0. Architecture: `docs/architecture.md`. Decisions log:
`docs/decisions.md`. Rule catalogue: `docs/packs.md` (generated).

## Layout

- `crates/veilkit-core` — engine, rules, validators, redaction. All logic lives here.
- `crates/veilkit-wasm` — wasm-bindgen facade; strings in, JSON out.
- `crates/veilkit-cli` — `veilkit scan|redact|packs`.
- `packs/*.toml` — rule packs (version-checked against `PACKS_VERSION`);
  `packs/fixtures/*.toml` — 2+ positives and 1+ negative per rule, enforced by test.
- `npm/` — TypeScript wrapper over the wasm-pack output; `npm/pkg` is generated.

## Run / test

```bash
cargo test --workspace                                  # all Rust tests
cargo clippy --workspace --all-targets -- -D warnings   # CI gate
cargo fmt --all -- --check
cd npm && npm run build && npm test                     # wasm-pack both targets + tsc + node tests
cargo run -p veilkit-cli -- redact --packs pii <<< "ssn 219-09-9999"
cargo run -p veilkit-cli -- packs --markdown > docs/packs.md   # regenerate the catalogue
cargo bench -p veilkit-core                             # criterion, scan 10 KB all packs
```

## Rules of the repo

- **Never publish.** No `npm publish`, no `cargo publish`, until Carlos says so.
  `npm pack --dry-run` is fine.
- **Regexes are RE2-compatible**: no lookaround, no backreferences. The `regex`
  crate rejects them at build; keep it that way so the packs stay portable to Go/JS RE2.
- **Every new rule needs fixtures** in `packs/fixtures/<pack>.toml`: 2+ positives,
  1+ negative. The fixtures test fails otherwise. Validate real checksums before
  writing a positive (a Python one-liner is fine).
- **Bump `PACKS_VERSION`** (core `pack.rs`) and every pack + fixture file's
  `version` together when rules change.
- **WASM size budget: 400 KiB gzipped**, enforced in CI. The regex crate is the
  cost. Current features are the minimum that compiles the packs; see the trap below.
- **No `unwrap`/`expect` on any path reachable from the WASM or CLI boundary.**
  Build errors are `Result`; scanning never fails.

## Traps

- **Cargo feature unification hides wasm-only regex failures.** Dev-deps
  (criterion, assert_cmd) pull `regex` with default features, so `cargo test`
  passes even when `veilkit-wasm` (built alone) lacks `unicode-case` or
  `unicode-perl` and every `(?i)`/`\b` rule fails to compile at runtime. The
  node tests are the guard; run them after touching regex features or patterns.
- **`wasm-opt` needs `--enable-bulk-memory`** with Rust 1.8x+ output; it is set in
  `crates/veilkit-wasm/Cargo.toml` metadata. Without it wasm-pack fails late.
- **GitHub push protection scans fixtures.** Any syntactically valid Stripe key
  (even a made-up one) blocks the push. Split such fixtures with `{{+}}`; the
  fixtures test removes the marker before scanning.
- **`JsError` only exists on wasm32.** The wasm crate's native unit test can only
  exercise the success path; error paths are covered in `npm/test`.
- **Overlap resolution is longest > severity > rule order.** A rule that matches a
  longer span than yours will win even at lower severity; extend your pattern
  (as `phi.portal.epic_mychart_patient` consumes the query value) rather than
  reorder rules.
- **`\d`, `\w`, `\s`, `\b` are Unicode-aware** (unicode-perl on). Validators work on
  ASCII digits only, so non-ASCII digits never validate.
