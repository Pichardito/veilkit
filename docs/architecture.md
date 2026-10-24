# Veilkit — Architecture (Phase 1)

**Status:** v1 design, 2026-10-24. **License:** Apache-2.0.
**npm publish:** pending a release review.

## 1. What Veilkit is

A fast, dependency-light library that finds and redacts sensitive text before
it leaves your process: names of things like SSNs, card numbers, phone numbers,
emails, medical record numbers, API keys. Written in Rust, compiled to
WebAssembly, callable from JavaScript (browser, Node, edge) and from Rust.

**Honest positioning.** Veilkit is pattern-and-checksum based, not a machine
learning NER model. It will not find an unlabeled person's name. It will find
structured identifiers with very low false-positive rates because every
candidate match is validated (Luhn, mod-97, SSN area rules, NPI check digit).
That is the right tool for the "scrub before the LLM call" use case, where
structured identifiers are the liability and latency matters.

**Open-core.** The library and CLI are free forever. A hosted tier (audit log of
what was redacted, custom rule packs managed in a dashboard, team policies) is
the possible paid layer and is not part of this repo.

## 2. Lineage

Seeded from earlier unpublished work by the same author. Kept: the versioned
rule-pack design, the override-by-id model, bounded excerpts, and the
panic-free WASM boundary discipline. Everything else is new: redaction,
validators, span resolution, the npm package, the CLI.

## 3. Crates

```
veilkit/
├─ crates/
│  ├─ veilkit-core     # rlib: rules, packs, validators, scan, redact
│  ├─ veilkit-wasm     # cdylib via wasm-bindgen → npm package "veilkit"
│  └─ veilkit-cli      # `veilkit scan|redact` over stdin/files
├─ packs/              # TOML rule packs, versioned (see §5)
├─ npm/                # package.json, TS wrapper, README for npm
└─ docs/
```

### veilkit-core API

```rust
let engine = Engine::builder()
    .pack(Pack::Pii)          // built-in packs by enum
    .pack(Pack::PhiUs)
    .custom_rules_toml(my_toml)?   // adds or overrides by id
    .build()?;

let spans: Vec<Span> = engine.scan(text);
// Span { id: "pii.ssn", start, end, severity, confidence }

let out: Redaction = engine.redact(text, &RedactOptions {
    style: Style::Label,      // "[SSN]"  | Style::Numbered "[SSN_1]" (stable per value)
                              // | Style::Mask { keep_last: 4 } "***-**-6789"
                              // | Style::Hash  (sha256 prefix)
    ..Default::default()
});
// Redaction { text, spans, map: Option<Vec<(placeholder, original)>> }
```

`redact` with `Style::Numbered` and `reversible: true` returns the map so a
caller can re-insert originals into an LLM's reply. Overlapping matches resolve
to the longest span, then highest severity, then earliest rule.

### Rule model

```toml
version = "2026.10"
[[rule]]
id = "pii.ssn"
severity = "high"
pattern = '\b(\d{3})-(\d{2})-(\d{4})\b'
validator = "ssn"          # optional; named validator in core
context = ["ssn", "social"]  # optional; nearby words raise confidence
```

Validators are Rust functions keyed by name: `luhn`, `iban_mod97`, `ssn`
(no 000/666/9xx area, no 00 group, no 0000 serial), `npi` (Luhn over 80840
prefix), `dea` (checksum digit), `routing_aba` (checksum). Rules without a
validator get `confidence = medium`; with a passing validator, `high`.

## 4. Packs (v1)

| Pack | Contents |
|---|---|
| `pii` | email, phone (US + E.164), IPv4, IPv6, credit card (Luhn), IBAN (mod-97), US SSN (validated), US passport (labeled), date of birth (labeled), street address (labeled, conservative) |
| `phi-us` | MRN (labeled), NPI (validated), DEA (validated), health plan / member id (labeled), ICD-10 code (labeled), a healthcare patient-portal URL list |
| `secrets` | AWS access key id, AWS secret (labeled), GitHub tokens (`ghp_`, `gho_`, …), Slack tokens, Stripe keys, JWTs, PEM private key blocks, generic `api_key=` assignments |
| `finance` | US ABA routing (validated), US bank account (labeled), card expiry + CVV (labeled) |

Every rule ships with positive and negative fixtures in `packs/fixtures/`, and
a test asserts each rule has at least two positives and one negative.

## 5. WASM and npm

- `wasm-bindgen` (not the Component Model) because the npm consumer is the
  priority and wasm-bindgen's JS glue is the smoothest path for browser + Node.
- `npm/` holds a hand-written TypeScript wrapper exposing `createEngine`,
  `scan`, `redact`, typed options, and loading helpers for browser and Node.
- Target bundle size under 400 KB gzipped; the regex crate is the main cost
  and is built with `unicode` features trimmed where safe.
- Panic policy: `panic = "abort"` for the wasm profile and no `unwrap` in
  exported paths. Invalid UTF-8 cannot occur across wasm-bindgen strings;
  oversized input returns an error, not a trap.

## 6. CLI

`veilkit redact --packs pii,secrets --style numbered < file.txt`. Exit code 2
when any high-severity span was found and `--fail-on high` is set, so it can
run in CI as a secrets gate.

## 7. Decisions and why

| Decision | Choice | Why |
|---|---|---|
| Rust | Yes | Performance and memory safety at the boundary, compiles to WASM once and runs everywhere; it is also the learning target |
| No ML | Deliberate | Keeps the WASM small and the false positives low; names are out of scope and documented as such |
| wasm-bindgen over WIT component | For now | npm reach beats runtime neutrality for a library whose first users are JS developers; a component build can be added later |
| Apache-2.0 | Chosen | Permissive plus patent grant; standard for Rust ecosystem |
| Public CI from day one | GitHub Actions | Free for public repos; cargo test, clippy, wasm build, npm pack |

## 8. What would force a redesign

- Users needing name/address detection: that means an ML model, likely a
  separate optional crate with a larger WASM, not a change to this core.
- Streaming redaction over very large inputs: the current API is whole-string;
  a chunked scanner with overlap would be a new entry point.
