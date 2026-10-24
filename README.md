# Veilkit

Fast, validated redaction of sensitive text, in Rust and WebAssembly.

Veilkit finds structured identifiers that should not leave your process and
replaces them before the text goes anywhere else: into an LLM prompt, a log
line, a support ticket, an analytics event.

```
SSN 219-09-9999, card 4111 1111 1111 1111, token ghp_abcdefghijklmnopqrstuvwxyz0123456789
→ SSN [SSN], card [CREDIT_CARD], token [GITHUB_TOKEN]
```

## What it is, honestly

- **Pattern + checksum, not machine learning.** Every candidate is matched by a
  regex and, where one exists, confirmed by a validator (Luhn, IBAN mod-97, SSN
  area rules, NPI and DEA check digits, ABA routing checksum). That keeps false
  positives low and the WebAssembly small (about 370 KB gzipped).
- **It will not find an unlabeled person's name** or a free-text address.
  Labeled ones ("DOB: 04/12/1985", "123 Main Street") it will.
- **Deterministic.** Same input, same output, no network, no model.

Four built-in packs: `pii`, `phi-us`, `secrets`, `finance`. Full rule list in
[docs/packs.md](docs/packs.md). Add or override rules with your own TOML.

## Use it

### Rust

```rust
use veilkit_core::{Engine, Pack, RedactOptions, Style};

let engine = Engine::builder().pack(Pack::Pii).pack(Pack::Secrets).build()?;
let out = engine.redact(text, &RedactOptions {
    style: Style::Numbered,     // [SSN_1], [SSN_2] — same value, same number
    reversible: true,           // out.map lets you restore originals
    ..Default::default()
});
let reply = call_llm(&out.text);
let restored = out.restore(&reply);
```

### JavaScript / TypeScript (Node, bundlers)

```ts
import { createEngine } from "veilkit";          // or "veilkit/node"

const engine = createEngine({ packs: ["pii", "secrets"] });
const red = engine.redact(text, { style: "numbered", reversible: true });
const reply = await llm(red.text);
const restored = engine.restore(red, reply);
```

The npm package is **not published yet**. Build it locally with
`cd npm && npm run build`.

### CLI

```bash
echo "routing number 021000021" | veilkit redact --packs finance --style mask
# routing number *****0021

veilkit scan --fail-on high src/**/*.env     # exit 2 if a high-severity span is found
veilkit packs --markdown                      # the rule catalogue
```

Container: `podman build -t veilkit . && echo "..." | podman run -i veilkit redact`.

## Redaction styles

| Style | Output | Reversible |
|---|---|---|
| `label` | `[SSN]` | no (placeholders repeat) |
| `numbered` | `[SSN_1]`, `[SSN_2]` | yes, with `reversible: true` |
| `mask` | `***-**-9999` (keeps last N alphanumerics) | no |
| `hash` | `[SSN:9f86d081]` (SHA-256 prefix, stable) | no |

When matches overlap, the longest span wins, then the higher severity, then the
rule declared first.

## Custom rules

```toml
version = "2026.10"

[[rule]]
id = "acme.ticket"
severity = "medium"
pattern = 'TCK-\d{6}'            # RE2-compatible: no lookaround, no backreferences
context = ["ticket"]              # optional: nearby words raise confidence
# validator = "luhn"              # optional: luhn, iban_mod97, ssn, npi, dea, routing_aba
# require_context = true          # optional: drop matches with no context word nearby
```

A rule with an existing id replaces the built-in one.

## Develop

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cd npm && npm run build && npm test
```

See [CLAUDE.md](CLAUDE.md) for the repo's rules and traps, and
[docs/architecture.md](docs/architecture.md) for the design.

## Lineage and license

Apache-2.0. The rule-pack model and the healthcare portal URL list grew out of
earlier unpublished work by the same author; see [NOTICE](NOTICE).
