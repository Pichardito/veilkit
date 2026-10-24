//! # Veilkit
//!
//! Pattern-and-checksum detection and redaction of sensitive text: PII, US PHI,
//! secrets and financial identifiers. Not a machine-learning NER model: it will
//! not find an unlabeled person's name, and it will find structured
//! identifiers with few false positives because candidates are validated.
//!
//! ```
//! use veilkit_core::{Engine, Pack, RedactOptions, Style};
//!
//! let engine = Engine::builder().pack(Pack::Pii).build().unwrap();
//! let out = engine.redact(
//!     "SSN 123-45-6789, card 4111 1111 1111 1111",
//!     &RedactOptions { style: Style::Label, ..Default::default() },
//! );
//! assert_eq!(out.text, "SSN [SSN], card [CREDIT_CARD]");
//! ```
//!
//! Regexes are RE2-compatible (the `regex` crate: no lookaround, no
//! backreferences) so the same rule files could drive a Go or JS RE2 engine.

mod engine;
mod error;
mod pack;
mod redact;
mod rule;
pub mod validators;

pub use engine::{Engine, EngineBuilder, RuleInfo, Span, DEFAULT_MAX_INPUT_BYTES};
pub use error::{Error, Result};
pub use pack::{Pack, PACKS_VERSION};
pub use redact::{MapEntry, RedactOptions, RedactedSpan, Redaction, Style};
pub use rule::{Confidence, RuleDef, RuleFile, Severity};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
