//! Rule schema, (de)serialized from TOML. One `RuleDef` is one detector.

use serde::{Deserialize, Serialize};

/// How bad a leak of this kind of value is. Drives overlap resolution and
/// the CLI's `--fail-on` gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            other => Err(format!("unknown severity `{other}`")),
        }
    }
}

/// How sure the engine is that a span is really the thing the rule names.
/// A rule with no validator yields `Medium`; a passing validator or a context
/// word nearby raises it to `High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// One detector as written in a pack file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleDef {
    /// Stable identifier, dotted: `pii.ssn`, `secret.github_token`.
    pub id: String,
    pub severity: Severity,
    /// RE2-compatible regex (no lookaround, no backreferences).
    pub pattern: String,
    /// Placeholder label for redaction; defaults to the id's last segment
    /// upper-cased (`pii.credit_card` -> `CREDIT_CARD`).
    #[serde(default)]
    pub label: Option<String>,
    /// Named checksum validator applied to every candidate match.
    #[serde(default)]
    pub validator: Option<String>,
    /// Words that, when found near a match, raise confidence to `High`.
    #[serde(default)]
    pub context: Vec<String>,
    /// When true, a match with no context word nearby is dropped.
    #[serde(default)]
    pub require_context: bool,
    /// One-line human description, surfaced by `docs/packs.md` and the CLI.
    #[serde(default)]
    pub description: String,
}

impl RuleDef {
    pub fn label(&self) -> String {
        match &self.label {
            Some(l) => l.clone(),
            None => self
                .id
                .rsplit('.')
                .next()
                .unwrap_or(&self.id)
                .to_ascii_uppercase()
                .replace('-', "_"),
        }
    }
}

/// Top-level shape of a pack file or a custom rule file.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleFile {
    pub version: String,
    #[serde(rename = "rule", default)]
    pub rules: Vec<RuleDef>,
}

impl RuleFile {
    pub fn parse_toml(src: &str) -> crate::Result<Self> {
        toml::from_str(src).map_err(|e| crate::Error::Parse(e.to_string()))
    }
}
