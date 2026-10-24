//! The engine: compiled rules, scanning, and overlap resolution.

use std::sync::Arc;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::pack::Pack;
use crate::rule::{Confidence, RuleDef, RuleFile, Severity};
use crate::validators::{self, Validator};
use crate::{Error, Result};

/// Default cap on input size for the boundaries (WASM, CLI) that enforce one.
pub const DEFAULT_MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;

/// How many bytes on each side of a match are searched for context words.
const CONTEXT_WINDOW: usize = 40;

/// One detected region of sensitive text. Byte offsets into the scanned
/// string; `end` is exclusive. `id` and `label` are shared with the engine's
/// rule (an `Arc<str>` clone is a pointer bump, not a string copy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub id: Arc<str>,
    pub label: Arc<str>,
    pub start: usize,
    pub end: usize,
    pub severity: Severity,
    pub confidence: Confidence,
}

impl Span {
    pub fn len(&self) -> usize {
        self.end - self.start
    }
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
    /// The matched text, borrowed from the input it was scanned from.
    pub fn slice<'t>(&self, text: &'t str) -> &'t str {
        &text[self.start..self.end]
    }
}

#[derive(Debug)]
struct CompiledRule {
    id: Arc<str>,
    label: Arc<str>,
    severity: Severity,
    regex: Regex,
    validator: Option<Validator>,
    /// Lower-cased context words.
    context: Vec<String>,
    require_context: bool,
    description: String,
}

impl CompiledRule {
    fn compile(def: &RuleDef) -> Result<Self> {
        let regex = Regex::new(&def.pattern).map_err(|e| Error::InvalidPattern {
            id: def.id.clone(),
            source: Box::new(e),
        })?;
        let validator = match &def.validator {
            None => None,
            Some(name) => {
                Some(
                    validators::by_name(name).ok_or_else(|| Error::UnknownValidator {
                        id: def.id.clone(),
                        validator: name.clone(),
                    })?,
                )
            }
        };
        Ok(Self {
            id: Arc::from(def.id.as_str()),
            label: Arc::from(def.label().as_str()),
            severity: def.severity,
            regex,
            validator,
            context: def.context.iter().map(|c| c.to_lowercase()).collect(),
            require_context: def.require_context,
            description: def.description.clone(),
        })
    }
}

/// Summary of one rule for docs and `veilkit packs`.
#[derive(Debug, Clone, Serialize)]
pub struct RuleInfo {
    pub id: String,
    pub label: String,
    pub severity: Severity,
    pub validator: Option<String>,
    pub requires_context: bool,
    pub description: String,
}

/// A compiled set of rules. Cheap to scan with, moderately expensive to build
/// (every regex compiles once); build one and reuse it.
#[derive(Debug)]
pub struct Engine {
    rules: Vec<CompiledRule>,
}

/// Builder: pick packs, add custom rules, then [`EngineBuilder::build`].
#[derive(Debug, Default)]
pub struct EngineBuilder {
    packs: Vec<Pack>,
    custom: Vec<RuleFile>,
}

impl EngineBuilder {
    pub fn pack(mut self, pack: Pack) -> Self {
        if !self.packs.contains(&pack) {
            self.packs.push(pack);
        }
        self
    }

    pub fn packs<I: IntoIterator<Item = Pack>>(mut self, packs: I) -> Self {
        for p in packs {
            self = self.pack(p);
        }
        self
    }

    /// Add rules from a TOML document in the pack format. A rule whose id
    /// already exists replaces that rule in place; a new id is appended.
    /// Parse errors surface here, compile errors at `build`.
    pub fn custom_rules_toml(mut self, toml_src: &str) -> Result<Self> {
        self.custom.push(RuleFile::parse_toml(toml_src)?);
        Ok(self)
    }

    pub fn custom_rules(mut self, rules: Vec<RuleDef>) -> Self {
        self.custom.push(RuleFile {
            version: crate::pack::PACKS_VERSION.to_string(),
            rules,
        });
        self
    }

    pub fn build(self) -> Result<Engine> {
        // All built-in packs form one source: a duplicate across them is a
        // shipped defect and must fail loudly.
        let mut defs: Vec<RuleDef> = Vec::new();
        for pack in &self.packs {
            defs.extend(pack.load()?.rules);
        }
        check_duplicates(&defs)?;

        // Each custom file is its own source for the duplicate check, then
        // overrides by id.
        for file in &self.custom {
            check_duplicates(&file.rules)?;
            for rule in &file.rules {
                match defs.iter_mut().find(|d| d.id == rule.id) {
                    Some(slot) => *slot = rule.clone(),
                    None => defs.push(rule.clone()),
                }
            }
        }

        let rules = defs
            .iter()
            .map(CompiledRule::compile)
            .collect::<Result<Vec<_>>>()?;
        Ok(Engine { rules })
    }
}

fn check_duplicates(defs: &[RuleDef]) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for d in defs {
        if !seen.insert(d.id.as_str()) {
            return Err(Error::DuplicateRule(d.id.clone()));
        }
    }
    Ok(())
}

struct Candidate {
    span: Span,
    rule_index: usize,
}

impl Engine {
    pub fn builder() -> EngineBuilder {
        EngineBuilder::default()
    }

    /// Every built-in pack, no custom rules.
    pub fn all_packs() -> Result<Engine> {
        Engine::builder().packs(Pack::ALL).build()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn rules(&self) -> Vec<RuleInfo> {
        self.rules
            .iter()
            .map(|r| RuleInfo {
                id: r.id.to_string(),
                label: r.label.to_string(),
                severity: r.severity,
                validator: r.validator.map(|_| validator_name_for(r)),
                requires_context: r.require_context,
                description: r.description.clone(),
            })
            .collect()
    }

    /// Return an error if `text` is larger than `max_bytes`. Boundaries that
    /// accept untrusted input call this before `scan`.
    pub fn ensure_within_limit(text: &str, max_bytes: usize) -> Result<()> {
        if text.len() > max_bytes {
            return Err(Error::InputTooLarge(text.len(), max_bytes));
        }
        Ok(())
    }

    /// Find every sensitive span. The result is sorted by `start` and spans
    /// never overlap: where candidates collide, the longest wins, then the
    /// higher severity, then the rule declared earliest.
    pub fn scan(&self, text: &str) -> Vec<Span> {
        let mut candidates = self.candidates(text);
        candidates.sort_by(|a, b| {
            b.span
                .len()
                .cmp(&a.span.len())
                .then(b.span.severity.cmp(&a.span.severity))
                .then(a.rule_index.cmp(&b.rule_index))
                .then(a.span.start.cmp(&b.span.start))
        });

        let mut accepted: Vec<Span> = Vec::with_capacity(candidates.len());
        for c in candidates {
            let overlaps = accepted
                .iter()
                .any(|s| c.span.start < s.end && s.start < c.span.end);
            if !overlaps {
                accepted.push(c.span);
            }
        }
        accepted.sort_by_key(|s| s.start);
        accepted
    }

    /// True when any span at or above `severity` exists. Cheaper than `scan`
    /// only in that it stops at the first hit.
    pub fn has_severity_at_least(&self, text: &str, severity: Severity) -> bool {
        self.scan(text).iter().any(|s| s.severity >= severity)
    }

    fn candidates(&self, text: &str) -> Vec<Candidate> {
        let mut out = Vec::new();
        for (rule_index, rule) in self.rules.iter().enumerate() {
            for m in rule.regex.find_iter(text) {
                if m.is_empty() {
                    continue;
                }
                let validated = match rule.validator {
                    Some(v) => {
                        if !v(m.as_str()) {
                            continue;
                        }
                        true
                    }
                    None => false,
                };
                let has_context = !rule.context.is_empty()
                    && near_context(text, m.start(), m.end(), &rule.context);
                if rule.require_context && !has_context {
                    continue;
                }
                let confidence = if validated || has_context {
                    Confidence::High
                } else {
                    Confidence::Medium
                };
                out.push(Candidate {
                    span: Span {
                        id: Arc::clone(&rule.id),
                        label: Arc::clone(&rule.label),
                        start: m.start(),
                        end: m.end(),
                        severity: rule.severity,
                        confidence,
                    },
                    rule_index,
                });
            }
        }
        out
    }
}

fn validator_name_for(rule: &CompiledRule) -> String {
    // Function pointers compare by address; recover the name for reporting.
    validators::NAMES
        .iter()
        .find(|n| validators::by_name(n).map(|f| f as usize) == rule.validator.map(|f| f as usize))
        .map(|n| n.to_string())
        .unwrap_or_default()
}

/// Is any context word within `CONTEXT_WINDOW` bytes before or after the match?
fn near_context(text: &str, start: usize, end: usize, words: &[String]) -> bool {
    let lo = floor_char_boundary(text, start.saturating_sub(CONTEXT_WINDOW));
    let hi = ceil_char_boundary(text, (end + CONTEXT_WINDOW).min(text.len()));
    let window = text[lo..hi].to_lowercase();
    words.iter().any(|w| window.contains(w.as_str()))
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}
