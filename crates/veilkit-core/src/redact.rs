//! Redaction: turn spans into placeholders.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::engine::{Engine, Span};
use crate::rule::{Confidence, Severity};

/// What replaces a detected span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "style", rename_all = "lowercase")]
pub enum Style {
    /// `[SSN]`
    #[default]
    Label,
    /// `[SSN_1]`, `[SSN_2]`: the same original value always gets the same
    /// number within one call, which makes the output reversible.
    Numbered,
    /// `***-**-6789`: every alphanumeric except the last `keep_last` becomes `*`,
    /// separators are kept.
    Mask {
        #[serde(default = "default_keep_last")]
        keep_last: usize,
    },
    /// `[SSN:9f86d081]`: label plus the first 8 hex chars of SHA-256 of the
    /// original. Stable across calls, not reversible.
    Hash,
}

fn default_keep_last() -> usize {
    4
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(try_from = "RawOptions")]
pub struct RedactOptions {
    #[serde(flatten)]
    pub style: Style,
    /// Return the placeholder → original map so a caller can restore values
    /// (meaningful with `Numbered`; with `Label` placeholders repeat).
    #[serde(default)]
    pub reversible: bool,
    /// Only redact spans at or above this severity.
    #[serde(default)]
    pub min_severity: Option<Severity>,
    /// Only redact spans at or above this confidence.
    #[serde(default)]
    pub min_confidence: Option<Confidence>,
}

/// Wire shape for `RedactOptions`: a flat object where `style` is optional and
/// defaults to `label`. (serde's `flatten` cannot default an internally tagged
/// enum, so the conversion is explicit.)
#[derive(Deserialize)]
struct RawOptions {
    #[serde(default)]
    style: Option<String>,
    #[serde(default)]
    keep_last: Option<usize>,
    #[serde(default)]
    reversible: bool,
    #[serde(default)]
    min_severity: Option<Severity>,
    #[serde(default)]
    min_confidence: Option<Confidence>,
}

impl TryFrom<RawOptions> for RedactOptions {
    type Error = String;
    fn try_from(raw: RawOptions) -> std::result::Result<Self, Self::Error> {
        let style = match raw.style.as_deref().map(str::to_ascii_lowercase).as_deref() {
            None | Some("label") => Style::Label,
            Some("numbered") => Style::Numbered,
            Some("mask") => Style::Mask {
                keep_last: raw.keep_last.unwrap_or_else(default_keep_last),
            },
            Some("hash") => Style::Hash,
            Some(other) => return Err(format!("unknown redaction style `{other}`")),
        };
        Ok(RedactOptions {
            style,
            reversible: raw.reversible,
            min_severity: raw.min_severity,
            min_confidence: raw.min_confidence,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedSpan {
    #[serde(flatten)]
    pub span: Span,
    pub placeholder: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapEntry {
    pub placeholder: String,
    pub original: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redaction {
    pub text: String,
    pub spans: Vec<RedactedSpan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub map: Option<Vec<MapEntry>>,
}

impl Redaction {
    /// Put originals back into `text` (typically an LLM reply that echoed
    /// placeholders). No-op when the redaction was not reversible.
    pub fn restore(&self, text: &str) -> String {
        let Some(map) = &self.map else {
            return text.to_string();
        };
        let mut out = text.to_string();
        for entry in map {
            out = out.replace(&entry.placeholder, &entry.original);
        }
        out
    }
}

impl Engine {
    /// Scan then replace. Spans filtered out by `min_*` are left in place and
    /// not reported.
    pub fn redact(&self, text: &str, opts: &RedactOptions) -> Redaction {
        let spans = self
            .scan(text)
            .into_iter()
            .filter(|s| opts.min_severity.is_none_or(|m| s.severity >= m))
            .filter(|s| opts.min_confidence.is_none_or(|m| s.confidence >= m))
            .collect::<Vec<_>>();
        apply(text, spans, opts)
    }
}

fn apply(text: &str, spans: Vec<Span>, opts: &RedactOptions) -> Redaction {
    let mut out = String::with_capacity(text.len());
    let mut redacted = Vec::with_capacity(spans.len());
    let mut map: Vec<MapEntry> = Vec::new();
    let mut numbering: HashMap<(String, String), usize> = HashMap::new();
    let mut counters: HashMap<String, usize> = HashMap::new();
    let mut cursor = 0;

    for span in spans {
        let original = span.slice(text);
        let placeholder = match &opts.style {
            Style::Label => format!("[{}]", span.label),
            Style::Numbered => {
                let key = (span.label.to_string(), original.to_string());
                let n = *numbering.entry(key).or_insert_with(|| {
                    let c = counters.entry(span.label.to_string()).or_insert(0);
                    *c += 1;
                    *c
                });
                format!("[{}_{}]", span.label, n)
            }
            Style::Mask { keep_last } => mask(original, *keep_last),
            Style::Hash => {
                let digest = Sha256::digest(original.as_bytes());
                let hex: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
                format!("[{}:{}]", span.label, hex)
            }
        };
        out.push_str(&text[cursor..span.start]);
        out.push_str(&placeholder);
        cursor = span.end;
        if opts.reversible && !map.iter().any(|m| m.placeholder == placeholder) {
            map.push(MapEntry {
                placeholder: placeholder.clone(),
                original: original.to_string(),
            });
        }
        redacted.push(RedactedSpan { span, placeholder });
    }
    out.push_str(&text[cursor..]);

    Redaction {
        text: out,
        spans: redacted,
        map: if opts.reversible { Some(map) } else { None },
    }
}

/// Replace every alphanumeric char except the last `keep_last` with `*`.
fn mask(s: &str, keep_last: usize) -> String {
    let total = s.chars().filter(char::is_ascii_alphanumeric).count();
    let hide = total.saturating_sub(keep_last);
    let mut seen = 0;
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                seen += 1;
                if seen <= hide {
                    return '*';
                }
            }
            c
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_keeps_separators_and_tail() {
        assert_eq!(mask("123-45-6789", 4), "***-**-6789");
        assert_eq!(mask("4111 1111 1111 1111", 4), "**** **** **** 1111");
        assert_eq!(mask("ab", 4), "ab");
        assert_eq!(mask("abcdef", 0), "******");
    }

    #[test]
    fn style_json_shapes() {
        let o: RedactOptions = serde_json::from_str(r#"{"style":"mask","keep_last":2}"#).unwrap();
        assert_eq!(o.style, Style::Mask { keep_last: 2 });
        let o: RedactOptions =
            serde_json::from_str(r#"{"style":"numbered","reversible":true}"#).unwrap();
        assert_eq!(o.style, Style::Numbered);
        assert!(o.reversible);
        let o: RedactOptions = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(o.style, Style::Label);
        let o: RedactOptions = serde_json::from_str(r#"{"style":"mask"}"#).unwrap();
        assert_eq!(o.style, Style::Mask { keep_last: 4 });
        assert!(serde_json::from_str::<RedactOptions>(r#"{"style":"blur"}"#).is_err());
        let round: RedactOptions = serde_json::from_str(
            &serde_json::to_string(&RedactOptions {
                style: Style::Mask { keep_last: 2 },
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(round.style, Style::Mask { keep_last: 2 });
    }
}
