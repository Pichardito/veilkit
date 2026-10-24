//! wasm-bindgen facade. Everything that crosses the boundary is a string
//! (text in, JSON out) so the JS glue stays small and the TypeScript wrapper
//! owns the types. No `unwrap` on any exported path; every failure becomes a
//! JS `Error`.

use wasm_bindgen::prelude::*;

use veilkit_core::{Engine, Pack, RedactOptions, DEFAULT_MAX_INPUT_BYTES};

fn js_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

/// A compiled engine held on the WASM side. Build once, call many times.
#[wasm_bindgen]
pub struct WasmEngine {
    inner: Engine,
    max_input: usize,
}

/// Build an engine from pack names (`"pii"`, `"phi-us"`, `"secrets"`,
/// `"finance"`) and optional custom rules in TOML.
#[wasm_bindgen(js_name = createEngine)]
pub fn create_engine(
    packs: Vec<String>,
    custom_toml: Option<String>,
) -> Result<WasmEngine, JsError> {
    let mut builder = Engine::builder();
    for p in &packs {
        let pack: Pack = p.parse().map_err(js_err)?;
        builder = builder.pack(pack);
    }
    if let Some(toml) = custom_toml {
        builder = builder.custom_rules_toml(&toml).map_err(js_err)?;
    }
    let inner = builder.build().map_err(js_err)?;
    Ok(WasmEngine {
        inner,
        max_input: DEFAULT_MAX_INPUT_BYTES,
    })
}

#[wasm_bindgen]
impl WasmEngine {
    /// Spans as a JSON array (see the TypeScript `Span` type).
    pub fn scan(&self, text: &str) -> Result<String, JsError> {
        Engine::ensure_within_limit(text, self.max_input).map_err(js_err)?;
        serde_json::to_string(&self.inner.scan(text)).map_err(js_err)
    }

    /// Redact with options given as JSON (`{"style":"numbered","reversible":true}`).
    /// Returns the `Redaction` as JSON.
    pub fn redact(&self, text: &str, options_json: Option<String>) -> Result<String, JsError> {
        Engine::ensure_within_limit(text, self.max_input).map_err(js_err)?;
        let opts: RedactOptions = match options_json {
            Some(s) if !s.trim().is_empty() => serde_json::from_str(&s).map_err(js_err)?,
            _ => RedactOptions::default(),
        };
        serde_json::to_string(&self.inner.redact(text, &opts)).map_err(js_err)
    }

    /// Rule summaries as JSON, for UIs that list what the engine detects.
    pub fn rules(&self) -> Result<String, JsError> {
        serde_json::to_string(&self.inner.rules()).map_err(js_err)
    }

    #[wasm_bindgen(js_name = ruleCount)]
    pub fn rule_count(&self) -> usize {
        self.inner.rule_count()
    }

    #[wasm_bindgen(js_name = maxInputBytes)]
    pub fn max_input_bytes(&self) -> usize {
        self.max_input
    }
}

#[wasm_bindgen(js_name = packsVersion)]
pub fn packs_version() -> String {
    veilkit_core::PACKS_VERSION.to_string()
}

#[wasm_bindgen]
pub fn version() -> String {
    veilkit_core::version().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_redact_natively() {
        let e = create_engine(vec!["pii".into()], None).unwrap();
        let out = e
            .redact("ssn 219-09-9999", Some(r#"{"style":"label"}"#.into()))
            .unwrap();
        assert!(out.contains("[SSN]"), "{out}");
        // The error path builds a `JsError`, which only exists on wasm32;
        // it is exercised by the node tests in npm/test.
    }
}
