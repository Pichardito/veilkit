//! Every rule in every pack must have >= 2 positive and >= 1 negative fixture,
//! and the fixtures must behave: each positive yields a span with that id,
//! each negative yields none. This is the regression net for pattern edits.

use serde::Deserialize;
use veilkit_core::{Engine, Pack};

#[derive(Deserialize)]
struct FixtureFile {
    version: String,
    #[serde(rename = "fixture")]
    fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
struct Fixture {
    id: String,
    positive: Vec<String>,
    negative: Vec<String>,
}

fn fixtures_for(pack: Pack) -> FixtureFile {
    let src = match pack {
        Pack::Pii => include_str!("../../../packs/fixtures/pii.toml"),
        Pack::PhiUs => include_str!("../../../packs/fixtures/phi-us.toml"),
        Pack::Secrets => include_str!("../../../packs/fixtures/secrets.toml"),
        Pack::Finance => include_str!("../../../packs/fixtures/finance.toml"),
    };
    toml::from_str(src).expect("fixture file parses")
}

#[test]
fn every_rule_has_fixtures_and_they_pass() {
    let mut failures = Vec::new();
    for pack in Pack::ALL {
        let engine = Engine::builder().pack(pack).build().expect("pack compiles");
        let fixtures = fixtures_for(pack);
        assert_eq!(
            fixtures.version,
            veilkit_core::PACKS_VERSION,
            "{}",
            pack.name()
        );

        for rule in engine.rules() {
            let Some(fx) = fixtures.fixtures.iter().find(|f| f.id == rule.id) else {
                failures.push(format!("{}: no fixture entry", rule.id));
                continue;
            };
            if fx.positive.len() < 2 {
                failures.push(format!("{}: needs >= 2 positives", rule.id));
            }
            if fx.negative.is_empty() {
                failures.push(format!("{}: needs >= 1 negative", rule.id));
            }
            for p in &fx.positive {
                // `{{+}}` splits strings that secret scanners would otherwise
                // flag in the repo (fake Stripe keys); drop it before scanning.
                let p = &p.replace("{{+}}", "");
                let spans = engine.scan(p);
                if !spans.iter().any(|s| *s.id == rule.id) {
                    failures.push(format!(
                        "{}: positive {:?} not detected (got {:?})",
                        rule.id,
                        p,
                        spans.iter().map(|s| s.id.to_string()).collect::<Vec<_>>()
                    ));
                }
            }
            for n in &fx.negative {
                let n = &n.replace("{{+}}", "");
                let spans = engine.scan(n);
                if spans.iter().any(|s| *s.id == rule.id) {
                    failures.push(format!("{}: negative {:?} was detected", rule.id, n));
                }
            }
        }
        for fx in &fixtures.fixtures {
            if !engine.rules().iter().any(|r| r.id == fx.id) {
                failures.push(format!("{}: fixture for a rule that does not exist", fx.id));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "fixture failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn all_packs_together_have_unique_ids() {
    let engine = Engine::all_packs().expect("all packs build together");
    let mut ids: Vec<String> = engine.rules().into_iter().map(|r| r.id).collect();
    let before = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(before, ids.len());
    assert!(before >= 40, "expected a healthy rule count, got {before}");
}
