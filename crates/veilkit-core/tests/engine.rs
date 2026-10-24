use veilkit_core::{Confidence, Engine, Error, Pack, RedactOptions, Severity, Style};

fn pii() -> Engine {
    Engine::builder().pack(Pack::Pii).build().unwrap()
}

#[test]
fn spans_are_sorted_and_non_overlapping() {
    let e = Engine::all_packs().unwrap();
    let text = "SSN 123-45-6789 and card 4111 1111 1111 1111 and routing number 021000021 ok";
    let spans = e.scan(text);
    for w in spans.windows(2) {
        assert!(w[0].end <= w[1].start, "overlap: {:?} {:?}", w[0], w[1]);
    }
    let ids: Vec<&str> = spans.iter().map(|s| &*s.id).collect();
    assert_eq!(ids, vec!["pii.ssn", "pii.credit_card", "fin.routing_aba"]);
}

#[test]
fn longest_span_wins_then_severity_then_rule_order() {
    // A custom rule set where candidates collide deliberately.
    let toml = r#"
version = "2026.10"
[[rule]]
id = "t.short_high"
severity = "high"
pattern = 'abc'
[[rule]]
id = "t.long_low"
severity = "low"
pattern = 'abcdef'
[[rule]]
id = "t.same_len_medium"
severity = "medium"
pattern = 'xyz'
[[rule]]
id = "t.same_len_high"
severity = "high"
pattern = 'xyz'
[[rule]]
id = "t.first_declared"
severity = "low"
pattern = 'qq'
[[rule]]
id = "t.second_declared"
severity = "low"
pattern = 'qq'
"#;
    let e = Engine::builder()
        .custom_rules_toml(toml)
        .unwrap()
        .build()
        .unwrap();
    let ids: Vec<String> = e
        .scan("abcdef xyz qq")
        .iter()
        .map(|s| s.id.to_string())
        .collect();
    assert_eq!(
        ids,
        vec!["t.long_low", "t.same_len_high", "t.first_declared"]
    );
}

#[test]
fn custom_rule_overrides_builtin_by_id_and_new_ids_append() {
    let toml = r#"
version = "2026.10"
[[rule]]
id = "pii.email"
severity = "low"
pattern = 'nobody@nowhere'
[[rule]]
id = "custom.ticket"
severity = "medium"
pattern = 'TCK-\d{4}'
"#;
    let e = Engine::builder()
        .pack(Pack::Pii)
        .custom_rules_toml(toml)
        .unwrap()
        .build()
        .unwrap();
    assert!(
        e.scan("mail jane@example.com").is_empty(),
        "builtin email replaced"
    );
    let spans = e.scan("ref TCK-1234 from nobody@nowhere");
    let ids: Vec<&str> = spans.iter().map(|s| &*s.id).collect();
    assert_eq!(ids, vec!["custom.ticket", "pii.email"]);
    assert_eq!(spans[1].severity, Severity::Low);
    assert_eq!(e.rule_count(), pii().rule_count() + 1);
}

#[test]
fn duplicate_id_in_one_source_is_an_error() {
    let toml = r#"
version = "2026.10"
[[rule]]
id = "a.b"
severity = "low"
pattern = 'x'
[[rule]]
id = "a.b"
severity = "low"
pattern = 'y'
"#;
    let err = Engine::builder()
        .custom_rules_toml(toml)
        .unwrap()
        .build()
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateRule(id) if id == "a.b"));
}

#[test]
fn bad_regex_and_unknown_validator_and_pack_are_errors() {
    let bad =
        "version = \"2026.10\"\n[[rule]]\nid = \"a\"\nseverity = \"low\"\npattern = '(unclosed'\n";
    assert!(matches!(
        Engine::builder()
            .custom_rules_toml(bad)
            .unwrap()
            .build()
            .unwrap_err(),
        Error::InvalidPattern { .. }
    ));
    let unknown = "version = \"2026.10\"\n[[rule]]\nid = \"a\"\nseverity = \"low\"\npattern = 'x'\nvalidator = \"nope\"\n";
    assert!(matches!(
        Engine::builder()
            .custom_rules_toml(unknown)
            .unwrap()
            .build()
            .unwrap_err(),
        Error::UnknownValidator { .. }
    ));
    assert!(matches!(
        "pci".parse::<Pack>().unwrap_err(),
        Error::UnknownPack(_)
    ));
    assert!(matches!(
        Engine::builder().custom_rules_toml("this is = not toml ["),
        Err(Error::Parse(_))
    ));
}

#[test]
fn validator_and_context_drive_confidence() {
    let e = pii();
    let validated = e.scan("219-09-9999");
    assert_eq!(
        validated[0].confidence,
        Confidence::High,
        "validator passed"
    );

    let plain = e.scan("mail a@b.co");
    assert_eq!(
        plain[0].confidence,
        Confidence::Medium,
        "no validator, no context"
    );

    let with_ctx = e.scan("email: a@b.co");
    // pii.email has no context list, so still Medium.
    assert_eq!(with_ctx[0].confidence, Confidence::Medium);

    let toml = r#"
version = "2026.10"
[[rule]]
id = "t.ctx"
severity = "low"
pattern = 'WIDGET-\d+'
context = ["widget id"]
"#;
    let e = Engine::builder()
        .custom_rules_toml(toml)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(e.scan("WIDGET-9")[0].confidence, Confidence::Medium);
    assert_eq!(
        e.scan("Widget ID: WIDGET-9")[0].confidence,
        Confidence::High
    );
    assert_eq!(
        e.scan("WIDGET-9 is the widget id")[0].confidence,
        Confidence::High
    );
}

#[test]
fn require_context_drops_bare_matches() {
    let e = pii();
    assert!(e.scan("order 123456789").is_empty());
    assert_eq!(&*e.scan("SSN 123456789")[0].id, "pii.ssn_unformatted");
}

#[test]
fn redact_styles() {
    let e = pii();
    let text = "SSN 123-45-6789 twice: 123-45-6789, other 219-09-9999, mail a@b.co";

    let label = e.redact(text, &RedactOptions::default());
    assert_eq!(
        label.text,
        "SSN [SSN] twice: [SSN], other [SSN], mail [EMAIL]"
    );
    assert!(label.map.is_none());

    let numbered = e.redact(
        text,
        &RedactOptions {
            style: Style::Numbered,
            reversible: true,
            ..Default::default()
        },
    );
    assert_eq!(
        numbered.text,
        "SSN [SSN_1] twice: [SSN_1], other [SSN_2], mail [EMAIL_1]"
    );
    let map = numbered.map.as_ref().unwrap();
    assert_eq!(map.len(), 3, "one entry per distinct placeholder");
    assert_eq!(numbered.restore(&numbered.text), text);

    let mask = e.redact(
        text,
        &RedactOptions {
            style: Style::Mask { keep_last: 4 },
            ..Default::default()
        },
    );
    assert!(mask.text.starts_with("SSN ***-**-6789 twice: ***-**-6789"));

    let hash = e.redact(
        "219-09-9999",
        &RedactOptions {
            style: Style::Hash,
            ..Default::default()
        },
    );
    assert!(
        hash.text.starts_with("[SSN:") && hash.text.len() == "[SSN:".len() + 8 + 1,
        "{}",
        hash.text
    );
    let again = e.redact(
        "219-09-9999",
        &RedactOptions {
            style: Style::Hash,
            ..Default::default()
        },
    );
    assert_eq!(hash.text, again.text, "hash is stable");
}

#[test]
fn redact_filters_by_severity_and_confidence() {
    let e = pii();
    let text = "ip 10.0.0.1 ssn 219-09-9999";
    let only_high = e.redact(
        text,
        &RedactOptions {
            min_severity: Some(Severity::High),
            ..Default::default()
        },
    );
    assert_eq!(only_high.text, "ip 10.0.0.1 ssn [SSN]");
    let only_confident = e.redact(
        text,
        &RedactOptions {
            min_confidence: Some(Confidence::High),
            ..Default::default()
        },
    );
    assert_eq!(only_confident.text, "ip 10.0.0.1 ssn [SSN]");
    assert_eq!(only_confident.spans.len(), 1);
}

#[test]
fn utf8_around_matches_is_preserved() {
    let e = pii();
    let text = "café → a@b.co ← naïve 日本 219-09-9999 end";
    let out = e.redact(text, &RedactOptions::default());
    assert_eq!(out.text, "café → [EMAIL] ← naïve 日本 [SSN] end");
    // context window near multibyte chars must not panic
    assert!(!e
        .scan("日本語日本語日本語日本語 SSN 123456789 日本語")
        .is_empty());
}

#[test]
fn input_limit_is_enforced_by_boundaries_not_scan() {
    let big = "x".repeat(10);
    assert!(matches!(
        Engine::ensure_within_limit(&big, 5),
        Err(Error::InputTooLarge(10, 5))
    ));
    assert!(Engine::ensure_within_limit(&big, 10).is_ok());
}

#[test]
fn has_severity_at_least() {
    let e = Engine::all_packs().unwrap();
    assert!(e.has_severity_at_least("AKIAIOSFODNN7EXAMPLE", Severity::High));
    assert!(!e.has_severity_at_least("ip 10.0.0.1", Severity::Medium));
}
