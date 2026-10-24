use assert_cmd::Command;
use predicates::prelude::*;

fn veilkit() -> Command {
    Command::cargo_bin("veilkit").unwrap()
}

#[test]
fn redact_from_stdin_default_label_style() {
    veilkit()
        .args(["redact", "--packs", "pii"])
        .write_stdin("ssn 219-09-9999 mail a@b.co")
        .assert()
        .success()
        .stdout("ssn [SSN] mail [EMAIL]");
}

#[test]
fn redact_numbered_json_reversible() {
    veilkit()
        .args([
            "redact",
            "--packs",
            "pii",
            "--style",
            "numbered",
            "--json",
            "--reversible",
        ])
        .write_stdin("219-09-9999 and 219-09-9999")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"[SSN_1]\"")
                .and(predicate::str::contains("\"original\": \"219-09-9999\"")),
        );
}

#[test]
fn redact_mask_keep_last() {
    veilkit()
        .args([
            "redact",
            "--packs",
            "pii",
            "--style",
            "mask",
            "--keep-last",
            "2",
        ])
        .write_stdin("219-09-9999")
        .assert()
        .success()
        .stdout("***-**-**99");
}

#[test]
fn scan_text_and_json() {
    veilkit()
        .args(["scan", "--packs", "secrets"])
        .write_stdin("key AKIAIOSFODNN7EXAMPLE here")
        .assert()
        .success()
        .stdout(predicate::str::starts_with(
            "secret.aws_access_key_id\tHigh\tMedium\t4..24\tAKIAIOSFODNN7EXAMPLE",
        ));
    veilkit()
        .args(["scan", "--format", "json"])
        .write_stdin("nothing sensitive")
        .assert()
        .success()
        .stdout("[]\n");
}

#[test]
fn fail_on_gate_exit_code_2() {
    veilkit()
        .args(["scan", "--fail-on", "high"])
        .write_stdin("AKIAIOSFODNN7EXAMPLE")
        .assert()
        .code(2);
    veilkit()
        .args(["scan", "--fail-on", "high"])
        .write_stdin("ip 10.0.0.1")
        .assert()
        .success();
    veilkit()
        .args(["redact", "--fail-on", "medium"])
        .write_stdin("mail a@b.co")
        .assert()
        .code(2)
        .stdout("mail [EMAIL]");
}

#[test]
fn files_and_custom_rules() {
    let dir = tempdir();
    let input = dir.join("in.txt");
    let rules = dir.join("rules.toml");
    std::fs::write(&input, "ticket TCK-0001 for a@b.co").unwrap();
    std::fs::write(
        &rules,
        "version = \"2026.10\"\n[[rule]]\nid = \"custom.ticket\"\nseverity = \"high\"\npattern = 'TCK-\\d{4}'\n",
    )
    .unwrap();
    veilkit()
        .args(["redact", "--packs", "pii", "--rules"])
        .arg(&rules)
        .arg(&input)
        .assert()
        .success()
        .stdout("ticket [TICKET] for [EMAIL]\n");
}

#[test]
fn unknown_pack_is_a_usage_error() {
    veilkit()
        .args(["scan", "--packs", "pci"])
        .write_stdin("x")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("unknown pack"));
}

#[test]
fn packs_markdown_lists_rules() {
    veilkit()
        .args(["packs", "--markdown", "--packs", "finance"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("| `fin.routing_aba` |")
                .and(predicate::str::contains("`routing_aba`")),
        );
}

fn tempdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("veilkit-cli-test-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
