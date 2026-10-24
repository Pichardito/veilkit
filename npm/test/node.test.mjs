import { test } from "node:test";
import assert from "node:assert/strict";
import { createEngine, packsVersion, version } from "../dist/node.js";

test("round-trips a numbered, reversible redaction", () => {
  const engine = createEngine({ packs: ["pii", "secrets"] });
  const input = "SSN 219-09-9999, again 219-09-9999, key AKIAIOSFODNN7EXAMPLE, mail a@b.co";
  const red = engine.redact(input, { style: "numbered", reversible: true });
  assert.equal(red.text, "SSN [SSN_1], again [SSN_1], key [AWS_ACCESS_KEY_ID_1], mail [EMAIL_1]");
  assert.equal(red.spans.length, 4);
  assert.equal(red.map.length, 3);
  assert.equal(engine.restore(red, red.text), input);
  engine.dispose();
});

test("scan returns typed spans with byte offsets", () => {
  const engine = createEngine({ packs: ["pii"] });
  const spans = engine.scan("ip 10.0.0.1 ssn 219-09-9999");
  assert.deepEqual(
    spans.map((s) => [s.id, s.severity, s.confidence, s.start, s.end]),
    [["pii.ipv4", "low", "medium", 3, 11], ["pii.ssn", "high", "high", 16, 27]],
  );
  engine.dispose();
});

test("mask and hash styles, severity filter", () => {
  const engine = createEngine({ packs: ["pii"] });
  assert.equal(engine.redact("219-09-9999", { style: "mask", keepLast: 4 }).text, "***-**-9999");
  assert.match(engine.redact("219-09-9999", { style: "hash" }).text, /^\[SSN:[0-9a-f]{8}\]$/);
  assert.equal(engine.redact("ip 10.0.0.1 ssn 219-09-9999", { minSeverity: "high" }).text, "ip 10.0.0.1 ssn [SSN]");
  engine.dispose();
});

test("custom rules override by id and add new ids", () => {
  const toml = `version = "2026.10"
[[rule]]
id = "custom.ticket"
severity = "medium"
pattern = 'TCK-\\d{4}'
[[rule]]
id = "pii.email"
severity = "low"
pattern = 'nobody@nowhere'
`;
  const engine = createEngine({ packs: ["pii"], customRulesToml: toml });
  assert.equal(engine.redact("TCK-0001 jane@example.com nobody@nowhere").text, "[TICKET] jane@example.com [EMAIL]");
  assert.ok(engine.rules().some((r) => r.id === "custom.ticket"));
  engine.dispose();
});

test("errors are JS errors, never traps", () => {
  assert.throws(() => createEngine({ packs: ["pci"] }), /unknown pack/);
  assert.throws(() => createEngine({ customRulesToml: "not = toml [" }), /parse/);
  const engine = createEngine({ packs: ["pii"] });
  const big = "x".repeat(engine.maxInputBytes + 1);
  assert.throws(() => engine.scan(big), /exceeds/);
  assert.throws(() => engine.redact("x", { style: "blur" }), /unknown redaction style/);
  engine.dispose();
});

test("metadata", () => {
  assert.equal(packsVersion, "2026.10");
  assert.match(version, /^\d+\.\d+\.\d+$/);
  const engine = createEngine();
  assert.ok(engine.ruleCount >= 40);
  engine.dispose();
});
