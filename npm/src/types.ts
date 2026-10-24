export type Severity = "low" | "medium" | "high";
export type Confidence = "low" | "medium" | "high";
export type PackName = "pii" | "phi-us" | "secrets" | "finance";

/** One detected region. `start`/`end` are UTF-8 byte offsets, `end` exclusive. */
export interface Span {
  id: string;
  label: string;
  start: number;
  end: number;
  severity: Severity;
  confidence: Confidence;
}

export type RedactStyle =
  | { style?: "label" }
  | { style: "numbered" }
  | { style: "mask"; keepLast?: number }
  | { style: "hash" };

export type RedactOptions = RedactStyle & {
  /** Return the placeholder → original map (use with `numbered`). */
  reversible?: boolean;
  minSeverity?: Severity;
  minConfidence?: Confidence;
};

export interface RedactedSpan extends Span {
  placeholder: string;
}

export interface MapEntry {
  placeholder: string;
  original: string;
}

export interface Redaction {
  text: string;
  spans: RedactedSpan[];
  map?: MapEntry[];
}

export interface RuleInfo {
  id: string;
  label: string;
  severity: Severity;
  validator: string | null;
  requires_context: boolean;
  description: string;
}

export interface CreateEngineOptions {
  /** Built-in packs to load. Default: all four. */
  packs?: PackName[];
  /** Custom rules in Veilkit's TOML pack format; overrides built-ins by id. */
  customRulesToml?: string;
}
