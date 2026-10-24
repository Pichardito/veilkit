import type {
  CreateEngineOptions,
  PackName,
  RedactOptions,
  Redaction,
  RuleInfo,
  Span,
} from "./types.js";

/** The shape wasm-bindgen generates for `WasmEngine`, for either target. */
export interface RawEngine {
  scan(text: string): string;
  redact(text: string, optionsJson?: string | null): string;
  rules(): string;
  ruleCount(): number;
  maxInputBytes(): number;
  free(): void;
}

export interface RawModule {
  createEngine(packs: string[], customToml?: string | null): RawEngine;
  packsVersion(): string;
  version(): string;
}

const ALL_PACKS: PackName[] = ["pii", "phi-us", "secrets", "finance"];

function toWireOptions(o: RedactOptions | undefined): string | null {
  if (!o) return null;
  const wire: Record<string, unknown> = {};
  if ("style" in o && o.style) wire.style = o.style;
  if ("keepLast" in o && o.keepLast !== undefined) wire.keep_last = o.keepLast;
  if (o.reversible) wire.reversible = true;
  if (o.minSeverity) wire.min_severity = o.minSeverity;
  if (o.minConfidence) wire.min_confidence = o.minConfidence;
  return JSON.stringify(wire);
}

/**
 * Typed facade over the WASM engine. Build once with `createEngine`, reuse,
 * and call `dispose()` when done to free WASM memory (or let it leak at exit).
 */
export class VeilkitEngine {
  #raw: RawEngine;

  constructor(raw: RawEngine) {
    this.#raw = raw;
  }

  scan(text: string): Span[] {
    return JSON.parse(this.#raw.scan(text)) as Span[];
  }

  redact(text: string, options?: RedactOptions): Redaction {
    return JSON.parse(this.#raw.redact(text, toWireOptions(options))) as Redaction;
  }

  /** Put originals back into `text` using a reversible redaction's map. */
  restore(redaction: Redaction, text: string): string {
    let out = text;
    for (const { placeholder, original } of redaction.map ?? []) {
      out = out.split(placeholder).join(original);
    }
    return out;
  }

  rules(): RuleInfo[] {
    return JSON.parse(this.#raw.rules()) as RuleInfo[];
  }

  get ruleCount(): number {
    return this.#raw.ruleCount();
  }

  get maxInputBytes(): number {
    return this.#raw.maxInputBytes();
  }

  dispose(): void {
    this.#raw.free();
  }
}

export function makeCreateEngine(mod: RawModule) {
  return function createEngine(options: CreateEngineOptions = {}): VeilkitEngine {
    const packs = options.packs ?? ALL_PACKS;
    const raw = mod.createEngine(packs, options.customRulesToml ?? null);
    return new VeilkitEngine(raw);
  };
}
