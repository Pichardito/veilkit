// Node entry: the nodejs wasm-bindgen target loads the .wasm synchronously
// from disk, so `createEngine` is synchronous here too.
import * as mod from "../pkg/node/veilkit.js";
import { makeCreateEngine } from "./engine.js";

export * from "./types.js";
export { VeilkitEngine } from "./engine.js";

export const createEngine = makeCreateEngine(mod);
export const packsVersion: string = mod.packsVersion();
export const version: string = mod.version();
