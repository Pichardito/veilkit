// Bundler entry (webpack 5, Vite, Rollup with a wasm plugin): the generated
// glue imports the .wasm as an ES module. For Node use "veilkit/node".
import * as mod from "../pkg/bundler/veilkit.js";
import { makeCreateEngine } from "./engine.js";

export * from "./types.js";
export { VeilkitEngine } from "./engine.js";

export const createEngine = makeCreateEngine(mod);
export const packsVersion: string = mod.packsVersion();
export const version: string = mod.version();
