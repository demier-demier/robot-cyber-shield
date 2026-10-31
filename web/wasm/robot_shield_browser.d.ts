/* tslint:disable */
/* eslint-disable */

/**
 * Live verification using the same Rust rules as the native guard.
 * This adapter has only in-memory state and uses an explicit logical clock.
 */
export class BrowserGuard {
    free(): void;
    [Symbol.dispose](): void;
    decide(envelope_json: string, logical_now_ms: number): string;
    constructor(policy_json: string, authority_hex: string);
    revoke(grant_id: string): void;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_browserguard_free: (a: number, b: number) => void;
    readonly browserguard_decide: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly browserguard_new: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly browserguard_revoke: (a: number, b: number, c: number) => [number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
