/* tslint:disable */
/* eslint-disable */

/**
 * Parsed otpauth URI fields the PWA needs to populate a new account.
 */
export class OtpauthFields {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Account label (typically a user identifier).
     */
    readonly account: string;
    /**
     * Issuer label (service name).
     */
    readonly issuer: string;
    /**
     * Secret, base32-encoded.
     */
    readonly secret_base32: string;
}

/**
 * One TOTP account: secret + display metadata.
 *
 * `TotpAccount` is the unit of work in the PWA — a Rust-side handle to a
 * Secret + a `Totp` config bundle. JS keeps the metadata (issuer / account
 * labels) in `localStorage`; this struct lives only for the duration of an
 * `otp_at` / `verify_at` call.
 */
export class TotpAccount {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Build a `TotpAccount` from a base32 secret.
     */
    constructor(secret_base32: string);
    /**
     * Compute the OTP at a given UNIX-epoch seconds timestamp.
     *
     * JS callers pass `Math.floor(Date.now() / 1000)` — WASM has no clock.
     */
    otp_at(unix_seconds: bigint): string;
    /**
     * Seconds remaining in the current 30-second window.
     */
    seconds_remaining_at(unix_seconds: bigint): number;
}

/**
 * Parse an `otpauth://totp/...` URI into the fields the PWA needs.
 *
 * Accepts the standard layout `otpauth://totp/{label}?secret=...&issuer=...`.
 * The label is split on `:` into issuer/account; if there's no `:`, the whole
 * label becomes the account and the `issuer` query parameter (if any) becomes
 * the issuer.
 */
export function parse_otpauth_uri(uri: string): OtpauthFields;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_otpauthfields_free: (a: number, b: number) => void;
    readonly __wbg_totpaccount_free: (a: number, b: number) => void;
    readonly otpauthfields_account: (a: number) => [number, number];
    readonly otpauthfields_issuer: (a: number) => [number, number];
    readonly otpauthfields_secret_base32: (a: number) => [number, number];
    readonly parse_otpauth_uri: (a: number, b: number) => [number, number, number];
    readonly totpaccount_new: (a: number, b: number) => [number, number, number];
    readonly totpaccount_otp_at: (a: number, b: bigint) => [number, number];
    readonly totpaccount_seconds_remaining_at: (a: number, b: bigint) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
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
