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
 * PWA-side handle for an encrypted vault.
 *
 * JS lifecycle:
 * 1. **First-run**: `new WasmVault()` → user picks master password →
 *    `seal_initial(password, random_28b, 0)` → store bytes in localStorage.
 * 2. **Unlock**: `WasmVault.unlock(sealed_bytes, password)` derives & **caches** the
 *    master key, decrypts accounts. PBKDF2 runs once here (≈ 200 ms).
 * 3. **Modify**: `add`/`add_from_uri`/`remove` → `reseal(nonce_12b)` (no PBKDF2,
 *    a few ms). Caller provides 12 fresh random bytes per reseal.
 * 4. **Lock**: drop the WasmVault → cached key gone from memory.
 */
export class WasmVault {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Account label for account at `index`. Empty string if out of bounds.
     */
    account_label(index: number): string;
    /**
     * Add an account from explicit fields (`secret_base32` is decoded).
     */
    add(issuer: string, account: string, secret_base32: string): void;
    /**
     * Add an account from an `otpauth://` URI.
     */
    add_from_uri(uri: string): void;
    /**
     * Issuer for account at `index`. Empty string if out of bounds.
     */
    issuer(index: number): string;
    /**
     * Number of accounts.
     */
    len(): number;
    /**
     * Create an empty unlocked vault in memory (no salt/key yet — `seal_initial` sets them).
     */
    constructor();
    /**
     * OTP at `unix_seconds` for account `index`.
     */
    otp_at(index: number, unix_seconds: bigint): string;
    /**
     * Remove account by index. Returns `false` if out of bounds.
     */
    remove(index: number): boolean;
    /**
     * Re-seal an already-unlocked vault using the cached key. `nonce_12b` must be
     * 12 fresh random bytes. **Will fail** if vault is locked.
     */
    reseal(nonce_12b: Uint8Array): Uint8Array;
    /**
     * First-time seal: derives a fresh key from `password` + the salt in `random_28b[..16]`,
     * then seals using `random_28b[16..28]` as nonce. Caches the key for `reseal`.
     * `iterations = 0` means use the library default (600 000).
     */
    seal_initial(password: string, random_28b: Uint8Array, iterations: number): Uint8Array;
    /**
     * Unlock an existing sealed vault. PBKDF2 runs here (~200 ms on M2).
     * Caches the derived key for cheap subsequent `reseal()`.
     */
    static unlock(sealed: Uint8Array, password: string): WasmVault;
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
    readonly __wbg_wasmvault_free: (a: number, b: number) => void;
    readonly otpauthfields_account: (a: number) => [number, number];
    readonly otpauthfields_issuer: (a: number) => [number, number];
    readonly otpauthfields_secret_base32: (a: number) => [number, number];
    readonly parse_otpauth_uri: (a: number, b: number) => [number, number, number];
    readonly totpaccount_new: (a: number, b: number) => [number, number, number];
    readonly totpaccount_otp_at: (a: number, b: bigint) => [number, number];
    readonly totpaccount_seconds_remaining_at: (a: number, b: bigint) => number;
    readonly wasmvault_account_label: (a: number, b: number) => [number, number];
    readonly wasmvault_add: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
    readonly wasmvault_add_from_uri: (a: number, b: number, c: number) => [number, number];
    readonly wasmvault_issuer: (a: number, b: number) => [number, number];
    readonly wasmvault_len: (a: number) => number;
    readonly wasmvault_new: () => number;
    readonly wasmvault_otp_at: (a: number, b: number, c: bigint) => [number, number, number, number];
    readonly wasmvault_remove: (a: number, b: number) => number;
    readonly wasmvault_reseal: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmvault_seal_initial: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly wasmvault_unlock: (a: number, b: number, c: number, d: number) => [number, number, number];
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
