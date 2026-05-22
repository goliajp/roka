/* @ts-self-types="./roka_wasm.d.ts" */

/**
 * Parsed otpauth URI fields the PWA needs to populate a new account.
 */
export class OtpauthFields {
    static __wrap(ptr) {
        const obj = Object.create(OtpauthFields.prototype);
        obj.__wbg_ptr = ptr;
        OtpauthFieldsFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        OtpauthFieldsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_otpauthfields_free(ptr, 0);
    }
    /**
     * Account label (typically a user identifier).
     * @returns {string}
     */
    get account() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.otpauthfields_account(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Issuer label (service name).
     * @returns {string}
     */
    get issuer() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.otpauthfields_issuer(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Secret, base32-encoded.
     * @returns {string}
     */
    get secret_base32() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.otpauthfields_secret_base32(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) OtpauthFields.prototype[Symbol.dispose] = OtpauthFields.prototype.free;

/**
 * One TOTP account: secret + display metadata.
 *
 * `TotpAccount` is the unit of work in the PWA — a Rust-side handle to a
 * Secret + a `Totp` config bundle. JS keeps the metadata (issuer / account
 * labels) in `localStorage`; this struct lives only for the duration of an
 * `otp_at` / `verify_at` call.
 */
export class TotpAccount {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        TotpAccountFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_totpaccount_free(ptr, 0);
    }
    /**
     * Build a `TotpAccount` from a base32 secret.
     * @param {string} secret_base32
     */
    constructor(secret_base32) {
        const ptr0 = passStringToWasm0(secret_base32, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.totpaccount_new(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0];
        TotpAccountFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Compute the OTP at a given UNIX-epoch seconds timestamp.
     *
     * JS callers pass `Math.floor(Date.now() / 1000)` — WASM has no clock.
     * @param {bigint} unix_seconds
     * @returns {string}
     */
    otp_at(unix_seconds) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.totpaccount_otp_at(this.__wbg_ptr, unix_seconds);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Seconds remaining in the current 30-second window.
     * @param {bigint} unix_seconds
     * @returns {number}
     */
    seconds_remaining_at(unix_seconds) {
        const ret = wasm.totpaccount_seconds_remaining_at(this.__wbg_ptr, unix_seconds);
        return ret >>> 0;
    }
}
if (Symbol.dispose) TotpAccount.prototype[Symbol.dispose] = TotpAccount.prototype.free;

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
    static __wrap(ptr) {
        const obj = Object.create(WasmVault.prototype);
        obj.__wbg_ptr = ptr;
        WasmVaultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmVaultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmvault_free(ptr, 0);
    }
    /**
     * Account label for account at `index`. Empty string if out of bounds.
     * @param {number} index
     * @returns {string}
     */
    account_label(index) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.wasmvault_account_label(this.__wbg_ptr, index);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Add an account from explicit fields (`secret_base32` is decoded).
     * @param {string} issuer
     * @param {string} account
     * @param {string} secret_base32
     */
    add(issuer, account, secret_base32) {
        const ptr0 = passStringToWasm0(issuer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(account, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(secret_base32, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmvault_add(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Add an account from an `otpauth://` URI.
     * @param {string} uri
     */
    add_from_uri(uri) {
        const ptr0 = passStringToWasm0(uri, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmvault_add_from_uri(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Issuer for account at `index`. Empty string if out of bounds.
     * @param {number} index
     * @returns {string}
     */
    issuer(index) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.wasmvault_issuer(this.__wbg_ptr, index);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Number of accounts.
     * @returns {number}
     */
    len() {
        const ret = wasm.wasmvault_len(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Create an empty unlocked vault in memory (no salt/key yet — `seal_initial` sets them).
     */
    constructor() {
        const ret = wasm.wasmvault_new();
        this.__wbg_ptr = ret;
        WasmVaultFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * OTP at `unix_seconds` for account `index`.
     * @param {number} index
     * @param {bigint} unix_seconds
     * @returns {string}
     */
    otp_at(index, unix_seconds) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.wasmvault_otp_at(this.__wbg_ptr, index, unix_seconds);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Remove account by index. Returns `false` if out of bounds.
     * @param {number} index
     * @returns {boolean}
     */
    remove(index) {
        const ret = wasm.wasmvault_remove(this.__wbg_ptr, index);
        return ret !== 0;
    }
    /**
     * Re-seal an already-unlocked vault using the cached key. `nonce_12b` must be
     * 12 fresh random bytes. **Will fail** if vault is locked.
     * @param {Uint8Array} nonce_12b
     * @returns {Uint8Array}
     */
    reseal(nonce_12b) {
        const ptr0 = passArray8ToWasm0(nonce_12b, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmvault_reseal(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * First-time seal: derives a fresh key from `password` + the salt in `random_28b[..16]`,
     * then seals using `random_28b[16..28]` as nonce. Caches the key for `reseal`.
     * `iterations = 0` means use the library default (600 000).
     * @param {string} password
     * @param {Uint8Array} random_28b
     * @param {number} iterations
     * @returns {Uint8Array}
     */
    seal_initial(password, random_28b, iterations) {
        const ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(random_28b, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmvault_seal_initial(this.__wbg_ptr, ptr0, len0, ptr1, len1, iterations);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
    /**
     * Unlock an existing sealed vault. PBKDF2 runs here (~200 ms on M2).
     * Caches the derived key for cheap subsequent `reseal()`.
     * @param {Uint8Array} sealed
     * @param {string} password
     * @returns {WasmVault}
     */
    static unlock(sealed, password) {
        const ptr0 = passArray8ToWasm0(sealed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmvault_unlock(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return WasmVault.__wrap(ret[0]);
    }
}
if (Symbol.dispose) WasmVault.prototype[Symbol.dispose] = WasmVault.prototype.free;

/**
 * Parse an `otpauth://totp/...` URI into the fields the PWA needs.
 *
 * Accepts the standard layout `otpauth://totp/{label}?secret=...&issuer=...`.
 * The label is split on `:` into issuer/account; if there's no `:`, the whole
 * label becomes the account and the `issuer` query parameter (if any) becomes
 * the issuer.
 * @param {string} uri
 * @returns {OtpauthFields}
 */
export function parse_otpauth_uri(uri) {
    const ptr0 = passStringToWasm0(uri, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.parse_otpauth_uri(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return OtpauthFields.__wrap(ret[0]);
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_bce6d499ff0a4aff: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg___wbindgen_throw_9c31b086c2b26051: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./roka_wasm_bg.js": import0,
    };
}

const OtpauthFieldsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_otpauthfields_free(ptr, 1));
const TotpAccountFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_totpaccount_free(ptr, 1));
const WasmVaultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmvault_free(ptr, 1));

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('roka_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
