// Roka PWA — v1.0-β: encrypted vault.
//
// localStorage now holds only AEAD-encrypted bytes (base64). The master password
// derives a PBKDF2 key; the cached key in WasmVault encrypts/decrypts. Locking
// the vault drops the JS reference, freeing the cached key.

import init, { TotpAccount, WasmVault } from './pkg/roka_wasm.js';

const STORAGE_KEY = 'roka.vault.v1';   // base64 of sealed bytes
const STEP_SECONDS = 30;
const RING_CIRC = 94.2477796077;

// ───────────────────── persistence helpers ────────────────────────────

function loadVaultBytes() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    const bin = atob(raw);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

function saveVaultBytes(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  localStorage.setItem(STORAGE_KEY, btoa(bin));
}

function randomBytes(n) {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

// ───────────────────── state ─────────────────────────────────────────

/** @type {WasmVault | null} */
let vault = null;
let lastWindowIdx = null;

// ───────────────────── DOM bootstrap ─────────────────────────────────

const $ = (sel) => document.querySelector(sel);

function show(el) { el.classList.remove('hidden'); }
function hide(el) { el.classList.add('hidden'); }

function showError(elId, msg) {
  const el = document.getElementById(elId);
  el.textContent = msg;
  el.classList.add('visible');
}
function clearError(elId) {
  const el = document.getElementById(elId);
  el.textContent = '';
  el.classList.remove('visible');
}

// ───────────────────── unlock / create flow ───────────────────────────

function showUnlockScreen() {
  const exists = loadVaultBytes() !== null;
  $('#auth-mode').textContent = exists ? 'Unlock' : 'Create vault';
  $('#auth-hint').textContent = exists
    ? 'Enter your master password.'
    : 'Choose a master password. Cannot be recovered if lost.';
  $('#confirm-row').classList.toggle('hidden', exists);
  show($('#auth-screen'));
  hide($('#main-screen'));
  $('#auth-password').focus();
}

function showMainScreen() {
  hide($('#auth-screen'));
  show($('#main-screen'));
  render();
}

async function tryUnlock() {
  clearError('auth-error');
  const pw = $('#auth-password').value;
  if (!pw) {
    showError('auth-error', 'Password required.');
    return;
  }
  const sealed = loadVaultBytes();
  if (sealed) {
    // existing vault — unlock (PBKDF2 runs here, ~200ms)
    try {
      vault = WasmVault.unlock(sealed, pw);
    } catch (e) {
      showError('auth-error', 'Wrong password.');
      return;
    }
  } else {
    // new vault — confirm password matches, create + seal
    const confirm = $('#auth-password-confirm').value;
    if (pw !== confirm) {
      showError('auth-error', 'Passwords do not match.');
      return;
    }
    if (pw.length < 8) {
      showError('auth-error', 'Master password must be ≥ 8 characters.');
      return;
    }
    vault = new WasmVault();
    try {
      const rand = randomBytes(28);
      const sealed = vault.seal_initial(pw, rand, 0);
      saveVaultBytes(sealed);
    } catch (e) {
      showError('auth-error', String(e.message || e));
      return;
    }
  }
  // clear password from DOM
  $('#auth-password').value = '';
  $('#auth-password-confirm').value = '';
  showMainScreen();
}

function lockVault() {
  // Drop the cached key (best-effort — JS GC can't guarantee zeroing).
  vault = null;
  // Clear any rendered codes from DOM in case they linger.
  $('#accounts').replaceChildren();
  showUnlockScreen();
}

// ───────────────────── add / remove ──────────────────────────────────

function persist() {
  if (!vault) return;
  const nonce = randomBytes(12);
  const sealed = vault.reseal(nonce);
  saveVaultBytes(sealed);
}

function addFromForm() {
  if (!vault) return;
  clearError('add-error');
  const uri = $('#uri-input').value.trim();
  try {
    if (uri) {
      vault.add_from_uri(uri);
    } else {
      const issuer = $('#issuer-input').value.trim() || 'Untitled';
      const account = $('#account-input').value.trim();
      const secret = $('#secret-input').value.trim().replace(/\s+/g, '');
      if (!secret) {
        showError('add-error', 'Secret required.');
        return;
      }
      vault.add(issuer, account, secret);
    }
  } catch (e) {
    showError('add-error', String(e.message || e));
    return;
  }
  persist();
  $('#uri-input').value = '';
  $('#issuer-input').value = '';
  $('#account-input').value = '';
  $('#secret-input').value = '';
  $('#uri-input').focus();
  render();
}

function removeAccount(index) {
  if (!vault) return;
  vault.remove(index);
  persist();
  render();
}

// ───────────────────── render ────────────────────────────────────────

function render() {
  const accountsEl = $('#accounts');
  const emptyEl = $('#empty-state');
  if (!vault || vault.len() === 0) {
    emptyEl.classList.remove('hidden');
    accountsEl.replaceChildren();
    return;
  }
  emptyEl.classList.add('hidden');

  const frag = document.createDocumentFragment();
  for (let i = 0; i < vault.len(); i++) {
    frag.appendChild(createCard(i));
  }
  accountsEl.replaceChildren(frag);
  updateAllCodes();
}

function createCard(index) {
  const li = document.createElement('li');
  li.className = 'account-card';
  li.dataset.idx = index;

  const meta = document.createElement('div');
  meta.className = 'account-card__meta';
  const issuer = document.createElement('div');
  issuer.className = 'account-card__issuer';
  issuer.textContent = vault.issuer(index) || '—';
  const acct = document.createElement('div');
  acct.className = 'account-card__account';
  acct.textContent = vault.account_label(index);
  meta.appendChild(issuer);
  meta.appendChild(acct);

  const code = document.createElement('button');
  code.type = 'button';
  code.className = 'account-card__code';
  code.dataset.role = 'code';
  code.title = 'Copy code';
  code.textContent = '······';
  code.addEventListener('click', () => copyCode(index));

  const countdown = document.createElement('div');
  countdown.className = 'account-card__countdown';
  countdown.innerHTML = `
    <svg class="countdown-ring" viewBox="0 0 36 36" aria-hidden="true">
      <circle class="countdown-ring__track" cx="18" cy="18" r="15"></circle>
      <circle class="countdown-ring__fill"  cx="18" cy="18" r="15"></circle>
    </svg>
    <span class="countdown-ring__label" data-role="countdown">30</span>
  `;

  const remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'account-card__remove';
  remove.setAttribute('aria-label', 'Remove account');
  remove.textContent = '×';
  remove.addEventListener('click', () => {
    if (confirm(`Remove ${vault.issuer(index) || 'account'}?`)) removeAccount(index);
  });

  li.appendChild(meta);
  li.appendChild(code);
  li.appendChild(countdown);
  li.appendChild(remove);
  return li;
}

function updateAllCodes() {
  if (!vault) return;
  const accountsEl = $('#accounts');
  const nowSec = Math.floor(Date.now() / 1000);
  const winIdx = Math.floor(nowSec / STEP_SECONDS);
  const remaining = STEP_SECONDS - (nowSec % STEP_SECONDS);
  const windowChanged = lastWindowIdx !== null && winIdx !== lastWindowIdx;
  lastWindowIdx = winIdx;

  for (const li of accountsEl.children) {
    const idx = parseInt(li.dataset.idx, 10);
    let codeStr;
    try {
      codeStr = vault.otp_at(idx, BigInt(nowSec));
    } catch (e) {
      codeStr = '------';
    }
    const codeEl = li.querySelector('[data-role="code"]');
    const labelEl = li.querySelector('[data-role="countdown"]');
    const ringFill = li.querySelector('.countdown-ring__fill');

    const formatted = codeStr.length === 6
      ? `${codeStr.slice(0, 3)} ${codeStr.slice(3)}`
      : codeStr;
    if (codeEl.textContent !== formatted) {
      codeEl.textContent = formatted;
      if (windowChanged) {
        codeEl.classList.remove('fresh');
        void codeEl.offsetWidth;
        codeEl.classList.add('fresh');
        setTimeout(() => codeEl.classList.remove('fresh'), 520);
      }
    }
    labelEl.textContent = remaining;
    const offset = RING_CIRC * (1 - remaining / STEP_SECONDS);
    ringFill.style.strokeDashoffset = offset.toFixed(3);

    if (remaining < 5) {
      li.classList.add('warning');
      codeEl.classList.add('warning');
    } else {
      li.classList.remove('warning');
      codeEl.classList.remove('warning');
    }
  }
}

async function copyCode(index) {
  if (!vault) return;
  const li = $('#accounts').querySelector(`[data-idx="${index}"]`);
  if (!li) return;
  const codeEl = li.querySelector('[data-role="code"]');
  const raw = (codeEl.textContent || '').replace(/\s+/g, '');
  try {
    await navigator.clipboard.writeText(raw);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = raw;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  codeEl.classList.remove('copied');
  void codeEl.offsetWidth;
  codeEl.classList.add('copied');
  setTimeout(() => codeEl.classList.remove('copied'), 600);
}

// ───────────────────── boot ──────────────────────────────────────────

(async function boot() {
  try {
    await init();
  } catch (e) {
    document.body.innerHTML = `<pre style="color:#d94340;padding:2rem">Failed to load WASM: ${e}</pre>`;
    return;
  }
  // Wire DOM
  $('#auth-submit').addEventListener('click', tryUnlock);
  $('#auth-password').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); tryUnlock(); }
  });
  $('#auth-password-confirm').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); tryUnlock(); }
  });
  $('#lock-btn').addEventListener('click', lockVault);
  $('#add-btn').addEventListener('click', addFromForm);
  for (const el of ['#uri-input', '#issuer-input', '#account-input', '#secret-input']) {
    $(el).addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); addFromForm(); }
    });
  }

  showUnlockScreen();

  // Live update loop
  const tick = () => updateAllCodes();
  const msToNext = 1000 - (Date.now() % 1000);
  setTimeout(() => { tick(); setInterval(tick, 1000); }, msToNext);

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./service-worker.js').catch(() => {});
  }
  // suppress unused import warning
  void TotpAccount;
})();
