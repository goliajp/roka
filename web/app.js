// Roka PWA — TOTP UI controller.
//
// Loads the WASM bindings (roka-wasm), keeps an account list in localStorage,
// and refreshes the rendered OTPs every second. Per the alpha banner in
// index.html, secrets are stored cleartext in localStorage for v1.0-α;
// vault-crate encryption arrives in v1.0-β.

import init, { TotpAccount, parse_otpauth_uri } from './pkg/roka_wasm.js';

const STORAGE_KEY = 'roka.accounts.v1';
const STEP_SECONDS = 30;
const RING_CIRC = 94.2477796077; // 2 * π * 15 ; keep in sync with style.css countdown-ring

// ───────────────────── store ─────────────────────────────────────────────

/** Account schema:
 *  { id: string (uuid-ish), issuer: string, account: string, secret: string }
 */
function loadAccounts() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveAccounts(list) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
}

function newId() {
  // Crypto-grade uuid is overkill; we just need DOM-keying uniqueness.
  return 'a' + Math.random().toString(36).slice(2) + Date.now().toString(36);
}

// ───────────────────── wasm engine cache ─────────────────────────────────

// TotpAccount instances are cheap but require the secret bytes. Cache them
// per account ID so we don't re-decode base32 every second.
const engines = new Map(); // id → { totp: TotpAccount, secret: string }

function ensureEngine(account) {
  const cached = engines.get(account.id);
  if (cached && cached.secret === account.secret) {
    return cached.totp;
  }
  // Free the old WASM-side struct if any (TotpAccount.free is provided by wasm-bindgen).
  if (cached) cached.totp.free?.();
  const totp = new TotpAccount(account.secret);
  engines.set(account.id, { totp, secret: account.secret });
  return totp;
}

function disposeEngine(id) {
  const cached = engines.get(id);
  if (cached) {
    cached.totp.free?.();
    engines.delete(id);
  }
}

// ───────────────────── DOM refs ──────────────────────────────────────────

const $ = (sel) => document.querySelector(sel);
const accountsEl = $('#accounts');
const emptyEl = $('#empty-state');
const errorEl = $('#add-error');
const uriInput = $('#uri-input');
const issuerInput = $('#issuer-input');
const accountInput = $('#account-input');
const secretInput = $('#secret-input');
const addBtn = $('#add-btn');

// ───────────────────── rendering ─────────────────────────────────────────

let state = []; // mirror of localStorage

function render() {
  state = loadAccounts();
  if (state.length === 0) {
    emptyEl.classList.remove('hidden');
    accountsEl.replaceChildren();
    return;
  }
  emptyEl.classList.add('hidden');

  // Build DOM diff against current children
  const existing = new Map();
  for (const li of accountsEl.children) {
    existing.set(li.dataset.id, li);
  }

  // Build new DOM in order; reuse existing where possible
  const frag = document.createDocumentFragment();
  for (const account of state) {
    let li = existing.get(account.id);
    if (!li) {
      li = createAccountCard(account);
    } else {
      // Update meta if the user renamed it (future feature) — for now stable
      existing.delete(account.id);
    }
    frag.appendChild(li);
  }
  // Anything left in `existing` was removed
  for (const [id, li] of existing) {
    li.remove();
    disposeEngine(id);
  }
  accountsEl.replaceChildren(frag);

  updateAllCodes();
}

function createAccountCard(account) {
  const li = document.createElement('li');
  li.className = 'account-card';
  li.dataset.id = account.id;

  const meta = document.createElement('div');
  meta.className = 'account-card__meta';

  const issuer = document.createElement('div');
  issuer.className = 'account-card__issuer';
  issuer.textContent = account.issuer || '—';

  const acct = document.createElement('div');
  acct.className = 'account-card__account';
  acct.textContent = account.account || '';

  meta.appendChild(issuer);
  meta.appendChild(acct);

  const code = document.createElement('button');
  code.type = 'button';
  code.className = 'account-card__code';
  code.dataset.role = 'code';
  code.title = 'Copy code';
  code.textContent = '······';
  code.addEventListener('click', () => copyCode(account.id));

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
  remove.setAttribute('aria-label', `Remove ${account.issuer || 'account'}`);
  remove.textContent = '×';
  remove.addEventListener('click', () => removeAccount(account.id));

  li.appendChild(meta);
  li.appendChild(code);
  li.appendChild(countdown);
  li.appendChild(remove);
  return li;
}

// ───────────────────── live update loop ──────────────────────────────────

let lastWindowIdx = null;

function updateAllCodes() {
  const nowSec = Math.floor(Date.now() / 1000);
  const winIdx = Math.floor(nowSec / STEP_SECONDS);
  const remaining = STEP_SECONDS - (nowSec % STEP_SECONDS);
  const windowChanged = lastWindowIdx !== null && winIdx !== lastWindowIdx;
  lastWindowIdx = winIdx;

  for (const li of accountsEl.children) {
    const id = li.dataset.id;
    const account = state.find((a) => a.id === id);
    if (!account) continue;

    let codeStr;
    try {
      const engine = ensureEngine(account);
      codeStr = engine.otp_at(BigInt(nowSec));
    } catch (e) {
      console.error('otp_at failed', e);
      codeStr = '------';
    }

    const codeEl = li.querySelector('[data-role="code"]');
    const labelEl = li.querySelector('[data-role="countdown"]');
    const ringFill = li.querySelector('.countdown-ring__fill');

    // Format "123 456" with a thin gap (en-space) for readability
    const formatted = codeStr.length === 6
      ? `${codeStr.slice(0, 3)} ${codeStr.slice(3)}`
      : codeStr;

    if (codeEl.textContent !== formatted) {
      codeEl.textContent = formatted;
      if (windowChanged) {
        // re-trigger the flip animation
        codeEl.classList.remove('fresh');
        // force reflow so the animation restarts
        void codeEl.offsetWidth;
        codeEl.classList.add('fresh');
        setTimeout(() => codeEl.classList.remove('fresh'), 520);
      }
    }

    labelEl.textContent = remaining;

    // Stroke offset: filled portion shrinks as time runs out.
    // dashoffset = circumference * (1 - remaining/STEP_SECONDS)
    const offset = RING_CIRC * (1 - remaining / STEP_SECONDS);
    ringFill.style.strokeDashoffset = offset.toFixed(3);

    // Warning state at < 5s
    if (remaining < 5) {
      li.classList.add('warning');
      codeEl.classList.add('warning');
    } else {
      li.classList.remove('warning');
      codeEl.classList.remove('warning');
    }
  }
}

// ───────────────────── actions ───────────────────────────────────────────

async function copyCode(id) {
  const li = accountsEl.querySelector(`[data-id="${id}"]`);
  if (!li) return;
  const codeEl = li.querySelector('[data-role="code"]');
  const raw = (codeEl.textContent || '').replace(/\s+/g, '');
  try {
    await navigator.clipboard.writeText(raw);
  } catch (e) {
    // Fall back to a textarea-based copy
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

function removeAccount(id) {
  const idx = state.findIndex((a) => a.id === id);
  if (idx === -1) return;
  state.splice(idx, 1);
  saveAccounts(state);
  disposeEngine(id);
  render();
}

function showError(msg) {
  errorEl.textContent = msg;
  errorEl.classList.add('visible');
}
function clearError() {
  errorEl.textContent = '';
  errorEl.classList.remove('visible');
}

function addFromForm() {
  clearError();
  const uri = uriInput.value.trim();
  let issuer, account, secret;
  if (uri) {
    try {
      const parsed = parse_otpauth_uri(uri);
      issuer = parsed.issuer;
      account = parsed.account;
      secret = parsed.secret_base32;
    } catch (e) {
      showError(String(e.message || e));
      return;
    }
  } else {
    issuer = issuerInput.value.trim();
    account = accountInput.value.trim();
    secret = secretInput.value.trim().replace(/\s+/g, '');
    if (!secret) {
      showError('Secret required.');
      return;
    }
  }

  // Validate by trying to construct a TotpAccount — surface base32 errors here
  let totp;
  try {
    totp = new TotpAccount(secret);
  } catch (e) {
    showError(String(e.message || e));
    return;
  }
  totp.free?.(); // we'll re-create via ensureEngine on render

  const id = newId();
  state.push({ id, issuer: issuer || 'Untitled', account, secret });
  saveAccounts(state);

  // Clear form
  uriInput.value = '';
  issuerInput.value = '';
  accountInput.value = '';
  secretInput.value = '';
  uriInput.focus();

  render();
}

addBtn.addEventListener('click', addFromForm);

// Submit on Enter for any of the inputs
for (const el of [uriInput, issuerInput, accountInput, secretInput]) {
  el.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addFromForm();
    }
  });
}

// ───────────────────── boot ──────────────────────────────────────────────

(async function boot() {
  try {
    await init();
  } catch (e) {
    console.error('Failed to load roka-wasm', e);
    showError('Failed to load WASM module: ' + String(e));
    return;
  }
  render();
  // First tick immediate, then align to second boundary
  updateAllCodes();
  const msToNextSecond = 1000 - (Date.now() % 1000);
  setTimeout(() => {
    updateAllCodes();
    setInterval(updateAllCodes, 1000);
  }, msToNextSecond);

  // Register the service worker (offline / installability)
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker
      .register('./service-worker.js')
      .catch((e) => console.warn('SW registration failed', e));
  }
})();
