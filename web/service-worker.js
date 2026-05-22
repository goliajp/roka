// Roka service worker — minimal offline shell for the PWA.
//
// Strategy:
//   • Precache the app shell (HTML, JS, CSS, WASM, icon, manifest) on install
//   • Network-first for the HTML doc (so updates land fast)
//   • Cache-first for static assets (JS / CSS / WASM / icons)
//
// All data lives in localStorage on the client, so there's no API to cache.

const VERSION = 'roka-shell-v1';
const SHELL = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './manifest.json',
  './icon.svg',
  './pkg/roka_wasm.js',
  './pkg/roka_wasm_bg.wasm',
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(VERSION).then((cache) => cache.addAll(SHELL))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  const isDocument = req.mode === 'navigate' || req.destination === 'document';
  if (isDocument) {
    // network-first for navigation
    e.respondWith(
      fetch(req)
        .then((resp) => {
          const copy = resp.clone();
          caches.open(VERSION).then((c) => c.put(req, copy));
          return resp;
        })
        .catch(() => caches.match(req).then((m) => m || caches.match('./index.html')))
    );
    return;
  }

  // cache-first for static assets
  e.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;
      return fetch(req).then((resp) => {
        if (resp.ok && resp.type === 'basic') {
          const copy = resp.clone();
          caches.open(VERSION).then((c) => c.put(req, copy));
        }
        return resp;
      });
    })
  );
});
