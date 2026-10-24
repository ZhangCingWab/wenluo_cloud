/* 文汇 Service Worker：静态资源缓存优先(后台更新) + 公开API SWR + 页面网络优先 */
const CACHE = 'wenhui-v2';
const API_CACHE = 'wenhui-api-v1';
const SHELL = ['/css/style.css', '/js/app.js', '/img/logo.svg', '/manifest.json'];
const PUBLIC_API = ['/api/home', '/api/announcements', '/api/discuss/help', '/api/contests'];
const isPublicApiGet = (req, url) => req.method === 'GET' && !req.headers.get('authorization') && PUBLIC_API.some((p) => p === '/api/discuss/help' ? url.pathname.startsWith(p) : url.pathname === p);

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).catch(() => {}));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE && k !== API_CACHE).map((k) => caches.delete(k)))));
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin) return;
  if (isPublicApiGet(e.request, url)) {
    e.respondWith(
      caches.open(API_CACHE).then((c) => c.match(e.request).then((hit) => {
        const net = fetch(e.request).then((res) => {
          if (res.ok) { const copy = res.clone(); c.put(e.request, copy); }
          return res;
        }).catch(() => hit || Response.error());
        return hit || net;
      }))
    );
    return;
  }
  if (url.pathname.startsWith('/api/')) return;
  if (e.request.method !== 'GET') return;
  const isStatic = url.pathname.startsWith('/css/') || url.pathname.startsWith('/js/') || url.pathname.startsWith('/img/');
  if (isStatic) {
    e.respondWith(
      caches.match(e.request, { ignoreSearch: true }).then((hit) => {
        const net = fetch(e.request).then((res) => {
          if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(e.request, copy)); }
          return res;
        }).catch(() => hit);
        return hit || net;
      })
    );
    return;
  }
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request, { ignoreSearch: true }).then((hit) => hit || (e.request.mode === 'navigate' ? caches.match('/') : undefined)))
  );
});
