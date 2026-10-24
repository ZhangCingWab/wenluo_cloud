/* 文汇 Service Worker：页面网络优先[NAV-NETWORK-FIRST-2026-10-24] + 静态资源缓存优先(后台更新) + 公开API SWR */
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
  // [NAV-NETWORK-FIRST-2026-10-24] HTML/导航请求强制网络优先：绕过 HTTP 缓存拿最新页面，
  // 成功后 clone 存入缓存并返回最新版；仅断网时回退缓存 HTML
  const isHtml = e.request.mode === 'navigate' || (e.request.headers.get('accept') || '').includes('text/html');
  if (isHtml) {
    e.respondWith(
      fetch(e.request, { cache: 'no-cache' }).then((res) => {
        if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(e.request, copy)); }
        return res;
      }).catch(() => caches.match(e.request, { ignoreSearch: true }).then((hit) => hit || (e.request.mode === 'navigate' ? caches.match('/') : undefined)))
    );
    return;
  }
  const isStatic = url.pathname.startsWith('/css/') || url.pathname.startsWith('/js/') || url.pathname.startsWith('/img/');
  if (isStatic) {
    e.respondWith(
      // 精确匹配 ?v= 版本号，避免 install 时代预缓存的无版本旧文件遮蔽新版（关站重开显示旧版根因）
      caches.match(e.request).then((hit) => {
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
