/* ============ 文汇 · 前端 SPA ============ */
// 深色模式（初始化 + toggle）
(function initTheme() {
  const saved = localStorage.getItem('theme');
  if (saved === 'dark' || (!saved && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    document.documentElement.classList.add('dark');
  }
  window.applyTheme = (isDark) => {
    document.documentElement.classList.toggle('dark', isDark);
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
  };
})();
// 主题色（data-accent 换肤）
(function initAccent() {
  const a = localStorage.getItem('accent');
  if (a && a !== 'blue') document.documentElement.dataset.accent = a;
})();
// 统一 routeCleanup（清理进度条 scroll 监听等）
window.addEventListener('hashchange', () => {
  setTimeout(() => document.dispatchEvent(new Event('routeCleanup')), 0);
});
const $app = document.getElementById('app');
const $sidebar = document.getElementById('sidebar');
const state = { me: null, token: localStorage.getItem('token') || null };

/* 静态数据 localStorage 缓存（减少后端请求） */
const CACHE_TTL = 5 * 60 * 1000; // 5 分钟
async function apiCached(path) {
  const key = 'cache:' + path;
  const raw = localStorage.getItem(key);
  if (raw) {
    try {
      const { ts, data } = JSON.parse(raw);
      if (Date.now() - ts < CACHE_TTL) return data;
    } catch {}
  }
  const data = await api(path);
  try { localStorage.setItem(key, JSON.stringify({ ts: Date.now(), data })); } catch {}
  return data;
}
/* 让缓存失效（写操作后调） */
function invalidateCache(path) {
  if (path) { localStorage.removeItem('cache:' + path); return; }
  Object.keys(localStorage).filter(k => k.startsWith('cache:')).forEach(k => localStorage.removeItem(k));
}

/* ---------- 类别常量 ---------- */
const ART_CATS = ['散文', '小说', '科幻', '诗歌', '记叙文', '议论文', '随笔', '其他'];
const POST_CATS = ['题目讲解', '方法分享', '经验交流', '灌水闲聊', '其他'];

/* ---------- 基础工具 ---------- */
async function api(path, { method = 'GET', body, form } = {}) {
  const opts = { method, headers: {} };
  if (state.token) {
    opts.headers['Authorization'] = `Bearer ${state.token}`;
  }
  if (form) opts.body = form;
  else if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || '请求失败 (' + res.status + ')');
    err.status = res.status;
    throw err;
  }
  return data;
}

function toast(msg, type = 'ok') {
  const d = document.createElement('div');
  d.className = 'toast ' + type;
  d.textContent = msg;
  document.getElementById('toast-wrap').appendChild(d);
  setTimeout(() => d.remove(), 2600);
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* 轻量 Markdown 渲染（优先 marked + DOMPurify，退化到内置） */
function hardSpaces(src) {
  let fence = false;
  return String(src).replace(/\r\n?/g, '\n').split('\n').map(ln => {
    if (/^\s{0,3}(```|~~~)/.test(ln)) fence = !fence;
    if (fence) return ln;
    if (/^\s{0,3}(#{1,6}\s|>|[-*+]\s|\d+[.)]\s|\||[-*_=]{3,}\s*$)/.test(ln)) return ln;
    return ln.replace(/^[ \t]+/, m => m.replace(/\t/g, '    ').replace(/ /g, '\u00A0'))
      .replace(/[ \t]{2,}/g, m => m.replace(/\t/g, '    ').replace(/ /g, '\u00A0'));
  }).join('\n');
}
function md(src) {
  if (!src) return '';
  try {
    const MK = window.marked && (window.marked.parse ? window.marked : window.marked.marked);
    if (MK && typeof MK.parse === 'function' && window.DOMPurify) {
      return DOMPurify.sanitize(MK.parse(hardSpaces(String(src)), { breaks: true, gfm: true }));
    }
  } catch (e) {}
  return mdLegacy(hardSpaces(src));
}
if (window.DOMPurify) DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'A') { node.setAttribute('target', '_blank'); node.setAttribute('rel', 'noopener'); }
  if (node.tagName === 'IMG') node.setAttribute('loading', 'lazy');
});
function mdLegacy(src) {
  if (!src) return '';
  let s = esc(src);
  const blocks = [];
  s = s.replace(/```([\s\S]*?)```/g, (_, code) => {
    blocks.push('<pre><code>' + code.replace(/^\n|\n$/g, '') + '</code></pre>');
    return '\u0000B' + (blocks.length - 1) + '\u0000';
  });
  s = s.replace(/^#### (.+)$/gm, '<h4>$1</h4>')
       .replace(/^### (.+)$/gm, '<h3>$1</h3>')
       .replace(/^## (.+)$/gm, '<h2>$1</h2>')
       .replace(/^# (.+)$/gm, '<h1>$1</h1>')
       .replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>')
       .replace(/^\*\s+(.+)$/gm, '<li>$1</li>')
       .replace(/^\d+\.\s+(.+)$/gm, '<li>$1</li>')
       .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
       .replace(/\*([^*\n]+)\*/g, '<i>$1</i>')
       .replace(/`([^`\n]+)`/g, '<code>$1</code>')
       .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')
       .replace(/\[([^\]]+)\]\((\/[^\s)]+)\)/g, '<a href="$2">$1</a>');
  // 把连续 <li> 用 <ul> 包起来
  s = s.replace(/((?:<li>.*<\/li>\n?)+)/g, '<ul>$1</ul>');
  s = s.split(/\n{2,}/).map(p => {
    const t = p.trim();
    if (/^<(h1|h2|h3|h4|blockquote|pre|ul)/.test(t)) return t;
    return '<p>' + t.replace(/\n/g, '<br>') + '</p>';
  }).join('');
  s = s.replace(/\u0000B(\d+)\u0000/g, (_, i) => blocks[i]);
  return s;
}

/* 正文分段分页渲染：按空行切段逐段 md()，按累计字数切页，每页约 1200 字 */
const PROSE_PAGE_CHARS = 1200;
const splitPages = (lens) => {
  const pages = [];
  let st = 0, sum = 0;
  for (let i = 0; i < lens.length; i++) {
    if (i > st && sum + lens[i] > PROSE_PAGE_CHARS) { pages.push([st, i]); st = i; sum = 0; }
    sum += lens[i];
    if (sum >= PROSE_PAGE_CHARS) { pages.push([st, i + 1]); st = i + 1; sum = 0; }
  }
  if (st < lens.length) pages.push([st, lens.length]);
  return pages;
};
const pgFold = (pg, total) => {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const set = new Set([1, total, pg - 1, pg, pg + 1]);
  if (pg <= 4) [2, 3, 4, 5].forEach(i => set.add(i));
  if (pg >= total - 3) [total - 4, total - 3, total - 2, total - 1].forEach(i => set.add(i));
  const out = [];
  let prev = 0;
  for (const p of [...set].filter(p => p >= 1 && p <= total).sort((a, b) => a - b)) {
    if (p - prev > 1) out.push(0);
    out.push(p);
    prev = p;
  }
  return out;
};
const pgBar = (pg, total, go) => {
  const pager = document.createElement('div');
  pager.className = 'pager';
  pager.innerHTML = `<button class="pg" data-p="1" ${pg <= 1 ? 'disabled' : ''}>«</button><button class="pg" data-p="${pg - 1}" ${pg <= 1 ? 'disabled' : ''}>‹</button>`
    + pgFold(pg, total).map(p => p ? `<button class="pg ${p === pg ? 'cur' : ''}" data-p="${p}">${p}</button>` : '<span class="dots">…</span>').join('')
    + `<button class="pg" data-p="${pg + 1}" ${pg >= total ? 'disabled' : ''}>›</button><button class="pg" data-p="${total}" ${pg >= total ? 'disabled' : ''}>»</button><span class="pg-info">${pg} / ${total} 页</span>`;
  pager.querySelectorAll('button.pg').forEach(b => b.onclick = () => {
    const p = +b.dataset.p;
    if (!(p >= 1 && p <= total) || p === pg) return;
    go(p);
  });
  return pager;
};
function paginateBody(box, raw) {
  const parts = [];
  for (let s of String(raw || '').split(/\n\s*\n/)) {
    s = s.trim();
    if (!s) continue;
    const prev = parts[parts.length - 1];
    if (prev && (prev.match(/```/g) || []).length % 2) parts[parts.length - 1] = prev + '\n\n' + s;
    else parts.push(s);
  }
  const paras = parts.map(md);
  const pages = splitPages(paras.map(p => p.length));
  const total = Math.max(1, pages.length);
  const render = (pg) => {
    const [a, b] = pages[pg - 1] || [0, paras.length];
    box.innerHTML = paras.slice(a, b).join('');
    if (total > 1) box.appendChild(pgBar(pg, total, p => { render(p); box.closest('.card')?.scrollIntoView({ behavior: 'smooth' }); }));
  };
  render(1);
}
function paginateHtml(box, html) {
  const tmp = document.createElement('div');
  tmp.innerHTML = String(html || '');
  const styles = Array.from(tmp.children).filter(n => n.tagName === 'STYLE');
  const nodes = Array.from(tmp.children).filter(n => n.tagName !== 'STYLE' && n.tagName !== 'SCRIPT');
  const pages = splitPages(nodes.map(n => (n.textContent || '').length));
  const total = Math.max(1, pages.length);
  const render = (pg) => {
    box.innerHTML = '';
    styles.forEach(s => box.appendChild(s));
    const [a, b] = pages[pg - 1] || [0, nodes.length];
    nodes.slice(a, b).forEach(n => box.appendChild(n));
    if (total > 1) box.appendChild(pgBar(pg, total, p => { render(p); box.scrollIntoView({ behavior: 'smooth' }); }));
  };
  render(1);
}

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
function fmtSize(n) {
  if (n > 1048576) return (n / 1048576).toFixed(1) + ' MB';
  if (n > 1024) return (n / 1024).toFixed(1) + ' KB';
  return n + ' B';
}
function fmtRange(a, b) { return fmtTime(a).slice(0, 16) + ' ~ ' + fmtTime(b).slice(0, 16); }
function excerpt(s, n = 90) {
  const t = String(s || '').replace(/[#*`>\n]/g, ' ').replace(/\s+/g, ' ').trim();
  return t.length > n ? t.slice(0, n) + '…' : t;
}

/* ---------- AI 助手面板 ---------- */
let _aiPanel = null;
function openAiPanel(defaultTask = 'outline', defaultInput = '') {
  closeAiPanel();
  _aiPanel = document.createElement('div');
  _aiPanel.className = 'ai-panel open';
  _aiPanel.innerHTML = `
  <div class="ai-head">
    <h3>${ic('robot')} AI 写作助手</h3>
    <span class="ai-close" id="aiClose">${ic('x')}</span>
  </div>
  <div class="ai-body">
    <div class="ai-task-bar">
      <button class="ai-task-btn active" data-t="outline">${ic('clipboard')} 大纲</button>
      <button class="ai-task-btn" data-t="rewrite">${ic('palette')} 润色</button>
      <button class="ai-task-btn" data-t="continue">${ic('book')} 续写</button>
      <button class="ai-task-btn" data-t="review">${ic('edit')} 批改</button>
    </div>
    <div class="form-item"><label>主题 / 你的问题</label><textarea id="aiInput" class="ai-input" placeholder="${defaultTask === 'rewrite' || defaultTask === 'continue' || defaultTask === 'review' ? '把你的文字贴在这里…' : '写这篇文章是关于什么的？'}">${esc(defaultInput)}</textarea></div>
    <div class="form-item"><label>风格 / 要求（可选）</label><input id="aiStyle" placeholder="例如：议论文、轻松幽默、简洁有力"></div>
    <button class="ai-send" id="aiSend">${ic('send')} 让 AI 帮我</button>
    <div id="aiResult"></div>
  </div>`;
  document.body.appendChild(_aiPanel);
  _aiPanel.querySelector('#aiClose').onclick = closeAiPanel;
  const taskBtns = _aiPanel.querySelectorAll('.ai-task-btn');
  const setTask = (t) => taskBtns.forEach(b => b.classList.toggle('active', b.dataset.t === t));
  taskBtns.forEach(b => b.onclick = () => setTask(b.dataset.t));
  _aiPanel.querySelector('#aiSend').onclick = async () => {
    if (!state.me) { toast('请先登录', 'err'); return; }
    const activeBtn = _aiPanel.querySelector('.ai-task-btn.active');
    const task = activeBtn ? activeBtn.dataset.t : 'outline';
    const input = _aiPanel.querySelector('#aiInput').value;
    const style = _aiPanel.querySelector('#aiStyle').value;
    if (!input) { toast('请写点什么', 'err'); return; }
    const sendBtn = _aiPanel.querySelector('#aiSend');
    const result = _aiPanel.querySelector('#aiResult');
    sendBtn.disabled = true; sendBtn.textContent = '思考中';
    result.innerHTML = '<div class="ai-loader">AI 正在帮你想办法</div>';
    try {
      const d = await api('/api/ai/assist', { method: 'POST', body: { task, topic: input, content: input, style, extra: '' } });
      result.innerHTML = `<div class="ai-result">${d.result.replace(/</g, '&lt;').replace(/\n/g, '<br>').replace(/&gt;/g, '>')}</div>
        <div style="margin-top:8px;display:flex;gap:8px">
          <button class="btn ghost sm" id="aiCopy">${ic('clipboard')} 复制</button>
          <button class="btn ghost sm" id="aiAppend">${ic('plus')} 加到编辑器</button>
          <span class="hint" style="flex:1;text-align:right">${d.source === 'ai' ? 'AI 生成' : '本地模板'}</span>
        </div>`;
      document.getElementById('aiCopy').onclick = async () => {
        await navigator.clipboard.writeText(d.result).catch(() => {});
        toast('已复制到剪贴板');
      };
      document.getElementById('aiAppend').onclick = () => {
        const ta = document.querySelector('textarea.tall, textarea#prContent');
        if (ta) { ta.value = (ta.value ? ta.value + '\n\n' : '') + d.result; toast('已追加到编辑器'); }
        else toast('当前没有找到编辑器', 'err');
      };
    } catch (e) { result.innerHTML = '<div class="ai-result" style="color:var(--red)">出错了：' + esc(e.message) + '</div>'; }
    sendBtn.disabled = false; sendBtn.innerHTML = ic('send')+' 让 AI 帮我';
  };
}
function closeAiPanel() { if (_aiPanel) { _aiPanel.remove(); _aiPanel = null; } }
function showAiFab() {
  if (document.getElementById('aiFab')) return;
  const fab = document.createElement('button');
  fab.className = 'ai-fab'; fab.id = 'aiFab'; fab.innerHTML = ic('robot'); fab.title = 'AI 写作助手';
  fab.onclick = () => openAiPanel();
  document.body.appendChild(fab);
}
function hideAiFab() { const f = document.getElementById('aiFab'); if (f) f.remove(); closeAiPanel(); }
const avatarColor = (id) => {
  const cs = ['#3498db', '#9b59b6', '#1abc9c', '#e67e22', '#e74c3c', '#2c82c9', '#16a085'];
  let h = 0; for (const c of String(id || 'x')) h = (h * 31 + c.charCodeAt(0)) % 997;
  return cs[h % cs.length];
};
const avatarHtml = (u, cls = '') =>
  u && u.avatarUrl
    ? `<img class="avatar avatar-img ${cls}" src="${esc(u.avatarUrl)}" alt="">`
    : `<div class="avatar ${cls}" style="background:${avatarColor(u && u.id)}">${esc((u && u.nickname || '?')[0].toUpperCase())}</div>`;
const statusBadge = (s) => ({ pending: '审核中', approved: '已通过', rejected: '未通过' }[s] || s);
const contestBadge = (s) => ({ upcoming: '未开始', ongoing: '进行中', ended: '已结束' }[s] || s);
const needLogin = () => {
  if (!state.me) { toast('请先登录', 'err'); location.hash = '#/login'; return true; }
  return false;
};

/* ---------- 线性描边图标（洛谷风 SVG） ---------- */
const ICONS = {
  home: '<path d="M3 10.5 12 3l9 7.5"/><path d="M5 9.7V21h14V9.7"/><path d="M9.5 21v-6.5h5V21"/>',
  daily: '<path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1"/><path d="m9 13.5 2 2 4-4.5"/>',
  forum: '<path d="M21 11.5a8.38 8.38 0 0 1-8.5 8.3 8.5 8.5 0 0 1-3.9-.9L3 21l2.1-4.2a8.38 8.38 0 0 1-1.1-4C4 8.5 7.6 5 12 5s9 3.2 9 6.5z"/>',
  discuss: '<circle cx="12" cy="12" r="9"/><path d="M9.2 9.2a2.8 2.8 0 0 1 5.5.7c0 1.9-2.7 2.3-2.7 3.7"/><path d="M12 17h.01"/>',
  articles: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
  problems: '<path d="M22 9 12 4 2 9l10 5 10-5z"/><path d="M6 11.5V16c0 1.6 2.7 3 6 3s6-1.4 6-3v-4.5"/><path d="M22 9v5"/>',
  templates: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 13h6M9 17h4"/>',
  rank: '<path d="M18 20V10M12 20V4M6 20v-6"/>',
  contests: '<path d="M6 3h12v6a6 6 0 0 1-12 0z"/><path d="M6 5H3.5A1.5 1.5 0 0 0 2 6.5C2 8.5 3.5 10 6 10"/><path d="M18 5h2.5A1.5 1.5 0 0 1 22 6.5C22 8.5 20.5 10 18 10"/><path d="M12 15v3"/><path d="M8 21h8"/>',
  submit: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/>',
  downloads: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
  mine: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 13h6M9 17h6"/>',
  messages: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
  checkA: '<circle cx="12" cy="12" r="9"/><path d="m8.5 12 2.5 2.5 5-5"/>',
  checkP: '<path d="M11 6h9M11 12h9M11 18h9"/><path d="m4 6 1.2 1.2L7.5 5"/><path d="m4 12 1.2 1.2L7.5 11"/><path d="m4 18 1.2 1.2L7.5 17"/>',
  folder: '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 8.8-8.8"/><path d="m16 7 3 3"/><path d="m19 4 2 2"/>',
  flag: '<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><path d="M4 22v-7"/>',
  win: '<rect x="4" y="4" width="7" height="7" rx="1.2"/><rect x="13" y="4" width="7" height="7" rx="1.2"/><rect x="4" y="13" width="7" height="7" rx="1.2"/><rect x="13" y="13" width="7" height="7" rx="1.2"/>',
  android: '<path d="M5 11a7 7 0 0 1 14 0v.5H5z"/><path d="m7 4.8 1.2 1.6M17 4.8l-1.2 1.6"/><path d="M9.5 8.6h.01M14.5 8.6h.01"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a15.3 15.3 0 0 1 4 9 15.3 15.3 0 0 1-4 9 15.3 15.3 0 0 1-4-9 15.3 15.3 0 0 1 4-9z"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  edit: '<path d="M17 3a2.83 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5z"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
  heart: '<path d="M19 14c1.49-1.46 3-3.21 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.76 0-3 .5-4.5 2-1.5-1.5-2.74-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4.05 3 5.5l7 7Z"/>',
  star: '<path d="m12 2 3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01z"/>',
  bell: '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>',
  sun: '<circle cx="12" cy="12" r="4.5"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.6 4.6l1.8 1.8M17.6 17.6l1.8 1.8M4.6 19.4l1.8-1.8M17.6 6.4l1.8-1.8"/>',
  moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
  sparkle: '<path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z"/><path d="M20 3v4M22 5h-4"/>',
  bolt: '<path d="M13 2 4 14h6l-1 8 9-12h-6z"/>',
  flame: '<path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.07-2.14-.22-4.05 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.15.43-2.29 1-3a2.5 2.5 0 0 0 2.5 2.5z"/>',
  clipboard: '<rect x="8" y="2" width="8" height="4" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="M9 12h6M9 16h4"/>',
  book: '<path d="M2 4h6a4 4 0 0 1 4 4v12a3 3 0 0 0-3-3H2z"/><path d="M22 4h-6a4 4 0 0 0-4 4v12a3 3 0 0 1 3-3h7z"/>',
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
  check: '<path d="m4.5 12.5 5 5 10-11"/>',
  x: '<path d="m6 6 12 12M18 6 6 18"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  send: '<path d="m22 2-7 20-4-9-9-4z"/><path d="M22 2 11 13"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  megaphone: '<path d="m3 11 18-5v12L3 14v-3z"/><path d="M11.6 16.8a3 3 0 1 1-5.8-1.6"/>',
  dice: '<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M8 8h.01M16 8h.01M12 12h.01M8 16h.01M16 16h.01"/>',
  shield: '<path d="M12 22s8-3.5 8-10V5l-8-3-8 3v7c0 6.5 8 10 8 10z"/>',
  image: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/>',
  mail: '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 6L2 7"/>',
  flask: '<path d="M10 2v6L4.5 18a2 2 0 0 0 1.8 3h11.4a2 2 0 0 0 1.8-3L14 8V2"/><path d="M8.5 2h7"/><path d="M7 15h10"/>',
  palette: '<circle cx="13.5" cy="6.5" r=".8"/><circle cx="17.5" cy="10.5" r=".8"/><circle cx="8.5" cy="7.5" r=".8"/><circle cx="6.5" cy="12.5" r=".8"/><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.9 0 1.6-.7 1.6-1.7 0-.4-.2-.8-.4-1.1-.3-.3-.4-.7-.4-1.1a1.6 1.6 0 0 1 1.6-1.6h2c3 0 5.6-2.5 5.6-5.6C22 6 17.5 2 12 2z"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.2 9.2a2.8 2.8 0 0 1 5.5.7c0 1.9-2.7 2.3-2.7 3.7"/><path d="M12 17h.01"/>',
  reply: '<path d="m9 15-5-5 5-5"/><path d="M20 4v7a4 4 0 0 1-4 4H4"/>',
  robot: '<rect x="4" y="8" width="16" height="12" rx="2"/><path d="M12 8V4M8 4h8"/><path d="M9 13h.01M15 13h.01"/><path d="M9.5 17h5"/>',
  warn: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4M12 17h.01"/>'
};
const ic = (n) => '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + ICONS[n] + '</svg>';

function renderSidebar() {
  const me = state.me;
  const cur = location.hash.replace(/^#/, '') || '/home';
  const link = (h, icon, label, extra) =>
    `<a href="#${h}" class="${cur === h || cur.startsWith(h + '/') ? 'active' : ''}"><span class="icon">${ic(icon)}</span><span class="txt">${label}</span>${extra || ''}</a>`;
  let html = `
  <div class="logo">
    <div class="logo-mark"><img src="/img/logo.svg" alt="文汇"></div>
    <div class="logo-text"><span class="logo-name">文汇</span><span class="logo-sub">WENHUI</span></div>
  </div>
  <nav class="nav">
    ${link('/home', 'home', '主页')}
    ${link('/daily', 'daily', '每日打卡')}
    ${link('/forum', 'forum', '论坛广场')}
    ${link('/discuss', 'discuss', '讨论区')}
    ${link('/articles', 'articles', '文章库')}
    ${link('/problems', 'problems', '题库')}
    ${link('/templates', 'templates', '写作模板')}
    ${link('/rank', 'rank', '排行榜')}
    ${link('/contests', 'contests', '比赛广场')}
    ${link('/submit', 'submit', '文件投稿')}
    ${link('/downloads', 'downloads', '下载站')}
    ${link('/mine', 'mine', '我的文章')}
    ${me ? link('/messages', 'messages', '私信', '<span class="msg-badge" id="msgBadge" style="display:none">0</span>') : ''}
    ${me && me.role === 'admin' ? `
      <div class="nav-label">后台管理</div>
      ${link('/admin/articles', 'checkA', '审核文章')}
      ${link('/admin/posts', 'checkP', '审核帖子')}
      ${link('/admin/problems', 'problems', '审核题目')}
      ${link('/admin/files', 'folder', '审核投稿')}
      ${link('/admin/invite', 'key', '邀请码管理')}
      ${link('/admin/contest', 'flag', '创建比赛')}` : ''}
  </nav>`;
  $sidebar.innerHTML = html;
  renderUserChip();
}
/* ---------- 右上角用户区（头像/名字/登录按钮，全端常驻） ---------- */
function renderUserChip() {
  let chip = document.getElementById('userChip');
  if (!chip) { chip = document.createElement('div'); chip.id = 'userChip'; document.body.appendChild(chip); }
  const me = state.me;
  if (me) {
    chip.className = 'userchip-in';
    chip.innerHTML = `${avatarHtml(me)}<span class="chip-name">${esc(me.nickname)}</span><span class="chip-dot" id="notifDot" style="display:none" title="有新通知"></span>`;
    chip.onclick = (e) => { e.stopPropagation(); toggleUserMenu(); };
  } else {
    chip.className = 'userchip-out';
    chip.innerHTML = `<a class="chip-login" href="#/login">登录 / 注册</a>`;
    chip.onclick = null;
  }
}
function toggleUserMenu() {
  const chip = document.getElementById('userChip');
  if (document.getElementById('userMenu')) return closeMenu();
  const me = state.me;
  const div = document.createElement('div');
  div.className = 'popover';
  div.id = 'userMenu';
  div.innerHTML = `
    <div class="p-head">${esc(me.nickname)} <span style="font-weight:400;font-size:12px">@${esc(me.username)}</span></div>
    <a href="#/user/${me.id}">${ic('user')} 个人主页</a>
    <a href="#/messages">${ic('messages')} 私信</a>
    <a href="#/notifications">${ic('bell')} 通知中心<span class="msg-badge" id="notifBadge" style="display:none">0</span></a>
    <a href="#/mine">${ic('edit')} 我的文章</a>
    <a href="#/settings">${ic('settings')} 偏好设置</a>
    <div class="divider"></div>
    <div class="p-item" id="themeToggle"><span id="themeIcon">${localStorage.getItem('theme') === 'dark' ? ic('sun') : ic('moon')}</span><span id="themeLabel">切换深色模式</span></div>
    <div class="divider"></div>
    <div class="p-item logout" id="logoutBtn">${ic('logout')} 登出账号</div>`;
  chip.appendChild(div);
  /* 深色开关：直接绑在菜单项上 + stopPropagation。
     之前挂在 document 上，但菜单是头像(有 stopPropagation)的子元素，点击根本到不了 document → 开关失效 */
  div.querySelector('#themeToggle').onclick = (e) => {
    e.stopPropagation();
    const now = !document.documentElement.classList.contains('dark');
    applyTheme(now);
    const icon = div.querySelector('#themeIcon'); if (icon) icon.innerHTML = now ? ic('sun') : ic('moon');
    const label = div.querySelector('#themeLabel'); if (label) label.textContent = now ? '深色模式：已开启' : '深色模式：已关闭';
  };
  div.querySelector('#logoutBtn').onclick = async () => {
    try { await api('/api/logout', { method: 'POST' }); } catch (e) {}
    state.me = null;
    state.token = null;
    localStorage.removeItem('token');
    closeMenu();
    renderSidebar();
    toast('已退出登录');
    location.hash = '#/home';
  };
  setTimeout(() => document.addEventListener('click', closeMenu, { once: true }), 0);
}
function closeMenu() { const m = document.getElementById('userMenu'); if (m) m.remove(); }

/* 未读红点（私信 + 通知），登录期间每 60 秒轮询一次 */
async function refreshUnread() {
  if (!state.me) return;
  try {
    const [md, nd] = await Promise.all([api('/api/messages/unread'), api('/api/notifications/unread-count')]);
    const b = document.getElementById('msgBadge');
    if (b) {
      b.textContent = md.count;
      b.style.display = md.count > 0 ? 'inline-block' : 'none';
    }
    const nb = document.getElementById('notifBadge');
    if (nb) {
      nb.textContent = nd.count > 99 ? '99+' : nd.count;
      nb.style.display = nd.count > 0 ? 'inline-block' : 'none';
    }
    const dot = document.getElementById('notifDot');
    if (dot) dot.style.display = nd.count > 0 ? 'inline-block' : 'none';
  } catch (e) {}
}
setInterval(refreshUnread, 60000);

/* ---------- 路由 ---------- */
const routes = {
  home: viewHome, forum: viewForum, post: viewPostDetail, newpost: viewNewPost,
  discuss: viewDiscuss,
  articles: viewArticles, article: viewArticleDetail, write: viewWrite,
  rank: viewRank, contests: viewContests, contest: viewContestDetail,
  submit: viewSubmit, mine: viewMine, user: viewProfile, settings: viewSettings,
  login: viewLogin, admin: viewAdmin, messages: viewMessages, chat: viewChat,
  problems: viewProblems, problem: viewProblemDetail, work: viewWorkspace,
  templates: viewTemplates, daily: viewDaily, 'contest-create': contestCreate,
  notifications: viewNotifications, announcements: viewAnnouncements, announcement: viewAnnouncement,
  changelog: viewChangelog, downloads: viewDownload
};
async function route() {
  closeMenu();
  const hash = location.hash.replace(/^#\//, '') || 'home';
  const [name, ...rest] = hash.split('/');
  const arg = rest.join('/');
  renderSidebar();
  refreshUnread();
  $app.innerHTML = '<div class="loading-block">加载中…</div>';
  try {
    const fn = routes[name] || viewHome;
    await fn(arg);
  } catch (e) {
    $app.innerHTML = `<div class="card"><div class="empty">${ic('help')} ${esc(e.message)}</div></div>`;
  }
  /* 页面入场动画：内容渲染完后加 page-anim 类，播完自动移除（避免点赞等局部刷新时重播） */
  $app.classList.remove('page-anim');
  void $app.offsetWidth;
  $app.classList.add('page-anim');
  clearTimeout($app._animT);
  $app._animT = setTimeout(() => $app.classList.remove('page-anim'), 800);
  window.scrollTo(0, 0);
}
const go = (h) => { location.hash = h; };
// 全局：比赛邀请码申请
window.applyContestInvite = function () {
  if (needLogin()) return;
  const code = prompt('请输入管理员给你的一次性邀请码：', '');
  if (!code) return;
  localStorage.setItem('contestInviteCode', code.trim().toUpperCase());
  go('#/contest-create');
};

/* ---------- 主页 ---------- */
/* 站点更新说明（每次部署时追加最新一条在最上面）*/
const CHANGELOG = [
  { date: '2026-10-31 03:10', author: 'ZhangCing', items: ['软件 v1.1.6 大更新：新增「文汇社区」，做题、打比赛、讨论区、群聊在软件里直接用，登录状态自动同步', '软件新增设置面板：6 色主题、深浅色界面、编辑器字号行距、预览宽度、自动保存，界面动效全面升级'] },
  { date: '2026-10-30 18:40', author: 'ZhangCing', items: ['全站+软件图标统一为洛谷风线性描边 SVG：页面标题、按钮、标签页、AI 助手、通知中心、管理后台等全部换新，跟随主题色与深色模式', '软件 v1.1.5：工具栏图标与网站侧边栏完全同款'] },
  { date: '2026-10-27 13:40', author: 'ZhangCing', items: ['⌨️ 空格全保留：段首缩进、行内多空格在预览和发布后都原样显示，缩进行不再被 Markdown 规则吞掉', '⬆ 软件 v1.1.4 同步此修复，旧版点「检查更新」即可升级'] },
  { date: '2026-10-25 21:00', author: 'ZhangCing', items: ['📝 Markdown 渲染换专业引擎（marked + DOMPurify）：空格/缩进/表格/任务列表/引用块全支持，全站与软件预览同步升级'] },
  { date: '2026-10-25 20:30', author: 'ZhangCing', items: ['🛠 软件 v1.1.2 修复启动崩溃：全部按钮无反应、编辑器空白、文字不可见已解决，并经端到端实测'] },
  { date: '2026-10-25 19:00', author: 'ZhangCing', items: ['⬆ 软件 v1.1.1 新增应用内「检查更新」：一键检查 → 进度条下载 → 静默安装 → 自动重启', '🛠 修复 v1.1.0 打开后全部按钮无反应的问题'] },
  { date: '2026-10-25 18:00', author: 'ZhangCing', items: ['🖥 软件大版本 v1.1.0：从网站套壳重做为 IDE 式写作编辑器（数据与网站互通）', '📁 全新「文章空间」：选择本地文件夹，多标签打开 .md 文章，行号+语法高亮+实时预览', '🚀 一键发布：登录文汇账号后，当前文档可直接发布为文章或帖子'] },
  { date: '2026-10-25 15:40', author: 'ZhangCing', items: ['💬 讨论区大更新：求助支持类型分类/状态筛选/关键词搜索', '👥 群聊支持自建群：起名+简介+图标，建群者当群主，入群仍需审核', '🧭 讨论区排版优化：搜索栏+筛选药丸条+类型徽标'] },
  { date: '2026-10-25 14:30', author: 'ZhangCing', items: ['🧭 下载站排版重做：居中 Hero + 三平台卡片一行三列 + 安装说明，图标统一线性风格'] },
  { date: '2026-10-25 13:30', author: 'ZhangCing', items: ['🎨 侧边栏图标改为洛谷风线性描边 SVG 图标，跟随主题色与深色模式'] },
  { date: '2026-10-25 12:00', author: 'ZhangCing', items: ['🏠 个人主页全新改版（洛谷风）：横幅头图 + 标签页 + 关键数据栏', '🔥 新增活跃热力图：近半年发文/发帖/打卡/练习按日统计，一眼看到坚持痕迹', '⚡ 新增积分构成卡：文章/帖子/获赞/评论/练习/打卡分别计分，与排行榜同源'] },
  { date: '2026-10-25 01:30', author: 'ZhangCing', items: ['📄 分页改按字数切页：每页约 1200 字，短句段落自动合并，长文档页数大幅减少'] },
  { date: '2026-10-25 00:30', author: 'ZhangCing', items: ['📄 文件投稿转文章也支持分段分页：长文档（Word 转正文）不再一次性渲染，翻页阅读更流畅'] },
  { date: '2026-10-24 23:30', author: 'ZhangCing', items: ['🎨 全站视觉升级：毛玻璃质感、渐变按钮、光斑 Hero、精致阴影层次', '🌈 新增主题色自定义：7 款配色即时切换，与深色模式自由组合'] },
  { date: '2026-10-24 22:00', author: 'ZhangCing', items: ['📖 阅读页排版全面美化：正文居中、行距加大、标题/引用/代码块样式', '📄 长文按段分页：每页 8 段，只渲染当前页内容，长文加载更快'] },
  { date: '2026-10-24 20:00', author: 'ZhangCing', items: ['🖼 支持上传图片头像：设置页选择图片自动裁剪压缩，全站头像位生效，可恢复默认'] },
  { date: '2026-10-24 18:00', author: 'ZhangCing', items: ['🐛 修复关闭浏览器后重开网站显示旧版页面的问题', '🔑 登录有效期延长至一年，常用自动续期，基本告别重新登录'] },
  { date: '2026-10-24 12:00', author: 'ZhangCing', items: ['⚡ 加载提速：首页/公告等公开数据本地秒开+后台静默更新，首页骨架屏'] },
  { date: '2026-10-22 12:00', author: 'ZhangCing', items: ['📧 注册页新增「邮箱注册」：邮箱+验证码+用户名密码一步注册，原内测注册保留'] },
  { date: '2026-10-21 12:00', author: 'ZhangCing', items: ['🔑 邮箱验证码改为找回密码：设置页绑定邮箱后，忘记密码可用邮箱+验证码重置', '🧪 注册页改为「内测注册」：用户名+密码直接注册，无需邮箱'] },
  { date: '2026-10-18 00:30', author: 'ZhangCing', items: ['📧 邮箱验证码改用 QQ 邮箱直发，无需注册第三方服务'] },
  { date: '2026-10-17 21:30', author: 'ZhangCing', items: ['📧 新增邮箱验证码登录：输入邮箱收验证码即可登录，新用户自动注册，原有密码登录不受影响'] },
  { date: '2026-10-17 20:00', author: 'ZhangCing', items: ['💬 群聊改为QQ式左右分栏：左侧群列表右侧聊天窗，手机端上下布局'] },
  { date: '2026-10-17 18:00', author: 'ZhangCing', items: ['🎨 主页改左右分栏排版', '📜 更新日志主页只显3条，新增详情页+分页', '✨ 全站补齐中间帧动画（入场/按压/弹窗/Toast）'] },
  { date: '2026-10-17 16:30', author: 'ZhangCing', items: ['🚀 Windows 安装包启用 Cloudflare 加速线路：下载走本站中转，国内速度大幅提升'] },
  { date: '2026-10-17 15:30', author: 'ZhangCing', items: ['🪟 Windows 安装版正式开放下载：下载站点击即可获取文汇.exe'] },
  { date: '2026-10-17 14:00', author: 'ZhangCing', items: ['⬇️ 新增「下载站」：Windows 安装版 / 安卓 APK / 网页版三种获取方式，侧边栏和主页均可进入'] },
  { date: '2026-10-17 12:00', author: 'ZhangCing', items: ['📢 主页公告改为链接列表（洛谷式）：只显示公告标题，点击进入公告详情页阅读全文'] },
  { date: '2026-10-16 12:00', author: 'ZhangCing', items: ['📦 上线安卓 APK 下载：文汇手机 App 可直接安装，支持全屏运行', '🪟 桌面安装版发布：文汇.exe 支持选目录安装+桌面快捷方式'] },
  { date: '2026-10-12 05:00', author: 'ZhangCing', items: ['📱 网站升级为 PWA 应用：手机浏览器「添加到主屏幕」即可像 App 一样全屏使用（带图标、启动页）', '🔄 新增 Service Worker：样式/脚本/图标本地缓存，弱网时页面壳加载更快'] },
  { date: '2026-10-12 04:00', author: 'ZhangCing', items: ['🧹 全面体检：清理已废弃的 saveDB 全量覆盖代码（历史事故根源，现已无调用）', '🩺 数据库操作失败不再静默：dbFirst/dbAll/dbRun 失败会记录日志，方便排查问题', '⚡ 主页公告请求去重：进主页少发一次请求'] },
  { date: '2026-10-12 03:20', author: 'ZhangCing', items: ['🏠 主页公告改为正常展示栏：hero 下方「📢 公告」栏直接显示公告全文，不再折叠'] },
  { date: '2026-10-12 03:00', author: 'ZhangCing', items: ['🏠 公告移到主页显示：hero 下方公告卡片，点击展开全文（新用户仍会自动弹出必读）', '🔔 通知藏进右上角名字菜单：点名字 →「通知中心」，有新通知时名字旁亮小红点'] },
  { date: '2026-10-12 02:20', author: 'ZhangCing', items: ['🔔 新增「通知中心」：右上角铃铛 + 未读红点，点赞/评论/回复/采纳答案/比赛开始/题目审核/练习提交都会提醒，点击通知直达对应页面', '📢 新增「公告」模块：上线第一篇《文汇新用户必读》，新用户进主页自动弹出，侧边栏可随时查看'] },
  { date: '2026-10-12 01:10', author: 'ZhangCing', items: ['📄 长列表加分页按钮：求助问答、排行榜（每页20）、我的文章/帖子/投稿、后台审核列表（每页10），翻页自动回到列表顶部', '🌙 分页按钮适配深色模式'] },
  { date: '2026-10-12 00:30', author: 'ZhangCing', items: ['👥 群聊升级为多群制：预置「官方公告 / 灌水闲聊 / 写作交流 / 兴趣杂谈」四个群（群主都是站长）', '🔐 加群需群主审核：申请后群主在群聊里点「通过 / 拒绝」，结果站内通知，审核卡片里可一键处理'] },
  { date: '2026-10-11 23:55', author: 'ZhangCing', items: ['🎉 新增「讨论区」模块：🙋 求助问答（发求助/回复/采纳答案/标记已解决，未解决自动置顶）+ 💬 群聊大厅（全员聊天室，5 秒自动刷新新消息）', '📱 讨论区适配手机端与深色模式'] },
  { date: '2026-10-11 16:00', author: 'ZhangCing', items: ['🎨 全站换上正式标志「开卷文汇」：浅蓝圆角方印 + 蓝字「文」+ 摊开书页', '🔖 浏览器标签页 favicon 同步替换为新标志'] },
  { date: '2026-10-11 12:00', author: 'ZhangCing', items: ['🔴 修复深色模式开关失效（菜单在头像内，头像的 stopPropagation 拦截了事件；改为直接绑定，切换后菜单不关闭可立即看到效果）', '✨ 全局流畅动效：页面切换淡入上移、卡片/列表依次上升、弹出菜单弹性缩放、toast 滑入（尊重系统减少动效设置）'] },
  { date: '2026-10-04 20:00', author: 'ZhangCing', items: ['🔄 用户区搬到页面右上角：头像+名字常驻右上角（点击弹出个人主页/私信/深色模式/登出菜单），未登录显示「登录 / 注册」按钮', '🖥️ 侧边栏底部不再放用户信息，纯导航更清爽', '🖥️ 修复导航图标没对齐：emoji 装进固定宽度盒子，文字严格排成一列'] },
  { date: '2026-10-04 19:00', author: 'ZhangCing', items: ['🖥️ 侧边栏收起时登录入口显示「登录」二字（不再是看不懂的孤零零钥匙图标）', '🔴 修复展开后「登录 / 注册」白底白字看不见（去掉旧样式里的 color:#fff !important）'] },
  { date: '2026-10-04 18:00', author: 'ZhangCing', items: ['🖥️ 文汇 Logo 收起时单独一行、严格正中央（展开不跳动）', '🔑 登录入口重做：收起时是和导航一样的图标行，不再是突兀的蓝色大块'] },
  { date: '2026-10-04 17:00', author: 'ZhangCing', items: ['🔑 修复未登录时侧边栏底部变成空蓝块：登录按钮收起时显示 🔑 图标，悬停展开显示完整文字', '🔄 静态资源加版本号 ?v=1004，彻底解决 CSS 缓存导致侧边栏样式不生效的问题'] },
  { date: '2026-10-04 16:00', author: 'ZhangCing', items: ['🖥️ 修复收起时 Logo「文汇」图标被挤出屏幕只剩半截（隐形文字占位导致，改 max-width 折叠）', '🖥️ 根除侧边栏底部横向滚动条'] },
  { date: '2026-10-04 15:00', author: 'ZhangCing', items: ['🖥️ 侧边栏收起时：Logo 图标居中、隐藏滚动条、所有图标精确居中对齐（悬停展开仍不跳动）'] },
  { date: '2026-10-04 14:00', author: 'ZhangCing', items: ['🖥️ 电脑端侧边栏改成洛谷风格：平时只显示图标条，鼠标悬停自动展开（浮层不挤内容）', '🖥️ 展开时文字淡入，图标位置固定不跳动；修复深色模式下侧边栏配色失效的问题'] },
  { date: '2026-10-04 12:00', author: 'ZhangCing', items: ['📱 手机端适配：侧边栏变抽屉菜单（左上角 ☰ 按钮开关），内容区全宽显示', '📱 统计/推荐/排行榜/私信/AI面板/写作工作台全部适配小屏'] },
  { date: '2026-10-03 12:00', author: 'ZhangCing', items: ['🔴 修复文件下载 404：文件内容之前存 KV，KV 清理时全部丢失；现在内容改存 D1（file_blobs 表），跟数据库一起走', '⚠️ 旧投稿内容已无法恢复：请在「文件投稿→我的投稿记录」删除旧文件后重新上传', '🔴 修复文章里「下载文件」链接显示成原始文本（markdown 不支持相对路径链接）', '🔴 严重安全修复：withAuthorSync 4处调用参数顺序颠倒，上传/比赛/练习接口把整个用户表（含密码hash）返回给了前端，已修复+加防御', '✨ 新增删除文件接口（同时清理内容/自动文章/KV备份）'] },
  { date: '2026-10-01 10:00', author: 'ZhangCing', items: ['✨ 投稿文章正文直接显示文档内容：Word(docx) 自动转正文排版、PDF 内嵌预览、txt 直接可读（不用下载也能看）', '🔴 修复点赞报错 a.likes.push is not a function（点赞改直接查 D1）', '🔴 修复文章详情「文章不存在」（详情/评论点赞/评论删除全部改直接 SQL，不再读旧内存）'] },
  { date: '2026-10-01 09:00', author: 'ZhangCing', items: ['✨ 投稿文件审核通过后自动发布到文章库「文件投稿」分类（含大小、投稿说明、下载按钮，署名投稿人）', '通过的文件开放所有人下载；拒绝/撤回时自动移除对应文章', '文章库新增「文件投稿」分类标签'] },
  { date: '2026-10-01 08:00', author: 'ZhangCing', items: ['🔴 根治：files/problems/practices/templates 表是旧 saveDB 自动建的 camelCase 列，所有 snake_case SQL 报 no such column → Word 文档投稿失败、审核列表永远空', '启动时自动检测真实列名，camelCase 旧表自动迁移数据到 snake_case（幂等，旧投稿不丢）', '说明：Word(docx) 一直在白名单里，之前传不上是列名 bug，不是不允许'] },
  { date: '2026-10-01 07:00', author: 'ZhangCing', items: ['🔴 auth/login 改直接 env.DB.prepare 查用户，绕过 dbFirst 吞异常返回 null 导致的 401', '🔴 admin/files+admin/posts+admin/problems 用 toCamel+手动map 转 snake_case→camelCase', '用户必须登出后重新登录'] },
  { date: '2026-10-01 06:00', author: 'ZhangCing', items: ['🔴 admin/files + admin/problems 返回 D1 原始 snake_case 行未转 camelCase → 前端 originalName/createdAt 全 undefined', '修复：admin/files/problems 用 toCamel + 手动 map 列名 + D1 查 author/proposer'] },
  { date: '2026-10-01 05:00', author: 'ZhangCing', items: ['文章创建 INSERT 后立刻 SELECT 验证（防静默丢失）', 'articles/mine 去掉吞异常 catch，错误直接返回给前端', '清理临时 debug/schema 端点'] },
  { date: '2026-10-01 04:00', author: 'ZhangCing', items: ['🔴 修复 Cloudflare 多 isolate 跨实例数据不同步：auth/登录/home/admin-stats 全部改直接 D1 SQL', '🔴 修复 pub 函数 createdAt 一直 undefined（snake_case vs camelCase 列名兼容）', '🔴 我的投稿记录/文件下载修复，admin 审核列表去掉多余内存 merge'] },
  { date: '2026-09-30 05:00', author: 'ZhangCing', items: ['P0 全量 saveDB 替换为直接 SQL（20+ 端点彻底解决跨 isolate 持久化问题）', 'P1 相关推荐（根据分类+标签 2-3 排）、阅读进度条（顶部分数）、深色模式'] },
  { date: '2026-09-30 03:30', author: 'ZhangCing', items: ['网站更名：文洛 → 文汇（logo、标题、欢迎语、杯赛名、Schema 注释全量替换）'] },
  { date: '2026-09-30 03:00', author: 'ZhangCing', items: ['每日打卡改用分屏工作台；修复文件投稿/比赛/我的练习的 withAuthorSync 未定义错误'] },
  { date: '2026-09-30 02:00', author: 'ZhangCing', items: ['分屏工作台编辑区支持 Markdown 预览；新增「上传文件」模块（.txt/.md 点击或拖入导入）'] },
  { date: '2026-09-30 01:30', author: 'ZhangCing', items: ['题目练习/比赛提交改为 Luogu 风格分屏工作台（可拖动调整，支持在线写作和粘贴导入）'] },
  { date: '2026-09-30 00:30', author: 'ZhangCing', items: ['文章库 / 论坛 / 题库新增分页（每页 10 条）'] },
  { date: '2026-09-29 23:30', author: 'ZhangCing', items: ['题库新增 100 道写作题，难度 1-6 全覆盖'] },
  { date: '2026-09-29 22:30', author: 'ZhangCing', items: ['修复主页比赛卡片显示 undefined', '评论系统升级：楼中楼回复、回复/删除按钮', '比赛报名名单显示用户昵称'] },
  { date: '2026-09-29', author: 'ZhangCing', items: ['审核系统全链路直接 SQL 持久化，审核状态不再丢失', '积分统一实时计算，个人主页与排行榜一致', 'Markdown 全站渲染适配', '比赛列表/详情/状态修复'] },
];
/* ---------- 通知中心 ---------- */
const NOTIF_ICON = { like: ic('heart'), comment: ic('forum'), reply: ic('reply'), adopt: ic('checkA'), contest_start: ic('contests'), problem_review: ic('problems'), practice: ic('edit') };
function notifUrl(n) {
  return { article: `#/article/${n.targetId}`, post: `#/post/${n.targetId}`, help: `#/discuss/help/${n.targetId}`, contest: `#/contest/${n.targetId}`, problem: `#/problem/${n.targetId}` }[n.targetType] || '';
}
async function viewNotifications() {
  if (needLogin()) return;
  const d = await api('/api/notifications');
  const notifTotal = Math.max(1, Math.ceil(d.notifications.length / PAGE_SIZE));
  const notifItem = (n) => `
    <div class="item notif-item ${n.read ? '' : 'unread'}" data-nid="${n.id}" data-href="${notifUrl(n)}">
      <div class="notif-ico">${NOTIF_ICON[n.type] || ic('bell')}</div>
      <div style="flex:1;min-width:0">
        <div class="title"><span class="notif-from">${n.from ? esc(n.from.nickname) : ic('megaphone')+' 系统'}</span>
          <span style="font-weight:400;color:var(--text2)">${esc(n.content)}</span></div>
        <div class="meta"><span>${fmtTime(n.createdAt)}</span></div>
      </div>
      ${n.read ? '' : '<span class="badge open">未读</span>'}
    </div>`;
  const renderNotifPage = () => {
    const pg = viewNotifications._page || 1;
    document.getElementById('notifList').innerHTML =
      d.notifications.slice((pg - 1) * PAGE_SIZE, pg * PAGE_SIZE).map(notifItem).join('') ||
      '<div class="empty">'+ic('bell')+' 还没有收到通知<br><span style="font-size:12px">有人点赞、评论你的文章，或你参加的比赛开始时，会在这里提醒你</span></div>';
    document.getElementById('notifPager').innerHTML = pagerHtml(pg, notifTotal, 'pgNotif');
    document.querySelectorAll('.notif-item').forEach(el => el.onclick = async () => {
      try { await api(`/api/notifications/${el.dataset.nid}/read`, { method: 'POST' }); } catch (e) {}
      refreshUnread();
      if (el.dataset.href) go(el.dataset.href); else route();
    });
  };
  window.pgNotif = (p) => {
    viewNotifications._page = Math.min(Math.max(1, p), notifTotal);
    renderNotifPage();
    document.querySelector('.page-title').scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  $app.innerHTML = `
  <div class="container" style="max-width:860px">
    <div class="page-title">
      <div><h1>${ic('bell')} 通知中心</h1><div class="sub">点赞、评论、回复、比赛提醒都在这里</div></div>
      <button class="btn ghost sm" id="readAllBtn">${ic('check')} 全部已读</button>
    </div>
    <div class="card">
      <div id="notifList"></div>
      <div id="notifPager"></div>
    </div>
  </div>`;
  document.getElementById('readAllBtn').onclick = async () => {
    await api('/api/notifications/read-all', { method: 'POST' });
    toast('已全部标记为已读');
    refreshUnread();
    route();
  };
  renderNotifPage();
}

/* ---------- 公告 ---------- */
async function viewAnnouncements() {
  const d = await api('/api/announcements');
  $app.innerHTML = `
  <div class="container" style="max-width:860px">
    <div class="page-title"><div><h1>${ic('megaphone')} 公告</h1><div class="sub">站点通知与使用指南</div></div></div>
    ${d.announcements.map(a => `
    <div class="card ann-card">
      <div class="ann-head"><h2>${esc(a.title)}</h2><span class="meta">${fmtTime(a.createdAt)}</span></div>
      <div class="ann-body">${md(a.content)}</div>
    </div>`).join('') || '<div class="card"><div class="empty">暂无公告</div></div>'}
  </div>`;
}
async function viewAnnouncement(arg) {
  const id = decodeURIComponent(arg || '');
  if (!id) { location.hash = '#/home'; return; }
  const a = await api('/api/announcements/' + encodeURIComponent(id));
  $app.innerHTML = `
  <div class="container" style="max-width:860px">
    <div class="page-title"><div><h1>${ic('megaphone')} ${esc(a.title)}</h1><div class="sub">发布于 ${fmtTime(a.createdAt)}</div></div></div>
    <div class="card"><div class="ann-body">${md(a.content || '')}</div></div>
    <div style="margin-top:12px"><a href="#/announcements">← 查看全部公告</a></div>
  </div>`;
}
/* ---------- 下载站 ---------- */
async function viewDownload() {
  $app.innerHTML = `
  <div class="container dl-page">
    <div class="card dl-hero">
      <img class="dl-logo" src="/img/logo.svg" alt="文汇">
      <h1>下载文汇</h1>
      <div class="dl-sub">桌面版 · 安卓版 · 网页版，随时随地记录与创作</div>
      <div class="dl-badges"><span>当前版本 v1.1.4</span><span>2026-10-27 更新</span><span>免费使用</span></div>
    </div>
    <div class="dl-grid">
      <div class="card dl-card">
        <div class="dl-ic">${ic('win')}</div>
        <div class="dl-name">Windows 安装版</div>
        <div class="dl-desc">IDE 式写作编辑器 v1.1.6：内置文汇社区（做题/比赛/讨论区）+ 设置面板 + 一键发布到网站 · 约 106MB</div>
        <a class="btn primary dl-btn" href="https://gh-proxy.com/https://github.com/ZhangCingWab/wenluo_cloud/releases/download/v1.1.6/WenHui-1.1.6-setup.exe" download="WenHui-1.1.6-setup.exe">${ic('downloads')} 高速下载</a>
        <div class="dl-alt">
          <a href="https://ghfast.top/https://github.com/ZhangCingWab/wenluo_cloud/releases/download/v1.1.6/WenHui-1.1.6-setup.exe" download>备用 1</a>
          <a href="https://ghproxy.net/https://github.com/ZhangCingWab/wenluo_cloud/releases/download/v1.1.6/WenHui-1.1.6-setup.exe" download>备用 2</a>
          <a href="/api/download/exe" download>本站直下</a>
        </div>
      </div>
      <div class="card dl-card">
        <div class="dl-ic">${ic('android')}</div>
        <div class="dl-name">Android 版</div>
        <div class="dl-desc">下载 APK 安装包 · 约 16.5KB · 安装时需允许未知来源应用</div>
        <a class="btn primary dl-btn" href="/app/wenhui.apk" download="wenhui.apk">${ic('downloads')} 下载 APK</a>
        <div class="dl-alt"><a href="#/home">或直接用网页版 →</a></div>
      </div>
      <div class="card dl-card">
        <div class="dl-ic">${ic('globe')}</div>
        <div class="dl-name">网页版</div>
        <div class="dl-desc">无需下载，手机浏览器添加到主屏幕即可像 App 一样使用</div>
        <a class="btn primary dl-btn" href="#/home">立即使用</a>
        <div class="dl-alt"><a href="#/downloads">所有平台数据实时同步</a></div>
      </div>
    </div>
    <div class="card dl-tips">
      <div class="dl-t"><b>Windows</b><span>双击安装包完成安装。新版是 IDE 式编辑器：左侧「文章空间」选文件夹打开 .md 文件，Ctrl+L 登录后可一键发布文章/帖子到网站</span></div>
      <div class="dl-t"><b>Android</b><span>安装时系统会提示「未知来源」，在设置中允许本应用即可</span></div>
      <div class="dl-t"><b>网页版</b><span>手机浏览器菜单 → 「添加到主屏幕」，即可全屏像原生 App 使用</span></div>
    </div>
  </div>`;
}
/* 新用户必读弹窗：进主页时检查 localStorage，有未读公告就弹一次 */
function showAnnModal(list) {
  if (!Array.isArray(list) || !list.length) return;
  let read = [];
  try { read = JSON.parse(localStorage.getItem('annReadIds') || '[]'); } catch (e) {}
  const target = list.find(a => a && a.id && !read.includes(a.id));
  if (!target) return;
  const ov = document.createElement('div');
  ov.className = 'modal-mask';
  ov.innerHTML = `
    <div class="modal-card ann-modal">
      <h2 style="margin-bottom:12px">${esc(target.title)}</h2>
      <div class="ann-body">${md(target.content || '')}</div>
      <div style="text-align:center;margin-top:16px"><button class="btn primary" id="annOk">我知道了</button></div>
    </div>`;
  document.body.appendChild(ov);
  const close = () => {
    ov.classList.add('closing');
    setTimeout(() => ov.remove(), 220);
    try {
      const arr = JSON.parse(localStorage.getItem('annReadIds') || '[]');
      if (!arr.includes(target.id)) { arr.push(target.id); localStorage.setItem('annReadIds', JSON.stringify(arr)); }
    } catch (e) {}
  };
  ov.querySelector('#annOk').onclick = close;
  ov.onclick = (e) => { if (e.target === ov) close(); };
}
async function viewHome() {
  hideAiFab();
  const skItem = () => `<div class="item"><div class="skeleton sk-ava"></div><div style="flex:1"><div class="skeleton sk-ln" style="width:72%"></div><div class="skeleton sk-ln" style="width:46%;height:11px"></div></div></div>`;
  $app.innerHTML = `
  <div class="container">
    <div class="hero">
      <div class="skeleton" style="width:min(320px,62%);height:30px;margin:0 auto 10px"></div>
      <div class="skeleton" style="width:min(430px,74%);height:15px;margin:0 auto 20px"></div>
      <div class="hero-btns">${'<div class="skeleton sk-btn"></div>'.repeat(4)}</div>
    </div>
    <div class="home-grid">
      <div class="hg-col">
        <div class="card"><h2>${ic('megaphone')} 公告</h2><div class="skeleton sk-ln"></div><div class="skeleton sk-ln" style="width:82%"></div><div class="skeleton sk-ln" style="width:64%"></div></div>
        <div class="card"><h2>${ic('book')} 最新文章</h2>${skItem() + skItem() + skItem()}</div>
      </div>
      <div class="hg-col">
        <div class="card"><h2>${ic('forum')} 最新帖子</h2>${skItem() + skItem() + skItem()}</div>
        <div class="card"><h2>${ic('contests')} 进行中的比赛</h2>${skItem()}</div>
      </div>
    </div>
    <div class="stats">${'<div class="stat"><div class="skeleton sk-num"></div><div class="skeleton sk-ln" style="width:52px;margin:6px auto 0"></div></div>'.repeat(4)}</div>
  </div>`;
  const [d, cd, ad] = await Promise.all([
    api('/api/home').catch(() => ({ stats: {}, latestArticles: [], latestPosts: [], activeContests: [] })),
    state.me ? api('/api/checkins/today').catch(() => ({ daily: null, streak: 0, myCheckin: null })) : { daily: null, streak: 0, myCheckin: null },
    api('/api/announcements').catch(() => ({ announcements: [] }))
  ]);
  showAnnModal(ad.announcements || []);
  const itemList = (arr, type) => arr.map(x => `
    <div class="item">
      ${avatarHtml(x.author, 'xs')}
      <div style="flex:1">
        <div class="title"><a href="#/${type}/${x.id}">${esc(x.title)}</a></div>
        <div class="meta"><span>${esc(x.author.nickname)}</span><span>${fmtTime(x.createdAt)}</span>
        ${type === 'article' ? `<span>${ic('eye')} <span class="num">${x.views || 0}</span></span><span>${ic('heart')} <span class="num">${x.likeCount || 0}</span></span>` : `<span>${ic('forum')} <span class="num">${x.commentCount || 0}</span></span>`}
        </div>
      </div>
    </div>`).join('') || '<div class="empty">暂无内容</div>';

  const annCard = (ad.announcements || []).length ? `
    <div class="card ann-list">
      <h2>${ic('megaphone')} 公告</h2>
      ${ad.announcements.map(a => `<div class="ann-link"><a href="#/announcement/${encodeURIComponent(a.id)}">${esc(a.title)}</a></div>`).join('')}
    </div>` : '';

  const checkinCard = cd && cd.daily ? `
    <div class="checkin-card" style="cursor:pointer" onclick="location.hash='#/daily'">
      <h2>${ic('flame')} 今日打卡 · 第 ${cd.streak || 1} 天</h2>
      <div class="cc-sub">每天一题，坚持写作</div>
      <div class="cc-row">
        <div class="streak-badge">
          <div class="n">${cd.streak || 0}</div>
          <div class="l">连续天数</div>
        </div>
        <div class="cc-problem">
          <b>${ic('clipboard')} ${esc(cd.daily.title)}</b><br>
          <span style="opacity:.85;font-size:12px">${cd.myCheckin ? ic('check')+' 今天已打卡，点我看详情' : ic('flame')+' 点我开始今天的练习！'}</span>
        </div>
      </div>
    </div>` : '';

  const changelogCard = `
    <div class="card">
      <h2 class="cl-head"><span>${ic('edit')} 更新日志</span><a class="cl-all" href="#/changelog">查看全部 »</a></h2>
      ${CHANGELOG.slice(0, 3).map(e => `
      <div class="item">
        <div style="flex:1">
          <div class="title" style="font-size:13.5px">${e.items.map(esc).join('；')}</div>
          <div class="meta"><span>${ic('user')} ${esc(e.author)}</span><span>${ic('clock')} ${esc(e.date)}</span></div>
        </div>
      </div>`).join('')}
    </div>`;

  $app.innerHTML = `
  <div class="container">
    <div class="hero">
      <h1>文汇 · 文章竞赛社区</h1>
      <p>写作、交流、比赛 —— 一个简洁流畅的创作家园</p>
      <div class="hero-btns">
        <button class="btn-hero solid" id="hWrite">${ic('edit')} 立即开始创作</button>
        <button class="btn-hero solid" id="hPost">${ic('forum')} 发帖 · 论坛</button>
        <button class="btn-hero ghost" id="hFile">${ic('submit')} 文件投稿</button>
        <button class="btn-hero ghost" id="hDown">${ic('downloads')} 下载 App</button>
      </div>
    </div>
    <div class="home-grid">
      <div class="hg-col">
        ${annCard}
        <div class="card"><h2>${ic('book')} 最新文章</h2>${itemList(d.latestArticles || [], 'article')}</div>
      </div>
      <div class="hg-col">
        ${checkinCard}
        <div class="card"><h2>${ic('forum')} 最新帖子</h2>${itemList(d.latestPosts || [], 'post')}</div>
        ${d.activeContests && d.activeContests.length ? `
        <div class="card">
          <h2>${ic('contests')} 进行中的比赛</h2>
          ${d.activeContests.map(c => contestRow(c)).join('')}
        </div>` : ''}
      </div>
    </div>
    ${changelogCard}
    <div class="stats">
      <div class="stat"><div class="num">${d.stats.users || 0}</div><div class="lab">注册用户</div></div>
      <div class="stat"><div class="num">${d.stats.articles || 0}</div><div class="lab">收录文章</div></div>
      <div class="stat"><div class="num">${d.stats.posts || 0}</div><div class="lab">论坛帖子</div></div>
      <div class="stat"><div class="num">${d.stats.contests || 0}</div><div class="lab">举办比赛</div></div>
    </div>
  </div>`;
  document.getElementById('hWrite').onclick = () => needLogin() || go('#/write');
  document.getElementById('hPost').onclick = () => needLogin() || go('#/newpost');
  document.getElementById('hFile').onclick = () => needLogin() || go('#/submit');
  document.getElementById('hDown').onclick = () => go('#/downloads');
}
const contestRow = (c) => `
  <div class="item contest" style="cursor:pointer" onclick="location.hash='#/contest/${c.id}'">
    <div style="flex:1">
      <div class="c-title">${esc(c.title)}</div>
      <div class="c-meta"><span class="badge ${c.status}">${contestBadge(c.status)}</span>
        <span>${ic('clock')} ${fmtRange(c.startTime, c.endTime)}</span><span>${ic('users')} ${c.participantCount} 人已报名</span><span>${ic('clipboard')} ${c.problemCount || 0} 道题</span></div>
    </div>
    <span style="color:var(--text2)">›</span>
  </div>`;

/* ---------- 更新日志详情页（每页 8 条，前端分页） ---------- */
function viewChangelog() {
  const size = 8;
  const total = Math.max(1, Math.ceil(CHANGELOG.length / size));
  const render = () => {
    const pg = Math.min(Math.max(1, viewChangelog._page || 1), total);
    viewChangelog._page = pg;
    $app.innerHTML = `
    <div class="container">
      <div class="page-title"><div><h1>${ic('edit')} 更新日志</h1><div class="sub">文汇的每一次更新，都记录在这里</div></div></div>
      <div class="card">
        ${CHANGELOG.slice((pg - 1) * size, pg * size).map(e => `
        <div class="item">
          <div style="flex:1">
            <div class="title" style="font-size:13.5px">${e.items.map(esc).join('；')}</div>
            <div class="meta"><span>${ic('user')} ${esc(e.author)}</span><span>${ic('clock')} ${esc(e.date)}</span></div>
          </div>
        </div>`).join('')}
      </div>
      ${pagerHtml(pg, total, 'pgChangelog')}
    </div>`;
    window.pgChangelog = (p) => {
      viewChangelog._page = Math.min(Math.max(1, p), total);
      render();
      window.scrollTo(0, 0);
    };
  };
  render();
}

/* 搜索框 UI */
function searchBoxHtml(id, q, placeholder) {
  return `<div class="search-box">
    <input id="${id}" value="${esc(q)}" placeholder="${esc(placeholder)}" maxlength="60">
    <button class="btn primary" data-searchbtn="${id}">${ic('search')} 搜索</button>
  </div>`;
}
function bindSearch(id, apply) {
  const input = document.getElementById(id);
  if (!input) return;
  const btn = document.querySelector(`[data-searchbtn="${id}"]`);
  const doSearch = () => apply(input.value.trim());
  if (btn) btn.onclick = doSearch;
  input.onkeydown = (e) => { if (e.key === 'Enter') doSearch(); };
}

/* ---------- 论坛 ---------- */
async function viewForum() {
  const cat = viewForum._c || '';
  const q = viewForum._q || '';
  const params = new URLSearchParams();
  if (cat) params.set('category', cat);
  if (q) params.set('q', q);
  const d = await api('/api/posts?' + params);
  $app.innerHTML = `
  <div class="container">
    <div class="page-title">
      <div><h1>论坛广场</h1><div class="sub">和大家一起交流讨论</div></div>
      <button class="btn primary" id="newPostBtn">＋ 发帖</button>
    </div>
    ${searchBoxHtml('fQ', q, '搜索帖子标题 / 内容 / 作者…')}
    <div class="tabs">
      <span class="t ${cat === '' ? 'active' : ''}" data-c="">全部</span>
      ${POST_CATS.map(c => `<span class="t ${cat === c ? 'active' : ''}" data-c="${c}">${c}</span>`).join('')}
    </div>
    <div class="card">
      <div id="postList"></div>
      <div id="postPager"></div>
    </div>
  </div>`;
  document.getElementById('newPostBtn').onclick = () => needLogin() || go('#/newpost');
  document.querySelectorAll('.tabs .t').forEach(t => t.onclick = () => { viewForum._c = t.dataset.c; viewForum._page = 1; route(); });
  bindSearch('fQ', (v) => { viewForum._q = v; viewForum._page = 1; route(); });
  // 前端分页
  const totalPages = Math.max(1, Math.ceil(d.posts.length / PAGE_SIZE));
  const postItem = (p) => `
      <div class="item">
        ${avatarHtml(p.author, 'xs')}
        <div style="flex:1">
          <div class="title"><a href="#/post/${p.id}">${esc(p.title)}</a> <span class="type-badge">${esc(p.category || '其他')}</span></div>
          <div class="meta"><span>${esc(p.author.nickname)}</span><span>${fmtTime(p.createdAt)}</span>
          <span>${ic('forum')} <span class="num">${p.commentCount}</span></span></div>
        </div>
      </div>`;
  const renderPostPage = () => {
    const pg = viewForum._page || 1;
    document.getElementById('postList').innerHTML =
      d.posts.slice((pg - 1) * PAGE_SIZE, pg * PAGE_SIZE).map(postItem).join('') ||
      `<div class="empty">${q || cat ? '没有匹配条件的帖子' : '还没有帖子，来发第一帖吧！'}</div>`;
    document.getElementById('postPager').innerHTML = pagerHtml(pg, totalPages, 'pgPost');
  };
  window.pgPost = (p) => {
    viewForum._page = Math.min(Math.max(1, p), totalPages);
    renderPostPage();
    document.querySelector('.tabs').scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  renderPostPage();
}

/* ---------- 讨论区（求助问答 + 群聊大厅） ---------- */
async function viewDiscuss(arg) {
  const parts = (arg || '').split('/').filter(Boolean);
  const sub = parts[0] || 'help';
  const tab = (t, icon, label) =>
    `<a class="dtab ${sub === t ? 'active' : ''}" href="#/discuss/${t === 'help' ? '' : t}"><span class="icon">${icon}</span>${label}</a>`;
  $app.innerHTML = `
  <div class="container">
    <div class="page-title">
      <div><h1>讨论区</h1><div class="sub">遇到问题来求助，或者到群聊和大家畅所欲言</div></div>
    </div>
    <div class="dtabs">${tab('help', ic('discuss'), '求助问答')}${tab('chat', ic('forum'), '群聊')}</div>
    <div id="discussBody"></div>
  </div>`;
  const body = document.getElementById('discussBody');
  if (sub === 'chat') return viewDiscussChat(body, parts[1]);
  if (parts[1]) return viewHelpDetail(body, parts[1]);
  return viewHelpList(body);
}

const HELP_CATS = ['学习求助', '写作交流', '网站使用', '软件问题', '其他'];

async function viewHelpList(body) {
  body.innerHTML = '<div class="card"><div class="loading-block">加载中…</div></div>';
  const st = viewHelpList._st || '';
  const cat = viewHelpList._cat || '';
  const q = (viewHelpList._q || '').trim();
  const d = await api('/api/discuss/help?_=' + Date.now()
    + (st ? '&status=' + st : '') + (cat ? '&cat=' + encodeURIComponent(cat) : '') + (q ? '&q=' + encodeURIComponent(q) : ''));
  const catBadge = (c) => `<span class="cat-badge">${esc(c)}</span>`;
  const helpItem = (p) => `
    <div class="item">
      ${avatarHtml(p.author, 'xs')}
      <div style="flex:1">
        <div class="title"><a href="#/discuss/help/${p.id}">${esc(p.title)}</a>
          ${catBadge(p.category || '其他')}
          <span class="badge ${p.status === 'solved' ? 'solved' : 'open'}">${p.status === 'solved' ? '已解决' : '待解决'}</span></div>
        <div class="meta"><span>${esc(p.author.nickname)}</span><span>${fmtTime(p.createdAt)}</span><span>${ic('forum')} <span class="num">${p.replyCount || 0}</span></span></div>
      </div>
    </div>`;
  const helpTotal = Math.max(1, Math.ceil(d.posts.length / PAGE_SIZE));
  const renderHelpPage = () => {
    const pg = viewHelpList._page || 1;
    document.getElementById('helpList').innerHTML =
      d.posts.slice((pg - 1) * PAGE_SIZE, pg * PAGE_SIZE).map(helpItem).join('') ||
      (q ? '<div class="empty">没有找到相关求助，换个关键词试试</div>' : '<div class="empty">还没有求助，点「发求助」提问吧！</div>');
    document.getElementById('helpPager').innerHTML = pagerHtml(pg, helpTotal, 'pgHelp');
  };
  window.pgHelp = (p) => {
    viewHelpList._page = Math.min(Math.max(1, p), helpTotal);
    renderHelpPage();
    document.querySelector('.tabs').scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  const chip = (label, on, attr) => `<span class="hchip${on ? ' active' : ''}" ${attr}>${label}</span>`;
  body.innerHTML = `
  <div class="card">
    <div class="hl-toolbar">
      <div class="hl-search">
        <input id="hSearch" maxlength="50" placeholder="搜索求助标题或内容…" value="${esc(q)}">
        <button class="btn ghost" id="hSearchBtn" aria-label="搜索">${ic('search')}</button>
      </div>
      <button class="btn primary" id="newHelpBtn">＋ 发求助</button>
    </div>
    <div class="hl-chips">
      ${chip('全部', !cat, 'data-cat=""')}
      ${HELP_CATS.map(c => chip(c, cat === c, `data-cat="${c}"`)).join('')}
    </div>
    <div class="hl-chips">
      ${chip('不限状态', st === '', 'data-s=""')}
      ${chip('待解决', st === 'open', 'data-s="open"')}
      ${chip('已解决', st === 'solved', 'data-s="solved"')}
      ${q ? `<span class="hclear" id="hClear">${ic('x')} 清除搜索「${esc(q)}」</span>` : ''}
    </div>
    <div id="newHelpForm" style="display:none;margin-bottom:14px;padding:14px;background:var(--blue-light);border-radius:var(--radius-sm)">
      <div class="form-item"><label>问题类型</label><div class="hl-chips" style="margin:0" id="hCatChips">
        ${HELP_CATS.map((c, i) => chip(c, i === 0, 'data-cat="' + c + '"')).join('')}
      </div></div>
      <div class="form-item"><label>标题</label><input id="hTitle" maxlength="80" placeholder="一句话描述你的问题"></div>
      <div class="form-item"><label>详细描述</label><textarea id="hContent" style="min-height:130px" placeholder="把问题背景、遇到的现象写清楚，方便大家帮你"></textarea></div>
      <button class="btn primary" id="hSubmit">发布求助</button>
    </div>
    <div id="helpList"></div>
    <div id="helpPager"></div>
  </div>`;
  const doSearch = () => { viewHelpList._q = document.getElementById('hSearch').value; viewHelpList._page = 1; viewDiscuss('help'); };
  document.getElementById('hSearchBtn').onclick = doSearch;
  document.getElementById('hSearch').onkeydown = (e) => { if (e.key === 'Enter') doSearch(); };
  const clearBtn = document.getElementById('hClear');
  if (clearBtn) clearBtn.onclick = () => { viewHelpList._q = ''; viewDiscuss('help'); };
  body.querySelectorAll('.hl-chips [data-cat]').forEach(t => t.onclick = () => {
    if (t.id === 'hCatChips' || t.closest('#hCatChips')) {
      t.parentElement.querySelectorAll('.hchip').forEach(x => x.classList.remove('active'));
      t.classList.add('active');
      return;
    }
    viewHelpList._cat = t.dataset.cat; viewHelpList._page = 1; viewDiscuss('help');
  });
  body.querySelectorAll('.hl-chips [data-s]').forEach(t => t.onclick = () => { viewHelpList._st = t.dataset.s; viewHelpList._page = 1; viewDiscuss('help'); });
  document.getElementById('newHelpBtn').onclick = () => {
    if (needLogin()) return;
    const f = document.getElementById('newHelpForm');
    f.style.display = f.style.display === 'none' ? 'block' : 'none';
  };
  document.getElementById('hSubmit').onclick = async (e) => {
    e.target.disabled = true;
    const hCat = document.querySelector('#hCatChips .hchip.active');
    try {
      await api('/api/discuss/help', { method: 'POST', body: { title: hTitle.value, content: hContent.value, category: hCat ? hCat.dataset.cat : '其他' } });
      toast('发布成功');
      viewHelpList._st = ''; viewHelpList._cat = ''; viewHelpList._q = '';
      viewDiscuss('help');
    } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
  };
  renderHelpPage();
}

async function viewHelpDetail(body, id) {
  body.innerHTML = '<div class="card"><div class="loading-block">加载中…</div></div>';
  let d;
  try { d = await api('/api/discuss/help/' + id); }
  catch (e) { body.innerHTML = `<div class="card"><div class="empty">${ic('help')} ${esc(e.message)}</div></div>`; return; }
  const p = d.post;
  const me = state.me;
  const canManage = me && (me.role === 'admin' || me.id === p.authorId);
  const solved = p.status === 'solved';
  const replies = (d.replies || []).map(r => `
    <div class="item ${r.isSolution ? 'hp-solution' : ''}">
      ${avatarHtml(r.author, 'xs')}
      <div style="flex:1">
        <div class="meta" style="margin:0 0 4px"><b>${esc(r.author.nickname)}</b><span>${fmtTime(r.createdAt)}</span>
          ${r.isSolution ? '<span class="badge solved">'+ic('check')+' 已采纳</span>' : ''}
          ${canManage && !solved && !r.isSolution ? `<span class="lnk" data-adopt="${r.id}">采纳为答案</span>` : ''}
        </div>
        <div class="hp-text">${esc(r.content)}</div>
      </div>
    </div>`).join('');
  body.innerHTML = `
  <a class="back-link" href="#/discuss">← 返回讨论区</a>
  <div class="card">
    <div class="hp-head">
      <h2 style="margin:0">${esc(p.title)}</h2>
      <span class="cat-badge">${esc(p.category || '其他')}</span>
      <span class="badge ${solved ? 'solved' : 'open'}">${solved ? ic('check')+' 已解决' : '待解决'}</span>
    </div>
    <div class="meta" style="margin:8px 0 12px"><span>${esc(p.author.nickname)}</span><span>${fmtTime(p.createdAt)}</span>
      ${canManage && !solved ? '<span class="lnk" id="markSolved">标记为已解决</span>' : ''}
      ${canManage ? '<span class="lnk danger" id="delHelp">删除</span>' : ''}
    </div>
    <div class="hp-text" style="font-size:14.5px">${esc(p.content)}</div>
  </div>
  <div class="card">
    <h2>回复（${(d.replies || []).length}）</h2>
    <div id="replyList">${replies || '<div class="empty">还没有回复，来帮帮他吧！</div>'}</div>
  </div>
  <div class="card">
    ${me ? `
      <div class="form-item"><textarea id="rContent" style="min-height:90px" placeholder="写下你的回答或建议…"></textarea></div>
      <button class="btn primary" id="rSubmit">回复</button>` :
      '<div class="empty"><a href="#/login">登录</a> 后可以回复</div>'}
  </div>`;
  const refresh = () => viewDiscuss('help/' + id);
  body.querySelectorAll('[data-adopt]').forEach(el => el.onclick = async () => {
    try {
      await api(`/api/discuss/help/${id}/solve`, { method: 'POST', body: { replyId: el.dataset.adopt } });
      toast('已采纳为答案');
      refresh();
    } catch (e) { toast(e.message, 'err'); }
  });
  const ms = document.getElementById('markSolved');
  if (ms) ms.onclick = async () => {
    try {
      await api(`/api/discuss/help/${id}/solve`, { method: 'POST', body: {} });
      toast('已标记为已解决');
      refresh();
    } catch (e) { toast(e.message, 'err'); }
  };
  const del = document.getElementById('delHelp');
  if (del) del.onclick = async () => {
    if (!confirm('确定删除这个求助吗？回复也会一起删除')) return;
    try {
      await api('/api/discuss/help/' + id, { method: 'DELETE' });
      toast('已删除');
      go('#/discuss');
    } catch (e) { toast(e.message, 'err'); }
  };
  const rs = document.getElementById('rSubmit');
  if (rs) rs.onclick = async (e) => {
    e.target.disabled = true;
    try {
      await api(`/api/discuss/help/${id}/reply`, { method: 'POST', body: { content: rContent.value } });
      toast('回复成功');
      refresh();
    } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
  };
}

async function viewDiscussChat(body, gId) {
  body.innerHTML = '<div class="card"><div class="loading-block">加载中…</div></div>';
  const gd = await api('/api/discuss/groups');
  const gs = gd.groups || [];
  const g = gId ? gs.find(x => x.id == gId) : null;
  if (gId && !g) { body.innerHTML = '<div class="card"><div class="empty">'+ic('help')+' 群不存在</div></div>'; return; }
  const me = state.me;
  const isOwner = me && g && (me.role === 'admin' || g.ownerId == me.id);
  const sideItem = (x) => `
  <a class="chat-gitem${x.id == gId ? ' active' : ''}" href="#/discuss/chat/${x.id}">
    <span class="cg-emoji">${esc(x.emoji) || '💬'}</span>
    <span class="cg-info"><b>${esc(x.name)}</b><span class="cg-meta">${ic('users')} ${x.memberCount} 人</span></span>
    ${x.pendingCount ? `<span class="cg-badge">${x.pendingCount}</span>` : ''}
  </a>`;
  body.innerHTML = `
  <div class="chat-layout">
    <aside class="chat-side">
      <div class="chat-side-head">
        <b>群聊（${gs.length}）</b>
        <button class="btn primary sm-btn" id="gCreateBtn">＋ 建群</button>
      </div>
      ${gs.map(sideItem).join('') || '<div class="empty" style="padding:14px 6px">还没有群聊，来建第一个群吧</div>'}
    </aside>
    <section class="chat-main" id="chatMain"></section>
  </div>`;
  const createBtn = document.getElementById('gCreateBtn');
  if (createBtn) createBtn.onclick = () => {
    if (needLogin()) return;
    const EMOJIS = ['💬', '📝', '🔥', '📚', '🎨', '🎮', '🎉', '☕'];
    const ov = document.createElement('div');
    ov.className = 'modal-mask';
    ov.innerHTML = `
    <div class="modal-card gcreate">
      <h2 style="margin-bottom:14px">创建新群聊</h2>
      <div class="form-item"><label>群名称</label><input id="gcName" maxlength="30" placeholder="给群起个名字，如：初三写作互助群"></div>
      <div class="form-item"><label>群简介</label><textarea id="gcDesc" maxlength="100" style="min-height:64px" placeholder="一句话介绍这个群（选填）"></textarea></div>
      <div class="form-item"><label>群图标</label><div class="hl-chips" style="margin:0" id="gcEmoji">
        ${EMOJIS.map((e, i) => `<span class="hchip gc-e${i === 0 ? ' active' : ''}" data-e="${e}">${e}</span>`).join('')}
      </div></div>
      <div style="display:flex;gap:8px;margin-top:14px">
        <button class="btn ghost" id="gcCancel" style="flex:1;justify-content:center">取消</button>
        <button class="btn primary" id="gcOk" style="flex:1;justify-content:center">创建群聊</button>
      </div>
      <div style="font-size:11.5px;color:var(--text2);margin-top:10px;text-align:center">你是群主，其他成员申请加入后需你审核</div>
    </div>`;
    document.body.appendChild(ov);
    ov.querySelectorAll('#gcEmoji .hchip').forEach(c => c.onclick = () => {
      ov.querySelectorAll('#gcEmoji .hchip').forEach(x => x.classList.remove('active'));
      c.classList.add('active');
    });
    const close = () => { ov.classList.add('closing'); setTimeout(() => ov.remove(), 220); };
    ov.querySelector('#gcCancel').onclick = close;
    ov.onclick = (e) => { if (e.target === ov) close(); };
    ov.querySelector('#gcOk').onclick = async () => {
      const btn = ov.querySelector('#gcOk');
      const name = ov.querySelector('#gcName').value.trim();
      if (!name) { toast('先给群起个名字', 'err'); return; }
      btn.disabled = true;
      const eEl = ov.querySelector('#gcEmoji .hchip.active');
      try {
        const r = await api('/api/discuss/groups', { method: 'POST', body: { name, description: ov.querySelector('#gcDesc').value, emoji: (eEl && eEl.dataset.e) || '💬' } });
        close();
        toast('群创建成功！');
        viewDiscuss('chat/' + r.group.id);
      } catch (e) { toast(e.message, 'err'); btn.disabled = false; }
    };
  };
  const main = document.getElementById('chatMain');
  if (!g) { main.innerHTML = '<div class="chat-empty">← 选择一个群开始聊天</div>'; return; }
  if (!me || (g.myStatus !== 'approved' && !isOwner)) {
    main.innerHTML = `
    <div class="chat-join">
      <div style="font-size:36px;margin-bottom:10px">${esc(g.emoji) || '💬'}</div>
      <h2 style="margin-bottom:6px">${esc(g.name)}</h2>
      <div class="empty" style="padding:6px 0 18px">${g.myStatus === 'pending' ? '⏳ 申请已提交，群主审核通过后就能进来聊天了' : esc(g.description || '申请加入后即可和群友聊天')}</div>
      ${!me ? '<a class="btn primary" href="#/login">先登录</a>'
        : g.myStatus === 'pending' ? '<button class="btn ghost" disabled>审核中…</button>'
        : '<button class="btn primary" id="gJoinBtn">申请加入</button>'}
    </div>`;
    const jb = document.getElementById('gJoinBtn');
    if (jb) jb.onclick = async () => {
      jb.disabled = true;
      try {
        await api(`/api/discuss/groups/${gId}/join`, { method: 'POST' });
        toast('已提交申请，等群主审核');
        viewDiscuss('chat/' + gId);
      } catch (e) { toast(e.message, 'err'); jb.disabled = false; }
    };
    return;
  }
  main.innerHTML = `
  <div class="card chat-card">
    <div class="g-head"><span class="g-emoji sm">${esc(g.emoji) || '💬'}</span><b>${esc(g.name)}</b><span class="g-meta">${ic('users')} ${g.memberCount} 人</span></div>
    <div class="chat-scroll" id="chatScroll">
      <div id="reqBox"></div>
      <div id="chatMsgs"><div class="empty" style="padding:40px 0">加载中…</div></div>
    </div>
    <div class="chat-input-bar">
      <textarea id="chatInput" maxlength="500" rows="1" placeholder="和群友聊点什么…（Enter 发送，Shift+Enter 换行）"></textarea>
      <button class="btn primary" id="chatSend">发送</button>
    </div>
  </div>`;
  const scroll = document.getElementById('chatScroll');
  const msgs = document.getElementById('chatMsgs');
  const reqBox = document.getElementById('reqBox');
  if (!msgs || !document.getElementById('chatSend')) return;
  // 群主：入群申请审核
  const renderReqs = async () => {
    if (!isOwner) return;
    try {
      const r = await api(`/api/discuss/groups/${gId}/requests`);
      if (!r.requests.length) { reqBox.innerHTML = ''; return; }
      reqBox.innerHTML = `
      <div class="req-card">
        <b>${ic('users')} 入群申请（${r.requests.length}）</b>
        ${r.requests.map(q => `
        <div class="req-row">
          ${avatarHtml(q.user, 'xs')}
          <div style="flex:1;min-width:0">
            <b style="font-size:13px">${esc(q.user.nickname)}</b> <span style="font-size:11px;color:var(--text2)">@${esc(q.user.username)}</span>
            <div style="font-size:11px;color:var(--text2)">${fmtTime(q.joinedAt)} 申请</div>
          </div>
          <button class="btn primary rq-btn" data-u="${q.userId}" data-ok="1">通过</button>
          <button class="btn ghost rq-btn" data-u="${q.userId}" data-ok="">拒绝</button>
        </div>`).join('')}
      </div>`;
      reqBox.querySelectorAll('.rq-btn').forEach(b => b.onclick = async () => {
        b.disabled = true;
        try {
          await api(`/api/discuss/groups/${gId}/review`, { method: 'POST', body: { userId: b.dataset.u, approve: !!b.dataset.ok } });
          toast(b.dataset.ok ? '已通过，对方已加入群聊' : '已拒绝');
          renderReqs();
        } catch (e) { toast(e.message, 'err'); b.disabled = false; }
      });
    } catch (e) { reqBox.innerHTML = ''; }
  };
  renderReqs();
  let lastTs = 0, timer = null, sending = false;
  const bubble = (mm) => {
    const mine = me && mm.authorId === me.id;
    return `
    <div class="chat-msg ${mine ? 'mine' : ''}">
      ${avatarHtml(mm.author, 'xs')}
      <div class="chat-bubble">
        <div class="cb-head">${esc(mm.author.nickname || '')}<span class="cb-time">${fmtTime(mm.createdAt)}</span></div>
        <div class="cb-text">${esc(mm.content)}</div>
      </div>
    </div>`;
  };
  const renderMsgs = (list, append) => {
    const atBottom = scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 90;
    if (append) msgs.insertAdjacentHTML('beforeend', list.map(bubble).join(''));
    else msgs.innerHTML = list.map(bubble).join('') || '<div class="empty" style="padding:40px 0">还没有消息，来抢个沙发！</div>';
    if (atBottom || !append) scroll.scrollTop = scroll.scrollHeight;
  };
  const pull = async (init) => {
    try {
      const d = await api(`/api/discuss/chat?group=${gId}` + (lastTs ? '&after=' + lastTs : ''));
      if (d.messages.length) {
        lastTs = d.messages[d.messages.length - 1].createdAt;
        renderMsgs(d.messages, !init);
      } else if (init) renderMsgs([], false);
    } catch (e) {}
  };
  await pull(true);
  timer = setInterval(() => pull(false), 5000);
  window.addEventListener('routeCleanup', viewDiscuss._chatCleanup = () => clearInterval(timer), { once: true });
  const send = async () => {
    const inp = document.getElementById('chatInput');
    const v = inp.value.trim();
    if (!v || sending) return;
    sending = true;
    try {
      const d = await api('/api/discuss/chat', { method: 'POST', body: { groupId: gId, content: v } });
      inp.value = '';
      lastTs = Math.max(lastTs, d.message.createdAt);
      renderMsgs([d.message], true);
    } catch (e) { toast(e.message, 'err'); }
    sending = false;
  };
  document.getElementById('chatSend').onclick = send;
  document.getElementById('chatInput').onkeydown = (e) => { if (e.key == 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } };
}

async function viewNewPost() {
  if (needLogin()) return;
  $app.innerHTML = `
  <div class="container" style="max-width:760px">
    <div class="page-title"><h1>发布帖子</h1></div>
    <div class="card">
      <div class="form-item"><label>标题</label><input id="pTitle" maxlength="80" placeholder="一句话概括你的话题"></div>
      <div class="form-item"><label>类型</label><select id="pCat">${POST_CATS.map(c => `<option>${c}</option>`).join('')}</select></div>
      <div class="form-item"><label>内容</label><textarea id="pContent" class="tall" style="min-height:220px" placeholder="支持 Markdown 基础语法"></textarea></div>
      <button class="btn primary" id="pSubmit">提交（待管理员审核）</button>
      <span class="hint" style="margin-left:10px">审核通过后将在论坛广场展示</span>
    </div>
  </div>`;
  document.getElementById('pSubmit').onclick = async (e) => {
    e.target.disabled = true;
    try {
      await api('/api/posts', { method: 'POST', body: { title: pTitle.value, category: pCat.value, content: pContent.value } });
      toast('发布成功，等待审核');
      go('#/mine');
    } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
  };
}

async function viewPostDetail(id) {
  const d = await api('/api/posts/' + id);
  const p = d.post;
  // 同时拉楼中楼评论
  const cd = await api('/api/comments?target_type=post&target_id=' + id).catch(() => ({ comments: [], total: 0 }));
  p._cmRoots = cd.comments || [];
  p.commentCount = cd.total || (p.comments?.length || 0);
  $app.innerHTML = `
  <div class="container" style="max-width:820px">
    <div class="card">
      <div class="doc-head">
        <h1>${esc(p.title)}</h1>
        <div class="meta">
          <span class="type-badge">${esc(p.category || '其他')}</span>
          <span class="who">${avatarHtml(p.author, 'small')} ${esc(p.author.nickname)}</span>
          <span>${fmtTime(p.createdAt)}</span>
          <span>${ic('forum')} ${p.commentCount} 条回复</span>
          ${state.me && (state.me.id === p.authorId || state.me.role === 'admin') ? '<button class="btn red sm" id="delPost">删除</button>' : ''}
        </div>
      </div>
      <div class="doc-content prose" id="postBody"></div>
    </div>
    <div class="card gap-top">
      <h2>全部回复（${p.commentCount}）</h2>
      <div id="postComments">${renderComments(p._cmRoots || [], 'post', id)}</div>
      ${state.me ? `
      <div style="margin-top:14px" class="form-item">
        <textarea id="cInput" placeholder="友善回复，理性讨论…" style="min-height:80px"></textarea>
        <button class="btn primary" id="cSubmit" style="margin-top:10px">发表回复</button>
      </div>` : `<div class="empty"><a href="#/login">登录</a> 后参与讨论</div>`}
    </div>
  </div>`;
  paginateBody(document.getElementById('postBody'), p.content);
  const del = document.getElementById('delPost');
  if (del) del.onclick = async () => {
    if (!confirm('确定删除该帖子？')) return;
    await api('/api/posts/' + id, { method: 'DELETE' });
    toast('已删除'); go('#/forum');
  };
  const cs = document.getElementById('cSubmit');
  if (cs) cs.onclick = async () => {
    let content = document.getElementById('cInput').value.trim();
    if (!content) return toast('评论内容不能为空', 'err');
    // 提取 @昵称
    content = content.replace(/^@\S+\s+/, '');
    const parentId = viewPostDetail._replyParentId || null;
    try {
      await api('/api/comments', { method: 'POST', body: { target_type: 'post', target_id: id, parent_id: parentId, content } });
      toast('评论成功');
      route();
    } catch (err) { toast(err.message, 'err'); }
  };
  // 初始绑定
  bindCommentEvents(document.getElementById('postComments'));
}

/* ---------- 文章库 ---------- */
async function viewArticles() {
  const sort = viewArticles._s || 'new';
  const cat = viewArticles._c || '';
  const q = viewArticles._q || '';
  const params = new URLSearchParams({ sort });
  if (cat) params.set('category', cat);
  if (q) params.set('q', q);
  const d = await api('/api/articles?' + params);
  $app.innerHTML = `
  <div class="container">
    <div class="page-title">
      <div><h1>文章库</h1><div class="sub">共 ${d.articles.length} 篇${cat ? '「' + cat + '」' : ''}文章${q ? `（搜索：“${esc(q)}”）` : ''}</div></div>
      <button class="btn primary" id="wBtn">${ic('edit')} 我要写文章</button>
    </div>
    ${searchBoxHtml('aQ', q, '搜索文章标题 / 内容 / 作者…')}
    <div class="tabs">
      <span class="t ${sort === 'new' ? 'active' : ''}" data-s="new">最新</span>
      <span class="t ${sort === 'hot' ? 'active' : ''}" data-s="hot">最热</span>
      <span style="margin:0 6px;color:var(--border)">|</span>
      <span class="t ${cat === '' ? 'active' : ''}" data-c="">全部类别</span>
      ${['文件投稿', ...ART_CATS].map(c => `<span class="t ${cat === c ? 'active' : ''}" data-c="${c}">${c}</span>`).join('')}
    </div>
    <div class="card">
      <div id="artList"></div>
      <div id="artPager"></div>
    </div>
  </div>`;
  document.getElementById('wBtn').onclick = () => needLogin() || go('#/write');
  document.querySelectorAll('.tabs .t[data-s]').forEach(t => t.onclick = () => { viewArticles._s = t.dataset.s; viewArticles._page = 1; route(); });
  document.querySelectorAll('.tabs .t[data-c]').forEach(t => t.onclick = () => { viewArticles._c = t.dataset.c; viewArticles._page = 1; route(); });
  bindSearch('aQ', (v) => { viewArticles._q = v; viewArticles._page = 1; route(); });
  // 前端分页
  const totalPages = Math.max(1, Math.ceil(d.articles.length / PAGE_SIZE));
  const artItem = (a) => `
      <div class="item">
        ${avatarHtml(a.author, 'xs')}
        <div style="flex:1">
          <div class="title"><a href="#/article/${a.id}">${esc(a.title)}</a> <span class="type-badge">${esc(a.category || '其他')}</span></div>
          <div class="meta"><span>${excerpt(a.content)}</span></div>
          <div class="meta"><span>${esc(a.author.nickname)}</span><span>${fmtTime(a.createdAt)}</span>
            <span>${ic('eye')} <span class="num">${a.views || 0}</span></span><span>${ic('heart')} <span class="num">${a.likeCount || 0}</span></span></div>
        </div>
      </div>`;
  const renderArtPage = () => {
    const pg = viewArticles._page || 1;
    document.getElementById('artList').innerHTML =
      d.articles.slice((pg - 1) * PAGE_SIZE, pg * PAGE_SIZE).map(artItem).join('') ||
      `<div class="empty">${q || cat ? '没有匹配条件的文章' : '暂无文章'}</div>`;
    document.getElementById('artPager').innerHTML = pagerHtml(pg, totalPages, 'pgArt');
  };
  window.pgArt = (p) => {
    viewArticles._page = Math.min(Math.max(1, p), totalPages);
    renderArtPage();
    document.querySelector('.tabs').scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  renderArtPage();
}

/* 动态加载外部脚本（Promise 化，重复加载直接成功） */
function loadScript(src) {
  return new Promise((ok, err) => {
    if (document.querySelector('script[data-src="' + src + '"]')) return ok();
    const s = document.createElement('script');
    s.src = src; s.dataset.src = src;
    s.onload = ok; s.onerror = () => err(new Error('脚本加载失败'));
    document.head.appendChild(s);
  });
}

async function viewArticleDetail(id) {
  hideAiFab(); showAiFab();
  const [d, rd, cd] = await Promise.all([
    api('/api/articles/' + id),
    api('/api/articles/' + id + '/reviews').catch(() => ({ reviews: [], avgRating: '0.0', count: 0 })),
    api('/api/comments?target_type=article&target_id=' + id).catch(() => ({ comments: [], total: 0 }))
  ]);
  const a = d.article;
  const stars = (n) => { let s = ''; for (let i = 1; i <= 5; i++) s += i <= n ? '★' : '☆'; return s; };
  const tagsHtml = (a.tags && a.tags.length) ? `<div style="margin-top:8px">${a.tags.map(t => `<a class="tag-chip" href="#/articles?tag=${encodeURIComponent(t)}">#${esc(t)}</a>`).join('')}</div>` : '';
  $app.innerHTML = `
  <div id="readBar"></div>
  <div class="container" style="max-width:820px">
    <div class="card">
      <div class="doc-head">
        <h1>${esc(a.title)}</h1>
        <div class="meta">
          <span class="type-badge">${esc(a.category || '其他')}</span>
          ${tagsHtml}
          <span class="who">${avatarHtml(a.author, 'small')} ${esc(a.author.nickname)}</span>
          <span>${fmtTime(a.createdAt)}</span>
          <span>${ic('eye')} ${a.views || 0}</span>
          ${a.status !== 'approved' ? `<span class="badge ${a.status}">${statusBadge(a.status)}</span>` : ''}
          ${state.me && (state.me.id === a.authorId || state.me.role === 'admin') ? `<button class="btn red sm" id="delArt">删除</button>` : ''}
        </div>
      </div>
      <div class="doc-content prose" id="artBody"></div>
      ${(a.id || '').startsWith('a_file_') ? `<div class="doc-content prose" id="fileDocBox" style="margin-top:16px;border-top:1px dashed var(--border);padding-top:16px"><div class="empty">${ic('file')} 正在加载文档内容…</div></div>` : ''}
      <div style="margin-top:22px;text-align:center">
        <button class="btn like-btn ${a.liked ? 'liked' : ''}" id="likeBtn">${a.liked ? ic('heart')+' 已赞' : ic('heart')+' 点赞'} · ${a.likeCount}</button>
      </div>
    </div>

    <div class="card gap-top">
      <h2>${ic('star')} 文章点评（${rd.count}）<span class="hint" style="font-weight:400">平均 ${rd.avgRating} 星</span></h2>
      ${state.me ? `
      <div style="margin-bottom:14px;padding-bottom:14px;border-bottom:1px dashed var(--border)">
        <div class="hint" style="margin-bottom:6px">给这篇文章打个分吧（点评 +10 积分）</div>
        <div class="star-picker" id="starPicker">
          ${[1,2,3,4,5].map(i => `<span class="s" data-v="${i}">${i <= (viewArticleDetail._sel || 0) ? '★' : '☆'}</span>`).join('')}
          <span class="hint" style="margin-left:10px;font-size:12px" id="starHint">点击星星评分</span>
        </div>
        <textarea id="revContent" style="width:100%;padding:8px 10px;border:1px solid var(--border);border-radius:8px;margin-top:8px;min-height:70px;font-size:13px;resize:vertical" placeholder="说说你的感受…"></textarea>
        <button class="btn primary sm" id="revSubmit" style="margin-top:6px">${ic('submit')} 提交点评</button>
      </div>` : `<div class="empty" style="margin-bottom:12px"><a href="#/login">登录</a> 后参与点评（点评 +10 积分）</div>`}
      ${rd.reviews.map(r => `
      <div class="review-item-box">
        ${avatarHtml(r.author, 'small')}
        <div class="review-content">
          <div class="rc-meta">
            <b>${esc(r.author.nickname)}</b>
            <span class="review-stars">${stars(r.rating)}</span>
            · ${fmtTime(r.createdAt)}
          </div>
          <div class="rc-text">${md(r.content)}</div>
        </div>
      </div>`).join('') || '<div class="empty">还没有点评，来当第一个吧！</div>'}
    </div>

    <div class="card gap-top">
      <h2>${ic('forum')} 评论（${cd.total}）</h2>
      ${state.me ? `
      <div style="margin-bottom:14px;padding-bottom:14px;border-bottom:1px dashed var(--border)">
        <textarea id="cmInput" style="width:100%;padding:8px 10px;border:1px solid var(--border);border-radius:8px;min-height:60px;font-size:13px;resize:vertical" placeholder="说点什么…"></textarea>
        <button class="btn primary sm" id="cmSubmit" style="margin-top:6px">${ic('forum')} 发表评论</button>
      </div>` : `<div class="empty" style="margin-bottom:12px"><a href="#/login">登录</a> 后参与评论</div>`}
      <div id="commentBox">${renderComments(cd.comments, 'article', id)}</div>
    </div>

    <div class="card" id="relatedCard" style="display:none"></div>
  </div>`;
  paginateBody(document.getElementById('artBody'), a.content);
  // 文件投稿文章：把文档内容直接渲染到正文（docx→HTML / pdf→内嵌预览 / txt→文本）
  if ((id || '').startsWith('a_file_')) {
    const fbox = document.getElementById('fileDocBox');
    if (fbox) (async () => {
      try {
        const ext = ((a.title || '').match(/\.([a-z0-9]+)$/i) || [])[1] ? a.title.match(/\.([a-z0-9]+)$/i)[1].toLowerCase() : '';
        if (['doc', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rtf', 'csv'].includes(ext)) {
          fbox.innerHTML = '<div class="empty">该文件类型暂不支持在线预览，请点击上方「下载文件」查看原文</div>';
          return;
        }
        const res = await fetch('/api/files/' + id.replace(/^a_file_/, '') + '/download');
        if (!res.ok) throw new Error('文件加载失败 (' + res.status + ')');
        if (ext === 'pdf') {
          fbox.innerHTML = `<iframe src="${URL.createObjectURL(await res.blob())}" style="width:100%;height:80vh;border:none;border-radius:8px" title="PDF 预览"></iframe>`;
        } else if (ext === 'docx') {
          await loadScript('https://cdnjs.cloudflare.com/ajax/libs/mammoth/1.8.0/mammoth.browser.min.js');
          const r = await window.mammoth.convertToHtml({ arrayBuffer: await res.arrayBuffer() });
          if (r.value && r.value.trim()) paginateHtml(fbox, r.value);
          else fbox.innerHTML = '<div class="empty">（文档内容为空）</div>';
        } else {
          paginateHtml(fbox, md(await res.text()));
        }
      } catch (e) {
        fbox.innerHTML = `<div class="empty">文档内容加载失败：${esc(e.message)}<br>可点击上方「下载文件」查看原文</div>`;
      }
    })();
  }
  // 绑定评论区事件（回复/删除/点赞）
  bindCommentEvents(document.getElementById('commentBox'));
  if (state.me) {
    const sp = document.getElementById('starPicker');
    if (sp) {
      const refreshStars = (v) => {
        sp.querySelectorAll('.s').forEach(el => el.classList.toggle('on', +el.dataset.v <= v));
        document.getElementById('starHint').textContent = v ? `你选了 ${v} 星` : '点击星星评分';
      };
      sp.querySelectorAll('.s').forEach(el => {
        el.onclick = () => { viewArticleDetail._sel = +el.dataset.v; refreshStars(+el.dataset.v); };
        el.onmouseenter = () => refreshStars(+el.dataset.v);
      });
      sp.onmouseleave = () => refreshStars(viewArticleDetail._sel || 0);
    }
    document.getElementById('revSubmit').onclick = async () => {
      if (!viewArticleDetail._sel) return toast('请先选星', 'err');
      const content = document.getElementById('revContent').value.trim();
      if (!content) return toast('请写点评内容', 'err');
      try {
        await api(`/api/articles/${id}/reviews`, { method: 'POST', body: { rating: viewArticleDetail._sel, content } });
        toast('点评成功！+10 积分'); viewArticleDetail._sel = 0; route();
      } catch (e) { toast(e.message, 'err'); }
    };
  }
  const del = document.getElementById('delArt');
  if (del) del.onclick = async () => {
    if (!confirm('确定删除该文章？')) return;
    await api('/api/articles/' + id, { method: 'DELETE' });
    toast('已删除'); go('#/articles');
  };
  const lb = document.getElementById('likeBtn');
  if (lb) lb.onclick = async () => {
    if (needLogin()) return;
    try {
      const r = await api(`/api/articles/${id}/like`, { method: 'POST' });
      lb.className = 'btn like-btn' + (r.liked ? ' liked' : '');
      lb.innerHTML = (r.liked ? ic('heart')+' 已赞' : ic('heart')+' 点赞') + ' · ' + r.likeCount;
    } catch (e) { toast(e.message, 'err'); }
  };
  // 评论提交
  const cmBtn = document.getElementById('cmSubmit');
  if (cmBtn) cmBtn.onclick = async () => {
    let content = document.getElementById('cmInput').value.trim();
    if (!content) return toast('评论内容不能为空', 'err');
    // 提取 @昵称（去掉它，保留真正内容）
    const mentionMatch = content.match(/^@(\S+)\s+/);
    content = content.replace(/^@\S+\s+/, '');
    const parentId = viewArticleDetail._replyParentId || null;
    try {
      await api('/api/comments', { method: 'POST', body: { target_type: 'article', target_id: id, parent_id: parentId, content } });
      toast('评论成功');
      route();
    } catch (e) { toast(e.message, 'err'); }
  };
  // 阅读进度条
  window.addEventListener('scroll', viewArticleDetail._onScroll = () => {
    const bar = document.getElementById('readBar'); if (!bar) return;
    const h = document.documentElement;
    const pct = Math.min(100, Math.max(0, (h.scrollTop / (h.scrollHeight - h.clientHeight)) * 100));
    bar.style.width = pct + '%';
  });
  viewArticleDetail._onScroll();
  // 离开时清理
  window.addEventListener('routeCleanup', viewArticleDetail._cleanup = () => {
    window.removeEventListener('scroll', viewArticleDetail._onScroll);
  });
  // 相关推荐
  api('/api/articles').then(r => {
    const list = (r.articles || []).filter(x => x.id !== id && x.status === 'approved');
    const sameCat = list.filter(x => x.category === a.category).slice(0, 6);
    const sameTag = (a.tags && a.tags.length) ? list.filter(x => x.tags && x.tags.some(t => a.tags.includes(t))).slice(0, 6) : [];
    const pool = [...sameCat, ...sameTag, ...list].filter((x, i, arr) => arr.findIndex(y => y.id === x.id) === i).slice(0, 6);
    if (!pool.length) return;
    const rc = document.getElementById('relatedCard');
    rc.style.display = '';
    rc.innerHTML = `<h2>${ic('book')} 相关推荐</h2><div class="rel-grid">${pool.map(x => `
      <a href="#/article/${x.id}" class="rel-item">
        <div class="rel-title">${esc(x.title)}</div>
        <div class="rel-meta"><span class="type-badge">${esc(x.category)}</span> · ${esc(x.author.nickname)} · ${ic('eye')} ${x.views || 0}</div>
      </a>`).join('')}</div>`;
  }).catch(() => {});
}

/* 递归渲染楼中楼评论 */
function renderComments(roots, targetType, targetId) {
  if (!roots || !roots.length) return '<div class="empty">还没有评论，来抢沙发！</div>';
  return roots.map(c => `
  <div class="cm-item" data-id="${c.id}">
    ${avatarHtml(c.author, 'small')}
    <div class="cm-body">
      <div class="cm-meta">
        <b>${esc(c.author.nickname)}</b> · <span class="hint">${fmtTime(c.createdAt)}</span>
        <span class="cm-like" data-cid="${c.id}" data-obj="${targetType === 'article' ? 'a' : 'p'}" data-tid="${targetId}">${ic('heart')} ${c.likeCount || 0}</span>
        <span class="cm-reply" data-cid="${c.id}" data-target="${targetType}" data-tid="${targetId}" data-replyto="${esc(c.author.nickname)}">回复</span>
        ${(state.me && (state.me.id === c.authorId || state.me.role === 'admin')) ? `<span class="cm-del" data-cid="${c.id}" data-target="${targetType}" data-tid="${targetId}">删除</span>` : ''}
      </div>
      <div class="cm-text">${esc(c.content)}</div>
      ${c.replies && c.replies.length ? `<div class="cm-replies">${renderComments(c.replies, targetType, targetId)}</div>` : ''}
    </div>
  </div>`).join('');
}

/* 绑定评论区的回复/点赞/删除事件（每次局部刷新后调用）*/
function bindCommentEvents(container) {
  if (!container) return;
  // 回复按钮
  container.querySelectorAll('.cm-reply').forEach(btn => {
    btn.onclick = () => {
      const cid = btn.dataset.cid;
      const target = btn.dataset.target;
      const tid = btn.dataset.tid;
      const replyTo = btn.dataset.replyto;
      // 自动 @昵称 + 存 parentId（兼容文章 cmInput 和论坛 cInput）
      const input = document.getElementById('cmInput') || document.getElementById('cInput');
      if (input) {
        input.focus();
        input.value = `@${replyTo} `;
        if (target === 'article') viewArticleDetail._replyParentId = cid;
        else viewPostDetail._replyParentId = cid;
      }
    };
  });
  // 点赞评论（暂未实现，占位）
  container.querySelectorAll('.cm-like').forEach(btn => {
    btn.onclick = () => toast('评论点赞暂未开放 🙏');
  });
  // 删除评论
  container.querySelectorAll('.cm-del').forEach(btn => {
    btn.onclick = async () => {
      if (!confirm('确定删除该评论？')) return;
      const cid = btn.dataset.cid;
      try {
        await api('/api/comments/' + cid, { method: 'DELETE' });
        toast('评论已删除');
        // 局部刷新
        const box = container.id === 'commentBox' ? container : container.closest('#commentBox, #postComments');
        const targetType = btn.dataset.target;
        const tid = btn.dataset.tid;
        if (box && targetType) {
          const gc = await api('/api/comments?target_type=' + targetType + '&target_id=' + tid);
          box.innerHTML = renderComments(gc.comments, targetType, tid) + `<div class="hint" style="margin-top:8px">共 ${gc.total} 条评论</div>`;
          bindCommentEvents(box);
        }
      } catch (e) { toast(e.message, 'err'); }
    };
  });
}

async function viewWrite(editId) {
  hideAiFab();
  hideAiFab(); // 确认关掉浮动按钮，写文章页面内嵌 AI
  if (needLogin()) return;
  let a = null;
  if (editId) {
    const d = await api('/api/articles/' + editId);
    a = d.article;
  }
  const tpls = await api('/api/templates').catch(() => ({ templates: [] }));
  $app.innerHTML = `
  <div class="container" style="max-width:100%;padding:0 16px">
    <div class="page-title">
      <h1>${a ? '编辑文章' : '写文章'}</h1>
      <div style="display:flex;gap:8px">
        <button class="btn ghost sm" id="tplBtn">${ic('templates')} 选择模板</button>
      </div>
    </div>

    <!-- 可拖拽分栏 -->
    <div id="writeSplit" class="write-split">
      <!-- 左侧：编辑器 -->
      <div id="writeLeft" class="write-pane" style="width:55%;min-width:340px">
        <div id="tplPanel" style="display:none">
          <div class="card">
            <h2>${ic('templates')} 写作模板（点击应用到编辑器）</h2>
            <div class="tpl-grid">
              ${tpls.templates.map(t => `
              <div class="tpl-card" data-tpl="${t.id}">
                <div class="t-title">${esc(t.title)}</div>
                <div class="t-desc">${esc(t.description)}</div>
                <span class="t-cat">${esc(t.category)}</span>
              </div>`).join('')}
            </div>
          </div>
        </div>

        <div id="tplDetail" style="display:none"></div>

        <div class="card">
          <div class="form-item"><label>标题</label><input id="aTitle" maxlength="80" value="${a ? esc(a.title) : ''}" placeholder="给你的文章起个标题"></div>
          <div class="form-item"><label>类别</label>
            <select id="aCat">${ART_CATS.map(c => `<option ${a && (a.category || '其他') === c ? 'selected' : ''}>${c}</option>`).join('')}</select>
            <div class="hint">选择文体/题材类别，方便读者在文章库筛选</div>
          </div>
          <div class="form-item">
            <label>内容（支持 Markdown）</label>
            <div style="display:flex;gap:10px;margin-bottom:6px">
              <label style="cursor:pointer;font-size:12px;color:var(--text-2)"><input type="checkbox" id="mdPreview" checked> 实时预览</label>
            </div>
            <div id="mdSplit" style="display:flex;gap:12px">
              <div style="flex:1;min-width:0">
                <textarea id="aContent" class="tall" style="min-height:520px" placeholder="## 标题
这里是正文…">${a ? esc(a.content) : ''}</textarea>
              </div>
              <div id="mdPreviewBox" style="flex:1;min-width:0;max-height:600px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;padding:14px;background:var(--bg-soft);font-size:14px;line-height:1.7"></div>
            </div>
          </div>
          <button class="btn primary" id="aSubmit">${a ? '保存修改' : '提交（待管理员审核）'}</button>
          <span class="hint" style="margin-left:10px">审核通过后将在文章库展示</span>
        </div>
      </div>

      <!-- 拖拽手柄 -->
      <div id="writeDivider" class="write-divider" title="拖拽调整宽度">
        <div class="divider-handle"></div>
      </div>

      <!-- 右侧：AI 助手 -->
      <div id="writeAI" class="write-pane write-ai" style="width:45%;min-width:280px">
        <div class="ai-card">
          <div class="ai-header">
            <div class="ai-logo">${ic('sparkle')}</div>
            <div>
              <div class="ai-title">AI 写作助手</div>
              <div class="ai-sub">描述你的创意，让 AI 帮你变成文字</div>
            </div>
          </div>
          <div class="ai-task-bar">
            <button class="ai-task-btn active" data-t="write">${ic('sparkle')} 帮你写</button>
            <button class="ai-task-btn" data-t="outline">${ic('clipboard')} 列大纲</button>
            <button class="ai-task-btn" data-t="rewrite">${ic('palette')} 润色</button>
            <button class="ai-task-btn" data-t="continue">${ic('book')} 续写</button>
            <button class="ai-task-btn" data-t="review">${ic('edit')} 批改</button>
          </div>
          <div class="ai-body">
            <div class="ai-field">
              <label>你想写什么？</label>
              <textarea id="aiInput" class="ai-input" placeholder="${a ? '基于已写内容帮我写更多…' : '比如：写一篇关于「代码与生活」的散文，谈谈编程教会了我什么'}">${a ? '' : ''}</textarea>
            </div>
            <div class="ai-field">
              <label>风格 / 要求</label>
              <input id="aiStyle" placeholder="议论文 / 轻松幽默 / 简洁有力 / 800 字">
            </div>
            <button class="ai-send" id="aiSend">
              <span class="ai-send-ico">${ic('bolt')}</span>
              <span>让 AI 帮你写</span>
            </button>
            <div id="aiResult" class="ai-result"></div>
            <button class="ai-apply" id="aiApply">
              <span>${ic('downloads')} 把结果插入编辑器</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>`;

  document.getElementById('tplBtn').onclick = () => {
    const p = document.getElementById('tplPanel');
    const d = document.getElementById('tplDetail');
    p.style.display = p.style.display === 'none' ? 'block' : 'none';
    d.style.display = 'none';
  };
  document.querySelectorAll('.tpl-card').forEach(c => c.onclick = async () => {
    const t = await api('/api/templates/' + c.dataset.tpl);
    document.getElementById('tplDetail').innerHTML = `
      <div class="card">
        <h2>${ic('file')} ${esc(t.template.title)}</h2>
        <div class="hint" style="margin-bottom:10px">${esc(t.template.description)}</div>
        <div class="tpl-preview">${esc(t.template.content)}</div>
        <button class="btn primary sm" id="applyTpl">${ic('check')} 应用到编辑器</button>
        <button class="btn ghost sm" id="closeTpl" style="margin-left:8px">关闭</button>
      </div>`;
    document.getElementById('tplDetail').style.display = 'block';
    document.getElementById('tplPanel').style.display = 'none';
    document.getElementById('applyTpl').onclick = () => {
      const ta = document.getElementById('aContent');
      ta.value = (ta.value ? ta.value + '\n\n' : '') + t.template.content;
      toast('模板已应用！');
      document.getElementById('tplDetail').style.display = 'none';
      document.getElementById('aContent').focus();
      updatePreview();
    };
    document.getElementById('closeTpl').onclick = () => { document.getElementById('tplDetail').style.display = 'none'; document.getElementById('tplPanel').style.display = 'block'; };
  });

  // ========== 可拖拽分栏 ==========
  (function() {
    const split = document.getElementById('writeSplit');
    const left = document.getElementById('writeLeft');
    const right = document.getElementById('writeAI');
    const div = document.getElementById('writeDivider');
    let dragging = false;
    div.addEventListener('mousedown', (e) => {
      dragging = true;
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    });
    document.addEventListener('mousemove', (e) => {
      if (!dragging) return;
      const rect = split.getBoundingClientRect();
      let pct = ((e.clientX - rect.left) / rect.width) * 100;
      pct = Math.max(25, Math.min(75, pct)); // 25%~75% 限制
      left.style.width = pct + '%';
      right.style.width = (100 - pct) + '%';
    });
    document.addEventListener('mouseup', () => {
      if (dragging) {
        dragging = false;
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
      }
    });
  })();

  // ========== AI 助手逻辑 ==========
  let _aiTask = 'write'; // 默认「帮你写」
  document.querySelectorAll('#writeAI .ai-task-btn').forEach(b => b.onclick = () => {
    _aiTask = b.dataset.t;
    document.querySelectorAll('#writeAI .ai-task-btn').forEach(x => x.classList.toggle('active', x === b));
    const aiInput = document.getElementById('aiInput');
    if (aiInput) {
      const phMap = {
        write: '比如：写一篇关于「代码与生活」的散文，谈谈编程教会了我什么',
        outline: '给「' + (aTitle?.value || '你的主题') + '」列一个大纲',
        rewrite: '把这段内容润色一下（会参考左侧编辑器里已写的内容）',
        continue: '接着左侧编辑器里已写的内容往下写',
        review: '帮我批改左侧编辑器里的内容，给建议和分数'
      };
      aiInput.placeholder = phMap[_aiTask] || '描述你的需求';
    }
  });
  document.getElementById('aiSend').onclick = async () => {
    if (needLogin()) return;
    const input = document.getElementById('aiInput').value;
    const style = document.getElementById('aiStyle').value;
    const aiResult = document.getElementById('aiResult');
    const aiApply = document.getElementById('aiApply');
    const btn = document.getElementById('aiSend');
    if (!input) return toast('请写点什么', 'err');
    btn.disabled = true;
    btn.innerHTML = '<span class="ai-send-ico">'+ic('sparkle')+'</span><span>AI 正在思考…</span>';
    aiResult.innerHTML = '<div class="ai-loader">AI 正在想办法</div>';
    aiApply.style.display = 'none';
    try {
      const currentContent = document.getElementById('aContent').value;
      const r = await api('/api/ai/assist', { method: 'POST', body: { task: _aiTask, input, style, content: currentContent, title: aTitle.value } });
      let html = md(r.result) || '<span class="hint">AI 没返回内容</span>';
      const tags = [];
      if (r.source === 'ai') tags.push('<span class="ai-tag ai-tag-ai">'+ic('sparkle')+' Workers AI</span>');
      if (r.source === 'template') tags.push('<span class="ai-tag ai-tag-tpl">'+ic('edit')+' 模板回复</span>');
      if (r.cached) tags.push('<span class="ai-tag ai-tag-cache">'+ic('folder')+' 缓存</span>');
      if (r.limited) tags.push('<span class="ai-tag ai-tag-limit">'+ic('warn')+' ' + esc(r.reason || '次数已用完') + '</span>');
      if (typeof r.remaining === 'number' && r.remaining >= 0 && !r.limited) tags.push(`<span class="ai-tag ai-tag-count">剩余 ${r.remaining} 次/天</span>`);
      if (tags.length) html = '<div class="ai-tags">' + tags.join('') + '</div>' + html;
      aiResult.innerHTML = html;
      aiApply.style.display = r.source !== 'template' || r.limited ? 'block' : 'block';
      aiApply.dataset.result = r.result || '';
      btn.innerHTML = '<span class="ai-send-ico">'+ic('bolt')+'</span><span>让 AI 帮你写</span>';
      btn.disabled = false;
    } catch (e) {
      aiResult.innerHTML = '<span style="color:var(--danger)">AI 暂时不可用：' + esc(e.message) + '</span>';
      btn.innerHTML = '<span class="ai-send-ico">'+ic('bolt')+'</span><span>让 AI 帮你写</span>';
      btn.disabled = false;
    }
    document.getElementById('aiSend').disabled = false;
    document.getElementById('aiSend').innerHTML = ic('send')+' 让 AI 帮我';
  };
  document.getElementById('aiApply').onclick = () => {
    const r = document.getElementById('aiApply').dataset.result;
    if (!r) return;
    const ta = document.getElementById('aContent');
    const cur = ta.value;
    if (cur) ta.value = cur + '\n\n' + r; else ta.value = r;
    toast('已应用到编辑器，记得检查修改');
    document.getElementById('aiApply').style.display = 'none';
    updatePreview();
  };
  // ========== Markdown 实时预览 ==========
  const aContent = document.getElementById('aContent');
  const mdBox = document.getElementById('mdPreviewBox');
  const mdCheck = document.getElementById('mdPreview');
  const updatePreview = () => {
    if (!mdCheck.checked) { mdBox.innerHTML = ''; return; }
    mdBox.innerHTML = md(aContent.value) || '<span class="hint">预览区（输入内容后自动渲染）</span>';
  };
  aContent.addEventListener('input', updatePreview);
  mdCheck.onchange = updatePreview;
  updatePreview();
  // ========== 标签输入（可多标签） ==========
  const tagsRow = document.createElement('div');
  tagsRow.style.marginTop = '8px';
  tagsRow.innerHTML = `<label style="font-size:12px;color:var(--text-2)">标签（逗号分隔，最多 8 个，选填）</label>
    <input id="aTags" placeholder="散文, 随笔, 思考" style="width:100%;padding:6px 10px;border:1px solid var(--border);border-radius:8px;margin-top:4px">`;
  document.getElementById('aCat').closest('.form-item').after(tagsRow);
  const aTags = document.getElementById('aTags');
  if (a) aTags.value = (a.tags || []).join(', ');

  document.getElementById('aSubmit').onclick = async (e) => {
    e.target.disabled = true;
    try {
      const tags = aTags.value.split(/[,，]/).map(t => t.trim()).filter(Boolean);
      if (a) await api('/api/articles/' + a.id, { method: 'PUT', body: { title: aTitle.value, category: aCat.value, content: aContent.value, tags } });
      else await api('/api/articles', { method: 'POST', body: { title: aTitle.value, category: aCat.value, content: aContent.value, tags } });
      toast('提交成功，等待审核');
      go('#/mine');
    } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
  };
}

/* ---------- 排行榜 ---------- */
async function viewRank() {
  const d = await api('/api/rank');
  const RANK_PAGE = 20;
  const rankTotal = Math.max(1, Math.ceil(d.rank.length / RANK_PAGE));
  const rankRow = (r, i) => `
        <tr>
          <td class="rank-no ${i < 3 ? 'r' + (i + 1) : ''}">${i + 1}</td>
          <td><a class="who" href="#/user/${r.user.id}">${avatarHtml(r.user, 'small')} ${esc(r.user.nickname)}
            ${r.user.role === 'admin' ? '<span class="role-badge">管理员</span>' : ''}</a></td>
          <td class="score">${r.score}</td><td>${r.articles}</td><td>${r.posts}</td><td>${r.likes}</td>
        </tr>`;
  const renderRankPage = () => {
    const pg = viewRank._page || 1;
    const start = (pg - 1) * RANK_PAGE;
    document.getElementById('rankBody').innerHTML =
      d.rank.slice(start, start + RANK_PAGE).map((r, i) => rankRow(r, start + i)).join('') ||
      '<tr><td colspan="6" class="empty">虚位以待</td></tr>';
    document.getElementById('rankPager').innerHTML = pagerHtml(pg, rankTotal, 'pgRank');
  };
  window.pgRank = (p) => {
    viewRank._page = Math.min(Math.max(1, p), rankTotal);
    renderRankPage();
    document.querySelector('.page-title').scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  $app.innerHTML = `
  <div class="container">
    <div class="page-title"><div><h1>排行榜</h1><div class="sub">文章×10 + 帖子×5 + 获赞×3 + 评论×2 = 积分</div></div></div>
    <div class="card">
      <table class="rank">
        <tr><th></th><th>用户</th><th>积分</th><th>文章</th><th>帖子</th><th>获赞</th></tr>
        <tbody id="rankBody"></tbody>
      </table>
      <div id="rankPager"></div>
    </div>
  </div>`;
  renderRankPage();
}

/* ---------- 比赛广场 ---------- */
async function viewContests() {
  const d = await api('/api/contests');
  $app.innerHTML = `
  <div class="container">
    <div class="page-title">
      <div><h1>比赛广场</h1><div class="sub">共 ${d.contests.length} 场比赛</div></div>
      ${state.me && state.me.role === 'admin' ? '<button class="btn primary" onclick="go(\'#/admin/contest\')">'+ic('plus')+' 创建比赛</button>' : (state.me ? '<button class="btn ghost" onclick="window.applyContestInvite()">'+ic('edit')+' 申请创建比赛</button>' : '')}
    </div>
    ${d.contests.map(c => `
    <div class="card contest" style="cursor:pointer" onclick="location.hash='#/contest/${c.id}'">
      <div style="flex:1">
        <div class="c-title">${esc(c.title)}</div>
        <div class="c-meta">
          <span class="badge ${c.status}">${contestBadge(c.status)}</span>
          <span>${ic('clock')} ${fmtRange(c.startTime, c.endTime)}</span>
          <span>${ic('users')} ${c.participantCount} 人报名</span>
          <span>${ic('clipboard')} ${c.problemCount || 0} 道题</span>
          <span>主办方：${esc(c.creator ? c.creator.nickname : '管理员')}</span>
        </div>
      </div>
      <span style="color:var(--text2);font-size:20px">›</span>
    </div>`).join('') || '<div class="card"><div class="empty">暂无比赛</div></div>'}
  </div>`;
}

async function viewContestDetail(id) {
  const d = await api('/api/contests/' + id);
  const c = d.contest;
  let mySubs = [];
  if (state.me) {
    try { mySubs = (await api(`/api/contests/${id}/my-submissions`)).submissions; } catch (e) {}
  }
  const canSubmit = c.status === 'ongoing' && c.joined;
  $app.innerHTML = `
  <div class="container" style="max-width:820px">
    <div class="card">
      <div class="doc-head">
        <h1>${esc(c.title)} <span class="badge ${c.status}">${contestBadge(c.status)}</span></h1>
        <div class="meta"><span>${ic('clock')} ${fmtRange(c.startTime, c.endTime)}</span><span>${ic('users')} ${c.participantCount} 人已报名</span>
        <span>${ic('clipboard')} ${c.problemCount} 道题</span><span>${ic('downloads')} ${c.submissionCount} 份作品</span>
        <span>主办方：${esc(c.creator ? c.creator.nickname : '')}</span></div>
      </div>
      <div class="doc-content">${md(c.description)}</div>
      <div style="margin-top:16px;text-align:center">
        ${c.status !== 'ended' ? `<button class="btn ${c.joined ? 'ghost' : 'green'}" id="joinBtn">${c.joined ? ic('check')+' 已报名（点击取消）' : ic('flame')+' 立即报名'}</button>` : ''}
      </div>
    </div>
    <div class="card">
      <h2>${ic('clipboard')} 比赛题目（${c.problemCount}）</h2>
      ${(c.problems || []).map((q, i) => {
        const mine = mySubs.find(s => s.problemId === q.id);
        return `
        <div class="review-item">
          <div class="r-head">
            <span class="r-title">第 ${i + 1} 题 · ${esc(q.title)}</span>
            ${q.wordLimit > 0 ? `<span class="badge upcoming">限 ${q.wordLimit} 字</span>` : '<span class="badge ended">不限字数</span>'}
            ${mine ? '<span class="badge approved">已提交</span>' : ''}
          </div>
          <div class="r-content" style="white-space:pre-wrap">${esc(q.content)}</div>
          ${mine ? `
          <div class="hint" style="margin-bottom:8px">我的作品：<b style="color:var(--text)">${esc(mine.title)}</b> · ${mine.wordCount} 字 · ${fmtTime(mine.updatedAt || mine.createdAt)}</div>` : ''}
          ${canSubmit ? `
          <div class="r-actions">
            <button class="btn primary sm" onclick="go('#/work/contest/${id}/${q.id}')">${mine ? ic('edit')+' 修改我的作品' : ic('submit')+' 提交本题作品'}</button>
          </div>` : (c.status === 'ongoing' && !c.joined ? '<div class="hint">报名后即可提交本题作品</div>' : '')}
        </div>`;
      }).join('') || '<div class="empty">该比赛暂无题目</div>'}
      ${c.status === 'upcoming' ? '<div class="hint" style="margin-top:10px">'+ic('clock')+' 比赛开始后即可提交作品</div>' : ''}
      ${c.status === 'ended' ? '<div class="hint" style="margin-top:10px">'+ic('flag')+' 比赛已结束，作品提交通道已关闭</div>' : ''}
    </div>
    <div class="card">
      <h2>报名名单（<span id="joinCount">${c.participantCount}</span>）</h2>
      <div id="plist">
      ${c.participantList.map(u => `
      <div class="item">${avatarHtml(u, 'small')}
        <div style="align-self:center"><a href="#/user/${u.id}">${esc(u.nickname)}</a>
        <span class="meta">@${esc(u.username)}</span></div>
      </div>`).join('') || '<div class="empty">还没有人报名</div>'}
      </div>
    </div>
  </div>`;
  const jb = document.getElementById('joinBtn');
  if (jb) jb.onclick = async () => {
    if (needLogin()) return;
    try {
      const r = await api(`/api/contests/${id}/join`, { method: 'POST' });
      toast(r.joined ? '报名成功！' : '已取消报名');
      route();
    } catch (e) { toast(e.message, 'err'); }
  };
  document.querySelectorAll('[data-view]').forEach(b => b.onclick = async () => {
    const pid = b.dataset.view;
    try {
      const r = await api(`/api/problems/${id}/practice/${pid}`);
      openPracticeModal(r.practice, p);
    } catch (e) { toast(e.message, 'err'); }
  });
}

/* ---------- 分屏写作工作台（Luogu 风格） ---------- */
async function viewWorkspace(arg) {
  if (needLogin()) return;
  hideAiFab();
  const [mode, id, qid] = (arg || '').split('/');
  let problem, mine = null, wordLimit = 0, backHash = '', submitLabel = '开始练习', submitBody, submitUrl;
  if (mode === 'problem') {
    const d = await api('/api/problems/' + id);
    problem = d.problem; mine = d.myPractice;
    backHash = '#/problem/' + id;
    if (!mine) mine = null;
    submitUrl = `/api/problems/${id}/practice`;
    submitBody = (title, content) => ({ title, content });
  } else if (mode === 'contest') {
    const d = await api('/api/contests/' + id);
    const c = d.contest;
    problem = (c.problems || []).find(q => q.id === qid);
    if (!problem) { $app.innerHTML = '<div class="card"><div class="empty">'+ic('help')+' 题目不存在</div></div>'; return; }
    wordLimit = problem.wordLimit || 0;
    backHash = '#/contest/' + id;
    submitLabel = '提交本题作品';
    try { mine = ((await api(`/api/contests/${id}/my-submissions`)).submissions || []).find(s => s.problemId === qid) || null; } catch (e) {}
    submitUrl = `/api/contests/${id}/submit`;
    submitBody = (title, content) => ({ problemId: qid, title, content });
  } else if (mode === 'checkin') {
    const d = await api('/api/checkins/today');
    problem = d.daily;
    if (!problem) { $app.innerHTML = '<div class="card"><div class="empty">'+ic('help')+' 今天暂无题目</div></div>'; return; }
    mine = d.myCheckin || null;
    backHash = '#/daily';
    submitLabel = '提交打卡';
    submitUrl = '/api/checkins';
    submitBody = (_title, content) => ({ content });
  } else { go('#/problems'); return; }
  const needTitle = mode !== 'checkin';
  $app.innerHTML = `
  <div class="ws-wrap" id="wsWrap">
    <div class="ws-left" id="wsLeft">
      <div class="ws-head">
        <a href="${backHash}" class="ws-back">← 返回</a>
        <span class="ws-title">${diffBadge(problem.difficulty)} ${esc(problem.title)}</span>
        ${wordLimit ? `<span class="badge upcoming">限 ${wordLimit} 字</span>` : ''}
      </div>
      <div class="ws-doc doc-content">${md(problem.content)}</div>
    </div>
    <div class="ws-bar" id="wsBar" title="拖动调整分屏大小"><div class="ws-grip"></div></div>
    <div class="ws-right">
      <div class="ws-tabs">
        <button class="ws-tab cur" id="wsTabWrite">${ic('edit')} 在线写作</button>
        <button class="ws-tab" id="wsTabUpload">${ic('file')} 上传文件</button>
        <span class="hint" style="margin-left:auto">字数：<b id="wsWc">0</b>${wordLimit ? ' / 上限 ' + wordLimit : ''}</span>
      </div>
      <div id="wsWritePane" style="display:flex;flex-direction:column;flex:1;min-height:0">
        <div class="ws-mode">
          <button class="mini cur" id="wsModeEdit">编辑</button>
          <button class="mini" id="wsModePrev">${ic('eye')} 预览</button>
        </div>
        ${needTitle ? `<input id="wsTitle" maxlength="80" placeholder="作品标题" value="${mine ? esc(mine.title) : (mode === 'problem' ? esc(state.me.nickname) + '的练习' : '')}">` : ''}
        <textarea id="wsContent" placeholder="${mode === 'checkin' ? '围绕今天的题目写一段打卡内容…' : '支持 Markdown（# 标题、**加粗**、> 引用…）。也可以把写好的内容直接粘贴进来（Ctrl+V）…'}">${mine ? esc(mine.content) : ''}</textarea>
        <div id="wsPreview" class="ws-preview doc-content" style="display:none"></div>
      </div>
      <div id="wsUploadPane" style="display:none;flex:1;min-height:0">
        <div class="upload-drop" id="wsDrop">
          <div class="big-ico">${ic('file')}</div>
          <p><b>点击选择或拖入文件</b></p>
          <p class="hint">支持 .txt / .md 纯文本（≤1MB），内容将导入编辑器，可预览后再提交</p>
          <input type="file" id="wsFile" accept=".txt,.md,.markdown,text/plain" style="display:none">
        </div>
      </div>
      <div class="ws-actions">
        <button class="btn ghost sm" id="wsPaste">${ic('clipboard')} 粘贴导入</button>
        <button class="btn green" id="wsSubmit">${ic('submit')} ${mine ? '保存修改' : '提交'}</button>
      </div>
    </div>
  </div>`;
  // 字数统计
  const ta = document.getElementById('wsContent'), wc = document.getElementById('wsWc');
  const updWc = () => { wc.textContent = ta.value.replace(/\s/g, '').length; };
  ta.oninput = updWc; updWc();
  // 模块 Tab：在线写作 / 上传文件
  const tabW = document.getElementById('wsTabWrite'), tabU = document.getElementById('wsTabUpload');
  const paneW = document.getElementById('wsWritePane'), paneU = document.getElementById('wsUploadPane');
  const switchTab = (up) => {
    tabW.classList.toggle('cur', !up); tabU.classList.toggle('cur', up);
    paneW.style.display = up ? 'none' : 'flex'; paneU.style.display = up ? 'block' : 'none';
  };
  tabW.onclick = () => switchTab(false);
  tabU.onclick = () => switchTab(true);
  // Markdown 编辑/预览切换
  const mE = document.getElementById('wsModeEdit'), mP = document.getElementById('wsModePrev'), prev = document.getElementById('wsPreview');
  mE.onclick = () => { mE.classList.add('cur'); mP.classList.remove('cur'); ta.style.display = ''; prev.style.display = 'none'; };
  mP.onclick = () => {
    mP.classList.add('cur'); mE.classList.remove('cur');
    prev.innerHTML = ta.value.trim() ? md(ta.value) : '<div class="empty">暂无内容，先写点东西吧</div>';
    ta.style.display = 'none'; prev.style.display = '';
  };
  // 上传文件导入
  const readFile = (file) => {
    if (!file) return;
    if (file.size > 1024 * 1024) return toast('文件过大（纯文本 ≤1MB）', 'err');
    const rd = new FileReader();
    rd.onload = () => {
      const t = document.getElementById('wsTitle');
      if (t && !t.value.trim()) t.value = file.name.replace(/\.(txt|md|markdown)$/i, '');
      ta.value = rd.result; updWc();
      switchTab(false); mE.click();
      toast(`已导入「${file.name}」，可预览后提交`);
    };
    rd.onerror = () => toast('文件读取失败', 'err');
    rd.readAsText(file, 'utf-8');
  };
  const drop = document.getElementById('wsDrop'), fin = document.getElementById('wsFile');
  drop.onclick = () => fin.click();
  fin.onchange = (e) => { readFile(e.target.files[0]); e.target.value = ''; };
  drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
  drop.ondragleave = () => drop.classList.remove('over');
  drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove('over'); readFile(e.dataTransfer.files[0]); };
  // 拖动分隔条
  const wrap = document.getElementById('wsWrap'), left = document.getElementById('wsLeft');
  let dragging = false;
  document.getElementById('wsBar').onmousedown = (e) => { dragging = true; e.preventDefault(); };
  document.onmousemove = (e) => {
    if (!dragging) return;
    const r = wrap.getBoundingClientRect();
    const pct = Math.min(78, Math.max(22, (e.clientX - r.left) / r.width * 100));
    left.style.width = pct + '%';
  };
  document.onmouseup = () => { dragging = false; };
  // 粘贴导入
  document.getElementById('wsPaste').onclick = async () => {
    try {
      const t = await navigator.clipboard.readText();
      if (t) { ta.value += (ta.value ? '\n\n' : '') + t; updWc(); toast('已从剪贴板导入'); }
    } catch (e) { toast('浏览器未授权剪贴板，请在编辑区 Ctrl+V', 'err'); }
  };
  // 提交
  document.getElementById('wsSubmit').onclick = async (e) => {
    const title = needTitle ? (document.getElementById('wsTitle').value || '').trim() : '';
    const content = ta.value;
    if (needTitle && !title) return toast('请填写标题', 'err');
    if (!content.trim()) return toast('内容不能为空', 'err');
    const n = content.replace(/\s/g, '').length;
    if (wordLimit && n > wordLimit) return toast(`超出字数上限（${n}/${wordLimit}）`, 'err');
    e.target.disabled = true;
    try {
      const r = await api(submitUrl, { method: 'POST', body: submitBody(title, content) });
      if (mode === 'checkin') toast(`打卡成功！+${r.points} 积分，连续 ${r.streak || 0} 天`);
      else toast(mode === 'problem' ? '练习已提交！' : '作品已保存提交！');
      go(backHash); route();
    } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
  };
}

/* ---------- 文件投稿 ---------- */
async function viewSubmit() {
  if (needLogin()) return;
  const d = await api('/api/files/mine');
  $app.innerHTML = `
  <div class="container" style="max-width:760px">
    <div class="page-title"><div><h1>文件投稿</h1><div class="sub">上传文档，审核通过后由管理员归档（≤20MB）</div></div></div>
    <div class="card">
      <div class="form-item"><label>选择文件</label><input type="file" id="fFile"></div>
      <div class="form-item"><label>投稿说明</label><input id="fNote" maxlength="200" placeholder="简单说明一下这份文件"></div>
      <button class="btn primary" id="fSubmit">${ic('submit')} 上传投稿</button>
    </div>
    <div class="card">
      <h2>我的投稿记录</h2>
      ${d.files.map(f => `
      <div class="item">
        <div class="big-ico sm">${ic('file')}</div>
        <div style="flex:1">
          <div class="title">${esc(f.originalName)} <span class="badge ${f.status}">${statusBadge(f.status)}</span></div>
          <div class="meta"><span>${esc(f.note || '无说明')}</span><span>${fmtSize(f.size)}</span><span>${fmtTime(f.createdAt)}</span></div>
        </div>
        <button class="btn ghost sm" onclick="window.open('/api/files/${f.id}/download')">下载</button>
      </div>`).join('') || '<div class="empty">暂无投稿记录</div>'}
    </div>
  </div>`;
  document.getElementById('fSubmit').onclick = async (e) => {
    const file = document.getElementById('fFile').files[0];
    if (!file) return toast('请选择文件', 'err');
    const form = new FormData();
    form.append('file', file);
    form.append('note', document.getElementById('fNote').value);
    e.target.disabled = true;
    try {
      await api('/api/files', { method: 'POST', form });
      toast('上传成功，等待审核');
      route();
    } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
  };
}

/* ---------- 我的文章 ---------- */
async function viewMine() {
  if (needLogin()) return;
  const tab = viewMine._t || 'a';
  const [da, dp, df] = await Promise.all([api('/api/articles/mine'), api('/api/posts/mine'), api('/api/files/mine')]);
  const mineData = { a: da.articles, p: dp.posts, f: df.files };
  const mineEmpty = {
    a: '<div class="empty">还没有写过文章，<a href="#/write">去写一篇</a>！</div>',
    p: '<div class="empty">还没有发过帖子</div>',
    f: '<div class="empty">暂无投稿</div>',
  };
  const mineItem = (x) => {
    if (tab === 'a') return `
      <div class="item">
        <div style="flex:1">
          <div class="title"><a href="#/article/${x.id}">${esc(x.title)}</a> <span class="badge ${x.status}">${statusBadge(x.status)}</span></div>
          <div class="meta"><span>${fmtTime(x.createdAt)}</span><span>${ic('eye')} ${x.views || 0}</span><span>${ic('heart')} ${x.likeCount || 0}</span></div>
        </div>
        ${x.status !== 'approved' ? `<button class="btn ghost sm" onclick="go('#/write/${x.id}')">编辑</button>` : ''}
        <button class="btn red sm" data-del-art="${x.id}">删除</button>
      </div>`;
    if (tab === 'p') return `
      <div class="item">
        <div style="flex:1">
          <div class="title"><a href="#/post/${x.id}">${esc(x.title)}</a> <span class="badge ${x.status}">${statusBadge(x.status)}</span></div>
          <div class="meta"><span>${fmtTime(x.createdAt)}</span><span>${ic('forum')} ${x.commentCount}</span></div>
        </div>
        <button class="btn red sm" data-del-post="${x.id}">删除</button>
      </div>`;
    return `
      <div class="item">
        <div class="big-ico sm">${ic('file')}</div>
        <div style="flex:1">
          <div class="title">${esc(x.originalName)} <span class="badge ${x.status}">${statusBadge(x.status)}</span></div>
          <div class="meta"><span>${esc(x.note || '')}</span><span>${fmtSize(x.size)}</span><span>${fmtTime(x.createdAt)}</span></div>
        </div>
      </div>`;
  };
  const mineTotal = Math.max(1, Math.ceil(mineData[tab].length / PAGE_SIZE));
  const renderMinePage = () => {
    const pg = viewMine._page || 1;
    document.getElementById('mineList').innerHTML =
      mineData[tab].slice((pg - 1) * PAGE_SIZE, pg * PAGE_SIZE).map(mineItem).join('') || mineEmpty[tab];
    document.getElementById('minePager').innerHTML = pagerHtml(pg, mineTotal, 'pgMine');
  };
  window.pgMine = (p) => {
    viewMine._page = Math.min(Math.max(1, p), mineTotal);
    renderMinePage();
    document.querySelector('.tabs').scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  $app.innerHTML = `
  <div class="container">
    <div class="page-title"><div><h1>我的文章</h1><div class="sub">管理你发布的文章、帖子与投稿</div></div>
    <button class="btn primary" onclick="go('#/write')">${ic('edit')} 写文章</button></div>
    <div class="tabs">
      <span class="t ${tab === 'a' ? 'active' : ''}" data-t="a">文章（${da.articles.length}）</span>
      <span class="t ${tab === 'p' ? 'active' : ''}" data-t="p">帖子（${dp.posts.length}）</span>
      <span class="t ${tab === 'f' ? 'active' : ''}" data-t="f">投稿（${df.files.length}）</span>
    </div>
    <div class="card">
      <div id="mineList"></div>
      <div id="minePager"></div>
    </div>
  </div>`;
  document.querySelectorAll('.tabs .t').forEach(t => t.onclick = () => { viewMine._t = t.dataset.t; viewMine._page = 1; route(); });
  document.querySelectorAll('[data-del-art]').forEach(b => b.onclick = async () => {
    if (!confirm('确定删除该文章？')) return;
    await api('/api/articles/' + b.dataset.delArt, { method: 'DELETE' });
    toast('已删除'); route();
  });
  document.querySelectorAll('[data-del-post]').forEach(b => b.onclick = async () => {
    if (!confirm('确定删除该帖子？')) return;
    await api('/api/posts/' + b.dataset.delPost, { method: 'DELETE' });
    toast('已删除'); route();
  });
  renderMinePage();
}

/* ---------- 偏好设置 ---------- */
async function viewSettings() {
  if (needLogin()) return;
  const me = state.me;
  const ACCENTS = [['blue', '#3498db', '经典蓝'], ['purple', '#9b59b6', '优雅紫'], ['teal', '#1abc9c', '青碧'], ['green', '#2ecc71', '清新绿'], ['orange', '#e67e22', '活力橙'], ['rose', '#e84393', '玫瑰粉'], ['indigo', '#6366f1', '靛蓝']];
  const curAcc = document.documentElement.dataset.accent || 'blue';
  const accDots = ACCENTS.map(([k, c, n]) => `<button class="acc-dot${curAcc === k ? ' on' : ''}" data-acc="${k}" style="background:${c}" title="${n}">${curAcc === k ? '✓' : ''}</button>`).join('');
  $app.innerHTML = `
  <div class="container" style="max-width:620px">
    <div class="page-title"><h1>偏好设置</h1></div>
    <div class="card">
      <h2>${ic('palette')} 界面</h2>
      <div class="set-row"><span class="set-lab">主题色</span><div class="acc-row" id="accRow">${accDots}</div></div>
      <div class="set-row"><span class="set-lab">深色模式</span><button class="dark-switch${document.documentElement.classList.contains('dark') ? ' on' : ''}" id="dkSwitch" aria-label="切换深色模式"></button></div>
    </div>
    <div class="card">
      <h2>基本资料</h2>
      <div class="form-item"><label>昵称</label><input id="sNick" maxlength="24" value="${esc(me.nickname)}"></div>
      <div class="form-item"><label>个人简介</label><textarea id="sBio" maxlength="200" style="min-height:70px">${esc(me.bio || '')}</textarea></div>
      <button class="btn primary" id="sSave">保存资料</button>
    </div>
    <div class="card">
      <h2>修改密码</h2>
      <div class="form-item"><label>原密码</label><input type="password" id="sOld"></div>
      <div class="form-item"><label>新密码（至少 8 位，包含字母和数字）</label><input type="password" id="sNew"></div>
      <button class="btn primary" id="sPwd">修改密码</button>
    </div>
    <div class="card">
      <h2>${ic('image')} 头像</h2>
      <div id="avPrev" style="margin-bottom:12px">${avatarHtml(me, 'big')}</div>
      <input type="file" id="avFile" accept="image/*" hidden>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <button class="btn ghost" id="avPick">选择图片</button>
        <button class="btn primary" id="avSave" disabled>保存头像</button>
        ${me.avatarUrl ? '<button class="btn ghost" id="avReset">恢复默认</button>' : ''}
      </div>
      <div class="hint" style="margin-top:10px">支持 JPG/PNG/WebP/GIF，自动居中裁剪为方形并压缩到 256×256</div>
    </div>
    <div class="card">
      <h2>${ic('mail')} 绑定邮箱</h2>
      ${me.email
        ? `<div class="hint">已绑定：<b>${esc(me.email.replace(/^([^@]{1,3})[^@]*(@.*)$/, '$1****$2'))}</b></div>`
        : `<div class="hint" style="margin-bottom:10px">未绑定，绑定后可找回密码</div>
      <div class="form-item"><label>邮箱</label><input id="bMail" type="email" placeholder="你的邮箱地址"></div>
      <button class="btn ghost" id="bSend" style="width:100%">发送验证码</button>
      <div class="form-item" style="margin-top:12px"><label>验证码</label><input id="bCode" inputmode="numeric" maxlength="6" placeholder="6 位数字验证码"></div>
      <button class="btn primary" id="bBind" style="width:100%">绑定</button>`}
    </div>
  </div>`;
  document.getElementById('accRow').onclick = (e) => {
    const b = e.target.closest('.acc-dot');
    if (!b || b.classList.contains('on')) return;
    const v = b.dataset.acc;
    if (v === 'blue') { delete document.documentElement.dataset.accent; localStorage.removeItem('accent'); }
    else { document.documentElement.dataset.accent = v; localStorage.setItem('accent', v); }
    document.querySelectorAll('#accRow .acc-dot').forEach(d => { const on = d === b; d.classList.toggle('on', on); d.textContent = on ? '✓' : ''; });
    toast('主题已切换');
  };
  document.getElementById('dkSwitch').onclick = (e) => {
    const nd = !document.documentElement.classList.contains('dark');
    window.applyTheme(nd);
    e.currentTarget.classList.toggle('on', nd);
    toast(nd ? '已开启深色模式' : '已切换为浅色模式');
  };
  document.getElementById('sSave').onclick = async () => {
    try {
      const d = await api('/api/me/profile', { method: 'PUT', body: { nickname: sNick.value, bio: sBio.value } });
      state.me = d.user; renderSidebar(); toast('资料已更新');
    } catch (e) { toast(e.message, 'err'); }
  };
  document.getElementById('sPwd').onclick = async () => {
    try {
      await api('/api/me/password', { method: 'PUT', body: { oldPassword: sOld.value, newPassword: sNew.value } });
      toast('密码已修改'); sOld.value = sNew.value = '';
    } catch (e) { toast(e.message, 'err'); }
  };
  let avData = '';
  const avPrev = document.getElementById('avPrev');
  const avSave = document.getElementById('avSave');
  document.getElementById('avPick').onclick = () => document.getElementById('avFile').click();
  document.getElementById('avFile').onchange = (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const rd = new FileReader();
    const img = new Image();
    rd.onload = () => { img.src = rd.result; };
    rd.onerror = () => toast('图片读取失败', 'err');
    img.onerror = () => toast('图片读取失败', 'err');
    img.onload = () => {
      try {
        const s = 256, cv = document.createElement('canvas');
        cv.width = s; cv.height = s;
        const cx = cv.getContext('2d');
        const sc = Math.max(s / img.width, s / img.height);
        const w = img.width * sc, h = img.height * sc;
        cx.drawImage(img, (s - w) / 2, (s - h) / 2, w, h);
        avData = cv.toDataURL('image/jpeg', 0.85);
        avPrev.innerHTML = `<img class="avatar avatar-img big" src="${avData}" alt="">`;
        avSave.disabled = false;
      } catch { toast('图片读取失败', 'err'); }
    };
    rd.readAsDataURL(f);
    e.target.value = '';
  };
  avSave.onclick = async () => {
    avSave.disabled = true;
    try {
      await api('/api/avatar', { method: 'POST', body: { data: avData } });
      toast('头像已更新');
      const d = await api('/api/me');
      state.me = d.user; renderSidebar(); viewSettings();
    } catch (e) { toast(e.message, 'err'); avSave.disabled = false; }
  };
  const avReset = document.getElementById('avReset');
  if (avReset) avReset.onclick = async () => {
    avReset.disabled = true;
    try {
      await api('/api/avatar', { method: 'DELETE' });
      toast('已恢复默认头像');
      const d = await api('/api/me');
      state.me = d.user; renderSidebar(); viewSettings();
    } catch (e) { toast(e.message, 'err'); avReset.disabled = false; }
  };
  const bSend = document.getElementById('bSend');
  if (bSend) {
    let bcd = 0, bTimer = null;
    bSend.onclick = async (e) => {
      e.target.disabled = true;
      try {
        await api('/api/auth/email-code', { method: 'POST', body: { email: bMail.value.trim() } });
        toast('验证码已发送，请到邮箱查收');
        clearInterval(bTimer);
        bcd = 60; bSend.textContent = bcd + ' s';
        bTimer = setInterval(() => {
          bcd--;
          if (bcd <= 0) { clearInterval(bTimer); bSend.disabled = false; bSend.textContent = '发送验证码'; }
          else bSend.textContent = bcd + ' s';
        }, 1000);
      } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
    };
    document.getElementById('bBind').onclick = async (e) => {
      e.target.disabled = true;
      try {
        await api('/api/auth/bind-email', { method: 'POST', body: { email: bMail.value.trim(), code: bCode.value.trim() } });
        clearInterval(bTimer);
        toast('绑定成功');
        const d = await api('/api/me');
        state.me = d.user;
        viewSettings();
      } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
    };
  }
}

/* ---------- 登录 / 注册 ---------- */
function viewLogin() {
  let mode = 'login';
  let regMode = 'beta';
  let cd = 0, cdTimer = null;
  const startCd = () => {
    clearInterval(cdTimer);
    cd = 60;
    const b = document.getElementById('eSend');
    if (b) { b.disabled = true; b.textContent = cd + ' s'; }
    cdTimer = setInterval(() => {
      cd--;
      const btn = document.getElementById('eSend');
      if (!btn) { clearInterval(cdTimer); return; }
      if (cd <= 0) { clearInterval(cdTimer); btn.disabled = false; btn.textContent = '发送验证码'; }
      else btn.textContent = cd + ' s';
    }, 1000);
  };
  $app.innerHTML = `
  <div class="container">
    <div class="card auth-card">
      <div class="auth-tabs">
        <div class="tab active" data-m="login">登 录</div>
        <div class="tab" data-m="reg">注 册</div>
      </div>
      <div id="authBody"></div>
    </div>
  </div>`;
  const body = document.getElementById('authBody');
  const render = () => {
    body.innerHTML = mode === 'login' ? `
      <div class="form-item"><label>用户名</label><input id="lUser" placeholder="用户名"></div>
      <div class="form-item"><label>密码</label><input type="password" id="lPass"></div>
      <button class="btn primary" id="lBtn" style="width:100%">登录</button>
      <div class="hint" style="margin-top:10px;text-align:center">连续输错 5 次密码将锁定账号 10 分钟</div>
      <div style="margin-top:12px;text-align:center"><a href="javascript:void(0)" id="fpToggle" style="font-size:13px">忘记密码？</a></div>
      <div id="fpBox" style="display:none;margin-top:14px;padding-top:14px;border-top:1px dashed var(--border)">
        <div class="hint" style="text-align:center;margin-bottom:12px">—— 通过绑定邮箱找回密码 ——</div>
        <div class="form-item"><label>邮箱</label><input id="fpMail" type="email" placeholder="账号绑定的邮箱地址"></div>
        <button class="btn ghost" id="fpSend" style="width:100%">发送验证码</button>
        <div class="form-item" style="margin-top:12px"><label>验证码</label><input id="fpCode" inputmode="numeric" maxlength="6" placeholder="6 位数字验证码"></div>
        <div class="form-item"><label>新密码</label><input type="password" id="fpPass" placeholder="设置新密码（至少6位）"></div>
        <button class="btn primary" id="fpBtn" style="width:100%">重置密码</button>
      </div>` : `
      <div class="tabs" style="justify-content:center">
        <div class="t ${regMode === 'beta' ? 'active' : ''}" data-r="beta">${ic('flask')} 内测注册</div>
        <div class="t ${regMode === 'email' ? 'active' : ''}" data-r="email">${ic('mail')} 邮箱注册</div>
      </div>
      ${regMode === 'email' ? `
      <div style="display:flex;align-items:center;justify-content:center;gap:8px;margin-bottom:4px">
        <h2 style="margin:0;font-size:18px">邮箱注册</h2>
        <span class="badge approved">邮箱</span>
      </div>
      <div class="hint" style="text-align:center;margin-bottom:14px">邮箱验证码 + 用户名密码一步注册，注册即绑定邮箱，可用于找回密码</div>
      <div class="form-item"><label>邮箱</label><input id="rMail" type="email" placeholder="你的邮箱地址"></div>
      <button class="btn ghost" id="rSend" style="width:100%">发送验证码</button>
      <div class="form-item" style="margin-top:12px"><label>验证码</label><input id="rCode" inputmode="numeric" maxlength="6" placeholder="6 位数字验证码"></div>
      <div class="form-item"><label>用户名</label><input id="rUser2" placeholder="3-24 位字母 / 数字 / 下划线"></div>
      <div class="form-item"><label>密码</label><input type="password" id="rPass2" placeholder="至少 8 位，需包含字母和数字"></div>
      <button class="btn primary" id="rBtn2" style="width:100%">${ic('mail')} 注册</button>` : `
      <div style="display:flex;align-items:center;justify-content:center;gap:8px;margin-bottom:4px">
        <h2 style="margin:0;font-size:18px">内测注册</h2>
        <span class="badge approved">内测</span>
      </div>
      <div class="hint" style="text-align:center;margin-bottom:14px">内测期间：用户名 + 密码直接注册，无需邮箱</div>
      <div class="form-item"><label>用户名</label><input id="rUser" placeholder="3-24 位字母 / 数字 / 下划线"></div>
      <div class="form-item"><label>昵称</label><input id="rNick" placeholder="展示昵称（可留空）"></div>
      <div class="form-item"><label>密码</label><input type="password" id="rPass" placeholder="至少 8 位，需包含字母和数字"></div>
      <button class="btn primary" id="rBtn" style="width:100%">注册并登录</button>`}`;
    if (mode === 'login') {
      if (cd > 0) { const b = document.getElementById('fpSend'); b.disabled = true; b.textContent = cd + ' s'; }
      document.getElementById('fpToggle').onclick = () => {
        const box = document.getElementById('fpBox');
        box.style.display = box.style.display === 'none' ? '' : 'none';
      };
      document.getElementById('lBtn').onclick = async (e) => {
        e.target.disabled = true;
        try {
          const d = await api('/api/login', { method: 'POST', body: { username: lUser.value, password: lPass.value } });
          state.me = d.user;
          state.token = d.token;
          localStorage.setItem('token', d.token);
          toast('欢迎回来，' + d.user.nickname); go('#/home'); route();
        } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
      };
      document.getElementById('fpSend').onclick = async (e) => {
        e.target.disabled = true;
        try {
          await api('/api/auth/email-code', { method: 'POST', body: { email: fpMail.value.trim() } });
          toast('验证码已发送，请到邮箱查收');
          startCd();
        } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
      };
      document.getElementById('fpBtn').onclick = async (e) => {
        e.target.disabled = true;
        try {
          await api('/api/auth/reset-password', { method: 'POST', body: { email: fpMail.value.trim(), code: fpCode.value.trim(), newPassword: fpPass.value } });
          toast('密码已重置，请用新密码登录');
          document.getElementById('fpBox').style.display = 'none';
        } catch (err) { toast(err.message, 'err'); }
        e.target.disabled = false;
      };
    }
    else {
      body.querySelectorAll('.tabs .t[data-r]').forEach(t => t.onclick = () => {
        regMode = t.dataset.r;
        body.querySelectorAll('.tabs .t[data-r]').forEach(x => x.classList.toggle('active', x === t));
        render();
      });
      const afterReg = (d) => {
        state.me = d.user;
        state.token = d.token;
        localStorage.setItem('token', d.token);
        toast('注册成功，欢迎加入文汇！'); go('#/home'); route();
      };
      if (regMode === 'email') {
        const rSend = document.getElementById('rSend');
        let rcd = 0, rTimer = null;
        rSend.onclick = async (e) => {
          e.target.disabled = true;
          try {
            await api('/api/auth/email-code', { method: 'POST', body: { email: rMail.value.trim() } });
            toast('验证码已发送，请到邮箱查收');
            clearInterval(rTimer);
            rcd = 60; rSend.textContent = rcd + ' s';
            rTimer = setInterval(() => {
              rcd--;
              if (rcd <= 0) { clearInterval(rTimer); rSend.disabled = false; rSend.textContent = '发送验证码'; }
              else rSend.textContent = rcd + ' s';
            }, 1000);
          } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
        };
        document.getElementById('rBtn2').onclick = async (e) => {
          e.target.disabled = true;
          try {
            const d = await api('/api/auth/register-email', { method: 'POST', body: { email: rMail.value.trim(), code: rCode.value.trim(), username: rUser2.value, password: rPass2.value } });
            clearInterval(rTimer);
            afterReg(d);
          } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
        };
      } else document.getElementById('rBtn').onclick = async (e) => {
        e.target.disabled = true;
        try {
          const d = await api('/api/register', { method: 'POST', body: { username: rUser.value, nickname: rNick.value, password: rPass.value } });
          afterReg(d);
        } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
      };
    }
  };
  render();
  document.querySelectorAll('.auth-tabs .tab').forEach(t => t.onclick = () => {
    mode = t.dataset.m;
    document.querySelectorAll('.auth-tabs .tab').forEach(x => x.classList.toggle('active', x === t));
    render();
  });
}

/* ---------- 后台管理 ---------- */
async function viewAdmin(sub) {
  if (!state.me || state.me.role !== 'admin') {
    $app.innerHTML = '<div class="card"><div class="empty">'+ic('shield')+' 仅管理员可访问后台</div></div>';
    return;
  }
  const [kind, st] = (sub || '').split('/');
  if (kind === 'contest') return contestCreate();
  if (kind === 'invite') return adminInviteManager();
  const map = { articles: 'articles', posts: 'posts', files: 'files', problems: 'problems' };
  if (map[kind]) return adminReview(map[kind], st);
  return adminReview('articles', st);
}

async function contestCreate() {
  if (needLogin()) return;
  const isAdmin = state.me.role === 'admin';
  let inviteCode = '';
  if (!isAdmin) {
    inviteCode = localStorage.getItem('contestInviteCode') || '';
    if (!inviteCode) {
      // 没邀请码 → 弹窗让输入
      const code = prompt('请输入管理员给你的一次性邀请码：', '');
      if (!code) return go('#/contests');
      localStorage.setItem('contestInviteCode', code.trim().toUpperCase());
      inviteCode = code.trim().toUpperCase();
    }
  }
  $app.innerHTML = `
  <div class="container" style="max-width:860px">
    <div class="page-title"><div><h1>创建比赛</h1><div class="sub">${isAdmin ? '管理员直接发布' : '使用一次性邀请码创建（比赛归你所有）'}</div></div>
      <button class="btn ghost sm" onclick="go('#/contests')">← 返回比赛广场</button>
    </div>
    <div class="card">
      ${!isAdmin ? `<div class="hint" style="margin-bottom:10px">${ic('key')} 邀请码：<code>${inviteCode}</code> <button class="btn ghost sm" id="changeInvite" style="margin-left:8px">换一个</button></div>` : ''}
      <div class="form-item"><label>比赛标题</label><input id="ctTitle" maxlength="80" placeholder="例如：第二届「文汇杯」创作赛"></div>
      <div class="form-item"><label>比赛说明（支持 Markdown）</label><textarea id="ctDesc" style="min-height:120px" placeholder="主题、规则、评分标准…"></textarea></div>
      <div class="grid-2">
        <div class="form-item"><label>开始时间</label><input type="datetime-local" id="ctStart"></div>
        <div class="form-item"><label>结束时间</label><input type="datetime-local" id="ctEnd"></div>
      </div>
    </div>
    <div class="card">
      <h2>比赛题目 <span class="hint" style="font-weight:400">（一般 3-4 题，也可更多，1-10 题）</span></h2>
      <div id="problemList"></div>
      <button class="btn ghost" id="addProblem">＋ 添加题目</button>
    </div>
    <div class="card">
      <button class="btn primary" id="ctSubmit">${ic('contests')} 发布比赛</button>
    </div>
  </div>`;
  if (document.getElementById('changeInvite')) document.getElementById('changeInvite').onclick = () => {
    const c = prompt('输入新的一次性邀请码：', '');
    if (c) { localStorage.setItem('contestInviteCode', c.trim().toUpperCase()); toast('邀请码已更新'); route(); }
  };
  const pad = n => String(n).padStart(2, '0');
  const now = new Date();
  const def = new Date(now.getTime() + 3600000);
  ctStart.value = `${def.getFullYear()}-${pad(def.getMonth() + 1)}-${pad(def.getDate())}T${pad(def.getHours())}:${pad(def.getMinutes())}`;
  const end = new Date(now.getTime() + 8 * 86400000);
  ctEnd.value = `${end.getFullYear()}-${pad(end.getMonth() + 1)}-${pad(end.getDate())}T${pad(end.getHours())}:${pad(end.getMinutes())}`;

  const problems = [{ title: '', content: '', wordLimit: '' }];
  function renderProblems() {
    document.getElementById('problemList').innerHTML = problems.map((p, i) => `
      <div class="review-item" style="margin-bottom:14px">
        <div class="r-head"><span class="r-title">第 ${i + 1} 题</span>
          ${problems.length > 1 ? `<button class="btn red sm" data-rm="${i}">${ic('x')} 删除本题</button>` : ''}</div>
        <div class="form-item"><label>题目标题</label><input maxlength="60" data-f="title" data-i="${i}" value="${esc(p.title)}" placeholder="例如：我的编程故事"></div>
        <div class="form-item"><label>题目内容 / 要求</label><textarea data-f="content" data-i="${i}" style="min-height:90px" placeholder="布置题目：写什么、要求是什么…">${esc(p.content)}</textarea></div>
        <div class="form-item"><label>字数限制</label><input type="number" min="0" step="100" data-f="wordLimit" data-i="${i}" value="${esc(p.wordLimit)}" placeholder="留空或 0 表示不限制，如 2000"></div>
      </div>`).join('');
    document.querySelectorAll('[data-f]').forEach(el => el.oninput = () => {
      problems[+el.dataset.i][el.dataset.f] = el.value;
    });
    document.querySelectorAll('[data-rm]').forEach(b => b.onclick = () => {
      problems.splice(+b.dataset.rm, 1);
      renderProblems();
    });
  }
  renderProblems();
  document.getElementById('addProblem').onclick = () => {
    if (problems.length >= 10) return toast('最多 10 道题', 'err');
    problems.push({ title: '', content: '', wordLimit: '' });
    renderProblems();
  };
  document.getElementById('ctSubmit').onclick = async (e) => {
    const valid = problems.filter(p => p.title.trim() && p.content.trim());
    if (!valid.length) return toast('至少布置一道完整的题目', 'err');
    const body = {
      title: ctTitle.value, description: ctDesc.value,
      startTime: new Date(ctStart.value).getTime(), endTime: new Date(ctEnd.value).getTime(),
      problems: valid
    };
    if (!isAdmin) body.inviteCode = (localStorage.getItem('contestInviteCode') || '').toUpperCase();
    try {
      const r = await api('/api/contests', { method: 'POST', body });
      if (!isAdmin) localStorage.removeItem('contestInviteCode');
      toast(isAdmin ? '比赛已发布' : '🎉 比赛创建成功！你现在是主办方');
      go('#/contest/' + r.contest.id);
    } catch (err) { toast(err.message, 'err'); }
  };
}

/* ---------- admin 邀请码管理 ---------- */
async function adminInviteManager() {
  $app.innerHTML = `
  <div class="container" style="max-width:860px">
    <div class="page-title"><div><h1>邀请码管理</h1><div class="sub">一次性使用，创建比赛后立即作废</div></div>
      <button class="btn ghost sm" onclick="go('#/admin/articles')">← 返回审核</button>
    </div>
    <div class="card" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
      <span style="flex:1;color:var(--text2)">生成后把码发给想创建比赛的人，他用掉后立即失效</span>
      <button class="btn primary" id="genInvite">${ic('dice')} 生成一次性邀请码</button>
    </div>
    <div id="newCodeArea"></div>
    <div class="card">
      <h2>历史邀请码</h2>
      <div id="inviteList"></div>
    </div>
  </div>`;
  const refresh = async () => {
    const d = await api('/api/admin/invite/list');
    document.getElementById('inviteList').innerHTML = (d.codes || []).map(c => {
      return `
      <div class="item" style="font-size:13px">
        <code style="font-family:monospace;font-size:15px;font-weight:700;letter-spacing:1px;color:#4f7cff">${esc(c.code)}</code>
        <span class="meta">创建者：${esc(c.createdBy)}</span>
        <span class="meta">${fmtTime(c.createdAt)}</span>
        ${c.used
          ? `<span class="badge rejected">${ic('x')} 已使用 · ${esc(c.usedBy)} · ${fmtTime(c.usedAt)}</span>`
          : `<span class="badge approved">${ic('check')} 未使用</span>`}
      </div>`;
    }).join('') || '<div class="empty">还没有生成过邀请码</div>';
  };
  refresh();
  document.getElementById('genInvite').onclick = async () => {
    try {
      const r = await api('/api/admin/invite/generate', { method: 'POST', body: { purpose: 'contest' } });
      localStorage.setItem('contestInviteCode', r.code);
      document.getElementById('newCodeArea').innerHTML = `
        <div class="card" style="border-left:4px solid #52c41a">
          <div style="font-size:12px;color:#8a93a6;margin-bottom:4px">新生成的邀请码（请立刻发给对方，使用后即失效）</div>
          <div style="font-family:monospace;font-size:22px;font-weight:700;letter-spacing:3px;color:#4f7cff;text-align:center;padding:6px 0">${r.code}</div>
          <div style="text-align:center;margin-top:8px">
            <button class="btn ghost sm" onclick="navigator.clipboard.writeText('${r.code}');toast('已复制')">${ic('clipboard')} 复制</button>
            <button class="btn ghost sm" onclick="document.getElementById('newCodeArea').innerHTML=''">关闭</button>
          </div>
        </div>`;
      toast('邀请码已生成，请发给对方');
      refresh();
    } catch (e) { toast(e.message, 'err'); }
  };
}

async function adminReview(kind, st) {
  st = ['pending', 'approved', 'rejected'].includes(st) ? st : 'pending';
  const apiPath = { articles: 'articles', posts: 'posts', files: 'files', problems: 'problems' }[kind];
  // 并行查三个状态的 count（标签上显示真实数字）
  const [dp, da, dr] = await Promise.all([
    api(`/api/admin/${apiPath}?status=pending`).catch(() => ({})),
    api(`/api/admin/${apiPath}?status=approved`).catch(() => ({})),
    api(`/api/admin/${apiPath}?status=rejected`).catch(() => ({})),
  ]);
  const counts = {
    pending: (dp[apiPath] || []).length,
    approved: (da[apiPath] || []).length,
    rejected: (dr[apiPath] || []).length,
  };
  const d = await api(`/api/admin/${apiPath}?status=${st}`);
  const title = { articles: '审核文章', posts: '审核帖子', files: '审核投稿', problems: '审核题目' }[kind];
  const labels = { pending: '待审核', approved: '已通过', rejected: '已拒绝' };
  const dataMap = { articles: d.articles, posts: d.posts, files: d.files, problems: d.problems };
  const revItem = (x) => {
    if (kind === 'problems') return `
      <div class="review-item">
        <div class="r-head">
          <span class="r-title">${esc(x.title)}</span>
          <span class="type-badge">${TYPE[x.type]}</span>
          ${diffBadge(x.difficulty)}
          <span class="badge ${x.status}">${statusBadge(x.status)}</span>
        </div>
        <div class="r-content">${md(x.content)}</div>
        <div class="r-actions">
          <span class="hint">出题人：${esc(x.proposer.nickname)}（@${esc(x.proposer.username || '')}）· ${fmtTime(x.createdAt)}</span>
          <button class="btn green sm" data-r="approve" data-id="${x.id}">${ic('check')} 通过</button>
          <button class="btn red sm" data-r="reject" data-id="${x.id}">${ic('x')} 拒绝</button>
        </div>
      </div>`;
    if (kind === 'files') return `
      <div class="review-item">
        <div class="r-head">
          <span class="big-ico sm">${ic('file')}</span>
          <span class="r-title">${esc(x.originalName)}</span>
          <span class="badge ${x.status}">${statusBadge(x.status)}</span>
        </div>
        <div class="r-content">投稿说明：${esc(x.note || '（无）')}\n文件大小：${fmtSize(x.size)}\n投稿人：${esc(x.author.nickname)}（@${esc(x.author.username)}）· ${fmtTime(x.createdAt)}</div>
        <div class="r-actions">
          <button class="btn green sm" data-r="approve" data-id="${x.id}">${ic('check')} 通过</button>
          <button class="btn red sm" data-r="reject" data-id="${x.id}">${ic('x')} 拒绝</button>
          <button class="btn ghost sm" onclick="window.open('/api/files/${x.id}/download')">${ic('downloads')} 下载查看</button>
        </div>
      </div>`;
    return `
      <div class="review-item">
        <div class="r-head">
          <span class="r-title">${esc(x.title)}</span>
          <span class="badge ${x.status}">${statusBadge(x.status)}</span>
        </div>
        <div class="r-content">${md(x.content)}</div>
        <div class="r-actions">
          <span class="hint">${kind === 'posts' ? '投稿人' : '作者'}：${esc(x.author.nickname)}（@${esc(x.author.username)}）· ${fmtTime(x.createdAt)}</span>
          <button class="btn green sm" data-r="approve" data-id="${x.id}">${ic('check')} 通过</button>
          <button class="btn red sm" data-r="reject" data-id="${x.id}">${ic('x')} 拒绝</button>
        </div>
      </div>`;
  };
  const revData = dataMap[kind];
  const revTotal = Math.max(1, Math.ceil(revData.length / PAGE_SIZE));
  const renderRevPage = () => {
    const pg = adminReview._page || 1;
    document.getElementById('revList').innerHTML =
      revData.slice((pg - 1) * PAGE_SIZE, pg * PAGE_SIZE).map(revItem).join('');
    document.getElementById('revPager').innerHTML = pagerHtml(pg, revTotal, 'pgRev');
    document.querySelectorAll('[data-r]').forEach(b => b.onclick = async () => {
      try {
        await api(`/api/admin/${apiPath}/${b.dataset.id}/review`, { method: 'POST', body: { action: b.dataset.r } });
        toast(b.dataset.r === 'approve' ? '已通过' : '已拒绝');
        route();
      } catch (e) { toast(e.message, 'err'); }
    });
  };
  window.pgRev = (p) => {
    adminReview._page = Math.min(Math.max(1, p), revTotal);
    renderRevPage();
    document.querySelector('.tabs').scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  $app.innerHTML = `
  <div class="container" style="max-width:900px">
    <div class="page-title"><div><h1>${title}</h1><div class="sub">后台管理 · ${state.me.nickname}</div></div>
    <a href="#/admin/${kind}/${st}" class="btn ghost">刷新</a></div>
    <div class="tabs">
      ${['pending', 'approved', 'rejected'].map(s => `
      <span class="t ${st === s ? 'active' : ''}" data-s="${s}">${labels[s]}（${counts[s]}）</span>`).join('')}
    </div>
    <div id="revList"></div>
    <div id="revPager"></div>
    ${revData.length ? '' : '<div class="card"><div class="empty">这里空空如也 🎉</div></div>'}
  </div>`;

  document.querySelectorAll('.tabs .t').forEach(t => t.onclick = () => {
    adminReview._page = 1;
    location.hash = `#/admin/${kind}/${t.dataset.s}`;
  });
  renderRevPage();
}

/* ---------- 私信 ---------- */
async function viewMessages() {
  if (needLogin()) return;
  const d = await api('/api/messages/conversations');
  $app.innerHTML = `
  <div class="container" style="max-width:720px">
    <div class="page-title"><div><h1>私信</h1><div class="sub">只属于你和他的对话</div></div></div>
    <div class="card">
      ${d.conversations.map(c => `
      <div class="item" style="cursor:pointer" onclick="location.hash='#/chat/${c.partner.id}'">
        ${avatarHtml(c.partner, 'xs')}
        <div style="flex:1">
          <div class="title">${esc(c.partner.nickname)}${c.unread ? `<span class="msg-badge" style="display:inline-block;margin-left:6px">${c.unread}</span>` : ''}</div>
          <div class="meta"><span>${c.lastFromMe ? '我：' : ''}${esc(excerpt(c.lastContent, 40))}</span><span>${fmtTime(c.lastTime)}</span></div>
        </div>
        <span style="color:var(--text2)">›</span>
      </div>`).join('') || `
      <div class="empty">还没有私信<br><span class="hint">去别人的<a href="#/rank">个人主页</a>点「发私信」开始聊天</span></div>`}
    </div>
  </div>`;
}

async function viewChat(id) {
  if (needLogin()) return;
  const d = await api('/api/messages/with/' + id);
  const p = d.partner;
  $app.innerHTML = `
  <div class="container" style="max-width:680px">
    <div class="page-title">
      <div style="display:flex;align-items:center;gap:10px">
        <a href="#/messages" class="btn ghost sm">← 返回</a>
        <h1 style="font-size:18px">与 ${esc(p.nickname)} 的对话</h1>
        <span class="hint">当前身份：${esc(state.me.nickname)}</span>
      </div>
      <a href="#/user/${p.id}" class="btn ghost sm">TA 的主页</a>
    </div>
    <div class="card">
      <div id="chatBox" style="max-height:420px;overflow-y:auto;padding:4px 2px">
        ${d.messages.map(m => `
        <div class="bubble-row ${m.fromId === state.me.id ? 'me' : ''}">
          <div class="bubble">${esc(m.content).replace(/\n/g, '<br>')}<div class="t">${fmtTime(m.createdAt)}</div></div>
        </div>`).join('') || '<div class="empty">还没有消息，打个招呼吧 👋</div>'}
      </div>
      <div style="display:flex;gap:10px;margin-top:14px">
        <input id="msgInput" style="flex:1;padding:9px 12px;border:1px solid var(--border);border-radius:8px;font-size:14px;outline:none" placeholder="输入消息，回车发送…" maxlength="2000">
        <button class="btn primary" id="msgSend">发送</button>
      </div>
    </div>
  </div>`;
  const box = document.getElementById('chatBox');
  box.scrollTop = box.scrollHeight;
  const send = async () => {
    const input = document.getElementById('msgInput');
    if (!input || !input.value.trim()) return;
    try {
      await api('/api/messages', { method: 'POST', body: { toId: id, content: input.value } });
      // 重新同步登录态：多标签页切换账号时防止身份错乱
      try { const d2 = await api('/api/me'); state.me = d2.user; renderSidebar(); } catch (e) {}
      route();
    } catch (e) { toast(e.message, 'err'); }
  };
  document.getElementById('msgSend').onclick = send;
  document.getElementById('msgInput').onkeydown = (e) => { if (e.key === 'Enter') send(); };
}

/* ---------- 题库 ---------- */
const DIFF = { 1: ['入门', '#fe4c61'], 2: ['简单', '#f39c11'], 3: ['普通', '#ffc116'], 4: ['较难', '#52c41a'], 5: ['困难', '#3498db'], 6: ['挑战', '#9d3dcf'] };
const TYPE = { theme: '主题写作', skill: '专项训练' };
const diffBadge = (d) => {
  const k = parseInt(d, 10) || 1;
  const [name, color] = DIFF[k] || DIFF[1];
  return `<span class="diff-badge" style="color:#fff;background:${color}">${name}</span>`;
};
const tagChips = (tags) => (tags || []).map(t => `<span class="tag-chip">${esc(t)}</span>`).join('');

/* 通用分页条（共 N 页 « ‹ 1 2 3 › »）*/
const PAGE_SIZE = 10;
function pagerHtml(page, total, fn) {
  if (total <= 1) return '';
  let start = Math.max(1, Math.min(page - 4, total - 9));
  const end = Math.min(total, start + 9);
  let btns = '';
  for (let i = start; i <= end; i++) btns += `<button class="pg ${i === page ? 'cur' : ''}" onclick="${fn}(${i})">${i}</button>`;
  return `<div class="pager"><span class="pg-info">共 ${total} 页</span>
    <button class="pg" onclick="${fn}(1)" ${page <= 1 ? 'disabled' : ''}>«</button>
    <button class="pg" onclick="${fn}(${page - 1})" ${page <= 1 ? 'disabled' : ''}>‹</button>
    ${btns}
    <button class="pg" onclick="${fn}(${page + 1})" ${page > total ? 'disabled' : ''}>›</button>
    <button class="pg" onclick="${fn}(${total})" ${page >= total ? 'disabled' : ''}>»</button>
  </div>`;
}
async function viewProblems() {
  const type = viewProblems._t || '';
  const diff = viewProblems._d || '';
  const q = viewProblems._q || '';
  const params = new URLSearchParams();
  if (type) params.set('type', type);
  if (diff) params.set('difficulty', diff);
  if (q) params.set('q', q);
  const d = await api('/api/problems' + (params.toString() ? '?' + params : ''));
  const isAdmin = state.me && state.me.role === 'admin';
  $app.innerHTML = `
  <div class="container">
    <div class="page-title">
      <div><h1>题库</h1><div class="sub">在练习中进步 —— 共 ${d.problems.length} 道题${q ? `（搜索：“${esc(q)}”）` : ''}</div></div>
      ${state.me ? `<button class="btn primary" id="addProbBtn">＋ ${isAdmin ? '收录题目' : '我要出题'}</button>`
                 : '<a class="btn ghost" href="#/login">登录后出题</a>'}
    </div>
    <div class="filter-row">
      <select id="pDiff" class="mini-select">
        <option value="">全部难度</option>
        ${[1, 2, 3, 4, 5, 6].map(i => `<option value="${i}" ${String(i) === diff ? 'selected' : ''}>${DIFF[i][0]}</option>`).join('')}
      </select>
      <div class="search-box" style="flex:1;margin:0">
        <input id="pQ" value="${esc(q)}" placeholder="搜索题目标题 / 内容 / 标签…" maxlength="60">
        <button class="btn primary" data-searchbtn="pQ">${ic('search')} 搜索</button>
      </div>
    </div>
    <div class="tabs">
      <span class="t ${type === '' ? 'active' : ''}" data-t="">全部</span>
      <span class="t ${type === 'theme' ? 'active' : ''}" data-t="theme">主题写作</span>
      <span class="t ${type === 'skill' ? 'active' : ''}" data-t="skill">专项训练</span>
    </div>
    <div id="probFormWrap" style="display:none">
      <div class="card">
        <h2>${isAdmin ? '收录新题目（直接生效）' : '投稿新题目（需管理员审核通过后收录）'}</h2>
        <div class="grid-2">
          <div class="form-item"><label>类型</label>
            <select id="npType"><option value="theme">主题写作</option><option value="skill">专项训练</option></select></div>
          <div class="form-item"><label>难度</label>
            <select id="npDiff">${[1, 2, 3, 4, 5, 6].map(i => `<option value="${i}">${DIFF[i][0]}</option>`).join('')}</select></div>
        </div>
        <div class="form-item"><label>题目标题</label><input id="npTitle" maxlength="80" placeholder="例如：用排比写一段风景"></div>
        <div class="form-item"><label>题目内容 / 要求（支持 Markdown）</label><textarea id="npContent" style="min-height:110px" placeholder="具体要求、字数建议、注意事项…"></textarea></div>
        <div class="form-item"><label>标签（用逗号分隔，最多 5 个）</label><input id="npTags" placeholder="排比,写景"></div>
        <button class="btn green" id="npSave">${isAdmin ? ic('check')+' 收录' : ic('submit')+' 提交出题'}</button>
      </div>
    </div>
    <div class="card">
      <div id="probList"></div>
      <div id="probPager"></div>
    </div>
  </div>`;
  document.querySelectorAll('.tabs .t').forEach(t => t.onclick = () => { viewProblems._t = t.dataset.t; viewProblems._page = 1; route(); });
  document.getElementById('pDiff').onchange = (e) => { viewProblems._d = e.target.value; viewProblems._page = 1; route(); };
  bindSearch('pQ', (v) => { viewProblems._q = v; viewProblems._page = 1; route(); });
  // 前端分页（不重新请求）
  const totalPages = Math.max(1, Math.ceil(d.problems.length / PAGE_SIZE));
  const probItem = (p) => `
      <div class="item problem-item">
        <div style="flex:1;cursor:pointer" onclick="location.hash='#/problem/${p.id}'">
          <div class="title">${diffBadge(p.difficulty)} <a href="#/problem/${p.id}" onclick="event.stopPropagation()">${esc(p.title)}</a>
            <span class="type-badge">${TYPE[p.type]}</span></div>
          <div class="meta"><span>${excerpt(p.content, 60)}</span></div>
          <div class="meta"><span>${ic('users')} ${p.doerCount} 人练过</span><span>${ic('edit')} ${p.practiceCount} 篇练习</span>${tagChips(p.tags)}</div>
        </div>
      </div>`;
  const renderProbPage = () => {
    const pg = viewProblems._page || 1;
    document.getElementById('probList').innerHTML =
      d.problems.slice((pg - 1) * PAGE_SIZE, pg * PAGE_SIZE).map(probItem).join('') ||
      `<div class="empty">${q || diff || type ? '没有匹配条件的题目' : '该分类下暂无题目'}</div>`;
    document.getElementById('probPager').innerHTML = pagerHtml(pg, totalPages, 'pgProb');
  };
  window.pgProb = (p) => {
    viewProblems._page = Math.min(Math.max(1, p), totalPages);
    renderProbPage();
    document.querySelector('.tabs').scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  renderProbPage();
  if (state.me) {
    document.getElementById('addProbBtn').onclick = () => {
      const w = document.getElementById('probFormWrap');
      w.style.display = w.style.display === 'none' ? 'block' : 'none';
    };
    document.getElementById('npSave').onclick = async () => {
      try {
        await api('/api/problems', {
          method: 'POST',
          body: {
            type: npType.value, difficulty: npDiff.value, title: npTitle.value,
            content: npContent.value, tags: npTags.value.split(/[,，]/).map(s => s.trim()).filter(Boolean)
          }
        });
        toast(isAdmin ? '题目已收录' : '出题已提交，等待管理员审核');
        go('#/problems'); route();
      } catch (e) { toast(e.message, 'err'); }
    };
  }
}

async function viewProblemDetail(id) {
  const d = await api('/api/problems/' + id);
  const p = d.problem;
  const mine = d.myPractice;
  $app.innerHTML = `
  <div class="container" style="max-width:820px">
    <div class="card">
      <div class="doc-head">
        <h1>${diffBadge(p.difficulty)} ${esc(p.title)}</h1>
        <div class="meta">
          <span class="type-badge">${TYPE[p.type]}</span>
          ${p.status !== 'approved' ? `<span class="badge ${p.status}">${statusBadge(p.status)}</span>` : ''}
          ${tagChips(p.tags)}
          <span>${ic('users')} ${p.doerCount} 人练过</span><span>${ic('edit')} ${p.practiceCount} 篇练习</span>
          ${mine ? '<span class="badge approved">我已完成</span>' : ''}
        </div>
      </div>
      <div class="doc-content">${md(p.content)}</div>
    </div>
    ${state.me ? `
    <div class="card" style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
      <div style="flex:1;min-width:220px">
        <h2 style="margin:0 0 4px">${ic('edit')} ${mine ? '继续练习' : '开始练习'}</h2>
        <div class="hint">${mine ? `已有作品：${esc(mine.title)} · ${mine.wordCount} 字` : '进入分屏工作台 —— 左边看题，右边写作'}</div>
      </div>
      <button class="btn green" id="goWorkspace">${mine ? ic('edit')+' 修改我的练习' : ic('edit')+' 开始练习'}</button>
    </div>` : `<div class="card"><div class="empty"><a href="#/login">登录</a> 后开始练习</div></div>`}
    <div class="card">
      <h2>练习作品（${p.practiceCount}）</h2>
      ${d.practices.map(x => `
      <div class="item">
        ${avatarHtml(x.author, 'xs')}
        <div style="flex:1">
          <div class="title">${esc(x.title)}${mine && x.id === mine.id ? '<span class="badge approved" style="margin-left:6px">我的</span>' : ''}</div>
          <div class="meta"><span>${esc(x.author.nickname)}</span><span>${x.wordCount} 字</span><span>${fmtTime(x.createdAt)}</span></div>
        </div>
        <button class="btn ghost sm" data-view="${x.id}">查看</button>
      </div>`).join('') || '<div class="empty">还没有人交练习，做第一个吧！</div>'}
    </div>
  </div>`;
  const gw = document.getElementById('goWorkspace');
  if (gw) gw.onclick = () => go('#/work/problem/' + id);
  document.querySelectorAll('[data-view]').forEach(b => b.onclick = async () => {
    const pid = b.dataset.view;
    try {
      const r = await api(`/api/problems/${id}/practice/${pid}`);
      openPracticeModal(r.practice, p);
    } catch (e) { toast(e.message, 'err'); }
  });
}

function openPracticeModal(pr, problem) {
  const mask = document.createElement('div');
  mask.style.cssText = 'position:fixed;inset:0;background:rgba(20,40,60,.5);z-index:50;display:flex;align-items:center;justify-content:center;padding:20px';
  mask.innerHTML = `
    <div class="card" style="max-width:640px;width:100%;max-height:82vh;overflow-y:auto;margin:0">
      <div class="doc-head" style="margin-top:4px">
        <h1 style="font-size:17px">${esc(pr.title)}</h1>
        <div class="meta"><span>${esc(pr.author.nickname)}</span><span>${pr.wordCount} 字</span><span>${fmtTime(pr.createdAt)}</span></div>
      </div>
      <div class="doc-content">${md(pr.content)}</div>
      <div style="text-align:right"><button class="btn ghost sm" id="pmClose">关闭</button></div>
    </div>`;
  document.body.appendChild(mask);
  mask.onclick = (e) => { if (e.target === mask) mask.remove(); };
  mask.querySelector('#pmClose').onclick = () => mask.remove();
}

/* ---------- 写作模板库页面 ---------- */
async function viewTemplates() {
  hideAiFab();
  showAiFab();
  const d = await api('/api/templates').catch(() => ({ templates: [] }));
  $app.innerHTML = `
  <div class="container">
    <div class="page-title">
      <div><h1>${ic('templates')} 写作模板库</h1><div class="sub">8 套精选模板，帮你快速搭建文章结构</div></div>
      <button class="btn primary" onclick="go('#/write')">${ic('edit')} 去写文章</button>
    </div>
    <div class="tpl-grid">
      ${d.templates.map(t => `
      <div class="tpl-card" data-tpl="${t.id}">
        <div class="t-title">${esc(t.title)}</div>
        <div class="t-desc">${esc(t.description)}</div>
        <span class="t-cat">${esc(t.category)}</span>
      </div>`).join('') || '<div class="empty" style="grid-column:span 2">模板库正在加载…</div>'}
    </div>
    <div id="tplDetail2" style="margin-top:16px"></div>
  </div>`;
  document.querySelectorAll('.tpl-card').forEach(c => c.onclick = async () => {
    const t = await api('/api/templates/' + c.dataset.tpl);
    document.getElementById('tplDetail2').innerHTML = `
      <div class="card">
        <h2>${ic('file')} ${esc(t.template.title)}</h2>
        <div class="hint" style="margin-bottom:10px">${esc(t.template.description)}</div>
        <div class="tpl-preview">${esc(t.template.content)}</div>
        <button class="btn primary" onclick="go('#/write')">${ic('check')} 用这个模板去写文章</button>
        <button class="btn ghost sm" id="closeTpl2" style="margin-left:8px">关闭</button>
      </div>`;
    document.getElementById('closeTpl2').onclick = () => { document.getElementById('tplDetail2').innerHTML = ''; };
  });
}

/* ---------- 每日打卡页 ---------- */
async function viewDaily() {
  hideAiFab();
  showAiFab();
  if (needLogin()) return;
  const [d, mine] = await Promise.all([
    api('/api/checkins/today'),
    api('/api/checkins/mine').catch(() => ({ checkins: [], streak: 0, total: 0 }))
  ]);
  const DIFF = { 1: ['入门', '#fe4c61'], 2: ['简单', '#f39c11'], 3: ['普通', '#ffc116'], 4: ['较难', '#52c41a'], 5: ['困难', '#3498db'], 6: ['挑战', '#9d3dcf'] };
  $app.innerHTML = `
  <div class="container" style="max-width:820px">
    <div class="page-title"><div><h1>${ic('flame')} 每日打卡</h1><div class="sub">每天一题，坚持写作 · 连续 ${mine.streak} 天</div></div></div>

    <div class="checkin-card">
      <h2>${ic('clipboard')} 今日题目</h2>
      ${d.daily ? `
      <div class="cc-row" style="flex-direction:column;align-items:flex-start;gap:10px">
        <div style="display:flex;gap:8px;align-items:center">
          <span class="diff-badge" style="background:${DIFF[parseInt(d.daily.difficulty,10)||1][1]}">${DIFF[parseInt(d.daily.difficulty,10)||1][0]}</span>
          <b style="font-size:16px">${esc(d.daily.title)}</b>
        </div>
        <div style="font-size:13px;line-height:1.7;white-space:pre-wrap">${esc(d.daily.content)}</div>
        <div class="streak-badge" style="align-self:flex-end">
          <div class="n">${mine.streak}</div>
          <div class="l">连续天数</div>
        </div>
      </div>` : '<div class="cc-problem">今天的题目正在准备中…</div>'}
    </div>

    <div class="card" style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
      <div style="flex:1;min-width:220px">
        <h2 style="margin:0 0 4px">${ic('edit')} ${d.myCheckin ? '今日已打卡' : '开始今日打卡'}</h2>
        <div class="hint">${d.myCheckin ? `已打卡：+${d.myCheckin.points} 积分，明天再来吧！` : '进入分屏工作台 —— 左边题目，右边写作，支持 Markdown / 粘贴 / 上传文件'}</div>
      </div>
      ${d.myCheckin ? '<span class="badge approved">'+ic('check')+' 今日已打卡</span>' : ''}
      <button class="btn primary" id="goCheckin" ${!d.myCheckin ? '' : 'disabled'}>${ic('send')} 进入工作台</button>
    </div>

    <div class="card">
      <h2>${ic('daily')} 我的打卡记录（共 ${mine.total} 次）</h2>
      ${mine.checkins.length ? mine.checkins.map(c => `
        <div class="item">
          <div style="flex:1">
            <div class="title">${ic('clipboard')} ${esc(c.problem ? c.problem.title : '题目')}</div>
            <div class="meta"><span>${fmtTime(c.createdAt)}</span><span class="hint">+${c.points} 积分</span></div>
            <div class="meta"><span style="font-size:12.5px;color:var(--text2)">${esc(c.content).slice(0, 80)}${c.content.length > 80 ? '…' : ''}</span></div>
          </div>
        </div>
      `).join('') : '<div class="empty">还没有打卡记录，从今天开始吧！</div>'}
    </div>
  </div>`;
  const gc = document.getElementById('goCheckin');
  if (gc) gc.onclick = () => go('#/work/checkin/today');
}

/* ---------- 个人作品集主页 ---------- */
async function viewProfile(id) {
  hideAiFab();
  showAiFab();
  const [d, rk] = await Promise.all([
    api('/api/users/' + id),
    api('/api/rank').catch(() => null)
  ]);
  const u = d.user;
  const isMe = state.me && state.me.id === u.id;
  const tab = viewProfile._t || 'home';
  const rankPos = rk && rk.rank ? rk.rank.findIndex(r => r.user.id === id) + 1 : 0;

  // 勋章定义
  const badges = u.badges || [];
  const allBadges = [
    { name: '热心点评员', reason: '点评 3 篇以上文章', icon: ic('star') },
    { name: '勤耕不辍', reason: '连续打卡 3 天', icon: ic('daily') },
    { name: '一周达人', reason: '连续打卡 7 天', icon: ic('flame') },
    { name: '月度冠军', reason: '连续打卡 30 天', icon: ic('contests') }
  ];
  const earned = new Set(badges.map(b => b.name));

  // 活跃热力图（近 28 周，列对齐周一）
  const actMap = {};
  (d.activity || []).forEach(a => { actMap[a.d] = a.n; });
  const lvOf = n => (n <= 0 ? 0 : n === 1 ? 1 : n <= 3 ? 2 : n <= 6 ? 3 : 4);
  const t0 = new Date(); t0.setHours(0, 0, 0, 0);
  const heatStart = new Date(t0);
  heatStart.setDate(heatStart.getDate() - 27 * 7 - ((t0.getDay() + 6) % 7));
  let cells = '', months = '', lastM = -1;
  for (let w = 0; w < 28; w++) {
    for (let dd = 0; dd < 7; dd++) {
      const day = new Date(heatStart);
      day.setDate(heatStart.getDate() + w * 7 + dd);
      if (day > t0) { cells += '<i></i>'; continue; }
      const k = day.getFullYear() + '-' + String(day.getMonth() + 1).padStart(2, '0') + '-' + String(day.getDate()).padStart(2, '0');
      const n = actMap[k] || 0;
      cells += `<i class="h${lvOf(n)}" title="${k} · ${n} 次动态"></i>`;
    }
    const m = new Date(heatStart);
    m.setDate(heatStart.getDate() + w * 7);
    if (m.getMonth() !== lastM) { lastM = m.getMonth(); months += `<span style="left:${w * 14}px">${m.getMonth() + 1}月</span>`; }
  }

  let list = '';
  if (tab === 'home') {
    const feed = [
      ...d.articles.map(a => ({ t: a.createdAt, kind: '文章', icon: ic('book'), url: '#/article/' + a.id, title: a.title })),
      ...d.posts.map(p => ({ t: p.createdAt, kind: '帖子', icon: ic('forum'), url: '#/post/' + p.id, title: p.title }))
    ].sort((a, b) => b.t - a.t).slice(0, 10);
    list = `
    <div class="card">
      <div class="lp-card-h">${ic('flame')} 活跃热力图<span class="lp-hint">近半年 · 发文/发帖/打卡/练习</span></div>
      <div class="lp-heat">
        <div class="heat-week"><span style="grid-row:1">一</span><span style="grid-row:3">三</span><span style="grid-row:5">五</span><span style="grid-row:7">日</span></div>
        <div class="heat-right">
          <div class="heat-months">${months}</div>
          <div class="heat-grid">${cells}</div>
        </div>
      </div>
      <div class="heat-legend">少<i class="h0"></i><i class="h1"></i><i class="h2"></i><i class="h3"></i><i class="h4"></i>多</div>
    </div>
    <div class="card">
      <div class="lp-card-h">${ic('articles')} 近期动态</div>
      ${feed.length ? feed.map(f => `
        <div class="item"><div style="flex:1">
          <div class="title">${f.icon} <a href="${f.url}">${esc(f.title)}</a></div>
          <div class="meta"><span>${f.kind}</span><span>${fmtTime(f.t)}</span></div>
        </div></div>`).join('') : '<div class="empty">还没有公开动态</div>'}
    </div>`;
  } else if (tab === 'a') {
    list = d.articles && d.articles.length ? d.articles.map(a => `
      <div class="item"><div style="flex:1">
        <div class="title"><a href="#/article/${a.id}">${esc(a.title)}</a></div>
        <div class="meta"><span>${fmtTime(a.createdAt)}</span><span>${ic('eye')} ${a.views || 0}</span><span>${ic('heart')} ${a.likeCount || 0}</span></div>
      </div></div>`).join('') : '<div class="empty">暂无公开文章</div>';
  } else if (tab === 'p') {
    list = d.posts && d.posts.length ? d.posts.map(p => `
      <div class="item"><div style="flex:1">
        <div class="title"><a href="#/post/${p.id}">${esc(p.title)}</a></div>
        <div class="meta"><span>${fmtTime(p.createdAt)}</span><span>${ic('forum')} ${p.commentCount || 0}</span></div>
      </div></div>`).join('') : '<div class="empty">暂无公开帖子</div>';
  } else if (tab === 'b') {
    list = `
      <div class="badge-list" style="margin-top:8px">
        ${allBadges.map(b => {
          const got = earned.has(b.name);
          const earnedDate = badges.find(x => x.name === b.name);
          return `<div class="badge-item ${got ? '' : 'bi-gray'}">
            <div class="bi-icon">${b.icon}</div>
            <div class="bi-name">${esc(b.name)}</div>
            <div class="hint" style="margin-top:4px;font-size:10px;text-align:center">${esc(b.reason)}</div>
            ${got ? `<div class="hint" style="margin-top:2px;font-size:9px">${fmtTime(earnedDate.earnedAt).slice(0, 10)}</div>` : ''}
          </div>`;
        }).join('')}
      </div>
      <div class="hint" style="margin-top:10px">已获得 ${badges.length} / ${allBadges.length} 个勋章</div>`;
  } else if (tab === 'c') {
    list = d.contests && d.contests.length ? d.contests.map(c => `
      <div class="item"><div style="flex:1">
        <div class="title"><a href="#/contest/${c.id}">${esc(c.title)}</a></div>
        <div class="meta"><span>${fmtRange(c.startTime, c.endTime)}</span><span class="badge ${c.status || 'ongoing'}">${contestBadge(c.status || 'ongoing')}</span></div>
      </div></div>`).join('') : '<div class="empty">还没有参加过比赛</div>';
  } else if (tab === 'f') {
    list = d.following && d.following.length ? d.following.map(u => `
      <div class="item">${avatarHtml(u, 'xs')}<div style="flex:1">
        <div class="title"><a href="#/user/${u.id}">${esc(u.nickname)}</a></div>
        <div class="meta"><span>@${esc(u.username)}</span></div>
      </div></div>`).join('') : '<div class="empty">还没有关注任何人</div>';
  } else if (tab === 'w') {
    list = d.followers && d.followers.length ? d.followers.map(u => `
      <div class="item">${avatarHtml(u, 'xs')}<div style="flex:1">
        <div class="title"><a href="#/user/${u.id}">${esc(u.nickname)}</a></div>
        <div class="meta"><span>@${esc(u.username)}</span></div>
      </div></div>`).join('') : '<div class="empty">还没有粉丝</div>';
  }

  const sc = d.stats;
  const comp = [
    [ic('book')+' 文章 ×10', sc.articles * 10],
    [ic('forum')+' 帖子 ×5', sc.posts * 5],
    [ic('heart')+' 获赞 ×3', sc.likes * 3],
    [ic('forum')+' 评论 ×2', (sc.comments || 0) * 2],
    [ic('edit')+' 练习 ×2', (sc.practices || 0) * 2],
    [ic('clipboard')+' 打卡 ×2', (sc.checkins || 0) * 2]
  ];
  $app.innerHTML = `
  <div class="container lp-page">
    <div class="lp-banner">
      <div class="lp-bokeh"><i></i><i></i><i></i><i></i><i></i></div>
      <div class="lp-in">
        <div class="lp-id">
          ${avatarHtml(u, 'lp-ava')}
          <div class="lp-idt">
            <h1>${esc(u.nickname)} ${u.role === 'admin' ? '<span class="role-badge">管理员</span>' : ''}</h1>
            <div class="lp-bio">${esc(u.bio || '这个人很懒，什么都没有留下')}</div>
          </div>
        </div>
        <div class="lp-acts">
          ${isMe
            ? '<a class="btn ghost" href="#/settings">'+ic('settings')+' 个人设置</a>'
            : (state.me ? `
          <button class="btn ${d.isFollowing ? 'ghost' : 'primary'}" id="followBtn">${d.isFollowing ? ic('check')+' 已关注' : ic('plus')+' 关注'}</button>
          <button class="btn ghost" id="dmBtn">${ic('messages')} 发私信</button>` : '')}
        </div>
      </div>
    </div>
    <div class="lp-tabs-wrap">
      <div class="lp-tabs">
        <span class="lt ${tab === 'home' ? 'active' : ''}" data-t="home">主页</span>
        <span class="lt ${tab === 'a' ? 'active' : ''}" data-t="a">文章</span>
        <span class="lt ${tab === 'p' ? 'active' : ''}" data-t="p">帖子</span>
        <span class="lt ${tab === 'c' ? 'active' : ''}" data-t="c">比赛</span>
        <span class="lt ${tab === 'b' ? 'active' : ''}" data-t="b">勋章</span>
        <span class="lt ${tab === 'f' ? 'active' : ''}" data-t="f">关注</span>
        <span class="lt ${tab === 'w' ? 'active' : ''}" data-t="w">粉丝</span>
      </div>
      <div class="lp-statsum">
        <span class="ls"><b>${sc.followingCount}</b>关注</span>
        <span class="ls"><b>${sc.followerCount}</b>粉丝</span>
        <span class="ls"><b>${sc.articles}</b>文章</span>
        <span class="ls"><b>${sc.likes}</b>获赞</span>
        <span class="ls"><b>${sc.score || 0}</b>积分</span>
        <span class="ls"><b>${rankPos ? '#' + rankPos : '—'}</b>排名</span>
      </div>
    </div>
    <div class="lp-body">
      <div class="lp-main">${list}</div>
      <div class="lp-side">
        <div class="card">
          <div class="lp-card-h">${ic('user')} 用户信息</div>
          <div class="lp-kv"><span>用户编号</span><b>${esc(u.id)}</b></div>
          <div class="lp-kv"><span>用户类型</span><b>${u.role === 'admin' ? '管理员' : '普通用户'}</b></div>
          <div class="lp-kv"><span>用户名</span><b>@${esc(u.username)}</b></div>
          <div class="lp-kv"><span>注册时间</span><b>${fmtTime(u.createdAt).slice(0, 10)}</b></div>
        </div>
        <div class="card">
          <div class="lp-card-h">${ic('bolt')} 积分构成<span class="lp-hint">与排行榜同源</span></div>
          ${comp.map(([l, v]) => `<div class="lp-kv"><span>${l}</span><b>${v}</b></div>`).join('')}
          <div class="lp-kv lp-total"><span>总分</span><b>${sc.score || 0}</b></div>
        </div>
      </div>
    </div>
  </div>`;
  document.querySelectorAll('.lp-tabs .lt').forEach(t => t.onclick = () => { viewProfile._t = t.dataset.t; route(); });
  const fb = document.getElementById('followBtn');
  if (fb) fb.onclick = async () => {
    if (needLogin()) return;
    try {
      const r = await api(`/api/users/${id}/follow`, { method: 'POST' });
      toast(r.followed ? '已关注 ' + u.nickname : '已取消关注');
      route();
    } catch (e) { toast(e.message, 'err'); }
  };
  const dm = document.getElementById('dmBtn');
  if (dm) dm.onclick = () => { go('#/chat/' + u.id); };
}

/* ---------- 启动 ---------- */
(async function init() {
  try {
    const d = await api('/api/me');
    state.me = d.user;
  } catch (e) { state.me = null; }
  window.addEventListener('hashchange', route);
  window.go = go;
  renderSidebar();
  route();
  setInterval(refreshUnread, 30000);
  // 移动端抽屉侧边栏：汉堡开关，点导航/遮罩/路由变化自动收起
  document.getElementById('menuBtn').addEventListener('click', () => document.body.classList.toggle('nav-open'));
  document.getElementById('navMask').addEventListener('click', () => document.body.classList.remove('nav-open'));
  document.getElementById('sidebar').addEventListener('click', e => {
    if (e.target.closest('a')) document.body.classList.remove('nav-open');
  });
})();
