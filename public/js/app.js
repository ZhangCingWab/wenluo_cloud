/* ============ 文汇 · 前端 SPA ============ */
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

/* 轻量 Markdown 渲染 */
function md(src) {
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
       .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
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
    <h3>🤖 AI 写作助手</h3>
    <span class="ai-close" id="aiClose">✕</span>
  </div>
  <div class="ai-body">
    <div class="ai-task-bar">
      <button class="ai-task-btn active" data-t="outline">📋 大纲</button>
      <button class="ai-task-btn" data-t="rewrite">✨ 润色</button>
      <button class="ai-task-btn" data-t="continue">📖 续写</button>
      <button class="ai-task-btn" data-t="review">📝 批改</button>
    </div>
    <div class="form-item"><label>主题 / 你的问题</label><textarea id="aiInput" class="ai-input" placeholder="${defaultTask === 'rewrite' || defaultTask === 'continue' || defaultTask === 'review' ? '把你的文字贴在这里…' : '写这篇文章是关于什么的？'}">${esc(defaultInput)}</textarea></div>
    <div class="form-item"><label>风格 / 要求（可选）</label><input id="aiStyle" placeholder="例如：议论文、轻松幽默、简洁有力"></div>
    <button class="ai-send" id="aiSend">🚀 让 AI 帮我</button>
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
          <button class="btn ghost sm" id="aiCopy">📋 复制</button>
          <button class="btn ghost sm" id="aiAppend">➕ 加到编辑器</button>
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
    sendBtn.disabled = false; sendBtn.textContent = '🚀 让 AI 帮我';
  };
}
function closeAiPanel() { if (_aiPanel) { _aiPanel.remove(); _aiPanel = null; } }
function showAiFab() {
  if (document.getElementById('aiFab')) return;
  const fab = document.createElement('button');
  fab.className = 'ai-fab'; fab.id = 'aiFab'; fab.innerHTML = '🤖'; fab.title = 'AI 写作助手';
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
  `<div class="avatar ${cls}" style="background:${avatarColor(u && u.id)}">${esc((u && u.nickname || '?')[0].toUpperCase())}</div>`;
const statusBadge = (s) => ({ pending: '审核中', approved: '已通过', rejected: '未通过' }[s] || s);
const contestBadge = (s) => ({ upcoming: '未开始', ongoing: '进行中', ended: '已结束' }[s] || s);
const needLogin = () => {
  if (!state.me) { toast('请先登录', 'err'); location.hash = '#/login'; return true; }
  return false;
};

/* ---------- 侧边栏 ---------- */
function renderSidebar() {
  const me = state.me;
  const cur = location.hash.replace(/^#/, '') || '/home';
  const link = (h, icon, label, extra) =>
    `<a href="#${h}" class="${cur === h || cur.startsWith(h + '/') ? 'active' : ''}"><span class="icon">${icon}</span><span class="txt">${label}</span>${extra || ''}</a>`;
  let html = `
  <div class="logo">
    <div class="logo-mark">文</div>
    <div><span class="logo-name">文汇</span><span class="logo-sub">WENHUI</span></div>
  </div>
  <nav class="nav">
    ${link('/home', '🏠', '主页')}
    ${link('/daily', '🔥', '每日打卡')}
    ${link('/forum', '💬', '论坛广场')}
    ${link('/articles', '📖', '文章库')}
    ${link('/problems', '📚', '题库')}
    ${link('/templates', '📝', '写作模板')}
    ${link('/rank', '🏆', '排行榜')}
    ${link('/contests', '🏁', '比赛广场')}
    ${link('/submit', '📤', '文件投稿')}
    ${link('/mine', '📝', '我的文章')}
    ${me ? link('/messages', '✉️', '私信', '<span class="msg-badge" id="msgBadge" style="display:none">0</span>') : ''}
    ${me && me.role === 'admin' ? `
      <div class="nav-label">后台管理</div>
      ${link('/admin/contest', '🛠️', '创建比赛')}
      ${link('/admin/articles', '✅', '审核文章')}
      ${link('/admin/posts', '📋', '审核帖子')}
      ${link('/admin/problems', '📚', '审核题目')}
      ${link('/admin/files', '📁', '审核投稿')}` : ''}
  </nav>
  <div class="user-zone" id="userZone">`;
  if (me) {
    html += `
    <div class="user-card" id="userCard">
      ${avatarHtml(me)}
      <div class="uinfo">
        <div class="name">${esc(me.nickname)}${me.role === 'admin' ? '<span class="role-badge">管理员</span>' : ''}</div>
        <div class="uname">@${esc(me.username)}</div>
      </div>
    </div>`;
  } else {
    html += `<a class="login-btn" href="#/login">登录 / 注册</a>`;
  }
  html += `</div>`;
  $sidebar.innerHTML = html;

  const card = document.getElementById('userCard');
  if (card) card.onclick = toggleUserMenu;
}
function toggleUserMenu() {
  const zone = document.getElementById('userZone');
  if (document.getElementById('userMenu')) return closeMenu();
  const me = state.me;
  const div = document.createElement('div');
  div.className = 'popover';
  div.id = 'userMenu';
  div.innerHTML = `
    <div class="p-head">${esc(me.nickname)} <span style="font-weight:400;font-size:12px">@${esc(me.username)}</span></div>
    <a href="#/user/${me.id}">👤 个人主页</a>
    <a href="#/messages">✉️ 私信</a>
    <a href="#/mine">📝 我的文章</a>
    <a href="#/settings">⚙️ 偏好设置</a>
    <div class="divider"></div>
    <div class="p-item logout" id="logoutBtn">🚪 登出账号</div>`;
  zone.appendChild(div);
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

/* 未读私信红点 */
async function refreshUnread() {
  if (!state.me) return;
  try {
    const d = await api('/api/messages/unread');
    const b = document.getElementById('msgBadge');
    if (b) {
      b.textContent = d.count;
      b.style.display = d.count > 0 ? 'inline-block' : 'none';
    }
  } catch (e) {}
}

/* ---------- 路由 ---------- */
const routes = {
  home: viewHome, forum: viewForum, post: viewPostDetail, newpost: viewNewPost,
  articles: viewArticles, article: viewArticleDetail, write: viewWrite,
  rank: viewRank, contests: viewContests, contest: viewContestDetail,
  submit: viewSubmit, mine: viewMine, user: viewProfile, settings: viewSettings,
  login: viewLogin, admin: viewAdmin, messages: viewMessages, chat: viewChat,
  problems: viewProblems, problem: viewProblemDetail, work: viewWorkspace,
  templates: viewTemplates, daily: viewDaily
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
    $app.innerHTML = `<div class="card"><div class="empty">😕 ${esc(e.message)}</div></div>`;
  }
  window.scrollTo(0, 0);
}
const go = (h) => { location.hash = h; };

/* ---------- 主页 ---------- */
/* 站点更新说明（每次部署时追加最新一条在最上面）*/
const CHANGELOG = [
  { date: '2026-09-30 03:30', author: 'ZhangCing', items: ['网站更名：文洛 → 文汇（logo、标题、欢迎语、杯赛名、Schema 注释全量替换）'] },
  { date: '2026-09-30 03:00', author: 'ZhangCing', items: ['每日打卡改用分屏工作台；修复文件投稿/比赛/我的练习的 withAuthorSync 未定义错误'] },
  { date: '2026-09-30 02:00', author: 'ZhangCing', items: ['分屏工作台编辑区支持 Markdown 预览；新增「上传文件」模块（.txt/.md 点击或拖入导入）'] },
  { date: '2026-09-30 01:30', author: 'ZhangCing', items: ['题目练习/比赛提交改为 Luogu 风格分屏工作台（可拖动调整，支持在线写作和粘贴导入）'] },
  { date: '2026-09-30 00:30', author: 'ZhangCing', items: ['文章库 / 论坛 / 题库新增分页（每页 10 条）'] },
  { date: '2026-09-29 23:30', author: 'ZhangCing', items: ['题库新增 100 道写作题，难度 1-6 全覆盖'] },
  { date: '2026-09-29 22:30', author: 'ZhangCing', items: ['修复主页比赛卡片显示 undefined', '评论系统升级：楼中楼回复、回复/删除按钮', '比赛报名名单显示用户昵称'] },
  { date: '2026-09-29', author: 'ZhangCing', items: ['审核系统全链路直接 SQL 持久化，审核状态不再丢失', '积分统一实时计算，个人主页与排行榜一致', 'Markdown 全站渲染适配', '比赛列表/详情/状态修复'] },
];
async function viewHome() {
  hideAiFab();
  const [d, cd] = await Promise.all([
    api('/api/home').catch(() => ({ stats: {}, latestArticles: [], latestPosts: [], activeContests: [] })),
    state.me ? api('/api/checkins/today').catch(() => ({ daily: null, streak: 0, myCheckin: null })) : { daily: null, streak: 0, myCheckin: null }
  ]);
  const itemList = (arr, type) => arr.map(x => `
    <div class="item">
      ${avatarHtml(x.author, 'xs')}
      <div style="flex:1">
        <div class="title"><a href="#/${type}/${x.id}">${esc(x.title)}</a></div>
        <div class="meta"><span>${esc(x.author.nickname)}</span><span>${fmtTime(x.createdAt)}</span>
        ${type === 'article' ? `<span>👁 <span class="num">${x.views || 0}</span></span><span>❤️ <span class="num">${x.likeCount || 0}</span></span>` : `<span>💬 <span class="num">${x.commentCount || 0}</span></span>`}
        </div>
      </div>
    </div>`).join('') || '<div class="empty">暂无内容</div>';

  const checkinCard = cd && cd.daily ? `
    <div class="checkin-card" style="cursor:pointer" onclick="location.hash='#/daily'">
      <h2>🔥 今日打卡 · 第 ${cd.streak || 1} 天</h2>
      <div class="cc-sub">每天一题，坚持写作</div>
      <div class="cc-row">
        <div class="streak-badge">
          <div class="n">${cd.streak || 0}</div>
          <div class="l">连续天数</div>
        </div>
        <div class="cc-problem">
          <b>📋 ${esc(cd.daily.title)}</b><br>
          <span style="opacity:.85;font-size:12px">${cd.myCheckin ? '✅ 今天已打卡，点我看详情' : '👉 点我开始今天的练习！'}</span>
        </div>
      </div>
    </div>` : '';

  $app.innerHTML = `
  <div class="container">
    <div class="hero">
      <h1>文汇 · 文章竞赛社区</h1>
      <p>写作、交流、比赛 —— 一个简洁流畅的创作家园</p>
      <div class="hero-btns">
        <button class="btn-hero solid" id="hWrite">✍️ 立即开始创作</button>
        <button class="btn-hero solid" id="hPost">💬 发帖 · 论坛</button>
        <button class="btn-hero ghost" id="hFile">📤 文件投稿</button>
      </div>
    </div>
    ${checkinCard}
    <div class="stats">
      <div class="stat"><div class="num">${d.stats.users || 0}</div><div class="lab">注册用户</div></div>
      <div class="stat"><div class="num">${d.stats.articles || 0}</div><div class="lab">收录文章</div></div>
      <div class="stat"><div class="num">${d.stats.posts || 0}</div><div class="lab">论坛帖子</div></div>
      <div class="stat"><div class="num">${d.stats.contests || 0}</div><div class="lab">举办比赛</div></div>
    </div>
    ${d.activeContests && d.activeContests.length ? `
    <div class="card">
      <h2>🏁 进行中的比赛</h2>
      ${d.activeContests.map(c => contestRow(c)).join('')}
    </div>` : ''}
    <div class="grid-2">
      <div class="card"><h2>📖 最新文章</h2>${itemList(d.latestArticles || [], 'article')}</div>
      <div class="card"><h2>💬 最新帖子</h2>${itemList(d.latestPosts || [], 'post')}</div>
    </div>
    <div class="card">
      <h2>📝 更新说明</h2>
      ${CHANGELOG.map(e => `
      <div class="item">
        <div style="flex:1">
          <div class="title" style="font-size:13.5px">${e.items.map(esc).join('；')}</div>
          <div class="meta"><span>👤 ${esc(e.author)}</span><span>🕒 ${esc(e.date)}</span></div>
        </div>
      </div>`).join('')}
    </div>
  </div>`;
  document.getElementById('hWrite').onclick = () => needLogin() || go('#/write');
  document.getElementById('hPost').onclick = () => needLogin() || go('#/newpost');
  document.getElementById('hFile').onclick = () => needLogin() || go('#/submit');
}
const contestRow = (c) => `
  <div class="item contest" style="cursor:pointer" onclick="location.hash='#/contest/${c.id}'">
    <div style="flex:1">
      <div class="c-title">${esc(c.title)}</div>
      <div class="c-meta"><span class="badge ${c.status}">${contestBadge(c.status)}</span>
        <span>⏰ ${fmtRange(c.startTime, c.endTime)}</span><span>👥 ${c.participantCount} 人已报名</span><span>📋 ${c.problemCount || 0} 道题</span></div>
    </div>
    <span style="color:var(--text2)">›</span>
  </div>`;

/* 搜索框 UI */
function searchBoxHtml(id, q, placeholder) {
  return `<div class="search-box">
    <input id="${id}" value="${esc(q)}" placeholder="${esc(placeholder)}" maxlength="60">
    <button class="btn primary" data-searchbtn="${id}">🔍 搜索</button>
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
          <span>💬 <span class="num">${p.commentCount}</span></span></div>
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
          <span>💬 ${p.commentCount} 条回复</span>
          ${state.me && (state.me.id === p.authorId || state.me.role === 'admin') ? '<button class="btn red sm" id="delPost">删除</button>' : ''}
        </div>
      </div>
      <div class="doc-content">${md(p.content)}</div>
    </div>
    <div class="card">
      <h2>全部回复（${p.commentCount}）</h2>
      <div id="postComments">${renderComments(p._cmRoots || [], 'post', id)}</div>
      ${state.me ? `
      <div style="margin-top:14px" class="form-item">
        <textarea id="cInput" placeholder="友善回复，理性讨论…" style="min-height:80px"></textarea>
        <button class="btn primary" id="cSubmit" style="margin-top:10px">发表回复</button>
      </div>` : `<div class="empty"><a href="#/login">登录</a> 后参与讨论</div>`}
    </div>
  </div>`;
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
      <button class="btn primary" id="wBtn">✍️ 我要写文章</button>
    </div>
    ${searchBoxHtml('aQ', q, '搜索文章标题 / 内容 / 作者…')}
    <div class="tabs">
      <span class="t ${sort === 'new' ? 'active' : ''}" data-s="new">最新</span>
      <span class="t ${sort === 'hot' ? 'active' : ''}" data-s="hot">最热</span>
      <span style="margin:0 6px;color:var(--border)">|</span>
      <span class="t ${cat === '' ? 'active' : ''}" data-c="">全部类别</span>
      ${ART_CATS.map(c => `<span class="t ${cat === c ? 'active' : ''}" data-c="${c}">${c}</span>`).join('')}
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
            <span>👁 <span class="num">${a.views || 0}</span></span><span>❤️ <span class="num">${a.likeCount || 0}</span></span></div>
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
  <div class="container" style="max-width:820px">
    <div class="card">
      <div class="doc-head">
        <h1>${esc(a.title)}</h1>
        <div class="meta">
          <span class="type-badge">${esc(a.category || '其他')}</span>
          ${tagsHtml}
          <span class="who">${avatarHtml(a.author, 'small')} ${esc(a.author.nickname)}</span>
          <span>${fmtTime(a.createdAt)}</span>
          <span>👁 ${a.views || 0}</span>
          ${a.status !== 'approved' ? `<span class="badge ${a.status}">${statusBadge(a.status)}</span>` : ''}
          ${state.me && (state.me.id === a.authorId || state.me.role === 'admin') ? `<button class="btn red sm" id="delArt">删除</button>` : ''}
        </div>
      </div>
      <div class="doc-content">${md(a.content)}</div>
      <div style="margin-top:22px;text-align:center">
        <button class="btn like-btn ${a.liked ? 'liked' : ''}" id="likeBtn">${a.liked ? '❤️ 已赞' : '🤍 点赞'} · ${a.likeCount}</button>
      </div>
    </div>

    <div class="card">
      <h2>⭐ 文章点评（${rd.count}）<span class="hint" style="font-weight:400">平均 ${rd.avgRating} 星</span></h2>
      ${state.me ? `
      <div style="margin-bottom:14px;padding-bottom:14px;border-bottom:1px dashed var(--border)">
        <div class="hint" style="margin-bottom:6px">给这篇文章打个分吧（点评 +10 积分）</div>
        <div class="star-picker" id="starPicker">
          ${[1,2,3,4,5].map(i => `<span class="s" data-v="${i}">${i <= (viewArticleDetail._sel || 0) ? '★' : '☆'}</span>`).join('')}
          <span class="hint" style="margin-left:10px;font-size:12px" id="starHint">点击星星评分</span>
        </div>
        <textarea id="revContent" style="width:100%;padding:8px 10px;border:1px solid var(--border);border-radius:8px;margin-top:8px;min-height:70px;font-size:13px;resize:vertical" placeholder="说说你的感受…"></textarea>
        <button class="btn primary sm" id="revSubmit" style="margin-top:6px">📤 提交点评</button>
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

    <div class="card">
      <h2>💬 评论（${cd.total}）</h2>
      ${state.me ? `
      <div style="margin-bottom:14px;padding-bottom:14px;border-bottom:1px dashed var(--border)">
        <textarea id="cmInput" style="width:100%;padding:8px 10px;border:1px solid var(--border);border-radius:8px;min-height:60px;font-size:13px;resize:vertical" placeholder="说点什么…"></textarea>
        <button class="btn primary sm" id="cmSubmit" style="margin-top:6px">💬 发表评论</button>
      </div>` : `<div class="empty" style="margin-bottom:12px"><a href="#/login">登录</a> 后参与评论</div>`}
      <div id="commentBox">${renderComments(cd.comments, 'article', id)}</div>
    </div>
  </div>`;
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
      lb.innerHTML = (r.liked ? '❤️ 已赞' : '🤍 点赞') + ' · ' + r.likeCount;
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
        <span class="cm-like" data-cid="${c.id}" data-obj="${targetType === 'article' ? 'a' : 'p'}" data-tid="${targetId}">${c.liked ? '❤️' : '🤍'} ${c.likeCount || 0}</span>
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
        <button class="btn ghost sm" id="tplBtn">📝 选择模板</button>
      </div>
    </div>

    <!-- 可拖拽分栏 -->
    <div id="writeSplit" class="write-split">
      <!-- 左侧：编辑器 -->
      <div id="writeLeft" class="write-pane" style="width:55%;min-width:340px">
        <div id="tplPanel" style="display:none">
          <div class="card">
            <h2>📝 写作模板（点击应用到编辑器）</h2>
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
            <div class="ai-logo">✦</div>
            <div>
              <div class="ai-title">AI 写作助手</div>
              <div class="ai-sub">描述你的创意，让 AI 帮你变成文字</div>
            </div>
          </div>
          <div class="ai-task-bar">
            <button class="ai-task-btn active" data-t="write">✨ 帮你写</button>
            <button class="ai-task-btn" data-t="outline">📋 列大纲</button>
            <button class="ai-task-btn" data-t="rewrite">🎨 润色</button>
            <button class="ai-task-btn" data-t="continue">📖 续写</button>
            <button class="ai-task-btn" data-t="review">📝 批改</button>
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
              <span class="ai-send-ico">⚡</span>
              <span>让 AI 帮你写</span>
            </button>
            <div id="aiResult" class="ai-result"></div>
            <button class="ai-apply" id="aiApply">
              <span>📥 把结果插入编辑器</span>
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
        <h2>📄 ${esc(t.template.title)}</h2>
        <div class="hint" style="margin-bottom:10px">${esc(t.template.description)}</div>
        <div class="tpl-preview">${esc(t.template.content)}</div>
        <button class="btn primary sm" id="applyTpl">✅ 应用到编辑器</button>
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
    btn.innerHTML = '<span class="ai-send-ico">✦</span><span>AI 正在思考…</span>';
    aiResult.innerHTML = '<div class="ai-loader">AI 正在想办法</div>';
    aiApply.style.display = 'none';
    try {
      const currentContent = document.getElementById('aContent').value;
      const r = await api('/api/ai/assist', { method: 'POST', body: { task: _aiTask, input, style, content: currentContent, title: aTitle.value } });
      let html = md(r.result) || '<span class="hint">AI 没返回内容</span>';
      const tags = [];
      if (r.source === 'ai') tags.push('<span class="ai-tag ai-tag-ai">✨ Workers AI</span>');
      if (r.source === 'template') tags.push('<span class="ai-tag ai-tag-tpl">📝 模板回复</span>');
      if (r.cached) tags.push('<span class="ai-tag ai-tag-cache">💾 缓存</span>');
      if (r.limited) tags.push('<span class="ai-tag ai-tag-limit">⚠️ ' + esc(r.reason || '次数已用完') + '</span>');
      if (typeof r.remaining === 'number' && r.remaining >= 0 && !r.limited) tags.push(`<span class="ai-tag ai-tag-count">剩余 ${r.remaining} 次/天</span>`);
      if (tags.length) html = '<div class="ai-tags">' + tags.join('') + '</div>' + html;
      aiResult.innerHTML = html;
      aiApply.style.display = r.source !== 'template' || r.limited ? 'block' : 'block';
      aiApply.dataset.result = r.result || '';
      btn.innerHTML = '<span class="ai-send-ico">⚡</span><span>让 AI 帮你写</span>';
      btn.disabled = false;
    } catch (e) {
      aiResult.innerHTML = '<span style="color:var(--danger)">AI 暂时不可用：' + esc(e.message) + '</span>';
      btn.innerHTML = '<span class="ai-send-ico">⚡</span><span>让 AI 帮你写</span>';
      btn.disabled = false;
    }
    document.getElementById('aiSend').disabled = false;
    document.getElementById('aiSend').textContent = '🚀 让 AI 帮我';
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
  $app.innerHTML = `
  <div class="container">
    <div class="page-title"><div><h1>排行榜</h1><div class="sub">文章×10 + 帖子×5 + 获赞×3 + 评论×2 = 积分</div></div></div>
    <div class="card">
      <table class="rank">
        <tr><th></th><th>用户</th><th>积分</th><th>文章</th><th>帖子</th><th>获赞</th></tr>
        ${d.rank.map((r, i) => `
        <tr>
          <td class="rank-no ${i < 3 ? 'r' + (i + 1) : ''}">${i < 3 ? ['🥇', '🥈', '🥉'][i] : i + 1}</td>
          <td><a class="who" href="#/user/${r.user.id}">${avatarHtml(r.user, 'small')} ${esc(r.user.nickname)}
            ${r.user.role === 'admin' ? '<span class="role-badge">管理员</span>' : ''}</a></td>
          <td class="score">${r.score}</td><td>${r.articles}</td><td>${r.posts}</td><td>${r.likes}</td>
        </tr>`).join('') || '<tr><td colspan="6" class="empty">虚位以待</td></tr>'}
      </table>
    </div>
  </div>`;
}

/* ---------- 比赛广场 ---------- */
async function viewContests() {
  const d = await api('/api/contests');
  $app.innerHTML = `
  <div class="container">
    <div class="page-title">
      <div><h1>比赛广场</h1><div class="sub">共 ${d.contests.length} 场比赛</div></div>
      ${state.me && state.me.role === 'admin' ? '<button class="btn primary" onclick="go(\'#/admin/contest\')">＋ 创建比赛</button>' : ''}
    </div>
    ${d.contests.map(c => `
    <div class="card contest" style="cursor:pointer" onclick="location.hash='#/contest/${c.id}'">
      <div style="flex:1">
        <div class="c-title">${esc(c.title)}</div>
        <div class="c-meta">
          <span class="badge ${c.status}">${contestBadge(c.status)}</span>
          <span>⏰ ${fmtRange(c.startTime, c.endTime)}</span>
          <span>👥 ${c.participantCount} 人报名</span>
          <span>📋 ${c.problemCount || 0} 道题</span>
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
        <div class="meta"><span>⏰ ${fmtRange(c.startTime, c.endTime)}</span><span>👥 ${c.participantCount} 人已报名</span>
        <span>📋 ${c.problemCount} 道题</span><span>📥 ${c.submissionCount} 份作品</span>
        <span>主办方：${esc(c.creator ? c.creator.nickname : '')}</span></div>
      </div>
      <div class="doc-content">${md(c.description)}</div>
      <div style="margin-top:16px;text-align:center">
        ${c.status !== 'ended' ? `<button class="btn ${c.joined ? 'ghost' : 'green'}" id="joinBtn">${c.joined ? '✅ 已报名（点击取消）' : '🔥 立即报名'}</button>` : ''}
      </div>
    </div>
    <div class="card">
      <h2>📋 比赛题目（${c.problemCount}）</h2>
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
            <button class="btn primary sm" onclick="go('#/work/contest/${id}/${q.id}')">${mine ? '✏️ 修改我的作品' : '� 提交本题作品'}</button>
          </div>` : (c.status === 'ongoing' && !c.joined ? '<div class="hint">报名后即可提交本题作品</div>' : '')}
        </div>`;
      }).join('') || '<div class="empty">该比赛暂无题目</div>'}
      ${c.status === 'upcoming' ? '<div class="hint" style="margin-top:10px">⏳ 比赛开始后即可提交作品</div>' : ''}
      ${c.status === 'ended' ? '<div class="hint" style="margin-top:10px">🏁 比赛已结束，作品提交通道已关闭</div>' : ''}
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
    if (!problem) { $app.innerHTML = '<div class="card"><div class="empty">😕 题目不存在</div></div>'; return; }
    wordLimit = problem.wordLimit || 0;
    backHash = '#/contest/' + id;
    submitLabel = '提交本题作品';
    try { mine = ((await api(`/api/contests/${id}/my-submissions`)).submissions || []).find(s => s.problemId === qid) || null; } catch (e) {}
    submitUrl = `/api/contests/${id}/submit`;
    submitBody = (title, content) => ({ problemId: qid, title, content });
  } else if (mode === 'checkin') {
    const d = await api('/api/checkins/today');
    problem = d.daily;
    if (!problem) { $app.innerHTML = '<div class="card"><div class="empty">😕 今天暂无题目</div></div>'; return; }
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
        <button class="ws-tab cur" id="wsTabWrite">✏️ 在线写作</button>
        <button class="ws-tab" id="wsTabUpload">📄 上传文件</button>
        <span class="hint" style="margin-left:auto">字数：<b id="wsWc">0</b>${wordLimit ? ' / 上限 ' + wordLimit : ''}</span>
      </div>
      <div id="wsWritePane" style="display:flex;flex-direction:column;flex:1;min-height:0">
        <div class="ws-mode">
          <button class="mini cur" id="wsModeEdit">编辑</button>
          <button class="mini" id="wsModePrev">👁 预览</button>
        </div>
        ${needTitle ? `<input id="wsTitle" maxlength="80" placeholder="作品标题" value="${mine ? esc(mine.title) : (mode === 'problem' ? esc(state.me.nickname) + '的练习' : '')}">` : ''}
        <textarea id="wsContent" placeholder="${mode === 'checkin' ? '围绕今天的题目写一段打卡内容…' : '支持 Markdown（# 标题、**加粗**、> 引用…）。也可以把写好的内容直接粘贴进来（Ctrl+V）…'}">${mine ? esc(mine.content) : ''}</textarea>
        <div id="wsPreview" class="ws-preview doc-content" style="display:none"></div>
      </div>
      <div id="wsUploadPane" style="display:none;flex:1;min-height:0">
        <div class="upload-drop" id="wsDrop">
          <div style="font-size:36px">📄</div>
          <p><b>点击选择或拖入文件</b></p>
          <p class="hint">支持 .txt / .md 纯文本（≤1MB），内容将导入编辑器，可预览后再提交</p>
          <input type="file" id="wsFile" accept=".txt,.md,.markdown,text/plain" style="display:none">
        </div>
      </div>
      <div class="ws-actions">
        <button class="btn ghost sm" id="wsPaste">📋 粘贴导入</button>
        <button class="btn green" id="wsSubmit">📤 ${mine ? '保存修改' : '提交'}</button>
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
      <button class="btn primary" id="fSubmit">📤 上传投稿</button>
    </div>
    <div class="card">
      <h2>我的投稿记录</h2>
      ${d.files.map(f => `
      <div class="item">
        <div style="align-self:center;font-size:22px">📄</div>
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
  let list = '';
  if (tab === 'a') {
    list = da.articles.map(a => `
      <div class="item">
        <div style="flex:1">
          <div class="title"><a href="#/article/${a.id}">${esc(a.title)}</a> <span class="badge ${a.status}">${statusBadge(a.status)}</span></div>
          <div class="meta"><span>${fmtTime(a.createdAt)}</span><span>👁 ${a.views || 0}</span><span>❤️ ${a.likeCount || 0}</span></div>
        </div>
        ${a.status !== 'approved' ? `<button class="btn ghost sm" onclick="go('#/write/${a.id}')">编辑</button>` : ''}
        <button class="btn red sm" data-del-art="${a.id}">删除</button>
      </div>`).join('') || '<div class="empty">还没有写过文章，<a href="#/write">去写一篇</a>！</div>';
  } else if (tab === 'p') {
    list = dp.posts.map(p => `
      <div class="item">
        <div style="flex:1">
          <div class="title"><a href="#/post/${p.id}">${esc(p.title)}</a> <span class="badge ${p.status}">${statusBadge(p.status)}</span></div>
          <div class="meta"><span>${fmtTime(p.createdAt)}</span><span>💬 ${p.commentCount}</span></div>
        </div>
        <button class="btn red sm" data-del-post="${p.id}">删除</button>
      </div>`).join('') || '<div class="empty">还没有发过帖子</div>';
  } else {
    list = df.files.map(f => `
      <div class="item">
        <div style="align-self:center;font-size:22px">📄</div>
        <div style="flex:1">
          <div class="title">${esc(f.originalName)} <span class="badge ${f.status}">${statusBadge(f.status)}</span></div>
          <div class="meta"><span>${esc(f.note || '')}</span><span>${fmtSize(f.size)}</span><span>${fmtTime(f.createdAt)}</span></div>
        </div>
      </div>`).join('') || '<div class="empty">暂无投稿</div>';
  }
  $app.innerHTML = `
  <div class="container">
    <div class="page-title"><div><h1>我的文章</h1><div class="sub">管理你发布的文章、帖子与投稿</div></div>
    <button class="btn primary" onclick="go('#/write')">✍️ 写文章</button></div>
    <div class="tabs">
      <span class="t ${tab === 'a' ? 'active' : ''}" data-t="a">文章（${da.articles.length}）</span>
      <span class="t ${tab === 'p' ? 'active' : ''}" data-t="p">帖子（${dp.posts.length}）</span>
      <span class="t ${tab === 'f' ? 'active' : ''}" data-t="f">投稿（${df.files.length}）</span>
    </div>
    <div class="card">${list}</div>
  </div>`;
  document.querySelectorAll('.tabs .t').forEach(t => t.onclick = () => { viewMine._t = t.dataset.t; route(); });
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
}

/* ---------- 偏好设置 ---------- */
async function viewSettings() {
  if (needLogin()) return;
  const me = state.me;
  $app.innerHTML = `
  <div class="container" style="max-width:620px">
    <div class="page-title"><h1>偏好设置</h1></div>
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
  </div>`;
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
}

/* ---------- 登录 / 注册 ---------- */
function viewLogin() {
  let mode = 'login';
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
      <div class="hint" style="margin-top:10px;text-align:center">连续输错 5 次密码将锁定账号 10 分钟</div>` : `
      <div class="form-item"><label>用户名</label><input id="rUser" placeholder="3-24 位字母 / 数字 / 下划线"></div>
      <div class="form-item"><label>昵称</label><input id="rNick" placeholder="展示昵称（可留空）"></div>
      <div class="form-item"><label>密码</label><input type="password" id="rPass" placeholder="至少 8 位，需包含字母和数字"></div>
      <button class="btn primary" id="rBtn" style="width:100%">注册并登录</button>`;
    if (mode === 'login') document.getElementById('lBtn').onclick = async (e) => {
      e.target.disabled = true;
      try {
        const d = await api('/api/login', { method: 'POST', body: { username: lUser.value, password: lPass.value } });
        state.me = d.user;
        state.token = d.token;
        localStorage.setItem('token', d.token);
        toast('欢迎回来，' + d.user.nickname); go('#/home'); route();
      } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
    };
    else document.getElementById('rBtn').onclick = async (e) => {
      e.target.disabled = true;
      try {
        const d = await api('/api/register', { method: 'POST', body: { username: rUser.value, nickname: rNick.value, password: rPass.value } });
        state.me = d.user;
        state.token = d.token;
        localStorage.setItem('token', d.token);
        toast('注册成功，欢迎加入文汇！'); go('#/home'); route();
      } catch (err) { toast(err.message, 'err'); e.target.disabled = false; }
    };
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
    $app.innerHTML = '<div class="card"><div class="empty">⛔ 仅管理员可访问后台</div></div>';
    return;
  }
  const [kind, st] = (sub || '').split('/');
  if (kind === 'contest') return adminNewContest();
  const map = { articles: 'articles', posts: 'posts', files: 'files', problems: 'problems' };
  if (map[kind]) return adminReview(map[kind], st);
  return adminReview('articles', st);
}

async function adminNewContest() {
  $app.innerHTML = `
  <div class="container" style="max-width:860px">
    <div class="page-title"><div><h1>创建比赛</h1><div class="sub">发布后会出现在比赛广场，用户报名后按题目提交作品</div></div></div>
    <div class="card">
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
      <button class="btn primary" id="ctSubmit">🏁 发布比赛</button>
    </div>
  </div>`;
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
          ${problems.length > 1 ? `<button class="btn red sm" data-rm="${i}">✕ 删除本题</button>` : ''}</div>
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
    try {
      await api('/api/contests', {
        method: 'POST',
        body: {
          title: ctTitle.value, description: ctDesc.value,
          startTime: new Date(ctStart.value).getTime(), endTime: new Date(ctEnd.value).getTime(),
          problems: valid
        }
      });
      toast('比赛已发布'); go('#/contests');
    } catch (err) { toast(err.message, 'err'); }
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

  let items = '';
  if (kind === 'problems') {
    items = d.problems.map(p => `
      <div class="review-item">
        <div class="r-head">
          <span class="r-title">${esc(p.title)}</span>
          <span class="type-badge">${TYPE[p.type]}</span>
          ${diffBadge(p.difficulty)}
          <span class="badge ${p.status}">${statusBadge(p.status)}</span>
        </div>
        <div class="r-content">${md(p.content)}</div>
        <div class="r-actions">
          <span class="hint">出题人：${esc(p.proposer.nickname)}（@${esc(p.proposer.username || '')}）· ${fmtTime(p.createdAt)}</span>
          <button class="btn green sm" data-r="approve" data-id="${p.id}">✔ 通过</button>
          <button class="btn red sm" data-r="reject" data-id="${p.id}">✘ 拒绝</button>
        </div>
      </div>`).join('');
  } else if (kind === 'files') {
    items = d.files.map(f => `
      <div class="review-item">
        <div class="r-head">
          <span style="font-size:22px">📄</span>
          <span class="r-title">${esc(f.originalName)}</span>
          <span class="badge ${f.status}">${statusBadge(f.status)}</span>
        </div>
        <div class="r-content">投稿说明：${esc(f.note || '（无）')}\n文件大小：${fmtSize(f.size)}\n投稿人：${esc(f.author.nickname)}（@${esc(f.author.username)}）· ${fmtTime(f.createdAt)}</div>
        <div class="r-actions">
          <button class="btn green sm" data-r="approve" data-id="${f.id}">✔ 通过</button>
          <button class="btn red sm" data-r="reject" data-id="${f.id}">✘ 拒绝</button>
          <button class="btn ghost sm" onclick="window.open('/api/files/${f.id}/download')">⬇ 下载查看</button>
        </div>
      </div>`).join('');
  } else if (kind === 'posts') {
    items = d.posts.map(p => `
      <div class="review-item">
        <div class="r-head">
          <span class="r-title">${esc(p.title)}</span>
          <span class="badge ${p.status}">${statusBadge(p.status)}</span>
        </div>
        <div class="r-content">${md(p.content)}</div>
        <div class="r-actions">
          <span class="hint">投稿人：${esc(p.author.nickname)}（@${esc(p.author.username)}）· ${fmtTime(p.createdAt)}</span>
          <button class="btn green sm" data-r="approve" data-id="${p.id}">✔ 通过</button>
          <button class="btn red sm" data-r="reject" data-id="${p.id}">✘ 拒绝</button>
        </div>
      </div>`).join('');
  } else {
    items = d.articles.map(a => `
      <div class="review-item">
        <div class="r-head">
          <span class="r-title">${esc(a.title)}</span>
          <span class="badge ${a.status}">${statusBadge(a.status)}</span>
        </div>
        <div class="r-content">${md(a.content)}</div>
        <div class="r-actions">
          <span class="hint">作者：${esc(a.author.nickname)}（@${esc(a.author.username)}）· ${fmtTime(a.createdAt)}</span>
          <button class="btn green sm" data-r="approve" data-id="${a.id}">✔ 通过</button>
          <button class="btn red sm" data-r="reject" data-id="${a.id}">✘ 拒绝</button>
        </div>
      </div>`).join('');
  }

  $app.innerHTML = `
  <div class="container" style="max-width:900px">
    <div class="page-title"><div><h1>${title}</h1><div class="sub">后台管理 · ${state.me.nickname}</div></div>
    <a href="#/admin/${kind}/${st}" class="btn ghost">刷新</a></div>
    <div class="tabs">
      ${['pending', 'approved', 'rejected'].map(s => `
      <span class="t ${st === s ? 'active' : ''}" data-s="${s}">${labels[s]}（${counts[s]}）</span>`).join('')}
    </div>
    ${items || '<div class="card"><div class="empty">这里空空如也 🎉</div></div>'}
  </div>`;

  document.querySelectorAll('.tabs .t').forEach(t => t.onclick = () => {
    location.hash = `#/admin/${kind}/${t.dataset.s}`;
  });
  document.querySelectorAll('[data-r]').forEach(b => b.onclick = async () => {
    try {
      await api(`/api/admin/${apiPath}/${b.dataset.id}/review`, { method: 'POST', body: { action: b.dataset.r } });
      toast(b.dataset.r === 'approve' ? '已通过' : '已拒绝');
      route();
    } catch (e) { toast(e.message, 'err'); }
  });
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
        <button class="btn primary" data-searchbtn="pQ">🔍 搜索</button>
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
        <button class="btn green" id="npSave">${isAdmin ? '✔ 收录' : '📤 提交出题'}</button>
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
          <div class="meta"><span>👥 ${p.doerCount} 人练过</span><span>📝 ${p.practiceCount} 篇练习</span>${tagChips(p.tags)}</div>
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
          <span>👥 ${p.doerCount} 人练过</span><span>📝 ${p.practiceCount} 篇练习</span>
          ${mine ? '<span class="badge approved">我已完成</span>' : ''}
        </div>
      </div>
      <div class="doc-content">${md(p.content)}</div>
    </div>
    ${state.me ? `
    <div class="card" style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
      <div style="flex:1;min-width:220px">
        <h2 style="margin:0 0 4px">✍️ ${mine ? '继续练习' : '开始练习'}</h2>
        <div class="hint">${mine ? `已有作品：${esc(mine.title)} · ${mine.wordCount} 字` : '进入分屏工作台 —— 左边看题，右边写作'}</div>
      </div>
      <button class="btn green" id="goWorkspace">${mine ? '✏️ 修改我的练习' : '� 开始练习'}</button>
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
      <div><h1>📝 写作模板库</h1><div class="sub">8 套精选模板，帮你快速搭建文章结构</div></div>
      <button class="btn primary" onclick="go('#/write')">✍️ 去写文章</button>
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
        <h2>📄 ${esc(t.template.title)}</h2>
        <div class="hint" style="margin-bottom:10px">${esc(t.template.description)}</div>
        <div class="tpl-preview">${esc(t.template.content)}</div>
        <button class="btn primary" onclick="go('#/write')">✅ 用这个模板去写文章</button>
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
    <div class="page-title"><div><h1>🔥 每日打卡</h1><div class="sub">每天一题，坚持写作 · 连续 ${mine.streak} 天</div></div></div>

    <div class="checkin-card">
      <h2>📋 今日题目</h2>
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
        <h2 style="margin:0 0 4px">✍️ ${d.myCheckin ? '今日已打卡' : '开始今日打卡'}</h2>
        <div class="hint">${d.myCheckin ? `已打卡：+${d.myCheckin.points} 积分，明天再来吧！` : '进入分屏工作台 —— 左边题目，右边写作，支持 Markdown / 粘贴 / 上传文件'}</div>
      </div>
      ${d.myCheckin ? '<span class="badge approved">✅ 今日已打卡</span>' : ''}
      <button class="btn primary" id="goCheckin" ${!d.myCheckin ? '' : 'disabled'}>🚀 进入工作台</button>
    </div>

    <div class="card">
      <h2>📅 我的打卡记录（共 ${mine.total} 次）</h2>
      ${mine.checkins.length ? mine.checkins.map(c => `
        <div class="item">
          <div style="flex:1">
            <div class="title">📋 ${esc(c.problem ? c.problem.title : '题目')}</div>
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
  const d = await api('/api/users/' + id);
  const u = d.user;
  const isMe = state.me && state.me.id === u.id;
  const tab = viewProfile._t || 'a';

  // 勋章 emoji 映射
  const badgeEmoji = {
    '热心点评员': '⭐',
    '勤耕不辍': '🌱',
    '一周达人': '🔥',
    '月度冠军': '🏆',
    '首篇文章': '📖',
    '首个帖子': '💬',
    '比赛勇士': '🎯'
  };
  const badges = u.badges || [];
  const allBadges = [
    { name: '热心点评员', reason: '点评 3 篇以上文章', icon: '⭐' },
    { name: '勤耕不辍', reason: '连续打卡 3 天', icon: '🌱' },
    { name: '一周达人', reason: '连续打卡 7 天', icon: '🔥' },
    { name: '月度冠军', reason: '连续打卡 30 天', icon: '🏆' }
  ];
  const earned = new Set(badges.map(b => b.name));

  let list = '';
  if (tab === 'a') {
    list = d.articles && d.articles.length ? d.articles.map(a => `
      <div class="item"><div style="flex:1">
        <div class="title"><a href="#/article/${a.id}">${esc(a.title)}</a></div>
        <div class="meta"><span>${fmtTime(a.createdAt)}</span><span>👁 ${a.views || 0}</span><span>❤️ ${a.likeCount || 0}</span></div>
      </div></div>`).join('') : '<div class="empty">暂无公开文章</div>';
  } else if (tab === 'p') {
    list = d.posts && d.posts.length ? d.posts.map(p => `
      <div class="item"><div style="flex:1">
        <div class="title"><a href="#/post/${p.id}">${esc(p.title)}</a></div>
        <div class="meta"><span>${fmtTime(p.createdAt)}</span><span>💬 ${p.commentCount || 0}</span></div>
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

  $app.innerHTML = `
  <div class="container" style="max-width:860px">
    <div class="card">
      <div class="portfolio-head">
        ${avatarHtml(u, 'big')}
        <div style="flex:1">
          <h1 style="font-size:20px">${esc(u.nickname)} ${u.role === 'admin' ? '<span class="role-badge">管理员</span>' : ''}</h1>
          <div class="meta" style="color:var(--text2);font-size:13px;margin-top:4px">@${esc(u.username)} · 加入于 ${fmtTime(u.createdAt)}</div>
          <div style="margin-top:8px;font-size:13.5px;color:#556">${esc(u.bio || '这个人很懒，什么都没写')}</div>
          ${!isMe && state.me ? `
          <div style="margin-top:10px;display:flex;gap:8px">
            <button class="btn ${d.isFollowing ? 'ghost' : 'primary'}" id="followBtn">${d.isFollowing ? '✅ 已关注' : '➕ 关注'}</button>
            <button class="btn ghost" id="dmBtn">✉️ 发私信</button>
          </div>` : ''}
        </div>
      </div>
      <div class="profile-stats">
        <div class="ps"><b>${d.stats.articles}</b><span class="hint">文章</span></div>
        <div class="ps"><b>${d.stats.posts}</b><span class="hint">帖子</span></div>
        <div class="ps"><b>${d.stats.likes}</b><span class="hint">获赞</span></div>
        <div class="ps"><b>${d.stats.score || 0}</b><span class="hint">积分</span></div>
        <div class="ps"><b>${d.stats.followingCount}</b><span class="hint">关注</span></div>
        <div class="ps"><b>${d.stats.followerCount}</b><span class="hint">粉丝</span></div>
      </div>
      ${badges.length ? `
      <div style="margin-top:14px;padding-top:12px;border-top:1px dashed var(--border)">
        <div class="hint" style="margin-bottom:6px">🎖️ 勋章墙（${badges.length}）</div>
        <div class="badge-list">
          ${badges.map(b => `<div class="badge-item">
            <div class="bi-icon">${badgeEmoji[b.name] || '🏅'}</div>
            <div class="bi-name">${esc(b.name)}</div>
          </div>`).join('')}
        </div>
      </div>` : ''}
    </div>

    <div class="card">
      <div class="portfolio-tabs">
        <span class="pt ${tab === 'a' ? 'active' : ''}" data-t="a">📖 文章 ${d.stats.articles}</span>
        <span class="pt ${tab === 'p' ? 'active' : ''}" data-t="p">💬 帖子 ${d.stats.posts}</span>
        <span class="pt ${tab === 'b' ? 'active' : ''}" data-t="b">🎖️ 勋章</span>
        <span class="pt ${tab === 'c' ? 'active' : ''}" data-t="c">🏁 比赛 ${(d.contests || []).length}</span>
        <span class="pt ${tab === 'f' ? 'active' : ''}" data-t="f">➕ 关注 ${d.stats.followingCount}</span>
        <span class="pt ${tab === 'w' ? 'active' : ''}" data-t="w">👥 粉丝 ${d.stats.followerCount}</span>
      </div>
      ${list}
    </div>
  </div>`;
  document.querySelectorAll('.portfolio-tabs .pt').forEach(t => t.onclick = () => { viewProfile._t = t.dataset.t; route(); });
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
})();
