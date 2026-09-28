/*
 * Cloudflare Pages Functions - 文洛·文章竞赛社区 完整 API
 * 数据存储：Cloudflare KV (DATA)
 * 认证方式：Bearer Token（KV 存储 token→userId）
 * 密码哈希：Web Crypto API PBKDF2
 */

/* ---------------- 工具函数 ---------------- */
const uid = (p) => p + '_' + Math.random().toString(36).slice(2, 11);
const bad = (msg, status = 400) => new Response(JSON.stringify({ error: msg }), { status, headers: corsHeaders() });
const json = (data, status = 200, extraHeaders = {}) => new Response(JSON.stringify(data), { status, headers: { ...corsHeaders(), ...extraHeaders } });
const corsHeaders = () => ({
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
});
const clean = (s, max) => String(s == null ? '' : s).trim().slice(0, max || 20000);

/* ---------------- 类别常量 ---------------- */
const ART_CATS = ['散文', '小说', '科幻', '诗歌', '记叙文', '议论文', '随笔', '其他'];
const POST_CATS = ['题目讲解', '方法分享', '经验交流', '灌水闲聊', '其他'];

/* ---------------- 密码哈希（Web Crypto PBKDF2） ---------------- */
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(String(password)), 'PBKDF2', false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits({
    name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256'
  }, key, 256);
  return { salt: bytesToHex(salt), hash: bytesToHex(new Uint8Array(hash)) };
}
async function verifyPassword(password, user) {
  const enc = new TextEncoder();
  const salt = hexToBytes(user.salt);
  const key = await crypto.subtle.importKey('raw', enc.encode(String(password)), 'PBKDF2', false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits({
    name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256'
  }, key, 256);
  return bytesToHex(new Uint8Array(hash)) === user.hash;
}
function hexToBytes(h) {
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < h.length; i += 2) a[i / 2] = parseInt(h.slice(i, i + 2), 16);
  return a;
}
function bytesToHex(b) {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

/* ---------------- 数据库管理 ---------------- */
const KV_KEY = 'database';
let _cache = null;

async function loadDB(env) {
  if (_cache) return _cache;
  const raw = await env.DATA.get(KV_KEY);
  if (!raw) {
    _cache = initDB();
    await saveDB(env);
  } else {
    _cache = JSON.parse(raw);
    // 兼容旧数据
    _cache.messages = _cache.messages || [];
    for (const u of _cache.users) u.following = u.following || [];
    if (!Array.isArray(_cache.problems)) { _cache.problems = []; seedProblems(); }
    for (const p of _cache.problems) if (!p.status) p.status = 'approved';
    _cache.practices = _cache.practices || [];
    for (const a of _cache.articles) if (!a.category) a.category = '其他';
    for (const p of _cache.posts) if (!p.category) p.category = '其他';
    for (const c of _cache.contests) {
      c.submissions = c.submissions || [];
      if (!c.problems || !c.problems.length) {
        c.problems = [
          { id: uid('q'), title: '主题创作', content: '围绕比赛主题，完成一篇原创作品。', wordLimit: 2000 },
          { id: uid('q'), title: '自由发挥', content: '题材不限，展现你的创意与文笔。', wordLimit: 2000 },
          { id: uid('q'), title: '我的社区故事', content: '写下你在社区里的经历或见闻。', wordLimit: 0 }
        ];
      }
    }
  }
  return _cache;
}

async function saveDB(env) {
  await env.DATA.put(KV_KEY, JSON.stringify(_cache, null, 2));
}

function initDB() {
  const now = Date.now();
  const user = {
    id: 'u_admin', username: 'admin', nickname: '站务管理员', role: 'admin',
    bio: '本站管理员，负责文章、帖子与投稿审核。', createdAt: now
  };
  const db = {
    users: [user], articles: [], posts: [], contests: [],
    files: [], messages: [], problems: [], practices: []
  };
  db.articles.push({
    id: 'a_welcome', authorId: 'u_admin', title: '欢迎来到文洛 · 文章竞赛社区',
    content: '## 这里可以做什么\n\n- **写文章**：点击侧边栏「我的文章」或主页「立即开始创作」，提交后由管理员审核，通过后进入文章库。\n- **逛论坛**：在「论坛广场」发帖交流，帖子同样需要审核。\n- **打比赛**：管理员会在「比赛广场」创建比赛，欢迎报名参加。\n- **文件投稿**：有文档想分享？通过「文件投稿」上传，审核通过后归档。\n\n## 社区公约\n\n1. 保持友善，尊重原创。\n2. 文章支持 `Markdown` 基础语法：**加粗**、`代码`、标题等。\n3. 违规内容将被拒绝并记录。\n\n祝大家玩得开心！',
    category: '其他', status: 'approved', views: 128, likes: [], createdAt: now - 86400000, reviewedAt: now - 86000000
  });
  db.posts.push({
    id: 'p_hello', authorId: 'u_admin', title: '【置顶】新人报到帖',
    content: '新来的同学在这里打个招呼吧！介绍一下自己擅长的领域 ~',
    category: '其他', status: 'approved', createdAt: now - 43200000, comments: []
  });
  db.contests.push({
    id: 'c_demo', title: '第一届「文洛杯」短文创作赛',
    description: '## 比赛说明\n\n围绕主题「**代码与生活**」写一篇不超过 2000 字的短文。\n\n- 参赛作品请通过「我的文章 → 写文章」提交，标题前缀【文洛杯】。\n- 评审标准：立意 40%、文笔 40%、创意 20%。\n\n期待大家的作品！',
    problems: [
      { id: uid('q'), title: '主题创作', content: '围绕比赛主题，完成一篇原创作品。', wordLimit: 2000 },
      { id: uid('q'), title: '自由发挥', content: '题材不限，展现你的创意与文笔。', wordLimit: 2000 },
      { id: uid('q'), title: '我的社区故事', content: '写下你在社区里的经历或见闻。', wordLimit: 0 }
    ],
    startTime: now - 3600000, endTime: now + 7 * 86400000,
    createdBy: 'u_admin', createdAt: now - 7200000,
    participants: [], submissions: []
  });
  seedProblems(db);
  // 管理员密码：admin123（哈希在 initTokens 中设置）
  user.salt = 'seed_salt_placeholder';
  user.hash = 'seed_hash_placeholder';
  return db;
}

function seedProblems(db) {
  db = db || _cache;
  if (!db.problems || db.problems.length) return;
  const now = Date.now();
  const mk = (type, title, content, difficulty, tags) => ({
    id: uid('q'), type, title, content, difficulty, tags,
    createdBy: 'u_admin', createdAt: now - 86400000, status: 'approved'
  });
  db.problems.push(
    mk('theme', '以「时光」为题，写一篇文章', '## 要求\n\n- 以「时光」为题，体裁不限\n- 围绕时光流逝中的人和事展开，要有真情实感\n- 建议字数 600-1500 字', 2, ['记叙', '抒情']),
    mk('theme', '以「窗外」为题，描写一个熟悉的场景', '## 要求\n\n- 以「窗外」为题\n- 选择一个你观察过的场景\n- 至少运用两种感官描写', 1, ['写景', '观察']),
    mk('theme', '以「选择」为题，写一次难忘的抉择', '## 要求\n\n- 以「选择」为题，写一次让你纠结、难忘的抉择\n- 写清楚：两难在哪里？你为什么这样选？事后怎么看？', 3, ['记叙', '成长']),
    mk('theme', '以「故乡」为题', '## 要求\n\n- 以「故乡」为题\n- 抓住故乡最有代表性的一两个意象\n- 避免空泛抒情，用具体细节承载情感', 2, ['散文', '乡情']),
    mk('theme', '科幻微小说：一百年后的世界', '## 要求\n\n- 写一篇一百年后的世界为背景的微型小说\n- 必须有一个完整的小故事\n- 字数 1000 字以内', 4, ['科幻', '小说']),
    mk('theme', '以「灯」为题', '## 要求\n\n- 以「灯」为题，可以写实也可以写虚\n- 让「灯」在文中承担象征意义', 3, ['象征', '散文']),
    mk('skill', '用排比写一段风景', '## 要求\n\n- 写一段 150-300 字的风景描写\n- 至少包含一组三句以上的排比句', 2, ['排比', '写景']),
    mk('skill', '用比喻描写「时间」', '## 要求\n\n- 写 3 个以上形容时间的比喻句\n- 不许用「时间像流水」这类常见比喻\n- 每个比喻配一句话展开', 1, ['比喻', '修辞']),
    mk('skill', '不用「哭」字，写一个人悲伤的样子', '## 要求\n\n- 写 100-200 字的片段\n- 全文禁止出现「哭」「泪」「难过」「伤心」\n- 只靠动作、神态、环境来传递悲伤', 3, ['细节描写', '侧面烘托']),
    mk('skill', '用「欲扬先抑」写一个人物', '## 要求\n\n- 写 300-500 字的人物片段\n- 先写缺点/不好的第一印象，再通过一件事反转\n- 反转要自然', 4, ['欲扬先抑', '人物']),
    mk('skill', '用对话推动一个故事', '## 要求\n\n- 写 300 字左右的片段\n- 情节推进必须全部靠对话完成\n- 对话要有「潜台词」', 3, ['对话', '小说']),
    mk('skill', '用环境描写烘托紧张气氛', '## 要求\n\n- 写 150 字左右\n- 人物正在等待一个重要结果\n- 只写环境，让读者自己紧张起来', 3, ['环境烘托', '气氛']),
    mk('skill', '用倒叙写一件小事', '## 要求\n\n- 写 400 字左右\n- 必须从事件的结尾或高潮写起，再回溯\n- 倒叙切入要自然', 4, ['倒叙', '结构']),
    mk('skill', '把「他跑得很快」扩写成 150 字', '## 要求\n\n- 把这句话扩写成 150 字左右的片段\n- 至少从三个角度展开\n- 不许出现「很快」「飞快」这两个词', 1, ['扩写', '描写'])
  );
}

/* ---------------- Token 管理 ---------------- */
async function createToken(env, userId) {
  const token = 'tk_' + uid('') + crypto.getRandomValues(new Uint8Array(8)).reduce((a, b) => a + b.toString(16).padStart(2, '0'), '');
  await env.DATA.put('token:' + token, userId, { expirationTtl: 7 * 86400 });
  return token;
}
async function resolveToken(env, token) {
  if (!token) return null;
  const pure = token.startsWith('tk_') ? token : token.replace(/^Bearer\s+/i, '');
  const id = await env.DATA.get('token:' + pure);
  return id;
}
async function deleteToken(env, token) {
  const pure = token.startsWith('tk_') ? token : token.replace(/^Bearer\s+/i, '');
  await env.DATA.delete('token:' + pure);
}

/* ---------------- 辅助函数 ---------------- */
const pub = (u) => u ? { id: u.id, username: u.username, nickname: u.nickname, role: u.role, bio: u.bio || '', createdAt: u.createdAt } : null;
const userById = (db, id) => db.users.find(u => u.id === id);
const withAuthor = (item, db) => Object.assign({}, item, { author: pub(userById(db, item.authorId)) || { nickname: '已注销用户' } });

function articleOut(a, db) {
  const o = withAuthor(a, db);
  o.likeCount = (a.likes || []).length;
  delete o.likes;
  return o;
}
function postOut(p, db) {
  const o = withAuthor(p, db);
  o.commentCount = (p.comments || []).length;
  return o;
}
function problemOut(p, db) {
  const ps = db.practices.filter(x => x.problemId === p.id);
  return Object.assign({}, p, {
    status: p.status || 'approved',
    proposer: pub(userById(db, p.createdBy)) || { nickname: '已注销用户' },
    practiceCount: ps.length,
    doerCount: new Set(ps.map(x => x.authorId)).size
  });
}
function contestOut(c, db) {
  const now = Date.now();
  const status = now < c.startTime ? 'upcoming' : now > c.endTime ? 'ended' : 'ongoing';
  return Object.assign({}, c, {
    status,
    problemCount: (c.problems || []).length,
    submissionCount: (c.submissions || []).length,
    participantCount: (c.participants || []).length,
    creator: pub(userById(db, c.createdBy))
  });
}

function searchFilter(list, q, db) {
  if (!q) return list;
  const lq = String(q).toLowerCase();
  return list.filter(x =>
    String(x.title || '').toLowerCase().includes(lq) ||
    String(x.content || '').toLowerCase().includes(lq) ||
    String((userById(db, x.authorId) || {}).nickname || '').toLowerCase().includes(lq) ||
    (x.tags || []).some(t => String(t).toLowerCase().includes(lq))
  );
}

function validPassword(pw) {
  return typeof pw === 'string' && pw.length >= 8 && /[a-zA-Z]/.test(pw) && /[0-9]/.test(pw);
}

/* ---------------- 中间件 ---------------- */
async function auth(request, env, db) {
  const header = request.headers.get('Authorization') || '';
  const token = header.replace(/^Bearer\s+/i, '');
  const userId = await resolveToken(env, token);
  if (!userId) return null;
  return userById(db, userId);
}

/* ---------------- 路由匹配 ---------------- */
function match(path, pattern) {
  const ps = pattern.split('/').filter(Boolean);
  const as = path.split('/').filter(Boolean);
  if (ps.length !== as.length) return null;
  const params = {};
  for (let i = 0; i < ps.length; i++) {
    if (ps[i].startsWith(':')) params[ps[i].slice(1)] = as[i];
    else if (ps[i] !== as[i]) return null;
  }
  return params;
}

/* ---------------- 主处理器 ---------------- */
export async function onRequest(context) {
  const { request, env } = context;

  // OPTIONS 预检
  if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() });

  try {
    const db = await loadDB(env);
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/api/, '').replace(/^\/+/, '');
    const method = request.method;

    // ---- 认证 ----
    if (match(path, 'me') && method === 'GET') {
      const u = await auth(request, env, db);
      return json({ user: pub(u) });
    }

    // ---- 健康检查 ----
    if (match(path, 'health') && method === 'GET') {
      return json({ status: 'ok', users: db.users.length });
    }

    // ---- 注册 ----
    if (match(path, 'register') && method === 'POST') {
      const body = await request.json();
      const username = clean(body.username, 24);
      const nickname = clean(body.nickname, 24) || username;
      const password = body.password;
      if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) return bad('用户名需为 3-24 位字母、数字或下划线');
      if (!validPassword(password)) return bad('密码至少 8 位，且需同时包含字母和数字');
      if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase())) return bad('用户名已被占用');
      const { salt, hash } = await hashPassword(password);
      const user = { id: uid('u'), username, nickname, role: 'user', bio: '', createdAt: Date.now(), salt, hash };
      db.users.push(user);
      await saveDB(env);
      const token = await createToken(env, user.id);
      return json({ user: pub(user), token });
    }

    // ---- 登录 ----
    if (match(path, 'login') && method === 'POST') {
      const body = await request.json();
      const username = clean(body.username, 24);
      const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
      if (!user) return bad('用户名或密码错误');
      if (user.lockedUntil && Date.now() < user.lockedUntil) {
        const mins = Math.ceil((user.lockedUntil - Date.now()) / 60000);
        return bad(`该账号已因多次登录失败被锁定，请 ${mins} 分钟后再试`, 429);
      }
      if (user.salt === 'seed_salt_placeholder') {
        // 首次登录：初始化管理员密码
        const { salt, hash } = await hashPassword(body.password);
        user.salt = salt; user.hash = hash;
        await saveDB(env);
        user.loginFails = 0; user.lockedUntil = 0;
        const token = await createToken(env, user.id);
        return json({ user: pub(user), token });
      }
      if (!await verifyPassword(body.password || '', user)) {
        user.loginFails = (user.loginFails || 0) + 1;
        if (user.loginFails >= 5) {
          user.lockedUntil = Date.now() + 10 * 60000;
          user.loginFails = 0;
        }
        await saveDB(env);
        return bad('用户名或密码错误');
      }
      user.loginFails = 0; user.lockedUntil = 0;
      await saveDB(env);
      const token = await createToken(env, user.id);
      return json({ user: pub(user), token });
    }

    // ---- 登出 ----
    if (match(path, 'logout') && method === 'POST') {
      const header = request.headers.get('Authorization') || '';
      const token = header.replace(/^Bearer\s+/i, '');
      if (token) await deleteToken(env, token);
      return json({ ok: true });
    }

    // ---- 更新资料 ----
    if (match(path, 'me/profile') && method === 'PUT') {
      const u = await auth(request, env, db);
      if (!u) return bad('请先登录', 401);
      const body = await request.json();
      const nickname = clean(body.nickname, 24);
      if (nickname) u.nickname = nickname;
      u.bio = clean(body.bio, 200);
      await saveDB(env);
      return json({ user: pub(u) });
    }

    // ---- 修改密码 ----
    if (match(path, 'me/password') && method === 'PUT') {
      const u = await auth(request, env, db);
      if (!u) return bad('请先登录', 401);
      const body = await request.json();
      if (!await verifyPassword(body.oldPassword || '', u)) return bad('原密码错误');
      if (!validPassword(body.newPassword)) return bad('新密码至少 8 位，且需同时包含字母和数字');
      const { salt, hash } = await hashPassword(body.newPassword);
      u.salt = salt; u.hash = hash;
      await saveDB(env);
      return json({ ok: true });
    }

    // ---- 用户详情 ----
    let m = match(path, 'users/:id');
    if (m && method === 'GET') {
      const u = userById(db, m.id);
      if (!u) return bad('用户不存在', 404);
      const me = await auth(request, env, db);
      const articles = db.articles.filter(a => a.authorId === u.id && a.status === 'approved');
      const posts = db.posts.filter(p => p.authorId === u.id && p.status === 'approved');
      const likes = articles.reduce((s, a) => s + (a.likes || []).length, 0);
      const followerCount = db.users.filter(x => (x.following || []).includes(u.id)).length;
      const followingCount = (u.following || []).length;
      const isFollowing = !!(me && (me.following || []).includes(u.id));
      return json({
        user: pub(u),
        stats: { articles: articles.length, posts: posts.length, likes, followerCount, followingCount },
        isFollowing,
        articles: articles.sort((a, b) => b.createdAt - a.createdAt).map(a => articleOut(a, db))
      });
    }

    // ---- 关注/取消 ----
    m = match(path, 'users/:id/follow');
    if (m && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const t = userById(db, m.id);
      if (!t) return bad('用户不存在', 404);
      if (t.id === me.id) return bad('不能关注自己');
      me.following = me.following || [];
      const i = me.following.indexOf(t.id);
      if (i >= 0) me.following.splice(i, 1); else me.following.push(t.id);
      await saveDB(env);
      const followerCount = db.users.filter(x => (x.following || []).includes(t.id)).length;
      return json({ followed: i < 0, followerCount });
    }

    // ---- 首页 ----
    if (match(path, 'home') && method === 'GET') {
      const now = Date.now();
      return json({
        stats: {
          users: db.users.length,
          articles: db.articles.filter(a => a.status === 'approved').length,
          posts: db.posts.filter(p => p.status === 'approved').length,
          contests: db.contests.length
        },
        latestArticles: db.articles.filter(a => a.status === 'approved').sort((a, b) => b.createdAt - a.createdAt).slice(0, 6).map(a => articleOut(a, db)),
        latestPosts: db.posts.filter(p => p.status === 'approved').sort((a, b) => b.createdAt - a.createdAt).slice(0, 6).map(p => postOut(p, db)),
        activeContests: db.contests.filter(c => c.startTime <= now && now <= c.endTime).slice(0, 3)
      });
    }

    // ---- 文章列表 ----
    if (match(path, 'articles') && method === 'GET') {
      let list = db.articles.filter(a => a.status === 'approved');
      const cat = url.searchParams.get('category');
      const q = url.searchParams.get('q');
      const sort = url.searchParams.get('sort');
      if (cat) list = list.filter(a => (a.category || '其他') === cat);
      list = searchFilter(list, q, db);
      if (sort === 'hot') list.sort((a, b) => ((b.likes || []).length * 5 + b.views) - ((a.likes || []).length * 5 + a.views));
      else list.sort((a, b) => b.createdAt - a.createdAt);
      return json({ articles: list.map(a => articleOut(a, db)) });
    }

    // ---- 我的文章 ----
    if (match(path, 'articles/mine') && method === 'GET') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      return json({ articles: db.articles.filter(a => a.authorId === me.id).sort((a, b) => b.createdAt - a.createdAt).map(a => articleOut(a, db)) });
    }

    // ---- 文章详情 ----
    m = match(path, 'articles/:id');
    if (m && method === 'GET') {
      const a = db.articles.find(x => x.id === m.id);
      if (!a) return bad('文章不存在', 404);
      const me = await auth(request, env, db);
      const canView = a.status === 'approved' || (me && (me.id === a.authorId || me.role === 'admin'));
      if (!canView) return bad('文章正在审核中', 403);
      if (!me || me.id !== a.authorId) { a.views = (a.views || 0) + 1; await saveDB(env); }
      const o = articleOut(a, db);
      o.liked = !!(me && (a.likes || []).includes(me.id));
      return json({ article: o });
    }

    // ---- 创建文章 ----
    if (match(path, 'articles') && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const body = await request.json();
      const title = clean(body.title, 80);
      const content = clean(body.content, 50000);
      if (!title || !content) return bad('标题和内容不能为空');
      const category = ART_CATS.includes(body.category) ? body.category : '其他';
      const a = { id: uid('a'), authorId: me.id, title, content, category, status: 'pending', views: 0, likes: [], createdAt: Date.now() };
      db.articles.push(a);
      await saveDB(env);
      return json({ article: articleOut(a, db) });
    }

    // ---- 编辑文章 ----
    m = match(path, 'articles/:id');
    if (m && method === 'PUT') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const a = db.articles.find(x => x.id === m.id);
      if (!a || a.authorId !== me.id) return bad('文章不存在或无权限', 404);
      const body = await request.json();
      a.title = clean(body.title, 80) || a.title;
      a.content = clean(body.content, 50000) || a.content;
      if (ART_CATS.includes(body.category)) a.category = body.category;
      if (a.status !== 'approved') a.status = 'pending';
      await saveDB(env);
      return json({ article: articleOut(a, db) });
    }

    // ---- 删除文章 ----
    m = match(path, 'articles/:id');
    if (m && method === 'DELETE') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const i = db.articles.findIndex(x => x.id === m.id);
      if (i < 0) return bad('文章不存在', 404);
      if (db.articles[i].authorId !== me.id && me.role !== 'admin') return bad('无权限', 403);
      db.articles.splice(i, 1);
      await saveDB(env);
      return json({ ok: true });
    }

    // ---- 点赞 ----
    m = match(path, 'articles/:id/like');
    if (m && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const a = db.articles.find(x => x.id === m.id && x.status === 'approved');
      if (!a) return bad('文章不存在', 404);
      a.likes = a.likes || [];
      const i = a.likes.indexOf(me.id);
      if (i >= 0) a.likes.splice(i, 1); else a.likes.push(me.id);
      await saveDB(env);
      return json({ liked: i < 0, likeCount: a.likes.length });
    }

    // ---- 帖子列表 ----
    if (match(path, 'posts') && method === 'GET') {
      let list = db.posts.filter(p => p.status === 'approved');
      const cat = url.searchParams.get('category');
      const q = url.searchParams.get('q');
      if (cat) list = list.filter(p => (p.category || '其他') === cat);
      list = searchFilter(list, q, db);
      list.sort((a, b) => b.createdAt - a.createdAt);
      return json({ posts: list.map(p => postOut(p, db)) });
    }

    // ---- 我的帖子 ----
    if (match(path, 'posts/mine') && method === 'GET') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      return json({ posts: db.posts.filter(p => p.authorId === me.id).sort((a, b) => b.createdAt - a.createdAt).map(p => postOut(p, db)) });
    }

    // ---- 帖子详情 ----
    m = match(path, 'posts/:id');
    if (m && method === 'GET') {
      const p = db.posts.find(x => x.id === m.id);
      if (!p) return bad('帖子不存在', 404);
      const me = await auth(request, env, db);
      if (p.status !== 'approved' && !(me && (me.id === p.authorId || me.role === 'admin'))) {
        return bad('帖子正在审核中', 403);
      }
      const o = postOut(p, db);
      o.comments = (p.comments || []).map(c => withAuthor(c, db));
      return json({ post: o });
    }

    // ---- 创建帖子 ----
    if (match(path, 'posts') && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const body = await request.json();
      const title = clean(body.title, 80);
      const content = clean(body.content, 20000);
      if (!title || !content) return bad('标题和内容不能为空');
      const category = POST_CATS.includes(body.category) ? body.category : '其他';
      const p = { id: uid('p'), authorId: me.id, title, content, category, status: 'pending', createdAt: Date.now(), comments: [] };
      db.posts.push(p);
      await saveDB(env);
      return json({ post: postOut(p, db) });
    }

    // ---- 评论 ----
    m = match(path, 'posts/:id/comments');
    if (m && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const p = db.posts.find(x => x.id === m.id && x.status === 'approved');
      if (!p) return bad('帖子不存在', 404);
      const body = await request.json();
      const content = clean(body.content, 2000);
      if (!content) return bad('评论不能为空');
      const c = { id: uid('c'), authorId: me.id, content, createdAt: Date.now() };
      p.comments.push(c);
      await saveDB(env);
      return json({ comment: withAuthor(c, db) });
    }

    // ---- 删除帖子 ----
    m = match(path, 'posts/:id');
    if (m && method === 'DELETE') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const i = db.posts.findIndex(x => x.id === m.id);
      if (i < 0) return bad('帖子不存在', 404);
      if (db.posts[i].authorId !== me.id && me.role !== 'admin') return bad('无权限', 403);
      db.posts.splice(i, 1);
      await saveDB(env);
      return json({ ok: true });
    }

    // ---- 私信：发送 ----
    if (match(path, 'messages') && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const body = await request.json();
      const to = userById(db, body.toId);
      if (!to) return bad('用户不存在', 404);
      if (to.id === me.id) return bad('不能给自己发私信');
      const content = clean(body.content, 2000);
      if (!content) return bad('内容不能为空');
      const msg = { id: uid('m'), fromId: me.id, toId: to.id, content, createdAt: Date.now(), read: false };
      db.messages.push(msg);
      await saveDB(env);
      return json({ message: msg });
    }

    // ---- 私信：未读数 ----
    if (match(path, 'messages/unread') && method === 'GET') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      return json({ count: db.messages.filter(m => m.toId === me.id && !m.read).length });
    }

    // ---- 私信：会话列表 ----
    if (match(path, 'messages/conversations') && method === 'GET') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const map = new Map();
      for (const m of db.messages) {
        const partnerId = m.fromId === me.id ? m.toId : (m.toId === me.id ? m.fromId : null);
        if (!partnerId) continue;
        let c = map.get(partnerId);
        if (!c) { c = { partnerId, last: m, unread: 0 }; map.set(partnerId, c); }
        if (m.createdAt > c.last.createdAt) c.last = m;
        if (m.toId === me.id && !m.read) c.unread++;
      }
      const conversations = [...map.values()]
        .sort((a, b) => b.last.createdAt - a.last.createdAt)
        .map(c => ({
          partner: pub(userById(db, c.partnerId)),
          lastContent: c.last.content, lastTime: c.last.createdAt,
          lastFromMe: c.last.fromId === me.id, unread: c.unread
        }))
        .filter(c => c.partner);
      return json({ conversations });
    }

    // ---- 私信：与某人聊天 ----
    m = match(path, 'messages/with/:userId');
    if (m && method === 'GET') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const other = userById(db, m.userId);
      if (!other) return bad('用户不存在', 404);
      const list = db.messages
        .filter(x => (x.fromId === me.id && x.toId === other.id) || (x.fromId === other.id && x.toId === me.id))
        .sort((a, b) => a.createdAt - b.createdAt);
      let changed = false;
      for (const x of list) if (x.toId === me.id && !x.read) { x.read = true; changed = true; }
      if (changed) await saveDB(env);
      return json({ partner: pub(other), messages: list });
    }

    // ---- 排行榜 ----
    if (match(path, 'rank') && method === 'GET') {
      const rows = db.users.map(u => {
        const arts = db.articles.filter(a => a.authorId === u.id && a.status === 'approved');
        const posts = db.posts.filter(p => p.authorId === u.id && p.status === 'approved');
        const likes = arts.reduce((s, a) => s + (a.likes || []).length, 0);
        const comments = posts.reduce((s, p) => s + (p.comments || []).length, 0);
        const practices = db.practices.filter(x => x.authorId === u.id).length;
        const score = arts.length * 10 + posts.length * 5 + likes * 3 + comments * 2 + practices * 2;
        return { user: pub(u), score, articles: arts.length, posts: posts.length, likes, practices };
      }).filter(r => r.score > 0 || r.user.role === 'admin');
      rows.sort((a, b) => b.score - a.score);
      return json({ rank: rows.slice(0, 50) });
    }

    // ---- 比赛列表 ----
    if (match(path, 'contests') && method === 'GET') {
      return json({ contests: db.contests.slice().sort((a, b) => b.createdAt - a.createdAt).map(c => contestOut(c, db)) });
    }

    // ---- 比赛详情 ----
    m = match(path, 'contests/:id');
    if (m && method === 'GET') {
      const c = db.contests.find(x => x.id === m.id);
      if (!c) return bad('比赛不存在', 404);
      const o = contestOut(c, db);
      const me = await auth(request, env, db);
      o.joined = !!(me && (c.participants || []).includes(me.id));
      o.participantList = (c.participants || []).map(id => pub(userById(db, id))).filter(Boolean);
      delete o.participants;
      delete o.submissions;
      return json({ contest: o });
    }

    // ---- 创建比赛 ----
    if (match(path, 'contests') && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      if (me.role !== 'admin') return bad('需要管理员权限', 403);
      const body = await request.json();
      const title = clean(body.title, 80);
      const description = clean(body.description, 20000);
      const startTime = Number(body.startTime);
      const endTime = Number(body.endTime);
      if (!title || !description) return bad('标题和说明不能为空');
      if (!startTime || !endTime || endTime <= startTime) return bad('结束时间必须晚于开始时间');
      const rawProblems = Array.isArray(body.problems) ? body.problems : [];
      if (!rawProblems.length) return bad('至少需要布置一道题目');
      const problems = rawProblems.slice(0, 10).map(p => ({
        id: uid('q'),
        title: clean(p.title, 60),
        content: clean(p.content, 10000),
        wordLimit: Math.max(0, parseInt(p.wordLimit, 10) || 0)
      })).filter(p => p.title && p.content);
      if (!problems.length) return bad('每道题目的标题和内容不能为空');
      const c = { id: uid('c'), title, description, problems, startTime, endTime, createdBy: me.id, createdAt: Date.now(), participants: [], submissions: [] };
      db.contests.push(c);
      await saveDB(env);
      return json({ contest: contestOut(c, db) });
    }

    // ---- 报名比赛 ----
    m = match(path, 'contests/:id/join');
    if (m && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const c = db.contests.find(x => x.id === m.id);
      if (!c) return bad('比赛不存在', 404);
      if (Date.now() > c.endTime) return bad('比赛已结束');
      c.participants = c.participants || [];
      const i = c.participants.indexOf(me.id);
      if (i >= 0) c.participants.splice(i, 1); else c.participants.push(me.id);
      await saveDB(env);
      return json({ joined: i < 0, participantCount: c.participants.length });
    }

    // ---- 比赛提交作品 ----
    m = match(path, 'contests/:id/submit');
    if (m && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const c = db.contests.find(x => x.id === m.id);
      if (!c) return bad('比赛不存在', 404);
      if (Date.now() < c.startTime) return bad('比赛尚未开始');
      if (Date.now() > c.endTime) return bad('比赛已结束，无法提交');
      if (!(c.participants || []).includes(me.id)) return bad('请先报名比赛');
      const body = await request.json();
      const p = (c.problems || []).find(q => q.id === body.problemId);
      if (!p) return bad('题目不存在', 404);
      const title = clean(body.title, 80);
      const content = clean(body.content, 50000);
      if (!title || !content) return bad('标题和内容不能为空');
      const wordCount = content.replace(/\s/g, '').length;
      if (p.wordLimit > 0 && wordCount > p.wordLimit) return bad(`超出字数限制：当前 ${wordCount} 字 / 上限 ${p.wordLimit} 字`);
      c.submissions = c.submissions || [];
      let s = c.submissions.find(x => x.problemId === p.id && x.authorId === me.id);
      if (s) { s.title = title; s.content = content; s.wordCount = wordCount; s.updatedAt = Date.now(); }
      else { s = { id: uid('s'), problemId: p.id, authorId: me.id, title, content, wordCount, createdAt: Date.now() }; c.submissions.push(s); }
      await saveDB(env);
      return json({ submission: s });
    }

    // ---- 我的比赛提交 ----
    m = match(path, 'contests/:id/my-submissions');
    if (m && method === 'GET') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const c = db.contests.find(x => x.id === m.id);
      if (!c) return bad('比赛不存在', 404);
      return json({ submissions: (c.submissions || []).filter(s => s.authorId === me.id) });
    }

    // ---- 管理员：比赛提交列表 ----
    m = match(path, 'contests/:id/submissions');
    if (m && method === 'GET') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      if (me.role !== 'admin') return bad('需要管理员权限', 403);
      const c = db.contests.find(x => x.id === m.id);
      if (!c) return bad('比赛不存在', 404);
      return json({
        problems: c.problems || [],
        submissions: (c.submissions || []).map(s => { const o = withAuthor(s, db); delete o.content; return o; })
      });
    }

    // ---- 删除比赛 ----
    m = match(path, 'contests/:id');
    if (m && method === 'DELETE') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      if (me.role !== 'admin') return bad('需要管理员权限', 403);
      const i = db.contests.findIndex(x => x.id === m.id);
      if (i < 0) return bad('比赛不存在', 404);
      db.contests.splice(i, 1);
      await saveDB(env);
      return json({ ok: true });
    }

    // ---- 题库列表 ----
    if (match(path, 'problems') && method === 'GET') {
      let list = db.problems.filter(p => (p.status || 'approved') === 'approved');
      const type = url.searchParams.get('type');
      const diff = url.searchParams.get('difficulty');
      const tag = url.searchParams.get('tag');
      const q = url.searchParams.get('q');
      if (['theme', 'skill'].includes(type)) list = list.filter(p => p.type === type);
      if (diff) list = list.filter(p => p.difficulty === Number(diff));
      if (tag) list = list.filter(p => (p.tags || []).includes(tag));
      list = searchFilter(list, q, db);
      list.sort((a, b) => b.createdAt - a.createdAt);
      return json({ problems: list.map(p => problemOut(p, db)) });
    }

    // ---- 题目详情 ----
    m = match(path, 'problems/:id');
    if (m && method === 'GET') {
      const p = db.problems.find(x => x.id === m.id);
      if (!p) return bad('题目不存在', 404);
      const me = await auth(request, env, db);
      if ((p.status || 'approved') !== 'approved' && !(me && (me.id === p.createdBy || me.role === 'admin'))) {
        return bad('题目正在审核中', 403);
      }
      const practices = db.practices.filter(x => x.problemId === p.id).sort((a, b) => b.createdAt - a.createdAt);
      const mine = me ? practices.find(x => x.authorId === me.id) || null : null;
      return json({
        problem: problemOut(p, db),
        myPractice: mine,
        practices: practices.slice(0, 50).map(x => { const o = withAuthor(x, db); delete o.content; return o; })
      });
    }

    // ---- 创建题目 ----
    if (match(path, 'problems') && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const body = await request.json();
      const title = clean(body.title, 80);
      const content = clean(body.content, 10000);
      const type = body.type === 'skill' ? 'skill' : 'theme';
      const difficulty = Math.min(6, Math.max(1, parseInt(body.difficulty, 10) || 1));
      const tags = Array.isArray(body.tags) ? body.tags.map(t => clean(t, 12)).filter(Boolean).slice(0, 5) : [];
      if (!title || !content) return bad('题目标题和内容不能为空');
      const isAdmin = me.role === 'admin';
      const p = { id: uid('q'), type, title, content, difficulty, tags, createdBy: me.id, createdAt: Date.now(), status: isAdmin ? 'approved' : 'pending' };
      db.problems.push(p);
      await saveDB(env);
      return json({ problem: problemOut(p, db) });
    }

    // ---- 删除题目 ----
    m = match(path, 'problems/:id');
    if (m && method === 'DELETE') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      if (me.role !== 'admin') return bad('需要管理员权限', 403);
      const i = db.problems.findIndex(x => x.id === m.id);
      if (i < 0) return bad('题目不存在', 404);
      db.practices = db.practices.filter(x => x.problemId !== m.id);
      db.problems.splice(i, 1);
      await saveDB(env);
      return json({ ok: true });
    }

    // ---- 提交练习 ----
    m = match(path, 'problems/:id/practice');
    if (m && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const p = db.problems.find(x => x.id === m.id);
      if (!p) return bad('题目不存在', 404);
      if ((p.status || 'approved') !== 'approved') return bad('题目尚未通过审核');
      const body = await request.json();
      const title = clean(body.title, 80);
      const content = clean(body.content, 50000);
      if (!title || !content) return bad('标题和内容不能为空');
      const wordCount = content.replace(/\s/g, '').length;
      let s = db.practices.find(x => x.problemId === p.id && x.authorId === me.id);
      if (s) { s.title = title; s.content = content; s.wordCount = wordCount; s.updatedAt = Date.now(); }
      else { s = { id: uid('r'), problemId: p.id, authorId: me.id, title, content, wordCount, createdAt: Date.now() }; db.practices.push(s); }
      await saveDB(env);
      return json({ practice: s });
    }

    // ---- 查看单个练习 ----
    m = match(path, 'problems/:id/practice/:prId');
    if (m && method === 'GET') {
      const s = db.practices.find(x => x.id === m.prId && x.problemId === m.id);
      if (!s) return bad('练习不存在', 404);
      return json({ practice: withAuthor(s, db) });
    }

    // ---- 我的练习 ----
    m = match(path, 'problems/:id/my-practice');
    if (m && method === 'GET') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const s = db.practices.find(x => x.problemId === m.id && x.authorId === me.id);
      return json({ practice: s || null });
    }

    // ---- 文件上传 ----
    if (match(path, 'files') && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const formData = await request.formData();
      const file = formData.get('file');
      const note = clean(formData.get('note') || '', 200);
      if (!file) return bad('请选择文件');
      if (file.size > 20 * 1024 * 1024) return bad('文件不能超过 20MB');
      const ALLOW_EXT = ['.txt', '.md', '.doc', '.docx', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.webp',
        '.zip', '.rar', '.7z', '.ppt', '.pptx', '.xls', '.xlsx', '.csv', '.mp3', '.mp4'];
      const originalName = file.name;
      const ext = originalName.slice(originalName.lastIndexOf('.')).toLowerCase();
      if (!ALLOW_EXT.includes(ext)) return bad('不允许上传该类型的文件');
      // 文件存入 KV（base64）
      const fileId = uid('f');
      const arrayBuf = await file.arrayBuffer();
      const base64 = new Uint8Array(arrayBuf).reduce((a, b) => a + String.fromCharCode(b), '');
      const storedName = fileId + ext.slice(0, 10);
      await env.DATA.put('file:' + storedName, btoa(base64));
      const f = { id: fileId, authorId: me.id, originalName, storedName, size: file.size, note, status: 'pending', createdAt: Date.now() };
      db.files.push(f);
      await saveDB(env);
      return json({ file: withAuthor(f, db) });
    }

    // ---- 我的文件 ----
    if (match(path, 'files/mine') && method === 'GET') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      return json({ files: db.files.filter(f => f.authorId === me.id).sort((a, b) => b.createdAt - a.createdAt).map(f => withAuthor(f, db)) });
    }

    // ---- 文件下载 ----
    m = match(path, 'files/:id/download');
    if (m && method === 'GET') {
      const me = await auth(request, env, db);
      if (!me) return bad('请先登录', 401);
      const f = db.files.find(x => x.id === m.id);
      if (!f) return bad('文件不存在', 404);
      if (f.authorId !== me.id && me.role !== 'admin') return bad('无权限下载', 403);
      const b64 = await env.DATA.get('file:' + f.storedName);
      if (!b64) return bad('文件已丢失', 404);
      const binary = atob(b64);
      const arr = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) arr[i] = binary.charCodeAt(i);
      const mime = guessMime(f.storedName);
      return new Response(arr, {
        headers: {
          'Content-Type': mime,
          'Content-Disposition': `attachment; filename="${encodeURIComponent(f.originalName)}"`,
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    function guessMime(name) {
      const e = name.slice(name.lastIndexOf('.') + 1).toLowerCase();
      return {
        txt: 'text/plain', md: 'text/markdown',
        doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        pdf: 'application/pdf',
        png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp',
        zip: 'application/zip', rar: 'application/x-rar-compressed', '7z': 'application/x-7z-compressed',
        ppt: 'application/vnd.ms-powerpoint', pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        csv: 'text/csv', mp3: 'audio/mpeg', mp4: 'video/mp4'
      }[e] || 'application/octet-stream';
    }

    // ---- 后台审核：文章列表 ----
    m = match(path, 'admin/articles');
    if (m && method === 'GET') {
      const me = await auth(request, env, db);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const status = ['pending', 'approved', 'rejected'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : 'pending';
      return json({ articles: db.articles.filter(a => a.status === status).sort((a, b) => b.createdAt - a.createdAt).map(a => articleOut(a, db)) });
    }

    // ---- 审核文章 ----
    m = match(path, 'admin/articles/:id/review');
    if (m && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const body = await request.json();
      const a = db.articles.find(x => x.id === m.id);
      if (!a) return bad('文章不存在', 404);
      a.status = body.action === 'approve' ? 'approved' : 'rejected';
      a.reviewedAt = Date.now();
      await saveDB(env);
      return json({ ok: true, status: a.status });
    }

    // ---- 后台审核：帖子列表 ----
    m = match(path, 'admin/posts');
    if (m && method === 'GET') {
      const me = await auth(request, env, db);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const status = ['pending', 'approved', 'rejected'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : 'pending';
      return json({ posts: db.posts.filter(p => p.status === status).sort((a, b) => b.createdAt - a.createdAt).map(p => postOut(p, db)) });
    }

    // ---- 审核帖子 ----
    m = match(path, 'admin/posts/:id/review');
    if (m && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const body = await request.json();
      const p = db.posts.find(x => x.id === m.id);
      if (!p) return bad('帖子不存在', 404);
      p.status = body.action === 'approve' ? 'approved' : 'rejected';
      p.reviewedAt = Date.now();
      await saveDB(env);
      return json({ ok: true, status: p.status });
    }

    // ---- 后台审核：文件列表 ----
    m = match(path, 'admin/files');
    if (m && method === 'GET') {
      const me = await auth(request, env, db);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const status = ['pending', 'approved', 'rejected'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : 'pending';
      return json({ files: db.files.filter(f => f.status === status).sort((a, b) => b.createdAt - a.createdAt).map(f => withAuthor(f, db)) });
    }

    // ---- 审核文件 ----
    m = match(path, 'admin/files/:id/review');
    if (m && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const body = await request.json();
      const f = db.files.find(x => x.id === m.id);
      if (!f) return bad('文件不存在', 404);
      f.status = body.action === 'approve' ? 'approved' : 'rejected';
      f.reviewedAt = Date.now();
      await saveDB(env);
      return json({ ok: true, status: f.status });
    }

    // ---- 后台审核：题目列表 ----
    m = match(path, 'admin/problems');
    if (m && method === 'GET') {
      const me = await auth(request, env, db);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const status = ['pending', 'approved', 'rejected'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : 'pending';
      return json({ problems: db.problems.filter(p => (p.status || 'approved') === status).sort((a, b) => b.createdAt - a.createdAt).map(p => problemOut(p, db)) });
    }

    // ---- 审核题目 ----
    m = match(path, 'admin/problems/:id/review');
    if (m && method === 'POST') {
      const me = await auth(request, env, db);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const body = await request.json();
      const p = db.problems.find(x => x.id === m.id);
      if (!p) return bad('题目不存在', 404);
      p.status = body.action === 'approve' ? 'approved' : 'rejected';
      p.reviewedAt = Date.now();
      await saveDB(env);
      return json({ ok: true, status: p.status });
    }

    // ---- 404 ----
    return bad('接口不存在: ' + path + ' ' + method, 404);

  } catch (err) {
    return bad('服务器内部错误: ' + (err.message || String(err)), 500);
  }
}
