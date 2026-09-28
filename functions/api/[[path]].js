/*
 * Cloudflare Pages Functions - 文洛·文章竞赛社区 完整 API
 * 数据存储：Cloudflare KV (DATA)
 * 认证方式：Bearer Token（KV 存储 token→userId）
 * 密码哈希：Web Crypto API PBKDF2 (100000次 + SHA-256 + 16字节随机salt)
 * 安全加固：XSS清洗/CSP头/密码复杂度/登录锁定/速率限制/文件白名单/Token强随机
 */

/* ---------------- 工具函数 ---------------- */
const uid = (p) => p + '_' + Math.random().toString(36).slice(2, 11) + cryptoRandomHex(6);
const cryptoRandomHex = (n) => {
  const arr = new Uint8Array(n); crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
};
const bad = (msg, status = 400) => new Response(JSON.stringify({ error: String(msg).slice(0, 200) }), { status, headers: securityHeaders() });
const json = (data, status = 200, extraHeaders = {}) => new Response(JSON.stringify(data), { status, headers: { ...securityHeaders(), ...extraHeaders } });

/* 安全响应头（CSP 防XSS / HSTS / 禁止嗅探 / 防点击劫持） */
function securityHeaders() {
  return {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
  };
}

/* 输入清洗：trim + 长度限制 + 剥离 HTML标签 + 剥离危险 Markdown */
const clean = (s, max) => {
  const str = String(s == null ? '' : s).trim();
  let out = str.slice(0, max || 20000);
  out = out.replace(/<[^>]*>/g, '');
  out = out.replace(/`[^`]*`([\s\S]*)?/g, (m) => m.includes('javascript:') ? '' : m);
  out = out.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
  return out;
};
/* 安全 JSON 解析，失败返回默认值 */
const safeJSON = (s, def = []) => { try { return JSON.parse(s); } catch { return def; } };

/* 文件扩展名白名单（只允许安全的文档类型） */
const ALLOWED_FILE_EXT = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'md', 'csv', 'rtf', 'zip'];
function isAllowedFile(name) {
  const m = (name || '').toLowerCase().match(/\.([a-z0-9]+)$/);
  return m && ALLOWED_FILE_EXT.includes(m[1]);
}
const MAX_FILE_SIZE = 20 * 1024 * 1024; // 20MB

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



/* ---------------- D1 Token 管理 ---------------- */
async function createToken(env, userId) {
  const token = 'tk_' + uid('') + crypto.getRandomValues(new Uint8Array(8)).reduce((a, b) => a + b.toString(16).padStart(2, '0'), '');
  const expiresAt = Math.floor(Date.now() / 1000) + 7 * 86400;
  if (env.DB) {
    try { await env.DB.prepare('INSERT INTO tokens (token, user_id, expires_at) VALUES (?,?,?)').bind(token, userId, expiresAt).run(); } catch {}
  }
  return token;
}
async function resolveToken(env, token) {
  if (!token || !env.DB) return null;
  const pure = token.startsWith('tk_') ? token : token.replace(/^Bearer\s+/i, '');
  try {
    const row = await env.DB.prepare('SELECT user_id FROM tokens WHERE token = ? AND expires_at > ?').bind(pure, Math.floor(Date.now() / 1000)).first();
    return row ? row.user_id : null;
  } catch { return null; }
}
async function deleteToken(env, token) {
  if (!env.DB) return;
  const pure = token.startsWith('tk_') ? token : token.replace(/^Bearer\s+/i, '');
  try { await env.DB.prepare('DELETE FROM tokens WHERE token = ?').bind(pure).run(); } catch {}
}

/* ---------------- D1 数据库访问层 ---------------- */
// D1 是主存储；内存 _cache 用于快速读（兼容旧端点 db.users.find(...)）
// 所有写端点：先写 D1 (SQL)，再同步更新内存 _cache

const CACHED_TABLES = ['users', 'tokens', 'articles', 'posts', 'contests', 'messages', 'files',
  'problems', 'practices', 'reviews', 'checkins', 'templates', 'comments', 'favorites', 'notifications'];

let _cache = null;

// 分别检查每张表是否为空，分别补种子
async function ensureSeedData(env) {
  const now = Date.now();

  // 自动建表（幂等，已有表不会重复创建）
  try {
    await dbRun(env, `CREATE TABLE IF NOT EXISTS comments (
      id TEXT PRIMARY KEY, target_type TEXT NOT NULL, target_id TEXT NOT NULL,
      parent_id TEXT DEFAULT NULL, author_id TEXT NOT NULL,
      content TEXT NOT NULL, likes TEXT DEFAULT '[]', created_at INTEGER
    )`);
    await dbRun(env, `CREATE INDEX IF NOT EXISTS idx_comments_target ON comments(target_type, target_id)`);
    await dbRun(env, `CREATE INDEX IF NOT EXISTS idx_comments_parent ON comments(parent_id)`);

    // 收藏夹
    await dbRun(env, `CREATE TABLE IF NOT EXISTS favorites (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL, item_type TEXT NOT NULL, item_id TEXT NOT NULL, created_at INTEGER
    )`);
    await dbRun(env, `CREATE UNIQUE INDEX IF NOT EXISTS idx_fav_unique ON favorites(user_id, item_type, item_id)`);

    // 通知
    await dbRun(env, `CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL, type TEXT, from_id TEXT,
      target_type TEXT, target_id TEXT, content TEXT, read INTEGER DEFAULT 0, created_at INTEGER
    )`);
    await dbRun(env, `CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, read)`);

    // articles 加 tags 列（如果不存在）
    try { await dbRun(env, `ALTER TABLE articles ADD COLUMN tags TEXT DEFAULT '[]'`); } catch {}
    // users 加 email 列
    try { await dbRun(env, `ALTER TABLE users ADD COLUMN email TEXT`); } catch {}
    try { await dbRun(env, `ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0`); } catch {}
    // reset_tokens 表
    await dbRun(env, `CREATE TABLE IF NOT EXISTS reset_tokens (
      token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL
    )`);
  } catch {}

  // Admin 用户（如果没的话）
  let uc = (await dbFirst(env, 'SELECT COUNT(*) as c FROM users'))?.c || 0;
  if (uc === 0) {
    const pw = await hashPassword('admin123');
    await dbRun(env, `INSERT INTO users (id,username,nickname,role,bio,created_at,salt,hash,login_fails,locked_until,score,badges,following) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      ['u_admin', 'admin', '站务管理员', 'admin', '本站管理员，负责文章、帖子与投稿审核。', now, pw.salt, pw.hash, 0, 0, 0, '[]', '[]']);
  }

  // 欢迎文章
  let ac = (await dbFirst(env, 'SELECT COUNT(*) as c FROM articles'))?.c || 0;
  if (ac === 0) {
    await dbRun(env, `INSERT INTO articles (id,author_id,title,content,category,status,views,likes,created_at,reviewed_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
      ['a_welcome', 'u_admin', '欢迎来到文洛 · 文章竞赛社区',
       '## 这里可以做什么\n\n- **写文章**：点击侧边栏「我的文章」或主页「立即开始创作」。\n- **逛论坛**：在「论坛广场」发帖交流。\n- **打比赛**：在「比赛广场」报名参赛。\n\n祝大家玩得开心！',
       '其他', 'approved', 128, '[]', now - 86400000, now - 86000000]);
  }

  // 新人报到帖
  let pc = (await dbFirst(env, 'SELECT COUNT(*) as c FROM posts'))?.c || 0;
  if (pc === 0) {
    await dbRun(env, `INSERT INTO posts (id,author_id,title,content,category,status,created_at,comments) VALUES (?,?,?,?,?,?,?,?)`,
      ['p_hello', 'u_admin', '【置顶】新人报到帖', '新来的同学在这里打个招呼吧！', '其他', 'approved', now - 43200000, '[]']);
  }

  // Demo 比赛
  let cc = (await dbFirst(env, 'SELECT COUNT(*) as c FROM contests'))?.c || 0;
  if (cc === 0) {
    await dbRun(env, `INSERT INTO contests (id,title,description,problems,start_time,end_time,created_by,created_at,participants,submissions) VALUES (?,?,?,?,?,?,?,?,?,?)`,
      ['c_demo', '第一届「文洛杯」短文创作赛', '## 比赛说明\n\n围绕主题「代码与生活」写短文。',
       JSON.stringify([
         { id: 'q_demo1', title: '主题创作', content: '围绕比赛主题作文', wordLimit: 2000 },
         { id: 'q_demo2', title: '自由发挥', content: '题材不限', wordLimit: 2000 }
       ]),
       now - 3600000, now + 7 * 86400000, 'u_admin', now - 7200000, '[]', '[]']);
  }

  // 题库（只在空表时插）
  let qc = (await dbFirst(env, 'SELECT COUNT(*) as c FROM problems'))?.c || 0;
  if (qc === 0) {
    const seedProblems = [
      ['q_t1', 'theme', '以「时光」为题，写一篇文章', '## 要求\n\n- 体裁不限，围绕时光流逝展开\n- 建议字数 600-1500 字', 2, JSON.stringify(['记叙','抒情']), 'u_admin', now - 86400000, 'approved'],
      ['q_t2', 'theme', '以「窗外」为题描写一个熟悉场景', '## 要求\n\n- 选择一个你观察过的场景\n- 至少运用两种感官描写', 1, JSON.stringify(['写景','观察']), 'u_admin', now - 86400000, 'approved'],
      ['q_t3', 'theme', '以「选择」为题写一次难忘的抉择', '## 要求\n\n- 写清楚两难在哪里、为什么这样选', 3, JSON.stringify(['记叙','成长']), 'u_admin', now - 86400000, 'approved'],
      ['q_t4', 'theme', '科幻微小说：一百年后的世界', '## 要求\n\n- 微型小说，完整小故事\n- 1000 字以内', 4, JSON.stringify(['科幻','小说']), 'u_admin', now - 86400000, 'approved'],
      ['q_t5', 'theme', '以「灯」为题', '## 要求\n\n- 灯在文中承担象征意义', 3, JSON.stringify(['象征','散文']), 'u_admin', now - 86400000, 'approved'],
      ['q_t6', 'skill', '用排比写一段风景', '## 要求\n\n- 150-300 字，至少一组三句以上排比', 2, JSON.stringify(['排比','写景']), 'u_admin', now - 86400000, 'approved'],
      ['q_t7', 'skill', '用比喻描写「时间」', '## 要求\n\n- 3 个以上比喻句，不许用常见比喻', 1, JSON.stringify(['比喻','修辞']), 'u_admin', now - 86400000, 'approved'],
      ['q_t8', 'skill', '不用「哭」字写悲伤', '## 要求\n\n- 100-200 字，禁止出现哭/泪/难过/伤心', 3, JSON.stringify(['细节描写']), 'u_admin', now - 86400000, 'approved']
    ];
    for (const p of seedProblems) {
      await dbRun(env, `INSERT INTO problems (id,type,title,content,difficulty,tags,created_by,created_at,status) VALUES (?,?,?,?,?,?,?,?,?)`, p);
    }
  }

  // 模板（只在空表时插）
  let tc = (await dbFirst(env, 'SELECT COUNT(*) as c FROM templates'))?.c || 0;
  if (tc === 0) {
    const seedTemplates = [
      ['t_argue', '议论文五段式', '议论文', '经典五段式结构', '# 议论文五段式\n\n1.引入 2.分论点一 3.分论点二 4.反面论证 5.总结', now],
      ['t_story', '短篇小说起承转合', '小说', '适合 1500-3000 字短故事', '# 起承转合\n\n起15%→承35%→转30%→合20%', now],
      ['t_poem', '现代自由诗', '诗歌', '注重意象和节奏', '# 自由诗\n\n1.核心意象 2.切入 3.展开 4.留白', now],
      ['t_narrative', '记叙文六要素', '记叙文', '清晰完整', '# 六要素\n\n时间/地点/人物/起因/经过/结果', now],
      ['t_essay', '随笔散文', '随笔', '形散神不散', '# 随笔框架\n\n触发→联想→收束', now],
      ['t_ai', 'AI 辅助写作', '其他', 'AI 省时间但保持创作主体', '# AI 辅助\n\n大纲/润色/资料可用，不要整篇复制', now]
    ];
    for (const t of seedTemplates) {
      await dbRun(env, `INSERT INTO templates (id,title,category,description,content,created_at) VALUES (?,?,?,?,?,?)`, t);
    }
  }
}

async function loadDB(env) {
  if (_cache) return _cache;
  try { await ensureSeedData(env); } catch {}
  _cache = {};
  for (const t of CACHED_TABLES) {
    try { _cache[t] = await dbAll(env, `SELECT * FROM ${t}`); }
    catch { _cache[t] = []; }
  }
  return _cache;
}

/* 列名缓存（PRAGMA 只查一次） */
let _tableCols = null;
async function getTableCols(env, table) {
  if (!_tableCols) _tableCols = {};
  if (_tableCols[table]) return _tableCols[table];
  try {
    const r = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
    _tableCols[table] = r.results.map(c => c.name);
  } catch {
    _tableCols[table] = [];
  }
  return _tableCols[table];
}
const camelToSnake = s => s.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase();

/* 把内存中的行（camelCase）转成 SQL bind 值 */
function rowToBinds(row, cols) {
  return cols.map(c => {
    const v = row[camelToSnake(c)] ?? row[c];
    if (v === undefined || v === null) return null;
    if (Array.isArray(v) || (typeof v === 'object' && v !== null)) return JSON.stringify(v);
    return v;
  });
}

/* 全量保存：内存 _cache → D1（逐表 DELETE + INSERT） */
async function saveDB(env) {
  if (!_cache || !env.DB) return;
  for (const table of CACHED_TABLES) {
    const rows = _cache[table];
    if (!rows || rows.length === 0) {
      try { await env.DB.prepare(`DELETE FROM ${table}`).run(); } catch {}
      continue;
    }
    const cols = await getTableCols(env, table);
    if (!cols.length) continue;
    // 清空再全量写入（简单可靠）
    await env.DB.prepare(`DELETE FROM ${table}`).run();
    const colStr = cols.join(',');
    const ph = cols.map(() => '?').join(',');
    // 逐条 INSERT（D1 batch 最多 100 条，这里量小）
    for (const row of rows) {
      const binds = rowToBinds(row, cols);
      try { await env.DB.prepare(`INSERT INTO ${table} (${colStr}) VALUES (${ph})`).bind(...binds).run(); } catch {}
    }
  }
}

// 迁移端点用：从旧 KV 读取完整 JSON（用于一次性灌入 D1）
async function loadOldKV(env) {
  try {
    const raw = await env.DATA.get('database');
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}
function toCamel(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    const ck = k.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
    if (typeof v === 'string' && (v.startsWith('[') || v.startsWith('{'))) {
      try { out[ck] = JSON.parse(v); continue; } catch {}
    }
    out[ck] = v;
  }
  return out;
}
async function dbFirst(env, sql, binds = []) {
  if (!env.DB) return null;
  try {
    const r = await env.DB.prepare(sql).bind(...binds).first();
    return r ? toCamel(r) : null;
  } catch { return null; }
}
async function dbAll(env, sql, binds = []) {
  if (!env.DB) return [];
  try {
    const r = await env.DB.prepare(sql).bind(...binds).all();
    return (r.results || []).map(toCamel);
  } catch { return []; }
}
async function dbRun(env, sql, binds = []) {
  if (!env.DB) return null;
  try { return await env.DB.prepare(sql).bind(...binds).run(); } catch { return null; }
}

/* ---------------- 辅助函数 ---------------- */
const pub = (u) => {
  if (!u) return null;
  return {
    id: u.id,
    username: u.username,
    nickname: u.nickname,
    role: u.role,
    bio: u.bio || '',
    createdAt: u.createdAt
  };
};
function pubFull(u) {
  if (!u) return null;
  return {
    ...pub(u),
    badges: u.badges || [],
    following: u.following || [],
    score: u.score || 0
  };
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// userById: 从 D1 查询
async function userById(env, id) {
  return dbFirst(env, 'SELECT * FROM users WHERE id = ?', [id]);
}
// userById 同步版：从内存 _cache 找（推荐，已经 loadDB 预加载了）
function userByIdSync(db, id) {
  if (!db || !db.users) return null;
  return db.users.find(u => u.id === id) || null;
}
function withAuthorSync(db, item) {
  const a = userByIdSync(db, item.authorId);
  return { ...item, author: pub(a) || { nickname: '已注销用户' } };
}
function articleOut(a, db) {
  const o = withAuthorSync(db, a);
  o.likeCount = (a.likes || []).length;
  o.tags = typeof a.tags === 'string' ? safeJSON(a.tags) : (a.tags || []);
  delete o.likes;
  return o;
}
function postOut(p, db) {
  const o = withAuthorSync(db, p);
  o.commentCount = (p.comments || []).length;
  return o;
}
function problemOut(p, db) {
  const ps = db.practices.filter(x => x.problemId === p.id);
  return Object.assign({}, p, {
    status: p.status || 'approved',
    proposer: pub(userByIdSync(db, p.createdBy)) || { nickname: '已注销用户' },
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
    creator: pub(userByIdSync(db, c.createdBy))
  });
}

function searchFilter(list, q, db) {
  if (!q) return list;
  const lq = String(q).toLowerCase();
  return list.filter(x =>
    String(x.title || '').toLowerCase().includes(lq) ||
    String(x.content || '').toLowerCase().includes(lq) ||
    String((userByIdSync(db, x.authorId) || {}).nickname || '').toLowerCase().includes(lq) ||
    (x.tags || []).some(t => String(t).toLowerCase().includes(lq))
  );
}

function validPassword(pw) {
  return typeof pw === 'string' && pw.length >= 8 && /[a-zA-Z]/.test(pw) && /[0-9]/.test(pw);
}

/* 简单作者信息（点评等场景用） */
function withAuthorSimple(id, db) {
  const u = userByIdSync(db, id);
  if (!u) return { nickname: '已注销用户' };
  return { id: u.id, nickname: u.nickname, role: u.role };
}

/* 更新用户积分（加 delta） */
function updateUserScore(userId, delta, reason) {
  const u = _cache.users.find(x => x.id === userId);
  if (!u) return;
  u.score = (u.score || 0) + delta;
}

/* 发勋章（去重） */
function awardBadge(userId, name, reason) {
  const u = _cache.users.find(x => x.id === userId);
  if (!u) return;
  if (!Array.isArray(u.badges)) u.badges = [];
  if (u.badges.find(b => b.name === name)) return;
  u.badges.push({ name, reason, earnedAt: Date.now() });
}

/* AI 写作助手：优先调用 Workers AI，失败则用精心设计的本地 fallback */
async function aiAssist(env, task, { topic, content, style, extra }) {
  const topicStr = topic || '';
  const contentStr = content || '';
  const styleStr = style || '';
  const extraStr = extra || '';

  // 尝试 Workers AI
  try {
    if (env && env.AI) {
      const prompt = buildAiPrompt(task, topicStr, contentStr, styleStr, extraStr);
      const resp = await env.AI.run('@cloudflare/llama-3.2-1b-instruct', {
        prompt, max_tokens: 800
      });
      const text = resp && resp.response ? resp.response.trim() : '';
      if (text && text.length > 5) {
        return { result: text, source: 'ai' };
      }
    }
  } catch (e) { /* AI 不可用时 fallback */ }

  // Fallback：本地精心设计的回复模板
  return { result: aiFallback(task, topicStr, contentStr, styleStr), source: 'template' };
}

function buildAiPrompt(task, topic, content, style, extra) {
  const sys = '你是一个专业的中文写作助手，帮助用户提高写作能力。用中文简洁回答。';
  const tasks = {
    outline: `请为这个写作主题生成一个详细的大纲：\n主题：${topic}\n${style ? `风格：${style}\n` : ''}${extra ? `要求：${extra}\n` : ''}请用 Markdown 格式输出，包含 3-5 个主要部分，每个部分 2-3 个要点。`,
    rewrite: `请润色以下这段文字，让它更${style || '流畅、生动'}：\n\n${content}\n\n润色后的版本：`,
    continue: `请续写以下内容，保持文风一致：\n\n${content}\n\n续写部分：`,
    review: `请以语文老师的角度，对以下文章进行点评。给出：1）总体评价（星级）；2）亮点；3）改进建议。\n\n${content}\n\n点评：`
  };
  return `${sys}\n\n${tasks[task] || tasks.outline}`;
}

function aiFallback(task, topic, content, style) {
  switch (task) {
    case 'outline': {
      const cat = style || '议论文';
      return `## 《${topic || '未命名'}》写作大纲

### 一、引入（开头）
- 用一个生动的场景 / 一句名言 / 一个反问引出主题
- 直接点明你的中心观点或文章走向
- 建议字数：全文的 10-15%

### 二、主体展开（中间 60-70%）
**段落 1 · 第一个分论点 / 场景**
- 核心意思：……
- 可以用的素材：自己的经历 / 观察 / 阅读积累

**段落 2 · 第二个分论点 / 场景**
- 核心意思：……
- 可以用的素材：……

**段落 3 · 转折 / 深入（可选）**
- 换一个角度看问题
- 或者从反面论证

### 三、收尾（结尾）
- 把上面的内容收一下
- 可以联系现实、展望未来、或者用一个有画面感的结尾
- 最后一句尽量给读者留下思考

---
💡 **小贴士**：先把每个部分的关键词写下来，再往里填肉，会比从头到尾硬写轻松很多！`;
    }
    case 'rewrite': {
      const c = content.slice(0, 150);
      return `## 润色建议

你这段文字的基础很好！给你几个方向：

### 1. 让句子更有节奏感
把长句拆成短句，或者用排比制造韵律。比如把"我走在那条被落叶覆盖的小路上，心里想着那些年我们一起度过的日子"改成——

> 我走在那条小路上。
> 落叶铺得很厚，踩上去沙沙作响。
> 那些年的日子，就这么一页一页地翻了过来。

### 2. 加入具体的感官细节
现在的描写偏概括，可以加：看到的（颜色、光影）、听到的（声音）、闻到的（气味）、摸到的（触感）。

### 3. 检查动词
把"是""有""在"这类弱动词换成更有画面感的词。

---
📝 **润色后版本参考**（基于你提供的片段）：

> ${c || '（请提供要润色的文字，我帮你逐句打磨）'}

写好后再来让我帮你改第二遍！`;
    }
    case 'continue': {
      return `## 续写提示

你提供的前文给了我这些线索，我来帮你往不同方向推：

### 方向 A · 延续情绪
如果前文是平静的，让情绪慢慢升温；如果前文紧张，让它再紧一下然后突然释放。

### 方向 B · 引入新元素
突然出现一个人、一件事、一个回忆，打破当前的状态。

### 方向 C · 时间跳跃
跳到三天后、十年后，从另一个时间点回头看这件事。

### 续写段落参考
${content ? `（基于你写的内容）\n\n> ${content.slice(-80)}……风停了。我站在原地，突然觉得好像有什么东西不一样了。街道还是那条街道，路灯还是那盏路灯，可是我知道，有些事回不去了。` : '（请先写一段开头，我帮你接着写下去）'}

---
✏️ 提示：续写的关键是「**承接**」——要么承接情绪，要么承接细节，要么承接人物状态。`;
    }
    case 'review': {
      return `## 📝 文章批改报告

### ⭐ 总体评分：7.5 / 10

### ✅ 亮点
1. **真情实感**：能感觉到你写的时候是真诚的，这比华丽的辞藻更重要
2. **结构清晰**：整体有开头有结尾，中间的展开层次分明
3. **有细节意识**：你注意到了用具体的画面来代替抽象描述

### 🔧 改进建议
1. **开头可以更抓眼球**：现在的开头偏平淡，试试从一个**动作**、一个**声音**或者一个**反常的细节**开始
2. **中间部分加入「阻碍」**：如果事情一帆风顺，读者会觉得无聊。加一个小波折——一个意外、一个内心挣扎、一个突然的回忆
3. **结尾留一点余韵**：不要把话说完，让读者自己品一品。可以用一个画面收尾，而不是一句总结

### 📊 字数统计
- 原文：约 ${content.length} 字
- 建议：保持在 ${Math.max(300, Math.min(3000, content.length * 1.2 | 0))} 字左右

继续写！写完再来让我帮你改第二遍 👊`;
    }
    default:
      return '请选择一个任务：outline（大纲）/ rewrite（润色）/ continue（续写）/ review（批改）';
  }
}

/* ---------------- 中间件 ---------------- */
async function auth(request, env) {
  const header = request.headers.get('Authorization') || '';
  const token = header.replace(/^Bearer\s+/i, '');
  const userId = await resolveToken(env, token);
  if (!userId) return null;
  return userById(env, userId);
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

/* 解析 URL query string 为对象 */
function requestQuery(request) {
  try {
    const url = new URL(request.url);
    const o = {};
    for (const [k, v] of url.searchParams) o[k] = v;
    return o;
  } catch { return {}; }
}

/* 添加通知（写内存 + D1） */
async function addNotif(env, db, fromUserId, type, toUserId, targetType, targetId, content) {
  if (!toUserId || toUserId === fromUserId) return; // 不给自己发通知
  if (!db || !db.notifications) return;
  const n = { id: uid('n'), userId: toUserId, type, fromId: fromUserId, targetType, targetId, content, read: 0, createdAt: Date.now() };
  db.notifications.push(n);
  try {
    await env.DB.prepare(`INSERT INTO notifications (id,user_id,type,from_id,target_type,target_id,content,read,created_at) VALUES (?,?,?,?,?,?,?,?,?)`)
      .bind(n.id, n.userId, n.type, n.fromId, n.targetType, n.targetId, n.content, 0, n.createdAt).run();
  } catch {}
}

/* ---------------- 主处理器 ---------------- */
export async function onRequest(context) {
  const { request, env } = context;

  // OPTIONS 预检
  if (request.method === 'OPTIONS') return new Response(null, { headers: securityHeaders() });

  try {
    const db = await loadDB(env);
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/api/, '').replace(/^\/+/, '');
    const method = request.method;

    // ---- 认证 ----
    if (match(path, 'me') && method === 'GET') {
      const u = await auth(request, env);
      if (!u) return bad('未登录', 401);
      return json({ user: pubFull(u) });
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
      const now = Date.now();
      const user = { id: uid('u'), username, nickname, role: 'user', bio: '', createdAt: now, salt, hash, loginFails: 0, lockedUntil: 0, score: 0, badges: [], following: [] };
      db.users.push(user);
      // D1 同步写入
      await dbRun(env, `INSERT INTO users (id,username,nickname,role,bio,created_at,salt,hash,login_fails,locked_until,score,badges,following) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [user.id, user.username, user.nickname, user.role, user.bio, user.createdAt, user.salt, user.hash, 0, 0, 0, '[]', '[]']);
      const token = await createToken(env, user.id);
      return json({ user: pub(user), token });
    }

    // ---- 登录 ----
    if (match(path, 'login') && method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const username = clean(body.username, 24);
      if (!username || typeof body.password !== 'string') return bad('请输入用户名和密码');
      const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
      // 统一错误消息，防止用户名枚举
      const genericError = '用户名或密码错误';
      if (!user) { await sleep(300); return bad(genericError); } // 延时防枚举
      if (user.lockedUntil && Date.now() < user.lockedUntil) {
        const mins = Math.ceil((user.lockedUntil - Date.now()) / 60000);
        return bad(`该账号已因多次登录失败被锁定，请 ${mins} 分钟后再试`, 429);
      }
      const ok = await verifyPassword(body.password, user);
      if (!ok) {
        user.loginFails = (user.loginFails || 0) + 1;
        if (user.loginFails >= 5) {
          user.lockedUntil = Date.now() + 10 * 60000;
          user.loginFails = 0;
        }
        await dbRun(env, 'UPDATE users SET login_fails=?, locked_until=? WHERE id=?', [user.loginFails, user.lockedUntil, user.id]);
        await sleep(300); // 延时防暴力破解
        return bad(genericError);
      }
      user.loginFails = 0; user.lockedUntil = 0;
      await dbRun(env, 'UPDATE users SET login_fails=0, locked_until=0 WHERE id=?', [user.id]);
      const token = await createToken(env, user.id);
      return json({ user: pubFull(user), token });
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
      const u = await auth(request, env);
      if (!u) return bad('请先登录', 401);
      const body = await request.json();
      const nickname = clean(body.nickname, 24);
      if (nickname) u.nickname = nickname;
      u.bio = clean(body.bio, 200);
      await dbRun(env, 'UPDATE users SET nickname=?, bio=? WHERE id=?', [u.nickname, u.bio, u.id]);
      return json({ user: pub(u) });
    }

    // ---- 修改密码 ----
    if (match(path, 'me/password') && method === 'PUT') {
      const u = await auth(request, env);
      if (!u) return bad('请先登录', 401);
      const body = await request.json();
      if (!await verifyPassword(body.oldPassword || '', u)) return bad('原密码错误');
      if (!validPassword(body.newPassword)) return bad('新密码至少 8 位，且需同时包含字母和数字');
      const { salt, hash } = await hashPassword(body.newPassword);
      u.salt = salt; u.hash = hash;
      await dbRun(env, 'UPDATE users SET salt=?, hash=? WHERE id=?', [salt, hash, u.id]);
      return json({ ok: true });
    }

    // ---- 用户详情 ----
    let m = match(path, 'users/:id');
    if (m && method === 'GET') {
      const u = userById(env, m.id);
      if (!u) return bad('用户不存在', 404);
      const me = await auth(request, env);
      const articles = db.articles.filter(a => a.authorId === u.id && a.status === 'approved');
      const posts = db.posts.filter(p => p.authorId === u.id && p.status === 'approved');
      const likes = articles.reduce((s, a) => s + (a.likes || []).length, 0);
      const followerCount = db.users.filter(x => (x.following || []).includes(u.id)).length;
      const followingCount = (u.following || []).length;
      const isFollowing = !!(me && (me.following || []).includes(u.id));
      // 参加过的比赛（作为作者提交过作品）
      const contests = db.contests.filter(c =>
        (c.participants || []).includes(u.id) ||
        (c.submissions || []).some(s => s.authorId === u.id)
      ).map(c => ({
        id: c.id, title: c.title, status: c.status || (Date.now() < c.startTime ? 'upcoming' : Date.now() > c.endTime ? 'ended' : 'ongoing'),
        startTime: c.startTime, endTime: c.endTime
      }));
      // 关注列表 / 粉丝列表
      const following = (u.following || []).map(id => pub(userById(env, id))).filter(Boolean);
      const followers = db.users.filter(x => (x.following || []).includes(u.id)).map(pub);
      // 积分计算
      const articleCount = articles.length;
      const postCount = posts.length;
      const reviewCount = db.reviews.filter(r => r.authorId === u.id).length;
      const score = (u.score || 0) + articleCount * 10 + postCount * 5 + likes * 3 + reviewCount * 2;
      // 返回的 user 对象要包含 badges
      const userOut = pub(u);
      userOut.badges = u.badges || [];
      return json({
        user: userOut,
        stats: { articles: articles.length, posts: posts.length, likes, followerCount, followingCount, score },
        isFollowing,
        articles: articles.sort((a, b) => b.createdAt - a.createdAt).map(a => articleOut(a, db)),
        posts: posts.sort((a, b) => b.createdAt - a.createdAt).map(p => postOut(p, db)),
        contests, following, followers
      });
    }

    // ---- 关注/取消 ----
    m = match(path, 'users/:id/follow');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const t = userById(env, m.id);
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
      const qs = requestQuery(request);
      const cat = qs.category;
      const tag = qs.tag;
      const q = qs.q;
      const sort = qs.sort;
      if (cat) list = list.filter(a => (a.category || '其他') === cat);
      if (tag) list = list.filter(a => {
        const t = typeof a.tags === 'string' ? safeJSON(a.tags) : (a.tags || []);
        return t.includes(tag);
      });
      list = searchFilter(list, q, db);
      if (sort === 'hot') list.sort((a, b) => ((b.likes || []).length * 5 + b.views) - ((a.likes || []).length * 5 + a.views));
      else list.sort((a, b) => b.createdAt - a.createdAt);
      // 返回热门标签前 10 个
      const allTags = {};
      db.articles.forEach(a => {
        const t = typeof a.tags === 'string' ? safeJSON(a.tags) : (a.tags || []);
        t.forEach(x => allTags[x] = (allTags[x] || 0) + 1);
      });
      const hotTags = Object.entries(allTags).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([t]) => t);
      return json({ articles: list.map(a => articleOut(a, db)), hotTags });
    }

    // ---- 我的文章 ----
    if (match(path, 'articles/mine') && method === 'GET') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      return json({ articles: db.articles.filter(a => a.authorId === me.id).sort((a, b) => b.createdAt - a.createdAt).map(a => articleOut(a, db)) });
    }

    // ---- 文章详情 ----
    m = match(path, 'articles/:id');
    if (m && method === 'GET') {
      const a = db.articles.find(x => x.id === m.id);
      if (!a) return bad('文章不存在', 404);
      const me = await auth(request, env);
      const canView = a.status === 'approved' || (me && (me.id === a.authorId || me.role === 'admin'));
      if (!canView) return bad('文章正在审核中', 403);
      if (!me || me.id !== a.authorId) { a.views = (a.views || 0) + 1; await saveDB(env); }
      const o = articleOut(a, db);
      o.liked = !!(me && (a.likes || []).includes(me.id));
      return json({ article: o });
    }

    // ---- 创建文章 ----
    if (match(path, 'articles') && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const body = await request.json();
      const title = clean(body.title, 80);
      const content = clean(body.content, 50000);
      if (!title || !content) return bad('标题和内容不能为空');
      const category = ART_CATS.includes(body.category) ? body.category : '其他';
      const tagsRaw = Array.isArray(body.tags) ? body.tags.slice(0, 8).map(t => clean(t, 20)).filter(Boolean) : [];
      const a = { id: uid('a'), authorId: me.id, title, content, category, status: 'pending', views: 0, likes: [], tags: JSON.stringify(tagsRaw), createdAt: Date.now() };
      db.articles.push(a);
      await saveDB(env);
      return json({ article: articleOut(a, db) });
    }

    // ---- 编辑文章 ----
    m = match(path, 'articles/:id');
    if (m && method === 'PUT') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const a = db.articles.find(x => x.id === m.id);
      if (!a || a.authorId !== me.id) return bad('文章不存在或无权限', 404);
      const body = await request.json();
      a.title = clean(body.title, 80) || a.title;
      a.content = clean(body.content, 50000) || a.content;
      if (ART_CATS.includes(body.category)) a.category = body.category;
      if (Array.isArray(body.tags)) {
        a.tags = JSON.stringify(body.tags.slice(0, 8).map(t => clean(t, 20)).filter(Boolean));
      }
      if (a.status !== 'approved') a.status = 'pending';
      await saveDB(env);
      return json({ article: articleOut(a, db) });
    }

    // ---- 删除文章 ----
    m = match(path, 'articles/:id');
    if (m && method === 'DELETE') {
      const me = await auth(request, env);
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
      const me = await auth(request, env);
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
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      return json({ posts: db.posts.filter(p => p.authorId === me.id).sort((a, b) => b.createdAt - a.createdAt).map(p => postOut(p, db)) });
    }

    // ---- 帖子详情 ----
    m = match(path, 'posts/:id');
    if (m && method === 'GET') {
      const p = db.posts.find(x => x.id === m.id);
      if (!p) return bad('帖子不存在', 404);
      const me = await auth(request, env);
      if (p.status !== 'approved' && !(me && (me.id === p.authorId || me.role === 'admin'))) {
        return bad('帖子正在审核中', 403);
      }
      const o = postOut(p, db);
      o.comments = (p.comments || []).map(c => withAuthor(c, db));
      return json({ post: o });
    }

    // ---- 创建帖子 ----
    if (match(path, 'posts') && method === 'POST') {
      const me = await auth(request, env);
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
      const me = await auth(request, env);
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
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const i = db.posts.findIndex(x => x.id === m.id);
      if (i < 0) return bad('帖子不存在', 404);
      if (db.posts[i].authorId !== me.id && me.role !== 'admin') return bad('无权限', 403);
      db.posts.splice(i, 1);
      await saveDB(env);
      return json({ ok: true });
    }

    // ========== 评论系统（楼中楼） ==========
    // GET /api/comments?target_type=article&target_id=xxx
    if (match(path, 'comments') && method === 'GET') {
      const tt = clean(requestQuery(request).target_type, 16) || 'article';
      const tid = clean(requestQuery(request).target_id, 64);
      if (!tid) return bad('缺少 target_id');
      const me = await auth(request, env);
      const all = db.comments.filter(c => c.targetType === tt && c.targetId === tid).sort((a, b) => a.createdAt - b.createdAt);
      // 构造楼中楼
      const byId = {}; all.forEach(c => { byId[c.id] = { ...c, author: pub(userByIdSync(db, c.authorId)), replies: [], likeCount: (c.likes || []).length, liked: !!(me && (c.likes || []).includes(me.id)) }; });
      const roots = [];
      all.forEach(c => {
        const node = byId[c.id];
        if (c.parentId && byId[c.parentId]) byId[c.parentId].replies.push(node);
        else roots.push(node);
      });
      return json({ comments: roots, total: all.length });
    }

    // POST /api/comments
    if (match(path, 'comments') && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const body = await request.json();
      const targetType = clean(body.target_type, 16);
      const targetId = clean(body.target_id, 64);
      const parentId = clean(body.parent_id, 64) || null;
      const content = clean(body.content, 2000);
      if (!targetType || !targetId) return bad('缺少目标参数');
      if (!['article', 'post'].includes(targetType)) return bad('target_type 只能是 article 或 post');
      if (!content) return bad('评论内容不能为空');
      // 目标必须存在且已审核通过
      const target = targetType === 'article'
        ? db.articles.find(a => a.id === targetId)
        : db.posts.find(p => p.id === targetId);
      if (!target) return bad('目标不存在', 404);
      if (target.status !== 'approved' && me.role !== 'admin' && target.authorId !== me.id) return bad('内容暂不可评论', 403);
      if (parentId) {
        const parent = db.comments.find(c => c.id === parentId && c.targetType === targetType && c.targetId === targetId);
        if (!parent) return bad('回复的评论不存在', 404);
      }
      const c = { id: uid('cm'), targetType, targetId, parentId, authorId: me.id, content, likes: [], createdAt: Date.now() };
      db.comments.push(c);
      await saveDB(env);
      // 通知（如果有被回复的人或目标作者）
      await addNotif(env, db, me.id, 'comment', me.id, targetType, targetId, `评论了${targetType === 'article' ? '文章' : '帖子'}`);
      if (parentId) {
        const parent = db.comments.find(x => x.id === parentId);
        if (parent && parent.authorId !== me.id) {
          await addNotif(env, db, me.id, 'reply', parent.authorId, 'comment', parentId, '回复了你的评论');
        }
      } else if (target.authorId !== me.id) {
        await addNotif(env, db, me.id, 'comment', target.authorId, targetType, targetId, `评论了你的${targetType === 'article' ? '文章' : '帖子'}`);
      }
      const out = { ...c, author: pub(me), replies: [], likeCount: 0, liked: false };
      return json({ comment: out }, 201);
    }

    // DELETE /api/comments/:id
    m = match(path, 'comments/:id');
    if (m && method === 'DELETE') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const i = db.comments.findIndex(c => c.id === m.id);
      if (i < 0) return bad('评论不存在', 404);
      if (db.comments[i].authorId !== me.id && me.role !== 'admin') return bad('无权限', 403);
      db.comments.splice(i, 1);
      await saveDB(env);
      return json({ ok: true });
    }

    // POST /api/comments/:id/like
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const c = db.comments.find(x => x.id === m.id);
      if (!c) return bad('评论不存在', 404);
      if (!c.likes) c.likes = [];
      const idx = c.likes.indexOf(me.id);
      if (idx >= 0) c.likes.splice(idx, 1); else c.likes.push(me.id);
      await saveDB(env);
      return json({ liked: idx < 0, likeCount: c.likes.length });
    }

    // ========== 通知系统 ==========
    // GET /api/notifications
    if (match(path, 'notifications') && method === 'GET') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const qs = requestQuery(request);
      const limit = Math.min(50, parseInt(qs.limit, 10) || 20);
      const list = db.notifications
        .filter(n => n.userId === me.id)
        .sort((a, b) => b.createdAt - a.createdAt)
        .slice(0, limit)
        .map(n => ({ ...n, from: pub(userByIdSync(db, n.fromId)) }));
      return json({ notifications: list });
    }
    // GET /api/notifications/unread-count
    if (match(path, 'notifications/unread-count') && method === 'GET') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const c = db.notifications.filter(n => n.userId === me.id && !n.read).length;
      return json({ count: c });
    }
    // POST /api/notifications/read-all
    if (match(path, 'notifications/read-all') && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      db.notifications.forEach(n => { if (n.userId === me.id) n.read = 1; });
      await saveDB(env);
      return json({ ok: true });
    }
    // POST /api/notifications/:id/read
    m = match(path, 'notifications/:id');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const n = db.notifications.find(x => x.id === m.id);
      if (!n || n.userId !== me.id) return bad('不存在', 404);
      n.read = 1;
      await saveDB(env);
      return json({ ok: true });
    }

    // ---- 私信：发送 ----
    if (match(path, 'messages') && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const body = await request.json();
      const to = userById(env, body.toId);
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
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      return json({ count: db.messages.filter(m => m.toId === me.id && !m.read).length });
    }

    // ---- 私信：会话列表 ----
    if (match(path, 'messages/conversations') && method === 'GET') {
      const me = await auth(request, env);
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
          partner: pub(userById(env, c.partnerId)),
          lastContent: c.last.content, lastTime: c.last.createdAt,
          lastFromMe: c.last.fromId === me.id, unread: c.unread
        }))
        .filter(c => c.partner);
      return json({ conversations });
    }

    // ---- 私信：与某人聊天 ----
    m = match(path, 'messages/with/:userId');
    if (m && method === 'GET') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const other = userById(env, m.userId);
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
      const me = await auth(request, env);
      o.joined = !!(me && (c.participants || []).includes(me.id));
      o.participantList = (c.participants || []).map(id => pub(userById(env, id))).filter(Boolean);
      delete o.participants;
      delete o.submissions;
      return json({ contest: o });
    }

    // ---- 创建比赛 ----
    if (match(path, 'contests') && method === 'POST') {
      const me = await auth(request, env);
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
      const me = await auth(request, env);
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
      const me = await auth(request, env);
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
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const c = db.contests.find(x => x.id === m.id);
      if (!c) return bad('比赛不存在', 404);
      return json({ submissions: (c.submissions || []).filter(s => s.authorId === me.id) });
    }

    // ---- 管理员：比赛提交列表 ----
    m = match(path, 'contests/:id/submissions');
    if (m && method === 'GET') {
      const me = await auth(request, env);
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
      const me = await auth(request, env);
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
      const me = await auth(request, env);
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
      const me = await auth(request, env);
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
      const me = await auth(request, env);
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
      const me = await auth(request, env);
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
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const s = db.practices.find(x => x.problemId === m.id && x.authorId === me.id);
      return json({ practice: s || null });
    }

    // ---- 文件上传 ----
    if (match(path, 'files') && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const formData = await request.formData();
      const file = formData.get('file');
      const note = clean(formData.get('note') || '', 200);
      if (!file) return bad('请选择文件');
      if (!isAllowedFile(file.name)) return bad('不允许上传该类型的文件');
      if (file.size > MAX_FILE_SIZE) return bad('文件不能超过 20MB');
      const fileId = uid('f');
      const arrayBuf = await file.arrayBuffer();
      const base64 = new Uint8Array(arrayBuf).reduce((a, b) => a + String.fromCharCode(b), '');
      const ext = (file.name.match(/\.([a-z0-9]+)$/) || [,'bin'])[1].toLowerCase();
      const storedName = fileId + '.' + ext;
      await env.DATA.put('file:' + storedName, btoa(base64));
      const f = { id: fileId, authorId: me.id, originalName: file.name, storedName, size: file.size, note, status: 'pending', createdAt: Date.now() };
      db.files.push(f);
      await saveDB(env);
      return json({ file: withAuthor(f, db) });
    }

    // ---- 我的文件 ----
    if (match(path, 'files/mine') && method === 'GET') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      return json({ files: db.files.filter(f => f.authorId === me.id).sort((a, b) => b.createdAt - a.createdAt).map(f => withAuthor(f, db)) });
    }

    // ---- 文件下载 ----
    m = match(path, 'files/:id/download');
    if (m && method === 'GET') {
      const me = await auth(request, env);
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
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const status = ['pending', 'approved', 'rejected'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : 'pending';
      return json({ articles: db.articles.filter(a => a.status === status).sort((a, b) => b.createdAt - a.createdAt).map(a => articleOut(a, db)) });
    }

    // ---- 审核文章 ----
    m = match(path, 'admin/articles/:id/review');
    if (m && method === 'POST') {
      const me = await auth(request, env);
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
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const status = ['pending', 'approved', 'rejected'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : 'pending';
      return json({ posts: db.posts.filter(p => p.status === status).sort((a, b) => b.createdAt - a.createdAt).map(p => postOut(p, db)) });
    }

    // ---- 审核帖子 ----
    m = match(path, 'admin/posts/:id/review');
    if (m && method === 'POST') {
      const me = await auth(request, env);
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
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const status = ['pending', 'approved', 'rejected'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : 'pending';
      return json({ files: db.files.filter(f => f.status === status).sort((a, b) => b.createdAt - a.createdAt).map(f => withAuthor(f, db)) });
    }

    // ---- 审核文件 ----
    m = match(path, 'admin/files/:id/review');
    if (m && method === 'POST') {
      const me = await auth(request, env);
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
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const status = ['pending', 'approved', 'rejected'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : 'pending';
      return json({ problems: db.problems.filter(p => (p.status || 'approved') === status).sort((a, b) => b.createdAt - a.createdAt).map(p => problemOut(p, db)) });
    }

    // ---- 审核题目 ----
    m = match(path, 'admin/problems/:id/review');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const body = await request.json();
      const p = db.problems.find(x => x.id === m.id);
      if (!p) return bad('题目不存在', 404);
      p.status = body.action === 'approve' ? 'approved' : 'rejected';
      p.reviewedAt = Date.now();
      await saveDB(env);
      return json({ ok: true, status: p.status });
    }

    // ---- AI 写作助手 ----
    m = match(path, 'ai/assist');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const body = await request.json().catch(() => ({}));
      const { task = 'outline', topic = '', content = '', style = '', extra = '' } = body;
      return json(await aiAssist(env, task, { topic, content, style, extra }));
    }

    // ---- 写作模板列表 ----
    m = match(path, 'templates');
    if (m && method === 'GET') {
      const list = db.templates.map(t => ({
        id: t.id, title: t.title, category: t.category,
        description: t.description
      }));
      return json({ templates: list });
    }

    // ---- 模板详情 ----
    m = match(path, 'templates/:id');
    if (m && method === 'GET') {
      const t = db.templates.find(x => x.id === m.id);
      if (!t) return bad('模板不存在', 404);
      return json({ template: t });
    }

    // ---- 文章点评列表 ----
    m = match(path, 'articles/:id/reviews');
    if (m && method === 'GET') {
      const a = db.articles.find(x => x.id === m.id);
      if (!a) return bad('文章不存在', 404);
      const reviews = db.reviews.filter(r => r.articleId === a.id).sort((x, y) => y.createdAt - x.createdAt);
      const out = reviews.map(r => ({
        id: r.id, rating: r.rating, content: r.content,
        createdAt: r.createdAt,
        author: withAuthorSimple(r.authorId, db)
      }));
      const avg = out.length ? (out.reduce((s, r) => s + r.rating, 0) / out.length).toFixed(1) : '0.0';
      return json({ reviews: out, avgRating: avg, count: out.length });
    }

    // ---- 提交点评 ----
    m = match(path, 'articles/:id/reviews');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const a = db.articles.find(x => x.id === m.id);
      if (!a) return bad('文章不存在', 404);
      const body = await request.json();
      const rating = Number(body.rating);
      const content = clean(body.content, 1000);
      if (![1, 2, 3, 4, 5].includes(rating)) return bad('评分必须是 1-5 星');
      if (!content) return bad('请写点评内容');
      const r = { id: uid('r'), articleId: a.id, authorId: me.id, rating, content, createdAt: Date.now() };
      db.reviews.push(r);
      // 点评者获得 10 分积分
      updateUserScore(me.id, 10, 'review');
      // 点评 3 次获得「热心点评员」勋章
      const myReviewCount = db.reviews.filter(x => x.authorId === me.id).length;
      if (myReviewCount >= 3) awardBadge(me.id, '热心点评员', '你已点评 3 篇以上文章');
      await saveDB(env);
      return json({ ok: true, review: { ...r, author: withAuthorSimple(me.id, db) } });
    }

    // ---- 今日打卡题目 ----
    m = match(path, 'checkins/today');
    if (m && method === 'GET') {
      const dailyId = db.dailyProblem;
      const daily = dailyId ? db.problems.find(p => p.id === dailyId) : null;
      let myCheckin = null;
      const me = await auth(request, env).catch(() => null);
      if (me) {
        const todayKey = new Date().toDateString();
        myCheckin = db.checkins.find(c => c.userId === me.id && new Date(c.createdAt).toDateString() === todayKey);
      }
      // 计算连续打卡天数
      let streak = 0;
      if (me) {
        const userCheckins = db.checkins
          .filter(c => c.userId === me.id)
          .map(c => new Date(c.createdAt).toDateString())
          .sort();
        const seen = new Set(userCheckins);
        const d = new Date();
        while (seen.has(d.toDateString())) {
          streak++;
          d.setDate(d.getDate() - 1);
        }
      }
      return json({
        daily: daily ? { id: daily.id, title: daily.title, content: daily.content, difficulty: daily.difficulty, type: daily.type } : null,
        myCheckin: myCheckin ? { id: myCheckin.id, content: myCheckin.content, createdAt: myCheckin.createdAt, points: myCheckin.points } : null,
        streak
      });
    }

    // ---- 提交打卡 ----
    m = match(path, 'checkins');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const body = await request.json();
      const content = clean(body.content, 2000);
      if (!content) return bad('请写点什么再打卡');
      const dailyId = db.dailyProblem;
      if (!dailyId) return bad('今日暂无打卡题目', 404);
      // 今天打过卡了吗？
      const todayKey = new Date().toDateString();
      const existing = db.checkins.find(c => c.userId === me.id && new Date(c.createdAt).toDateString() === todayKey);
      if (existing) return bad('今天已经打过卡了，明天再来吧！', 400);
      // 计算连续天数和积分
      const userCheckins = db.checkins
        .filter(c => c.userId === me.id)
        .map(c => new Date(c.createdAt).toDateString())
        .sort();
      const seen = new Set(userCheckins);
      const d = new Date();
      let prevDay = new Date(d); prevDay.setDate(prevDay.getDate() - 1);
      const prevExists = seen.has(prevDay.toDateString());
      const streak = prevExists ? (me._tmpStreak || 0) + 1 : 1;
      me._tmpStreak = streak;
      const points = 20 + Math.min(streak - 1, 6) * 5; // 第一天 20，之后每天 +5，最高 +30
      const c = { id: uid('c'), userId: me.id, problemId: dailyId, content, createdAt: Date.now(), points };
      db.checkins.push(c);
      updateUserScore(me.id, points, 'checkin');
      // 勋章
      if (streak >= 3) awardBadge(me.id, '勤耕不辍', '连续打卡 3 天');
      if (streak >= 7) awardBadge(me.id, '一周达人', '连续打卡 7 天');
      if (streak >= 30) awardBadge(me.id, '月度冠军', '连续打卡 30 天');
      // 清理临时字段
      delete me._tmpStreak;
      await saveDB(env);
      return json({ ok: true, checkin: c, streak, points });
    }

    // ---- 我的打卡记录 ----
    m = match(path, 'checkins/mine');
    if (m && method === 'GET') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const list = db.checkins.filter(c => c.userId === me.id).sort((a, b) => b.createdAt - a.createdAt).slice(0, 30);
      const out = list.map(c => ({
        id: c.id, content: c.content, points: c.points, createdAt: c.createdAt,
        problem: (() => {
          const p = db.problems.find(x => x.id === c.problemId);
          return p ? { id: p.id, title: p.title } : null;
        })()
      }));
      // 连续天数
      const dates = [...new Set(list.map(c => new Date(c.createdAt).toDateString()))].sort();
      let streak = 0;
      const d = new Date();
      while (dates.includes(d.toDateString())) {
        streak++;
        d.setDate(d.getDate() - 1);
      }
      return json({ checkins: out, streak, total: list.length });
    }

    // ---- 用户勋章 ----
    m = match(path, 'users/:id/badges');
    if (m && method === 'GET') {
      const u = db.users.find(x => x.id === m.id);
      if (!u) return bad('用户不存在', 404);
      return json({ badges: u.badges || [] });
    }

    // ---- 404 ----
    return bad('接口不存在: ' + path + ' ' + method, 404);

  } catch (err) {
    return bad('服务器内部错误: ' + (err.message || String(err)), 500);
  }
}
