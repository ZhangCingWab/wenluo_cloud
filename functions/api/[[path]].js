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
  // 剥离所有 HTML 标签（Markdown 保留的 <code> 等前端 esc() 会处理，但后端存储要安全）
  out = out.replace(/<[^>]*>/g, '');
  // 剥离危险 Markdown 攻击向量
  out = out.replace(/`[^`]*`([\s\S]*)?/g, (m) => m.includes('javascript:') ? '' : m);
  // 过滤事件处理器 onXxx=
  out = out.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
  return out;
};

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

/* ---------------- 数据库管理 ---------------- */
const KV_KEY = 'database';
let _cache = null;

async function loadDB(env) {
  if (_cache) return _cache;
  const raw = await env.DATA.get(KV_KEY);
  let changed = false;
  if (!raw) {
    _cache = await initDB();
    await saveDB(env);
  } else {
    _cache = JSON.parse(raw);
    // 兼容旧数据
    _cache.messages = _cache.messages || [];
    for (const u of _cache.users) u.following = u.following || [];
    if (!Array.isArray(_cache.problems)) { _cache.problems = []; seedProblems(); changed = true; }
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

    // ---- 自动补齐缺失的种子数据（兼容旧版本空 KV） ----
    const now = Date.now();
    const adminUser = _cache.users.find(u => u.role === 'admin');

    // 补齐新字段
    _cache.reviews = _cache.reviews || [];
    _cache.checkins = _cache.checkins || [];
    if (!Array.isArray(_cache.templates) || _cache.templates.length === 0) {
      seedTemplates(_cache);
      changed = true;
    }
    // 每日题目（每天自动换）
    const today = new Date();
    const dayKey = today.getFullYear() * 10000 + (today.getMonth() + 1) * 100 + today.getDate();
    if (!_cache.dailyProblem || (_cache._dailyDayKey && _cache._dailyDayKey !== dayKey)) {
      _cache.dailyProblem = pickDailyProblem(_cache);
      _cache._dailyDayKey = dayKey;
      changed = true;
    }
    // 用户勋章字段
    for (const u of _cache.users) {
      if (!Array.isArray(u.badges)) { u.badges = []; changed = true; }
    }

    if (!_cache.problems || _cache.problems.length === 0) {
      seedProblems();
      changed = true;
    }

    // 补齐欢迎文章
    if ((!_cache.articles || _cache.articles.length === 0) && adminUser) {
      _cache.articles.push({
        id: 'a_welcome', authorId: adminUser.id, title: '欢迎来到文洛 · 文章竞赛社区',
        content: '## 这里可以做什么\n\n- **写文章**：点击侧边栏「我的文章」或主页「立即开始创作」，提交后由管理员审核，通过后进入文章库。\n- **逛论坛**：在「论坛广场」发帖交流，帖子同样需要审核。\n- **打比赛**：管理员会在「比赛广场」创建比赛，欢迎报名参加。\n- **文件投稿**：有文档想分享？通过「文件投稿」上传，审核通过后归档。\n\n## 社区公约\n\n1. 保持友善，尊重原创。\n2. 文章支持 `Markdown` 基础语法：**加粗**、`代码`、标题等。\n3. 违规内容将被拒绝并记录。\n\n祝大家玩得开心！',
        category: '其他', status: 'approved', views: 128, likes: [], createdAt: now - 86400000, reviewedAt: now - 86000000
      });
      changed = true;
    }

    // 补齐新人报到帖
    if ((!_cache.posts || _cache.posts.length === 0) && adminUser) {
      _cache.posts.push({
        id: 'p_hello', authorId: adminUser.id, title: '【置顶】新人报到帖',
        content: '新来的同学在这里打个招呼吧！介绍一下自己擅长的领域 ~',
        category: '其他', status: 'approved', createdAt: now - 43200000, comments: []
      });
      changed = true;
    }

    // 补齐 demo 比赛
    if ((!_cache.contests || _cache.contests.length === 0) && adminUser) {
      _cache.contests.push({
        id: 'c_demo', title: '第一届「文洛杯」短文创作赛',
        description: '## 比赛说明\n\n围绕主题「**代码与生活**」写一篇不超过 2000 字的短文。\n\n- 参赛作品请通过「我的文章 → 写文章」提交，标题前缀【文洛杯】。\n- 评审标准：立意 40%、文笔 40%、创意 20%。\n\n期待大家的作品！',
        problems: [
          { id: uid('q'), title: '主题创作', content: '围绕比赛主题，完成一篇原创作品。', wordLimit: 2000 },
          { id: uid('q'), title: '自由发挥', content: '题材不限，展现你的创意与文笔。', wordLimit: 2000 },
          { id: uid('q'), title: '我的社区故事', content: '写下你在社区里的经历或见闻。', wordLimit: 0 }
        ],
        startTime: now - 3600000, endTime: now + 7 * 86400000,
        createdBy: adminUser.id, createdAt: now - 7200000,
        participants: [], submissions: []
      });
      changed = true;
    }

    // 补齐题库
    if (!_cache.problems || _cache.problems.length === 0) {
      seedProblems();
      changed = true;
    }

    // 补齐管理员密码（旧数据是 placeholder 时强制重置为 admin123 真实 hash）
    if (adminUser && (adminUser.salt === 'seed_salt_placeholder' || adminUser.hash === 'seed_hash_placeholder')) {
      const pw = await hashPassword('admin123');
      adminUser.salt = pw.salt;
      adminUser.hash = pw.hash;
      adminUser.loginFails = 0; adminUser.lockedUntil = 0;
      changed = true;
    }

    if (changed) await saveDB(env);
  }
  return _cache;
}

async function saveDB(env) {
  await env.DATA.put(KV_KEY, JSON.stringify(_cache, null, 2));
}

async function initDB() {
  const now = Date.now();
  const user = {
    id: 'u_admin', username: 'admin', nickname: '站务管理员', role: 'admin',
    bio: '本站管理员，负责文章、帖子与投稿审核。', createdAt: now,
    badges: []
  };
  // admin 默认密码：admin123（真实 PBKDF2 hash，不再是 placeholder 任何人可绕过）
  const pw = await hashPassword('admin123');
  user.salt = pw.salt;
  user.hash = pw.hash;
  user.loginFails = 0; user.lockedUntil = 0;
  const db = {
    users: [user], articles: [], posts: [], contests: [],
    files: [], messages: [], problems: [], practices: [],
    reviews: [], checkins: [], templates: [], dailyProblem: null
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
  seedTemplates(db);
  // 设置每日题目
  db.dailyProblem = pickDailyProblem(db);
  // 管理员密码：admin123（哈希在 initTokens 中设置）
  user.salt = 'seed_salt_placeholder';
  user.hash = 'seed_hash_placeholder';
  return db;
}

/* ---------------- 写作模板种子 ---------------- */
function seedTemplates(db) {
  if (db.templates && db.templates.length) return;
  const now = Date.now();
  db.templates = [
    {
      id: 't_argue', title: '议论文五段式', category: '议论文',
      description: '经典的议论文结构，适合考场作文和思辨类文章',
      content: `# 议论文五段式模板

## 第一段 · 引入
> 用一个生动的场景 / 一句名言 / 一个反问，引出你的中心论点。
> 示例：「有人说……，但我认为……」

## 第二段 · 分论点一
**论点**：……
**论据**：可以用历史典故、名人故事、数据统计等。
**分析**：说明这个论据如何支撑你的观点。

## 第三段 · 分论点二
**论点**：……
**论据**：……
**分析**：……

## 第四段 · 反面论证 / 补充论述
> 从反面角度出发，说一下如果不这样会怎么样，或者补充一个不同角度的思考。

## 第五段 · 总结
> 升华主题，联系现实，给读者留下思考。`,
      createdAt: now
    },
    {
      id: 't_story', title: '短篇小说起承转合', category: '小说',
      description: '经典小说结构，适合 1500-3000 字的短故事创作',
      content: `# 短篇小说 · 起承转合模板

## 起（开头 15%）
- **人物**：主角出场，用行动 / 对话展示性格（不要直接介绍）
- **场景**：时间、地点、氛围
- **钩子**：一个小冲突 / 悬念，让读者想读下去

## 承（发展 35%）
- **事件展开**：主角遇到一系列困难 / 挑战
- **人物关系**：和配角互动，揭示更多背景
- **小高潮**：矛盾初步显现

## 转（高潮 30%）
- **重大转折**：意想不到的事件，打破平衡
- **人物抉择**：主角面对核心冲突，做出关键选择
- **情感爆发**：情绪最强烈的时刻

## 合（结尾 20%）
- **结局**：事件的最终走向
- **余韵**：一个画面 / 一句话，留给读者回味
- **不要解释**：让读者自己体会`,
      createdAt: now
    },
    {
      id: 't_poem', title: '现代自由诗', category: '诗歌',
      description: '自由体诗的写法框架，注重意象和节奏',
      content: `# 自由诗写作要点

## 1. 找一个核心意象
> 一棵树、一盏灯、一条河……选一个具体的东西作为诗的中心。

## 2. 第一节 · 切入
> 直接切入意象或场景，不要铺垫。

## 3. 中间 · 展开与变化
- 意象可以延伸、变形
- 情绪可以转折
- 每一节之间要有呼吸感

## 4. 结尾 · 留白
> 最后一两句给读者留下想象空间。

## 技巧提示
- 用具体的词，避免抽象（用"玻璃杯碎在地上"代替"心碎了"）
- 注意断句和换行，留白也是节奏的一部分
- 读出来听听，有节奏感才好`,
      createdAt: now
    },
    {
      id: 't_narrative', title: '记叙文六要素', category: '记叙文',
      description: '适合写人记事类作文，清晰完整',
      content: `# 记叙文 · 六要素模板

## 六要素一览
1. **时间**：什么时候？（具体或模糊）
2. **地点**：在哪里？
3. **人物**：谁？主角 / 配角
4. **起因**：发生了什么？为什么开始？
5. **经过**：过程如何？（重点！要详细）
6. **结果**：最后怎样？你学到了什么？

## 推荐结构
### 开头
- 一个画面 / 一个声音 / 一个感受开头
- 快速把读者带入场景

### 中间（核心）
- 详细写"经过"：用动作、对话、心理描写
- 制造小波澜：不要一帆风顺
- 重点段落放慢节奏，详写

### 结尾
- 事件的结局
- "我"的感受 / 成长 / 反思
- 可以用一句意味深长的话收尾`,
      createdAt: now
    },
    {
      id: 't_essay', title: '随笔散文', category: '随笔',
      description: '形散神不散，适合抒发个人感悟',
      content: `# 随笔散文写作框架

## 核心：一个情绪 / 一个感悟
> 先想清楚：我这篇随笔最想表达的是什么感受？

## 建议结构
### 触发（10%）
- 一个场景、一件小事、一个念头
- "今天路过那家店的时候，突然想起……"

### 联想（60%）
- 围绕核心感受自由发散
- 可以回忆往事、可以观察当下、可以读书思考
- 像和朋友聊天一样自然

### 收束（30%）
- 回到当下，或者升华为对生活的理解
- 不一定要有"标准答案"，真实就好

## 随笔的灵魂
- **真**：真诚，不装
- **细**：有细节，不空泛
- **自然**：像说话一样写`,
      createdAt: now
    },
    {
      id: 't_sci', title: '科幻短篇', category: '科幻',
      description: '适合脑洞类短文，在有限篇幅内讲好一个科幻点子',
      content: `# 科幻短篇 · 点子驱动模板

## 第一步：一个核心设定
> 选一个"如果"：如果人可以读取记忆？如果时间可以倒带 5 秒？

## 第二步：让设定影响一个普通人
> 不要写拯救世界，写一个普通人的日常被这个设定改变了。

## 推荐结构
### 日常 → 异变
- 开头写主角的普通生活
- 然后"那个设定"突然介入

### 尝试 → 挫折
- 主角尝试利用 / 适应这个设定
- 遇到意料之外的问题

### 抉择 → 结局
- 主角必须做出一个选择
- 结局可以是开放性的，但要有分量

## 科幻的精髓
- 设定要"自洽"（自己的规则要遵守）
- 重点在"人"，而不是"道具"
- 用科幻讲人的故事`,
      createdAt: now
    },
    {
      id: 't_hot', title: '公众号爆款结构', category: '随笔',
      description: '适合写热点评论、干货分享，有传播力',
      content: `# 公众号爆款文结构

## 标题：制造好奇心
- 数字："3 个步骤让你……"
- 痛点："为什么你总是……"
- 反差："我辞职了，因为……"

## 开头（钩子）
- 讲一个故事 / 一个场景，让读者有代入感
- 3 秒内抓住注意力

## 中间（价值）
### 结构 A：痛点 → 方案 → 案例
1. 戳中痛点（你是不是也这样？）
2. 给出方案（怎么做）
3. 真实案例（谁谁谁用了之后……）

### 结构 B：观点 → 论证 → 升华
1. 抛出一个反常识观点
2. 用 2-3 个角度论证
3. 联系读者的生活

## 结尾（行动号召）
- 总结 + 给读者一个"小行动"
- 引导点赞 / 在看 / 评论`,
      createdAt: now
    },
    {
      id: 't_ai_chat', title: 'AI 对话写文', category: '其他',
      description: '借助 AI 助手高效产出文章的工作流',
      content: `# AI 辅助写作工作流

## 第一步：用 AI 搭框架
> 告诉 AI："帮我写一篇关于【主题】的文章，风格是【风格】，字数【大概】，给我大纲。"

## 第二步：人工填充血肉
> AI 给的大纲是骨架，你需要：
- 把自己真实的故事 / 感受加进去
- 改掉 AI 写得太笼统的地方
- 加入具体的细节和例子

## 第三步：用 AI 润色
> 初稿完成后：
- "帮我把这一段润色得更流畅"
- "检查有没有错别字和不通顺的地方"
- "帮我写一个更吸引人的开头"

## 关键提醒
- **AI 是工具，你才是作者**
- 不要直接复制 AI 生成的大段文字
- 用 AI 省时间，把精力放在思考和真实表达上`,
      createdAt: now
    }
  ];
}

/* ---------------- 每日题目挑选 ---------------- */
function pickDailyProblem(db) {
  const approved = (db.problems || []).filter(p => (p.status || 'approved') === 'approved');
  if (!approved.length) return null;
  // 根据今天的日期挑一道（同一天稳定，明天自动换）
  const today = new Date();
  const dayKey = today.getFullYear() * 10000 + (today.getMonth() + 1) * 100 + today.getDate();
  return approved[dayKey % approved.length].id;
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
// pub() 严格脱敏：绝对不能泄露 salt/hash/loginFails/lockedUntil/score 内部数据
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
  // 仅管理员 / 本人自己看自己的完整资料时用
  if (!u) return null;
  return {
    ...pub(u),
    badges: u.badges || [],
    following: u.following || [],
    score: u.score || 0
  };
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
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

/* 简单作者信息（点评等场景用） */
function withAuthorSimple(id, db) {
  const u = userById(db, id);
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
  if (request.method === 'OPTIONS') return new Response(null, { headers: securityHeaders() });

  try {
    const db = await loadDB(env);
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/api/, '').replace(/^\/+/, '');
    const method = request.method;

    // ---- 认证 ----
    if (match(path, 'me') && method === 'GET') {
      const u = await auth(request, env, db);
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
      const user = { id: uid('u'), username, nickname, role: 'user', bio: '', createdAt: Date.now(), salt, hash };
      db.users.push(user);
      await saveDB(env);
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
        await saveDB(env);
        await sleep(300); // 延时防暴力破解
        return bad(genericError);
      }
      user.loginFails = 0; user.lockedUntil = 0;
      await saveDB(env);
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
      // 参加过的比赛（作为作者提交过作品）
      const contests = db.contests.filter(c =>
        (c.participants || []).includes(u.id) ||
        (c.submissions || []).some(s => s.authorId === u.id)
      ).map(c => ({
        id: c.id, title: c.title, status: c.status || (Date.now() < c.startTime ? 'upcoming' : Date.now() > c.endTime ? 'ended' : 'ongoing'),
        startTime: c.startTime, endTime: c.endTime
      }));
      // 关注列表 / 粉丝列表
      const following = (u.following || []).map(id => pub(userById(db, id))).filter(Boolean);
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

    // ---- AI 写作助手 ----
    m = match(path, 'ai/assist');
    if (m && method === 'POST') {
      const me = await auth(request, env, db);
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
      const me = await auth(request, env, db);
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
      const me = await auth(request, env, db).catch(() => null);
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
      const me = await auth(request, env, db);
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
      const me = await auth(request, env, db);
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
