/*
 * Cloudflare Pages Functions - 文汇·文章竞赛社区 完整 API
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
let _cacheDirty = false;
/* 标记内存缓存过期（写操作后调，下次 loadDB 重查 D1） */
function invalidateCache() { _cacheDirty = true; }

// 分别检查每张表是否为空，分别补种子
// —— 题库扩充包：100 道题，难度 1-6 全覆盖 ——
// 格式：[type, title, difficulty, tags, hint]
const PROBLEM_PACK = [
  // 难度 1（入门）
  ['theme','以「春天」为题，写一段你眼中的季节',1,'写景','选择一个具体的春天画面，写出你的真实感受'],
  ['skill','用比喻描写「月亮」',1,'比喻','写 3 个以上比喻句，不许用「像圆盘」「像镰刀」这两个常见比喻'],
  ['theme','以「我的书桌」为题介绍一件物品',1,'状物','按空间顺序描写书桌的样子，再讲一件和它有关的小事'],
  ['skill','用拟人写一场雨',1,'拟人','把雨当成一个人来写，让它有动作、有脾气'],
  ['theme','以「课间十分钟」为题记录一个场景',1,'记叙','抓住一个最热闹或最安静的瞬间来写'],
  ['skill','描写一种食物的味道',1,'感官','调动味觉、嗅觉、口感三种感官，150 字左右'],
  ['theme','以「放学路上」为题写一段路程',1,'记叙','路上你看到了什么、想到了什么'],
  ['skill','用三句话介绍你的好朋友',1,'人物','第一句外貌、第二句性格、第三句一件小事'],
  ['theme','以「晚安」为题写一段小对话',1,'对话','写一段睡前对话，不超过 10 个回合'],
  ['skill','描写你最喜欢的颜色和它让你想到的东西',1,'联想','由颜色展开联想，写出至少三个相关画面'],
  ['theme','以「一张笑脸」为题',1,'记叙','谁的笑脸？为什么让你记住？'],
  ['skill','用「先…接着…最后…」写泡一杯茶',1,'顺序','把过程写清楚，动作要具体'],
  ['theme','以「早晨的声音」为题',1,'写景','写出三种以上早晨的声音，用上拟声词'],
  ['skill','用叠词写一段天气',1,'叠词','至少用 5 个叠词（如滴滴答答、朦朦胧胧）'],
  ['theme','以「我的爱好」为题',1,'记叙','这个爱好是什么？它给你带来了什么？'],
  ['skill','描写一种动物走路的姿态',1,'观察','只写动作，不看不算，150 字'],
  ['theme','以「下雨了」为题',1,'写景','雨来了，世界发生了什么变化？'],
  // 难度 2（基础）
  ['theme','以「礼物」为题写一次收礼或送礼的经历',2,'记叙','礼物背后的心意比礼物本身更重要'],
  ['skill','用排比写「家是什么」',2,'排比','至少三组结构相同的句子'],
  ['theme','以「一次道歉」为题',2,'记叙','写清楚为什么道歉、怎么开口、结果如何'],
  ['skill','不用「热」字写天气很热',2,'细节描写','全文禁止出现「热」字，让读者自己感到热'],
  ['theme','以「旧照片」为题',2,'抒情','照片里有什么？它让你想起了谁？'],
  ['skill','用对比写两个人物',2,'对比','两个人物的性格要有明显反差'],
  ['theme','以「赶公交车」为题写一件事',2,'记叙','把追赶过程的紧张感写出来'],
  ['skill','用夸张写「饿」',2,'夸张','至少三个夸张句，不许重复同一手法'],
  ['theme','以「校园的树」为题',2,'写景','这棵树见过多少个学期的人和事？'],
  ['skill','用「虽然…但是…」写一段有转折的观点',2,'逻辑','观点明确，转折合理，不少于 5 句'],
  ['theme','以「第一次做饭」为题',2,'记叙','第一次的过程、意外和结果'],
  ['skill','用设问开头写「为什么读书」',2,'设问','自问自答，开头吸引人'],
  ['theme','以「雨后的操场」为题',2,'写景','雨停了，操场上有什么新东西？'],
  ['skill','用动作描写写「紧张」',2,'动作描写','不写「紧张」两个字，只写动作和身体反应'],
  ['theme','以「我的邻居」为题',2,'人物','选一个让你印象深刻的邻居'],
  ['skill','写一篇因果清晰的日记',2,'逻辑','因为…所以…，一天中的一件事，因果关系完整'],
  ['theme','以「书桌上的月光」为题',2,'抒情','月光和书桌之间发生的故事'],
  // 难度 3（进阶）
  ['theme','以「选择」为题写一次两难抉择',3,'成长','两难在哪里？你为什么这样选？选完后悔吗？'],
  ['skill','不用「哭」字写悲伤',3,'细节描写','禁止出现哭/泪/难过/伤心四个词'],
  ['theme','以「灯」为题，灯承担象征意义',3,'象征','灯象征什么？在结尾点明'],
  ['skill','用白描手法写一位陌生人',3,'白描','不用形容词堆砌，只用简洁的线条勾勒'],
  ['theme','以「毕业前的最后一节课」为题',3,'记叙','课堂的细节和不舍的情绪'],
  ['skill','用倒叙写一件往事',3,'结构','先写结局，再回到开头'],
  ['theme','以「桥」为题',3,'象征','桥连接的两岸各是什么？'],
  ['skill','用意识流手法写清晨醒来的十分钟',3,'意识流','念头跳跃、不讲逻辑，但要真实'],
  ['theme','以「等待」为题',3,'抒情','等什么？等待时心里经过了什么？'],
  ['skill','写一段推动情节的冲突对话',3,'对话','两个人的对话要有交锋，少用「他说」'],
  ['theme','以「修好的自行车」为题',3,'记叙','修理的过程也是理解的过程'],
  ['skill','用环境描写烘托人物心情',3,'烘托','不直接写心情，让环境替你说话'],
  ['theme','以「钥匙」为题',3,'象征','一把钥匙能打开的只是锁吗？'],
  ['skill','把一个俗套的故事写出新意',3,'创意','任选一个耳熟能详的故事（如龟兔赛跑），改写结局'],
  ['theme','以「阳台上的植物」为题',3,'状物','植物和你之间发生过什么？'],
  ['skill','用三个镜头感段落写一幅画面',3,'镜头','每段是一个镜头，像电影一样切换'],
  ['theme','以「故乡的味道」为题',3,'抒情','一种味道，一座城，一段记忆'],
  // 难度 4（提高）
  ['theme','科幻微小说：一百年后的世界',4,'科幻','完整的微型小说，1000 字以内'],
  ['skill','用有限视角写悬疑开头',4,'悬念','主角只能看到一部分真相，300 字'],
  ['theme','以「谎言」为题写一篇议论文',4,'议论','善意的谎言该不该说？给出你的论证'],
  ['skill','用蒙太奇剪辑三个时间点写「成长」',4,'结构','三个时间点，三个片段，暗示变化'],
  ['theme','以「失物招领」为题构思一个故事',4,'小说','失物是什么？谁丢了它？谁捡到它？'],
  ['skill','用反讽写一则校园生活随笔',4,'反讽','表面夸奖，实则批评，注意分寸'],
  ['theme','以「窗口」为题双线叙事',4,'结构','窗内和窗外两条线，最后交汇'],
  ['skill','用寓言体写一篇「乌鸦求职记」',4,'寓言','借动物说人事，500 字以内'],
  ['theme','以「山那边的灯」为题',4,'散文','灯在远方，路在脚下'],
  ['skill','用第二人称「你」写一封信',4,'人称','写给谁？用「你」贯穿全文'],
  ['theme','以「无人售卖摊」为题',4,'记叙','没有摊主，会发生什么？'],
  ['skill','用新闻体报道一件虚构事件',4,'文体','标题、导语、正文、引语齐全'],
  ['theme','以「时间旅行者的日记」为题',4,'科幻','三则日记，时间线可以错乱'],
  ['skill','用回环结构写「今天和昨天」',4,'结构','结尾要能接回开头'],
  ['theme','以「一张车票」为题',4,'记叙','一张车票，一段旅程，一个故事'],
  ['skill','用插叙补全人物背景',4,'结构','主线进行中插入回忆，再自然回到主线'],
  ['theme','以「安静的爆炸」为题',4,'创意','反差命题：什么是安静的爆炸？'],
  // 难度 5（高阶）
  ['theme','写一篇不超过 500 字的完整小说',5,'小说','含起承转合，人物、冲突、结局一个不能少'],
  ['skill','全文禁用「的」字写一段叙事',5,'限制','严格禁用「的」，语句要通顺自然'],
  ['theme','以「数据时代的孤独」为题写议论文',5,'议论','联系至少两个现实例子，论证层次分明'],
  ['skill','用三种文体写同一事件',5,'文体','新闻、日记、诗歌各写一段'],
  ['theme','以「我和我的影子」为题',5,'哲思','影子是另一个你吗？'],
  ['skill','用不可靠叙述者写一个撒谎的孩子',5,'叙事','读者能从字缝里发现真相'],
  ['theme','以「边界」为题',5,'哲思','有形的边界，无形的边界'],
  ['skill','用纯对话完成一个反转故事',5,'对话','只有对话，结尾要有反转'],
  ['theme','以「城市的呼吸」为题',5,'散文','把城市写成一个活物'],
  ['skill','用魔幻现实主义手法写排队的一天',5,'魔幻','现实的场景，魔幻的细节'],
  ['theme','以「备份人生」为题',5,'科幻','如果人生可以备份，你会备份哪一天？'],
  ['skill','用复调结构写两种声音的争辩',5,'结构','两种声音平行展开，互不打断'],
  ['theme','以「消失的方言」为题',5,'文化','一种正在消失的语言，一段正在消失的记忆'],
  ['skill','写一首十四行诗',5,'诗歌','严格十四行，有韵脚或节奏感'],
  ['theme','以「第七天」为题',5,'小说','第七天发生了什么？前六天呢？'],
  ['skill','用倒计时结构写地震中的十分钟',5,'结构','10:00、9:00…每分钟一段'],
  // 难度 6（挑战）
  ['theme','写一个没有「人」出现但充满人的痕迹的故事',6,'实验','空椅子、半杯水、开着的电视……'],
  ['skill','全文只用陈述句写一个悲伤的故事',6,'限制','禁止疑问句、感叹句、祈使句'],
  ['theme','以「零」为题写一篇哲理散文',6,'哲思','零是开始还是结束？'],
  ['skill','用注释体（正文+脚注）写一篇短文',6,'形式','脚注不少于 5 个，正文与脚注互相补充'],
  ['theme','以「平行世界的我在写作业」为题',6,'脑洞','两个世界的作业，哪个更真实？'],
  ['skill','用词条/词典体写「家乡」',6,'形式','至少 5 个词条，按词典格式'],
  ['theme','以「噪音考古学」为题',6,'创意','一百年后的人如何考古今天的声音？'],
  ['skill','写一个循环叙事，结尾接回开头',6,'结构','无缝循环，读者读到最后发现回到起点'],
  ['theme','以「最后一位读者」为题',6,'科幻','最后一个读书的人，和最后一本书'],
  ['skill','用实验诗体写「地铁运行图」',6,'诗歌','站名、线路、换乘，都可以是诗'],
  ['theme','以「翻译一封看不懂的信」为题',6,'创意','信上的字都不认识，你翻译出了什么？'],
  ['skill','用极简主义写一篇 100 字小说',6,'限制','100 字以内，必须含反转'],
  ['theme','以「未来考古报告：21 世纪的手机」为题',6,'科幻','用考古报告的口吻描述手机这件「文物」'],
  ['skill','用系统日志体讲一个故事',6,'形式','ERROR/WARN/INFO 之间，藏着一个故事'],
  ['theme','以「遗忘服务所」为题',6,'科幻','你想遗忘什么？代价是什么？'],
  ['skill','用两种颜色贯穿全文写一段人生',6,'意象','两种颜色交替出现，对应人生的两面'],
];

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
    // email_codes 表（邮箱验证码登录）
    await dbRun(env, `CREATE TABLE IF NOT EXISTS email_codes (email TEXT PRIMARY KEY, code TEXT, expires_at INTEGER, attempts INTEGER DEFAULT 0, created_at INTEGER)`);
    // reset_tokens 表
    await dbRun(env, `CREATE TABLE IF NOT EXISTS reset_tokens (
      token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL
    )`);
    // tokens 表（登录 session——之前漏建了！导致每次 login 返回 200 但 token 根本没存）
    await dbRun(env, `CREATE TABLE IF NOT EXISTS tokens (
      token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL
    )`);
    // comments 表
    await dbRun(env, `CREATE TABLE IF NOT EXISTS comments (
      id TEXT PRIMARY KEY, target_type TEXT, target_id TEXT, author_id TEXT,
      content TEXT, parent_id TEXT, likes TEXT, created_at INTEGER
    )`);
    // notifications 表
    await dbRun(env, `CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY, user_id TEXT, type TEXT, target_id TEXT, target_type TEXT,
      from_user_id TEXT, content TEXT, read INTEGER DEFAULT 0, created_at INTEGER
    )`);
    // ai_limits / ai_cache（之前在 ensureAiTables 里，挪过来）
    await dbRun(env, `CREATE TABLE IF NOT EXISTS ai_limits (
      user_id TEXT, day TEXT, count INTEGER DEFAULT 0, PRIMARY KEY (user_id, day)
    )`);
    await dbRun(env, `CREATE TABLE IF NOT EXISTS ai_cache (
      hash TEXT PRIMARY KEY, result TEXT, source TEXT, created_at INTEGER
    )`);
    // messages 表（私信）
    await dbRun(env, `CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT NOT NULL,
      content TEXT, created_at INTEGER, \`read\` INTEGER DEFAULT 0
    )`);
    await dbRun(env, `CREATE TABLE IF NOT EXISTS invite_codes (
      code TEXT PRIMARY KEY, purpose TEXT NOT NULL, created_by TEXT NOT NULL,
      created_at INTEGER NOT NULL, used INTEGER DEFAULT 0, used_by TEXT, used_at INTEGER
    )`);
    // 讨论区：求助帖
    await dbRun(env, `CREATE TABLE IF NOT EXISTS help_posts (
      id TEXT PRIMARY KEY, author_id TEXT NOT NULL, title TEXT NOT NULL,
      content TEXT, status TEXT DEFAULT 'open', created_at INTEGER
    )`);
    // 讨论区：求助回复
    await dbRun(env, `CREATE TABLE IF NOT EXISTS help_replies (
      id TEXT PRIMARY KEY, post_id TEXT NOT NULL, author_id TEXT NOT NULL,
      content TEXT NOT NULL, is_solution INTEGER DEFAULT 0, created_at INTEGER
    )`);
    // 讨论区：群聊消息（group_id 为空的历史数据是旧大厅消息，不再展示）
    await dbRun(env, `CREATE TABLE IF NOT EXISTS chat_messages (
      id TEXT PRIMARY KEY, author_id TEXT NOT NULL, content TEXT NOT NULL, created_at INTEGER
    )`);
    try { await dbRun(env, `ALTER TABLE chat_messages ADD COLUMN group_id TEXT`); } catch {}
    // 讨论区：群聊（多群制 + 群主审核入群）；name 加 UNIQUE 防多 isolate 并发 seed 重复建群
    await dbRun(env, `CREATE TABLE IF NOT EXISTS chat_groups (
      id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT DEFAULT '',
      emoji TEXT DEFAULT '💬', owner_id TEXT, created_at INTEGER
    )`);
    await dbRun(env, `CREATE TABLE IF NOT EXISTS chat_members (
      group_id TEXT NOT NULL, user_id TEXT NOT NULL,
      status TEXT DEFAULT 'pending', joined_at INTEGER,
      PRIMARY KEY (group_id, user_id)
    )`);
    // 旧表若无 UNIQUE 约束：按名字去重（保留最早一组）后重建（一次性，幂等）
    try {
      const ddl = await env.DB.prepare(`SELECT sql FROM sqlite_master WHERE type='table' AND name='chat_groups'`).first();
      if (ddl && ddl.sql && !ddl.sql.includes('UNIQUE')) {
        await env.DB.prepare(`DELETE FROM chat_groups WHERE rowid NOT IN (SELECT MIN(rowid) FROM chat_groups GROUP BY name)`).run();
        await env.DB.prepare(`CREATE TABLE chat_groups_new (
          id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT DEFAULT '',
          emoji TEXT DEFAULT '💬', owner_id TEXT, created_at INTEGER
        )`).run();
        await env.DB.prepare(`INSERT INTO chat_groups_new SELECT id, name, description, emoji, owner_id, created_at FROM chat_groups`).run();
        await env.DB.prepare(`DROP TABLE chat_groups`).run();
        await env.DB.prepare(`ALTER TABLE chat_groups_new RENAME TO chat_groups`).run();
        await env.DB.prepare(`DELETE FROM chat_members WHERE group_id NOT IN (SELECT id FROM chat_groups)`).run();
      }
    } catch {}
    // 预置群（仅群表为空时插入一次，群主 = 站长 admin；OR IGNORE 依赖 name UNIQUE 挡并发）
    try {
      const gcnt = (await env.DB.prepare(`SELECT COUNT(*) AS n FROM chat_groups`).first()).n;
      if (!gcnt) {
        const admin = (await env.DB.prepare(`SELECT id FROM users WHERE role='admin' LIMIT 1`).first());
        const seeds = [
          ['📢', '官方公告', '网站更新、比赛通知、重要事项都在这里'],
          ['💬', '灌水闲聊', '天南海北随便聊，开心就好'],
          ['📖', '写作交流', '分享写作技巧，互相点评文章'],
          ['🎮', '兴趣杂谈', '游戏、动漫、音乐，在这里找到同好']
        ];
        for (const [emoji, name, desc] of seeds) {
          const gid = uid('g'), now = Date.now();
          await env.DB.prepare(`INSERT OR IGNORE INTO chat_groups (id, name, description, emoji, owner_id, created_at) VALUES (?,?,?,?,?,?)`)
            .bind(gid, name, desc, emoji, admin ? admin.id : null, now).run();
          if (admin) {
            await env.DB.prepare(`INSERT OR IGNORE INTO chat_members (group_id, user_id, status, joined_at)
              SELECT id, ?, 'approved', ? FROM chat_groups WHERE name = ?`).bind(admin.id, now, name).run();
          }
        }
      }
    } catch {}
    await dbRun(env, `CREATE INDEX IF NOT EXISTS idx_help_replies_post ON help_replies(post_id)`);
    await dbRun(env, `CREATE INDEX IF NOT EXISTS idx_chat_created ON chat_messages(created_at)`);
    // 公告表（站点公告，先只有一条「文汇新用户必读」，固定 id + OR IGNORE 幂等）
    await dbRun(env, `CREATE TABLE IF NOT EXISTS announcements (
      id TEXT PRIMARY KEY, title TEXT NOT NULL, content TEXT, created_at INTEGER
    )`);
    try {
      await env.DB.prepare(`INSERT OR IGNORE INTO announcements (id, title, content, created_at) VALUES (?,?,?,?)`)
        .bind('ann_readme', '📢 文汇新用户必读', [
          '欢迎来到「文汇」！这是一份 5 分钟看完的新手指南，帮你快速上手：',
          '',
          '## ✍️ 写文章与审核',
          '- 点侧边栏「📖 文章库」→ 右上角「✍️ 我要写文章」，支持 Markdown 排版',
          '- 管理员的文章发布即通过；普通用户提交后进入「待审核」，管理员通过后才会出现在文章库',
          '- 写好的文章在「📝 我的文章」里随时查看、编辑、删除',
          '',
          '## 🏁 比赛与题库',
          '- 「🏁 比赛广场」可以报名比赛，比赛开始后会收到通知提醒',
          '- 「📚 题库」是写作题目练习：你也可以出题（需审核），出被采纳的题、做练习都能涨积分',
          '- 报名比赛后在比赛页提交作品，截止时间前可以修改',
          '',
          '## 🙋 讨论区（求助 + 群聊）',
          '- 「🙋 求助问答」：写作遇到问题就发求助，别人回复后你可以采纳最佳答案',
          '- 「💬 群聊大厅」：目前有 4 个群（官方公告 / 灌水闲聊 / 写作交流 / 兴趣杂谈），加群需要群主（站长）审核',
          '',
          '## ❤️ 互动与通知',
          '- 文章支持点赞、评论、星级点评；帖子和评论也可以互动',
          '- 所有互动（点赞 / 评论 / 回复 / 采纳 / 比赛开始 / 题目审核）都会在右上角 🔔 通知中心提醒你',
          '',
          '## 🏆 积分与排行',
          '- 积分 = 文章×10 + 帖子×5 + 获赞×3 + 评论×2，排行见「🏆 排行榜」',
          '- 每天来「🔥 每日打卡」也有积分拿',
          '',
          '## 📤 其他',
          '- 「📤 文件投稿」支持上传 pdf / doc / zip 等文件，审核通过后自动转成文章展示',
          '- 有问题可以进讨论区发求助，管理员和热心网友都会帮你！',
          '',
          '> 祝你在文汇玩得开心，写出好文章！🎉'
        ].join('\n'), 1791706692076).run();
    } catch {}
  } catch {}

  /* ---------- 旧 camelCase 表一次性迁移为 snake_case（saveDB 时代遗留） ---------- */
  // files/problems/practices 是旧 saveDB 按内存对象自动建的表，列名是 camelCase（authorId、
  // originalName、createdAt），导致所有 snake_case SQL 报 "no such column"：投稿上传失败、
  // 审核列表永远为空。这里运行时检测真实列名，若是 camelCase 则建新表搬数据后换名（幂等）。
  async function migrateTableToSnake(table, createSQL, colMap) {
    try {
      const info = (await env.DB.prepare(`PRAGMA table_info(${table})`).all()).results || [];
      const cols = info.map(c => c.name);
      if (cols.length === 0) { await env.DB.prepare(createSQL).run(); return; } // 表不存在 → 直接建
      const needCols = colMap.map(m => m.s);
      if (needCols.every(c => cols.includes(c))) return; // 已是 snake_case → 跳过
      await env.DB.prepare(`DROP TABLE IF EXISTS ${table}__mig`).run();
      await env.DB.prepare(createSQL.replace(`TABLE ${table}`, `TABLE ${table}__mig`)).run();
      const pick = m => cols.includes(m.s) ? m.s : (cols.includes(m.c) ? m.c : 'NULL');
      const sel = colMap.map(m => `${pick(m)} AS ${m.s}`).join(', ');
      await env.DB.prepare(`INSERT INTO ${table}__mig (${needCols.join(',')}) SELECT ${sel} FROM ${table}`).run();
      await env.DB.prepare(`DROP TABLE ${table}`).run();
      await env.DB.prepare(`ALTER TABLE ${table}__mig RENAME TO ${table}`).run();
      console.error(`[migrate] ${table}: camelCase → snake_case 迁移完成`);
    } catch (e) { console.error(`[migrate] ${table} 迁移失败:`, e.message); }
  }
  await migrateTableToSnake('files', `CREATE TABLE files (
    id TEXT PRIMARY KEY, author_id TEXT, original_name TEXT, stored_name TEXT,
    size INTEGER, note TEXT, status TEXT, created_at INTEGER, reviewed_at INTEGER
  )`, [
    { s: 'id', c: 'id' }, { s: 'author_id', c: 'authorId' },
    { s: 'original_name', c: 'originalName' }, { s: 'stored_name', c: 'storedName' },
    { s: 'size', c: 'size' }, { s: 'note', c: 'note' }, { s: 'status', c: 'status' },
    { s: 'created_at', c: 'createdAt' }, { s: 'reviewed_at', c: 'reviewedAt' }
  ]);
  await migrateTableToSnake('problems', `CREATE TABLE problems (
    id TEXT PRIMARY KEY, type TEXT, title TEXT, content TEXT, difficulty INTEGER,
    tags TEXT, created_by TEXT, status TEXT DEFAULT 'approved', created_at INTEGER, reviewed_at INTEGER
  )`, [
    { s: 'id', c: 'id' }, { s: 'type', c: 'type' }, { s: 'title', c: 'title' },
    { s: 'content', c: 'content' }, { s: 'difficulty', c: 'difficulty' }, { s: 'tags', c: 'tags' },
    { s: 'created_by', c: 'createdBy' }, { s: 'status', c: 'status' },
    { s: 'created_at', c: 'createdAt' }, { s: 'reviewed_at', c: 'reviewedAt' }
  ]);
  await migrateTableToSnake('practices', `CREATE TABLE practices (
    id TEXT PRIMARY KEY, problem_id TEXT, author_id TEXT, title TEXT, content TEXT,
    word_count INTEGER, created_at INTEGER
  )`, [
    { s: 'id', c: 'id' }, { s: 'problem_id', c: 'problemId' }, { s: 'author_id', c: 'authorId' },
    { s: 'title', c: 'title' }, { s: 'content', c: 'content' },
    { s: 'word_count', c: 'wordCount' }, { s: 'created_at', c: 'createdAt' }
  ]);
  // templates 表之前根本没建过，种子数据一直静默失败
  await migrateTableToSnake('templates', `CREATE TABLE templates (
    id TEXT PRIMARY KEY, title TEXT, category TEXT, description TEXT,
    content TEXT, created_at INTEGER
  )`, [
    { s: 'id', c: 'id' }, { s: 'title', c: 'title' }, { s: 'category', c: 'category' },
    { s: 'description', c: 'description' }, { s: 'content', c: 'content' }, { s: 'created_at', c: 'createdAt' }
  ]);

  // 文件内容表：正文以 base64 存 D1（KV 曾被清空导致旧文件全丢，现在内容跟着 D1 走）
  try { await dbRun(env, `CREATE TABLE IF NOT EXISTS file_blobs (id TEXT PRIMARY KEY, content TEXT)`); } catch {}

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
      ['a_welcome', 'u_admin', '欢迎来到文汇 · 文章竞赛社区',
       '## 这里可以做什么\n\n- **写文章**：点击侧边栏「我的文章」或主页「立即开始创作」。\n- **逛论坛**：在「论坛广场」发帖交流。\n- **打比赛**：在「比赛广场」报名参赛。\n\n祝大家玩得开心！',
       '其他', 'approved', 128, '[]', now - 86400000, now - 86000000]);
  }

  // 新人报到帖
  let pc = (await dbFirst(env, 'SELECT COUNT(*) as c FROM posts'))?.c || 0;
  if (pc === 0) {
    await dbRun(env, `INSERT INTO posts (id,author_id,title,content,category,status,created_at,comments) VALUES (?,?,?,?,?,?,?,?)`,
      ['p_hello', 'u_admin', '【置顶】新人报到帖', '新来的同学在这里打个招呼吧！', '其他', 'approved', now - 43200000, '[]']);
  }

  // Demo 比赛（同时修复旧 saveDB 覆盖导致的 null 时间）
  await dbRun(env, `INSERT INTO contests (id,title,description,problems,start_time,end_time,created_by,created_at,participants,submissions) VALUES (?,?,?,?,?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET
      start_time = COALESCE(excluded.start_time, contests.start_time),
      end_time = COALESCE(excluded.end_time, contests.end_time),
      created_by = COALESCE(excluded.created_by, contests.created_by),
      created_at = COALESCE(excluded.created_at, contests.created_at)`,
    ['c_demo', '第一届「文汇杯」短文创作赛', '## 比赛说明\n\n围绕主题「代码与生活」写短文。',
     JSON.stringify([
       { id: 'q_demo1', title: '主题创作', content: '围绕比赛主题作文', wordLimit: 2000 },
       { id: 'q_demo2', title: '自由发挥', content: '题材不限', wordLimit: 2000 }
     ]),
     now - 3600000, now + 7 * 86400000, 'u_admin', now - 7200000, '[]', '[]']);

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

  // 题库扩充包（100 题，难度 1-6；幂等：只插不存在的）
  try {
    const haveRows = await dbAll(env, 'SELECT id FROM problems');
    const have = new Set((haveRows || []).map(r => r.id));
    let idx = 0;
    for (const [type, title, diff, tags, hint] of PROBLEM_PACK) {
      idx++;
      const id = 'q_x' + idx;
      if (have.has(id)) continue;
      const wc = type === 'theme'
        ? (diff <= 2 ? '400-800' : diff <= 4 ? '600-1200' : '800-1500') + ' 字'
        : (100 + diff * 100) + ' 字左右';
      const content = `## 要求\n\n- ${hint}\n- 建议字数 ${wc}${type === 'skill' ? '，注重技巧的自然融入' : ''}`;
      await dbRun(env, `INSERT INTO problems (id,type,title,content,difficulty,tags,created_by,created_at,status) VALUES (?,?,?,?,?,?,?,?,?)`,
        [id, type, title, content, diff, JSON.stringify(tags.split(',')), 'u_admin', now, 'approved']);
    }
  } catch {}

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
  if (_cache && !_cacheDirty) return _cache;
  try { await ensureSeedData(env); } catch {}
  // 并行加载所有表（15 个 SELECT 同时发出）
  const results = await Promise.all(CACHED_TABLES.map(async t => {
    try { return [t, await dbAll(env, `SELECT * FROM ${t}`)]; }
    catch { return [t, []]; }
  }));
  _cache = Object.fromEntries(results);
  _cacheDirty = false;
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
  } catch (e) { console.error('dbFirst:', sql.slice(0, 60), e.message); return null; }
}
async function dbAll(env, sql, binds = []) {
  if (!env.DB) return [];
  try {
    const r = await env.DB.prepare(sql).bind(...binds).all();
    return (r.results || []).map(toCamel);
  } catch (e) { console.error('dbAll:', sql.slice(0, 60), e.message); return []; }
}
async function dbRun(env, sql, binds = []) {
  if (!env.DB) return null;
  try { return await env.DB.prepare(sql).bind(...binds).run(); } catch (e) { console.error('dbRun:', sql.slice(0, 60), e.message); return null; }
}

/* ---------------- 辅助函数 ---------------- */
// 同时兼容 snake_case（D1 原始）和 camelCase（内存对象）
const pub = (u) => {
  if (!u) return null;
  return {
    id: u.id,
    username: u.username,
    nickname: u.nickname,
    role: u.role,
    bio: u.bio || '',
    createdAt: u.createdAt ?? u.created_at
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

/* 实时从 D1 计算用户积分（和排行榜同算法）*/
async function computeScore(env, userId) {
  const pracCols = await getTableCols(env, 'practices');
  const checkCols = await getTableCols(env, 'checkins');
  const pracAuthorCol = pracCols.includes('author_id') ? 'author_id' : 'authorId';
  const checkUserCol = checkCols.includes('user_id') ? 'user_id' : 'userId';
  let artRows = [], postRows = [], pracRows = [], checkRows = [];
  try { artRows = (await env.DB.prepare(`SELECT likes FROM articles WHERE author_id=? AND status='approved'`).bind(userId).all()).results || []; } catch {}
  try { postRows = (await env.DB.prepare(`SELECT comments FROM posts WHERE author_id=? AND status='approved'`).bind(userId).all()).results || []; } catch {}
  try { pracRows = (await env.DB.prepare(`SELECT id FROM practices WHERE ${pracAuthorCol}=?`).bind(userId).all()).results || []; } catch {}
  try { checkRows = (await env.DB.prepare(`SELECT id FROM checkins WHERE ${checkUserCol}=?`).bind(userId).all()).results || []; } catch {}
  let likes = 0, comments = 0;
  for (const a of artRows) try { likes += (JSON.parse(a.likes || '[]')).length; } catch {}
  for (const p of postRows) try { comments += (JSON.parse(p.comments || '[]')).length; } catch {}
  return {
    score: artRows.length * 10 + postRows.length * 5 + likes * 3 + comments * 2 + pracRows.length * 2 + checkRows.length * 2,
    articles: artRows.length, posts: postRows.length, likes, comments, practices: pracRows.length, checkins: checkRows.length
  };
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// userById: 从 D1 查询（dbFirst 返回 camelCase）
async function userById(env, id) {
  return dbFirst(env, 'SELECT * FROM users WHERE id = ?', [id]);
}
async function userByIdByUsername(env, username) {
  return dbFirst(env, 'SELECT * FROM users WHERE username = ? COLLATE NOCASE', [username]);
}
// userById 同步版：从内存 _cache 找（推荐，已经 loadDB 预加载了）
function userByIdSync(db, id) {
  if (!db || !db.users) return null;
  return db.users.find(u => u.id === id) || null;
}
function withAuthorSync(db, item) {
  // 防御：历史调用点曾把参数顺序写成 (item, db)，导致 ...item 展开整个 db 泄露用户 hash
  if (db && !Array.isArray(db.users) && item && Array.isArray(item.users)) { const t = db; db = item; item = t; }
  const a = item ? userByIdSync(db, item.authorId) : null;
  return { ...(item || {}), author: pub(a) || { nickname: '已注销用户' } };
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
    difficulty: parseInt(p.difficulty, 10) || 1,
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
function withAuthorSyncSimple(id, db) {
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

/* AI 限频：每用户每天 MAX_PER_USER 次，全局每天 MAX_GLOBAL 次（保护免费 10k Neurons） */
const AI_MAX_PER_USER = 10;       // 每用户每天 10 次（够写大纲+润色+批改 2 篇）
const AI_MAX_GLOBAL = 1200;       // 全局每天 1200 次（约 9600 Neurons，留 buffer）
const AI_CACHE_TTL = 3600;        // 相同请求缓存 1 小时（省重复调用）

function aiTodayKey() { return new Date().toISOString().slice(0, 10); } // YYYY-MM-DD

async function cryptoHash(str) {
  try {
    const buf = new TextEncoder().encode(str);
    const hashBuf = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2,'0')).join('').slice(0, 24);
  } catch {
    // fallback：简单 hash
    let h = 0;
    for (let i = 0; i < str.length; i++) h = ((h << 5) - h + str.charCodeAt(i)) | 0;
    return 'h_' + Math.abs(h).toString(36);
  }
}

/* 确保 AI 相关表存在（D1 的 CREATE TABLE IF NOT EXISTS 需显式调） */
async function ensureAiTables(env) {
  if (!env.DB) return;
  try { await env.DB.prepare(`CREATE TABLE IF NOT EXISTS ai_limits (
    user_id TEXT, day TEXT, count INTEGER DEFAULT 0,
    PRIMARY KEY (user_id, day))`).run(); } catch {}
  try { await env.DB.prepare(`CREATE TABLE IF NOT EXISTS ai_cache (
    hash TEXT PRIMARY KEY, result TEXT, source TEXT, created_at INTEGER)`).run(); } catch {}
}

async function checkAiLimit(env, userId) {
  if (!env.DB) return { ok: true, reason: '' };
  const dayKey = aiTodayKey();

  // 全局计数
  const gRow = await env.DB.prepare(`SELECT COALESCE(SUM(count),0) as c FROM ai_limits WHERE day = ?`).bind(dayKey).first();
  const globalCount = gRow?.c || 0;
  if (globalCount >= AI_MAX_GLOBAL) return { ok: false, reason: '今日 AI 额度已用完，请明天再来' };

  // 用户计数
  const uRow = await env.DB.prepare(`SELECT count FROM ai_limits WHERE user_id = ? AND day = ?`).bind(userId, dayKey).first();
  const userCount = uRow?.count || 0;
  if (userCount >= AI_MAX_PER_USER) return { ok: false, reason: `今日 AI 次数已用完（${AI_MAX_PER_USER}次/天），明天再来吧` };

  return { ok: true, remaining: AI_MAX_PER_USER - userCount - 1 };
}

async function incrementAiUsage(env, userId) {
  if (!env.DB) return;
  const dayKey = aiTodayKey();
  await env.DB.prepare(`INSERT INTO ai_limits (user_id, day, count) VALUES (?, ?, 1)
    ON CONFLICT(user_id, day) DO UPDATE SET count = count + 1`).bind(userId, dayKey).run();
}

async function getAiCache(env, hash) {
  if (!env.DB) return null;
  const row = await env.DB.prepare(`SELECT result, source FROM ai_cache WHERE hash = ? AND created_at > ?`)
    .bind(hash, Math.floor(Date.now()/1000) - AI_CACHE_TTL).first();
  return row ? { result: row.result, source: row.source } : null;
}

async function setAiCache(env, hash, result, source) {
  if (!env.DB) return;
  await env.DB.prepare(`INSERT OR REPLACE INTO ai_cache (hash, result, source, created_at)
    VALUES (?, ?, ?, ?)`).bind(hash, result, source, Math.floor(Date.now()/1000)).run();
}

/* AI 写作助手：优先 Workers AI → 缓存命中 → 超限 fallback 模板 */
async function aiAssist(env, userId, task, { topic, content, style, extra }) {
  const topicStr = topic || '';
  const contentStr = content || '';
  const styleStr = style || '';
  const extraStr = extra || '';

  // 先确保表存在（避免 "no such table"）
  await ensureAiTables(env);

  // 生成请求 hash（去重缓存）
  const hash = await cryptoHash(`${task}|${topicStr}|${contentStr.slice(0,300)}|${styleStr}`);

  // 1) 先查缓存
  const cached = await getAiCache(env, hash);
  if (cached) return { ...cached, cached: true, remaining: -1 };

  // 2) 检查限频
  const limit = await checkAiLimit(env, userId);
  if (!limit.ok) {
    // 超限 → fallback 模板（不扣次数）
    return { result: aiFallback(task, topicStr, contentStr, styleStr), source: 'template', limited: true, reason: limit.reason };
  }

  // 3) 尝试 Workers AI
  try {
    if (env && env.AI) {
      const prompt = buildAiPrompt(task, topicStr, contentStr, styleStr, extraStr);
      const resp = await env.AI.run('@cf/meta/llama-3.2-1b-instruct', {
        prompt, max_tokens: 800
      });
      const text = resp && resp.response ? resp.response.trim() : '';
      if (text && text.length > 5) {
        await incrementAiUsage(env, userId);
        await setAiCache(env, hash, text, 'ai');
        return { result: text, source: 'ai', remaining: limit.remaining };
      }
    }
  } catch (e) { /* AI 不可用时 fallback */ }

  // Fallback：本地精心设计的回复模板
  return { result: aiFallback(task, topicStr, contentStr, styleStr), source: 'template', remaining: limit?.remaining ?? AI_MAX_PER_USER };
}

function buildAiPrompt(task, topic, content, style, extra) {
  const sys = '你是一个专业的中文写作助手，帮助用户提高写作能力。用中文简洁回答。';
  const tasks = {
    write: `请根据用户的描述，写一篇完整的文章。\n描述：${topic}\n${style ? `风格/字数要求：${style}\n` : ''}${content ? `参考已有内容：${content.slice(0, 500)}\n` : ''}${extra ? `其他要求：${extra}\n` : ''}请用 Markdown 格式输出完整文章，包含标题、分段、适当使用 **加粗** 等格式。`,
    outline: `请为这个写作主题生成一个详细的大纲：\n主题：${topic}\n${style ? `风格：${style}\n` : ''}${extra ? `要求：${extra}\n` : ''}请用 Markdown 格式输出，包含 3-5 个主要部分，每个部分 2-3 个要点。`,
    rewrite: `请润色以下这段文字，让它更${style || '流畅、生动'}：\n\n${content}\n\n润色后的版本：`,
    continue: `请续写以下内容，保持文风一致：\n\n${content}\n\n续写部分：`,
    review: `请以语文老师的角度，对以下文章进行点评。给出：1）总体评价（星级）；2）亮点；3）改进建议。\n\n${content}\n\n点评：`
  };
  return `${sys}\n\n${tasks[task] || tasks.write}`;
}

function aiFallback(task, topic, content, style) {
  switch (task) {
    case 'write': {
      const t = topic || '你的主题';
      return `# ${t}

## 引言

关于「${t}」，每个人都有自己的理解。${style === '议论文' ? '它不是一个非黑即白的命题，而是值得我们反复思考的话题。' : '让我们慢慢展开，看看它能带给我们什么样的感受。'}

## 展开

${style === '议论文' ? '首先，我们需要明确核心观点。任何讨论都不能停留在表面，我们需要追溯问题的根源。其次，多角度的分析能让我们看得更全面——既要看它的积极面，也要承认它可能带来的挑战。' : '每一个细节都值得细细品味。它们或许不显眼，但正是这些细碎的片段，拼出了完整的画面。当我们停下来认真感受时，会发现意想不到的触动。'}

${content ? `> 参考了你已写的内容，以下是延续：\n\n${content.slice(0, 200)}...` : ''}

## 结语

${style === '议论文' ? '结论或许并不重要，重要的是思考本身。希望这篇文字能带给你一些启发。' : '文字到这里告一段落，但思考和感受会继续。愿你写出更多属于自己的故事。'}

---

*（AI 模板回复，开启 Workers AI 后自动替换为真实 AI 生成内容）*`;
    }
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
// Token → userId 内存缓存（避免每次 auth 都查 D1 tokens 表）
const _tokenCache = new Map(); // token → { userId, expiresAt }
async function resolveToken(env, token) {
  if (!token) return null;
  // 内存缓存命中
  const cached = _tokenCache.get(token);
  if (cached && cached.expiresAt > Date.now()) return cached.userId;
  if (cached) _tokenCache.delete(token);
  // 查 D1（expires_at 存的是秒级时间戳）
  try {
    const row = await env.DB.prepare(`SELECT user_id, expires_at FROM tokens WHERE token = ?`).bind(token).first();
    if (!row) return null;
    const nowSec = Math.floor(Date.now() / 1000);
    if (row.expires_at < nowSec) return null; // 秒 vs 秒
    // 缓存用毫秒方便统一比较
    _tokenCache.set(token, { userId: row.user_id, expiresAt: row.expires_at * 1000 });
    return row.user_id;
  } catch { return null; }
}

async function auth(request, env) {
  const header = request.headers.get('Authorization') || '';
  const token = header.replace(/^Bearer\s+/i, '');
  const userId = await resolveToken(env, token);
  if (!userId) return null;
  // 直接 env.DB.prepare 查，不吞异常（dbFirst 的 catch {} 会把真实错误藏起来）
  let row;
  try { row = (await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first()); } catch { return null; }
  if (!row) return null;
  return toCamel(row);
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

/* 添加通知（直接写 D1，多 isolate 安全；fromUserId 为空表示系统通知） */
async function addNotif(env, fromUserId, type, toUserId, targetType, targetId, content) {
  if (!toUserId) return;
  if (fromUserId && fromUserId === toUserId) return;
  try {
    await env.DB.prepare(`INSERT INTO notifications (id,user_id,type,from_id,target_type,target_id,content,read,created_at) VALUES (?,?,?,?,?,?,?,?,?)`)
      .bind(uid('n'), toUserId, type, fromUserId || '', targetType, targetId, content, 0, Date.now()).run();
  } catch {}
}

/* 惰性检查：我报名的比赛已开始且未通知过 → 补发通知（Workers 无 cron，靠用户轮询触发） */
async function checkContestStart(env, me) {
  try {
    const now = Date.now();
    const r = await env.DB.prepare(`SELECT id, title, participants FROM contests WHERE start_time <= ?`).bind(now).all();
    for (const c of (r.results || [])) {
      let parts = safeJSON(c.participants);
      if (!Array.isArray(parts) || !parts.includes(me.id)) continue;
      const hit = await env.DB.prepare(`SELECT id FROM notifications WHERE user_id=? AND type='contest_start' AND target_id=? LIMIT 1`).bind(me.id, c.id).first();
      if (hit) continue;
      await addNotif(env, null, 'contest_start', me.id, 'contest', c.id, `你参加的比赛《${c.title}》已开始，快去提交作品吧！`);
    }
  } catch {}
}

/* ---------------- QQ 邮箱 SMTP 直发 ---------------- */
async function smtpRead(reader, expect, step) {
  let buf = '';
  const end = Date.now() + 8000;
  const dec = new TextDecoder();
  while (true) {
    const lines = buf.split('\r\n');
    for (let i = 0; i < lines.length - 1; i++) {
      if (/^\d{3} /.test(lines[i])) {
        const code = parseInt(lines[i].slice(0, 3), 10);
        if (code !== expect) throw new Error('SMTP ' + step + ' 失败: ' + lines[i].slice(0, 120));
        return;
      }
    }
    if (Date.now() > end) throw new Error('SMTP ' + step + ' 响应超时');
    const left = Math.max(100, end - Date.now());
    const r = await Promise.race([reader.read(), new Promise((_, rej) => setTimeout(() => rej(new Error('SMTP ' + step + ' 响应超时')), left))]);
    if (r.done) throw new Error('SMTP ' + step + ' 连接已关闭');
    buf += dec.decode(r.value, { stream: true });
  }
}

async function smtpSession(env, to, code, port, mode) {
  const { connect } = await import('cloudflare:sockets');
  const opts = { allowHalfOpen: false };
  if (mode == 'ssl') opts.secureTransport = 'on'; else opts.secureTransport = 'starttls';
  const socket = connect('smtp.qq.com:' + port, opts);
  let reader = socket.readable.getReader();
  const enc = new TextEncoder();
  const b64 = (s) => btoa(String.fromCharCode(...enc.encode(s)));
  let send = (line) => socket.writer.write(enc.encode(line + '\r\n'));
  try {
    await smtpRead(reader, 220, '握手');
    await send('EHLO wenhui.pages.dev');
    await smtpRead(reader, 250, 'EHLO');
    if (mode == 'starttls') {
      await send('STARTTLS');
      await smtpRead(reader, 220, 'STARTTLS');
      const up = socket.upgradeTLS();
      reader = up.readable.getReader();
      const w2 = up.writable;
      send = (line) => w2.write(enc.encode(line + '\r\n'));
      await send('EHLO wenhui.pages.dev');
      await smtpRead(reader, 250, 'EHLO2');
    }
    await send('AUTH LOGIN');
    await smtpRead(reader, 334, 'AUTH 开始');
    await send(b64(env.SMTP_USER));
    await smtpRead(reader, 334, 'AUTH 用户名');
    await send(b64(env.SMTP_PASS));
    await smtpRead(reader, 235, 'AUTH 认证');
    await send('MAIL FROM:<' + env.SMTP_USER + '>');
    await smtpRead(reader, 250, 'MAIL FROM');
    await send('RCPT TO:<' + to + '>');
    await smtpRead(reader, 250, 'RCPT TO');
    await send('DATA');
    await smtpRead(reader, 354, 'DATA');
    const html = '<html><body style="font-family:sans-serif"><h2>文汇登录验证码</h2><p>你的验证码是：</p><p style="font-size:28px;font-weight:700;letter-spacing:6px;color:#2980b9">' + code + '</p><p>10 分钟内有效。如果不是你本人操作，请忽略本邮件。</p></body></html>';
    await send('From: 文汇 <' + env.SMTP_USER + '>\r\nTo: ' + to + '\r\nSubject: =?UTF-8?B?' + b64('文汇登录验证码') + '?=\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n' + html + '\r\n.');
    await smtpRead(reader, 250, '发送正文');
    await send('QUIT');
  } finally {
    try { socket.close(); } catch (_) {}
  }
}

async function sendQQMail(env, to, code) {
  try {
    return await smtpSession(env, to, code, 465, 'ssl');
  } catch (e1) {
    console.error('QQ SMTP 465 失败:', e1 && e1.message);
    return await smtpSession(env, to, code, 587, 'starttls');
  }
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
    let m; // 统一声明 match 结果变量

    // ---- 认证 ----
    if (match(path, 'me') && method === 'GET') {
      const u = await auth(request, env);
      if (!u) return bad('未登录', 401);
      const realtime = await computeScore(env, u.id);
      const full = pubFull(u);
      full.score = realtime.score;
      return json({ user: full });
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
      // 直接 env.DB.prepare 查，不吞异常
      let row;
      try { row = await env.DB.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').bind(username).first(); } catch (e) { return bad(e.message); }
      let user = row ? toCamel(row) : null;
      const genericError = '用户名或密码错误';
      if (!user) { await sleep(300); return bad(genericError); }
      if (user.lockedUntil && Date.now() < user.lockedUntil) {
        const mins = Math.ceil((user.lockedUntil - Date.now()) / 60000);
        return bad(`该账号已因多次登录失败被锁定，请 ${mins} 分钟后再试`, 429);
      }
      const ok = await verifyPassword(body.password, user);
      if (!ok) {
        const newFails = (user.loginFails || 0) + 1;
        const newLocked = newFails >= 5 ? Date.now() + 10 * 60000 : 0;
        const finalFails = newFails >= 5 ? 0 : newFails;
        await env.DB.prepare('UPDATE users SET login_fails=?, locked_until=? WHERE id=?').bind(finalFails, newLocked, user.id).run();
        await sleep(300);
        return bad(genericError);
      }
      await env.DB.prepare('UPDATE users SET login_fails=0, locked_until=0 WHERE id=?').bind(user.id).run();
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

    // ---- 邮箱验证码：发送 ----
    if (match(path, 'auth/email-code') && method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const email = String(body.email || '').trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return bad('请输入正确的邮箱地址');
      const useBrevo = !!(env.MAIL_API_KEY && env.MAIL_FROM);
      const useSMTP = !!(env.SMTP_USER && env.SMTP_PASS);
      if (!useBrevo && !useSMTP) return bad('邮件服务未配置，请联系站长', 503);
      const now = Date.now();
      const old = await dbFirst(env, 'SELECT * FROM email_codes WHERE email=?', [email]);
      if (old && now - (old.createdAt || 0) < 60000) return bad('发送太频繁，请 1 分钟后再试', 429);
      const code = String(Math.floor(100000 + Math.random() * 900000));
      await dbRun(env, `INSERT INTO email_codes (email,code,expires_at,attempts,created_at) VALUES (?,?,?,0,?)
        ON CONFLICT(email) DO UPDATE SET code=excluded.code, expires_at=excluded.expires_at, attempts=0, created_at=excluded.created_at`,
        [email, code, now + 10 * 60000, now]);
      try {
        if (useBrevo) {
          const r = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: { 'api-key': env.MAIL_API_KEY, 'content-type': 'application/json', 'accept': 'application/json' },
            body: JSON.stringify({
              sender: { name: '文汇', email: env.MAIL_FROM },
              to: [{ email }],
              subject: '文汇登录验证码',
              htmlContent: '<div style="font-family:sans-serif"><h2>文汇登录验证码</h2><p>你的验证码是：</p><p style="font-size:28px;font-weight:700;letter-spacing:6px;color:#2980b9">' + code + '</p><p>10 分钟内有效。如果不是你本人操作，请忽略本邮件。</p></div>'
            })
          });
          if (!r.ok) {
            console.error('Brevo send failed:', r.status, (await r.text()).slice(0, 300));
            return bad('验证码邮件发送失败，请稍后再试', 502);
          }
        } else {
          await sendQQMail(env, email, code);
        }
      } catch (e) { console.error('邮件发送失败:', e && e.message); return bad('验证码邮件发送失败: ' + ((e && e.message) || '未知错误').slice(0, 150), 502); }
      return json({ ok: true });
    }

    // ---- 邮箱验证码：校验登录（新邮箱自动注册） ----
    if (match(path, 'auth/email-login') && method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const email = String(body.email || '').trim().toLowerCase();
      const code = String(body.code || '').trim();
      if (!email || !code) return bad('请输入邮箱和验证码');
      const rec = await dbFirst(env, 'SELECT * FROM email_codes WHERE email=?', [email]);
      if (!rec || Date.now() > (rec.expiresAt || 0) || (rec.attempts || 0) >= 5) return bad('验证码无效或已过期');
      if (rec.code !== code) {
        await dbRun(env, 'UPDATE email_codes SET attempts=attempts+1 WHERE email=?', [email]);
        return bad('验证码错误');
      }
      await dbRun(env, 'DELETE FROM email_codes WHERE email=?', [email]);
      let user = await dbFirst(env, 'SELECT * FROM users WHERE email=?', [email]);
      if (!user) {
        const username = 'wenhui_' + String(Math.floor(100000 + Math.random() * 900000));
        const nickname = '文友' + String(Math.floor(1000 + Math.random() * 9000));
        const { salt, hash } = await hashPassword(cryptoRandomHex(16));
        const now = Date.now();
        const id = uid('u');
        await dbRun(env, `INSERT INTO users (id,username,nickname,role,bio,created_at,salt,hash,login_fails,locked_until,score,badges,following,email) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          [id, username, nickname, 'user', '', now, salt, hash, 0, 0, 0, '[]', '[]', email]);
        user = { id, username, nickname, role: 'user', bio: '', createdAt: now, salt, hash, loginFails: 0, lockedUntil: 0, score: 0, badges: [], following: [], email };
      }
      const token = await createToken(env, user.id);
      return json({ user: pub(user), token });
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

    // ---- 用户详情（score 用实时 SQL）----
    m = match(path, 'users/:id');
    if (m && method === 'GET') {
      const u = userByIdSync(db, m.id);
      if (!u) return bad('用户不存在', 404);
      const me = await auth(request, env);
      // 实时 score + 统计数据 + approved 内容列表
      const [realtime, ar, pr] = await Promise.all([
        computeScore(env, u.id),
        env.DB.prepare(`SELECT * FROM articles WHERE author_id=? AND status='approved' ORDER BY created_at DESC`).bind(u.id).all().catch(() => ({ results: [] })),
        env.DB.prepare(`SELECT * FROM posts WHERE author_id=? AND status='approved' ORDER BY created_at DESC`).bind(u.id).all().catch(() => ({ results: [] })),
      ]);
      const articles = (ar.results || []).map(row => ({
        id: row.id, authorId: row.author_id, title: row.title, content: row.content,
        category: row.category, status: row.status, views: row.views, likes: JSON.parse(row.likes || '[]'),
        tags: row.tags, createdAt: row.created_at
      }));
      const posts = (pr.results || []).map(row => ({
        id: row.id, authorId: row.author_id, title: row.title, content: row.content,
        category: row.category, status: row.status, createdAt: row.created_at,
        comments: JSON.parse(row.comments || '[]')
      }));
      // 参加过的比赛
      const contests = db.contests.filter(c =>
        (c.participants || []).includes(u.id) ||
        (c.submissions || []).some(s => s.authorId === u.id)
      ).map(c => ({
        id: c.id, title: c.title, status: c.status || (Date.now() < c.startTime ? 'upcoming' : Date.now() > c.endTime ? 'ended' : 'ongoing'),
        startTime: c.startTime, endTime: c.endTime
      }));
      const following = (u.following || []).map(id => pub(userByIdSync(db, id))).filter(Boolean);
      const followers = db.users.filter(x => (x.following || []).includes(u.id)).map(pub);
      const isFollowing = !!(me && (me.following || []).includes(u.id));
      const userOut = pub(u);
      userOut.badges = u.badges || [];
      return json({
        user: userOut,
        stats: { articles: realtime.articles, posts: realtime.posts, likes: realtime.likes, followerCount: followers.length, followingCount: following.length, score: realtime.score, practices: realtime.practices, checkins: realtime.checkins },
        isFollowing,
        articles: articles.map(a => articleOut(a, db)),
        posts: posts.map(p => postOut(p, db)),
        contests, following, followers
      });
    }

    // ---- 关注/取消 ----
    m = match(path, 'users/:id/follow');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const t = userByIdSync(db, m.id);
      if (!t) return bad('用户不存在', 404);
      if (t.id === me.id) return bad('不能关注自己');
      me.following = me.following || [];
      const i = me.following.indexOf(t.id);
      if (i >= 0) me.following.splice(i, 1); else me.following.push(t.id);
      try { await env.DB.prepare(`UPDATE users SET following=? WHERE id=?`).bind(JSON.stringify(me.following), me.id).run(); } catch (e) { return bad(e.message); }
      invalidateCache();
      const followerCount = db.users.filter(x => (x.following || []).includes(t.id)).length;
      return json({ followed: i < 0, followerCount });
    }

    // ---- DEBUG: 查 D1 表结构 ----
    if (match(path, 'debug/schema') && method === 'GET') {
      const tables = ['users','articles','posts','files','contests','problems','comments','notifications','messages','checkins','practices'];
      const result = {};
      for (const t of tables) {
        try {
          const r = await env.DB.prepare(`PRAGMA table_info(${t})`).all();
          result[t] = r.results.map(c => ({ name: c.name, type: c.type, notnull: c.notnull }));
        } catch (e) { result[t] = { error: String(e) }; }
      }
      return json(result);
    }

    // ---- 首页 ----
    if (match(path, 'home') && method === 'GET') {
      const now = Date.now();
      try {
        const [usersR, artsR, postsR, contestsR] = await Promise.all([
          env.DB.prepare('SELECT * FROM users').all(),
          env.DB.prepare('SELECT * FROM articles').all(),
          env.DB.prepare('SELECT * FROM posts').all(),
          env.DB.prepare('SELECT * FROM contests').all()
        ]);
        const users = (usersR.results || []).map(toCamel);
        const allArts = (artsR.results || []).map(toCamel);
        const allPosts = (postsR.results || []).map(toCamel);
        const allContests = (contestsR.results || []).map(toCamel);
        const approvedArts = allArts.filter(a => a.status === 'approved');
        const approvedPosts = allPosts.filter(p => p.status === 'approved');
        const stats = {
          users: users.length,
          articles: approvedArts.length,
          posts: approvedPosts.length,
          contests: allContests.length
        };
        const latestArticles = await Promise.all(
          approvedArts.sort((a, b) => b.createdAt - a.createdAt).slice(0, 6).map(async row => {
            const author = await userById(env, row.authorId);
            return {
              id: row.id, authorId: row.authorId, title: row.title, content: row.content,
              category: row.category, status: row.status, views: row.views || 0,
              likeCount: (row.likes ? safeJSON(row.likes).length : 0),
              tags: row.tags ? safeJSON(row.tags) : [],
              createdAt: row.createdAt, reviewedAt: row.reviewedAt,
              author: author ? pub(author) : { nickname: '未知用户' }
            };
          })
        );
        const latestPosts = await Promise.all(
          approvedPosts.sort((a, b) => b.createdAt - a.createdAt).slice(0, 6).map(async row => {
            const author = await userById(env, row.authorId);
            return {
              id: row.id, authorId: row.authorId, title: row.title, content: row.content,
              category: row.category, status: row.status, createdAt: row.createdAt,
              commentCount: (row.comments ? safeJSON(row.comments).length : 0),
              author: author ? pub(author) : { nickname: '未知用户' }
            };
          })
        );
        const activeContests = allContests
          .filter(c => (c.startTime || 0) <= now && now <= (c.endTime || 0))
          .map(c => ({
            id: c.id, title: c.title, description: c.description,
            participantCount: (() => { const p = c.participants ? safeJSON(c.participants) : []; return Array.isArray(p) ? p.length : 0; })(),
            problemCount: (() => { const p = c.problems ? safeJSON(c.problems) : []; return Array.isArray(p) ? p.length : 0; })(),
            startTime: c.startTime, endTime: c.endTime, createdAt: c.createdAt,
            status: 'active'
          })).slice(0, 3);
        return json({ stats, latestArticles, latestPosts, activeContests });
      } catch (e) { return json({ stats: { users: 0, articles: 0, posts: 0, contests: 0 }, latestArticles: [], latestPosts: [], activeContests: [] }); }
    }

    // ---- 文章列表（直接 SQL D1，跨 isolate 必拿到最新）----
    if (match(path, 'articles') && method === 'GET') {
      let list = [];
      try {
        const r = await env.DB.prepare(`SELECT * FROM articles WHERE status = 'approved' ORDER BY created_at DESC`).all();
        list = (r.results || []).map(row => ({
          id: row.id, authorId: row.author_id, title: row.title, content: row.content,
          category: row.category, status: row.status, views: row.views, likes: JSON.parse(row.likes || '[]'),
          tags: row.tags, createdAt: row.created_at, reviewedAt: row.reviewed_at
        }));
      } catch {}
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
      // 返回热门标签前 10 个（全量 D1 文章统计）
      let allTags = {};
      try {
        const tr = await env.DB.prepare(`SELECT tags FROM articles`).all();
        (tr.results || []).forEach(row => {
          const t = typeof row.tags === 'string' ? safeJSON(row.tags) : (row.tags || []);
          t.forEach(x => allTags[x] = (allTags[x] || 0) + 1);
        });
      } catch {}
      const hotTags = Object.entries(allTags).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([t]) => t);
      return json({ articles: list.map(a => articleOut(a, db)), hotTags });
    }

    // ---- 我的文章（直接 SQL，跨 isolate 看到最新审核状态）----
    if (match(path, 'articles/mine') && method === 'GET') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      let rows = [];
      try {
        const r = await env.DB.prepare(`SELECT * FROM articles WHERE author_id = ? ORDER BY created_at DESC`).bind(me.id).all();
        rows = await Promise.all((r.results || []).map(async row => {
          const author = await userById(env, row.author_id);
          return {
            id: row.id, authorId: row.author_id, title: row.title, content: row.content,
            category: row.category, status: row.status, views: row.views || 0,
            likeCount: (row.likes ? JSON.parse(row.likes).length : 0),
            tags: row.tags ? JSON.parse(row.tags) : [],
            createdAt: row.created_at, reviewedAt: row.reviewed_at,
            author: author ? pub(author) : { nickname: '未知用户' }
          };
        }));
      } catch (e) { return bad('查询失败: ' + e.message); }
      return json({ articles: rows });
    }

    // ---- 文章详情 ----
    m = match(path, 'articles/:id');
    if (m && method === 'GET') {
      // 直接查 D1（内存 db.articles 跨 isolate 不同步，会误报"文章不存在"）
      let row;
      try { row = await env.DB.prepare(`SELECT * FROM articles WHERE id=?`).bind(m.id).first(); } catch (e) { return bad(e.message); }
      if (!row) return bad('文章不存在', 404);
      const me = await auth(request, env);
      const st = row.status || 'pending';
      const authorId = row.author_id || row.authorId;
      const canView = st === 'approved' || (me && (me.id === authorId || me.role === 'admin'));
      if (!canView) return bad('文章正在审核中', 403);
      let views = row.views || 0;
      if (!me || me.id !== authorId) {
        views += 1;
        try { await env.DB.prepare(`UPDATE articles SET views = ? WHERE id = ?`).bind(views, m.id).run(); } catch {}
      }
      const likesArr = safeJSON(row.likes);
      const a = {
        id: row.id, authorId, title: row.title, content: row.content,
        category: row.category, status: st, views,
        likes: Array.isArray(likesArr) ? likesArr : [],
        tags: safeJSON(row.tags), createdAt: row.created_at || row.createdAt,
        reviewedAt: row.reviewed_at || row.reviewedAt
      };
      const o = articleOut(a, db);
      o.liked = !!(me && a.likes.includes(me.id));
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
      const status = me.role === 'admin' ? 'approved' : 'pending';
      const id = uid('a');
      const now = Date.now();
      // 直接 SQL INSERT（不同 isolate 间必须持久化）
      try {
        await env.DB.prepare(`INSERT INTO articles (id, author_id, title, content, category, status, views, likes, tags, created_at)
          VALUES (?,?,?,?,?,?,?,?,?,?)`)
          .bind(id, me.id, title, content, category, status, 0, '[]', JSON.stringify(tagsRaw), now).run();
        // 立刻 SELECT COUNT 验证真的写进 D1（防止静默丢失）
        const verify = await env.DB.prepare('SELECT COUNT(*) as c FROM articles WHERE id = ?').bind(id).first();
        if (!verify?.c) return bad('创建失败：数据库未确认写入，请稍后重试');
      } catch (e) { return bad('创建失败: ' + e.message); }
      const a = { id, authorId: me.id, title, content, category, status, views: 0, likes: [], tags: JSON.stringify(tagsRaw), createdAt: now };
      db.articles.push(a);
      invalidateCache();
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
      try { await env.DB.prepare(`UPDATE articles SET title=?,content=?,status=?,tags=?,category=?,updated_at=? WHERE id=?`)
        .bind(a.title, a.content, a.status, a.tags, a.category, Date.now(), a.id).run(); } catch (e) { return bad(e.message); }
      invalidateCache();
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
      try { await env.DB.prepare(`DELETE FROM articles WHERE id=?`).bind(m.id).run(); } catch (e) { return bad(e.message); }
      invalidateCache();
      return json({ ok: true });
    }

    // ---- 点赞 ----
    m = match(path, 'articles/:id/like');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      // 直接查 D1：内存行 likes 是 JSON 字符串（曾导致 a.likes.push is not a function）
      let row;
      try { row = await env.DB.prepare(`SELECT id, likes, author_id, title FROM articles WHERE id=? AND status='approved'`).bind(m.id).first(); } catch (e) { return bad(e.message); }
      if (!row) return bad('文章不存在', 404);
      let likes = safeJSON(row.likes);
      if (!Array.isArray(likes)) likes = [];
      const i = likes.indexOf(me.id);
      if (i >= 0) likes.splice(i, 1); else likes.push(me.id);
      try { await env.DB.prepare(`UPDATE articles SET likes=? WHERE id=?`).bind(JSON.stringify(likes), m.id).run(); } catch (e) { return bad(e.message); }
      invalidateCache();
      if (i < 0) await addNotif(env, me.id, 'like', row.author_id, 'article', m.id, `赞了你的文章《${row.title}》`);
      return json({ liked: i < 0, likeCount: likes.length });
    }

    // ---- 帖子列表（直接 SQL）----
    if (match(path, 'posts') && method === 'GET') {
      let list = [];
      try {
        const r = await env.DB.prepare(`SELECT * FROM posts WHERE status = 'approved' ORDER BY created_at DESC`).all();
        list = (r.results || []).map(row => ({
          id: row.id, authorId: row.author_id, title: row.title, content: row.content,
          category: row.category, status: row.status, createdAt: row.created_at,
          comments: JSON.parse(row.comments || '[]')
        }));
      } catch {}
      const cat = url.searchParams.get('category');
      const q = url.searchParams.get('q');
      if (cat) list = list.filter(p => (p.category || '其他') === cat);
      list = searchFilter(list, q, db);
      list.sort((a, b) => b.createdAt - a.createdAt);
      return json({ posts: list.map(p => postOut(p, db)) });
    }

    // ---- 我的帖子（直接 SQL）----
    if (match(path, 'posts/mine') && method === 'GET') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      let rows = [];
      try {
        const r = await env.DB.prepare(`SELECT * FROM posts WHERE author_id = ? ORDER BY created_at DESC`).bind(me.id).all();
        rows = (r.results || []).map(row => ({
          id: row.id, authorId: row.author_id, title: row.title, content: row.content,
          category: row.category, status: row.status, createdAt: row.created_at,
          comments: JSON.parse(row.comments || '[]')
        }));
      } catch {}
      return json({ posts: rows.map(p => postOut(p, db)) });
    }

    // ---- 帖子详情（直接 SQL）----
    m = match(path, 'posts/:id');
    if (m && method === 'GET') {
      let p;
      try {
        const r = await env.DB.prepare(`SELECT * FROM posts WHERE id=?`).bind(m.id).all();
        const row = (r.results || [])[0];
        if (row) p = {
          id: row.id, authorId: row.author_id, title: row.title, content: row.content,
          category: row.category, status: row.status, createdAt: row.created_at,
          comments: JSON.parse(row.comments || '[]')
        };
      } catch {}
      if (!p) return bad('帖子不存在', 404);
      const me = await auth(request, env);
      if (p.status !== 'approved' && !(me && (me.id === p.authorId || me.role === 'admin'))) {
        return bad('帖子正在审核中', 403);
      }
      const o = postOut(p, db);
      o.comments = (p.comments || []).map(c => withAuthorSync(db, c));
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
      try { await env.DB.prepare(`INSERT INTO posts (id,author_id,title,content,category,status,created_at,comments) VALUES (?,?,?,?,?,?,?,?)`)
        .bind(p.id, p.authorId, p.title, p.content, p.category, p.status, p.createdAt, '[]').run(); } catch (e) { return bad(e.message); }
      invalidateCache();
      return json({ post: postOut(p, db) });
    }

    // ---- 评论 ----
    m = match(path, 'posts/:id/comments');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      // 直接 SQL 查帖子
      let p;
      try {
        const r = await env.DB.prepare(`SELECT * FROM posts WHERE id=? AND status='approved'`).bind(m.id).all();
        const row = (r.results || [])[0];
        if (row) p = { id: row.id, comments: JSON.parse(row.comments || '[]') };
      } catch {}
      if (!p) return bad('帖子不存在', 404);
      const body = await request.json();
      const content = clean(body.content, 2000);
      if (!content) return bad('评论不能为空');
      const c = { id: uid('c'), authorId: me.id, content, createdAt: Date.now() };
      p.comments.push(c);
      // 直接 SQL UPDATE
      try { await env.DB.prepare(`UPDATE posts SET comments=? WHERE id=?`).bind(JSON.stringify(p.comments), m.id).run(); }
      catch (e) { return bad('评论失败: ' + e.message); }
      invalidateCache();
      // 同步更新内存
      const memP = db.posts.find(x => x.id === m.id);
      if (memP) { memP.comments = p.comments; }
      return json({ comment: withAuthorSync(db, c) });
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
      try { await env.DB.prepare(`DELETE FROM posts WHERE id=?`).bind(m.id).run(); } catch (e) { return bad(e.message); }
      invalidateCache();
      return json({ ok: true });
    }

    // ========== 评论系统（楼中楼） ==========
    // GET /api/comments?target_type=article&target_id=xxx
    if (match(path, 'comments') && method === 'GET') {
      const tt = clean(requestQuery(request).target_type, 16) || 'article';
      const tid = clean(requestQuery(request).target_id, 64);
      if (!tid) return bad('缺少 target_id');
      const me = await auth(request, env);
      let all = [];
      try {
        const r = await env.DB.prepare(`SELECT * FROM comments WHERE target_type=? AND target_id=? ORDER BY created_at ASC`).bind(tt, tid).all();
        all = (r.results || []).map(row => ({
          id: row.id, targetType: row.target_type, targetId: row.target_id, parentId: row.parent_id,
          authorId: row.author_id, content: row.content, likes: JSON.parse(row.likes || '[]'), createdAt: row.created_at
        }));
      } catch {}
      // 楼中楼
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
      // 目标必须存在且已审核通过（直接 SQL 查）
      let target;
      try {
        const tbl = targetType === 'article' ? 'articles' : 'posts';
        const r = await env.DB.prepare(`SELECT * FROM ${tbl} WHERE id=? AND status='approved'`).bind(targetId).all();
        target = (r.results || [])[0];
      } catch {}
      if (!target) return bad('目标不存在或暂不可评论', 404);
      const c = { id: uid('cm'), targetType, targetId, parentId, authorId: me.id, content, likes: [], createdAt: Date.now() };
      // 直接 SQL INSERT
      try {
        await env.DB.prepare(`INSERT INTO comments (id, target_type, target_id, parent_id, author_id, content, likes, created_at)
          VALUES (?,?,?,?,?,?,?,?)`)
          .bind(c.id, c.targetType, c.targetId, c.parentId, c.authorId, c.content, '[]', c.createdAt).run();
      } catch (e) { return bad('评论失败: ' + e.message); }
      invalidateCache();
      // 通知：回复楼中楼 → 通知父评论作者；普通评论 → 通知文章/帖子作者（直接 SQL 查，不依赖内存）
      if (parentId) {
        const pr = await env.DB.prepare(`SELECT author_id FROM comments WHERE id=?`).bind(parentId).first().catch(() => null);
        if (pr && pr.author_id) await addNotif(env, me.id, 'reply', pr.author_id, targetType, targetId, '回复了你的评论');
      } else if (target.author_id) {
        await addNotif(env, me.id, 'comment', target.author_id, targetType, targetId, `评论了你的${targetType === 'article' ? '文章' : '帖子'}`);
      }
      const out = { ...c, author: pub(me), replies: [], likeCount: 0, liked: false };
      return json({ comment: out }, 201);
    }

    // DELETE /api/comments/:id
    m = match(path, 'comments/:id');
    if (m && method === 'DELETE') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      let row;
      try { row = await env.DB.prepare(`SELECT author_id FROM comments WHERE id=?`).bind(m.id).first(); } catch (e) { return bad(e.message); }
      if (!row) return bad('评论不存在', 404);
      const cAuthor = row.author_id || row.authorId;
      if (cAuthor !== me.id && me.role !== 'admin') return bad('无权限', 403);
      try { await env.DB.prepare(`DELETE FROM comments WHERE id=?`).bind(m.id).run(); } catch (e) { return bad(e.message); }
      invalidateCache();
      return json({ ok: true });
    }

    // POST /api/comments/:id/like
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      let row;
      try { row = await env.DB.prepare(`SELECT id, likes FROM comments WHERE id=?`).bind(m.id).first(); } catch (e) { return bad(e.message); }
      if (!row) return bad('评论不存在', 404);
      let likes = safeJSON(row.likes);
      if (!Array.isArray(likes)) likes = [];
      const idx = likes.indexOf(me.id);
      if (idx >= 0) likes.splice(idx, 1); else likes.push(me.id);
      try { await env.DB.prepare(`UPDATE comments SET likes=? WHERE id=?`).bind(JSON.stringify(likes), m.id).run(); } catch (e) { return bad(e.message); }
      invalidateCache();
      return json({ liked: idx < 0, likeCount: likes.length });
    }

    // ========== 通知系统（直接查 D1，多 isolate 一致） ==========
    // GET /api/notifications 通知列表（顺带惰性检查比赛开始）
    if (match(path, 'notifications') && method === 'GET') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      await checkContestStart(env, me);
      let list = [];
      try {
        const r = await env.DB.prepare(`SELECT n.*, u.nickname AS f_nick FROM notifications n LEFT JOIN users u ON n.from_id = u.id WHERE n.user_id=? ORDER BY n.created_at DESC LIMIT 50`).bind(me.id).all();
        list = (r.results || []).map(row => ({
          id: row.id, type: row.type, targetType: row.target_type, targetId: row.target_id,
          content: row.content, read: row.read, createdAt: row.created_at,
          from: row.from_id ? { id: row.from_id, nickname: row.f_nick || '用户' } : null
        }));
      } catch {}
      return json({ notifications: list });
    }
    // GET /api/notifications/unread-count 未读数（轮询时顺带惰性检查比赛开始）
    if (match(path, 'notifications/unread-count') && method === 'GET') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      await checkContestStart(env, me);
      const c = await env.DB.prepare(`SELECT COUNT(*) AS c FROM notifications WHERE user_id=? AND read=0`).bind(me.id).first().catch(() => null);
      return json({ count: c ? c.c : 0 });
    }
    // POST /api/notifications/read-all 全部已读
    if (match(path, 'notifications/read-all') && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      try { await env.DB.prepare(`UPDATE notifications SET read=1 WHERE user_id=?`).bind(me.id).run(); } catch (e) {}
      invalidateCache();
      return json({ ok: true });
    }
    // POST /api/notifications/:id/read 单条已读
    m = match(path, 'notifications/:id');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      try { await env.DB.prepare(`UPDATE notifications SET read=1 WHERE id=? AND user_id=?`).bind(m.id, me.id).run(); } catch (e) {}
      invalidateCache();
      return json({ ok: true });
    }

    // GET /api/announcements 公告列表（公开，无需登录）
    if (match(path, 'announcements') && method === 'GET') {
      let list = [];
      try {
        const r = await env.DB.prepare(`SELECT * FROM announcements ORDER BY created_at DESC`).all();
        list = (r.results || []).map(row => ({ id: row.id, title: row.title, content: row.content, createdAt: row.created_at }));
      } catch {}
      return json({ announcements: list });
    }

    // GET /api/announcements/:id 公告详情（公开）
    const annMatch = match(path, 'announcements/:id');
    if (annMatch && method === 'GET') {
      const r = await dbFirst(env, `SELECT * FROM announcements WHERE id=?`, [annMatch.id]);
      if (!r) return json({ error: '公告不存在' }, 404);
      return json({ id: r.id, title: r.title, content: r.content, createdAt: r.createdAt });
    }

    // GET /api/download/exe Cloudflare 流式代理 GitHub 安装包（用户直连本站，服务端走国际线路拉取）
    if (match(path, 'download/exe') && (method === 'GET' || method === 'HEAD')) {
      const GH = 'https://github.com/ZhangCingWab/wenluo_cloud/releases/download/v1.0.0/wenhui-setup-1.0.0.exe';
      if (method === 'HEAD') return Response.redirect(GH, 302);
      const h = {};
      const rg = request.headers.get('range');
      if (rg) h['Range'] = rg;
      const up = await fetch(GH, { redirect: 'follow', headers: h });
      if (!up.ok) return Response.redirect(GH, 302);
      const rh = { 'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment; filename="wenhui-setup-1.0.0.exe"', 'Cache-Control': 'no-cache' };
      const cl = up.headers.get('content-length'); if (cl) rh['Content-Length'] = cl;
      const cr = up.headers.get('content-range'); if (cr) rh['Content-Range'] = cr;
      return new Response(up.body, { status: up.status, headers: rh });
    }

    // ==================== 讨论区 ====================
    // 求助帖 JOIN 作者 → 前端可用的对象
    function helpOut(r) {
      const o = toCamel(r);
      o.author = (r.a_nick || r.a_name) ? { id: o.authorId, nickname: r.a_nick || r.a_name, username: r.a_name || '', role: r.a_role || 'user' } : { nickname: '已注销用户' };
      delete o.a_nick; delete o.a_name; delete o.a_role;
      return o;
    }

    // GET /api/discuss/help 列表（?status=open|solved）
    if (match(path, 'discuss/help') && method === 'GET') {
      const st = new URL(request.url).searchParams.get('status');
      let sql = `SELECT h.*, u.nickname AS a_nick, u.username AS a_name, u.role AS a_role
        FROM help_posts h LEFT JOIN users u ON h.author_id = u.id`;
      const binds = [];
      if (st === 'open' || st === 'solved') { sql += ` WHERE h.status = ?`; binds.push(st); }
      sql += ` ORDER BY CASE h.status WHEN 'solved' THEN 1 ELSE 0 END, h.created_at DESC LIMIT 100`;
      let rows = [];
      try { rows = (await env.DB.prepare(sql).bind(...binds).all()).results || []; } catch (e) { return bad('加载失败: ' + e.message); }
      // 回复数
      let cntMap = {};
      try {
        const cs = (await env.DB.prepare(`SELECT post_id, COUNT(*) AS cnt FROM help_replies GROUP BY post_id`).all()).results || [];
        cs.forEach(c => { cntMap[c.post_id] = c.cnt; });
      } catch {}
      return json({ posts: rows.map(r => { const o = helpOut(r); o.replyCount = cntMap[o.id] || 0; return o; }) });
    }

    // POST /api/discuss/help 发布求助
    if (match(path, 'discuss/help') && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const body = await request.json();
      const title = clean(body.title, 80);
      const content = clean(body.content, 5000);
      if (!title) return bad('标题不能为空');
      if (!content) return bad('内容不能为空');
      const p = { id: uid('h'), status: 'open', createdAt: Date.now() };
      try {
        await env.DB.prepare(`INSERT INTO help_posts (id, author_id, title, content, status, created_at) VALUES (?,?,?,?,?,?)`)
          .bind(p.id, me.id, title, content, p.status, p.createdAt).run();
      } catch (e) { return bad('发布失败: ' + e.message); }
      return json({ post: { id: p.id, authorId: me.id, title, content, status: p.status, createdAt: p.createdAt, author: pub(me), replyCount: 0 } });
    }

    // GET /api/discuss/help/:id 详情（含回复）
    m = match(path, 'discuss/help/:id');
    if (m && method === 'GET') {
      let row = null;
      try {
        row = (await env.DB.prepare(`SELECT h.*, u.nickname AS a_nick, u.username AS a_name, u.role AS a_role
          FROM help_posts h LEFT JOIN users u ON h.author_id = u.id WHERE h.id = ?`).bind(m.id).first());
      } catch (e) { return bad('加载失败: ' + e.message); }
      if (!row) return bad('求助不存在', 404);
      const post = helpOut(row);
      let replies = [];
      try {
        const rs = (await env.DB.prepare(`SELECT r.*, u.nickname AS a_nick, u.username AS a_name, u.role AS a_role
          FROM help_replies r LEFT JOIN users u ON r.author_id = u.id WHERE r.post_id = ? ORDER BY r.created_at ASC`)
          .bind(m.id).all()).results || [];
        replies = rs.map(helpOut);
      } catch {}
      return json({ post, replies });
    }

    // POST /api/discuss/help/:id/reply 回复
    m = match(path, 'discuss/help/:id/reply');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const body = await request.json();
      const content = clean(body.content, 3000);
      if (!content) return bad('内容不能为空');
      const post = await dbFirst(env, `SELECT id, author_id FROM help_posts WHERE id = ?`, [m.id]);
      if (!post) return bad('求助不存在', 404);
      const r = { id: uid('hr'), postId: m.id, authorId: me.id, content, isSolution: 0, createdAt: Date.now() };
      try {
        await env.DB.prepare(`INSERT INTO help_replies (id, post_id, author_id, content, is_solution, created_at) VALUES (?,?,?,?,0,?)`)
          .bind(r.id, m.id, me.id, content, r.createdAt).run();
      } catch (e) { return bad('回复失败: ' + e.message); }
      // 通知求助作者
      if (post.author_id) {
        await addNotif(env, me.id, 'reply', post.author_id, 'help', m.id, '回复了你的求助');
      }
      return json({ reply: { ...r, author: pub(me) } });
    }

    // POST /api/discuss/help/:id/solve 采纳答案（作者或管理员）
    m = match(path, 'discuss/help/:id/solve');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const body = await request.json().catch(() => ({}));
      const replyId = body.replyId || '';
      const post = await dbFirst(env, `SELECT id, author_id, status FROM help_posts WHERE id = ?`, [m.id]);
      if (!post) return bad('求助不存在', 404);
      const isAdmin = (me.role === 'admin');
      const isOwner = post.author_id === me.id || post.authorId === me.id;
      if (!isAdmin && !isOwner) return bad('只有求助发起人可以采纳答案', 403);
      if (replyId) {
        const rp = await dbFirst(env, `SELECT id, post_id, author_id FROM help_replies WHERE id = ?`, [replyId]);
        if (!rp || (rp.post_id || rp.postId) !== m.id) return bad('回复不存在', 404);
        try {
          await env.DB.prepare(`UPDATE help_replies SET is_solution = 1 WHERE id = ?`).bind(replyId).run();
        } catch (e) { return bad('操作失败: ' + e.message); }
        // 通知回复者：你的回复被采纳
        if (rp.author_id) await addNotif(env, me.id, 'adopt', rp.author_id, 'help', m.id, '你的回复被采纳为答案');
      }
      try {
        await env.DB.prepare(`UPDATE help_posts SET status = 'solved' WHERE id = ?`).bind(m.id).run();
      } catch (e) { return bad('操作失败: ' + e.message); }
      invalidateCache();
      return json({ ok: true });
    }

    // DELETE /api/discuss/help/:id 删除求助（作者或管理员）
    m = match(path, 'discuss/help/:id');
    if (m && method === 'DELETE') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const post = await dbFirst(env, `SELECT id, author_id FROM help_posts WHERE id = ?`, [m.id]);
      if (!post) return bad('求助不存在', 404);
      const isAdmin = (me.role === 'admin');
      const isOwner = post.author_id === me.id || post.authorId === me.id;
      if (!isAdmin && !isOwner) return bad('无权删除', 403);
      try {
        await env.DB.prepare(`DELETE FROM help_replies WHERE post_id = ?`).bind(m.id).run();
        await env.DB.prepare(`DELETE FROM help_posts WHERE id = ?`).bind(m.id).run();
      } catch (e) { return bad('删除失败: ' + e.message); }
      invalidateCache();
      return json({ ok: true });
    }

    // ==================== 群聊（多群制 + 群主审核） ====================
    // GET /api/discuss/groups 群列表（含我的成员状态、成员数、群主可见的待审数）
    if (match(path, 'discuss/groups') && method === 'GET') {
      const me = await auth(request, env);
      let rows = [];
      try {
        rows = (await env.DB.prepare(`SELECT g.*, u.nickname AS a_nick FROM chat_groups g
          LEFT JOIN users u ON g.owner_id = u.id ORDER BY g.created_at ASC`).all()).results || [];
      } catch (e) { return bad('加载失败: ' + e.message); }
      let cntMap = {}, pendMap = {}, mine = {};
      try {
        (await env.DB.prepare(`SELECT group_id, COUNT(*) AS cnt FROM chat_members WHERE status='approved' GROUP BY group_id`).all()).results
          .forEach(r => { cntMap[r.group_id] = r.cnt; });
      } catch {}
      if (me) {
        try {
          (await env.DB.prepare(`SELECT group_id, status FROM chat_members WHERE user_id = ?`).bind(me.id).all()).results
            .forEach(r => { mine[r.group_id] = r.status; });
        } catch {}
        try {
          (await env.DB.prepare(`SELECT group_id, COUNT(*) AS cnt FROM chat_members WHERE status='pending' GROUP BY group_id`).all()).results
            .forEach(r => { pendMap[r.group_id] = r.cnt; });
        } catch {}
      }
      return json({
        groups: rows.map(r => {
          const o = toCamel(r);
          o.ownerName = r.a_nick || '';
          delete o.a_nick;
          o.memberCount = cntMap[o.id] || 0;
          o.myStatus = mine[o.id] || 'none';
          if (me && (o.ownerId === me.id || me.role === 'admin')) o.pendingCount = pendMap[o.id] || 0;
          return o;
        })
      });
    }

    // POST /api/discuss/groups/:id/join 申请加群
    m = match(path, 'discuss/groups/:id/join');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const g = await dbFirst(env, `SELECT id, name, owner_id FROM chat_groups WHERE id = ?`, [m.id]);
      if (!g) return bad('群不存在', 404);
      const ex = await dbFirst(env, `SELECT status FROM chat_members WHERE group_id = ? AND user_id = ?`, [m.id, me.id]);
      if (ex && (ex.status === 'approved' || ex.status === 'pending')) return json({ ok: true, status: ex.status });
      try {
        await env.DB.prepare(`INSERT OR IGNORE INTO chat_members (group_id, user_id, status, joined_at) VALUES (?,?,'pending',?)`)
          .bind(m.id, me.id, Date.now()).run();
      } catch (e) { return bad('申请失败: ' + e.message); }
      const ownerId = g.owner_id || g.ownerId;
      if (ownerId && ownerId !== me.id) {
        await addNotif(env, db, me.id, 'group', ownerId, 'group', m.id, `申请加入群聊「${g.name}」`);
      }
      return json({ ok: true, status: 'pending' });
    }

    // GET /api/discuss/groups/:id/requests 群主查待审申请
    m = match(path, 'discuss/groups/:id/requests');
    if (m && method === 'GET') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const g = await dbFirst(env, `SELECT id, owner_id FROM chat_groups WHERE id = ?`, [m.id]);
      if (!g) return bad('群不存在', 404);
      const ownerId = g.owner_id || g.ownerId;
      if (ownerId !== me.id && me.role !== 'admin') return bad('只有群主可以查看申请', 403);
      let rows = [];
      try {
        rows = (await env.DB.prepare(`SELECT cm.user_id, cm.joined_at, u.nickname, u.username, u.role
          FROM chat_members cm LEFT JOIN users u ON cm.user_id = u.id
          WHERE cm.group_id = ? AND cm.status = 'pending' ORDER BY cm.joined_at ASC`).bind(m.id).all()).results || [];
      } catch (e) { return bad('加载失败: ' + e.message); }
      return json({
        requests: rows.map(r => ({
          userId: r.user_id, joinedAt: r.joined_at,
          user: { id: r.user_id, nickname: r.nickname || '已注销用户', username: r.username || '', role: r.role || 'user' }
        }))
      });
    }

    // POST /api/discuss/groups/:id/review 群主审核 {userId, approve}
    m = match(path, 'discuss/groups/:id/review');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const body = await request.json();
      const targetId = body.userId || '';
      if (!targetId) return bad('缺少 userId');
      const g = await dbFirst(env, `SELECT id, name, owner_id FROM chat_groups WHERE id = ?`, [m.id]);
      if (!g) return bad('群不存在', 404);
      const ownerId = g.owner_id || g.ownerId;
      if (ownerId !== me.id && me.role !== 'admin') return bad('只有群主可以审核', 403);
      const ex = await dbFirst(env, `SELECT status FROM chat_members WHERE group_id = ? AND user_id = ?`, [m.id, targetId]);
      if (!ex || ex.status !== 'pending') return bad('该用户没有待审申请');
      if (body.approve) {
        try {
          await env.DB.prepare(`UPDATE chat_members SET status = 'approved' WHERE group_id = ? AND user_id = ?`).bind(m.id, targetId).run();
        } catch (e) { return bad('操作失败: ' + e.message); }
        await addNotif(env, db, me.id, 'group', targetId, 'group', m.id, `你已通过群聊「${g.name}」的审核`);
      } else {
        try {
          await env.DB.prepare(`DELETE FROM chat_members WHERE group_id = ? AND user_id = ?`).bind(m.id, targetId).run();
        } catch (e) { return bad('操作失败: ' + e.message); }
        await addNotif(env, db, me.id, 'group', targetId, 'group', m.id, `你加入群聊「${g.name}」的申请未通过`);
      }
      invalidateCache();
      return json({ ok: true });
    }

    // GET /api/discuss/chat 群消息（?group=<群id>&after=毫秒时间戳 增量拉取，需已是成员）
    if (match(path, 'discuss/chat') && method === 'GET') {
      const url = new URL(request.url);
      const gId = url.searchParams.get('group') || '';
      if (!gId) return bad('缺少群参数');
      const after = Number(url.searchParams.get('after') || 0);
      const me = await auth(request, env);
      if (me) {
        const mb = await dbFirst(env, `SELECT status FROM chat_members WHERE group_id = ? AND user_id = ?`, [gId, me.id]);
        const g = await dbFirst(env, `SELECT owner_id FROM chat_groups WHERE id = ?`, [gId]);
        const isOwner = g && ((g.owner_id || g.ownerId) === me.id || me.role === 'admin');
        const st = mb ? (mb.status || 'none') : 'none';
        if (st !== 'approved' && !isOwner) return bad(st === 'pending' ? '申请审核中，群主通过后即可进入' : '请先申请加入该群', 403);
      } else {
        return bad('请先登录', 401);
      }
      let rows = [];
      try {
        if (after > 0) {
          rows = (await env.DB.prepare(`SELECT c.*, u.nickname AS a_nick, u.username AS a_name, u.role AS a_role
            FROM chat_messages c LEFT JOIN users u ON c.author_id = u.id
            WHERE c.group_id = ? AND c.created_at > ? ORDER BY c.created_at ASC LIMIT 200`).bind(gId, after).all()).results || [];
        } else {
          const rs = (await env.DB.prepare(`SELECT c.*, u.nickname AS a_nick, u.username AS a_name, u.role AS a_role
            FROM chat_messages c LEFT JOIN users u ON c.author_id = u.id
            WHERE c.group_id = ? ORDER BY c.created_at DESC LIMIT 50`).bind(gId).all()).results || [];
          rows = rs.reverse();
        }
      } catch (e) { return bad('加载失败: ' + e.message); }
      return json({ messages: rows.map(helpOut) });
    }

    // POST /api/discuss/chat 发送群消息 {groupId, content}
    if (match(path, 'discuss/chat') && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const body = await request.json();
      const gId = body.groupId || body.group_id || '';
      if (!gId) return bad('缺少群参数');
      const mb = await dbFirst(env, `SELECT status FROM chat_members WHERE group_id = ? AND user_id = ?`, [gId, me.id]);
      const g = await dbFirst(env, `SELECT owner_id FROM chat_groups WHERE id = ?`, [gId]);
      const isOwner = g && ((g.owner_id || g.ownerId) === me.id || me.role === 'admin');
      const st = mb ? (mb.status || 'none') : 'none';
      if (st !== 'approved' && !isOwner) return bad(st === 'pending' ? '申请审核中，还不能发言' : '请先申请加入该群', 403);
      const content = clean(body.content, 500);
      if (!content) return bad('内容不能为空');
      const c = { id: uid('c'), groupId: gId, authorId: me.id, content, createdAt: Date.now() };
      try {
        await env.DB.prepare(`INSERT INTO chat_messages (id, group_id, author_id, content, created_at) VALUES (?,?,?,?,?)`)
          .bind(c.id, gId, me.id, content, c.createdAt).run();
      } catch (e) { return bad('发送失败: ' + e.message); }
      return json({ message: { ...c, author: pub(me) } });
    }

    // ---- 私信：发送 ----
    if (match(path, 'messages') && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const body = await request.json();
      // 兼容 to_id 和 toId
      const toId = body.toId || body.to_id;
      const to = userByIdSync(db, toId);
      if (!to) return bad('用户不存在', 404);
      if (to.id === me.id) return bad('不能给自己发私信');
      const content = clean(body.content, 2000);
      if (!content) return bad('内容不能为空');
      const msg = { id: uid('m'), fromId: me.id, toId: to.id, content, createdAt: Date.now(), read: false };
      // 直接同步写 D1（不同 isolate 间内存不共享，必须持久化）
      try {
        await env.DB.prepare(`INSERT INTO messages (id, from_id, to_id, content, created_at, \`read\`) VALUES (?,?,?,?,?,0)`)
          .bind(msg.id, msg.fromId, msg.toId, msg.content, msg.createdAt).run();
      } catch (e) {
        return bad('发送失败: ' + e.message);
      }
      // 同步更新内存缓存（让同 isolate 后续 GET 能读到）
      db.messages.push(msg);
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
          partner: pub(userByIdSync(db, c.partnerId)),
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
      const other = userByIdSync(db, m.userId);
      if (!other) return bad('用户不存在', 404);
      // 直接从 D1 读（不同 isolate 间内存不共享，必须持久化数据源）
      let list = [];
      try {
        const rows = await env.DB.prepare(`SELECT * FROM messages WHERE 
          (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)
          ORDER BY created_at ASC`)
          .bind(me.id, other.id, other.id, me.id).all();
        list = (rows.results || []).map(row => ({
          id: row.id, fromId: row.from_id, toId: row.to_id,
          content: row.content, createdAt: row.created_at, read: !!row.read
        }));
      } catch {}
      // 同步内存 db.messages 保证最新
      db.messages = db.messages || [];
      for (const msg of list) {
        if (!db.messages.find(x => x.id === msg.id)) db.messages.push(msg);
      }
      // 把已读消息标记为 read（直接 SQL UPDATE）
      const unreadIds = list.filter(x => x.toId === me.id && !x.read).map(x => x.id);
      if (unreadIds.length > 0) {
        try {
          const qmarks = unreadIds.map(() => '?').join(',');
          await env.DB.prepare(`UPDATE messages SET \`read\` = 1 WHERE id IN (${qmarks})`).bind(...unreadIds).run();
          for (const x of list) if (x.toId === me.id) x.read = true;
          for (const x of db.messages) if (unreadIds.includes(x.id)) x.read = true;
        } catch {}
      }
      return json({ partner: pub(other), messages: list });
    }

    // ---- 排行榜（直接 SQL 查 D1 实时算，跨 isolate 一致）----
    if (match(path, 'rank') && method === 'GET') {
      // 用 getTableCols 拿真实列名（旧 KV 迁移的表可能用 camelCase）
      const pracCols = await getTableCols(env, 'practices');
      const checkCols = await getTableCols(env, 'checkins');
      const pracAuthorCol = pracCols.includes('author_id') ? 'author_id' : 'authorId';
      const checkUserCol = checkCols.includes('user_id') ? 'user_id' : 'userId';
      let artRows = [];
      try { artRows = (await env.DB.prepare(`SELECT author_id, likes FROM articles WHERE status='approved'`).all()).results || []; } catch {}
      let postRows = [];
      try { postRows = (await env.DB.prepare(`SELECT author_id, comments FROM posts WHERE status='approved'`).all()).results || []; } catch {}
      let pracRows = [];
      try { pracRows = (await env.DB.prepare(`SELECT ${pracAuthorCol} as author_id FROM practices`).all()).results || []; } catch {}
      let checkRows2 = [];
      try { checkRows2 = (await env.DB.prepare(`SELECT ${checkUserCol} as user_id FROM checkins`).all()).results || []; } catch {}
      const stats = {};
      for (const u of db.users) stats[u.id] = { arts: 0, posts: 0, likes: 0, comments: 0, practices: 0, checkins: 0 };
      for (const row of artRows) {
        const s = stats[row.author_id] || (stats[row.author_id] = { arts:0, posts:0, likes:0, comments:0, practices:0, checkins:0 });
        s.arts++;
        try { s.likes += (JSON.parse(row.likes || '[]')).length; } catch {}
      }
      for (const row of postRows) {
        const s = stats[row.author_id] || (stats[row.author_id] = { arts:0, posts:0, likes:0, comments:0, practices:0, checkins:0 });
        s.posts++;
        try { s.comments += (JSON.parse(row.comments || '[]')).length; } catch {}
      }
      for (const row of pracRows) { const s = stats[row.author_id]; if (s) s.practices++; }
      for (const row of checkRows2) { const s = stats[row.user_id]; if (s) s.checkins++; }

      const rows = db.users.map(u => {
        const s = stats[u.id] || { arts:0, posts:0, likes:0, comments:0, practices:0, checkins:0 };
        const score = s.arts * 10 + s.posts * 5 + s.likes * 3 + s.comments * 2 + s.practices * 2 + s.checkins * 2;
        return { user: pub(u), score, articles: s.arts, posts: s.posts, likes: s.likes, practices: s.practices, checkins: s.checkins };
      });
      rows.sort((a, b) => b.score - a.score);
      return json({ rank: rows.slice(0, 50), total: rows.length });
    }

    // ---- 比赛列表（直接 SQL D1）----
    if (match(path, 'contests') && method === 'GET') {
      const cols = await getTableCols(env, 'contests');
      const timeStart = cols.includes('start_time') ? 'start_time' : 'startTime';
      const timeEnd = cols.includes('end_time') ? 'end_time' : 'endTime';
      let rows = [];
      try {
        const r = await env.DB.prepare(`SELECT * FROM contests ORDER BY created_at DESC`).all();
        rows = (r.results || []).map(row => ({
          id: row.id, title: row.title, description: row.description,
          problems: JSON.parse(row.problems || '[]'),
          startTime: row[timeStart], endTime: row[timeEnd],
          createdBy: row.created_by || row.createdBy, createdAt: row.created_at || row.createdAt,
          participants: JSON.parse(row.participants || '[]'),
          submissions: JSON.parse(row.submissions || '[]')
        }));
      } catch {}
      return json({ contests: rows.map(c => contestOut(c, db)) });
    }

    // ---- 我的比赛 ----
    if (match(path, 'contests/mine') && method === 'GET') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const mine = db.contests.filter(c => c.authorId === me.id || (c.participants && c.participants.includes(me.id)));
      return json({ contests: mine.map(c => contestOut(c, db)) });
    }

    // ---- 比赛详情 ----
    m = match(path, 'contests/:id');
    if (m && method === 'GET') {
      const cols = await getTableCols(env, 'contests');
      const timeStart = cols.includes('start_time') ? 'start_time' : 'startTime';
      const timeEnd = cols.includes('end_time') ? 'end_time' : 'endTime';
      let c;
      try {
        const r = await env.DB.prepare(`SELECT * FROM contests WHERE id = ?`).bind(m.id).all();
        const row = (r.results || [])[0];
        if (row) {
          c = {
            id: row.id, title: row.title, description: row.description,
            problems: JSON.parse(row.problems || '[]'),
            startTime: row[timeStart], endTime: row[timeEnd],
            createdBy: row.created_by || row.createdBy, createdAt: row.created_at || row.createdAt,
            participants: JSON.parse(row.participants || '[]'),
            submissions: JSON.parse(row.submissions || '[]')
          };
        }
      } catch {}
      if (!c) return bad('比赛不存在', 404);
      const o = contestOut(c, db);
      const me = await auth(request, env);
      o.joined = !!(me && (c.participants || []).includes(me.id));
      o.participantList = (c.participants || []).map(id => pub(userByIdSync(db, id))).filter(Boolean);
      delete o.participants;
      delete o.submissions;
      return json({ contest: o });
    }

    // ---- 创建比赛 ----
    if (match(path, 'contests') && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
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
      // 权限：admin 直接创建；普通用户需要有效的一次性邀请码
      let creatorId = me.id;
      if (me.role !== 'admin') {
        const inviteCode = clean(body.inviteCode, 32);
        if (!inviteCode) return bad('需要一次性邀请码', 403);
        let row;
        try { row = (await env.DB.prepare(`SELECT * FROM invite_codes WHERE code=? AND purpose='contest'`).bind(inviteCode).all()).results[0]; }
        catch (e) { return bad('系统错误，请稍后再试'); }
        if (!row) return bad('邀请码无效', 403);
        if (row.used) return bad('邀请码已被使用过了', 403);
        try { await env.DB.prepare(`UPDATE invite_codes SET used=1, used_by=?, used_at=? WHERE code=?`).bind(me.id, Date.now(), inviteCode).run(); }
        catch (e) {}
      }
      const id = uid('c');
      const now = Date.now();
      const participants = [];
      const submissions = [];
      // 直接 SQL INSERT（跨 isolate 持久化）
      try {
        await env.DB.prepare(`INSERT INTO contests (id, title, description, problems, start_time, end_time, created_by, created_at, participants, submissions)
          VALUES (?,?,?,?,?,?,?,?,?,?)`)
          .bind(id, title, description, JSON.stringify(problems), startTime, endTime, creatorId, now, '[]', '[]').run();
      } catch (e) { return bad('创建失败: ' + e.message); }
      const c = { id, title, description, problems, startTime, endTime, createdBy: creatorId, createdAt: now, participants, submissions };
      db.contests.push(c);
      invalidateCache();
      return json({ contest: contestOut(c, db) });
    }

    // ---- 报名比赛 ----
    m = match(path, 'contests/:id/join');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      // 直接 SQL 查 + 更新
      let c;
      const cols = await getTableCols(env, 'contests');
      const timeEnd = cols.includes('end_time') ? 'end_time' : 'endTime';
      try {
        const r = await env.DB.prepare(`SELECT * FROM contests WHERE id=?`).bind(m.id).all();
        const row = (r.results || [])[0];
        if (row) {
          c = { participants: JSON.parse(row.participants || '[]'), endTime: row[timeEnd] };
        }
      } catch {}
      if (!c) return bad('比赛不存在', 404);
      if (Date.now() > c.endTime) return bad('比赛已结束');
      const i = c.participants.indexOf(me.id);
      if (i >= 0) c.participants.splice(i, 1); else c.participants.push(me.id);
      try { await env.DB.prepare(`UPDATE contests SET participants=? WHERE id=?`).bind(JSON.stringify(c.participants), m.id).run(); }
      catch (e) { return bad('操作失败: ' + e.message); }
      invalidateCache();
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
      try { await env.DB.prepare(`UPDATE contests SET submissions=? WHERE id=?`).bind(JSON.stringify(c.submissions), c.id).run(); } catch (e) { return bad(e.message); }
      invalidateCache();
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
        submissions: (c.submissions || []).map(s => { const o = withAuthorSync(db, s); delete o.content; return o; })
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
      try { await env.DB.prepare(`DELETE FROM contests WHERE id=?`).bind(m.id).run(); } catch (e) { return bad(e.message); }
      invalidateCache();
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
      if (diff) list = list.filter(p => parseInt(p.difficulty, 10) === Number(diff));
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
        practices: practices.slice(0, 50).map(x => { const o = withAuthorSync(db, x); delete o.content; return o; })
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
      try { await env.DB.prepare(`INSERT INTO problems (id,type,title,content,difficulty,tags,created_by,created_at,status) VALUES (?,?,?,?,?,?,?,?,?)`)
        .bind(p.id, p.type, p.title, p.content, p.difficulty, p.tags, p.createdBy, p.createdAt, p.status).run(); } catch (e) { return bad(e.message); }
      invalidateCache();
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
      try { await env.DB.prepare(`DELETE FROM practices WHERE problem_id=?`).bind(m.id).run(); } catch (e) {}
      try { await env.DB.prepare(`DELETE FROM problems WHERE id=?`).bind(m.id).run(); } catch (e) { return bad(e.message); }
      invalidateCache();
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
      if (s) {
        s.title = title; s.content = content; s.wordCount = wordCount; s.updatedAt = Date.now();
        try { await env.DB.prepare(`UPDATE practices SET title=?,content=?,word_count=?,updated_at=? WHERE id=?`)
          .bind(s.title, s.content, s.wordCount, s.updatedAt, s.id).run(); } catch (e) { return bad(e.message); }
      } else {
        s = { id: uid('r'), problemId: p.id, authorId: me.id, title, content, wordCount, createdAt: Date.now() };
        db.practices.push(s);
        try { await env.DB.prepare(`INSERT INTO practices (id,problem_id,author_id,title,content,word_count,created_at) VALUES (?,?,?,?,?,?,?)`)
          .bind(s.id, s.problemId, s.authorId, s.title, s.content, s.wordCount, s.createdAt).run(); } catch (e) { return bad(e.message); }
      }
      invalidateCache();
      // 通知出题人：有人提交了练习
      if (p.createdBy) await addNotif(env, me.id, 'practice', p.createdBy, 'problem', p.id, `提交了你的题目《${p.title}》的练习`);
      return json({ practice: s });
    }

    // ---- 查看单个练习 ----
    m = match(path, 'problems/:id/practice/:prId');
    if (m && method === 'GET') {
      const s = db.practices.find(x => x.id === m.prId && x.problemId === m.id);
      if (!s) return bad('练习不存在', 404);
      return json({ practice: withAuthorSync(db, s) });
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
      if (!file.size) return bad('文件内容为空（0 字节），请检查文件后重新上传');
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
      try { await env.DB.prepare(`INSERT INTO files (id,author_id,original_name,stored_name,size,note,status,created_at) VALUES (?,?,?,?,?,?,?,?)`)
        .bind(f.id, f.authorId, f.originalName, f.storedName, f.size, f.note, f.status, f.createdAt).run(); } catch (e) { return bad(e.message); }
      // 文件内容同步存 D1（D1 单值上限 2MB，大文件只存 KV）
      const b64 = btoa(base64);
      if (b64.length <= 1900000) {
        try { await env.DB.prepare(`INSERT INTO file_blobs (id, content) VALUES (?,?)`).bind(fileId, b64).run(); } catch (e) { console.error('file_blobs:', e.message); }
      }
      invalidateCache();
      return json({ file: withAuthorSync(db, f) });
    }

    // ---- 删除文件（作者或管理员）----
    m = match(path, 'files/:id');
    if (m && method === 'DELETE') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      let row;
      try { row = (await env.DB.prepare(`SELECT * FROM files WHERE id=?`).bind(m.id).all()).results[0]; }
      catch (e) { return bad(e.message); }
      if (!row) return bad('文件不存在', 404);
      if ((row.author_id || row.authorId) !== me.id && me.role !== 'admin') return bad('无权限删除', 403);
      const stored = row.stored_name || row.storedName;
      try { await env.DB.prepare(`DELETE FROM files WHERE id=?`).bind(m.id).run(); } catch (e) { return bad(e.message); }
      try { await env.DB.prepare(`DELETE FROM file_blobs WHERE id=?`).bind(m.id).run(); } catch {}
      try { await env.DB.prepare(`DELETE FROM articles WHERE id=?`).bind('a_file_' + m.id).run(); } catch {}
      try { await env.DATA.delete('file:' + stored); } catch {}
      invalidateCache();
      return json({ ok: true });
    }

    // ---- 我的文件 ----
    if (match(path, 'files/mine') && method === 'GET') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      let rows = [];
      try { rows = (await env.DB.prepare(`SELECT * FROM files WHERE author_id=? ORDER BY created_at DESC`).bind(me.id).all()).results || []; }
      catch (e) { return bad(e.message); }
      return json({ files: rows.map(r => {
        const author = userByIdSync(db, r.author_id) || pub(me);
        return {
          id: r.id, authorId: r.author_id, originalName: r.original_name || r.originalName,
          storedName: r.stored_name || r.storedName, size: r.size,
          note: r.note, status: r.status, createdAt: r.created_at,
          reviewedAt: r.reviewed_at, author
        };
      })});
    }

    // ---- 文件下载 ----
    m = match(path, 'files/:id/download');
    if (m && method === 'GET') {
      let row;
      try { row = (await env.DB.prepare(`SELECT * FROM files WHERE id=?`).bind(m.id).all()).results[0]; }
      catch (e) { return bad(e.message); }
      if (!row) return bad('文件不存在', 404);
      // 已通过审核的投稿 = 公开社区内容（文件 id 为不可猜 UUID）；未通过的仅作者/管理员可下载
      const st = row.status || 'pending';
      if (st !== 'approved') {
        const me = await auth(request, env);
        if (!me) return bad('请先登录', 401);
        if (row.author_id !== me.id && me.role !== 'admin') return bad('无权限下载', 403);
      }
      const stored = row.stored_name || row.storedName;
      // 优先从 D1 读内容，旧文件回退 KV
      let b64 = null;
      try { const br = await env.DB.prepare(`SELECT content FROM file_blobs WHERE id=?`).bind(m.id).first(); if (br && br.content) b64 = br.content; } catch {}
      if (!b64) b64 = await env.DATA.get('file:' + stored);
      if (!b64) return bad('文件内容不存在（可能是空文件或损坏的上传），请删除后重新上传', 404);
      const binary = atob(b64);
      const arr = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) arr[i] = binary.charCodeAt(i);
      const mime = guessMime(stored);
      const origName = row.original_name || row.originalName || 'file';
      return new Response(arr, {
        headers: {
          'Content-Type': mime,
          'Content-Disposition': `attachment; filename="${encodeURIComponent(origName)}"`,
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

    // ---- 后台审核：文章列表（直接 SQL，跨 isolate 必拿到最新）----
    m = match(path, 'admin/articles');
    if (m && method === 'GET') {
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const status = ['pending', 'approved', 'rejected'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : 'pending';
      let rows = [];
      try {
        const r = await env.DB.prepare(`SELECT * FROM articles WHERE status = ? ORDER BY created_at DESC`).bind(status).all();
        rows = await Promise.all((r.results || []).map(async row => {
          const author = await userById(env, row.author_id);
          return {
            id: row.id, authorId: row.author_id, title: row.title, content: row.content,
            category: row.category, status: row.status, views: row.views || 0,
            likeCount: (row.likes ? JSON.parse(row.likes).length : 0),
            tags: row.tags ? JSON.parse(row.tags) : [],
            createdAt: row.created_at, reviewedAt: row.reviewed_at,
            author: author ? pub(author) : { nickname: '未知用户' }
          };
        }));
      } catch (e) { return bad(e.message); }
      return json({ articles: rows });
    }

    // ---- 审核文章 ----
    m = match(path, 'admin/articles/:id/review');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const body = await request.json();
      const status = body.action === 'approve' ? 'approved' : 'rejected';
      // 直接 SQL UPDATE（不同 isolate 间必须持久化）
      try { await env.DB.prepare(`UPDATE articles SET status = ?, reviewed_at = ? WHERE id = ?`).bind(status, Date.now(), m.id).run(); } catch (e) { return bad('审核失败: ' + e.message); }
      const a = db.articles.find(x => x.id === m.id);
      if (a) { a.status = status; a.reviewedAt = Date.now(); }
      invalidateCache();
      return json({ ok: true, status });
    }

    // ---- 后台审核：帖子列表（直接 SQL）----
    m = match(path, 'admin/posts');
    if (m && method === 'GET') {
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const status = ['pending', 'approved', 'rejected'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : 'pending';
      let rows = [];
      try {
        const r = await env.DB.prepare(`SELECT * FROM posts WHERE status = ? ORDER BY created_at DESC`).bind(status).all();
        rows = await Promise.all((r.results || []).map(async row => {
          const author = await userById(env, row.author_id);
          return {
            id: row.id, authorId: row.author_id, title: row.title, content: row.content,
            category: row.category, status: row.status, createdAt: row.created_at,
            commentCount: (row.comments ? JSON.parse(row.comments).length : 0),
            author: author ? pub(author) : { nickname: '未知用户' }
          };
        }));
      } catch (e) { return bad(e.message); }
      return json({ posts: rows });
    }

    // ---- 审核帖子 ----
    m = match(path, 'admin/posts/:id/review');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const body = await request.json();
      const status = body.action === 'approve' ? 'approved' : 'rejected';
      try { await env.DB.prepare(`UPDATE posts SET status = ?, reviewed_at = ? WHERE id = ?`).bind(status, Date.now(), m.id).run(); } catch (e) { return bad('审核失败: ' + e.message); }
      const p = db.posts.find(x => x.id === m.id);
      if (p) { p.status = status; p.reviewedAt = Date.now(); }
      invalidateCache();
      return json({ ok: true, status });
    }

    // ---- 后台审核：文件列表 ----
    m = match(path, 'admin/files');
    if (m && method === 'GET') {
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const status = ['pending', 'approved', 'rejected'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : 'pending';
      let rows = [];
      try { rows = (await env.DB.prepare(`SELECT * FROM files WHERE status=? ORDER BY created_at DESC`).bind(status).all()).results || []; }
      catch (e) { return bad(e.message); }
      // 用 toCamel 转列名，再手动组装（兼容 files 表 snake_case/camelCase 混合）
      const files = await Promise.all(rows.map(async r => {
        const c = toCamel(r);
        const author = await userById(env, c.authorId);
        return {
          id: c.id, authorId: c.authorId,
          originalName: c.originalName || c.original_name,
          storedName: c.storedName || c.stored_name,
          size: c.size, note: c.note, status: c.status,
          createdAt: c.createdAt || c.created_at,
          reviewedAt: c.reviewedAt || c.reviewed_at,
          author: author ? pub(author) : { nickname: '未知用户' }
        };
      }));
      return json({ files });
    }

    // ---- 审核文件 ----
    m = match(path, 'admin/files/:id/review');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const body = await request.json();
      let row;
      try { row = (await env.DB.prepare(`SELECT * FROM files WHERE id=?`).bind(m.id).all()).results[0]; }
      catch (e) { return bad(e.message); }
      if (!row) return bad('文件不存在', 404);
      const newStatus = body.action === 'approve' ? 'approved' : 'rejected';
      const reviewedAt = Date.now();
      // 同步更新内存
      const f = db.files.find(x => x.id === m.id);
      if (f) { f.status = newStatus; f.reviewedAt = reviewedAt; }
      try { await env.DB.prepare(`UPDATE files SET status=?, reviewed_at=? WHERE id=?`).bind(newStatus, reviewedAt, m.id).run(); } catch (e) { return bad(e.message); }
      // 通过 → 自动生成一篇文章放进文章库（id 固定 a_file_<fileId>，重复审核不会重复发）
      if (newStatus === 'approved') {
        const origName = clean(row.original_name || row.originalName || '未命名文件', 120);
        const size = Number(row.size) || 0;
        const sizeText = size > 1048576 ? (size / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(size / 1024)) + ' KB';
        const note = clean(row.note || '', 300);
        const content = `## 📄 文件投稿：${origName}\n\n**文件大小**：${sizeText}\n\n${note ? '> 投稿说明：' + note + '\n\n' : ''}[⬇ 下载文件](/api/files/${m.id}/download)\n\n*本文由文件投稿审核通过后自动发布到文章库*`;
        try {
          await env.DB.prepare(`INSERT INTO articles (id, author_id, title, content, category, status, views, likes, tags, created_at, reviewed_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
            .bind('a_file_' + m.id, row.author_id, origName, content, '文件投稿', 'approved', 0, 0, '[]', reviewedAt, reviewedAt).run();
        } catch (e) { console.error('file->article:', e.message); } // 文章已存在（重复审核）则跳过
      } else {
        // 拒绝 → 移除之前自动生成的文章（如有）
        try { await env.DB.prepare(`DELETE FROM articles WHERE id=?`).bind('a_file_' + m.id).run(); } catch (e) {}
      }
      invalidateCache();
      return json({ ok: true, status: newStatus });
    }

    // ---- 后台审核：题目列表 ----
    m = match(path, 'admin/problems');
    if (m && method === 'GET') {
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const status = ['pending', 'approved', 'rejected'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : 'pending';
      let rows = [];
      try { rows = (await env.DB.prepare(`SELECT * FROM problems WHERE COALESCE(status,'approved')=? ORDER BY created_at DESC`).bind(status).all()).results || []; }
      catch (e) { return bad(e.message); }
      // toCamel + 手动组装列名（problems 表混合）
      const problems = await Promise.all(rows.map(async r => {
        const c = toCamel(r);
        const proposer = await userById(env, c.createdBy || c.created_by);
        const rawTags = c.tags || c.tag || c.tags_json;
        return {
          id: c.id, type: c.type, title: c.title, content: c.content,
          difficulty: parseInt(c.difficulty, 10) || 1,
          tags: rawTags ? (typeof rawTags === 'string' ? safeJSON(rawTags) : rawTags) : [],
          createdAt: c.createdAt || c.created_at,
          status: c.status || 'approved',
          reviewedAt: c.reviewedAt || c.reviewed_at,
          proposer: proposer ? pub(proposer) : { nickname: '未知用户', username: '' }
        };
      }));
      return json({ problems });
    }

    // ---- 审核题目 ----
    m = match(path, 'admin/problems/:id/review');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const body = await request.json();
      let row;
      try { row = (await env.DB.prepare(`SELECT * FROM problems WHERE id=?`).bind(m.id).all()).results[0]; }
      catch (e) { return bad(e.message); }
      if (!row) return bad('题目不存在', 404);
      const newStatus = body.action === 'approve' ? 'approved' : 'rejected';
      const reviewedAt = Date.now();
      try { await env.DB.prepare(`UPDATE problems SET status=?, reviewed_at=? WHERE id=?`).bind(newStatus, reviewedAt, m.id).run(); } catch (e) { return bad(e.message); }
      invalidateCache();
      // 通知出题人审核结果
      await addNotif(env, me.id, 'problem_review', row.created_by, 'problem', m.id,
        newStatus === 'approved' ? `你出的题目《${row.title}》已通过审核，进入题库啦！` : `你出的题目《${row.title}》未通过审核，可修改后重新提交`);
      return json({ ok: true, status: newStatus });
    }
    // GET /api/admin/stats
    if (match(path, 'admin/stats') && method === 'GET') {
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      try {
        const [uC, aC, pC, cC, aP, pP, coC, prC, chC, fC] = await Promise.all([
          env.DB.prepare('SELECT COUNT(*) as c FROM users').first(),
          env.DB.prepare('SELECT COUNT(*) as c FROM articles').first(),
          env.DB.prepare('SELECT COUNT(*) as c FROM posts').first(),
          env.DB.prepare('SELECT COUNT(*) as c FROM comments').first(),
          env.DB.prepare("SELECT COUNT(*) as c FROM articles WHERE status='pending'").first(),
          env.DB.prepare("SELECT COUNT(*) as c FROM posts WHERE status='pending'").first(),
          env.DB.prepare('SELECT COUNT(*) as c FROM contests').first(),
          env.DB.prepare('SELECT COUNT(*) as c FROM problems').first(),
          env.DB.prepare('SELECT COUNT(*) as c FROM checkins').first(),
          env.DB.prepare('SELECT COUNT(*) as c FROM files').first()
        ]);
        return json({
          users: uC?.c || 0,
          articles: aC?.c || 0,
          posts: pC?.c || 0,
          comments: cC?.c || 0,
          pendingArticles: aP?.c || 0,
          pendingPosts: pP?.c || 0,
          contests: coC?.c || 0,
          problems: prC?.c || 0,
          checkins: chC?.c || 0,
          files: fC?.c || 0
        });
      } catch (e) { return bad(e.message); }
    }

    // ---- admin 生成一次性邀请码 ----
    if (match(path, 'admin/invite/generate') && method === 'POST') {
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const purpose = clean((await request.json().catch(() => ({}))).purpose || 'contest', 32);
      const chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
      let code;
      do { code = Array.from({ length: 10 }, () => chars[Math.floor(Math.random() * chars.length)]).join(''); }
      while ((await dbFirst(env, `SELECT 1 FROM invite_codes WHERE code=?`, code)));
      await dbRun(env, `INSERT INTO invite_codes (code,purpose,created_by,created_at,used) VALUES (?,?,?,?,0)`,
        [code, purpose, me.id, Date.now()]);
      return json({ code, purpose });
    }

    // ---- admin 查看邀请码列表 ----
    if (match(path, 'admin/invite/list') && method === 'GET') {
      const me = await auth(request, env);
      if (!me || me.role !== 'admin') return bad('需要管理员权限', 403);
      const rows = (await env.DB.prepare(`SELECT * FROM invite_codes ORDER BY created_at DESC LIMIT 50`).all()).results || [];
      const codes = rows.map(r => ({
        code: r.code, purpose: r.purpose,
        used: !!r.used,
        createdBy: r.created_by, createdAt: r.created_at,
        usedBy: r.used_by, usedAt: r.used_at
      }));
      return json({ codes });
    }

    // ---- AI 写作助手 ----
    m = match(path, 'ai/assist');
    if (m && method === 'POST') {
      const me = await auth(request, env);
      if (!me) return bad('请先登录', 401);
      const body = await request.json().catch(() => ({}));
      // 兼容前端传 input 或 topic
      const { task = 'write', input = '', topic = '', content = '', style = '', extra = '', title = '' } = body;
      const finalTopic = topic || input || title;
      return json(await aiAssist(env, me.id, task, { topic: finalTopic, content, style, extra }));
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
        author: withAuthorSyncSimple(r.authorId, db)
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
      try { await env.DB.prepare(`INSERT INTO reviews (id,article_id,author_id,rating,content,created_at) VALUES (?,?,?,?,?,?)`)
        .bind(uid('rv'), r.targetId, r.authorId, r.rating, r.content, Date.now()).run(); } catch (e) { return bad(e.message); }
      try { await env.DB.prepare(`UPDATE users SET score=?, badges=? WHERE id=?`).bind(me.score, JSON.stringify(me.badges), me.id).run(); } catch (e) {}
      invalidateCache();
      return json({ ok: true, review: { ...r, author: withAuthorSyncSimple(me.id, db) } });
    }

    // ---- 今日打卡题目 ----
    m = match(path, 'checkins/today');
    if (m && method === 'GET') {
      // 每日一题：用日期确定性从 problems 里选（零存储、同天所有人一样）
      const todayStr = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
      const daySeed = todayStr.split('-').reduce((a, b) => a + parseInt(b, 10), 0);
      const available = db.problems.filter(p => p.status === 'approved');
      let daily = null;
      if (available.length > 0) {
        const idx = daySeed % available.length;
        daily = available[idx];
      }
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
      try { await env.DB.prepare(`INSERT INTO checkins (id,author_id,problem_id,content,word_count,points,streak,created_at) VALUES (?,?,?,?,?,?,?,?)`)
        .bind(c.id, c.authorId, c.problemId, c.content, c.wordCount, c.points, c.streak, c.createdAt).run(); } catch (e) { return bad(e.message); }
      try { await env.DB.prepare(`UPDATE users SET score=?, badges=? WHERE id=?`).bind(me.score, JSON.stringify(me.badges), me.id).run(); } catch (e) {}
      invalidateCache();
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
