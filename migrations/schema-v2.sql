-- 文洛社区 D1 Schema（Cloudflare Dashboard Console 粘贴执行）
-- 13 张表 + 索引
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, nickname TEXT, role TEXT DEFAULT 'user',
  bio TEXT, created_at INTEGER, salt TEXT, hash TEXT, login_fails INTEGER DEFAULT 0,
  locked_until INTEGER DEFAULT 0, score INTEGER DEFAULT 0, badges TEXT, following TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

CREATE TABLE IF NOT EXISTS tokens (
  token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id);

CREATE TABLE IF NOT EXISTS articles (
  id TEXT PRIMARY KEY, author_id TEXT NOT NULL, title TEXT, content TEXT,
  category TEXT DEFAULT '其他', status TEXT DEFAULT 'pending', views INTEGER DEFAULT 0,
  likes TEXT, created_at INTEGER, reviewed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_articles_author ON articles(author_id);
CREATE INDEX IF NOT EXISTS idx_articles_status ON articles(status);

CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY, author_id TEXT NOT NULL, title TEXT, content TEXT,
  category TEXT DEFAULT '其他', status TEXT DEFAULT 'pending',
  created_at INTEGER, comments TEXT
);
CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_id);
CREATE INDEX IF NOT EXISTS idx_posts_status ON posts(status);

CREATE TABLE IF NOT EXISTS contests (
  id TEXT PRIMARY KEY, title TEXT, description TEXT, problems TEXT,
  start_time INTEGER, end_time INTEGER, created_by TEXT, created_at INTEGER,
  participants TEXT, submissions TEXT
);
CREATE INDEX IF NOT EXISTS idx_contests_time ON contests(start_time, end_time);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT NOT NULL,
  content TEXT, read INTEGER DEFAULT 0, created_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(from_id, to_id);
CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_id, read);

CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY, author_id TEXT NOT NULL, original_name TEXT, stored_name TEXT,
  size INTEGER, note TEXT, status TEXT DEFAULT 'pending', created_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_files_author ON files(author_id);
CREATE INDEX IF NOT EXISTS idx_files_status ON files(status);

CREATE TABLE IF NOT EXISTS problems (
  id TEXT PRIMARY KEY, type TEXT, title TEXT, content TEXT, difficulty TEXT,
  tags TEXT, created_by TEXT, created_at INTEGER, status TEXT DEFAULT 'approved'
);
CREATE INDEX IF NOT EXISTS idx_problems_type ON problems(type);
CREATE INDEX IF NOT EXISTS idx_problems_status ON problems(status);

CREATE TABLE IF NOT EXISTS practices (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, problem_id TEXT NOT NULL,
  code TEXT, result TEXT, created_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_practices_user ON practices(user_id);
CREATE INDEX IF NOT EXISTS idx_practices_problem ON practices(problem_id);

CREATE TABLE IF NOT EXISTS reviews (
  id TEXT PRIMARY KEY, article_id TEXT NOT NULL, author_id TEXT NOT NULL,
  rating INTEGER, content TEXT, created_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_reviews_article ON reviews(article_id);
CREATE INDEX IF NOT EXISTS idx_reviews_author ON reviews(author_id);

CREATE TABLE IF NOT EXISTS checkins (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, problem_id TEXT,
  content TEXT, created_at INTEGER, points INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_checkins_user ON checkins(user_id);

CREATE TABLE IF NOT EXISTS templates (
  id TEXT PRIMARY KEY, title TEXT, category TEXT, description TEXT,
  content TEXT, created_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_templates_category ON templates(category);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
