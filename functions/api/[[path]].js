/*
 * Cloudflare Pages Functions - API 处理器
 * 使用 Cloudflare KV 存储 JSON 数据
 * 不依赖外部包，手动实现路由
 */

// 数据库初始化数据
const INITIAL_DATA = {
  users: [{
    id: 'u_admin',
    username: 'admin',
    nickname: '站务管理员',
    role: 'admin',
    bio: '本站管理员，负责文章、帖子与投稿审核。',
    createdAt: Date.now(),
    password: 'admin123' // 实际使用时应该加密
  }],
  articles: [],
  posts: [],
  contests: [],
  files: [],
  messages: [],
  problems: [],
  practices: []
};

// 工具函数
const uid = (prefix) => `${prefix}_${Math.random().toString(36).substr(2, 9)}`;

const hashPassword = (password) => {
  // 简单的密码哈希（生产环境应该使用更安全的方法）
  return btoa(password);
};

const verifyPassword = (password, hash) => {
  return btoa(password) === hash;
};

// 从 KV 获取数据
async function getData(env) {
  const data = await env.DATA.get('database');
  if (!data) {
    // 初始化数据
    await env.DATA.put('database', JSON.stringify(INITIAL_DATA));
    return INITIAL_DATA;
  }
  return JSON.parse(data);
}

// 保存数据到 KV
async function saveData(env, data) {
  await env.DATA.put('database', JSON.stringify(data));
}

// 用户认证中间件
async function requireAuth(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader) return null;
  
  const token = authHeader.replace('Bearer ', '');
  const data = await getData(env);
  return data.users.find(u => u.id === token);
}

// 简单路由器
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // 健康检查
  if (path === '/api/health' && method === 'GET') {
    return jsonResponse({ status: 'ok' });
  }

  // 获取当前用户
  if (path === '/api/me' && method === 'GET') {
    const user = await requireAuth(request, env);
    return jsonResponse({ user });
  }

  // 登录
  if (path === '/api/login' && method === 'POST') {
    try {
      const { username, password } = await request.json();
      const data = await getData(env);
      
      const user = data.users.find(u => u.username === username);
      if (!user || !verifyPassword(password, user.password)) {
        return jsonResponse({ error: '用户名或密码错误' }, 401);
      }
      
      // 返回用户 ID 作为 token
      return jsonResponse({ 
        user: { 
          id: user.id, 
          username: user.username, 
          nickname: user.nickname, 
          role: user.role 
        },
        token: user.id 
      });
    } catch (error) {
      return jsonResponse({ error: '登录失败' }, 500);
    }
  }

  // 注册
  if (path === '/api/register' && method === 'POST') {
    try {
      const { username, nickname, password } = await request.json();
      const data = await getData(env);
      
      // 检查用户名是否已存在
      if (data.users.find(u => u.username === username)) {
        return jsonResponse({ error: '用户名已被占用' }, 400);
      }
      
      const newUser = {
        id: uid('u'),
        username,
        nickname: nickname || username,
        role: 'user',
        bio: '',
        password: hashPassword(password),
        createdAt: Date.now()
      };
      
      data.users.push(newUser);
      await saveData(env, data);
      
      return jsonResponse({ 
        user: { 
          id: newUser.id, 
          username: newUser.username, 
          nickname: newUser.nickname, 
          role: newUser.role 
        },
        token: newUser.id 
      });
    } catch (error) {
      return jsonResponse({ error: '注册失败' }, 500);
    }
  }

  // 获取首页数据
  if (path === '/api/home' && method === 'GET') {
    const data = await getData(env);
    const now = Date.now();
    
    return jsonResponse({
      stats: {
        users: data.users.length,
        articles: data.articles.filter(a => a.status === 'approved').length,
        posts: data.posts.filter(p => p.status === 'approved').length,
        contests: data.contests.length
      },
      latestArticles: data.articles
        .filter(a => a.status === 'approved')
        .sort((a, b) => b.createdAt - a.createdAt)
        .slice(0, 6),
      latestPosts: data.posts
        .filter(p => p.status === 'approved')
        .sort((a, b) => b.createdAt - a.createdAt)
        .slice(0, 6),
      activeContests: data.contests
        .filter(c => c.startTime <= now && now <= c.endTime)
        .slice(0, 3)
    });
  }

  // 获取文章列表
  if (path === '/api/articles' && method === 'GET') {
    const data = await getData(env);
    const category = url.searchParams.get('category');
    const query = url.searchParams.get('q');
    
    let articles = data.articles.filter(a => a.status === 'approved');
    
    if (category) {
      articles = articles.filter(a => a.category === category);
    }
    
    if (query) {
      const lowerQuery = query.toLowerCase();
      articles = articles.filter(a => 
        a.title.toLowerCase().includes(lowerQuery) ||
        a.content.toLowerCase().includes(lowerQuery)
      );
    }
    
    articles.sort((a, b) => b.createdAt - a.createdAt);
    
    return jsonResponse({ articles });
  }

  // 创建文章
  if (path === '/api/articles' && method === 'POST') {
    try {
      const user = await requireAuth(request, env);
      if (!user) {
        return jsonResponse({ error: '请先登录' }, 401);
      }
      
      const { title, content, category } = await request.json();
      const data = await getData(env);
      
      const newArticle = {
        id: uid('a'),
        authorId: user.id,
        title,
        content,
        category: category || '其他',
        status: 'pending',
        views: 0,
        likes: [],
        createdAt: Date.now()
      };
      
      data.articles.push(newArticle);
      await saveData(env, data);
      
      return jsonResponse({ article: newArticle });
    } catch (error) {
      return jsonResponse({ error: '创建文章失败' }, 500);
    }
  }

  // 404 处理
  return jsonResponse({ error: 'Not Found' }, 404);
}

// JSON 响应辅助函数
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

// 主处理函数
export async function onRequest(context) {
  const { request, env } = context;
  
  // 添加 CORS 头
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  };
  
  // 处理 OPTIONS 请求
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }
  
  try {
    const response = await handleRequest(request, env);
    
    // 添加 CORS 头到响应
    Object.entries(corsHeaders).forEach(([key, value]) => {
      response.headers.set(key, value);
    });
    
    return response;
  } catch (error) {
    return jsonResponse({ error: 'Internal Server Error' }, 500);
  }
}