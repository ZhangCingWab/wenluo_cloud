/*
 * Cloudflare Pages Functions - API 处理器
 * 使用 Cloudflare KV 存储 JSON 数据
 */
import { Router } from 'itty-router';

const router = Router();

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

// API 路由

// 健康检查
router.get('/api/health', () => {
  return new Response(JSON.stringify({ status: 'ok' }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// 获取当前用户
router.get('/api/me', async (request, env) => {
  const user = await requireAuth(request, env);
  return new Response(JSON.stringify({ user }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// 登录
router.post('/api/login', async (request, env) => {
  try {
    const { username, password } = await request.json();
    const data = await getData(env);
    
    const user = data.users.find(u => u.username === username);
    if (!user || !verifyPassword(password, user.password)) {
      return new Response(JSON.stringify({ error: '用户名或密码错误' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // 返回用户 ID 作为 token
    return new Response(JSON.stringify({ 
      user: { 
        id: user.id, 
        username: user.username, 
        nickname: user.nickname, 
        role: user.role 
      },
      token: user.id 
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: '登录失败' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 注册
router.post('/api/register', async (request, env) => {
  try {
    const { username, nickname, password } = await request.json();
    const data = await getData(env);
    
    // 检查用户名是否已存在
    if (data.users.find(u => u.username === username)) {
      return new Response(JSON.stringify({ error: '用户名已被占用' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
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
    
    return new Response(JSON.stringify({ 
      user: { 
        id: newUser.id, 
        username: newUser.username, 
        nickname: newUser.nickname, 
        role: newUser.role 
      },
      token: newUser.id 
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: '注册失败' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 获取首页数据
router.get('/api/home', async (request, env) => {
  const data = await getData(env);
  const now = Date.now();
  
  return new Response(JSON.stringify({
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
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// 获取文章列表
router.get('/api/articles', async (request, env) => {
  const data = await getData(env);
  const url = new URL(request.url);
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
  
  return new Response(JSON.stringify({ articles }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// 创建文章
router.post('/api/articles', async (request, env) => {
  try {
    const user = await requireAuth(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: '请先登录' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
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
    
    return new Response(JSON.stringify({ article: newArticle }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: '创建文章失败' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 404 处理
router.all('*', () => {
  return new Response(JSON.stringify({ error: 'Not Found' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json' }
  });
});

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
    const response = await router.handle(request, env);
    
    // 添加 CORS 头到响应
    Object.entries(corsHeaders).forEach(([key, value]) => {
      response.headers.set(key, value);
    });
    
    return response;
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: { 
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  }
}