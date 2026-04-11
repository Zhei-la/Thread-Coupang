const express = require('express');
const cors = require('cors');
const multer = require('multer');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
const cron = require('node-cron');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

// ── 보안 설정 ──
const ALLOWED_ORIGINS = process.env.BASE_URL ? [process.env.BASE_URL] : [];
const corsOptions = {
  origin: function(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS 차단'));
    }
  },
  credentials: true
};
app.use(cors(corsOptions));

const DATA_ROOT = process.env.DATA_PATH || '/app/data';
if (!fs.existsSync(DATA_ROOT)) fs.mkdirSync(DATA_ROOT, { recursive: true });

function loadJSON(file, def) {
  try { return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : def; } catch(e) { return def; }
}
function saveJSON(file, data) {
  const dir = require('path').dirname(file);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[<>]/g, '').trim().slice(0, 5000);
}

let users       = loadJSON(`${DATA_ROOT}/users.json`, []);
let inviteCodes = loadJSON(`${DATA_ROOT}/invite_codes.json`, []);
let sessions    = {};

function userDir(userId) {
  const path = require('path');
  const safeUserId = String(userId).replace(/[^a-zA-Z0-9_-]/g, '');
  const dir = path.resolve(`${DATA_ROOT}/users`, safeUserId);
  const base = path.resolve(`${DATA_ROOT}/users`);
  if (!dir.startsWith(base)) throw new Error('경로 접근 차단');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}
function getAccounts(userId)  { return loadJSON(`${userDir(userId)}/accounts.json`, []); }
function getSettings() { return loadJSON(`${DATA_ROOT}/settings.json`, { kakaoLink: '' }); }
function saveSettings(data) { saveJSON(`${DATA_ROOT}/settings.json`, data); }
function getTodayKey() { return new Date().toISOString().slice(0, 10); }
function getPublishCount(userId) { return loadJSON(`${userDir(userId)}/publish_count.json`, {}); }
function savePublishCount(userId, data) { saveJSON(`${userDir(userId)}/publish_count.json`, data); }
function getAccPublishKey(accountId) { return accountId + '_' + getTodayKey(); }
function saveAccounts(userId, data) { saveJSON(`${userDir(userId)}/accounts.json`, data); }
function getScheduled(userId) { return loadJSON(`${userDir(userId)}/scheduled.json`, []); }
function saveScheduled(userId, data) { saveJSON(`${userDir(userId)}/scheduled.json`, data); }

// ── 미디어 URL 검증 (SSRF 방지) ──
const ALLOWED_MEDIA_DOMAINS = ['res.cloudinary.com', 'image.mux.com', 'i.imgur.com'];
const PRIVATE_IP_RE = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.|localhost)/i;
function validateMediaUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== 'https:') return { ok: false, reason: 'HTTPS 아님' };
    if (PRIVATE_IP_RE.test(u.hostname)) return { ok: false, reason: '내부 IP 차단' };
    const ok = ALLOWED_MEDIA_DOMAINS.some(d => u.hostname === d || u.hostname.endsWith('.' + d));
    if (!ok) return { ok: false, reason: '허용되지 않은 도메인: ' + u.hostname };
    return { ok: true };
  } catch(e) { return { ok: false, reason: '유효하지 않은 URL' }; }
}

function hashPw(pw) {
  return crypto.pbkdf2Sync(pw, 'threads_secure_salt_2025_!@#', 100000, 64, 'sha512').toString('hex');
}
function hashPwLegacy(pw) {
  return crypto.createHash('sha256').update(pw + 'threads_salt_2025').digest('hex');
}
function verifyPw(pw, storedHash) {
  if (hashPw(pw) === storedHash) return true;
  if (hashPwLegacy(pw) === storedHash) return true;
  return false;
}

const SESSION_TTL = 3 * 24 * 60 * 60 * 1000;
const SESSIONS_FILE = `${DATA_ROOT}/sessions.json`;
function loadSessions() {
  try {
    if (!fs.existsSync(SESSIONS_FILE)) return {};
    const data = JSON.parse(fs.readFileSync(SESSIONS_FILE));
    const now = Date.now();
    const valid = {};
    for (const [token, s] of Object.entries(data)) {
      if (s.expiresAt > now) valid[token] = s;
    }
    return valid;
  } catch(e) { return {}; }
}
function saveSessions() {
  try { fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions, null, 2)); } catch(e) {}
}
function createSession(userId) {
  const token = crypto.randomUUID();
  sessions[token] = { userId, expiresAt: Date.now() + SESSION_TTL };
  saveSessions();
  return token;
}
function getSession(token) {
  const s = sessions[token];
  if (!s) return null;
  if (Date.now() > s.expiresAt) { delete sessions[token]; saveSessions(); return null; }
  return s;
}
setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const [token, s] of Object.entries(sessions)) {
    if (now > s.expiresAt) { delete sessions[token]; changed = true; }
  }
  if (changed) saveSessions();
}, 60 * 60 * 1000);

const rateLimitMap = {};
function rateLimit(maxReq = 60, windowMs = 60000) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    if (!rateLimitMap[ip]) rateLimitMap[ip] = [];
    rateLimitMap[ip] = rateLimitMap[ip].filter(t => now - t < windowMs);
    if (rateLimitMap[ip].length >= maxReq) {
      return res.status(429).json({ error: '요청이 너무 많아. 잠시 후 다시 시도해줘.' });
    }
    rateLimitMap[ip].push(now);
    next();
  };
}
setInterval(() => {
  const now = Date.now();
  for (const ip of Object.keys(rateLimitMap)) {
    rateLimitMap[ip] = (rateLimitMap[ip] || []).filter(t => now - t < 60000);
    if (!rateLimitMap[ip].length) delete rateLimitMap[ip];
  }
}, 10 * 60 * 1000);

function auth(req, res, next) {
  const token = req.headers['x-session'];
  if (!token || typeof token !== 'string' || token.length > 64 || !/^[a-zA-Z0-9-]+$/.test(token)) {
    return res.status(401).json({ error: '로그인 필요' });
  }
  const s = getSession(token);
  if (!s) return res.status(401).json({ error: '로그인 필요' });
  req.userId = s.userId;
  req.user = users.find(u => u.id === req.userId);
  if (!req.user) return res.status(401).json({ error: '유저 없음' });
  next();
}
function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (req.user?.role !== 'admin') return res.status(403).json({ error: '관리자만 가능' });
    next();
  });
}

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.removeHeader('X-Powered-By');
  next();
});
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// ══════════════════════════════════
//  AUTH API
// ══════════════════════════════════

app.get('/api/auth/is-first', (req, res) => res.json({ isFirst: users.length === 0 }));

app.get('/api/auth/reset-admin', (req, res) => {
  if (req.query.secret !== 'RESET_2025_THREADS') return res.status(403).json({ error: '권한 없음' });
  const newpw = req.query.newpw;
  if (!newpw || newpw.length < 4) return res.status(400).json({ error: '비밀번호 4자 이상' });
  const admin = users.find(u => u.role === 'admin');
  if (!admin) return res.status(404).json({ error: '관리자 없음' });
  admin.passwordHash = hashPw(newpw);
  delete admin.password;
  saveJSON(`${DATA_ROOT}/users.json`, users);
  res.json({ ok: true, nickname: admin.nickname, message: '비밀번호 변경 완료' });
});

app.post('/api/auth/setup', (req, res) => {
  if (users.length > 0) return res.status(400).json({ error: '이미 설정됨' });
  const { nickname, password } = req.body;
  if (!nickname || !password) return res.status(400).json({ error: '닉네임/비밀번호 필요' });
  const user = { id: Date.now().toString(), nickname, passwordHash: hashPw(password), role: 'admin', createdAt: new Date().toISOString() };
  users.push(user);
  saveJSON(`${DATA_ROOT}/users.json`, users);
  const token = crypto.randomUUID();
  sessions[token] = user.id;
  res.json({ token, nickname: user.nickname, role: user.role });
});

app.post('/api/auth/register', rateLimit(3, 60000), (req, res) => {
  const { nickname, password, inviteCode } = req.body;
  if (!nickname || !password) return res.status(400).json({ error: '닉네임과 비밀번호 필요' });
  if (password.length < 4) return res.status(400).json({ error: '비밀번호는 4자리 이상 입력해줘' });
  if (users.find(u => u.nickname === nickname)) return res.status(400).json({ error: '이미 사용중인 닉네임' });
  let role = 'user';
  if (users.length === 0) {
    role = 'admin';
  } else {
    if (!inviteCode) return res.status(400).json({ error: '초대코드가 필요해' });
    const invite = inviteCodes.find(c => c.code === inviteCode);
    if (!invite) return res.status(400).json({ error: '유효하지 않은 초대코드' });
    if (invite.status === 'done') return res.status(400).json({ error: '만료된 초대코드야. 새 코드를 받아줘.' });
    invite.lastUsedBy = nickname; invite.lastUsedAt = new Date().toISOString();
    invite.useCount = (invite.useCount || 0) + 1;
    saveJSON(`${DATA_ROOT}/invite_codes.json`, inviteCodes);
    const settings = getSettings();
    if (settings.partnerCode && inviteCode === settings.partnerCode) {
      req.body._partnerJoin = true;
    }
  }
  const status = role === 'admin' ? 'approved' : 'pending';
  const user = { id: Date.now().toString(), nickname, name: req.body.name || '', passwordHash: hashPw(password), role, status, joinedVia: req.body._partnerJoin ? 'partner' : 'normal', createdAt: new Date().toISOString() };
  users.push(user);
  saveJSON(`${DATA_ROOT}/users.json`, users);
  if (user.status === 'pending') { res.json({ pending: true, nickname: user.nickname }); return; }
  const token = createSession(user.id);
  res.json({ token, nickname: user.nickname, role: user.role });
});

app.post('/api/auth/login', rateLimit(5, 60000), (req, res) => {
  const nickname = sanitize(req.body.nickname || '');
  const password = req.body.password || '';
  if (!nickname || !password) return res.status(400).json({ error: '닉네임과 비밀번호 필요' });
  if (nickname.length > 30 || password.length > 100) return res.status(400).json({ error: '입력값 오류' });
  const user = users.find(u => {
    if (u.nickname !== nickname) return false;
    const stored = u.passwordHash || u.password || '';
    return verifyPw(password, stored);
  });
  if (!user) return res.status(401).json({ error: '닉네임 또는 비밀번호 오류' });
  if (user.status === 'pending') return res.status(403).json({ error: 'pending' });
  if (user.status === 'suspended') return res.status(403).json({ error: 'suspended' });
  if (user.expiresAt && new Date() > new Date(user.expiresAt) && user.role !== 'admin') {
    return res.status(403).json({ error: 'expired' });
  }
  const stored = user.passwordHash || user.password || '';
  if (stored !== hashPw(password)) {
    user.passwordHash = hashPw(password);
    delete user.password;
    saveJSON(`${DATA_ROOT}/users.json`, users);
  }
  const token = createSession(user.id);
  res.json({ token, nickname: user.nickname, role: user.role });
});

app.post('/api/auth/logout', auth, (req, res) => {
  const token = req.headers['x-session'];
  delete sessions[token];
  saveSessions();
  res.json({ ok: true });
});

app.get('/api/auth/me', auth, (req, res) => {
  const u = req.user;
  const today = getTodayKey();
  const counts = getPublishCount(u.id);
  const genUsed = counts['gen_' + today] || 0;
  const genLimit = u.plan === 'free' ? 100 : 200;
  res.json({
    id: u.id, nickname: u.nickname, name: u.name || '', role: u.role,
    plan: u.plan || 'free', accountLimit: u.accountLimit || 1,
    expiresAt: u.expiresAt || null, genUsed, genLimit, status: u.status || 'approved'
  });
});

app.get('/api/invites', adminAuth, (req, res) => res.json(inviteCodes));
app.get('/api/settings', auth, (req, res) => {
  const s = getSettings();
  const u = req.user;
  if (u?.role !== 'admin') {
    // 일반 유저에게는 알림 숨김
    const { _openaiQuotaAlert, ...pub } = s;
    return res.json(pub);
  }
  res.json(s);
});

// 관리자가 OpenAI 쿼터 알림 확인 후 초기화
app.delete('/api/settings/openai-alert', adminAuth, (req, res) => {
  const s = getSettings();
  delete s._openaiQuotaAlert;
  saveSettings(s);
  res.json({ ok: true });
});

app.put('/api/settings/basic-tags', auth, (req, res) => {
  const dir = userDir(req.userId);
  saveJSON(`${dir}/basic_tags.json`, { topics: req.body.topics || [] });
  res.json({ ok: true });
});

app.put('/api/settings', adminAuth, (req, res) => {
  const settings = getSettings();
  if (req.body.kakaoLink !== undefined) settings.kakaoLink = req.body.kakaoLink;
  if (req.body.partnerCode !== undefined) settings.partnerCode = req.body.partnerCode.toUpperCase();
  saveSettings(settings);
  res.json({ ok: true });
});

app.post('/api/invites', adminAuth, (req, res) => {
  const activeCodes = inviteCodes.filter(c => c.status !== 'done');
  if (activeCodes.length >= 2) activeCodes[0].status = 'done';
  const code = crypto.randomBytes(4).toString('hex').toUpperCase();
  const invite = { code, createdBy: req.user.nickname, status: 'active', useCount: 0, createdAt: new Date().toISOString() };
  inviteCodes.push(invite);
  saveJSON(`${DATA_ROOT}/invite_codes.json`, inviteCodes);
  res.json(invite);
});

app.delete('/api/invites/:code', adminAuth, (req, res) => {
  inviteCodes = inviteCodes.filter(c => c.code !== req.params.code);
  saveJSON(`${DATA_ROOT}/invite_codes.json`, inviteCodes);
  res.json({ ok: true });
});

app.get('/api/users', adminAuth, (req, res) => {
  res.json(users.map(u => ({ id: u.id, nickname: u.nickname, name: u.name||'', role: u.role, status: u.status||'approved', plan: u.plan||'free', accountLimit: u.accountLimit||2, dailyPublishLimit: u.dailyPublishLimit||null, limitRequest: u.limitRequest||null, extendRequest: u.extendRequest||null, upgradeRequest: u.upgradeRequest||null, planChangeRequest: u.planChangeRequest||null, joinedVia: u.joinedVia||'normal', approvedAt: u.approvedAt||null, expiresAt: u.expiresAt||null, createdAt: u.createdAt, isExpired: u.expiresAt ? new Date(u.expiresAt) < new Date() : false })));
});

app.delete('/api/users/:id', adminAuth, (req, res) => {
  if (req.params.id === req.userId) return res.status(400).json({ error: '본인 삭제 불가' });
  users = users.filter(u => u.id !== req.params.id);
  saveJSON(`${DATA_ROOT}/users.json`, users);
  res.json({ ok: true });
});

app.post('/api/users/upgrade-request', auth, (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: '없음' });
  if (user.plan !== 'free') return res.status(400).json({ error: '이미 유료 계정이야' });
  if (user.upgradeRequest) return res.status(400).json({ error: '이미 신청 중이야' });
  user.upgradeRequest = { requestedAt: new Date().toISOString() };
  saveJSON(`${DATA_ROOT}/users.json`, users);
  res.json({ ok: true });
});

app.post('/api/users/limit-request', auth, (req, res) => {
  if (req.body.requestPlan) {
    const user = users.find(u => u.id === req.userId);
    if (!user) return res.status(404).json({ error: '없음' });
    user.planChangeRequest = { plan: req.body.requestPlan, requestedAt: new Date().toISOString() };
    saveJSON(`${DATA_ROOT}/users.json`, users);
    return res.json({ ok: true });
  }
  const user = users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: '없음' });
  const { requestLimit, requestExtend } = req.body;
  if (requestExtend) {
    if (user.extendRequest) return res.status(400).json({ error: '이미 연장 신청 중이야' });
    user.extendRequest = { requestedAt: new Date().toISOString() };
    saveJSON(`${DATA_ROOT}/users.json`, users);
    return res.json({ ok: true });
  }
  if (![3, 6].includes(requestLimit)) return res.status(400).json({ error: '3 또는 6만 가능' });
  if (user.accountLimit === requestLimit) return res.status(400).json({ error: '이미 해당 한도야' });
  user.limitRequest = { requestLimit, requestedAt: new Date().toISOString() };
  saveJSON(`${DATA_ROOT}/users.json`, users);
  res.json({ ok: true });
});

app.put('/api/users/:id/status', adminAuth, (req, res) => {
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: '없음' });
  if (user.role === 'admin') return res.status(400).json({ error: '관리자 상태 변경 불가' });
  user.status = req.body.status;
  if (req.body.status === 'approved' && !user.approvedAt) {
    user.approvedAt = new Date().toISOString();
    const days = req.body.planDays || 30;
    user.expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
    user.plan = req.body.plan || 'basic';
    if (req.body.plan === 'basic') { user.accountLimit = 0; user.dailyPublishLimit = 0; }
    else if (req.body.plan === 'legacy') { user.accountLimit = 2; user.dailyPublishLimit = 3; }
    else if (req.body.plan === 'pro') { user.accountLimit = 6; user.dailyPublishLimit = 5; }
    else if (req.body.plan === 'free') { user.accountLimit = 1; user.dailyPublishLimit = 2; }
  }
  if (req.body.changePlan) {
    user.plan = req.body.plan;
    if (req.body.plan === 'basic') { user.accountLimit = 0; user.dailyPublishLimit = 0; }
    else if (req.body.plan === 'legacy') { user.accountLimit = 2; user.dailyPublishLimit = 3; }
    else if (req.body.plan === 'pro') { user.accountLimit = 6; user.dailyPublishLimit = 5; }
    const base = user.expiresAt && new Date(user.expiresAt) > new Date() ? new Date(user.expiresAt) : new Date();
    user.expiresAt = new Date(base.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
  }
  if (req.body.accountLimit) { user.accountLimit = req.body.accountLimit; user.limitRequest = null; }
  if (req.body.clearLimitRequest) user.limitRequest = null;
  if (req.body.extendDays) {
    const base = user.expiresAt && new Date(user.expiresAt) > new Date() ? new Date(user.expiresAt) : new Date();
    user.expiresAt = new Date(base.getTime() + Number(req.body.extendDays) * 24 * 60 * 60 * 1000).toISOString();
    user.extendRequest = null;
  }
  if (req.body.setPlan) {
    user.plan = req.body.setPlan;
    if (req.body.setPlan === 'basic') { user.accountLimit = 0; user.dailyPublishLimit = 0; }
    else if (req.body.setPlan === 'legacy') { user.accountLimit = 2; user.dailyPublishLimit = 3; }
    else if (req.body.setPlan === 'pro') { user.accountLimit = 6; user.dailyPublishLimit = 5; }
    const planDays = req.body.planDays || (req.body.setPlan === 'pro' ? 30 : 30);
    const base2 = user.expiresAt && new Date(user.expiresAt) > new Date() ? new Date(user.expiresAt) : new Date();
    user.expiresAt = new Date(base2.getTime() + planDays * 24 * 60 * 60 * 1000).toISOString();
    if (!user.approvedAt) { user.approvedAt = new Date().toISOString(); user.status = 'approved'; }
    user.planChangeRequest = null;
  }
  if (req.body.denyExtend) user.extendRequest = null;
  if (req.body.approveUpgrade) {
    user.plan = 'paid'; user.dailyPublishLimit = null; user.upgradeRequest = null;
    if (req.body.accountLimit) user.accountLimit = req.body.accountLimit;
    const base = user.expiresAt && new Date(user.expiresAt) > new Date() ? new Date(user.expiresAt) : new Date();
    user.expiresAt = new Date(base.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
    if (!user.approvedAt) user.approvedAt = new Date().toISOString();
  }
  if (req.body.denyUpgrade) user.upgradeRequest = null;
  if (req.body.denyPlanChange) user.planChangeRequest = null;
  if (req.body.approvePlanChange) {
    const reqPlan = user.planChangeRequest ? user.planChangeRequest.plan : null;
    if (reqPlan) {
      user.plan = reqPlan;
      if (reqPlan === 'basic') { user.accountLimit = 0; user.dailyPublishLimit = 0; user.expiresAt = new Date(Date.now() + 30 * 86400000).toISOString(); }
      else if (reqPlan === 'legacy') { user.accountLimit = 2; user.dailyPublishLimit = 3; user.expiresAt = new Date(Date.now() + 30 * 86400000).toISOString(); }
      else if (reqPlan === 'pro') { user.accountLimit = 6; user.dailyPublishLimit = 5; user.expiresAt = new Date(Date.now() + 60 * 86400000).toISOString(); }
    }
    user.planChangeRequest = null;
  }
  saveJSON(`${DATA_ROOT}/users.json`, users);
  res.json({ ok: true });
});

// ══════════════════════════════════
//  Threads 계정 관리
// ══════════════════════════════════

app.get('/api/accounts', auth, (req, res) => {
  const accs = getAccounts(req.userId);
  res.json(accs.map(a => ({ ...a, accessToken: (a.accessToken || '').slice(0, 6) + '...' + (a.accessToken || '').slice(-4), tokenRegisteredAt: a.tokenRegisteredAt || null })));
});

app.post('/api/accounts', auth, (req, res) => {
  const { name, accessToken, topics } = req.body;
  if (!name || !accessToken) return res.status(400).json({ error: '이름과 토큰 필요' });
  const accs = getAccounts(req.userId);
  const user = users.find(u => u.id === req.userId);
  const limit = user?.accountLimit || 3;
  if (user?.role !== 'admin' && accs.length >= limit) {
    return res.status(400).json({ error: `계정은 최대 ${limit}개까지 등록 가능해` });
  }
  const acc = { id: Date.now().toString(), name, accessToken, topics: topics || [], tokenRegisteredAt: new Date().toISOString() };
  accs.push(acc);
  saveAccounts(req.userId, accs);
  res.json(acc);
});

app.delete('/api/accounts/:id', auth, (req, res) => {
  let accs = getAccounts(req.userId);
  accs = accs.filter(a => a.id !== req.params.id);
  saveAccounts(req.userId, accs);
  res.json({ ok: true });
});

app.put('/api/accounts/:id/topics', auth, (req, res) => {
  const accs = getAccounts(req.userId);
  const acc = accs.find(a => a.id === req.params.id);
  if (!acc) return res.status(404).json({ error: '없음' });
  acc.topics = req.body.topics || [];
  saveAccounts(req.userId, accs);
  res.json(acc);
});

// ══════════════════════════════════
//  AI 글 생성 (OpenAI GPT-4o-mini)
// ══════════════════════════════════

app.post('/api/generate', auth, rateLimit(30, 60000), async (req, res) => {
  const genUser = users.find(u => u.id === req.userId);
  if (genUser && genUser.role !== 'admin') {
    const genCount = getPublishCount(req.userId);
    const genKey = 'gen_' + getTodayKey();
    const genLimit = genUser.plan === 'free' ? 100 : 200;
    if ((genCount[genKey] || 0) >= genLimit) {
      return res.status(429).json({ error: '오늘 글 생성 한도(' + genLimit + '번)를 초과했어.' });
    }
    genCount[genKey] = (genCount[genKey] || 0) + 1;
    savePublishCount(req.userId, genCount);
  }

  const { topic, tone, type, imageDesc, userPrompt, commentPrompt } = req.body;
  const fixedTones = Array.isArray(req.body.fixedTones) ? req.body.fixedTones : [];
  const hasCoupang = fixedTones.includes('쿠팡/홍보');
  const hasCommentLure = fixedTones.includes('댓글유도형');
  const hasSirk = fixedTones.includes('시크하게');
  const postLength = req.body.postLength || 'short';
  const lengthRules = {
    short: `[글 길이 - 짧게]
- 반드시 6~8줄 이내로 작성.
- 2줄씩 붙여 쓰고 → 빈 줄 → 2줄씩 붙여 쓰기 반복.
- 1줄 단독으로 끊는 거 금지.
- 예시 (마침표 절대 없음):
  요즘 이거 쓰는데
  생각보다 괜찮더라

  처음엔 별로였는데
  손이 가네`,

    medium: `[글 길이 - 중간]
- 9~14줄 분량으로 작성.
- 2~4줄씩 붙여 쓰고 → 빈 줄 → 반복.
- 1줄 단독 금지.`,

    long: `[글 길이 - 길게]
- 15~20줄 분량으로 작성.
- 2~4줄씩 붙여 쓰고 → 빈 줄 → 반복.
- 1줄 단독 금지.`
  };
  const lengthInstr = lengthRules[postLength] || lengthRules.short;
  const openaiKey = process.env.OPENAI_API_KEY;
  const groqKey = process.env.GROQ_API_KEY;
  const apiKey = openaiKey || groqKey;
  if (!apiKey) return res.status(500).json({ error: 'API 키 없음 (OPENAI_API_KEY 또는 GROQ_API_KEY)' });

  const apiUrl = openaiKey ? 'https://api.openai.com/v1/chat/completions' : 'https://api.groq.com/openai/v1/chat/completions';
  const model = openaiKey ? 'gpt-4o-mini' : 'llama-3.3-70b-versatile';

  const imgContext = imageDesc ? `\n[이미지 분석 결과]: ${imageDesc}` : '';
  const customUserPrompt = userPrompt ? String(userPrompt).slice(0, 500) : '';
  const customCommentPrompt = commentPrompt ? String(commentPrompt).slice(0, 300) : '';

  const tonePrompts = {
    '리스트형': `SNS 리스트형 글. 번호나 줄 나열. 핵심만. 일부 정보는 숨겨서 궁금하게.
[절대 금지] "~인데요", "~습니다" 뻔한 시작 금지. 교과서 같은 정리 금지.
[예시]
요즘 사람들이 많이 찾던데
1. 이래서 쓰는 거였음
2. 생각보다 쓸만함
3. 솔직히 좀 아쉬운 부분도 있음
나머지는 댓글에 씀`,

    '정보성': `SNS 정보형 글. 아는 척 말고 알게 된 척.
[절대 금지] "안녕하세요", "오늘은 ~에 대해" 뻔한 시작 금지. 너무 친절한 설명 금지.
[예시]
모르면 진짜 손해인 것들
대부분 이렇게 쓰는데 그게 아니라
이렇게 하면 훨씬 낫더라
자세한 건 댓글`,

    '리뷰형': `실제로 써본 사람 느낌. 솔직하게.
[절대 금지] "안녕하세요 오늘은 리뷰" 이런 시작 절대 금지. 지나친 칭찬 금지.
[예시]
솔직히 별로일 줄 알았는데
생각보다 괜찮아서 당황함
이 부분은 좀 걸리긴 함
전반적으로는 쓸 것 같음`,

    '일상': `그냥 하는 일상 얘기. 평범하게.
[절대 금지] 과장 금지. 억지 스토리 금지. 교훈 금지.
[예시]
오늘 그냥 아무 생각 없이 해봤는데
생각보다 나쁘지 않음
왜 진작 안 했지`,

    '공감형': `모두가 겪는 상황. 짧게. 공감 유도.
[절대 금지] 억지 공감 금지. 너무 길게 설명 금지.
[예시]
나만 이런 거 아니지
뭔가 하려고 하면 꼭 이런 일이 생김
진짜 왜 이러냐`,

    '스토리형': `짧은 일화. 과정이 재밌어야 함.
[절대 금지] "그 날 이후로 나는 달라졌다" 뻔한 결말 절대 금지. 드라마 같은 전개 금지. 교훈 마무리 금지.
[예시]
어제 완전 황당한 일이 있었는데
결국 별거 아니었음
근데 생각할수록 웃기네`,

    '쿠팡/홍보': `일상 SNS 글을 쓰는 평범한 사람. 절대 광고처럼 보이면 안 됨.
[핵심] 내 것이 아닌 척. 사진/영상 보고 궁금하게만 만들면 됨. 1~2줄. 구매 유도 절대 금지.
[예시]
강아지: 우리 강아지 밤만 되면 이 난리ㅠㅠ 하나 바꿨는데 밤에 좀 덜해졌어
음식: 남편이 또 이것만 달래 이제 진짜 지겨워
생활용품: 쓰고 나서 예전으로 못 돌아가겠다
[규칙] 이모지 금지(ㅠㅠ ㅋㅋ 가능). 반말만. 1~2줄 엄수. 구매유도 금지. 제품명 금지.`,

    '쿠팡': `일상 SNS 글. 1~2줄. 경험담처럼. 궁금하게만. 구매유도 금지. 제품명 금지. 반말.`,

    '댓글유도형': `SNS 게시글을 작성하되, 중간에 내용을 자연스럽게 끊어서 댓글에서 이어지는 느낌으로 작성.
글은 정보나 이야기를 전달하다가 핵심 직전에 멈추고, 마지막에 댓글을 보게 유도.
억지스럽지 않게, 진짜 쓰다가 공간이 부족한 느낌으로.`
  };

  const toneInstruction = tonePrompts[tone] || tonePrompts['일상'];

  // 고정 말투 추가 지침
  let fixedToneInstr = '';
  if (hasCoupang) {
    fixedToneInstr += `\n\n[쿠팡/홍보 적용]
- 글 전체가 광고처럼 보이지 않게. 자연스러운 일상 얘기로.
- 제품명·브랜드명 직접 언급 금지.`;
  }
  if (hasCommentLure) {
    fixedToneInstr += `\n\n[댓글유도형 - 두 가지 패턴 중 하나를 자연스럽게 선택]

패턴1: 말하다 뚝 끊기
- 상황이나 경험을 말하다가 결과 직전에 그냥 끝냄
- 예고나 유도 표현 없이 그냥 문장이 끝남
- 예시:
  강아지담요 써봤는데 생각보다 괜찮더라
  내 강아지가 진짜 좋아하더라고
  처음엔 별로 기대 안 했는데 다르네
  꽤 부드럽고 따뜻하고
  ← 여기서 그냥 끝

패턴2: 질문으로 끝내기
- 상황 설명하다가 마지막에 왜 이래? 어떡해? 이게 맞아? 같은 질문으로 끝
- 독자가 궁금해서 댓글 확인하게 만드는 느낌
- 예시:
  강아지 사료 바꿨는데
  갑자기 밥을 안 먹네
  어제까지 잘 먹었는데 이게 왜 이래?

공통 규칙:
- "댓글에", "나머지는", "알려줄게" 같은 직접 유도 표현 절대 금지
- 자연스럽게 말하다 끝나는 느낌`;
  }
  if (hasSirk) {
    fixedToneInstr += `\n\n[😎 시크하게]\n- 건조하고 툭 던지는 식. 감정 과잉 절대 금지.\n- 귀찮은 듯한 뉘앙스. 설명하려 하지 마.\n- 공감하되 티 내지 마. 위트는 있되 노력한 티 없게.\n- 예시: "그냥 해봤는데 됨" / "별거 없었음" / "왜 이게 돼"`;
  }

  const sirkInstr = hasSirk ? `

[😎 시크하게]
- 담백하게. 있는 그대로.
- 쿨한 척·멋있는 척 금지. 억지로 무관심한 척도 금지.
- 건조하게 툭 뱉는 것과 감정 없는 척은 다름.
- 설명하려 하지 마. 이유 붙이지 마.
- 예시: "그냥 해봤는데 됨" / "별거 없음" / "왜 되는지 모르겠음"` : '';

  const systemMsg = `너는 SNS에 글 올리는 평범한 한국인이다. AI가 쓴 것처럼 보이면 절대 안 된다.

[언어]
- 한국어만. 한자·일본어·영어 절대 금지 (주제 속 영어 단어 제외).
- 이모지 완전 금지. 해시태그(#) 완전 금지.

[말투 - 가장 중요]
- 진짜 사람이 폰으로 빠르게 치는 것처럼 써.
- 마침표(.) 어디에도 절대 금지. 예시: "좋더라" O / "좋더라." X
- 물음표(?)·느낌표(!)도 꼭 필요할 때만.
- 착한 척·다정한 척·희망찬 마무리 금지.
- 느끼한 표현 금지: "빛나는", "특별한 하루", "나만의 방식", "설레는" 등.
- 멋있어 보이려는 척 금지. 과장 남발 금지.
- "함께라면", "할 수 있어", "오늘도 화이팅" 같은 교과서 표현 금지.
- "정말", "진짜로", "꼭", "반드시", "최고" 남발 금지.
- 그냥 툭 뱉듯이. "~했어" "~하더라" "~인 것 같음" "~임" "~네".
- 반말만. 제품명·브랜드명 직접 언급 금지.
- 리스트형 외 번호·불릿 금지.

${lengthInstr}

[출력]
- 게시글 텍스트만. 설명·주석·따옴표 없이.${sirkInstr}`;

  let prompt = '';
  if (type === 'comment') {
    const extra = customCommentPrompt ? '\n추가 지침: ' + customCommentPrompt : '';
    const commentLureInstr = hasCommentLure
      ? '\n\n[댓글 작성 규칙 - 두 가지 경우]\n\n글이 말하다 뚝 끊긴 경우:\n- 끊긴 이후 결과나 뒷이야기를 자연스럽게 이어서 써줘\n- 구체적인 정보나 경험으로\n\n글이 질문으로 끝난 경우:\n- 같은 사람이 댓글 다는 거임. 절대로 "나도 몰라", "나도 같은 상황" 이런 말 금지\n- 질문에 대한 상황을 더 구체적으로 추가 설명하거나, 다른 각도로 궁금증을 더 키워\n- 예시: 사료 안 먹는 강아지면 → "3일째인데 물은 먹음, 산책은 잘 하는데 밥만 거부함"\n- 읽는 사람이 댓글로 도움주고 싶게 만드는 방향으로\n\n공통: 짧고 자연스럽게. 반말. 이모지 없이. 마침표 없이.'
      : '';
    prompt = '댓글 1개만.\n주제: ' + (topic||'') + imgContext + '\n반말, 1~2문장, 이모지·해시태그 금지, 한국어만, 텍스트만 출력' + commentLureInstr + extra;
  } else {
    const extra = customUserPrompt ? '\n\n[사용자 지침]\n' + customUserPrompt : '';
    prompt = toneInstruction + fixedToneInstr + '\n\n주제: ' + (topic||'') + imgContext + extra + '\n\n위 형식으로 자연스러운 Threads 게시글 작성. 한국어만, 반말, 이모지·해시태그 없이, 텍스트만 출력.';
  }

  // OpenAI 먼저 시도, 쿼터 초과 시 Groq fallback
  async function tryGenerate(url, key, mdl, msgs) {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` },
      body: JSON.stringify({ model: mdl, messages: msgs, temperature: 0.82, max_tokens: 500 })
    });
    const data = await r.json();
    if (data.error) throw new Error(data.error.message);
    return (data.choices?.[0]?.message?.content || '').trim();
  }

  const msgs = [{ role: 'system', content: systemMsg }, { role: 'user', content: prompt }];
  let text = '';
  let usedFallback = false;

  try {
    text = await tryGenerate(apiUrl, apiKey, model, msgs);
  } catch(e) {
    const isQuotaErr = e.message.includes('quota') || e.message.includes('billing') || e.message.includes('insufficient') || e.message.includes('429');
    if (isQuotaErr && openaiKey && groqKey) {
      // OpenAI 쿼터 초과 → Groq fallback
      console.log('[GEN] OpenAI 쿼터 초과 - Groq fallback');
      usedFallback = true;
      // 관리자 알림 저장
      const settings = getSettings();
      settings._openaiQuotaAlert = { at: new Date().toISOString(), msg: e.message };
      saveSettings(settings);
      try {
        text = await tryGenerate('https://api.groq.com/openai/v1/chat/completions', groqKey, 'llama-3.3-70b-versatile', msgs);
      } catch(e2) { return res.status(500).json({ error: 'OpenAI 쿼터 초과 + Groq도 실패: ' + e2.message }); }
    } else {
      return res.status(500).json({ error: e.message });
    }
  }

  if (!text) return res.status(500).json({ error: '글 생성 실패' });

  // 외국어 제거
  if (/[\u3400-\u4DBF\u4E00-\u9FFF\u3040-\u309F\u30A0-\u30FF\uF900-\uFAFF]/.test(text)) {
    text = text.replace(/[\u3400-\u4DBF\u4E00-\u9FFF\u3040-\u309F\u30A0-\u30FF\uF900-\uFAFF]/g, '').replace(/  +/g, ' ').trim();
  }

  // 이모지 제거
  text = text.replace(/[\u{1F000}-\u{1FFFF}]|[\u{2600}-\u{27FF}]|[\u{2B00}-\u{2BFF}]/gu, '').trim();

  // 해시태그 제거
  text = text.replace(/#\S+/g, '').replace(/  +/g, ' ').trim();

  // 마침표 제거 (문장 끝 마침표만, 줄임표 ... 는 유지)
  text = text.replace(/\.(?!\.|\d)/g, '');

  // 빈줄 3개 이상만 정리 (AI 흐름 그대로 유지)
  text = text.replace(/\n{3,}/g, '\n\n').trim();

  res.json({ text, usedFallback });
});

// 이미지 분석 (Groq vision - 그대로 유지)
app.post('/api/analyze-image', auth, async (req, res) => {
  const { imageUrl } = req.body;
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'GROQ_API_KEY 없음' });
  if (!imageUrl) return res.status(400).json({ error: 'imageUrl 필요' });
  const visionModels = ['meta-llama/llama-4-scout-17b-16e-instruct', 'llava-v1.5-7b-4096-preview'];
  for (const model of visionModels) {
    try {
      const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        body: JSON.stringify({ model, messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: imageUrl } }, { type: 'text', text: '이 이미지를 한국어로 짧게 설명해줘. 1~2문장.' }] }], max_tokens: 150 })
      });
      const data = await r.json();
      if (data.error) { console.log(model, '실패:', data.error.message); continue; }
      return res.json({ desc: data.choices?.[0]?.message?.content || '' });
    } catch(e) { console.log(model, '에러:', e.message); }
  }
  res.json({ desc: '' });
});

// ══════════════════════════════════
//  Threads 발행
// ══════════════════════════════════

async function publishToThreads(accessToken, text, imageUrls = [], videoUrl = '') {
  let containerId;
  if (videoUrl) {
    const vc = validateMediaUrl(videoUrl);
    if (!vc.ok) throw new Error('영상 URL 보안 오류: ' + vc.reason);
  }
  for (const imgUrl of (imageUrls || [])) {
    const ic = validateMediaUrl(imgUrl);
    if (!ic.ok) throw new Error('이미지 URL 보안 오류: ' + ic.reason);
  }
  if (videoUrl) {
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'VIDEO', video_url: videoUrl, text, access_token: accessToken }) });
    const d = await r.json(); if (d.error) throw new Error(d.error.message);
    containerId = d.id;
    await new Promise(r => setTimeout(r, 30000));
  } else if (imageUrls.length === 0) {
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'TEXT', text, access_token: accessToken }) });
    const d = await r.json(); if (d.error) throw new Error(d.error.message);
    containerId = d.id;
  } else if (imageUrls.length === 1) {
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'IMAGE', image_url: imageUrls[0], text, access_token: accessToken }) });
    const d = await r.json(); if (d.error) throw new Error(d.error.message);
    containerId = d.id;
    await new Promise(r => setTimeout(r, 30000));
  } else {
    const childIds = [];
    for (const url of imageUrls) {
      const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'IMAGE', image_url: url, is_carousel_item: true, access_token: accessToken }) });
      const d = await r.json(); if (d.error) throw new Error(d.error.message);
      childIds.push(d.id);
    }
    await new Promise(r => setTimeout(r, 30000));
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'CAROUSEL', children: childIds.join(','), text, access_token: accessToken }) });
    const d = await r.json(); if (d.error) throw new Error(d.error.message);
    containerId = d.id;
  }
  await new Promise(r => setTimeout(r, 2000));
  const pub = await fetch(`https://graph.threads.net/v1.0/me/threads_publish`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ creation_id: containerId, access_token: accessToken }) });
  const pubData = await pub.json();
  if (pubData.error) throw new Error(pubData.error.message);
  return pubData.id;
}

async function replyToThread(accessToken, postId, commentText) {
  const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ media_type: 'TEXT', text: commentText, reply_to_id: postId, access_token: accessToken })
  });
  const d = await r.json(); if (d.error) throw new Error(d.error.message);
  const containerId = d.id;
  await new Promise(r => setTimeout(r, 2000));
  const pub = await fetch(`https://graph.threads.net/v1.0/me/threads_publish`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ creation_id: containerId, access_token: accessToken })
  });
  const pubData = await pub.json();
  if (pubData.error) throw new Error(pubData.error.message);
  return pubData.id;
}

app.post('/api/publish', auth, rateLimit(20, 60000), async (req, res) => {
  const { accountId, imageUrls, videoUrl } = req.body;
  const text = sanitize(req.body.text || '').slice(0, 500);
  const commentText = sanitize(req.body.commentText || '').slice(0, 500);
  if (!text) return res.status(400).json({ error: '글 내용 필요' });
  const accs = getAccounts(req.userId);
  const account = accs.find(a => a.id === accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  const user = users.find(u => u.id === req.userId);
  if (user?.plan === 'basic') return res.status(403).json({ error: '베이직 플랜은 발행 불가. 프로 이상으로 업그레이드해줘요.' });
  let dailyLimit = 5;
  if (user?.role === 'admin') dailyLimit = 9999;
  else if (user?.dailyPublishLimit) dailyLimit = user.dailyPublishLimit;
  else if (user?.plan === 'free') dailyLimit = 2;
  else dailyLimit = 3;
  const today = getTodayKey();
  const counts = getPublishCount(req.userId);
  if (dailyLimit < 9999 && (counts[today] || 0) >= dailyLimit) {
    return res.status(429).json({ error: `오늘 발행 한도(${dailyLimit}개) 초과.` });
  }
  if (videoUrl) { const vc = validateMediaUrl(videoUrl); if (!vc.ok) return res.status(400).json({ error: '영상 URL 오류: ' + vc.reason }); }
  if (Array.isArray(imageUrls)) {
    for (const u of imageUrls) { const ic = validateMediaUrl(u); if (!ic.ok) return res.status(400).json({ error: '이미지 URL 오류: ' + ic.reason }); }
  }
  try {
    const postId = await publishToThreads(account.accessToken, text, imageUrls || [], videoUrl || '');
    let commentId = null;
    if (commentText && commentText.trim()) {
      await new Promise(r => setTimeout(r, 3000));
      commentId = await replyToThread(account.accessToken, postId, commentText.trim());
    }
    const countData = getPublishCount(req.userId);
    countData[today] = (countData[today] || 0) + 1;
    savePublishCount(req.userId, countData);
    res.json({ ok: true, postId, commentId });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════
//  예약 발행
// ══════════════════════════════════

app.post('/api/schedule', auth, (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (user?.plan === 'basic') return res.status(403).json({ error: '베이직 플랜은 예약 발행 불가.' });
  const { accountId, text, imageUrls, videoUrl, scheduledAt, commentText } = req.body;
  const accs = getAccounts(req.userId);
  const account = accs.find(a => a.id === accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  const posts = getScheduled(req.userId);
  const post = { id: Date.now().toString(), accountId, accountName: account.name, text, type: req.body.type || 'post', imageUrls: imageUrls || [], videoUrl: videoUrl || '', commentText: commentText || '', replyToId: req.body.replyToId || null, scheduledAt, status: 'pending', createdAt: new Date().toISOString() };
  posts.push(post);
  saveScheduled(req.userId, posts);
  res.json(post);
});

app.get('/api/schedule', auth, (req, res) => res.json(getScheduled(req.userId)));

app.delete('/api/schedule/:id', auth, (req, res) => {
  let posts = getScheduled(req.userId);
  posts = posts.filter(p => p.id !== req.params.id);
  saveScheduled(req.userId, posts);
  res.json({ ok: true });
});

app.put('/api/schedule/:id', auth, (req, res) => {
  const posts = getScheduled(req.userId);
  const post = posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ error: '없음' });
  if (post.status === 'done') return res.status(400).json({ error: '이미 발행된 글은 수정 불가' });
  post.status = 'pending';
  if (req.body.text) post.text = req.body.text;
  if (req.body.scheduledAt) post.scheduledAt = req.body.scheduledAt;
  if (req.body.imageUrls !== undefined) post.imageUrls = req.body.imageUrls;
  if (req.body.videoUrl !== undefined) post.videoUrl = req.body.videoUrl;
  if (req.body.commentText !== undefined) post.commentText = req.body.commentText;
  saveScheduled(req.userId, posts);
  res.json(post);
});

app.post('/api/schedule/:id/publish-now', auth, async (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (user?.plan === 'basic') return res.status(403).json({ error: '베이직 플랜은 발행 불가.' });
  const posts = getScheduled(req.userId);
  const post = posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ error: '없음' });
  if (post.status === 'done') return res.status(400).json({ error: '이미 발행됨' });
  post.status = 'pending';
  const accs = getAccounts(req.userId);
  const account = accs.find(a => a.id === post.accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  try {
    if (post.type === 'comment') {
      const feedRes = await fetch(`https://graph.threads.net/v1.0/me/threads?fields=id&limit=1&access_token=${account.accessToken}`);
      const feedData = await feedRes.json();
      const latestPostId = feedData.data?.[0]?.id;
      if (!latestPostId) throw new Error('댓글 달 게시글 없음');
      await replyToThread(account.accessToken, post.replyToId || latestPostId, post.text);
      post.status = 'done';
      saveScheduled(req.userId, posts);
      return res.json({ ok: true });
    }
    let postId;
    try { postId = await publishToThreads(account.accessToken, post.text, post.imageUrls || [], post.videoUrl || ''); }
    catch(imgErr) { postId = await publishToThreads(account.accessToken, post.text, [], ''); }
    if (post.commentText && post.commentText.trim()) {
      await new Promise(r => setTimeout(r, 3000));
      await replyToThread(account.accessToken, postId, post.commentText.trim());
    }
    post.status = 'done';
    saveScheduled(req.userId, posts);
    res.json({ ok: true });
  } catch(e) {
    post.status = 'failed'; post.error = e.message;
    saveScheduled(req.userId, posts);
    res.status(500).json({ error: e.message });
  }
});

cron.schedule('* * * * *', async () => {
  const dataDir = `${DATA_ROOT}/users`;
  if (!fs.existsSync(dataDir)) return;
  const userDirs = fs.readdirSync(dataDir);
  for (const userId of userDirs) {
    const posts = getScheduled(userId);
    const now = new Date();
    const pending = posts.filter(p => p.status === 'pending' && new Date(p.scheduledAt) <= now);
    if (!pending.length) continue;
    const cronUser = users.find(u => u.id === userId);
    if (cronUser?.plan === 'basic') {
      pending.forEach(p => { p.status = 'failed'; p.error = '베이직 플랜 발행 불가'; });
      saveScheduled(userId, posts); continue;
    }
    let changed = false;
    for (const post of pending) {
      const accs = getAccounts(userId);
      const account = accs.find(a => a.id === post.accountId);
      if (!account) { post.status = 'failed'; changed = true; continue; }
      try {
        if (post.type === 'comment') {
          if (post.replyToId) {
            await replyToThread(account.accessToken, post.replyToId, post.text);
          } else {
            const feedRes = await fetch(`https://graph.threads.net/v1.0/me/threads?fields=id&limit=1&access_token=${account.accessToken}`);
            const feedData = await feedRes.json();
            const latestPostId = feedData.data?.[0]?.id;
            if (latestPostId) await replyToThread(account.accessToken, latestPostId, post.text);
            else throw new Error('최근 게시글 없음');
          }
        } else {
          let postId;
          try { postId = await publishToThreads(account.accessToken, post.text, post.imageUrls || [], post.videoUrl || ''); }
          catch(imgErr) { postId = await publishToThreads(account.accessToken, post.text, [], ''); }
          if (post.commentText && post.commentText.trim()) {
            await new Promise(r => setTimeout(r, 3000));
            await replyToThread(account.accessToken, postId, post.commentText.trim());
          }
        }
        post.status = 'done'; changed = true;
      } catch(e) { post.status = 'failed'; post.error = e.message; changed = true; }
    }
    if (changed) saveScheduled(userId, posts);
  }
});

// ══════════════════════════════════
//  인사이트 / 키워드
// ══════════════════════════════════

app.get('/api/insights/:accountId', auth, async (req, res) => {
  const accs = getAccounts(req.userId);
  const account = accs.find(a => a.id === req.params.accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  try {
    const r = await fetch(`https://graph.threads.net/v1.0/me?fields=id,username&access_token=${account.accessToken}`);
    const data = await r.json();
    if (data.error) return res.status(400).json({ error: data.error.message || JSON.stringify(data.error) });
    res.json({ id: data.id || '-', username: data.username || '-' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/keywords', auth, async (req, res) => {
  const results = { google: [], naver: [], threads: [] };
  try {
    const r = await fetch('https://trends.google.co.kr/trending/rss?geo=KR', { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const xml = await r.text();
    const titles = [...xml.matchAll(/<title><!\[CDATA\[(.+?)\]\]><\/title>/g)].slice(1, 11);
    const traffics = [...xml.matchAll(/<ht:approx_traffic>([^<]+)<\/ht:approx_traffic>/g)];
    results.google = titles.map((m, i) => ({ text: m[1], traffic: traffics[i]?.[1] || '' }));
  } catch(e) {}
  try {
    const r = await fetch('https://signal.bz/news/realtime', { headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0.0.0', 'Accept-Language': 'ko-KR,ko;q=0.9' } });
    const html = await r.text();
    const matches = [...html.matchAll(/class="tit"[^>]*>\s*([^<]{2,20})\s*<\/[a-z]/g)];
    results.naver = [...new Set(matches.map(m => m[1].trim()).filter(k => k.length >= 2))].slice(0, 10).map(t => ({ text: t }));
  } catch(e) {}
  try {
    const r = await fetch('https://trends.google.co.kr/trending/rss?geo=KR&hours=4', { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const xml = await r.text();
    results.threads = [...xml.matchAll(/<title><!\[CDATA\[(.+?)\]\]><\/title>/g)].slice(1, 6).map(m => ({ text: m[1], isNew: true }));
  } catch(e) {}
  res.json(results);
});

// ══════════════════════════════════
//  이미지/영상 업로드 (Cloudinary)
// ══════════════════════════════════

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });
const videoStorage = multer.diskStorage({
  destination: function(req, file, cb) { cb(null, '/tmp'); },
  filename: function(req, file, cb) { cb(null, 'vid_' + Date.now() + '.mp4'); }
});
const videoUpload = multer({ storage: videoStorage, limits: { fileSize: 100 * 1024 * 1024 } });

async function uploadToCloudinary(buffer, filename, resourceType = 'image') {
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const apiKey = process.env.CLOUDINARY_API_KEY;
  const apiSecret = process.env.CLOUDINARY_API_SECRET;
  if (!cloudName || !apiKey || !apiSecret) throw new Error('CLOUDINARY 환경변수 없음');
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = crypto.createHash('sha256').update(`access_mode=public&timestamp=${timestamp}&type=upload${apiSecret}`).digest('hex');
  const boundary = '----FormBoundary' + crypto.randomBytes(8).toString('hex');
  const crlf = '\r\n';
  const ext = filename.split('.').pop()?.toLowerCase() || (resourceType === 'video' ? 'mp4' : 'jpg');
  const mimeType = resourceType === 'video' ? 'video/mp4' : `image/${ext === 'jpg' ? 'jpeg' : ext}`;
  let body = Buffer.alloc(0);
  const addField = (name, value) => {
    body = Buffer.concat([body, Buffer.from(`--${boundary}${crlf}Content-Disposition: form-data; name="${name}"${crlf}${crlf}${value}${crlf}`)]);
  };
  const addFile = (name, fname, mime, data) => {
    body = Buffer.concat([body, Buffer.from(`--${boundary}${crlf}Content-Disposition: form-data; name="${name}"; filename="${fname}"${crlf}Content-Type: ${mime}${crlf}${crlf}`), data, Buffer.from(crlf)]);
  };
  addField('api_key', apiKey); addField('timestamp', String(timestamp));
  addField('signature', signature); addField('type', 'upload'); addField('access_mode', 'public');
  addFile('file', filename, mimeType, buffer);
  body = Buffer.concat([body, Buffer.from(`--${boundary}--${crlf}`)]);
  const r = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/${resourceType}/upload`, {
    method: 'POST', headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` }, body
  });
  const d = await r.json();
  if (d.error) throw new Error(d.error.message);
  return d.secure_url;
}

app.post('/api/upload', auth, upload.array('images', 10), async (req, res) => {
  try {
    const urls = [];
    for (const file of req.files) { urls.push(await uploadToCloudinary(file.buffer, file.originalname, 'image')); }
    res.json({ urls });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/upload-video', auth, videoUpload.single('video'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: '영상 없음' });
    const fileBuffer = fs.readFileSync(req.file.path);
    const url = await uploadToCloudinary(fileBuffer, req.file.originalname || 'video.mp4', 'video');
    try { fs.unlinkSync(req.file.path); } catch(e2) {}
    res.json({ url });
  } catch(e) {
    if (req.file?.path) { try { fs.unlinkSync(req.file.path); } catch(e2) {} }
    res.status(500).json({ error: e.message });
  }
});

// ==============================
//  쿠팡 파트너스 API
// ==============================

async function getCoupangLink(keyword) {
  const accessKey = process.env.COUPANG_ACCESS_KEY;
  const secretKey = process.env.COUPANG_SECRET_KEY;
  if (!accessKey || !secretKey) throw new Error('COUPANG API 키 없음');
  const method = 'GET';
  const path = `/v2/providers/affiliate_open_api/apis/openapi/products/search?keyword=${encodeURIComponent(keyword)}&limit=5`;
  const datetime = new Date().toISOString().replace(/[:\-]|\..{3}/g, '').slice(0, 15) + 'Z';
  const message = datetime + method + path;
  const signature = crypto.createHmac('sha256', secretKey).update(message).digest('hex');
  const authorization = `CEA algorithm=HmacSHA256, access-key=${accessKey}, signed-date=${datetime}, signature=${signature}`;
  const r = await fetch(`https://api-gateway.coupang.com${path}`, { method, headers: { 'Authorization': authorization, 'Content-Type': 'application/json' } });
  const d = await r.json();
  if (d.rCode !== '0' && d.rCode !== 0) throw new Error('쿠팡 API 오류: ' + d.rMessage);
  const products = d.data?.productData || [];
  if (!products.length) throw new Error('검색 결과 없음');
  return products[0].productUrl || products[0].shortenUrl || '';
}

// ==============================
//  자동 스케줄러
// ==============================

function getAutoSchedules(userId) { return loadJSON(`${userDir(userId)}/auto_schedules.json`, []); }
function saveAutoSchedules(userId, data) { saveJSON(`${userDir(userId)}/auto_schedules.json`, data); }

app.get('/api/auto-schedule', auth, (req, res) => {
  res.json(getAutoSchedules(req.userId));
});

app.post('/api/auto-schedule', auth, (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (user?.role !== 'admin') {
    const settings2 = getSettings();
    if (!settings2.autoSchedulerEnabled) return res.status(403).json({ error: 'disabled' });
    if (user?.plan !== 'pro') return res.status(403).json({ error: 'pro_only' });
  }
  const { accountId, topics, tone, publishTime, commentTone, commentDelay, enabled, toneExample, tonePrompt } = req.body;
  const accs = getAccounts(req.userId);
  const account = accs.find(a => a.id === accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  const schedules = getAutoSchedules(req.userId);
  if (req.body.id) {
    const existing = schedules.find(s => s.id === req.body.id);
    if (existing) {
      Object.assign(existing, { accountId, accountName: account.name, topics: topics || [], tone, publishTime, commentTone: commentTone || '', commentDelay: commentDelay || 10, toneExample: toneExample || '', tonePrompt: tonePrompt || '', enabled: enabled !== false });
      saveAutoSchedules(req.userId, schedules);
      return res.json(existing);
    }
  }
  const today = getTodayKey();
  const todayCount = schedules.filter(s => s.accountId === accountId && s.createdDate === today).length;
  const user2 = users.find(u => u.id === req.userId);
  if (user2?.role !== 'admin' && todayCount >= 5) return res.status(429).json({ error: '계정당 하루 최대 5개' });
  const item = { id: Date.now().toString(), accountId, accountName: account.name, topics: Array.isArray(topics) ? topics : [], tone, publishTime, commentTone: commentTone || '', commentDelay: commentDelay || 10, toneExample: toneExample || '', tonePrompt: tonePrompt || '', enabled: enabled !== false, createdDate: today, createdAt: new Date().toISOString() };
  schedules.push(item);
  saveAutoSchedules(req.userId, schedules);
  res.json(item);
});

app.put('/api/auto-schedule/:id/topics', auth, (req, res) => {
  const schedules = getAutoSchedules(req.userId);
  const sched = schedules.find(s => s.id === req.params.id);
  if (!sched) return res.status(404).json({ error: '없음' });
  sched.topics = req.body.topics;
  saveAutoSchedules(req.userId, schedules);
  res.json(sched);
});

app.put('/api/auto-schedule/:id', auth, (req, res) => {
  const schedules = getAutoSchedules(req.userId);
  const sched = schedules.find(s => s.id === req.params.id);
  if (!sched) return res.status(404).json({ error: '없음' });
  if (req.body.publishTime) sched.publishTime = req.body.publishTime;
  if (req.body.tone) sched.tone = req.body.tone;
  if (req.body.topics) sched.topics = req.body.topics;
  if (req.body.toneExample !== undefined) sched.toneExample = req.body.toneExample;
  if (req.body.tonePrompt !== undefined) sched.tonePrompt = req.body.tonePrompt;
  if (req.body.enabled !== undefined) sched.enabled = req.body.enabled;
  saveAutoSchedules(req.userId, schedules);
  res.json(sched);
});

app.delete('/api/auto-schedule/:id', auth, (req, res) => {
  let schedules = getAutoSchedules(req.userId);
  schedules = schedules.filter(s => s.id !== req.params.id);
  saveAutoSchedules(req.userId, schedules);
  res.json({ ok: true });
});

app.put('/api/settings/auto-scheduler', adminAuth, (req, res) => {
  const settings = getSettings();
  settings.autoSchedulerEnabled = !!req.body.enabled;
  saveSettings(settings);
  res.json({ ok: true, enabled: settings.autoSchedulerEnabled });
});

function getAutoLogs(userId) { return loadJSON(`${userDir(userId)}/auto_logs.json`, []); }
function saveAutoLog(userId, log) {
  const logs = getAutoLogs(userId);
  logs.unshift(log);
  if (logs.length > 20) logs.splice(20);
  saveJSON(`${userDir(userId)}/auto_logs.json`, logs);
}

app.get('/api/auto-logs', auth, (req, res) => {
  res.json(getAutoLogs(req.userId).slice(0, 5));
});

// ── 매일 자정 만료 처리 cron (KST 00:00 = UTC 15:00) ──
cron.schedule('0 15 * * *', () => {
  const now = new Date();
  let changed = false;
  users.forEach(u => {
    if (u.role === 'admin' || !u.expiresAt) return;
    if (new Date(u.expiresAt) < now && u.status === 'approved') {
      u.status = 'suspended'; u._expiredAt = now.toISOString(); changed = true;
      console.log(`[EXPIRE] ${u.nickname} 만료로 정지`);
    }
  });
  if (changed) saveJSON(`${DATA_ROOT}/users.json`, users);
});

// 자동 스케줄러 cron (매 분마다) - OpenAI 사용
cron.schedule('* * * * *', async () => {
  const settings = getSettings();
  const now = new Date();
  const kstNow = new Date(now.getTime() + 9 * 60 * 60 * 1000);
  const currentTime = kstNow.getUTCHours().toString().padStart(2,'0') + ':' + kstNow.getUTCMinutes().toString().padStart(2,'0');
  const dataDir = `${DATA_ROOT}/users`;
  if (!fs.existsSync(dataDir)) return;
  const userDirs = fs.readdirSync(dataDir);
  for (const userId of userDirs) {
    const user = users.find(u => u.id === userId);
    if (!user) continue;
    if (user.role !== 'admin') {
      if (!settings.autoSchedulerEnabled) continue;
      if (user.plan !== 'pro') continue;
    }
    const autoSchedules = getAutoSchedules(userId);
    const maxAuto = user.role === 'admin' ? 999 : 5;
    const toRun = autoSchedules.filter(s => s.enabled && s.publishTime === currentTime).slice(0, maxAuto);
    if (!toRun.length) continue;
    const autoCountToday = {};
    for (const sched of toRun) {
      const accs = getAccounts(userId);
      const account = accs.find(a => a.id === sched.accountId);
      if (!account) continue;
      if (user.role !== 'admin') {
        const accCount = autoCountToday[sched.accountId] || 0;
        if (accCount >= 5) continue;
        autoCountToday[sched.accountId] = accCount + 1;
      }
      try {
        const openaiKey = process.env.OPENAI_API_KEY;
        const groqKey = process.env.GROQ_API_KEY;
        const apiKey = openaiKey || groqKey;
        if (!apiKey) continue;
        const apiUrl = openaiKey ? 'https://api.openai.com/v1/chat/completions' : 'https://api.groq.com/openai/v1/chat/completions';
        const model = openaiKey ? 'gpt-4o-mini' : 'llama-3.3-70b-versatile';

        const toneDesc = {
          '리스트형': '리스트형. 핵심만. 번호 나열. 댓글 유도.',
          '정보성': '정보형. 알게 된 척. 핵심 요약. 댓글 유도.',
          '리뷰형': '리뷰형. 실제 경험처럼. 솔직하게.',
          '일상': '일상형. 말하듯. 짧고 자연스럽게.',
          '공감형': '공감형. 짧게. 공감 유도.',
          '스토리형': '스토리형. 짧은 일화. 뻔한 결말 금지.',
          '쿠팡/홍보': '일상 SNS. 광고티 없이. 1~2줄. 구매유도 금지.',
          '쿠팡': '일상 SNS. 1~2줄. 경험담처럼. 구매유도 금지.'
        };

        let selectedTopic = sched.topic || '';
        if (Array.isArray(sched.topics) && sched.topics.length > 0) {
          const active = sched.topics.filter(t => t.active !== false);
          if (active.length > 0) selectedTopic = active[Math.floor(Math.random() * active.length)].text;
        }
        if (!selectedTopic) continue;

        const toneExtraInstr = sched.toneExample ? '\n\n[말투 예시 - 반드시 이 스타일로]\n' + sched.toneExample : '';
        const promptExtraInstr = sched.tonePrompt ? '\n\n[추가 지침]\n' + sched.tonePrompt : '';
        const systemMsg = `너는 SNS에 글 올리는 평범한 한국인이다. AI가 쓴 것처럼 보이면 절대 안 된다.
- 한국어만. 한자·일본어·영어 절대 금지 (주제에 포함된 영어 단어 제외).
- 진짜 사람이 폰으로 빠르게 치는 것처럼 써.
- 문장 끝에 마침표(.) 절대 금지.
- 완성된 문장보다 말하다 끊긴 느낌이 자연스러움.
- "~했어" "~하더라" "~인 것 같음" "~임" "~네" 같은 말투.
- 이모지 금지. 반말만. 제품명 직접 언급 금지.
- 리스트형 외 번호·불릿 금지.
- 내용이 이어지는 문장은 줄바꿈만. 내용 전환될 때만 빈 줄 1개. 흐름 끊기지 않게.
- 텍스트만 출력.` + toneExtraInstr + promptExtraInstr;

        const prompt = (toneDesc[sched.tone] || toneDesc['일상']) + '\n\n주제: ' + selectedTopic + '\n\n자연스러운 Threads 게시글. 한국어만. 이모지 없이. 텍스트만 출력.';

        let text = '';
        try {
          const r = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
            body: JSON.stringify({ model, messages: [{ role: 'system', content: systemMsg }, { role: 'user', content: prompt }], temperature: 0.82, max_tokens: 400 })
          });
          const data = await r.json();
          if (data.error) throw new Error(data.error.message);
          text = (data.choices?.[0]?.message?.content || '').trim();
        } catch(genErr) {
          const isQuota = genErr.message.includes('quota') || genErr.message.includes('billing') || genErr.message.includes('insufficient');
          if (isQuota && openaiKey && groqKey) {
            console.log('[AUTO] OpenAI 쿼터 초과 - Groq fallback');
            const settings2 = getSettings();
            settings2._openaiQuotaAlert = { at: new Date().toISOString(), msg: genErr.message };
            saveSettings(settings2);
            const rf = await fetch('https://api.groq.com/openai/v1/chat/completions', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${groqKey}` },
              body: JSON.stringify({ model: 'llama-3.3-70b-versatile', messages: [{ role: 'system', content: systemMsg }, { role: 'user', content: prompt }], temperature: 0.82, max_tokens: 400 })
            });
            const df = await rf.json();
            if (df.error) throw new Error(df.error.message);
            text = (df.choices?.[0]?.message?.content || '').trim();
          } else { throw genErr; }
        }
        if (!text) continue;

        const postId = await publishToThreads(account.accessToken, text, [], '');
        saveAutoLog(userId, { id: postId, accountName: account.name, topic: selectedTopic, tone: sched.tone, postText: text, status: 'success', publishedAt: new Date().toISOString() });

        if (sched.commentTone) {
          const delay = sched.commentDelay || 10;
          const commentAt = new Date(Date.now() + delay * 60 * 1000).toISOString();
          const commentPrompt = '댓글 1개.\n주제: ' + selectedTopic + '\n반말, 1~2문장, 이모지 금지, 한국어만, 텍스트만.';
          const rc = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
            body: JSON.stringify({ model, messages: [{ role: 'system', content: systemMsg }, { role: 'user', content: commentPrompt }], temperature: 0.82, max_tokens: 150 })
          });
          const dc = await rc.json();
          const commentText = (dc.choices?.[0]?.message?.content || '').trim();
          if (commentText) {
            const posts = getScheduled(userId);
            posts.push({ id: Date.now().toString(), accountId: sched.accountId, accountName: account.name, text: commentText, type: 'comment', imageUrls: [], commentText: '', scheduledAt: commentAt, status: 'pending', createdAt: new Date().toISOString() });
            saveScheduled(userId, posts);
          }
        }
      } catch(e) {
        console.log(`[AUTO] 실패:`, e.message);
        saveAutoLog(userId, { id: Date.now().toString(), accountName: account?.name || '-', topic: sched.topic || '-', tone: sched.tone, status: 'failed', error: e.message, publishedAt: new Date().toISOString() });
      }
    }
  }
});

sessions = loadSessions();
console.log(`세션 복원: ${Object.keys(sessions).length}개`);

app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: '서버 오류. 잠시 후 다시 시도해줘.' });
});

app.use((req, res) => {
  res.status(404).json({ error: '없는 경로야' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`서버 실행중: ${PORT}`));
