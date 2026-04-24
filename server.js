const express = require('express');
const cors = require('cors');
const multer = require('multer');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
const cron = require('node-cron');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

// ── 보안 설정 ──
const ALLOWED_ORIGINS = process.env.BASE_URL
  ? [process.env.BASE_URL, 'https://zhei-la.github.io']
  : ['https://zhei-la.github.io'];
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
  // 마지막 활동 기준으로 3일 갱신 (sliding session)
  s.expiresAt = Date.now() + SESSION_TTL;
  saveSessions();
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
    if (req.user?.role !== 'admin' || req.user?.nickname !== ADMIN_NICKNAME) {
      return res.status(403).json({ error: '관리자만 가능' });
    }
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
  if (user.expiresAt && new Date() > new Date(user.expiresAt) && user.role !== 'admin' && user.plan !== 'basic') {
    // 만료 시 정지가 아닌 베이직으로 자동 강등 후 로그인 허용
    user.plan = 'basic';
    user.expiresAt = null;
    user.accountLimit = 0;
    user.dailyPublishLimit = 0;
    user._downgradedAt = new Date().toISOString();
    saveJSON(`${DATA_ROOT}/users.json`, users);
    console.log(`[LOGIN-EXPIRE] ${user.nickname} 만료 → 베이직 강등`);
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

const ADMIN_NICKNAME = 'dud2587';

app.get('/api/auth/me', auth, (req, res) => {
  const u = req.user;
  // 닉네임이 관리자가 아닌데 role이 admin이면 강제 보정
  const safeRole = u.nickname === ADMIN_NICKNAME ? u.role : 'user';
  const today = getTodayKey();
  const counts = getPublishCount(u.id);
  const genUsed = counts['gen_' + today] || 0;
  const genLimit = u.plan === 'free' ? 100 : 200;
  res.json({
    id: u.id, nickname: u.nickname, name: u.name || '', role: safeRole,
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
  // 쿠팡 파트너스 설정
  if (req.body.coupangPartnersEnabled !== undefined) settings.coupangPartnersEnabled = !!req.body.coupangPartnersEnabled;
  if (req.body.coupangPartnerAccessKey !== undefined) settings.coupangPartnerAccessKey = req.body.coupangPartnerAccessKey;
  if (req.body.coupangPartnerSecretKey !== undefined) settings.coupangPartnerSecretKey = req.body.coupangPartnerSecretKey;
  if (req.body.coupangPartnerSubIdDefault !== undefined) settings.coupangPartnerSubIdDefault = req.body.coupangPartnerSubIdDefault;
  if (req.body.coupangDeepLinkMode !== undefined) settings.coupangDeepLinkMode = req.body.coupangDeepLinkMode;
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

app.get('/api/admin/stats', adminAuth, (req, res) => {
  const today = getTodayKey();
  const last7 = Array.from({length: 7}, (_, i) => {
    const d = new Date(); d.setDate(d.getDate() - i);
    return d.toISOString().slice(0, 10);
  }).reverse();

  const nonAdmins = users.filter(u => u.role !== 'admin');

  const result = nonAdmins.map(u => {
    const counts = getPublishCount(u.id);
    const genToday = counts['gen_' + today] || 0;
    const pubToday = counts[today] || 0;
    const totalPub = Object.keys(counts).filter(k => !k.startsWith('gen_')).reduce((s, k) => s + (counts[k] || 0), 0);
    const totalGen = Object.keys(counts).filter(k => k.startsWith('gen_')).reduce((s, k) => s + (counts[k] || 0), 0);
    const daily = last7.map(date => ({ date, gen: counts['gen_' + date] || 0, pub: counts[date] || 0 }));
    return { nickname: u.nickname, name: u.name || '-', plan: u.plan || 'free', genToday, pubToday, totalGen, totalPub, daily };
  })
  .filter(u => u.totalGen > 0 || u.totalPub > 0)
  .sort((a, b) => b.totalGen - a.totalGen);

  // 요약 통계
  const joinedToday = nonAdmins.filter(u => u.createdAt && u.createdAt.slice(0, 10) === today).length;
  const visitToday = result.filter(u => u.genToday > 0 || u.pubToday > 0).length;
  const genToday = result.reduce((s, u) => s + u.genToday, 0);
  const pubToday = result.reduce((s, u) => s + u.pubToday, 0);
  const totalGenAll = result.reduce((s, u) => s + u.totalGen, 0);
  const totalPubAll = result.reduce((s, u) => s + u.totalPub, 0);

  res.json({
    result, last7,
    summary: {
      totalUsers: nonAdmins.length,
      visitToday, pubToday, joinedToday,
      genToday, totalGenAll, totalPubAll
    }
  });
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
  // 관리자 본인 플랜 변경은 허용 (다른 관리자 변경은 불가)
  if (user.role === 'admin' && user.id !== req.userId) return res.status(400).json({ error: '관리자 상태 변경 불가' });
  user.status = req.body.status;
  if (req.body.status === 'approved' && !user.approvedAt) {
    user.approvedAt = new Date().toISOString();
    user.plan = req.body.plan || 'basic';
    if (req.body.plan === 'basic' || !req.body.plan) {
      // 베이직은 영구 - expiresAt 없음
      user.accountLimit = 0; user.dailyPublishLimit = 0; user.expiresAt = null;
    } else if (req.body.plan === 'free') {
      const days = req.body.planDays || 7;
      user.expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
      user.accountLimit = 2; user.dailyPublishLimit = 5;
    } else if (req.body.plan === 'pro') {
      const days = req.body.planDays || 30;
      user.expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
      user.accountLimit = 6; user.dailyPublishLimit = 5;
    } else if (req.body.plan === 'legacy') {
      const days = req.body.planDays || 30;
      user.expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
      user.accountLimit = 2; user.dailyPublishLimit = 3;
    }
  }
  if (req.body.changePlan) {
    user.plan = req.body.plan;
    if (req.body.plan === 'basic') {
      user.accountLimit = 0; user.dailyPublishLimit = 0; user.expiresAt = null; // 베이직 영구
    } else if (req.body.plan === 'legacy') {
      user.accountLimit = 2; user.dailyPublishLimit = 3;
      const base = user.expiresAt && new Date(user.expiresAt) > new Date() ? new Date(user.expiresAt) : new Date();
      user.expiresAt = new Date(base.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
    } else if (req.body.plan === 'pro') {
      user.accountLimit = 6; user.dailyPublishLimit = 5;
      const base = user.expiresAt && new Date(user.expiresAt) > new Date() ? new Date(user.expiresAt) : new Date();
      user.expiresAt = new Date(base.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
    }
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
    if (req.body.setPlan === 'basic') {
      user.accountLimit = 0; user.dailyPublishLimit = 0;
      user.expiresAt = null; // 베이직은 기간 없음
    } else if (req.body.setPlan === 'legacy') { user.accountLimit = 2; user.dailyPublishLimit = 3; }
    else if (req.body.setPlan === 'pro') {
      user.accountLimit = 6; user.dailyPublishLimit = 5;
      const planDays = req.body.planDays || 30;
      const base2 = user.expiresAt && new Date(user.expiresAt) > new Date() ? new Date(user.expiresAt) : new Date();
      user.expiresAt = new Date(base2.getTime() + planDays * 24 * 60 * 60 * 1000).toISOString();
    }
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
      user.status = 'approved'; // 어떤 플랜이든 승인 시 status 보장
      if (reqPlan === 'basic') { user.plan = 'basic'; user.accountLimit = 0; user.dailyPublishLimit = 0; user.expiresAt = null; }
      else if (reqPlan === 'pro') { user.plan = 'pro'; user.accountLimit = 6; user.dailyPublishLimit = 5; user.expiresAt = new Date(Date.now() + 30 * 86400000).toISOString(); }
      else if (reqPlan === 'pro90') { user.plan = 'pro'; user.accountLimit = 6; user.dailyPublishLimit = 5; user.expiresAt = new Date(Date.now() + 90 * 86400000).toISOString(); }
      else if (reqPlan === 'free') { user.plan = 'free'; user.accountLimit = 2; user.dailyPublishLimit = 5; user.expiresAt = new Date(Date.now() + 7 * 86400000).toISOString(); }
    }
    user.planChangeRequest = null;
  }
  saveJSON(`${DATA_ROOT}/users.json`, users);
  res.json({ ok: true });
});

// ══════════════════════════════════
//  Threads 계정 관리
// ══════════════════════════════════

// ===== 네이버 계정 API =====
const naverAccsFile = () => `${DATA_ROOT}/naver_accounts.json`;
function getNaverAccs(userId) {
  const all = loadJSON(naverAccsFile(), []);
  return all.filter(a => a.userId_app === userId);
}

app.get('/api/naver/accounts', auth, (req, res) => {
  const accs = getNaverAccs(req.userId);
  res.json(accs.map(a => ({ userId: a.userId, clientId: a.clientId ? a.clientId.slice(0,4)+'***' : '', category: a.category || '' })));
});

app.post('/api/naver/accounts', auth, (req, res) => {
  const { userId, clientId, clientSecret, category } = req.body;
  if (!userId) return res.status(400).json({ error: '네이버 아이디 필요' });
  const all = loadJSON(naverAccsFile(), []);
  const existing = all.findIndex(a => a.userId_app === req.userId && a.userId === userId);
  const acc = { userId_app: req.userId, userId, clientId: clientId||'', clientSecret: clientSecret||'', category: category||'', createdAt: new Date().toISOString() };
  if (existing >= 0) all[existing] = acc;
  else all.push(acc);
  saveJSON(naverAccsFile(), all);
  res.json({ ok: true });
});

app.delete('/api/naver/accounts/:userId', auth, (req, res) => {
  let all = loadJSON(naverAccsFile(), []);
  all = all.filter(a => !(a.userId_app === req.userId && a.userId === req.params.userId));
  saveJSON(naverAccsFile(), all);
  res.json({ ok: true });
});

app.post('/api/naver/test', auth, async (req, res) => {
  const { userId } = req.body;
  const all = loadJSON(naverAccsFile(), []);
  const acc = all.find(a => a.userId_app === req.userId && a.userId === userId);
  if (!acc) return res.status(404).json({ error: '등록된 계정 없음' });
  // 네이버 오픈API로 블로그 정보 조회 테스트
  if (acc.clientId && acc.clientSecret) {
    try {
      const r = await fetch(`https://openapi.naver.com/v1/me`, {
        headers: { 'X-Naver-Client-Id': acc.clientId, 'X-Naver-Client-Secret': acc.clientSecret }
      });
      if (r.status === 401) return res.status(400).json({ error: 'Client ID/Secret 인증 실패' });
      return res.json({ ok: true, method: 'openapi' });
    } catch(e) {
      return res.status(400).json({ error: '연결 실패: ' + e.message });
    }
  }
  res.json({ ok: true, method: 'saved', note: 'API 키 없이 저장만 됨' });
});

// 네이버 블로그 발행 API (오픈API 방식)
app.post('/api/naver/publish', auth, async (req, res) => {
  const { naverUserId, title, content: blogContent, tags, category } = req.body;
  if (!naverUserId || !title || !blogContent) return res.status(400).json({ error: '필수 항목 누락' });
  const all = loadJSON(naverAccsFile(), []);
  const acc = all.find(a => a.userId_app === req.userId && a.userId === naverUserId);
  if (!acc) return res.status(404).json({ error: '등록된 네이버 계정 없음' });
  if (!acc.clientId || !acc.clientSecret) return res.status(400).json({ error: '오픈API Client ID/Secret 필요' });
  try {
    const params = new URLSearchParams();
    params.append('title', title);
    params.append('contents', blogContent);
    if (tags) params.append('tags', Array.isArray(tags) ? tags.join(',') : tags);
    if (category || acc.category) params.append('categoryNo', category || acc.category);
    const r = await fetch('https://openapi.naver.com/blog/post.json', {
      method: 'POST',
      headers: {
        'X-Naver-Client-Id': acc.clientId,
        'X-Naver-Client-Secret': acc.clientSecret,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: params.toString()
    });
    const data = await r.json();
    if (data.errorCode) return res.status(400).json({ error: data.errorMessage || '발행 실패' });
    res.json({ ok: true, postId: data.postId, url: data.url });
  } catch(e) {
    res.status(500).json({ error: '발행 실패: ' + e.message });

// 네이버 발행 로그 조회
app.get('/api/naver/logs', auth, (req, res) => {
  try {
    const logsFile = `${DATA_ROOT}/naver_publish_logs.json`;
    const all = loadJSON(logsFile, []);
    const myLogs = all.filter(l => l.userId_app === req.userId).slice(-50).reverse();
    res.json(myLogs);
  } catch(e) { res.json([]); }
});

  }
});

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
  const postMode = req.body.postMode || 'normal'; // 'normal' or 'agro'
  const fixedTones = Array.isArray(req.body.fixedTones) ? req.body.fixedTones : [];
  // 프론트에서 직접 빌드한 프롬프트가 있으면 우선 사용
  const builtPrompt = req.body.customCommentPrompt ? String(req.body.customCommentPrompt).slice(0, 3000) : '';
  const hasCoupang = fixedTones.includes('쿠팡/홍보');
  const hasCommentLure = fixedTones.includes('댓글유도형');
  const isChic = fixedTones.includes('시크하게');
  const hasBad = fixedTones.includes('하소연');
  const hasGood = fixedTones.includes('기분좋음');
  const hasShahriTone = fixedTones.includes('스하리말투');
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
  if (hasBad) {
    fixedToneInstr += `\n\n━━━ 하소연 모드 ━━━
- 속상하거나 짜증나거나 허무한 감정을 솔직하게 털어놓는 글
- 아래 방향 중 하나를 랜덤으로 골라서 매번 다르게:
  1. 아무도 스하리 안 해줌 — 혼자 하는 느낌
  2. 뒷삭 당한 서운함
  3. 팔로워가 도무지 안 늘어나는 현실
  4. 반하리 기다렸는데 안 옴
  5. 스하리 문화 자체에 살짝 지침
  6. 열심히 했는데 반응 없는 허무함
  7. 뒷삭하는 사람 이해 안 됨
  8. 혼자 열심히 하는 게 바보같은 느낌
  9. 오늘따라 스레드 하기 싫은 날
  10. 맞팔인 줄 알았는데 아닌 경우
- 과장하지 말고 있는 그대로 툭 뱉는 느낌
- 극적으로 슬픈 척 금지 — 담담하게`;
  }
  if (hasGood) {
    fixedToneInstr += `\n\n━━━ 기분좋음 모드 ━━━
- 오늘 기분 좋은 일이 있었던 것처럼 가볍게 자랑하는 글
- 아래 방향 중 하나를 랜덤으로 골라서 매번 다르게:
  1. 팔로워가 갑자기 훅 늘었음
  2. 스하리 해줬는데 반하리까지 빠르게 옴
  3. 오늘 반응이 유독 좋은 날
  4. 좋은 스치니 만난 기분
  5. 뒷삭 없이 팔로워 유지되는 게 뿌듯함
  6. 댓글이나 반응이 많이 달린 날
  7. 스하리 먼저 갔는데 결과가 좋았음
  8. 팔로워 목표치에 가까워지는 느낌
  9. 오늘 스레드 하길 잘했다는 기분
  10. 좋은 스치니랑 이어진 것 같아서 기분 좋음
- 과하게 흥분하거나 감사하다는 척 금지
- 슬쩍 기분 좋은 티 내는 정도, 부담 없이 가볍게`;
  }

  const chicRule = isChic ? `

━━━ 시크 모드 (최우선 적용) ━━━
- 쿨한 척 금지 — 시크한 거랑 멋있는 척은 다름
- 감정 과잉 금지 — 흥분하거나 감탄하는 표현 쓰지 말 것
- 담백하게 — 그냥 일어난 일, 느낀 거 그대로 씀
- 리액션 유도 금지 — "어떻게 생각해?" 같은 거 붙이지 말 것
- 건조하되 자연스럽게 — 억지로 무관심한 척하는 것도 금지
- 예시 느낌: "오늘 그냥 이랬음", "별로였음", "뭐 그럼"
` : '';



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
- 게시글 텍스트만. 설명·주석·따옴표 없이.

${chicRule}`;

  const isShahri = (topic || '').includes('스하리');

  let prompt = '';
  if (isShahri && type !== 'comment') {
    // 스하리 말투 칩 선택 시 부정/긍정 반반 랜덤
    const shahriMood = hasShahriTone
      ? (Math.random() < 0.5 ? 'negative' : 'positive')
      : null;

    const shahriNegative = `[부정/하소연 방향 - 이 중 하나 랜덤 선택]
1. 아무도 스하리 안 해줘서 서운한 느낌
2. 스하리 했는데 뒷삭 당해서 억울한 느낌
3. 반하리 안 해주는 사람에 대한 섭섭함
4. 팔로워가 안 늘어서 현타 오는 느낌
5. 스하리 먼저 했는데 무반응이라 뻘쭘한 느낌
6. 뒷삭할 거면 스하리하지 말라고 경고하는 느낌
7. 혼자 스레드 하는 게 외롭다고 투정하는 느낌`;

    const shahriPositive = `[긍정/자랑 방향 - 이 중 하나 랜덤 선택]
1. 스하리 해줘서 팔로워 많이 늘었다고 자랑하는 느낌
2. 다들 스하리 너무 잘 해줘서 기분 좋다는 느낌
3. 반하리 다 받아서 뿌듯한 느낌
4. 오늘 스하리 몇 개 받았다고 신나는 느낌
5. 스하리 덕분에 팔로워 목표 달성했다고 좋아하는 느낌
6. 스하리 해줬더니 바로 반하리 와서 기분 좋은 느낌
7. 스하리 하면서 좋은 스치니 생겼다는 느낌`;

    const shahriMoodInstr = shahriMood === 'negative'
      ? shahriNegative
      : shahriMood === 'positive'
        ? shahriPositive
        : `[감정/방향 목록 - 랜덤 1개 선택]
※ 긍정적인 느낌(1~10)과 솔직/툴툴대는 느낌(11~20) 중 랜덤으로 하나만 선택.

[긍정/따뜻한 방향]
1. 스하리 먼저 가겠다고 밝고 적극적으로 제안하는 느낌
2. 반하리 꼭 갈 거라고 진심으로 약속하는 느낌
3. 스하리 받았을 때 기분 좋다고 솔직하게 표현하는 느낌
4. 같이 스레드 키워가자고 따뜻하게 제안하는 느낌
5. 스레드 막 시작했다고 설레는 마음으로 어필하는 느낌
6. 밤에 스레드 하다 괜히 기분 좋아진 느낌
7. 스하리 하나하나 챙기겠다고 다정하게 말하는 느낌
8. 맞팔하면 자주 소통하겠다고 기대감 담아 말하는 느낌
9. 팔로워 늘어가는 게 재밌다고 솔직하게 고백하는 느낌
10. 아무도 모르게 먼저 스하리 하고 도망가는 귀여운 느낌

[솔직/현실적인 방향]
11. 찡찡거리며 친구 없다고 하소연하는 느낌
12. 스레드 해봤자 인싸 못 된다고 자조하는 느낌
13. 팔로워 숫자 보며 현타 오는 느낌
14. 혼자 스레드 하는 게 외롭다고 투정하는 느낌
15. 팔로워보다 팔로잉이 많아서 억울한 느낌
16. 뒷삭 당한 서운함을 담담하게 얘기하는 느낌
17. 스하리 안 하면 삐질 거라고 장난스럽게 말하는 느낌
18. 이미 스하리 다 해놨으니 반하리만 해달라는 느낌
19. 오늘만 특별히 스하리 이벤트 연다고 선언하는 느낌
20. 팔로워 0명인 척 살짝 과장해서 귀엽게 구걸하는 느낌`;

    prompt = `스레드(Threads) SNS에서 스하리할 사람을 찾는 게시글을 써줘.

[스레드 전용 용어]
- 스하리: 팔로우+좋아요+리포스트를 먼저 해주는 것
- 반하리: 받은 스하리를 그대로 돌려주는 것 (답례)
- 스치니: 스레드 사용자 간 호칭
- 스팔/쓰팔: 스레드 팔로우
- 뒷삭: 맞팔 후 언팔하는 행위

[규칙]
- 반말 필수. 2~4줄. 마침표 없음. 이모지·해시태그 없음.
- 아래 20가지 감정/방향 중 하나를 랜덤으로 골라서 완전히 새로운 표현으로 창작.
- 절대로 고정된 문장 쓰지 말 것. 매번 다른 단어, 다른 감정, 다른 상황으로.

${shahriMoodInstr}

텍스트만 출력.`;
  } else if (type === 'comment') {
    // 프론트에서 직접 빌드한 프롬프트가 있으면 그걸 그대로 사용
    if (builtPrompt) {
      prompt = builtPrompt;
    } else if (isShahri) {
      prompt = `스레드 스하리 활동에 관한 내 솔직한 감정이나 다짐을 담은 댓글 1개를 써줘.

[아래 중 하나를 랜덤 선택]
- 뒷삭 없이 반하리 꼭 간다는 다짐
- 뒷삭할 거면 스하리하지 말라는 경고
- 늦게라도 반하리 꼭 갈 거라는 약속
- 스하리 받으면 기분 좋다는 솔직한 감정
- 뒷삭 당했을 때 서운한 감정
- 반하리 안 하는 사람에 대한 섭섭함

[나쁜 예시 - 절대 이렇게 쓰지 말 것]
× "스하리 감사해요" → 상대한테 인사하는 말투
× "같이 스하리 해요" → 너무 평범한 고정 문장
× "반하리 꼭 할게요" → 존댓말

[좋은 예시 - 이런 느낌으로]
○ "뒷삭할 거면 스하리하지 마셈 진짜" → 경고 느낌
○ "반하리 늦어도 꼭 감 기다려" → 다짐
○ "뒷삭 당하면 진짜 현타옴" → 솔직한 감정

[규칙]
- 반말. 1~3줄. 마침표 없음. 이모지·해시태그 없음.
- 매번 다른 표현으로. 고정 문장 금지.
- 텍스트만 출력.` + (extra ? '\n' + extra : '');
    } else {
      const commentLureInstr = hasCommentLure
        ? '\n\n글이 뚝 끊긴 경우: 뒷이야기 자연스럽게 이어서 작성.\n글이 질문으로 끝난 경우: 상황 더 구체화하거나 궁금증 키워.\n공통: 짧고 자연스럽게. 반말. 이모지 없이. 마침표 없이.'
        : '';
      prompt = '게시글 작성자가 자기 글에 직접 다는 댓글 1개.\n주제: ' + (topic||'') + imgContext + `

[핵심 규칙]
- 내가 쓴 글의 흐름을 자연스럽게 이어가는 댓글.
- 글에서 못 다한 말, 추가 감정, 뒷얘기를 덧붙이는 느낌.
- 또는 읽는 사람이 반응하고 싶게 살짝 여지 남기기.
- 반말. 1~2문장. 마침표 없음. 이모지·해시태그 없음.

[나쁜 예시 - 절대 이렇게 쓰지 말 것]
× "스하리, 정말 매력적인 작품이야" → 주제를 칭찬하는 제3자 반응
× "저도 그런 경험 있어요" → 남이 쓴 것처럼 공감
× "맞아요 진짜 공감돼요" → 타인 시점
× "좋은 정보 감사합니다" → 독자 반응
× "오늘도 좋은 하루 되세요" → 희망찬 마무리

[좋은 예시 - 이런 느낌으로]
○ "근데 이거 진짜 생각보다 오래 걸리더라" → 글 뒷이야기 이어감
○ "솔직히 처음엔 나도 몰랐음" → 내 감정 추가
○ "이거 물어보는 사람 많을 것 같아서" → 여지 남기기
○ "뒷삭할 거면 스하리하지 마셈" → 스하리 관련 내 다짐/경고

텍스트만 출력.` + commentLureInstr + (extra ? '\n' + extra : '');
    }
  } else {
    const extra = customUserPrompt ? '\n\n[사용자 지침]\n' + customUserPrompt : '';
    if (postMode === 'agro') {
      // 어그로글 - 제품 경험담 후킹 방식
      prompt = `아래 제품/상황을 경험한 일반인이 SNS에 올리는 어그로성 후킹 게시글을 써줘.

[핵심 원칙]
- 광고처럼 보이면 절대 안 됨. 진짜 일상 경험담처럼.
- 제품명·브랜드명 직접 언급 절대 금지.
- 거짓말 아닌 과장된 반응. "이게 뭐야" "미쳤다" "진짜임?" 같은 실제 반응.
- 후킹은 제품 효과/변화에 대한 놀람이나 감탄으로.

[어그로 패턴 - 아래 중 1개 랜덤 선택]
1. 가족/반려동물 반응형: "우리 강아지가 이것만 찾아요" "남편이 또 달라고 함 지겨워"
2. 변화 전/후 비교형: "쓰기 전엔 몰랐는데 이제 못 돌아가겠음"  
3. 의외성 반전형: "별로일 줄 알았는데 진짜로 달라짐"
4. 공감 유도형: "나만 이런 거 아니지 써보면 다 알아"
5. 시간 경과형: "한 달 쓰고 나서 주변에서 다 물어봄"

[말투]
- 반말. 마침표 없음. 자연스러운 일상체.
- 6~10줄. 2~3줄씩 묶어서.
- 이모지 금지. 해시태그 금지.

주제/상황: ` + (topic||'') + imgContext + extra + `

텍스트만 출력.`;
    } else {
      prompt = toneInstruction + fixedToneInstr + '\n\n주제: ' + (topic||'') + imgContext + extra + '\n\n위 형식으로 자연스러운 Threads 게시글 작성. 한국어만, 반말, 이모지·해시태그 없이, 텍스트만 출력.';
    }
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

async function publishToThreads(accessToken, text, imageUrls = [], videoUrls = []) {
  // videoUrls가 배열이 아니면 (구버전 호환) 변환
  if (typeof videoUrls === 'string') videoUrls = videoUrls ? [videoUrls] : [];
  const hasImages = imageUrls && imageUrls.length > 0;
  const hasVideos = videoUrls && videoUrls.length > 0;
  const totalMedia = (imageUrls||[]).length + (videoUrls||[]).length;

  // URL 보안 검증
  for (const u of (imageUrls||[])) { const c = validateMediaUrl(u); if (!c.ok) throw new Error('이미지 URL 오류: ' + c.reason); }
  for (const u of (videoUrls||[])) { const c = validateMediaUrl(u); if (!c.ok) throw new Error('영상 URL 오류: ' + c.reason); }

  let containerId;

  if (!hasImages && !hasVideos) {
    // 텍스트만
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'TEXT', text, access_token: accessToken }) });
    const d = await r.json(); if (d.error) throw new Error(d.error.message);
    containerId = d.id;
  } else if (totalMedia === 1 && hasImages) {
    // 사진 1장
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'IMAGE', image_url: imageUrls[0], text, access_token: accessToken }) });
    const d = await r.json(); if (d.error) throw new Error(d.error.message);
    containerId = d.id;
    await new Promise(r => setTimeout(r, 30000));
  } else if (totalMedia === 1 && hasVideos) {
    // 영상 1개
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'VIDEO', video_url: videoUrls[0], text, access_token: accessToken }) });
    const d = await r.json(); if (d.error) throw new Error(d.error.message);
    containerId = d.id;
    await new Promise(r => setTimeout(r, 30000));
  } else {
    // 사진 여러 장 / 영상 여러 개 / 혼합 캐러셀 (최대 20개)
    const childIds = [];
    for (const url of (imageUrls||[])) {
      const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'IMAGE', image_url: url, is_carousel_item: true, access_token: accessToken }) });
      const d = await r.json(); if (d.error) throw new Error(d.error.message);
      childIds.push(d.id);
    }
    for (const url of (videoUrls||[])) {
      const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'VIDEO', video_url: url, is_carousel_item: true, access_token: accessToken }) });
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
  const { accountId, imageUrls } = req.body;
  const videoUrls = Array.isArray(req.body.videoUrls) ? req.body.videoUrls : (req.body.videoUrl ? [req.body.videoUrl] : []);
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
  else if (user?.plan === 'free') dailyLimit = 5;        // 이벤트: 반자동 하루 5회
  else if (user?.plan === 'pro') dailyLimit = 100;       // 프로: 사실상 무제한 (100회)
  else if (user?.dailyPublishLimit) dailyLimit = user.dailyPublishLimit;
  else dailyLimit = 5;
  const today = getTodayKey();
  const counts = getPublishCount(req.userId);
  if (dailyLimit < 9999 && (counts[today] || 0) >= dailyLimit) {
    return res.status(429).json({ error: `오늘 발행 한도 초과. 너무 빠른 발행은 IP 차단될 수 있어요.` });
  }
  if (videoUrl) { const vc = validateMediaUrl(videoUrl); if (!vc.ok) return res.status(400).json({ error: '영상 URL 오류: ' + vc.reason }); }
  if (Array.isArray(imageUrls)) {
    for (const u of imageUrls) { const ic = validateMediaUrl(u); if (!ic.ok) return res.status(400).json({ error: '이미지 URL 오류: ' + ic.reason }); }
  }
  try {
    const postId = await publishToThreads(account.accessToken, text, imageUrls || [], videoUrls);
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
  const { accountId, text, imageUrls, scheduledAt, commentText } = req.body;
  const videoUrls2 = Array.isArray(req.body.videoUrls) ? req.body.videoUrls : (req.body.videoUrl ? [req.body.videoUrl] : []);
  const accs = getAccounts(req.userId);
  const account = accs.find(a => a.id === accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  const posts = getScheduled(req.userId);
  const post = { id: Date.now().toString(), accountId, accountName: account.name, text, type: req.body.type || 'post', imageUrls: imageUrls || [], videoUrls: videoUrls2, videoUrl: videoUrls2[0] || '', commentText: commentText || '', replyToId: req.body.replyToId || null, scheduledAt, status: 'pending', createdAt: new Date().toISOString() };
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
    try { postId = await publishToThreads(account.accessToken, post.text, post.imageUrls || [], post.videoUrls || (post.videoUrl ? [post.videoUrl] : [])); }
    catch(imgErr) { postId = await publishToThreads(account.accessToken, post.text, [], []); }
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
          try { postId = await publishToThreads(account.accessToken, post.text, post.imageUrls || [], post.videoUrls || (post.videoUrl ? [post.videoUrl] : [])); }
          catch(imgErr) { postId = await publishToThreads(account.accessToken, post.text, [], []); }
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

// ==============================
//  쿠팡 파트너스 링크 생성 API
// ==============================

const COUPANG_PARTNER_ID = 'AF5722914'; // 관리자 파트너스 ID 고정

function getCoupangClickLogs() { return loadJSON(`${DATA_ROOT}/coupang_clicks.json`, []); }
function saveCoupangClickLogs(data) { saveJSON(`${DATA_ROOT}/coupang_clicks.json`, data); }

// 쿠팡 파트너스 딥링크 생성 함수
async function buildCoupangPartnerLink(productUrl, subId = '') {
  const settings = getSettings();
  const accessKey = settings.coupangPartnerAccessKey || process.env.COUPANG_ACCESS_KEY;
  const secretKey = settings.coupangPartnerSecretKey || process.env.COUPANG_SECRET_KEY;
  const partnerId = COUPANG_PARTNER_ID;
  const subIdFinal = subId || settings.coupangPartnerSubIdDefault || 'app';
  const deepLinkMode = settings.coupangDeepLinkMode || 'template';

  // 딥링크 API 방식 시도
  if (accessKey && secretKey && deepLinkMode === 'api') {
    try {
      const method = 'GET';
      const path = `/v2/providers/affiliate_open_api/apis/openapi/deeplink?coupangUrls=${encodeURIComponent(productUrl)}&subId=${encodeURIComponent(subIdFinal)}`;
      const datetime = new Date().toISOString().replace(/[:\-]|\..{3}/g, '').slice(0, 15) + 'Z';
      const message = datetime + method + path;
      const signature = crypto.createHmac('sha256', secretKey).update(message).digest('hex');
      const authorization = `CEA algorithm=HmacSHA256, access-key=${accessKey}, signed-date=${datetime}, signature=${signature}`;
      const r = await fetch(`https://api-gateway.coupang.com${path}`, { method, headers: { 'Authorization': authorization } });
      const d = await r.json();
      if (d.data && d.data.landingUrl) return d.data.landingUrl;
    } catch(e) { /* API 실패 시 템플릿 방식으로 폴백 */ }
  }

  // 템플릿 방식 (항상 사용 가능)
  // 쿠팡 URL에 파트너스 파라미터 주입
  try {
    const url = new URL(productUrl);
    url.searchParams.set('partnersCoupangWhere', `${partnerId}_${subIdFinal}`);
    url.searchParams.set('traceId', `${partnerId}_${subIdFinal}_${Date.now()}`);
    return url.toString();
  } catch(e) {
    // URL 파싱 실패 시 바로 리다이렉트 URL 생성
    const sep = productUrl.includes('?') ? '&' : '?';
    return `${productUrl}${sep}partnersCoupangWhere=${partnerId}_${subIdFinal}`;
  }
}

// POST /api/coupang/link - 파트너스 링크 생성
app.post('/api/coupang/link', auth, async (req, res) => {
  const { productUrl, subId, productId, sourcePage } = req.body;
  if (!productUrl) return res.status(400).json({ error: 'productUrl 필요' });
  const settings = getSettings();
  if (!settings.coupangPartnersEnabled) {
    // 파트너스 비활성화 시 원본 URL 반환
    return res.json({ url: productUrl, partnered: false });
  }
  try {
    const partnerUrl = await buildCoupangPartnerLink(productUrl, subId);
    // 클릭 로그 저장
    const logs = getCoupangClickLogs();
    logs.push({
      id: Date.now().toString(),
      userId: req.userId,
      productId: productId || '',
      productUrl,
      partnerUrl,
      subId: subId || settings.coupangPartnerSubIdDefault || 'app',
      sourcePage: sourcePage || '',
      clickedAt: new Date().toISOString()
    });
    if (logs.length > 5000) logs.splice(0, logs.length - 5000); // 최대 5000개
    saveCoupangClickLogs(logs);
    res.json({ url: partnerUrl, partnered: true });
  } catch(e) {
    res.json({ url: productUrl, partnered: false, error: e.message });
  }
});

// GET /api/coupang/click/:productId - 상품 클릭 리다이렉트
app.get('/api/coupang/click/:productId', auth, async (req, res) => {
  const { productId } = req.params;
  const { subId, sourcePage } = req.query;
  // productId가 URL 인코딩된 상품 URL인 경우
  let productUrl = decodeURIComponent(productId);
  if (!productUrl.startsWith('http')) {
    productUrl = `https://www.coupang.com/vp/products/${productId}`;
  }
  const settings = getSettings();
  if (!settings.coupangPartnersEnabled) {
    return res.redirect(productUrl);
  }
  try {
    const partnerUrl = await buildCoupangPartnerLink(productUrl, subId);
    // 클릭 로그
    const logs = getCoupangClickLogs();
    logs.push({ id: Date.now().toString(), userId: req.userId, productId, productUrl, partnerUrl, subId: subId || 'click', sourcePage: sourcePage || '', clickedAt: new Date().toISOString() });
    if (logs.length > 5000) logs.splice(0, logs.length - 5000);
    saveCoupangClickLogs(logs);
    res.redirect(partnerUrl);
  } catch(e) {
    res.redirect(productUrl);
  }
});

// GET /api/coupang/clicks - 클릭 로그 조회 (관리자)
app.get('/api/coupang/clicks', adminAuth, (req, res) => {
  const logs = getCoupangClickLogs();
  res.json(logs.slice(-200).reverse()); // 최근 200개
});

// 인기상품 캐시 (카테고리별)
const _productCaches = {};
const PRODUCT_CACHE_TTL = 30 * 60 * 1000; // 30분

// 쿠팡 카테고리 키 → ID 맵
const COUPANG_CAT_IDS = {
  'best':'36405', 'fashion':'36407', 'beauty':'36410', 'baby':'36413', 'food':'37527',
  'kitchen':'36415', 'living':'36416', 'interior':'36412', 'digital':'36405',
  'sports':'36416', 'car':'36417', 'book':'36418', 'hobby':'36419', 'office':'36420',
  'pet':'36421', 'health':'36422', 'travel':'36423',
  '전체':'36405', '반려동물':'36421', '생활가전':'36405', '주방용품':'36415',
  '육아':'36413', '캠핑':'36416', '뷰티':'36410', '식품':'37527'
};

// 쿠팡 파트너스 API로 베스트셀러 가져오기
async function fetchCoupangBestByApi(accessKey, secretKey, categoryId, limit) {
  limit = limit || 20;
  const crypto = require('crypto');
  const method = 'GET';
  const apiPath = '/v2/providers/affiliate_open_api/apis/openapi/v1/products/bestseller';
  const query = 'categoryId=' + categoryId + '&limit=' + limit;
  const dt = new Date();
  const pad = function(n){return String(n).padStart(2,'0');};
  const datetime = String(dt.getUTCFullYear()).slice(2) + pad(dt.getUTCMonth()+1) + pad(dt.getUTCDate()) + 'T' + pad(dt.getUTCHours()) + pad(dt.getUTCMinutes()) + pad(dt.getUTCSeconds()) + 'Z';
  const message = datetime + method + apiPath + query;
  const signature = crypto.createHmac('sha256', secretKey).update(message).digest('hex');
  const authorization = 'CEA algorithm=HmacSHA256, access-key=' + accessKey + ', signed-date=' + datetime + ', signature=' + signature;
  try {
    const r = await fetch('https://api-gateway.coupang.com' + apiPath + '?' + query, {
      headers: { 'Authorization': authorization, 'Content-Type': 'application/json;charset=UTF-8' }
    });
    const data = await r.json();
    if (!data.data || !data.data.productData) return [];
    return data.data.productData.map(function(p, i) {
      return {
        rank: i + 1,
        productId: String(p.productId),
        productName: p.productName,
        price: p.productPrice,
        reviewCount: p.productReview || 0,
        rating: p.productRating || 0,
        productUrl: p.productUrl || ('https://www.coupang.com/vp/products/' + p.productId),
        imageUrl: p.productImage || '',
        trackingUrl: p.deepLink || ''
      };
    });
  } catch(e) {
    return [];
  }
}

// GET /api/coupang/products - 인기상품 목록
app.get('/api/coupang/products', auth, async (req, res) => {
  const catKey = req.query.category || 'best';
  const q = req.query.q || '';
  const now = Date.now();
  const cacheKey = catKey;

  // 캐시 유효하면 반환
  if (!q && _productCaches[cacheKey] && _productCaches[cacheKey].data.length && now - _productCaches[cacheKey].cachedAt < PRODUCT_CACHE_TTL) {
    let items = _productCaches[cacheKey].data;
    if (q) items = items.filter(i => i.productName && i.productName.includes(q));
    return res.json(items);
  }

  // 파트너스 API 키가 있으면 실제 API 호출
  const s = getSettings();
  let items = [];
  if (s.coupangPartnerAccessKey && s.coupangPartnerSecretKey && s.coupangPartnerSecretKey !== '***') {
    const catId = COUPANG_CAT_IDS[catKey] || '36405';
    items = await fetchCoupangBestByApi(s.coupangPartnerAccessKey, s.coupangPartnerSecretKey, catId, 20);
  }

  // 키 없거나 실패 시 카테고리별 샘플 데이터
  if (!items.length) {
    const IMG = {
      airfryer: 'https://images.unsplash.com/photo-1626082927389-6cd097cdc6ec?w=100&h=100&fit=crop',
      vacuum: 'https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=100&h=100&fit=crop',
      skincare: 'https://images.unsplash.com/photo-1556228578-0d85b1a4d571?w=100&h=100&fit=crop',
      protein: 'https://images.unsplash.com/photo-1593095948071-474c5cc2989d?w=100&h=100&fit=crop',
      yogamat: 'https://images.unsplash.com/photo-1545205597-3d9d02c29597?w=100&h=100&fit=crop',
      tumbler: 'https://images.unsplash.com/photo-1577937927133-66ef06acdf18?w=100&h=100&fit=crop',
      earphone: 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=100&h=100&fit=crop',
      omega3: 'https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?w=100&h=100&fit=crop',
      battery: 'https://images.unsplash.com/photo-1609592806596-b6d9614da4ad?w=100&h=100&fit=crop',
      handcream: 'https://images.unsplash.com/photo-1556228720-195a672e8a03?w=100&h=100&fit=crop',
      sunscreen: 'https://images.unsplash.com/photo-1608248597279-f99d160bfcbc?w=100&h=100&fit=crop',
      serum: 'https://images.unsplash.com/photo-1620916566398-39f1143ab7be?w=100&h=100&fit=crop',
      cream: 'https://images.unsplash.com/photo-1616394584738-fc6e612e71b9?w=100&h=100&fit=crop',
      mask: 'https://images.unsplash.com/photo-1598440947619-2c35fc9aa908?w=100&h=100&fit=crop',
      water: 'https://images.unsplash.com/photo-1548839140-29a749e1cf4d?w=100&h=100&fit=crop',
      banana: 'https://images.unsplash.com/photo-1571771894821-ce9b6c11b08e?w=100&h=100&fit=crop',
      meat: 'https://images.unsplash.com/photo-1607623814075-e51df1bdc82f?w=100&h=100&fit=crop',
      coffee: 'https://images.unsplash.com/photo-1509042239860-f550ce710b93?w=100&h=100&fit=crop',
      granola: 'https://images.unsplash.com/photo-1517093728165-5f19e8e38b5e?w=100&h=100&fit=crop',
      feeder: 'https://images.unsplash.com/photo-1601758228041-f3b2795255f1?w=100&h=100&fit=crop',
      catlit: 'https://images.unsplash.com/photo-1519052537078-e6302a4968d4?w=100&h=100&fit=crop',
      dogpad: 'https://images.unsplash.com/photo-1587300003388-59208cc962cb?w=100&h=100&fit=crop',
      cattower: 'https://images.unsplash.com/photo-1548802673-380ab8ebc7b7?w=100&h=100&fit=crop',
      dogfood: 'https://images.unsplash.com/photo-1568640347023-a616a30bc3bd?w=100&h=100&fit=crop',
      fashion: 'https://images.unsplash.com/photo-1523381210434-271e8be1f52b?w=100&h=100&fit=crop',
      bag: 'https://images.unsplash.com/photo-1548036328-c9fa89d128fa?w=100&h=100&fit=crop',
      shoes: 'https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=100&h=100&fit=crop',
      tshirt: 'https://images.unsplash.com/photo-1581655353564-df123a1eb820?w=100&h=100&fit=crop',
      pants: 'https://images.unsplash.com/photo-1624378439575-d8705ad7ae80?w=100&h=100&fit=crop',
      tv: 'https://images.unsplash.com/photo-1593784991095-a205069470b6?w=100&h=100&fit=crop',
      laptop: 'https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=100&h=100&fit=crop',
      phone: 'https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=100&h=100&fit=crop',
      tablet: 'https://images.unsplash.com/photo-1544244015-0df4b3ffc6b0?w=100&h=100&fit=crop',
      keyboard: 'https://images.unsplash.com/photo-1587829741301-dc798b83add3?w=100&h=100&fit=crop',
      rice: 'https://images.unsplash.com/photo-1536304929831-ee1ca9d44906?w=100&h=100&fit=crop',
      furniture: 'https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=100&h=100&fit=crop',
      bedding: 'https://images.unsplash.com/photo-1584100936595-c0654b55a2e2?w=100&h=100&fit=crop',
      towel: 'https://images.unsplash.com/photo-1617975558503-a5f08d3ead50?w=100&h=100&fit=crop',
      lamp: 'https://images.unsplash.com/photo-1507473885765-e6ed057f782c?w=100&h=100&fit=crop',
      pan: 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=100&h=100&fit=crop',
      knife: 'https://images.unsplash.com/photo-1593618998160-e34014e67546?w=100&h=100&fit=crop',
      blender: 'https://images.unsplash.com/photo-1619068670907-9f7de751b00c?w=100&h=100&fit=crop',
      container: 'https://images.unsplash.com/photo-1583947215259-38e31be8751f?w=100&h=100&fit=crop',
      dumbbell: 'https://images.unsplash.com/photo-1534438327276-14e5300c3a48?w=100&h=100&fit=crop',
      bike: 'https://images.unsplash.com/photo-1502744688674-c619d1586c9e?w=100&h=100&fit=crop',
      tent: 'https://images.unsplash.com/photo-1504280390367-361c6d9f38f4?w=100&h=100&fit=crop',
      sneakers: 'https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=100&h=100&fit=crop',
      book: 'https://images.unsplash.com/photo-1512820790803-83ca734da794?w=100&h=100&fit=crop',
      game: 'https://images.unsplash.com/photo-1606144042614-b2417e99c4e3?w=100&h=100&fit=crop',
      car_mat: 'https://images.unsplash.com/photo-1568605117036-5fe5e7bab0b7?w=100&h=100&fit=crop',
      vitamin: 'https://images.unsplash.com/photo-1550572017-edd951b55104?w=100&h=100&fit=crop',
      probiotic: 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=100&h=100&fit=crop',
    };
    const samples = {
      best: [
        { rank:1, productName:'에어프라이어 6L 대용량 스마트', price:49800, reviewCount:8420, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=에어프라이어', imageUrl:IMG.airfryer },
        { rank:2, productName:'무선 청소기 경량형 흡입력 강화', price:128000, reviewCount:5231, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=무선청소기', imageUrl:IMG.vacuum },
        { rank:3, productName:'수분 스킨케어 세트 히알루론산', price:35000, reviewCount:12840, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=스킨케어세트', imageUrl:IMG.skincare },
        { rank:4, productName:'단백질 쉐이크 초코맛 1kg WPC', price:29800, reviewCount:6720, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=단백질쉐이크', imageUrl:IMG.protein },
        { rank:5, productName:'요가매트 15mm 고밀도 논슬립', price:18900, reviewCount:9150, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=요가매트', imageUrl:IMG.yogamat },
        { rank:6, productName:'스텐 텀블러 보온보냉 500ml', price:15900, reviewCount:7340, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=텀블러', imageUrl:IMG.tumbler },
        { rank:7, productName:'무선 이어폰 노이즈캔슬링 ANC', price:89000, reviewCount:4210, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=무선이어폰', imageUrl:IMG.earphone },
        { rank:8, productName:'오메가3 고함량 rTG형 90캡슐', price:19800, reviewCount:11200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=오메가3', imageUrl:IMG.omega3 },
        { rank:9, productName:'보조배터리 20000mAh PD65W', price:25800, reviewCount:7610, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=보조배터리', imageUrl:IMG.battery },
        { rank:10, productName:'핸드크림 세트 5종 촉촉함', price:12900, reviewCount:15400, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=핸드크림', imageUrl:IMG.handcream },
      ],
      rocket: [
        { rank:1, productName:'[로켓] 삼성 갤럭시 버즈3 프로', price:189000, reviewCount:3240, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=갤럭시버즈3프로', imageUrl:IMG.earphone },
        { rank:2, productName:'[로켓] LG 코드제로 무선청소기', price:398000, reviewCount:1820, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=LG코드제로', imageUrl:IMG.vacuum },
        { rank:3, productName:'[로켓] 에어팟 프로 2세대', price:219000, reviewCount:8420, rating:4.9, productUrl:'https://www.coupang.com/np/search?q=에어팟프로2', imageUrl:IMG.earphone },
        { rank:4, productName:'[로켓] 닌텐도 스위치 OLED', price:398000, reviewCount:5610, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=닌텐도스위치OLED', imageUrl:IMG.game },
        { rank:5, productName:'[로켓] 다이슨 에어랩 롱 배럴', price:698000, reviewCount:2340, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=다이슨에어랩', imageUrl:IMG.vacuum },
        { rank:6, productName:'[로켓] 네스프레소 버츄오 팝', price:129000, reviewCount:4120, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=네스프레소버츄오', imageUrl:IMG.coffee },
        { rank:7, productName:'[로켓] 아이패드 10세대 64GB', price:598000, reviewCount:3890, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=아이패드10세대', imageUrl:IMG.tablet },
        { rank:8, productName:'[로켓] 필립스 에어프라이어 XXL', price:189000, reviewCount:6720, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=필립스에어프라이어', imageUrl:IMG.airfryer },
        { rank:9, productName:'[로켓] 쿠쿠 IH밥솥 6인용', price:198000, reviewCount:5430, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=쿠쿠IH밥솥', imageUrl:IMG.rice },
        { rank:10, productName:'[로켓] 삼성 QD-OLED TV 55인치', price:1290000, reviewCount:890, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=삼성QDOLED55', imageUrl:IMG.tv },
      ],
      rocket_fresh: [
        { rank:1, productName:'[로켓프레시] 제주 삼다수 2L 24개', price:21600, reviewCount:45200, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=제주삼다수', imageUrl:IMG.water },
        { rank:2, productName:'[로켓프레시] 신선 바나나 1.2kg', price:4900, reviewCount:28900, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=바나나', imageUrl:IMG.banana },
        { rank:3, productName:'[로켓프레시] 냉장 삼겹살 500g', price:14900, reviewCount:18200, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=냉장삼겹살', imageUrl:IMG.meat },
        { rank:4, productName:'[로켓프레시] 유기농 달걀 30구', price:8900, reviewCount:35600, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=유기농달걀', imageUrl:IMG.granola },
        { rank:5, productName:'[로켓프레시] 딸기 500g 특', price:9900, reviewCount:22400, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=딸기500g', imageUrl:IMG.banana },
        { rank:6, productName:'[로켓프레시] 무항생제 닭가슴살 1kg', price:12900, reviewCount:19800, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=닭가슴살', imageUrl:IMG.meat },
        { rank:7, productName:'[로켓프레시] 그리스식 요거트 400g', price:5900, reviewCount:14200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=그릭요거트', imageUrl:IMG.granola },
        { rank:8, productName:'[로켓프레시] 아보카도 4입', price:6900, reviewCount:11600, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=아보카도', imageUrl:IMG.banana },
        { rank:9, productName:'[로켓프레시] 두부 찌개용 2입', price:2900, reviewCount:32100, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=두부찌개용', imageUrl:IMG.granola },
        { rank:10, productName:'[로켓프레시] 곤약 쌀 200g×5', price:7900, reviewCount:16800, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=곤약쌀', imageUrl:IMG.rice },
      ],
      discount: [
        { rank:1, productName:'[오늘의딜] 나이키 에어맥스 270 40%↓', price:89000, reviewCount:6720, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=나이키에어맥스270', imageUrl:IMG.sneakers },
        { rank:2, productName:'[오늘의딜] 아이패드 케이스 50%↓', price:12900, reviewCount:8420, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=아이패드케이스', imageUrl:IMG.tablet },
        { rank:3, productName:'[오늘의딜] 캐시미어 니트 45%↓', price:39000, reviewCount:3240, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=캐시미어니트', imageUrl:IMG.tshirt },
        { rank:4, productName:'[오늘의딜] 무선 충전기 세트 55%↓', price:19800, reviewCount:11200, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=무선충전기세트', imageUrl:IMG.battery },
        { rank:5, productName:'[오늘의딜] 캠핑 텐트 3인용 40%↓', price:89000, reviewCount:4820, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=캠핑텐트3인용', imageUrl:IMG.tent },
        { rank:6, productName:'[오늘의딜] 에센스 50ml 2+1 행사', price:28000, reviewCount:15600, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=에센스50ml', imageUrl:IMG.serum },
        { rank:7, productName:'[오늘의딜] 베개 솜털 2개 세트 35%↓', price:34900, reviewCount:7340, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=베개솜털세트', imageUrl:IMG.bedding },
        { rank:8, productName:'[오늘의딜] 가정용 안마기 50%↓', price:59000, reviewCount:5430, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=가정용안마기', imageUrl:IMG.dumbbell },
        { rank:9, productName:'[오늘의딜] 주방 수납 선반 세트 30%↓', price:24800, reviewCount:9150, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=주방수납선반', imageUrl:IMG.container },
        { rank:10, productName:'[오늘의딜] 런닝화 쿠션 강화 45%↓', price:49000, reviewCount:6720, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=런닝화쿠션', imageUrl:IMG.sneakers },
      ],
      global: [
        { rank:1, productName:'[직구] 뉴발란스 993 US Men', price:198000, reviewCount:3240, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=뉴발란스993', imageUrl:IMG.sneakers },
        { rank:2, productName:'[직구] 아이허브 비타민C 1000mg', price:24800, reviewCount:18200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=아이허브비타민C', imageUrl:IMG.vitamin },
        { rank:3, productName:'[직구] 레고 테크닉 42161', price:89000, reviewCount:2840, rating:4.9, productUrl:'https://www.coupang.com/np/search?q=레고테크닉42161', imageUrl:IMG.game },
        { rank:4, productName:'[직구] 랄프로렌 폴로 셔츠', price:69000, reviewCount:5610, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=랄프로렌폴로', imageUrl:IMG.tshirt },
        { rank:5, productName:'[직구] 코스트코 커클랜드 오메가3', price:39800, reviewCount:22400, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=커클랜드오메가3', imageUrl:IMG.omega3 },
        { rank:6, productName:'[직구] 어그 클래식 미니 부츠', price:189000, reviewCount:4120, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=어그클래식미니', imageUrl:IMG.shoes },
        { rank:7, productName:'[직구] 스탠리 퀜처 텀블러 40oz', price:49000, reviewCount:8420, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=스탠리퀜처', imageUrl:IMG.tumbler },
        { rank:8, productName:'[직구] 러쉬 인터갈락틱 배스밤', price:12900, reviewCount:6720, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=러쉬인터갈락틱', imageUrl:IMG.mask },
        { rank:9, productName:'[직구] 카시오 G-SHOCK GA-2100', price:98000, reviewCount:3890, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=카시오G-SHOCK', imageUrl:IMG.keyboard },
        { rank:10, productName:'[직구] 얼타 뷰티 레티놀 세럼', price:34800, reviewCount:9150, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=얼타뷰티레티놀', imageUrl:IMG.serum },
      ],
      fashion: [
        { rank:1, productName:'오버핏 무지 반팔 티셔츠 5컬러', price:19900, reviewCount:28400, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=오버핏반팔티', imageUrl:IMG.tshirt },
        { rank:2, productName:'여성 와이드 데님 팬츠 스트레이트', price:34900, reviewCount:15600, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=와이드데님팬츠', imageUrl:IMG.pants },
        { rank:3, productName:'남성 슬림핏 청바지 스트레치', price:39900, reviewCount:12800, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=슬림핏청바지', imageUrl:IMG.pants },
        { rank:4, productName:'크로스백 미니 숄더백 여성', price:24900, reviewCount:18200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=크로스백미니', imageUrl:IMG.bag },
        { rank:5, productName:'운동화 쿠션 에어 런닝화 남여', price:49900, reviewCount:22400, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=런닝화에어', imageUrl:IMG.sneakers },
        { rank:6, productName:'여성 니트 가디건 브이넥 7컬러', price:29900, reviewCount:9150, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=니트가디건브이넥', imageUrl:IMG.tshirt },
        { rank:7, productName:'백팩 노트북 수납 방수 30L', price:39900, reviewCount:11200, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=백팩노트북방수', imageUrl:IMG.bag },
        { rank:8, productName:'남성 캐주얼 치노 팬츠 슬림', price:29900, reviewCount:7340, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=치노팬츠슬림', imageUrl:IMG.pants },
        { rank:9, productName:'여성 플랫슈즈 메리제인 로퍼', price:34900, reviewCount:14200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=플랫슈즈메리제인', imageUrl:IMG.shoes },
        { rank:10, productName:'캔버스 토트백 에코백 대형', price:14900, reviewCount:19800, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=캔버스토트백', imageUrl:IMG.bag },
      ],
      beauty: [
        { rank:1, productName:'에스트라 아토베리어365 크림 80ml', price:28900, reviewCount:45200, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=에스트라아토베리어크림', imageUrl:IMG.cream },
        { rank:2, productName:'선크림 에스쁘아 UV프로텍터 SPF50+', price:18900, reviewCount:38400, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=에스쁘아선크림', imageUrl:IMG.sunscreen },
        { rank:3, productName:'히알루론산 앰플 토리든 2.0', price:24800, reviewCount:28900, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=토리든히알루론산', imageUrl:IMG.serum },
        { rank:4, productName:'비타민C 세럼 올리브영 자체브랜드', price:15900, reviewCount:32100, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=비타민C세럼', imageUrl:IMG.serum },
        { rank:5, productName:'마스크팩 메디힐 NMF 10매입', price:12900, reviewCount:56800, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=메디힐마스크팩', imageUrl:IMG.mask },
        { rank:6, productName:'콜라겐 크림 닥터지 브라이트닝 50ml', price:32000, reviewCount:21400, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=닥터지콜라겐크림', imageUrl:IMG.cream },
        { rank:7, productName:'미셀라워터 메이크업 클렌징 500ml', price:9900, reviewCount:18600, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=미셀라워터클렌징', imageUrl:IMG.cream },
        { rank:8, productName:'레티놀 세럼 RoC 나이트크림', price:29800, reviewCount:14200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=레티놀세럼', imageUrl:IMG.serum },
        { rank:9, productName:'페이셜 스크럽 폼 클렌저 150ml', price:8900, reviewCount:22400, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=페이셜스크럽클렌저', imageUrl:IMG.cream },
        { rank:10, productName:'BB크림 SPF35 쿠션 파운데이션', price:16900, reviewCount:19800, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=BB크림쿠션', imageUrl:IMG.sunscreen },
      ],
      baby: [
        { rank:1, productName:'하기스 매직팬티 3단계 56매', price:24900, reviewCount:38400, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=하기스매직팬티3단계', imageUrl:IMG.dogpad },
        { rank:2, productName:'아이배냇 유기농 쌀과자 30g×6', price:12900, reviewCount:22400, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=아이배냇쌀과자', imageUrl:IMG.granola },
        { rank:3, productName:'범보 시트 유아 보조의자', price:39900, reviewCount:15600, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=범보시트보조의자', imageUrl:IMG.furniture },
        { rank:4, productName:'유모차 경량 접이식 원핸드', price:189000, reviewCount:8420, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=경량유모차원핸드', imageUrl:IMG.furniture },
        { rank:5, productName:'아기 물티슈 순수한 캡형 100매×10', price:18900, reviewCount:45200, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=아기물티슈순수한', imageUrl:IMG.towel },
        { rank:6, productName:'아기욕조 온도계 포함 신생아', price:29900, reviewCount:12800, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=아기욕조온도계', imageUrl:IMG.container },
        { rank:7, productName:'이유식 블렌더 분유포트 일체형', price:89000, reviewCount:6720, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=이유식블렌더포트', imageUrl:IMG.blender },
        { rank:8, productName:'아기 딸랑이 치발기 세트', price:19900, reviewCount:18200, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=아기딸랑이치발기', imageUrl:IMG.game },
        { rank:9, productName:'출산선물 세트 신생아 3종', price:49900, reviewCount:9150, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=출산선물세트신생아', imageUrl:IMG.dogpad },
        { rank:10, productName:'아기 이불 세트 사계절 누빔', price:59000, reviewCount:11200, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=아기이불세트', imageUrl:IMG.bedding },
      ],
      food: [
        { rank:1, productName:'제주 삼다수 2L 24개 (무료배송)', price:21600, reviewCount:45200, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=제주삼다수2L24개', imageUrl:IMG.water },
        { rank:2, productName:'스타벅스 아메리카노 블랙 50T', price:14900, reviewCount:35600, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=스타벅스아메리카노블랙', imageUrl:IMG.coffee },
        { rank:3, productName:'신선 바나나 제스프리 1.2kg', price:4900, reviewCount:28900, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=제스프리바나나', imageUrl:IMG.banana },
        { rank:4, productName:'냉동 삼겹살 국내산 1kg 두툼', price:17900, reviewCount:18200, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=냉동삼겹살국내산1kg', imageUrl:IMG.meat },
        { rank:5, productName:'그래놀라 어니스트 아몬드 500g', price:9800, reviewCount:19800, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=그래놀라아몬드500g', imageUrl:IMG.granola },
        { rank:6, productName:'햇반 즉석밥 210g 24개입', price:24900, reviewCount:42100, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=햇반즉석밥24개', imageUrl:IMG.rice },
        { rank:7, productName:'진라면 매운맛 120g×40봉', price:22900, reviewCount:38400, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=진라면매운맛40봉', imageUrl:IMG.granola },
        { rank:8, productName:'CJ 비비고 왕교자 420g×3입', price:19900, reviewCount:28900, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=비비고왕교자', imageUrl:IMG.meat },
        { rank:9, productName:'동원 참치 150g 12캔 선물세트', price:29900, reviewCount:15600, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=동원참치12캔', imageUrl:IMG.granola },
        { rank:10, productName:'해태 맛동산 500g 과자 대용량', price:7900, reviewCount:22400, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=맛동산500g', imageUrl:IMG.granola },
      ],
      kitchen: [
        { rank:1, productName:'스테인리스 냄비 세트 3종 IH', price:89000, reviewCount:12800, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=스테인리스냄비세트IH', imageUrl:IMG.pan },
        { rank:2, productName:'세라믹 코팅 프라이팬 28cm', price:29800, reviewCount:22400, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=세라믹프라이팬28cm', imageUrl:IMG.pan },
        { rank:3, productName:'유리 밀폐용기 세트 10개입', price:24900, reviewCount:18600, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=유리밀폐용기세트10개', imageUrl:IMG.container },
        { rank:4, productName:'전기 포트 1.7L 빠른 끓음', price:19900, reviewCount:28900, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=전기포트1.7L', imageUrl:IMG.blender },
        { rank:5, productName:'미니 블렌더 스무디 개인컵형', price:34900, reviewCount:15600, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=미니블렌더스무디', imageUrl:IMG.blender },
        { rank:6, productName:'독일제 주방칼 세트 5종', price:49800, reviewCount:9150, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=독일주방칼세트', imageUrl:IMG.knife },
        { rank:7, productName:'실리콘 주방도구 세트 8종', price:19900, reviewCount:14200, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=실리콘주방도구세트', imageUrl:IMG.pan },
        { rank:8, productName:'식기세척기 전용 세제 700g×2', price:14900, reviewCount:32100, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=식기세척기세제', imageUrl:IMG.container },
        { rank:9, productName:'에어프라이어 전용 실리콘 트레이', price:9900, reviewCount:22400, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=에어프라이어실리콘트레이', imageUrl:IMG.pan },
        { rank:10, productName:'와인잔 세트 6개 크리스탈', price:39900, reviewCount:7340, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=와인잔세트6개', imageUrl:IMG.container },
      ],
      living: [
        { rank:1, productName:'극세사 이불 세트 S 퀸 겨울', price:49900, reviewCount:28400, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=극세사이불세트', imageUrl:IMG.bedding },
        { rank:2, productName:'호텔식 베개 솜 2개 쿨링', price:34900, reviewCount:18200, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=호텔베개솜쿨링', imageUrl:IMG.bedding },
        { rank:3, productName:'국화 타올 면100% 대형 10매', price:24900, reviewCount:22400, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=국화타올면100', imageUrl:IMG.towel },
        { rank:4, productName:'욕실 수납 선반 스테인리스', price:19900, reviewCount:15600, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=욕실수납선반', imageUrl:IMG.furniture },
        { rank:5, productName:'LED 스탠드 밝기조절 독서등', price:29900, reviewCount:12800, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=LED스탠드독서등', imageUrl:IMG.lamp },
        { rank:6, productName:'공기청정기 필터 교체용 10인치', price:19800, reviewCount:18600, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=공기청정기필터', imageUrl:IMG.vacuum },
        { rank:7, productName:'세탁세제 액체 드럼용 3L', price:14900, reviewCount:35600, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=세탁세제드럼용3L', imageUrl:IMG.container },
        { rank:8, productName:'빨래건조대 접이식 실내외 겸용', price:24900, reviewCount:9150, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=빨래건조대접이식', imageUrl:IMG.furniture },
        { rank:9, productName:'쓰레기통 페달형 10L 위생', price:19900, reviewCount:14200, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=쓰레기통페달형10L', imageUrl:IMG.container },
        { rank:10, productName:'욕실 매트 규조토 발매트 대형', price:29900, reviewCount:11200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=규조토발매트', imageUrl:IMG.towel },
      ],
      interior: [
        { rank:1, productName:'3인 소파 패브릭 스칸디나비아', price:298000, reviewCount:4820, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=패브릭소파3인', imageUrl:IMG.furniture },
        { rank:2, productName:'원목 커피테이블 북유럽 스타일', price:149000, reviewCount:3240, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=원목커피테이블', imageUrl:IMG.furniture },
        { rank:3, productName:'무드등 간접조명 LED 원형', price:24900, reviewCount:22400, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=무드등간접조명', imageUrl:IMG.lamp },
        { rank:4, productName:'커튼 암막 135×220 차광률 99%', price:39900, reviewCount:15600, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=커튼암막차광', imageUrl:IMG.bedding },
        { rank:5, productName:'벽걸이 선반 플로팅 원목 60cm', price:29900, reviewCount:12800, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=벽걸이선반플로팅', imageUrl:IMG.furniture },
        { rank:6, productName:'조명 간접등 버티컬 블라인드', price:59000, reviewCount:8420, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=버티컬블라인드', imageUrl:IMG.lamp },
        { rank:7, productName:'인조식물 수국 화병 세트 인테리어', price:19900, reviewCount:18200, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=인조식물수국화병', imageUrl:IMG.lamp },
        { rank:8, productName:'캔버스 그림 액자 현대미술 50×70', price:34900, reviewCount:9150, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=캔버스그림액자', imageUrl:IMG.lamp },
        { rank:9, productName:'러그 거실 면 북유럽 160×230', price:89000, reviewCount:6720, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=거실러그북유럽', imageUrl:IMG.bedding },
        { rank:10, productName:'수납 바구니 라탄 소형 3개', price:24900, reviewCount:14200, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=라탄수납바구니', imageUrl:IMG.container },
      ],
      digital: [
        { rank:1, productName:'삼성 갤럭시 A55 256GB 자급제', price:498000, reviewCount:3240, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=갤럭시A55자급제', imageUrl:IMG.phone },
        { rank:2, productName:'LG 올레드 TV 55인치 4K', price:998000, reviewCount:1820, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=LG올레드TV55인치', imageUrl:IMG.tv },
        { rank:3, productName:'애플 맥북에어 M3 15인치', price:1590000, reviewCount:2840, rating:4.9, productUrl:'https://www.coupang.com/np/search?q=맥북에어M3', imageUrl:IMG.laptop },
        { rank:4, productName:'아이패드 10세대 64GB 와이파이', price:598000, reviewCount:4120, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=아이패드10세대', imageUrl:IMG.tablet },
        { rank:5, productName:'갤럭시 워치6 40mm 블루투스', price:248000, reviewCount:3890, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=갤럭시워치6', imageUrl:IMG.keyboard },
        { rank:6, productName:'에어팟 프로 2세대 USB-C', price:219000, reviewCount:8420, rating:4.9, productUrl:'https://www.coupang.com/np/search?q=에어팟프로2세대', imageUrl:IMG.earphone },
        { rank:7, productName:'로지텍 MX Keys S 무선 키보드', price:129000, reviewCount:5430, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=로지텍MXKeysS', imageUrl:IMG.keyboard },
        { rank:8, productName:'삼성 T7 외장SSD 1TB 포터블', price:98000, reviewCount:6720, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=삼성T7외장SSD1TB', imageUrl:IMG.keyboard },
        { rank:9, productName:'소니 WH-1000XM5 노이즈캔슬링', price:389000, reviewCount:2840, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=소니WH1000XM5', imageUrl:IMG.earphone },
        { rank:10, productName:'닌텐도 스위치 OLED 화이트', price:398000, reviewCount:5610, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=닌텐도스위치OLED', imageUrl:IMG.game },
      ],
      sports: [
        { rank:1, productName:'요가매트 15mm 고밀도 TPE 논슬립', price:18900, reviewCount:22400, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=요가매트TPE논슬립', imageUrl:IMG.yogamat },
        { rank:2, productName:'아령 덤벨 세트 5kg×2', price:24900, reviewCount:15600, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=아령덤벨세트5kg', imageUrl:IMG.dumbbell },
        { rank:3, productName:'실내 자전거 스피닝 8단 저항', price:149000, reviewCount:8420, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=실내자전거스피닝', imageUrl:IMG.bike },
        { rank:4, productName:'캠핑 텐트 3~4인 오토캠핑', price:98000, reviewCount:6720, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=캠핑텐트오토', imageUrl:IMG.tent },
        { rank:5, productName:'등산화 방수 고어텍스 남여', price:89000, reviewCount:12800, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=등산화방수고어텍스', imageUrl:IMG.sneakers },
        { rank:6, productName:'폼롤러 32cm 근막이완 맛사지', price:19900, reviewCount:28900, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=폼롤러32cm', imageUrl:IMG.yogamat },
        { rank:7, productName:'런닝화 나이키 에어줌 페가수스', price:129000, reviewCount:9150, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=나이키에어줌페가수스', imageUrl:IMG.sneakers },
        { rank:8, productName:'스포츠 레깅스 기능성 여성 4종', price:29900, reviewCount:18200, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=스포츠레깅스기능성', imageUrl:IMG.pants },
        { rank:9, productName:'케틀벨 12kg 주철 코팅', price:29900, reviewCount:7340, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=케틀벨12kg', imageUrl:IMG.dumbbell },
        { rank:10, productName:'수영복 래쉬가드 UV차단 남', price:24900, reviewCount:14200, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=래쉬가드남성', imageUrl:IMG.tshirt },
      ],
      car: [
        { rank:1, productName:'차량용 방향제 나무 스틱형 3개', price:14900, reviewCount:28400, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=차량방향제나무스틱', imageUrl:IMG.car_mat },
        { rank:2, productName:'자동차 발매트 순정형 앞좌석', price:49900, reviewCount:15600, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=자동차발매트순정', imageUrl:IMG.car_mat },
        { rank:3, productName:'차량용 공기청정기 USB 소형', price:24900, reviewCount:18200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=차량공기청정기USB', imageUrl:IMG.vacuum },
        { rank:4, productName:'블랙박스 전후방 4K 2채널', price:189000, reviewCount:8420, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=블랙박스4K2채널', imageUrl:IMG.tv },
        { rank:5, productName:'카시트 주니어 3~12세 ISOFIX', price:129000, reviewCount:6720, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=카시트주니어ISOFIX', imageUrl:IMG.furniture },
        { rank:6, productName:'차량용 핸드폰 거치대 대시보드', price:19900, reviewCount:22400, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=차량핸드폰거치대', imageUrl:IMG.keyboard },
        { rank:7, productName:'자동차 세차용품 세트 7종', price:29900, reviewCount:12800, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=자동차세차용품세트', imageUrl:IMG.car_mat },
        { rank:8, productName:'차량용 점프스타터 보조배터리', price:49900, reviewCount:9150, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=차량점프스타터', imageUrl:IMG.battery },
        { rank:9, productName:'LED 차폭등 T10 웨지 6500K', price:9900, reviewCount:14200, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=차폭등T10LED', imageUrl:IMG.lamp },
        { rank:10, productName:'후방카메라 와이파이 무선 AHD', price:39900, reviewCount:7340, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=후방카메라와이파이', imageUrl:IMG.tv },
      ],
      book: [
        { rank:1, productName:'트렌드 코리아 2025 베스트셀러', price:18000, reviewCount:12800, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=트렌드코리아2025', imageUrl:IMG.book },
        { rank:2, productName:'도파민 네이션 아나 렘키 지음', price:16800, reviewCount:8420, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=도파민네이션', imageUrl:IMG.book },
        { rank:3, productName:'세이노의 가르침 전면개정판', price:14900, reviewCount:22400, rating:4.9, productUrl:'https://www.coupang.com/np/search?q=세이노의가르침', imageUrl:IMG.book },
        { rank:4, productName:'BTS 앤솔로지 화양연화 OST', price:29800, reviewCount:6720, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=BTS화양연화OST', imageUrl:IMG.book },
        { rank:5, productName:'원피스 106권 최신간', price:5500, reviewCount:9150, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=원피스106권', imageUrl:IMG.book },
        { rank:6, productName:'어른의 어휘력 유선경 저자', price:14900, reviewCount:15600, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=어른의어휘력', imageUrl:IMG.book },
        { rank:7, productName:'파친코 이민진 소설 2권 세트', price:28000, reviewCount:11200, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=파친코이민진2권', imageUrl:IMG.book },
        { rank:8, productName:'사피엔스 유발 하라리 전면개정', price:22000, reviewCount:18200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=사피엔스하라리개정', imageUrl:IMG.book },
        { rank:9, productName:'아기 그림책 월령별 12권 세트', price:39900, reviewCount:7340, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=아기그림책월령별12권', imageUrl:IMG.book },
        { rank:10, productName:'공무원 한국사 기본서 2025', price:28000, reviewCount:5430, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=공무원한국사2025', imageUrl:IMG.book },
      ],
      hobby: [
        { rank:1, productName:'레고 클래식 아이디어박스 484pcs', price:39900, reviewCount:18200, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=레고클래식아이디어박스', imageUrl:IMG.game },
        { rank:2, productName:'닌텐도 스위치 게임 마리오카트8', price:59800, reviewCount:12800, rating:4.9, productUrl:'https://www.coupang.com/np/search?q=닌텐도마리오카트8', imageUrl:IMG.game },
        { rank:3, productName:'보드게임 루미큐브 클래식', price:24900, reviewCount:15600, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=루미큐브클래식', imageUrl:IMG.game },
        { rank:4, productName:'퍼즐 1000조각 풍경 명화', price:19900, reviewCount:9150, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=퍼즐1000조각풍경', imageUrl:IMG.book },
        { rank:5, productName:'색연필 유성 72색 전문가용', price:29900, reviewCount:8420, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=색연필유성72색', imageUrl:IMG.book },
        { rank:6, productName:'다이아몬드 아트 키트 40×50', price:19900, reviewCount:14200, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=다이아몬드아트키트', imageUrl:IMG.book },
        { rank:7, productName:'RC카 오프로드 1:16 무선조종', price:49900, reviewCount:6720, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=RC카오프로드', imageUrl:IMG.game },
        { rank:8, productName:'미니어처 키트 방 꾸미기 DIY', price:34900, reviewCount:11200, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=미니어처키트DIY', imageUrl:IMG.game },
        { rank:9, productName:'통기타 입문용 41인치 어쿠스틱', price:89000, reviewCount:5430, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=통기타입문용41인치', imageUrl:IMG.book },
        { rank:10, productName:'무선 드론 접이식 카메라 4K', price:89000, reviewCount:7340, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=드론접이식4K', imageUrl:IMG.game },
      ],
      office: [
        { rank:1, productName:'포스트잇 654-5PK 76×76 5색 5패드', price:14900, reviewCount:28400, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=포스트잇654-5PK', imageUrl:IMG.book },
        { rank:2, productName:'A4 복사용지 75g 500매 5권', price:24900, reviewCount:35600, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=A4복사용지75g500매5권', imageUrl:IMG.book },
        { rank:3, productName:'모나미 153 볼펜 12자루 검정', price:4900, reviewCount:45200, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=모나미153볼펜12자루', imageUrl:IMG.book },
        { rank:4, productName:'듀얼 모니터 스탠드 가스실린더', price:49900, reviewCount:12800, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=듀얼모니터스탠드', imageUrl:IMG.keyboard },
        { rank:5, productName:'노트북 거치대 접이식 알루미늄', price:29900, reviewCount:18200, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=노트북거치대알루미늄', imageUrl:IMG.laptop },
        { rank:6, productName:'인체공학 의자 메쉬 요추지지', price:198000, reviewCount:8420, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=인체공학의자메쉬', imageUrl:IMG.furniture },
        { rank:7, productName:'책상 정리함 서랍 3단 A4', price:24900, reviewCount:15600, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=책상정리함서랍3단', imageUrl:IMG.container },
        { rank:8, productName:'마카 트윈팁 수성 60색 세트', price:29900, reviewCount:9150, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=마카트윈팁60색', imageUrl:IMG.book },
        { rank:9, productName:'스카치 투명 테이프 33m 10개입', price:9900, reviewCount:22400, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=스카치투명테이프33m', imageUrl:IMG.book },
        { rank:10, productName:'무선 마우스 로지텍 M650 조용한', price:39900, reviewCount:14200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=로지텍M650무선마우스', imageUrl:IMG.keyboard },
      ],
      pet: [
        { rank:1, productName:'하림 더 리얼 소프트 강아지 사료 1.2kg', price:18900, reviewCount:28400, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=하림더리얼강아지사료', imageUrl:IMG.dogfood },
        { rank:2, productName:'자동 급식기 5L 앱 연동 타이머', price:39800, reviewCount:12800, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=자동급식기5L앱연동', imageUrl:IMG.feeder },
        { rank:3, productName:'오리지널 고양이 모래 두부 10kg', price:22900, reviewCount:22400, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=두부고양이모래10kg', imageUrl:IMG.catlit },
        { rank:4, productName:'강아지 패드 와이드 60×90 100매', price:24800, reviewCount:35600, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=강아지패드와이드100매', imageUrl:IMG.dogpad },
        { rank:5, productName:'캣타워 스크래처 4단 대형', price:69800, reviewCount:8420, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=캣타워스크래처4단', imageUrl:IMG.cattower },
        { rank:6, productName:'펫 이동가방 백팩 투명창 소형견', price:49900, reviewCount:9150, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=펫백팩투명창', imageUrl:IMG.bag },
        { rank:7, productName:'강아지 하네스 목줄 세트 S~XL', price:19900, reviewCount:18200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=강아지하네스목줄세트', imageUrl:IMG.dogpad },
        { rank:8, productName:'고양이 장난감 낚싯대 깃털 5종', price:14900, reviewCount:22400, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=고양이낚싯대깃털', imageUrl:IMG.cattower },
        { rank:9, productName:'강아지 간식 져키 닭가슴살 500g', price:15900, reviewCount:28900, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=강아지간식닭가슴살져키', imageUrl:IMG.dogfood },
        { rank:10, productName:'펫 스파 드라이어 조용한 1200W', price:89000, reviewCount:5430, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=펫드라이어조용한', imageUrl:IMG.vacuum },
      ],
      health: [
        { rank:1, productName:'오메가3 rTG형 고함량 EPA+DHA 90', price:19800, reviewCount:45200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=오메가3rTG고함량', imageUrl:IMG.omega3 },
        { rank:2, productName:'프로바이오틱스 유산균 60억 30포', price:24800, reviewCount:38400, rating:4.8, productUrl:'https://www.coupang.com/np/search?q=유산균60억30포', imageUrl:IMG.probiotic },
        { rank:3, productName:'비타민D3 2000IU 90정 6개월치', price:12900, reviewCount:28900, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=비타민D3 2000IU90정', imageUrl:IMG.vitamin },
        { rank:4, productName:'마그네슘 글리시네이트 킬레이트', price:18900, reviewCount:22400, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=마그네슘글리시네이트킬레이트', imageUrl:IMG.vitamin },
        { rank:5, productName:'종합비타민 멀티 영양제 60정', price:19800, reviewCount:32100, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=종합비타민멀티영양제', imageUrl:IMG.vitamin },
        { rank:6, productName:'콜라겐 저분자 마린 파우더 300g', price:32000, reviewCount:18200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=마린콜라겐파우더', imageUrl:IMG.protein },
        { rank:7, productName:'루테인 지아잔틴 눈 건강 60정', price:14900, reviewCount:19800, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=루테인지아잔틴눈건강', imageUrl:IMG.vitamin },
        { rank:8, productName:'밀크씨슬 실리마린 간 건강 100정', price:16900, reviewCount:15600, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=밀크씨슬실리마린', imageUrl:IMG.probiotic },
        { rank:9, productName:'크레아틴 모노하이드레이트 500g', price:24900, reviewCount:12800, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=크레아틴모노하이드레이트', imageUrl:IMG.protein },
        { rank:10, productName:'철분제 킬레이트 임산부 영양제', price:19800, reviewCount:9150, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=철분제킬레이트임산부', imageUrl:IMG.vitamin },
      ],
      travel: [
        { rank:1, productName:'여행용 캐리어 20인치 경량 TSA', price:89000, reviewCount:18200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=여행캐리어20인치경량', imageUrl:IMG.bag },
        { rank:2, productName:'여행 세면도구 파우치 실리콘 소분', price:19900, reviewCount:28400, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=여행세면도구파우치', imageUrl:IMG.container },
        { rank:3, productName:'목베개 여행용 폼 기억 쿨링', price:24900, reviewCount:15600, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=목베개여행폼', imageUrl:IMG.bedding },
        { rank:4, productName:'해외여행 멀티 어댑터 전세계', price:19900, reviewCount:22400, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=해외여행멀티어댑터', imageUrl:IMG.battery },
        { rank:5, productName:'캐리어 커버 방수 20~28인치', price:14900, reviewCount:12800, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=캐리어커버방수', imageUrl:IMG.bag },
        { rank:6, productName:'넥 파우치 여행용 RFID차단 목걸이', price:12900, reviewCount:18200, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=넥파우치RFID차단', imageUrl:IMG.bag },
        { rank:7, productName:'압축팩 여행용 10개 세트 지퍼', price:15900, reviewCount:22400, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=압축팩여행10개세트', imageUrl:IMG.container },
        { rank:8, productName:'여행용 자물쇠 TSA 비밀번호', price:9900, reviewCount:28900, rating:4.6, productUrl:'https://www.coupang.com/np/search?q=여행자물쇠TSA', imageUrl:IMG.container },
        { rank:9, productName:'도자기 시크릿 여행 에센셜 키트', price:39900, reviewCount:9150, rating:4.7, productUrl:'https://www.coupang.com/np/search?q=도자기시크릿여행키트', imageUrl:IMG.mask },
        { rank:10, productName:'항공권 수하물 무게 저울 전자', price:14900, reviewCount:14200, rating:4.5, productUrl:'https://www.coupang.com/np/search?q=수하물무게저울전자', imageUrl:IMG.keyboard },
      ],
    };
    items = samples[catKey] || samples.best;
    if (q) {
      const allSamples = Object.values(samples).flat();
      items = allSamples.filter(i => i.productName && i.productName.includes(q));
      if (!items.length) items = [{ rank:1, productName: q + ' 검색결과', price:0, reviewCount:0, rating:0, productUrl:'https://www.coupang.com/np/search?q=' + encodeURIComponent(q), imageUrl:'' }];
    }
  }

  if (!q) { _productCaches[cacheKey] = { data: items, cachedAt: now }; }
  if (q) items = items.filter(i => i.productName && i.productName.includes(q));

  res.json(items);
});

// GET /api/coupang/settings - 쿠팡 파트너스 설정 조회 (관리자)
app.get('/api/coupang/settings', adminAuth, (req, res) => {
  const s = getSettings();
  res.json({
    coupangPartnersEnabled: !!s.coupangPartnersEnabled,
    coupangPartnerAccessKey: s.coupangPartnerAccessKey || '',
    coupangPartnerSecretKey: s.coupangPartnerSecretKey || '',
    coupangPartnerSubIdDefault: s.coupangPartnerSubIdDefault || 'app',
    coupangDeepLinkMode: s.coupangDeepLinkMode || 'template',
    partnerId: COUPANG_PARTNER_ID
  });
});

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
    if (user?.plan !== 'pro' && user?.plan !== 'free') return res.status(403).json({ error: 'pro_only' });
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
    if (u.role === 'admin') return;
    // 베이직은 expiresAt 항상 null (영구)
    if (u.plan === 'basic') {
      if (u.expiresAt !== null && u.expiresAt !== undefined) {
        u.expiresAt = null; changed = true;
      }
      return;
    }
    if (u.expiresAt && new Date(u.expiresAt) < now && u.status === 'approved') {
      u.plan = 'basic';
      u.expiresAt = null;
      u.accountLimit = 0;
      u.dailyPublishLimit = 0;
      u._downgradedAt = now.toISOString();
      changed = true;
      console.log(`[EXPIRE] ${u.nickname} 만료 → 베이직 강등`);
    }
  });
  if (changed) saveJSON(`${DATA_ROOT}/users.json`, users);
});

// ── 서버 시작 시 만료 유저 즉시 베이직 전환 ──
(function fixExpiredUsers() {
  const now = new Date();
  let changed = false;
  users.forEach(u => {
    if (u.role === 'admin') return;
    // 베이직인데 expiresAt이 있으면 null로
    if (u.plan === 'basic' && u.expiresAt) {
      u.expiresAt = null; changed = true;
      console.log(`[FIX] ${u.nickname} 베이직 expiresAt 제거`);
    }
    // 만료된 유저 베이직으로 강등
    if (u.plan !== 'basic' && u.expiresAt && new Date(u.expiresAt) < now && u.status === 'approved') {
      u.plan = 'basic';
      u.expiresAt = null;
      u.accountLimit = 0;
      u.dailyPublishLimit = 0;
      u._downgradedAt = now.toISOString();
      changed = true;
      console.log(`[FIX] ${u.nickname} 만료 → 베이직 강등`);
    }
  });
  if (changed) {
    saveJSON(`${DATA_ROOT}/users.json`, users);
    console.log('[FIX] 만료 유저 베이직 강등 완료');
  }
})();

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
      if (user.plan !== 'pro' && user.plan !== 'free') continue;
    }
    const autoSchedules = getAutoSchedules(userId);
    const maxAuto = user.role === 'admin' ? 999 : (user.plan === 'free' ? 2 : 5); // 이벤트:2회, 프로:5회
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

        const postId = await publishToThreads(account.accessToken, text, [], []);
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
