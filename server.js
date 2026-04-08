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

// ── 데이터 루트 경로 (Railway Volume 마운트) ──
const DATA_ROOT = process.env.DATA_PATH || '/app/data';
if (!fs.existsSync(DATA_ROOT)) fs.mkdirSync(DATA_ROOT, { recursive: true });

// ── 파일 헬퍼 ──
function loadJSON(file, def) {
  try { return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : def; } catch(e) { return def; }
}
function saveJSON(file, data) {
  const dir = require('path').dirname(file);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// 입력값 sanitize (XSS 방지)
function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[<>]/g, '').trim().slice(0, 5000);
}

// ── 데이터 저장소 ──
let users       = loadJSON(`${DATA_ROOT}/users.json`, []);
let inviteCodes = loadJSON(`${DATA_ROOT}/invite_codes.json`, []);
// sessions는 loadSessions() 이후 아래에서 초기화됨
let sessions    = {}; // 임시, 아래 init에서 덮어씀

function userDir(userId) {
  const path = require('path');
  // Path Traversal 방지
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

// 일별 발행 횟수 추적
function getTodayKey() { return new Date().toISOString().slice(0, 10); }
function getPublishCount(userId) { return loadJSON(`${userDir(userId)}/publish_count.json`, {}); }
function savePublishCount(userId, data) { saveJSON(`${userDir(userId)}/publish_count.json`, data); }
// 계정별 발행 횟수 (accountId_날짜 키)
function getAccPublishKey(accountId) { return accountId + '_' + getTodayKey(); }
function saveAccounts(userId, data) { saveJSON(`${userDir(userId)}/accounts.json`, data); }
function getScheduled(userId) { return loadJSON(`${userDir(userId)}/scheduled.json`, []); }
function saveScheduled(userId, data) { saveJSON(`${userDir(userId)}/scheduled.json`, data); }

// ── 비밀번호 해시 ──
function hashPw(pw) {
  // PBKDF2 - SHA-256보다 강력한 해시
  return crypto.pbkdf2Sync(pw, 'threads_secure_salt_2025_!@#', 100000, 64, 'sha512').toString('hex');
}
function hashPwLegacy(pw) {
  // 기존 해시 (하위 호환용)
  return crypto.createHash('sha256').update(pw + 'threads_salt_2025').digest('hex');
}
function verifyPw(pw, storedHash) {
  // 새 해시 먼저 확인, 실패하면 기존 해시 확인
  if (hashPw(pw) === storedHash) return true;
  if (hashPwLegacy(pw) === storedHash) return true;
  return false;
}

// ── 세션 저장소 (파일 영속 + 만료시간) ──
const SESSION_TTL = 3 * 24 * 60 * 60 * 1000; // 3일
const SESSIONS_FILE = `${DATA_ROOT}/sessions.json`;

// 파일에서 세션 복원
function loadSessions() {
  try {
    if (!fs.existsSync(SESSIONS_FILE)) return {};
    const data = JSON.parse(fs.readFileSync(SESSIONS_FILE));
    // 만료된 세션 제거 후 반환
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

// 만료 세션 정리 (1시간마다)
setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const [token, s] of Object.entries(sessions)) {
    if (now > s.expiresAt) { delete sessions[token]; changed = true; }
  }
  if (changed) saveSessions();
}, 60 * 60 * 1000);

// ── Rate Limiting ──
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

// Rate limit 맵 정리 (10분마다)
setInterval(() => {
  const now = Date.now();
  for (const ip of Object.keys(rateLimitMap)) {
    rateLimitMap[ip] = (rateLimitMap[ip] || []).filter(t => now - t < 60000);
    if (!rateLimitMap[ip].length) delete rateLimitMap[ip];
  }
}, 10 * 60 * 1000);

// ── 세션 미들웨어 ──
function auth(req, res, next) {
  const token = req.headers['x-session']; // URL query 세션 제거 (보안)
  // 토큰 형식 검증 (UUID 형식이어야 함)
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

// ── 보안 HTTP 헤더 ──
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.removeHeader('X-Powered-By');
  next();
});

// ── 요청 크기 제한 ──
app.use(express.json({ limit: '10mb' }));

// ── 정적 파일 (로그인 전에도 접근 가능) ──
app.use(express.static('public'));

// ══════════════════════════════════
//  AUTH API
// ══════════════════════════════════

// 첫 번째 유저 여부 확인
app.get('/api/auth/is-first', (req, res) => res.json({ isFirst: users.length === 0 }));

// 긴급 비밀번호 리셋 (관리자 계정이 로그인 안될 때)
// 사용법: /api/auth/reset-admin?secret=RESET_2025&newpw=새비밀번호
app.get('/api/auth/reset-admin', (req, res) => {
  if (req.query.secret !== 'RESET_2025_THREADS') return res.status(403).json({ error: '권한 없음' });
  const newpw = req.query.newpw;
  if (!newpw || newpw.length < 6) return res.status(400).json({ error: '비밀번호 6자 이상' });
  const admin = users.find(u => u.role === 'admin');
  if (!admin) return res.status(404).json({ error: '관리자 없음' });
  admin.passwordHash = hashPw(newpw);
  delete admin.password;
  saveJSON(`${DATA_ROOT}/users.json`, users);
  console.log('[RESET] 관리자 비밀번호 리셋됨');
  res.json({ ok: true, nickname: admin.nickname, message: '비밀번호 변경 완료' });
});

// 최초 관리자 가입 (유저 0명일 때만)
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

// 가입 (유저 0명이면 초대코드 없이 관리자, 이후엔 초대코드 필수)
app.post('/api/auth/register', rateLimit(3, 60000), (req, res) => {
  const { nickname, password, inviteCode } = req.body;
  if (!nickname || !password) return res.status(400).json({ error: '닉네임과 비밀번호 필요' });
  if (users.find(u => u.nickname === nickname)) return res.status(400).json({ error: '이미 사용중인 닉네임' });

  let role = 'user';
  if (users.length === 0) {
    // 첫 번째 유저 → 관리자
    role = 'admin';
  } else {
    // 이후엔 초대코드 필수
    if (!inviteCode) return res.status(400).json({ error: '초대코드가 필요해' });
    const invite = inviteCodes.find(c => c.code === inviteCode);
    if (!invite) return res.status(400).json({ error: '유효하지 않은 초대코드' });
    if (invite.status === 'done') return res.status(400).json({ error: '만료된 초대코드야. 새 코드를 받아줘.' });
    invite.lastUsedBy = nickname; invite.lastUsedAt = new Date().toISOString();
    invite.useCount = (invite.useCount || 0) + 1;
    saveJSON(`${DATA_ROOT}/invite_codes.json`, inviteCodes);
    // 공동대표 코드로 가입 여부 기록
    const settings = getSettings();
    if (settings.partnerCode && inviteCode === settings.partnerCode) {
      // joinedVia = 'partner' 로 기록 (user 생성 시 아래서 처리)
      req.body._partnerJoin = true;
    }
  }

  const status = role === 'admin' ? 'approved' : 'pending';
  const user = { id: Date.now().toString(), nickname, name: req.body.name || '', passwordHash: hashPw(password), role, status, joinedVia: req.body._partnerJoin ? 'partner' : 'normal', createdAt: new Date().toISOString() };
  users.push(user);
  saveJSON(`${DATA_ROOT}/users.json`, users);
  if (user.status === 'pending') {
    res.json({ pending: true, nickname: user.nickname });
    return;
  }
  const token = createSession(user.id);
  res.json({ token, nickname: user.nickname, role: user.role });
});

// 로그인
app.post('/api/auth/login', rateLimit(5, 60000), (req, res) => {
  const nickname = sanitize(req.body.nickname || '');
  const password = req.body.password || '';
  if (!nickname || !password) return res.status(400).json({ error: '닉네임과 비밀번호 필요' });
  if (nickname.length > 30 || password.length > 100) return res.status(400).json({ error: '입력값 오류' });
  // passwordHash 또는 password 필드 모두 지원 (마이그레이션 호환)
  const user = users.find(u => {
    if (u.nickname !== nickname) return false;
    const stored = u.passwordHash || u.password || '';
    return verifyPw(password, stored);
  });
  if (!user) return res.status(401).json({ error: '닉네임 또는 비밀번호 오류' });
  if (user.status === 'pending') return res.status(403).json({ error: 'pending' });
  if (user.status === 'suspended') return res.status(403).json({ error: 'suspended' });
  // 사용기간 만료 체크
  if (user.expiresAt && new Date() > new Date(user.expiresAt) && user.role !== 'admin') {
    return res.status(403).json({ error: 'expired' });
  }
  // 구버전 해시면 새 해시로 마이그레이션
  const stored = user.passwordHash || user.password || '';
  if (stored !== hashPw(password)) {
    user.passwordHash = hashPw(password);
    delete user.password;
    saveJSON(`${DATA_ROOT}/users.json`, users);
  }
  const token = createSession(user.id);
  res.json({ token, nickname: user.nickname, role: user.role });
});

// 로그아웃
app.post('/api/auth/logout', auth, (req, res) => {
  const token = req.headers['x-session'];
  delete sessions[token];
  saveSessions();
  res.json({ ok: true });
});

// 내 정보
app.get('/api/auth/me', auth, (req, res) => {
  const u = req.user;
  const today = getTodayKey();
  const counts = getPublishCount(u.id);
  const genUsed = counts['gen_' + today] || 0;
  const genLimit = u.plan === 'free' ? 100 : 200; // 무료 100, 나머지 200
  res.json({
    id: u.id,
    nickname: u.nickname,
    name: u.name || '',
    role: u.role,
    plan: u.plan || 'free',
    accountLimit: u.accountLimit || 1,
    expiresAt: u.expiresAt || null,
    genUsed: genUsed,
    genLimit: genLimit,
    status: u.status || 'approved'
  });
});

// ══════════════════════════════════
//  초대코드 관리 (관리자 전용)
// ══════════════════════════════════

app.get('/api/invites', adminAuth, (req, res) => res.json(inviteCodes));

// 설정 (카카오 링크 등)
app.get('/api/settings', auth, (req, res) => res.json(getSettings()));

// 베이직 유저 주제 태그 저장
app.put('/api/settings/basic-tags', auth, (req, res) => {
  const user = users.find(u => u.id === req.userId);
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
  // active 코드가 이미 2개면 가장 오래된 것 만료
  const activeCodes = inviteCodes.filter(c => c.status !== 'done');
  if (activeCodes.length >= 2) {
    activeCodes[0].status = 'done'; // 가장 오래된 것 만료
  }
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

// 유저 목록 (관리자)
app.get('/api/users', adminAuth, (req, res) => {
  res.json(users.map(u => ({ id: u.id, nickname: u.nickname, name: u.name||'', role: u.role, status: u.status||'approved', plan: u.plan||'free', accountLimit: u.accountLimit||2, dailyPublishLimit: u.dailyPublishLimit||null, limitRequest: u.limitRequest||null, extendRequest: u.extendRequest||null, upgradeRequest: u.upgradeRequest||null, planChangeRequest: u.planChangeRequest||null, joinedVia: u.joinedVia||'normal', approvedAt: u.approvedAt||null, expiresAt: u.expiresAt||null, createdAt: u.createdAt, isExpired: u.expiresAt ? new Date(u.expiresAt) < new Date() : false })));
});

app.delete('/api/users/:id', adminAuth, (req, res) => {
  if (req.params.id === req.userId) return res.status(400).json({ error: '본인 삭제 불가' });
  users = users.filter(u => u.id !== req.params.id);
  saveJSON(`${DATA_ROOT}/users.json`, users);
  res.json({ ok: true });
});

// 유료 전환 신청
app.post('/api/users/upgrade-request', auth, (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: '없음' });
  if (user.plan !== 'free') return res.status(400).json({ error: '이미 유료 계정이야' });
  if (user.upgradeRequest) return res.status(400).json({ error: '이미 신청 중이야' });
  user.upgradeRequest = { requestedAt: new Date().toISOString() };
  saveJSON(`${DATA_ROOT}/users.json`, users);
  res.json({ ok: true });
});

// 계정 한도 변경 요청 (유저가 직접)
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
    // 기간 연장 신청
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

// 유저 상태 변경 (승인/정지/활성화) + 계정 한도
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
    if (req.body.plan === 'basic') {
      user.accountLimit = 0; // 계정 불필요
      user.dailyPublishLimit = 0; // 발행 불가
    } else if (req.body.plan === 'pro') {
      user.accountLimit = 2;
      user.dailyPublishLimit = 3;
    } else if (req.body.plan === 'premium') {
      user.accountLimit = 6;
      user.dailyPublishLimit = 5;
    } else if (req.body.plan === 'free') {
      user.accountLimit = 1;
      user.dailyPublishLimit = 2;
    }
  }
  // 재승인 시 플랜 변경
  if (req.body.changePlan) {
    user.plan = req.body.plan;
    if (req.body.plan === 'basic') { user.accountLimit = 0; user.dailyPublishLimit = 0; }
    else if (req.body.plan === 'pro') { user.accountLimit = 2; user.dailyPublishLimit = 3; }
    else if (req.body.plan === 'premium') { user.accountLimit = 6; user.dailyPublishLimit = 5; }
    const base = user.expiresAt && new Date(user.expiresAt) > new Date() ? new Date(user.expiresAt) : new Date();
    user.expiresAt = new Date(base.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
  }
  if (req.body.accountLimit) {
    user.accountLimit = req.body.accountLimit;
    user.limitRequest = null;
  }
  if (req.body.clearLimitRequest) user.limitRequest = null;
  if (req.body.extendDays) {
    const base = user.expiresAt && new Date(user.expiresAt) > new Date() ? new Date(user.expiresAt) : new Date();
    user.expiresAt = new Date(base.getTime() + Number(req.body.extendDays) * 24 * 60 * 60 * 1000).toISOString();
    user.extendRequest = null;
  }
  // 플랜 변경 + 기간 설정 (관리자가 유저 목록에서 클릭)
  if (req.body.setPlan) {
    user.plan = req.body.setPlan;
    if (req.body.setPlan === 'basic') { user.accountLimit = 0; user.dailyPublishLimit = 0; }
    else if (req.body.setPlan === 'pro') { user.accountLimit = 2; user.dailyPublishLimit = 3; }
    else if (req.body.setPlan === 'premium') { user.accountLimit = 6; user.dailyPublishLimit = 5; }
    const planDays = req.body.setPlan === 'premium' ? 60 : 30;
    const base2 = user.expiresAt && new Date(user.expiresAt) > new Date() ? new Date(user.expiresAt) : new Date();
    user.expiresAt = new Date(base2.getTime() + planDays * 24 * 60 * 60 * 1000).toISOString();
    if (!user.approvedAt) { user.approvedAt = new Date().toISOString(); user.status = 'approved'; }
    user.planChangeRequest = null;
  }
  if (req.body.denyExtend) user.extendRequest = null;
  if (req.body.approveUpgrade) {
    user.plan = 'paid';
    user.dailyPublishLimit = null; // 기본값(5개)으로 복원
    user.upgradeRequest = null;
    if (req.body.accountLimit) user.accountLimit = req.body.accountLimit;
    // 30일 추가
    const base = user.expiresAt && new Date(user.expiresAt) > new Date() ? new Date(user.expiresAt) : new Date();
    user.expiresAt = new Date(base.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
    if (!user.approvedAt) user.approvedAt = new Date().toISOString();
  }
  if (req.body.denyUpgrade) user.upgradeRequest = null;
  if (req.body.denyPlanChange) user.planChangeRequest = null;
  saveJSON(`${DATA_ROOT}/users.json`, users);
  res.json({ ok: true });
});

// ══════════════════════════════════
//  Threads 계정 관리 (유저별)
// ══════════════════════════════════

app.get('/api/accounts', auth, (req, res) => {
  const accs = getAccounts(req.userId);
  // 토큰은 앞 6자리만 노출
  res.json(accs.map(a => ({ ...a, accessToken: (a.accessToken || '').slice(0, 6) + '...' + (a.accessToken || '').slice(-4), tokenRegisteredAt: a.tokenRegisteredAt || null })));
});

app.post('/api/accounts', auth, (req, res) => {
  const { name, accessToken, topics } = req.body;
  if (!name || !accessToken) return res.status(400).json({ error: '이름과 토큰 필요' });
  const accs = getAccounts(req.userId);
  // 관리자는 무제한, 일반 유저는 accountLimit 기준
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
//  AI 글 생성
// ══════════════════════════════════

app.post('/api/generate', auth, rateLimit(30, 60000), async (req, res) => {
  // 플랜별 하루 생성 제한
  const genUser = users.find(u => u.id === req.userId);
  if (genUser && genUser.role !== 'admin') {
    const genCount = getPublishCount(req.userId);
    const genKey = 'gen_' + getTodayKey();
    const genLimit = genUser.plan === 'free' ? 100 : 200; // 무료 100, 나머지 200
    if ((genCount[genKey] || 0) >= genLimit) {
      return res.status(429).json({ error: '오늘 글 생성 한도(' + genLimit + '번)를 초과했어. 내일 다시 시도해줘.' });
    }
    genCount[genKey] = (genCount[genKey] || 0) + 1;
    savePublishCount(req.userId, genCount);
  }
  const { topic, tone, type, imageDesc, userPrompt, commentPrompt } = req.body;
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'GROQ_API_KEY 없음' });

  const imgContext = imageDesc ? `\n[이미지 분석 결과 - 이 상품/내용으로 글 작성]: ${imageDesc}` : '';
  const customUserPrompt = userPrompt ? String(userPrompt).slice(0, 500) : '';
  const customCommentPrompt = commentPrompt ? String(commentPrompt).slice(0, 300) : '';

  const tonePrompts = {
    '리스트형': `SNS 리스트형 글. 번호나 줄 나열. 핵심만. 일부 정보는 숨겨서 궁금하게.

[절대 금지]
- "~인데요", "~습니다" 같은 뻔한 시작 금지
- 교과서 같은 정리 금지
- 너무 예의바른 말투 금지

[예시]
요즘 사람들이 많이 찾던데
1. 이래서 쓰는 거였음
2. 이 부분이 생각보다 쓸만함
3. 이건 솔직히 좀 아쉬움
나머지는 댓글에 씀`,

    '정보성': `SNS 정보형 글. 아는 척 말고 알게 된 척.

[절대 금지]
- "안녕하세요", "오늘은 ~에 대해" 같은 뻔한 시작 금지
- 너무 친절한 설명 금지
- 뻔한 결말 금지

[예시]
모르면 진짜 손해인 것들
대부분 이렇게 쓰는데 그게 아니라
이렇게 쓰면 훨씬 낫더라
자세한 건 댓글`,

    '리뷰형': `실제로 써본 사람 느낌. 솔직하게. 좋은 것만 말하지 말고.

[절대 금지]
- "안녕하세요 오늘은 리뷰" 이런 시작 절대 금지
- 지나치게 칭찬하는 말 금지

[예시]
솔직히 별로일 줄 알았는데
생각보다 괜찮아서 당황함
근데 이 부분은 좀 걸림
전반적으로는 쓸 것 같음`,

    '일상': `그냥 하는 일상 얘기. 평범하게. 특별한 사건 없어도 됨.

[절대 금지]
- "오늘 정말 특별한 하루였어요" 같은 과장 금지
- 억지 스토리 금지
- 교훈 금지

[예시]
오늘 그냥 아무 생각 없이 해봤는데
생각보다 나쁘지 않음
왜 진작 안 했지`,

    '공감형': `모두가 겪는 상황. 짧게. 마지막에 공감 유도.

[절대 금지]
- 억지 공감 금지
- 너무 길게 설명 금지

[예시]
나만 이런 거 아니지
뭔가 하려고 하면 꼭 이런 일이 생김
진짜 왜 이러냐`,

    '스토리형': `짧은 일화. 결론보다 과정이 재밌어야 함. 억지 교훈 금지.

[절대 금지]
- "그 날 이후로 나는 달라졌다" 같은 뻔한 결말 절대 금지
- 드라마 같은 전개 금지
- 교훈으로 마무리 금지

[예시]
어제 완전 황당한 일이 있었는데
결국 별거 아니었음
근데 생각할수록 웃기네`,

    '쿠팡/홍보': `너는 일상 SNS 글을 쓰는 평범한 사람이다. 절대 광고처럼 보이면 안 된다.

[핵심 원칙]
- 내 것이 아닌 척. 그냥 일상 얘기하듯이.
- 사진/영상을 보고 궁금하게만 만들면 된다. 글로 다 설명하지 마라.
- 1~2줄. 무조건 짧게. 길면 광고처럼 보인다.
- 구매 유도 표현 절대 금지. "사봐", "추천", "클릭" 이런 말 절대 하지 마라.

[예시 — 이 느낌으로]
강아지: 우리 강아지는 밤만 되면 이 난리ㅠㅠ 하나 바꿨는데 밤에 좀 덜해졌어
음식: 남편이 또 이것만 달래 이제 진짜 지겨워
아기: 우리 애기 없으면 밥 안 먹음 ㅋㅋ
생활용품: 쓰고 나서 예전으로 못 돌아가겠다
고양이: 얘가 왜 이걸 이렇게 좋아하는지 모르겠음

[절대 규칙]
- 이모지 금지 (ㅠㅠ, ㅋㅋ 같은 자음은 가능)
- 반말만
- 제품명/브랜드명 직접 언급 금지. 꼭 필요하면 한 번만 대명사 사용. 남발 금지.
- 구매 유도 문장 절대 금지
- 1~2줄 엄수. 3줄 넘으면 안 됨
- 예시 복붙 금지. 주제에 맞게 새로 창작`,

    '쿠팡': `너는 일상 SNS 글을 쓰는 평범한 사람이다. 절대 광고처럼 보이면 안 된다.
1~2줄. 경험담처럼. 사진 보고 궁금하게만 만들면 됨. 구매유도 금지. 제품명 금지. 반말.`
  };

  const toneInstruction = tonePrompts[tone] || tonePrompts['일상'];

  const systemMsg = `너는 한국어 콘텐츠 전문 작가다.

[절대 언어 규칙]
- 반드시 한국어(한글 + 숫자 + 기본 특수문자)만 사용한다.
- 한자, 일본어, 영어 단어를 절대 사용하지 않는다.
- 외래어도 가능한 순수 한국어로 바꿔 작성한다.
- 단, 주제에 직접 적혀있는 영어 단어는 그대로 사용 가능.
- 작성 후 한글 외 문자가 있으면 전체 문장을 다시 작성한다.

[위트·스타일 규칙]
- 센스 있는 개그우먼처럼 드립도 칠 줄 알고 위트 있게 작성한다.
- 뻔한 말 절대 금지: "건강에 좋다", "꼭 해보세요", "정말 좋습니다" 등 금지.
- 예상을 비트는 표현, 첫 줄 바로 훅, 친구가 하는 말처럼 자연스럽게.
- 과장 없이 신뢰감 있게, 읽기 쉬운 문장.

[작성 규칙]
- 이모지 절대 사용 금지.
- 반말로만 작성 (존댓말, ~합니다, ~해요 절대 금지).
- 같은 단어, 같은 표현 반복 금지.
- 게시글 텍스트만 출력 (설명, 주석, 따옴표 없이).
- 제품명, 브랜드명 직접 언급 금지. 꼭 필요할 때만 대명사 사용, 남발 금지.
- "이거", "요거", "이것" 같은 표현 반복 사용 금지. 꼭 필요한 경우만 한 번.
- 리스트형 말투가 아닌 이상 번호(1. 2. 3.)나 불릿(- * •) 절대 사용 금지.
- 간결하고 포인트 있게. 군더더기 없이. 읽히는 흐름이 자연스러워야 함.
- 한 문장에 하나의 생각만. 복잡하게 엮지 말 것.

[줄바꿈 규칙]
- 2~3문장마다 줄바꿈 1번.
- 한 문장마다 줄바꿈 금지.
- 문단 전환 시에만 빈 줄 1개.`;

  let prompt = '';
  if (type === 'comment') {
    const commentExtra = customCommentPrompt ? '\n추가 지침: ' + customCommentPrompt : '';
    prompt = '댓글 1개만 작성해줘.\n주제: ' + (topic||'') + imgContext + '\n규칙: 반말, 1~2문장, 이모지 금지, 한국어만, 댓글 텍스트만 출력' + commentExtra;
  } else {
    const userExtra = customUserPrompt ? '\n\n[사용자 추가 지침 - 반드시 반영]\n' + customUserPrompt : '';
    prompt = toneInstruction + '\n\n주제: ' + (topic||'') + imgContext + userExtra + '\n\n위 형식에 맞게 위트 있고 자연스러운 Threads 게시글을 작성해줘.\n반드시 한국어로만, 반말로, 이모지 없이, 게시글 텍스트만 출력해.';
  }

  try {
    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: systemMsg },
          { role: 'user', content: prompt }
        ],
        temperature: 0.85,
        max_tokens: 600
      })
    });
    const data = await r.json();
    if (data.error) throw new Error(data.error.message);
    let text = (data.choices?.[0]?.message?.content || '').trim();
    if (!text) return res.status(500).json({ error: '글 생성 실패' });

    // ── 한국어 필터링 (한자/일본어/중국어 제거) ──
    // ── 한국어 필터링 (한자/일본어/중국어 제거) ──
    const hasForeign = /[\u3400-\u4DBF\u4E00-\u9FFF\u3040-\u309F\u30A0-\u30FF\uF900-\uFAFF]/.test(text);
    if (hasForeign) {
      console.log('[GEN] 외국어 감지 - 제거');
      text = text.replace(/[\u3400-\u4DBF\u4E00-\u9FFF\u3040-\u309F\u30A0-\u30FF\uF900-\uFAFF]/g, '');
      text = text.replace(/  +/g, ' ').trim();
    }

    // ── 줄바꿈 보장 ──
    if (text.indexOf('\n') === -1 && text.length > 40) {
      text = text.replace(/([.!?]) /g, '$1\n');
    }

        res.json({ text });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 이미지 분석 (Groq vision)
app.post('/api/analyze-image', auth, async (req, res) => {
  const { imageUrl } = req.body;
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'GROQ_API_KEY 없음' });
  if (!imageUrl) return res.status(400).json({ error: 'imageUrl 필요' });

  // Groq에서 지원하는 vision 모델 순서대로 시도
  const visionModels = [
    'meta-llama/llama-4-scout-17b-16e-instruct',
    'meta-llama/llama-4-scout-17b-16e-instruct',
    'llava-v1.5-7b-4096-preview'
  ];

  for (const model of visionModels) {
    try {
      const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        body: JSON.stringify({
          model,
          messages: [{
            role: 'user',
            content: [
              { type: 'image_url', image_url: { url: imageUrl } },
              { type: 'text', text: '이 이미지에서 보이는 것을 한국어로 짧게 설명해줘. 상품이면 상품명과 특징, 음식이면 종류와 느낌, 동물이면 종류와 행동. 1~2문장으로 핵심만.' }
            ]
          }],
          max_tokens: 150
        })
      });
      const data = await r.json();
      if (data.error) { console.log(model, '실패:', data.error.message); continue; }
      const desc = data.choices?.[0]?.message?.content || '';
      console.log('이미지 분석 성공:', model, desc);
      return res.json({ desc });
    } catch(e) { console.log(model, '에러:', e.message); }
  }
  res.json({ desc: '' });
});

// ══════════════════════════════════
//  Threads 발행
// ══════════════════════════════════

async function publishToThreads(accessToken, text, imageUrls = [], videoUrl = '') {
  let containerId;
  // 미디어 URL SSRF 검증
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
    await new Promise(r => setTimeout(r, 30000)); // 영상 처리 대기 30초
  } else if (imageUrls.length === 0) {
    console.log('[PUBLISH] 텍스트 발행 시작');
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'TEXT', text, access_token: accessToken }) });
    const d = await r.json();
    console.log('[PUBLISH] Threads TEXT 응답:', JSON.stringify(d));
    if (d.error) throw new Error(d.error.message);
    containerId = d.id;
  } else if (imageUrls.length === 1) {
    console.log('[PUBLISH] 이미지 발행 시작');
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'IMAGE', image_url: imageUrls[0], text, access_token: accessToken }) });
    const d = await r.json();
    console.log('[PUBLISH] Threads API 응답:', JSON.stringify(d));
    if (d.error) throw new Error(d.error.message);
    containerId = d.id;
    await new Promise(r => setTimeout(r, 30000)); // 이미지 처리 대기 30초
  } else {
    const childIds = [];
    for (const url of imageUrls) {
      const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'IMAGE', image_url: url, is_carousel_item: true, access_token: accessToken }) });
      const d = await r.json(); if (d.error) throw new Error(d.error.message);
      childIds.push(d.id);
    }
    await new Promise(r => setTimeout(r, 30000)); // 이미지 처리 대기 30초
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

// 댓글 달기 함수
async function replyToThread(accessToken, postId, commentText) {
  const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ media_type: 'TEXT', text: commentText, reply_to_id: postId, access_token: accessToken })
  });
  const d = await r.json();
  if (d.error) throw new Error(d.error.message);
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
  const text = sanitize(req.body.text || '').slice(0, 500); // Threads 500자 제한
  const commentText = sanitize(req.body.commentText || '').slice(0, 500);
  if (!text) return res.status(400).json({ error: '글 내용 필요' });
  const accs = getAccounts(req.userId);
  const account = accs.find(a => a.id === accountId);
  if (!account) {
    console.error('[PUBLISH] 계정 없음 - accountId:', accountId, '등록계정:', accs.map(a=>a.id));
    return res.status(404).json({ error: '계정 없음' });
  }

  // 일별 발행 횟수 체크
  const user = users.find(u => u.id === req.userId);

  // 베이직 플랜은 발행 완전 차단
  if (user?.plan === 'basic') {
    return res.status(403).json({ error: '베이직 플랜은 글 생성과 복사만 가능해요. 발행하려면 프로 이상으로 업그레이드해줘요.' });
  }

  // 관리자 무제한, 무료=2개, 프로=3개, 프리미엄=5개
  let dailyLimit = 5;
  if (user?.role === 'admin') dailyLimit = 9999;
  else if (user?.dailyPublishLimit) dailyLimit = user.dailyPublishLimit;
  else if ((user?.accountLimit || 3) >= 6) dailyLimit = 5;
  else if (user?.plan === 'free') dailyLimit = 2;
  else dailyLimit = 3; // 베이직(2계정)
  const today = getTodayKey();
  const counts = getPublishCount(req.userId);
  const todayCount = counts[today] || 0;
  if (dailyLimit < 9999 && todayCount >= dailyLimit) {
    return res.status(429).json({ error: `오늘 발행 한도(${dailyLimit}개)를 초과했어. 내일 다시 시도해줘.` });
  }

  // 발행 전 미디어 URL 검증
  if (videoUrl) { const vc = validateMediaUrl(videoUrl); if (!vc.ok) return res.status(400).json({ error: '영상 URL 오류: ' + vc.reason }); }
  if (Array.isArray(imageUrls)) {
    for (const u of imageUrls) { const ic = validateMediaUrl(u); if (!ic.ok) return res.status(400).json({ error: '이미지 URL 오류: ' + ic.reason }); }
  }
  console.log('[PUBLISH] 발행 시작');
  try {
    const postId = await publishToThreads(account.accessToken, text, imageUrls || [], videoUrl || '');
    console.log('[PUBLISH] 글 발행 성공 - postId:', postId);
    let commentId = null;
    if (commentText && commentText.trim()) {
      await new Promise(r => setTimeout(r, 3000));
      commentId = await replyToThread(account.accessToken, postId, commentText.trim());
      console.log('[PUBLISH] 댓글 발행 성공 - commentId:', commentId);
    }
    const countData = getPublishCount(req.userId);
    const todayKey = getTodayKey();
    countData[todayKey] = (countData[todayKey] || 0) + 1;
    savePublishCount(req.userId, countData);
    res.json({ ok: true, postId, commentId });
  } catch(e) {
    console.error('[PUBLISH] 에러:', e.message, e.stack);
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════
//  예약 발행
// ══════════════════════════════════

app.post('/api/schedule', auth, (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (user?.plan === 'basic') {
    return res.status(403).json({ error: '베이직 플랜은 예약 발행이 불가해요. 프로 이상으로 업그레이드해줘요.' });
  }
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



// 예약 수정 (텍스트, 시간 변경)
app.put('/api/schedule/:id', auth, (req, res) => {
  const posts = getScheduled(req.userId);
  const post = posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ error: '없음' });
  if (post.status === 'done') return res.status(400).json({ error: '이미 발행된 글은 수정 불가' });
  post.status = 'pending'; // 실패 상태도 수정 가능
  if (req.body.text) post.text = req.body.text;
  if (req.body.scheduledAt) post.scheduledAt = req.body.scheduledAt;
  if (req.body.imageUrls !== undefined) post.imageUrls = req.body.imageUrls;
  if (req.body.videoUrl !== undefined) post.videoUrl = req.body.videoUrl;
  if (req.body.commentText !== undefined) post.commentText = req.body.commentText;
  saveScheduled(req.userId, posts);
  res.json(post);
});

// 예약 즉시 발행
app.post('/api/schedule/:id/publish-now', auth, async (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (user?.plan === 'basic') {
    return res.status(403).json({ error: '베이직 플랜은 발행이 불가해요. 프로 이상으로 업그레이드해줘요.' });
  }
  const posts = getScheduled(req.userId);
  const post = posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ error: '없음' });
  if (post.status === 'done') return res.status(400).json({ error: '이미 발행됨' });
  post.status = 'pending'; // 실패 상태도 재시도 가능
  const accs = getAccounts(req.userId);
  const account = accs.find(a => a.id === post.accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  try {
    if (post.type === 'comment') {
      // 댓글 즉시발행 - 최근 게시글에 달기
      const feedRes = await fetch(`https://graph.threads.net/v1.0/me/threads?fields=id&limit=1&access_token=${account.accessToken}`);
      const feedData = await feedRes.json();
      const latestPostId = feedData.data?.[0]?.id;
      if (!latestPostId) throw new Error('댓글 달 게시글 없음');
      const targetId = post.replyToId || latestPostId;
      await replyToThread(account.accessToken, targetId, post.text);
      post.status = 'done';
      saveScheduled(req.userId, posts);
      return res.json({ ok: true });
    }
    let postId;
    try {
      postId = await publishToThreads(account.accessToken, post.text, post.imageUrls || [], post.videoUrl || '');
    } catch(imgErr) {
      console.log('[PUBLISH-NOW] 이미지 실패, 텍스트만 재시도:', imgErr.message);
      postId = await publishToThreads(account.accessToken, post.text, [], '');
    }
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

// 예약 발행 실행 (1분마다)
cron.schedule('* * * * *', async () => {
  const dataDir = `${DATA_ROOT}/users`;
  if (!fs.existsSync(dataDir)) return;
  const userDirs = fs.readdirSync(dataDir);
  for (const userId of userDirs) {
    const posts = getScheduled(userId);
    const now = new Date();
    const pending = posts.filter(p => p.status === 'pending' && new Date(p.scheduledAt) <= now);
    if (!pending.length) continue;
    // 베이직 플랜은 cron 발행도 차단
    const cronUser = users.find(u => u.id === userId);
    if (cronUser?.plan === 'basic') {
      // 예약 항목 전부 취소 처리
      pending.forEach(p => { p.status = 'failed'; p.error = '베이직 플랜 발행 불가'; });
      saveScheduled(userId, posts);
      continue;
    }
    console.log(`[CRON] 유저 ${userId} - 발행 대기 ${pending.length}건`);
    let changed = false;
    for (const post of pending) {
      const accs = getAccounts(userId);
      const account = accs.find(a => a.id === post.accountId);
      if (!account) { post.status = 'failed'; changed = true; continue; }
      try {
        // 댓글 전용 예약
        if (post.type === 'comment') {
          if (post.replyToId) {
            // 특정 글 ID에 댓글
            await replyToThread(account.accessToken, post.replyToId, post.text);
          } else {
            // replyToId 없으면 → 해당 계정의 가장 최근 게시글에 댓글
            try {
              const feedRes = await fetch(`https://graph.threads.net/v1.0/me/threads?fields=id&limit=1&access_token=${account.accessToken}`);
              const feedData = await feedRes.json();
              const latestPostId = feedData.data?.[0]?.id;
              if (latestPostId) {
                console.log(`[CRON] 최근 게시글 ${latestPostId}에 댓글 달기`);
                await replyToThread(account.accessToken, latestPostId, post.text);
              } else {
                throw new Error('최근 게시글 없음');
              }
            } catch(e) {
              throw new Error('댓글 달 게시글 없음: ' + e.message);
            }
          }
        } else {
          // 글 발행 (이미지는 URL 만료 가능성 있어서 실패하면 텍스트만 발행)
          let postId;
          try {
            postId = await publishToThreads(account.accessToken, post.text, post.imageUrls || [], post.videoUrl || '');
          } catch(imgErr) {
            console.log(`[CRON] 이미지 발행 실패, 텍스트만 재시도:`, imgErr.message);
            postId = await publishToThreads(account.accessToken, post.text, [], '');
          }
          // 댓글이 있으면 글 발행 후 댓글 달기
          if (post.commentText && post.commentText.trim()) {
            await new Promise(r => setTimeout(r, 3000));
            await replyToThread(account.accessToken, postId, post.commentText.trim());
          }
        }
        post.status = 'done';
        changed = true;
        console.log(`[CRON] 발행 성공:`, post.id, '댓글:', post.commentText ? '있음' : '없음');
      } catch(e) {
        post.status = 'failed';
        post.error = e.message;
        changed = true;
        console.log(`[CRON] 발행 실패:`, post.id, e.message);
      }
    }
    if (changed) saveScheduled(userId, posts);
  }
});

// ══════════════════════════════════
//  인사이트
// ══════════════════════════════════

app.get('/api/insights/:accountId', auth, async (req, res) => {
  const accs = getAccounts(req.userId);
  const account = accs.find(a => a.id === req.params.accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  try {
    const r = await fetch(`https://graph.threads.net/v1.0/me?fields=id,username&access_token=${account.accessToken}`);
    const data = await r.json();
    if (data.error) return res.status(400).json({ error: data.error.message || JSON.stringify(data.error) });
    res.json({
      id: data.id || '-',
      username: data.username || '-'
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════
//  실시간 키워드
// ══════════════════════════════════

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
// 영상은 디스크에 임시 저장 (메모리 절약)
const videoStorage = multer.diskStorage({
  destination: function(req, file, cb) { cb(null, '/tmp'); },
  filename: function(req, file, cb) { cb(null, 'vid_' + Date.now() + '.mp4'); }
});
const videoUpload = multer({ storage: videoStorage, limits: { fileSize: 100 * 1024 * 1024 } }); // 100MB 제한

async function uploadToCloudinary(buffer, filename, resourceType = 'image') {
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const apiKey = process.env.CLOUDINARY_API_KEY;
  const apiSecret = process.env.CLOUDINARY_API_SECRET;
  if (!cloudName || !apiKey || !apiSecret) throw new Error('CLOUDINARY 환경변수 없음 (CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET)');

  const timestamp = Math.floor(Date.now() / 1000);
  const signature = crypto.createHash('sha256')
    .update(`access_mode=public&timestamp=${timestamp}&type=upload${apiSecret}`)
    .digest('hex');

  // FormData 직접 구성 (multipart)
  const boundary = '----FormBoundary' + crypto.randomBytes(8).toString('hex');
  const crlf = '\r\n';
  const ext = filename.split('.').pop()?.toLowerCase() || (resourceType === 'video' ? 'mp4' : 'jpg');
  const mimeType = resourceType === 'video' ? 'video/mp4' : `image/${ext === 'jpg' ? 'jpeg' : ext}`;

  let body = Buffer.alloc(0);
  const addField = (name, value) => {
    const part = Buffer.from(
      `--${boundary}${crlf}Content-Disposition: form-data; name="${name}"${crlf}${crlf}${value}${crlf}`
    );
    body = Buffer.concat([body, part]);
  };
  const addFile = (name, fname, mime, data) => {
    const header = Buffer.from(
      `--${boundary}${crlf}Content-Disposition: form-data; name="${name}"; filename="${fname}"${crlf}Content-Type: ${mime}${crlf}${crlf}`
    );
    const footer = Buffer.from(crlf);
    body = Buffer.concat([body, header, data, footer]);
  };

  addField('api_key', apiKey);
  addField('timestamp', String(timestamp));
  addField('signature', signature);
  addField('type', 'upload');
  addField('access_mode', 'public');
  addFile('file', filename, mimeType, buffer);
  body = Buffer.concat([body, Buffer.from(`--${boundary}--${crlf}`)]);

  const url = `https://api.cloudinary.com/v1_1/${cloudName}/${resourceType}/upload`;
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
    body
  });
  const d = await r.json();
  if (d.error) throw new Error(d.error.message);
  console.log('[CLOUDINARY] 업로드 성공');
  return d.secure_url;
}

app.post('/api/upload', auth, upload.array('images', 10), async (req, res) => {
  try {
    const urls = [];
    for (const file of req.files) {
      const url = await uploadToCloudinary(file.buffer, file.originalname, 'image');
      urls.push(url);
    }
    res.json({ urls });
  } catch(e) {
    console.error('[UPLOAD] 에러:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/upload-video', auth, videoUpload.single('video'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: '영상 없음' });
    // 디스크에서 읽어서 Cloudinary 업로드
    const fileBuffer = fs.readFileSync(req.file.path);
    const url = await uploadToCloudinary(fileBuffer, req.file.originalname || 'video.mp4', 'video');
    // 임시 파일 삭제
    try { fs.unlinkSync(req.file.path); } catch(e2) {}
    res.json({ url });
  } catch(e) {
    console.error('[UPLOAD-VIDEO] 에러:', e.message);
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
  const datetime = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '').slice(0, 15) + 'Z';

  // HMAC-SHA256 서명
  const message = datetime + method + path;
  const signature = crypto.createHmac('sha256', secretKey).update(message).digest('hex');
  const authorization = `CEA algorithm=HmacSHA256, access-key=${accessKey}, signed-date=${datetime}, signature=${signature}`;

  const r = await fetch(`https://api-gateway.coupang.com${path}`, {
    method,
    headers: { 'Authorization': authorization, 'Content-Type': 'application/json' }
  });
  const d = await r.json();
  console.log('[COUPANG] 검색 응답 코드:', d.rCode);
  if (d.rCode !== '0' && d.rCode !== 0) throw new Error('쿠팡 API 오류: ' + d.rMessage);

  const products = d.data?.productData || [];
  if (!products.length) throw new Error('검색 결과 없음');

  // 첫 번째 상품 링크 반환
  const product = products[0];
  return product.productUrl || product.shortenUrl || '';
}

// ==============================
//  자동 스케줄러
// ==============================

function getAutoSchedules(userId) { return loadJSON(`${userDir(userId)}/auto_schedules.json`, []); }
function saveAutoSchedules(userId, data) { saveJSON(`${userDir(userId)}/auto_schedules.json`, data); }

// 자동 스케줄 목록
app.get('/api/auto-schedule', auth, (req, res) => {
  res.json(getAutoSchedules(req.userId));
});

// 자동 스케줄 등록/수정
app.post('/api/auto-schedule', auth, (req, res) => {
  const user = users.find(u => u.id === req.userId);
  const settings = getSettings();
  if (user?.role !== 'admin') {
    const settings2 = getSettings();
    if (!settings2.autoSchedulerEnabled) {
      return res.status(403).json({ error: 'disabled' });
    }
    if (user?.plan !== 'premium') {
      return res.status(403).json({ error: 'premium_only' });
    }
  }
  const { accountId, topics, tone, publishTime, commentTone, commentDelay, enabled, toneExample, tonePrompt } = req.body;
  const accs = getAccounts(req.userId);
  // 계정 토큰이 실제 토큰 (앞자리 숨겨진 경우 원본 찾기)
  const account = accs.find(a => a.id === accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  const schedules = getAutoSchedules(req.userId);
  // 기존 수정
  if (req.body.id) {
    const existing = schedules.find(s => s.id === req.body.id);
    if (existing) {
      Object.assign(existing, { accountId, accountName: account.name, topics: topics || [], tone, publishTime, commentTone: commentTone || '', commentDelay: commentDelay || 10, toneExample: toneExample || '', tonePrompt: tonePrompt || '', enabled: enabled !== false });
      saveAutoSchedules(req.userId, schedules);
      return res.json(existing);
    }
  }
  // 신규 등록 - 계정당 하루 5개 제한 체크
  const today = getTodayKey();
  const todayCount = schedules.filter(s => s.accountId === accountId && s.createdDate === today).length;
  if (user.role !== 'admin' && todayCount >= 5) {
    return res.status(429).json({ error: '계정당 하루 최대 5개까지 등록 가능해' });
  }
  const item = {
    id: Date.now().toString(),
    accountId, accountName: account.name,
    topics: Array.isArray(topics) ? topics : [],  // [{text, active}]
    tone, publishTime,
    commentTone: commentTone || '', commentDelay: commentDelay || 10,
    toneExample: toneExample || '', tonePrompt: tonePrompt || '',
    enabled: enabled !== false,
    createdDate: today,
    createdAt: new Date().toISOString()
  };
  schedules.push(item);
  saveAutoSchedules(req.userId, schedules);
  res.json(item);
});

// 자동 스케줄 주제 활성화 토글
app.put('/api/auto-schedule/:id/topics', auth, (req, res) => {
  const schedules = getAutoSchedules(req.userId);
  const sched = schedules.find(s => s.id === req.params.id);
  if (!sched) return res.status(404).json({ error: '없음' });
  sched.topics = req.body.topics;
  saveAutoSchedules(req.userId, schedules);
  res.json(sched);
});

// 자동 스케줄 시간/말투 수정
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

// 자동 스케줄 삭제
app.delete('/api/auto-schedule/:id', auth, (req, res) => {
  let schedules = getAutoSchedules(req.userId);
  schedules = schedules.filter(s => s.id !== req.params.id);
  saveAutoSchedules(req.userId, schedules);
  res.json({ ok: true });
});

// 자동 스케줄러 활성화 설정 (관리자만)
app.put('/api/settings/auto-scheduler', adminAuth, (req, res) => {
  const settings = getSettings();
  settings.autoSchedulerEnabled = !!req.body.enabled;
  saveSettings(settings);
  res.json({ ok: true, enabled: settings.autoSchedulerEnabled });
});

// 자동 스케줄러 발행 로그
function getAutoLogs(userId) { return loadJSON(`${userDir(userId)}/auto_logs.json`, []); }
function saveAutoLog(userId, log) {
  const logs = getAutoLogs(userId);
  logs.unshift(log); // 최신 맨 앞
  if (logs.length > 20) logs.splice(20); // 최대 20개 보관
  saveJSON(`${userDir(userId)}/auto_logs.json`, logs);
}

app.get('/api/auto-logs', auth, (req, res) => {
  const logs = getAutoLogs(req.userId);
  res.json(logs.slice(0, 5)); // 최근 5개만
});

// ── 매일 자정 만료 처리 cron (KST 기준 00:00 = UTC 15:00) ──
cron.schedule('0 15 * * *', () => {
  const now = new Date();
  let changed = false;
  users.forEach(u => {
    if (u.role === 'admin' || !u.expiresAt) return;
    const exp = new Date(u.expiresAt);
    // 만료됐는데 아직 approved면 suspended로 변경
    if (exp < now && u.status === 'approved') {
      u.status = 'suspended';
      u._expiredAt = now.toISOString();
      changed = true;
      console.log(`[EXPIRE] ${u.nickname} 만료로 정지`);
    }
  });
  if (changed) saveJSON(`${DATA_ROOT}/users.json`, users);
});

// 자동 스케줄러 cron (매 분마다 체크)
cron.schedule('* * * * *', async () => {
  const settings = getSettings();
  const now = new Date();
  // Railway는 UTC 기준 - 한국시간(KST = UTC+9)으로 변환
  const kstOffset = 9 * 60 * 60 * 1000;
  const kstNow = new Date(now.getTime() + kstOffset);
  const currentTime = kstNow.getUTCHours().toString().padStart(2,'0') + ':' + kstNow.getUTCMinutes().toString().padStart(2,'0');
  console.log(`[AUTO-CRON] KST시간: ${currentTime}, 자동스케줄러활성: ${settings.autoSchedulerEnabled}`);
  const dataDir = `${DATA_ROOT}/users`;
  if (!fs.existsSync(dataDir)) return;
  const userDirs = fs.readdirSync(dataDir);
  for (const userId of userDirs) {
    const user = users.find(u => u.id === userId);
    if (!user) continue;
    // 관리자이거나 (자동스케줄러 활성화 + 프리미엄 플랜) 유저만
    if (user.role !== 'admin') {
      if (!settings.autoSchedulerEnabled) { continue; } // 비활성화면 전체 중지
      if (user.plan !== 'premium') { continue; } // 프리미엄만 허용
    }
    const autoSchedules = getAutoSchedules(userId);
    console.log(`[AUTO-CRON] 유저 ${user.nickname}(${user.role}) - 스케줄 ${autoSchedules.length}개`);
    // 관리자 무제한, 프리미엄 최대 5개
    const maxAuto = user.role === 'admin' ? 999 : 5;
    const toRun = autoSchedules.filter(s => s.enabled && s.publishTime === currentTime).slice(0, maxAuto);
    console.log(`[AUTO-CRON] 현재시간(${currentTime}) 매칭 스케줄: ${toRun.length}개`);
    if (!toRun.length) continue;
    console.log(`[AUTO] 유저 ${userId} - ${toRun.length}개 자동 발행`);
    // 계정별 오늘 발행 횟수 추적
    const autoCountToday = {};
    for (const sched of toRun) {
      const accs = getAccounts(userId);
      const account = accs.find(a => a.id === sched.accountId);
      if (!account) continue;
      // 관리자 무제한, 프리미엄 계정당 5개 제한
      if (user.role !== 'admin') {
        const accCount = autoCountToday[sched.accountId] || 0;
        if (accCount >= 5) {
          console.log(`[AUTO] 계정 ${account.name} 오늘 5개 한도 초과 - 건너뜀`);
          continue;
        }
        autoCountToday[sched.accountId] = accCount + 1;
      }
      try {
        const apiKey = process.env.GROQ_API_KEY;
        if (!apiKey) continue;
        // 글 생성
        const tonePrompts = {
          '리스트형': '리스트형 SNS 콘텐츠. 번호/불릿 중심, 핵심만, 댓글 유도.',
          '정보성': '정보형 SNS 콘텐츠. 신뢰감 있는 톤, 핵심 요약, 댓글 유도.',
          '리뷰형': '리뷰형 SNS 콘텐츠. 실제 경험처럼, 장단점 포함.',
          '일상': '일상형 SNS 콘텐츠. 말하듯 자연스럽게, 짧고 가볍게.',
          '공감형': '공감형 SNS 콘텐츠. 공감 상황 제시, 질문형 마무리.',
          '스토리형': '스토리형 SNS 콘텐츠. 상황->전개->결론 구조.',
          '쿠팡': '쿠팡 클릭 유도. 1~3줄. 어그로성 첫줄. 경험담처럼. 부정표현 절대 금지. 제품명 금지. 읽으면 클릭하고 싶게.'
        };
        // 주제 선택 - topics 배열에서 active인 것 중 랜덤 1개
        let selectedTopic = sched.topic || '';
        if (Array.isArray(sched.topics) && sched.topics.length > 0) {
          const activeTopics = sched.topics.filter(t => t.active !== false);
          if (activeTopics.length > 0) {
            selectedTopic = activeTopics[Math.floor(Math.random() * activeTopics.length)].text;
          }
        }
        if (!selectedTopic) { console.log('[AUTO] 활성 주제 없음 - 건너뜀'); continue; }
        console.log(`[AUTO] 선택된 주제: ${selectedTopic}`);

        const toneExample = '';
        const tonePromptExtra = '';
        const toneExtraInstr = sched.toneExample ? '\n\n[말투 예시 - 반드시 이 스타일로 작성]\n' + sched.toneExample : '';
        const promptExtraInstr = sched.tonePrompt ? '\n\n[추가 스타일 지침 - 반드시 따를 것]\n' + sched.tonePrompt : '';
        const systemMsg = `너는 한국어 콘텐츠 전문 작가다.

[절대 언어 규칙]
- 반드시 한국어(한글 + 숫자 + 기본 특수문자)만 사용한다.
- 한자, 일본어, 영어 단어를 절대 사용하지 않는다.
- 외래어도 가능한 순수 한국어로 바꿔 작성한다.
- 단, 주제에 직접 적혀있는 영어 단어는 그대로 사용 가능.
- 작성 후 한글 외 문자가 있으면 전체 문장을 다시 작성한다.

[위트·스타일 규칙]
- 센스 있고 위트 있게, 드립도 칠 줄 아는 작가처럼 작성한다.
- 뻔한 말 금지: "건강에 좋다", "꼭 해보세요" 등 원론적 표현 금지.
- 예상을 비트는 표현, 첫 줄 바로 훅, 친구가 하는 말처럼.

[작성 규칙]
- 이모지 절대 금지. 반말로만. 같은 단어/표현 반복 금지.
- "이거", "요거" 남발 금지. 꼭 필요한 경우만 한 번.
- 게시글 텍스트만 출력.
- 리스트형 말투가 아닌 이상 번호나 불릿 절대 금지.
- 간결하고 포인트 있게. 군더더기 없이. 읽히는 흐름이 자연스럽게.

[줄바꿈]
- 2~3문장마다 줄바꿈 1번. 문단 전환 시 빈 줄 1개.` + toneExtraInstr + promptExtraInstr;
        const prompt = (tonePrompts[sched.tone] || tonePrompts['일상']) + toneExample + tonePromptExtra + '\n\n주제: ' + selectedTopic + '\n\n위 형식에 맞게 Threads 게시글을 작성해줘. 반드시 한국어로만, 이모지 없이, 줄바꿈 포함해서, 게시글 텍스트만 출력해.';
        const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
          body: JSON.stringify({ model: 'llama-3.3-70b-versatile', messages: [{ role: 'system', content: systemMsg }, { role: 'user', content: prompt }], temperature: 0.85, max_tokens: 500 })
        });
        const data = await r.json();
        if (data.error) throw new Error(data.error.message);
        const text = (data.choices?.[0]?.message?.content || '').trim();
        if (!text) continue;
        // 즉시 발행
        const postId = await publishToThreads(account.accessToken, text, [], '');
        console.log(`[AUTO] 발행 성공: ${selectedTopic} / ${sched.tone}`);
        saveAutoLog(userId, {
          id: postId,
          accountName: account.name,
          topic: selectedTopic,
          tone: sched.tone,
          postText: text,
          status: 'success',
          publishedAt: new Date().toISOString()
        });
        // 댓글도 있으면 delay 후 예약
        if (sched.commentTone) {
          const delay = sched.commentDelay || 10;
          const commentAt = new Date(Date.now() + delay * 60 * 1000).toISOString();
          const commentPrompt = '스레드 댓글 1개만 작성해줘.\n주제: ' + sched.topic + '\n규칙: 반드시 한국어로만, 반말, 1~2문장, 이모지 절대 금지, 존댓말 금지, 댓글 텍스트만 출력.';
          const rc = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
            body: JSON.stringify({ model: 'llama-3.3-70b-versatile', messages: [{ role: 'system', content: systemMsg }, { role: 'user', content: commentPrompt }], temperature: 0.85, max_tokens: 200 })
          });
          const dc = await rc.json();
          let commentText = (dc.choices?.[0]?.message?.content || '').trim();
          if (commentText) {
            // 쿠팡 말투면 링크 자동 추가
            if (sched.tone === '쿠팡' && sched.coupangKeyword) {
              try {
                const coupangUrl = await getCoupangLink(sched.coupangKeyword);
                if (coupangUrl) {
                  commentText = '[쿠팡 파트너스 활동으로 수수료를 제공받을 수 있습니다]\n\n' + commentText + '\n\n' + coupangUrl + '\n' + coupangUrl + '\n' + coupangUrl;
                  console.log('[AUTO] 쿠팡 링크 자동 생성 성공');
                }
              } catch(e) {
                console.log('[AUTO] 쿠팡 링크 생성 실패:', e.message);
              }
            }
            const posts = getScheduled(userId);
            posts.push({ id: Date.now().toString(), accountId: sched.accountId, accountName: account.name, text: commentText, type: 'comment', imageUrls: [], commentText: '', scheduledAt: commentAt, status: 'pending', createdAt: new Date().toISOString() });
            saveScheduled(userId, posts);
            console.log(`[AUTO] 댓글 예약됨: ${delay}분 후`);
          }
        }
      } catch(e) {
        console.log(`[AUTO] 실패:`, e.message);
        saveAutoLog(userId, {
          id: Date.now().toString(),
          accountName: account.name,
          topic: selectedTopic || sched.topic || '-',
          tone: sched.tone,
          status: 'failed',
          error: e.message,
          publishedAt: new Date().toISOString()
        });
      }
    }
  }
});

// 서버 시작 시 세션 파일 로드
sessions = loadSessions();
console.log(`세션 복원: ${Object.keys(sessions).length}개`);

// ── 전역 에러 핸들러 (스택 트레이스 숨김) ──
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: '서버 오류가 발생했어. 잠시 후 다시 시도해줘.' });
});

// ── 없는 라우트 404 ──
app.use((req, res) => {
  res.status(404).json({ error: '없는 경로야' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`서버 실행중: ${PORT}`));
