const express = require('express');
const cors = require('cors');
const multer = require('multer');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
const cron = require('node-cron');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

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

// ── 데이터 저장소 ──
let users       = loadJSON(`${DATA_ROOT}/users.json`, []);
let inviteCodes = loadJSON(`${DATA_ROOT}/invite_codes.json`, []);
// sessions는 loadSessions() 이후 아래에서 초기화됨
let sessions    = {}; // 임시, 아래 init에서 덮어씀

function userDir(userId) {
  const dir = `${DATA_ROOT}/users/${userId}`;
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
function saveAccounts(userId, data) { saveJSON(`${userDir(userId)}/accounts.json`, data); }
function getScheduled(userId) { return loadJSON(`${userDir(userId)}/scheduled.json`, []); }
function saveScheduled(userId, data) { saveJSON(`${userDir(userId)}/scheduled.json`, data); }

// ── 비밀번호 해시 ──
function hashPw(pw) { return crypto.createHash('sha256').update(pw + 'threads_salt_2025').digest('hex'); }

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
  const token = req.headers['x-session'] || req.query.session;
  const s = getSession(token);
  if (!token || !s) return res.status(401).json({ error: '로그인 필요' });
  req.userId = s.userId;
  req.user = users.find(u => u.id === req.userId);
  next();
}
function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (req.user?.role !== 'admin') return res.status(403).json({ error: '관리자만 가능' });
    next();
  });
}

// ── 정적 파일 (로그인 전에도 접근 가능) ──
app.use(express.static('public'));

// ══════════════════════════════════
//  AUTH API
// ══════════════════════════════════

// 첫 번째 유저 여부 확인
app.get('/api/auth/is-first', (req, res) => res.json({ isFirst: users.length === 0 }));

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
app.post('/api/auth/register', rateLimit(5, 60000), (req, res) => {
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
app.post('/api/auth/login', rateLimit(10, 60000), (req, res) => {
  const { nickname, password } = req.body;
  const user = users.find(u => u.nickname === nickname && u.passwordHash === hashPw(password));
  if (!user) return res.status(401).json({ error: '닉네임 또는 비밀번호 오류' });
  if (user.status === 'pending') return res.status(403).json({ error: 'pending' });
  if (user.status === 'suspended') return res.status(403).json({ error: 'suspended' });
  // 사용기간 만료 체크
  if (user.expiresAt && new Date() > new Date(user.expiresAt) && user.role !== 'admin') {
    return res.status(403).json({ error: 'expired' });
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
  res.json({ nickname: req.user.nickname, role: req.user.role });
});

// ══════════════════════════════════
//  초대코드 관리 (관리자 전용)
// ══════════════════════════════════

app.get('/api/invites', adminAuth, (req, res) => res.json(inviteCodes));

// 설정 (카카오 링크 등)
app.get('/api/settings', auth, (req, res) => res.json(getSettings()));
app.put('/api/settings', adminAuth, (req, res) => {
  const settings = getSettings();
  if (req.body.kakaoLink !== undefined) settings.kakaoLink = req.body.kakaoLink;
  if (req.body.partnerCode !== undefined) settings.partnerCode = req.body.partnerCode.toUpperCase();
  saveSettings(settings);
  res.json({ ok: true });
});

app.post('/api/invites', adminAuth, (req, res) => {
  // 기존 active 코드들 모두 사용완료로 변경
  inviteCodes.forEach(c => {
    if (c.status !== 'done') c.status = 'done';
  });
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
  res.json(users.map(u => ({ id: u.id, nickname: u.nickname, name: u.name||'', role: u.role, status: u.status||'approved', plan: u.plan||'paid', accountLimit: u.accountLimit||3, dailyPublishLimit: u.dailyPublishLimit||null, limitRequest: u.limitRequest||null, extendRequest: u.extendRequest||null, upgradeRequest: u.upgradeRequest||null, joinedVia: u.joinedVia||'normal', approvedAt: u.approvedAt||null, expiresAt: u.expiresAt||null, createdAt: u.createdAt })));
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
    user.plan = req.body.plan || 'paid'; // 'free' or 'paid'
    if (req.body.plan === 'free') {
      user.accountLimit = 1;
      user.dailyPublishLimit = 2;
    }
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
  saveJSON(`${DATA_ROOT}/users.json`, users);
  res.json({ ok: true });
});

// ══════════════════════════════════
//  Threads 계정 관리 (유저별)
// ══════════════════════════════════

app.get('/api/accounts', auth, (req, res) => res.json(getAccounts(req.userId)));

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
  const acc = { id: Date.now().toString(), name, accessToken, topics: topics || [] };
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
  const { topic, tone, type, imageDesc } = req.body;
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'GROQ_API_KEY 없음' });

  const imgContext = imageDesc ? `\n[이미지 분석 결과 - 이 상품/내용으로 글 작성]: ${imageDesc}` : '';

  const tonePrompts = {
    '리스트형': `너는 리스트형 SNS 콘텐츠 작성자다.
규칙: 번호/불릿 중심, 핵심만 짧게, 일부 정보는 숨겨서 댓글 유도, 마지막 줄에 댓글 유도 문장 필수.
출력 형식: 제목 1줄 → 리스트 3~5개 → 마무리 한 줄
예시:
요즘 사람들이 많이 찾는 ○○ 정리
1. A - 핵심 특징만
2. B - 핵심 특징만
3. C - 핵심 특징만
자세한 기준은 댓글에 정리해둠`,

    '정보성': `너는 정보형 SNS 콘텐츠 작성자다.
규칙: 설명형 문장, 신뢰감 있는 톤, 핵심만 요약, 일부 디테일은 의도적으로 생략, 댓글 확인 유도 필수.
출력 형식: 제목 → 간단 설명 → 핵심 포인트 2~3개 → 마무리
예시:
○○ 제대로 고르는 기준
이건 생각보다 기준이 중요하다
- 기준 1
- 기준 2
- 기준 3
이거 모르고 사면 후회하는 경우 많다
추가 체크 포인트는 댓글에 정리함`,

    '리뷰형': `너는 리뷰형 SNS 콘텐츠 작성자다.
규칙: 실제 경험처럼 작성, 장점/단점 포함, 솔직한 말투, 너무 길지 않게.
출력 형식: 도입 → 좋은 점 → 아쉬운 점 → 총평
예시:
요즘 많이 보이길래 직접 써봤는데
좋았던 점
- 포인트 1
- 포인트 2
아쉬운 점
- 포인트 1
결론적으로 이런 사람은 추천, 이런 사람은 비추`,

    '일상': `너는 일상형 SNS 콘텐츠 작성자다.
규칙: 말하듯 자연스럽게, 짧고 가볍게, 감정 포함.
예시:
오늘 그냥 ○○ 하다가
우연히 ○○ 했는데
생각보다 괜찮아서 놀람
이런 날이 은근 기분 좋다`,

    '공감형': `너는 공감형 SNS 콘텐츠 작성자다.
규칙: 사람들이 공감할 상황 제시, 짧고 임팩트 있게, 질문형 마무리.
예시:
이거 왜 이럼
○○하려고 하면
갑자기 ○○ 하고 싶어짐
이거 나만 이런 거 아니지`,

    '스토리형': `너는 스토리형 SNS 콘텐츠 작성자다.
규칙: 상황→전개→결론 구조, 몰입감 있게, 감정 흐름 포함.
예시:
어제 그냥 ○○ 하다가
우연히 ○○ 했는데
생각보다 너무 괜찮았음
이래서 사람들이 찾는 건가 싶더라`,

    '쿠팡': `쿠팡 구매 유도 SNS 글. 무조건 짧게. 1~3줄이면 충분.

[예시 — 이 길이와 느낌으로]
음식: 남편이 야식 만들어 달래서 만들어줬더니 맨날 이것만 찾는다 골치아프네
디저트: 지인 것 뺏어먹었다가 두박스 시킴 진짜 개맛있다
강아지: 사료에 이거 하나 넣으면 완뚝임
아기: 우리 딸래미 이거 없으면 밥 절대 안먹음
생활용품: 이거 사고 나서 삶의 질이 달라졌네

[규칙]
- 1~3줄 엄수. 절대 길게 쓰지 말 것
- 첫 줄에 바로 어그로
- 경험담처럼 (광고 절대 금지)
- 뻔한 말 금지: 가성비, 추천, 좋은제품
- 이모지 금지, 반말
- 예시 복붙 금지, 주제에 맞게 새로 창작
- 제품명/브랜드명 절대 언급 금지 → "이거", "이것", "요거"로 둘러 말할 것
- 제품명 대신 반응, 상황, 감정으로만 표현`
  };

  const toneInstruction = tonePrompts[tone] || tonePrompts['일상'];

  const systemMsg = `당신은 한국 Threads SNS 콘텐츠 전문 작성자입니다.
[절대 규칙]
- 반드시 한국어로만 작성 (영어, 한자, 외국어 절대 금지)
- 이모지 절대 사용 금지
- 반말로만 작성 (존댓말, ~합니다, ~해요, ~입니다 절대 금지)
- 가독성을 위해 문장 단위로 줄바꿈 (단, 빈 줄은 꼭 필요한 곳에만)
- 게시글 텍스트만 출력 (설명, 주석, 따옴표 없이)
- 제품명, 브랜드명을 글에 절대 직접 언급하지 말 것
- "이거", "이것", "이 녀석", "요거", "이런 거" 등으로 둘러 말할 것
- 제품명 대신 상황과 경험으로 후킹을 만들 것`;

  let prompt = '';
  if (type === 'comment') {
    prompt = `댓글 1개만 작성해줘.
주제: ${topic}${imgContext}
규칙: 반말, 1~2문장, 이모지 금지, 한국어만, 댓글 텍스트만 출력`;
  } else {
    prompt = `${toneInstruction}

주제: ${topic}${imgContext}

위 형식에 맞게 Threads 게시글을 작성해줘.
반드시 한국어로만, 반말로, 이모지 없이, 게시글 텍스트만 출력해.`;
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
    const text = (data.choices?.[0]?.message?.content || '').trim();
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
  if (videoUrl) {
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'VIDEO', video_url: videoUrl, text, access_token: accessToken }) });
    const d = await r.json(); if (d.error) throw new Error(d.error.message);
    containerId = d.id;
    await new Promise(r => setTimeout(r, 10000));
  } else if (imageUrls.length === 0) {
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'TEXT', text, access_token: accessToken }) });
    const d = await r.json(); if (d.error) throw new Error(d.error.message);
    containerId = d.id;
  } else if (imageUrls.length === 1) {
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'IMAGE', image_url: imageUrls[0], text, access_token: accessToken }) });
    const d = await r.json(); if (d.error) throw new Error(d.error.message);
    containerId = d.id;
  } else {
    const childIds = [];
    for (const url of imageUrls) {
      const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ media_type: 'IMAGE', image_url: url, is_carousel_item: true, access_token: accessToken }) });
      const d = await r.json(); if (d.error) throw new Error(d.error.message);
      childIds.push(d.id);
    }
    await new Promise(r => setTimeout(r, 3000));
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
  const { accountId, text, imageUrls, videoUrl, commentText } = req.body;
  const accs = getAccounts(req.userId);
  const account = accs.find(a => a.id === accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });

  // 일별 발행 횟수 체크
  const user = users.find(u => u.id === req.userId);
  const dailyLimit = user?.dailyPublishLimit || 5; // 기본 5개, 무료는 2개
  const today = getTodayKey();
  const counts = getPublishCount(req.userId);
  const todayCount = counts[today] || 0;
  if (user?.role !== 'admin' && todayCount >= dailyLimit) {
    return res.status(429).json({ error: `오늘 발행 한도(${dailyLimit}개)를 초과했어. 내일 다시 시도해줘.` });
  }

  try {
    const postId = await publishToThreads(account.accessToken, text, imageUrls || [], videoUrl || '');
    let commentId = null;
    if (commentText && commentText.trim()) {
      await new Promise(r => setTimeout(r, 3000)); // 글 발행 후 3초 대기
      commentId = await replyToThread(account.accessToken, postId, commentText.trim());
    }
    // 발행 횟수 기록
    const countData = getPublishCount(req.userId);
    const todayKey = getTodayKey();
    countData[todayKey] = (countData[todayKey] || 0) + 1;
    savePublishCount(req.userId, countData);

    res.json({ ok: true, postId, commentId });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════
//  예약 발행
// ══════════════════════════════════

app.post('/api/schedule', auth, (req, res) => {
  const { accountId, text, imageUrls, scheduledAt, commentText } = req.body;
  const accs = getAccounts(req.userId);
  const account = accs.find(a => a.id === accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  const posts = getScheduled(req.userId);
  const post = { id: Date.now().toString(), accountId, accountName: account.name, text, type: req.body.type || 'post', imageUrls: imageUrls || [], commentText: commentText || '', scheduledAt, status: 'pending', createdAt: new Date().toISOString() };
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
  if (post.status !== 'pending') return res.status(400).json({ error: '이미 발행된 글은 수정 불가' });
  if (req.body.text) post.text = req.body.text;
  if (req.body.scheduledAt) post.scheduledAt = req.body.scheduledAt;
  saveScheduled(req.userId, posts);
  res.json(post);
});

// 예약 즉시 발행
app.post('/api/schedule/:id/publish-now', auth, async (req, res) => {
  const posts = getScheduled(req.userId);
  const post = posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ error: '없음' });
  if (post.status === 'done') return res.status(400).json({ error: '이미 발행됨' });
  post.status = 'pending'; // 실패 상태도 재시도 가능
  const accs = getAccounts(req.userId);
  const account = accs.find(a => a.id === post.accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  try {
    await publishToThreads(account.accessToken, post.text, post.imageUrls || []);
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
            await replyToThread(account.accessToken, post.replyToId, post.text);
          }
        } else {
          // 글 발행
          const postId = await publishToThreads(account.accessToken, post.text, post.imageUrls || [], post.videoUrl || '');
          // 댓글이 있으면 글 발행 후 댓글 달기
          if (post.commentText && post.commentText.trim()) {
            await new Promise(r => setTimeout(r, 3000));
            await replyToThread(account.accessToken, postId, post.commentText.trim());
          }
        }
        post.status = 'done';
        changed = true;
        console.log(`[CRON] 발행 성공:`, post.id);
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
//  이미지/영상 업로드
// ══════════════════════════════════

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

app.post('/api/upload', auth, upload.array('images', 10), async (req, res) => {
  const apiKey = process.env.IMGBB_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'IMGBB_API_KEY 없음' });
  try {
    const urls = [];
    for (const file of req.files) {
      const form = new URLSearchParams();
      form.append('key', apiKey);
      form.append('image', file.buffer.toString('base64'));
      const r = await fetch('https://api.imgbb.com/1/upload', { method: 'POST', body: form });
      const d = await r.json();
      if (d.data?.url) urls.push(d.data.url);
    }
    res.json({ urls });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

const videoUpload = multer({ storage: multer.diskStorage({
  destination: (req, file, cb) => { const dir='./uploads'; if(!fs.existsSync(dir)) fs.mkdirSync(dir); cb(null,dir); },
  filename: (req, file, cb) => cb(null, Date.now()+'_'+file.originalname)
}), limits: { fileSize: 1024*1024*1024 } });

app.use('/uploads', express.static('uploads'));

app.post('/api/upload-video', auth, videoUpload.single('video'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: '영상 없음' });
  const baseUrl = process.env.BASE_URL || `http://localhost:${process.env.PORT||3000}`;
  res.json({ url: `${baseUrl}/uploads/${req.file.filename}` });
});

// 서버 시작 시 세션 파일 로드
sessions = loadSessions();
console.log(`세션 복원: ${Object.keys(sessions).length}개`);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`서버 실행중: ${PORT}`));
