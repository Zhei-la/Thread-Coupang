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
let sessions    = {};

function userDir(userId) {
  const dir = `${DATA_ROOT}/users/${userId}`;
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}
function getAccounts(userId)  { return loadJSON(`${userDir(userId)}/accounts.json`, []); }
function saveAccounts(userId, data) { saveJSON(`${userDir(userId)}/accounts.json`, data); }
function getScheduled(userId) { return loadJSON(`${userDir(userId)}/scheduled.json`, []); }
function saveScheduled(userId, data) { saveJSON(`${userDir(userId)}/scheduled.json`, data); }

// ── 비밀번호 해시 ──
function hashPw(pw) { return crypto.createHash('sha256').update(pw + 'threads_salt_2025').digest('hex'); }

// ── 세션 미들웨어 ──
function auth(req, res, next) {
  const token = req.headers['x-session'] || req.query.session;
  if (!token || !sessions[token]) return res.status(401).json({ error: '로그인 필요' });
  req.userId = sessions[token];
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
app.post('/api/auth/register', (req, res) => {
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
    const invite = inviteCodes.find(c => c.code === inviteCode && !c.used);
    if (!invite) return res.status(400).json({ error: '유효하지 않은 초대코드' });
    invite.used = true; invite.usedBy = nickname; invite.usedAt = new Date().toISOString();
    saveJSON(`${DATA_ROOT}/invite_codes.json`, inviteCodes);
  }

  const user = { id: Date.now().toString(), nickname, passwordHash: hashPw(password), role, createdAt: new Date().toISOString() };
  users.push(user);
  saveJSON(`${DATA_ROOT}/users.json`, users);
  const token = crypto.randomUUID();
  sessions[token] = user.id;
  res.json({ token, nickname: user.nickname, role: user.role });
});

// 로그인
app.post('/api/auth/login', (req, res) => {
  const { nickname, password } = req.body;
  const user = users.find(u => u.nickname === nickname && u.passwordHash === hashPw(password));
  if (!user) return res.status(401).json({ error: '닉네임 또는 비밀번호 오류' });
  const token = crypto.randomUUID();
  sessions[token] = user.id;
  res.json({ token, nickname: user.nickname, role: user.role });
});

// 로그아웃
app.post('/api/auth/logout', auth, (req, res) => {
  const token = req.headers['x-session'];
  delete sessions[token];
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

app.post('/api/invites', adminAuth, (req, res) => {
  const code = crypto.randomBytes(4).toString('hex').toUpperCase(); // 예: A3F2B1C4
  const invite = { code, createdBy: req.user.nickname, used: false, createdAt: new Date().toISOString() };
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
  res.json(users.map(u => ({ id: u.id, nickname: u.nickname, role: u.role, createdAt: u.createdAt })));
});

app.delete('/api/users/:id', adminAuth, (req, res) => {
  if (req.params.id === req.userId) return res.status(400).json({ error: '본인 삭제 불가' });
  users = users.filter(u => u.id !== req.params.id);
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

app.post('/api/generate', auth, async (req, res) => {
  const { topic, tone, type } = req.body;
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'GEMINI_API_KEY 없음' });

  const toneMap = { '일상': '친구한테 말하듯 편하고 자연스럽게', '정보': '유용한 정보를 쉽게 설명하듯', '유머': '재치있고 웃긴 느낌으로', '감성': '감성적이고 공감되는 느낌으로', '도발': '자극적이고 관심끄는 느낌으로' };
  const toneDesc = toneMap[tone] || '자연스럽게';

  const prompt = type === 'comment'
    ? `스레드(Threads SNS)에 달 댓글을 1개만 작성해줘.\n주제: ${topic}\n조건:\n- 반드시 반말로\n- ${toneDesc}\n- 이모지 절대 사용 금지\n- "첫째", "둘째", "결론적으로" 같은 형식적 표현 금지\n- ~합니다, ~해요 같은 존댓말 절대 금지\n- 짧고 자연스럽게 (1~2문장)\n- 다른 설명 없이 댓글 텍스트만 출력`
    : `스레드(Threads SNS)에 올릴 게시글을 작성해줘.\n주제: ${topic}\n조건:\n- 반드시 반말로\n- ${toneDesc}\n- 이모지 절대 사용 금지\n- "첫째", "둘째", "결론적으로" 같은 형식적 표현 금지\n- ~합니다, ~해요 같은 존댓말 절대 금지\n- SNS 특유의 자연스러운 구어체\n- 500자 이내\n- 다른 설명 없이 게시글 텍스트만 출력`;

  try {
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.9, maxOutputTokens: 500 } })
    });
    const data = await r.json();
    console.log("Gemini 응답:", JSON.stringify(data));
    res.json({ text: (data.candidates?.[0]?.content?.parts?.[0]?.text || '').trim() });
  } catch(e) { res.status(500).json({ error: e.message }); }
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

app.post('/api/publish', auth, async (req, res) => {
  const { accountId, text, imageUrls, videoUrl } = req.body;
  const accs = getAccounts(req.userId);
  const account = accs.find(a => a.id === accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  try {
    const postId = await publishToThreads(account.accessToken, text, imageUrls || [], videoUrl || '');
    res.json({ ok: true, postId });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════
//  예약 발행
// ══════════════════════════════════

app.post('/api/schedule', auth, (req, res) => {
  const { accountId, text, imageUrls, scheduledAt } = req.body;
  const accs = getAccounts(req.userId);
  const account = accs.find(a => a.id === accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  const posts = getScheduled(req.userId);
  const post = { id: Date.now().toString(), accountId, accountName: account.name, text, imageUrls: imageUrls || [], scheduledAt, status: 'pending', createdAt: new Date().toISOString() };
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

// 예약 발행 실행 (1분마다)
cron.schedule('* * * * *', async () => {
  if (!fs.existsSync('./data')) return;
  const userDirs = fs.readdirSync('./data');
  for (const userId of userDirs) {
    const posts = getScheduled(userId);
    const now = new Date();
    const pending = posts.filter(p => p.status === 'pending' && new Date(p.scheduledAt) <= now);
    for (const post of pending) {
      const accs = getAccounts(userId);
      const account = accs.find(a => a.id === post.accountId);
      if (!account) { post.status = 'failed'; continue; }
      try { await publishToThreads(account.accessToken, post.text, post.imageUrls); post.status = 'done'; }
      catch(e) { post.status = 'failed'; post.error = e.message; }
    }
    if (pending.length > 0) saveScheduled(userId, posts);
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
    const r = await fetch(`https://graph.threads.net/v1.0/me?fields=id,username,followers_count&access_token=${account.accessToken}`);
    res.json(await r.json());
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`서버 실행중: ${PORT}`));
