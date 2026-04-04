const express = require('express');
const cors = require('cors');
const multer = require('multer');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
const cron = require('node-cron');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }
});

// 예약 발행 저장소 (메모리 + JSON 파일)
const SCHEDULE_FILE = './scheduled_posts.json';
let scheduledPosts = [];
if (fs.existsSync(SCHEDULE_FILE)) {
  try { scheduledPosts = JSON.parse(fs.readFileSync(SCHEDULE_FILE)); } catch(e) {}
}
function saveScheduled() {
  fs.writeFileSync(SCHEDULE_FILE, JSON.stringify(scheduledPosts, null, 2));
}

// 계정 저장소
const ACCOUNTS_FILE = './accounts.json';
let accounts = [];
if (fs.existsSync(ACCOUNTS_FILE)) {
  try { accounts = JSON.parse(fs.readFileSync(ACCOUNTS_FILE)); } catch(e) {}
}
function saveAccounts() {
  fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(accounts, null, 2));
}

// ─── 계정 관리 ───
app.get('/api/accounts', (req, res) => res.json(accounts));

app.post('/api/accounts', (req, res) => {
  const { name, accessToken, userId } = req.body;
  if (!name || !accessToken) return res.status(400).json({ error: '이름과 토큰 필요' });
  const account = { id: Date.now().toString(), name, accessToken, userId: userId || '' };
  accounts.push(account);
  saveAccounts();
  res.json(account);
});

app.delete('/api/accounts/:id', (req, res) => {
  accounts = accounts.filter(a => a.id !== req.params.id);
  saveAccounts();
  res.json({ ok: true });
});

// ─── Gemini AI 글 생성 ───
app.post('/api/generate', async (req, res) => {
  const { topic, tone, type } = req.body; // type: 'post' | 'comment'
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'GEMINI_API_KEY 없음' });

  const toneMap = {
    '일상': '친구한테 말하듯 편하고 자연스럽게',
    '정보': '유용한 정보를 쉽게 설명하듯',
    '유머': '재치있고 웃긴 느낌으로',
    '감성': '감성적이고 공감되는 느낌으로',
    '도발': '자극적이고 관심끄는 느낌으로'
  };

  const toneDesc = toneMap[tone] || '자연스럽게';
  
  let prompt = '';
  if (type === 'comment') {
    prompt = `스레드(Threads SNS)에 달 댓글을 1개만 작성해줘.
주제: ${topic}
조건:
- 반드시 반말로
- ${toneDesc}
- 이모지 절대 사용 금지
- "첫째", "둘째", "결론적으로" 같은 형식적 표현 금지
- ~합니다, ~해요 같은 존댓말 절대 금지
- 짧고 자연스럽게 (1~2문장)
- 다른 설명 없이 댓글 텍스트만 출력`;
  } else {
    prompt = `스레드(Threads SNS)에 올릴 게시글을 작성해줘.
주제: ${topic}
조건:
- 반드시 반말로
- ${toneDesc}
- 이모지 절대 사용 금지
- "첫째", "둘째", "결론적으로" 같은 형식적 표현 금지
- ~합니다, ~해요 같은 존댓말 절대 금지
- SNS 특유의 자연스러운 구어체
- 500자 이내
- 다른 설명 없이 게시글 텍스트만 출력`;
  }

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.9, maxOutputTokens: 500 }
        })
      }
    );
    const data = await response.json();
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    res.json({ text: text.trim() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Threads 게시글 발행 ───
async function publishToThreads(accessToken, text, imageUrls = [], videoUrl = '') {
  let containerId;

  if (videoUrl) {
    // 영상
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ media_type: 'VIDEO', video_url: videoUrl, text, access_token: accessToken })
    });
    const d = await r.json();
    if (d.error) throw new Error(d.error.message);
    containerId = d.id;
    // 영상은 처리 시간 필요
    await new Promise(r => setTimeout(r, 10000));
  } else if (imageUrls.length === 0) {
    // 텍스트만
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ media_type: 'TEXT', text, access_token: accessToken })
    });
    const d = await r.json();
    if (d.error) throw new Error(d.error.message);
    containerId = d.id;
  } else if (imageUrls.length === 1) {
    // 이미지 1장
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ media_type: 'IMAGE', image_url: imageUrls[0], text, access_token: accessToken })
    });
    const d = await r.json();
    if (d.error) throw new Error(d.error.message);
    containerId = d.id;
  } else {
    // 이미지 여러장 (carousel)
    const childIds = [];
    for (const url of imageUrls) {
      const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ media_type: 'IMAGE', image_url: url, is_carousel_item: true, access_token: accessToken })
      });
      const d = await r.json();
      if (d.error) throw new Error(d.error.message);
      childIds.push(d.id);
    }
    await new Promise(r => setTimeout(r, 3000));
    const r = await fetch(`https://graph.threads.net/v1.0/me/threads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ media_type: 'CAROUSEL', children: childIds.join(','), text, access_token: accessToken })
    });
    const d = await r.json();
    if (d.error) throw new Error(d.error.message);
    containerId = d.id;
  }

  // 2. 발행
  await new Promise(r => setTimeout(r, 2000));
  const pub = await fetch(`https://graph.threads.net/v1.0/me/threads_publish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ creation_id: containerId, access_token: accessToken })
  });
  const pubData = await pub.json();
  if (pubData.error) throw new Error(pubData.error.message);
  return pubData.id;
}

// ─── 즉시 발행 ───
app.post('/api/publish', async (req, res) => {
  const { accountId, text, imageUrls, videoUrl } = req.body;
  const account = accounts.find(a => a.id === accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  try {
    const postId = await publishToThreads(account.accessToken, text, imageUrls || [], videoUrl || '');
    res.json({ ok: true, postId });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── 예약 발행 ───
app.post('/api/schedule', (req, res) => {
  const { accountId, text, imageUrls, scheduledAt } = req.body;
  const account = accounts.find(a => a.id === accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });

  const post = {
    id: Date.now().toString(),
    accountId,
    accountName: account.name,
    text,
    imageUrls: imageUrls || [],
    scheduledAt,
    status: 'pending',
    createdAt: new Date().toISOString()
  };
  scheduledPosts.push(post);
  saveScheduled();
  res.json(post);
});

app.get('/api/schedule', (req, res) => res.json(scheduledPosts));

app.delete('/api/schedule/:id', (req, res) => {
  scheduledPosts = scheduledPosts.filter(p => p.id !== req.params.id);
  saveScheduled();
  res.json({ ok: true });
});

// 예약 발행 실행 (1분마다 체크)
cron.schedule('* * * * *', async () => {
  const now = new Date();
  const pending = scheduledPosts.filter(p => p.status === 'pending' && new Date(p.scheduledAt) <= now);
  for (const post of pending) {
    const account = accounts.find(a => a.id === post.accountId);
    if (!account) { post.status = 'failed'; continue; }
    try {
      await publishToThreads(account.accessToken, post.text, post.imageUrls);
      post.status = 'done';
    } catch (e) {
      post.status = 'failed';
      post.error = e.message;
    }
  }
  if (pending.length > 0) saveScheduled();
});

// ─── 인사이트 ───
app.get('/api/insights/:accountId', async (req, res) => {
  const account = accounts.find(a => a.id === req.params.accountId);
  if (!account) return res.status(404).json({ error: '계정 없음' });

  try {
    const r = await fetch(
      `https://graph.threads.net/v1.0/me?fields=id,username,followers_count,threads_profile_audience_gender_age&access_token=${account.accessToken}`
    );
    const data = await r.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── 실시간 키워드 ───
app.get('/api/keywords', async (req, res) => {
  const results = { google: [], naver: [], threads: [] };

  // 구글 트렌드 (RSS)
  try {
    const r = await fetch('https://trends.google.co.kr/trending/rss?geo=KR', {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
    });
    const xml = await r.text();
    const titles = [...xml.matchAll(/<title><![CDATA[(.+?)]]></title>/g)].slice(1, 11);
    const traffics = [...xml.matchAll(/<ht:approx_traffic>([^<]+)</ht:approx_traffic>/g)];
    results.google = titles.map((m, i) => ({ text: m[1], traffic: traffics[i]?.[1] || '' }));
  } catch(e) { console.log('구글 트렌드 실패:', e.message); }

  // 네이버 - signal.bz 크롤링
  try {
    const r = await fetch('https://signal.bz/news/realtime', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
        'Accept-Language': 'ko-KR,ko;q=0.9',
        'Referer': 'https://signal.bz/'
      }
    });
    const html = await r.text();
    const matches = [...html.matchAll(/class="tit"[^>]*>s*([^<]{2,20})s*</[a-z]/g)];
    const keywords = [...new Set(matches.map(m => m[1].trim()).filter(k => k.length >= 2))].slice(0, 10);
    results.naver = keywords.map(t => ({ text: t }));
  } catch(e) { console.log('네이버 크롤링 실패:', e.message); }

  // Threads 탭 - 구글 최근 4시간 트렌드
  try {
    const r = await fetch('https://trends.google.co.kr/trending/rss?geo=KR&hours=4', {
      headers: { 'User-Agent': 'Mozilla/5.0' }
    });
    const xml = await r.text();
    const titles = [...xml.matchAll(/<title><![CDATA[(.+?)]]></title>/g)].slice(1, 6);
    results.threads = titles.map(m => ({ text: m[1], isNew: true }));
  } catch(e) {}

  res.json(results);
});

// ─── 이미지 업로드 (imgbb) ───
app.post('/api/upload', upload.array('images', 10), async (req, res) => {
  const apiKey = process.env.IMGBB_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'IMGBB_API_KEY 없음' });
  try {
    const urls = [];
    for (const file of req.files) {
      const base64 = file.buffer.toString('base64');
      const form = new URLSearchParams();
      form.append('key', apiKey);
      form.append('image', base64);
      const r = await fetch('https://api.imgbb.com/1/upload', { method: 'POST', body: form });
      const d = await r.json();
      if (d.data?.url) urls.push(d.data.url);
    }
    res.json({ urls });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── 영상 업로드 (로컬 임시 저장 후 URL 제공) ───
const videoUpload = multer({ storage: multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = './uploads';
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname)
}), limits: { fileSize: 1024 * 1024 * 1024 } });

app.use('/uploads', express.static('uploads'));

app.post('/api/upload-video', videoUpload.single('video'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: '영상 없음' });
  const baseUrl = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
  res.json({ url: `${baseUrl}/uploads/${req.file.filename}` });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`서버 실행중: ${PORT}`));

// ─── 계정 주제 태그 수정 ───
app.put('/api/accounts/:id/topics', (req, res) => {
  const account = accounts.find(a => a.id === req.params.id);
  if (!account) return res.status(404).json({ error: '계정 없음' });
  account.topics = req.body.topics || [];
  saveAccounts();
  res.json(account);
});
