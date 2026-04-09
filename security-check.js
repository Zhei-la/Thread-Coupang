const fs = require('fs');
const path = require('path');
const https = require('https');

const SKIP = ['node_modules', '.git', 'dist', 'build'];
const EXT = ['.js', '.ts', '.py', '.html', '.json'];

function collect(dir, out = []) {
  try {
    fs.readdirSync(dir).forEach(e => {
      if (SKIP.includes(e)) return;
      const f = path.join(dir, e);
      try {
        const s = fs.statSync(f);
        if (s.isDirectory()) collect(f, out);
        else if (EXT.some(x => f.endsWith(x))) out.push(f);
      } catch {}
    });
  } catch {}
  return out;
}

let code = '';
for (const f of collect('.')) {
  try {
    code += '\n--- ' + f + ' ---\n' + fs.readFileSync(f, 'utf8');
    if (code.length > 10000) { code = code.slice(0, 10000) + '...'; break; }
  } catch {}
}

const prompt = `보안 전문가로서 아래 코드의 취약점을 분석하세요.
코드:
${code}

반드시 JSON만 응답 (마크다운 없이):
{"overall":"safe|warning|danger","summary":"요약","critical":[{"title":"제목","detail":"설명","fix":"수정"}],"warning":[{"title":"제목","detail":"설명","fix":"수정"}],"passed":["항목"]}`;

function post(hostname, p, body, headers) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname, path: p, method: 'POST', headers }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve(JSON.parse(d)));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

(async () => {
  try {
    const body = JSON.stringify({
      model: 'gpt-4o-mini',
      max_tokens: 1500,
      messages: [{ role: 'user', content: prompt }]
    });

    const r = await post('api.openai.com', '/v1/chat/completions', body, {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + process.env.OPENAI_API_KEY
    });

    const text = r.choices[0].message.content.replace(/```json|```/g, '').trim();
    const j = JSON.parse(text);

    const e = j.overall === 'danger' ? '🚨' : j.overall === 'warning' ? '⚠️' : '✅';
    const color = j.overall === 'danger' ? 0xE24B4A : j.overall === 'warning' ? 0xEF9F27 : 0x639922;
    const now = new Date().toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' });

    const fields = [];
    if (j.critical && j.critical.length) fields.push({
      name: '🚨 위험',
      value: j.critical.map(i => `**${i.title}**\n${i.detail}\n수정: ${i.fix}`).join('\n\n').slice(0, 900)
    });
    if (j.warning && j.warning.length) fields.push({
      name: '⚠️ 경고',
      value: j.warning.map(i => `**${i.title}**\n${i.detail}\n수정: ${i.fix}`).join('\n\n').slice(0, 900)
    });
    if (j.passed && j.passed.length) fields.push({
      name: '✅ 안전',
      value: j.passed.map(p => '• ' + p).join('\n').slice(0, 500)
    });

    const wb = JSON.stringify({
      embeds: [{
        title: `${e} 보안점검 - ${process.env.REPO_NAME}`,
        description: j.summary,
        color,
        fields,
        footer: { text: '점검: ' + now }
      }]
    });

    const u = new URL(process.env.DISCORD_WEBHOOK);
    await post(u.hostname, u.pathname + u.search, wb, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(wb)
    });

    console.log('✅ 완료');
  } catch (e) {
    console.error('오류:', e.message);
    process.exit(1);
  }
})();
