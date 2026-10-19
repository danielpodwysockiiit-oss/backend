// Täglicher Werbe-Bot. Tokens kommen aus tokens.json (wird durch /tiktok/connect erzeugt).
// DEINE DATEN für den Bot (Insights) trägst du hier ein:
import fs from 'fs';

const CONFIG = {
  hashtags: ['#fyp', '#viral'],
  sounds: ['trend-sound-1'],
  captionBase: 'Erstelle virale TikToks mit KI',
};
const TOKENS = './tokens.json';
const API = 'https://open.tiktokapis.com';

async function getToken() {
  if (!fs.existsSync(TOKENS)) throw new Error('Bot-Account noch nicht verbunden (/tiktok/connect)');
  let t = JSON.parse(fs.readFileSync(TOKENS));
  if (t.expires_at < Date.now() + 60000) {
    const r = await fetch(API + '/v2/oauth/token/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_key: process.env.TIKTOK_CLIENT_KEY, client_secret: process.env.TIKTOK_CLIENT_SECRET, grant_type: 'refresh_token', refresh_token: t.refresh_token }) });
    const n = await r.json();
    if (!n.access_token) throw new Error('Refresh fehlgeschlagen: ' + JSON.stringify(n));
    t = { access_token: n.access_token, refresh_token: n.refresh_token || t.refresh_token, expires_at: Date.now() + n.expires_in * 1000 };
    fs.writeFileSync(TOKENS, JSON.stringify(t));
  }
  return t.access_token;
}

// TODO: hier KI-Video erzeugen und den Pfad der fertigen mp4-Datei zurückgeben.
// Zum Testen/Demo: Lege eine kleine Datei "demo.mp4" ins Hauptverzeichnis des Repos.
async function makeVideo(i) { return fs.existsSync('./demo.mp4') ? './demo.mp4' : null; }

async function post(token, file, title) {
  const size = fs.statSync(file).size;
  const r = await fetch(API + '/v2/post/publish/video/init/', { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json; charset=UTF-8' },
    body: JSON.stringify({ post_info: { title, privacy_level: 'SELF_ONLY' }, // SELF_ONLY bis TikTok deine App freigegeben hat
      source_info: { source: 'FILE_UPLOAD', video_size: size, chunk_size: size, total_chunk_count: 1 } }) });
  const init = await r.json();
  const url = init.data?.upload_url;
  if (!url) return init;
  const up = await fetch(url, { method: 'PUT', headers: { 'Content-Type': 'video/mp4', 'Content-Range': `bytes 0-${size - 1}/${size}` }, body: fs.readFileSync(file) });
  return { init: init.data?.publish_id, upload: up.status };
}

fs.writeFileSync('./insights.json', JSON.stringify({ hashtags: CONFIG.hashtags, sounds: CONFIG.sounds }));
try {
  const token = await getToken();
  for (let i = 1; i <= 5; i++) {
    const url = await makeVideo(i);
    if (i > 1 && url === './demo.mp4') { console.log('Demo: nur 1 Video'); break; }
    if (!url) { console.log(`Video ${i}/5 übersprungen (noch keine Videoerzeugung)`); continue; }
    const res = await post(token, url, CONFIG.captionBase + ' ' + CONFIG.hashtags.join(' '));
    console.log(`Video ${i}/5`, JSON.stringify(res));
  }
} catch (e) { console.error('Bot-Fehler:', e.message); }
