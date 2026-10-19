import express from 'express';
import fs from 'fs';
import crypto from 'crypto';
import { authenticator } from 'otplib';
import { execFile } from 'child_process';

const ADMIN = 'typposki';
const LIMITS = { free: 3, pro: 10, platin: Infinity };
const F = './db.json';
const db = fs.existsSync(F) ? JSON.parse(fs.readFileSync(F)) :
  { users: {}, ipBans: [], bots: [], payments: [], admin: { totp: null, passkey: null, setupDone: false }, sessions: {}, adminSessions: {} };
const save = () => fs.writeFileSync(F, JSON.stringify(db, null, 1));
const app = express();
app.set('trust proxy', true);
app.use(express.json());
const ip = (r) => r.ip;
const today = () => new Date().toISOString().slice(0, 10);
const ban = (u, reason, permanent = false) => { u.banned = { reason, permanent, ip: !!permanent }; save(); };

// ---- Login (TikTok OAuth: serverseitig Code gegen open_id tauschen, hier vereinfacht) ----
app.post('/login', (req, res) => {
  const { openId, handle } = req.body;
  if (!openId || !handle) return res.status(400).json({ error: 'missing' });
  if (db.ipBans.includes(ip(req))) return res.json({ banned: { reason: 'IP-Ban', permanent: true } });
  let u = db.users[openId] ||= { openId, handle, plan: 'free', planLocked: false, used: 0, day: today(), ips: [], banned: null };
  if (!u.ips.includes(ip(req))) u.ips.push(ip(req));
  // IP-Limit: max. 2 Accounts pro IP
  const onIp = Object.values(db.users).filter((x) => x.ips.includes(ip(req)));
  if (onIp.length > 2 && handle !== ADMIN && !u.banned) {
    u.plan = 'free'; u.planLocked = true;
    ban(u, 'Anti-Bot: Mehr als 2 Accounts pro IP (Botting)');
  }
  const token = crypto.randomUUID();
  db.sessions[token] = openId; save();
  res.json({ token, banned: u.banned });
});
const auth = (req, res, next) => {
  const u = db.users[db.sessions[req.headers.authorization]];
  if (!u) return res.status(401).json({ error: 'auth' });
  if (db.ipBans.includes(ip(req))) return res.json({ banned: { reason: 'IP-Ban', permanent: true } });
  req.u = u; next();
};
app.get('/me', auth, (req, res) => {
  const u = req.u; if (u.day !== today()) { u.day = today(); u.used = 0; }
  const out = { ...u, limit: LIMITS[u.plan] === Infinity ? 'unendlich' : LIMITS[u.plan], isAdmin: u.handle === ADMIN, lastPayment: [...db.payments].reverse().find((p) => p.openId === u.openId) };
  res.json(out);
});
app.post('/generate', auth, (req, res) => {
  const u = req.u; if (u.banned) return res.status(403).json({ banned: u.banned });
  if (u.day !== today()) { u.day = today(); u.used = 0; }
  if (u.used >= LIMITS[u.plan]) return res.status(429).json({ error: 'Tageslimit erreicht' });
  u.used++; save();
  const ins = fs.existsSync('./insights.json') ? JSON.parse(fs.readFileSync('./insights.json')) : { hashtags: [], sounds: [] };
  // TODO: hier KI-Videoerstellung aufrufen (eigener Dienst); Platzhalter-Ergebnis:
  res.json({ ok: true, hashtags: ins.hashtags.slice(0, 5), sound: ins.sounds[0] || null, videoUrl: null });
});
app.post('/pay', auth, (req, res) => {
  const { plan, code } = req.body;
  if (!['pro', 'platin'].includes(plan) || !code) return res.status(400).json({ error: 'invalid' });
  db.payments.push({ id: crypto.randomUUID(), openId: req.u.openId, handle: req.u.handle, plan, code, status: 'pending', at: Date.now() });
  save(); res.json({ ok: true });
});

// ---- Admin ----
const adm = (req, res, next) => {
  const u = db.users[db.sessions[req.headers.authorization]];
  if (!u || u.handle !== ADMIN) return res.status(403).json({ error: 'forbidden' });
  req.adminOk = !!db.adminSessions[req.headers.authorization]; req.u = u; next();
};
const admOk = (req, res, next) => adm(req, res, () => req.adminOk ? next() : res.status(401).json({ error: 'verify' }));
// Nur beim allerersten Mal: Setup mit Passkey + Authenticator-App
app.get('/admin/state', adm, (req, res) => res.json({ setupDone: db.admin.setupDone, verified: req.adminOk }));
app.post('/admin/setup/start', adm, (req, res) => {
  if (db.admin.setupDone) return res.status(403).json({ error: 'already' });
  db.admin.totp = authenticator.generateSecret(); save();
  res.json({ otpauth: authenticator.keyuri(ADMIN, 'TikBot', db.admin.totp), secret: db.admin.totp });
});
app.post('/admin/setup/finish', adm, (req, res) => {
  if (db.admin.setupDone) return res.status(403).json({ error: 'already' });
  // Passkey: hier @simplewebauthn/server einbauen (Registrierung). Platzhalter speichert Credential-ID.
  if (!authenticator.check(req.body.totp, db.admin.totp) || !req.body.passkeyCredentialId) return res.status(400).json({ error: 'invalid' });
  db.admin.passkey = req.body.passkeyCredentialId; db.admin.setupDone = true;
  db.adminSessions[req.headers.authorization] = true; save(); res.json({ ok: true });
});
app.post('/admin/verify', adm, (req, res) => {
  if (!db.admin.setupDone || !authenticator.check(req.body.totp, db.admin.totp)) return res.status(401).json({ error: 'invalid' });
  db.adminSessions[req.headers.authorization] = true; res.json({ ok: true });
});
const find = (h) => Object.values(db.users).find((u) => u.handle === h);
app.get('/admin/banned', admOk, (q, r) => r.json(Object.values(db.users).filter((u) => u.banned)));
app.post('/admin/unban', admOk, (q, r) => { const u = find(q.body.handle); if (!u || u.banned?.permanent) return r.status(400).json({ error: 'permanent' }); u.banned = null; save(); r.json({ ok: true }); });
app.post('/admin/ban', admOk, (q, r) => { const u = find(q.body.handle); if (!u) return r.status(404).json({}); ban(u, q.body.reason || 'Gebannt'); r.json({ ok: true }); });
app.post('/admin/ipban', admOk, (q, r) => { const u = find(q.body.handle); if (!u) return r.status(404).json({}); ban(u, q.body.reason || 'IP-Ban', true); u.ips.forEach((i) => !db.ipBans.includes(i) && db.ipBans.push(i)); save(); r.json({ ok: true }); });
app.get('/admin/users', admOk, (q, r) => r.json(Object.values(db.users).filter((u) => u.handle.includes(q.query.q || '')).map(({ handle, plan, planLocked }) => ({ handle, plan, planLocked }))));
app.post('/admin/plan', admOk, (q, r) => { const u = find(q.body.handle); if (!u || !LIMITS[q.body.plan]) return r.status(400).json({}); u.plan = q.body.plan; u.planLocked = false; save(); r.json({ ok: true }); });
app.get('/admin/bots', admOk, (q, r) => r.json(db.bots));
app.post('/admin/bots', admOk, (q, r) => { if (!['Sicherheit', 'Anti-Bot'].includes(q.body.role)) return r.status(400).json({}); db.bots.push({ id: crypto.randomUUID(), name: q.body.name, role: q.body.role }); save(); r.json({ ok: true }); });
app.get('/admin/payments', admOk, (q, r) => r.json(db.payments));
app.post('/admin/payments/:id', admOk, (q, r) => { const p = db.payments.find((x) => x.id === q.params.id); if (!p) return r.status(404).json({}); p.status = q.body.status === 'done' ? 'done' : 'rejected'; save(); r.json({ ok: true }); });

// ---- Rechtstexte (für TikTok-App-Prüfung) ----
const page = (title, body) => `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;line-height:1.6}</style></head><body><h1>${title}</h1>${body}</body></html>`;
const CONTACT = process.env.CONTACT_EMAIL || 'support-tikbot@proton.me';
app.get('/terms', (req, res) => res.send(page('Terms of Service / Nutzungsbedingungen', `
<p><i>Last updated: 2026-10-19</i></p>
<h2>1. Service</h2><p>TikBot helps users create TikTok videos with suggested hashtags and sounds. You sign in with your TikTok account.</p>
<h2>2. Plans</h2><p>Free: 3 videos per day. Pro: 3 EUR per month, 10 videos per day. Platin: 7.99 EUR per month, unlimited videos. Plans are activated manually after payment verification.</p>
<h2>3. Rules</h2><p>Using bots, automated accounts or multiple accounts to bypass plan limits is prohibited. Accounts may be suspended or permanently banned, including by IP address.</p>
<h2>4. Content</h2><p>You are responsible for the content you create and publish and must follow TikTok's Community Guidelines.</p>
<h2>5. Liability</h2><p>The service is provided "as is" without warranty. We may change or discontinue it at any time.</p>
<h2>6. Contact</h2><p>${CONTACT}</p>
<hr><h2>Deutsch</h2><p>TikBot unterstützt bei der Erstellung von TikTok-Videos. Bots und Mehrfach-Accounts zur Umgehung von Limits sind verboten und führen zu Sperren. Pläne: Free 3 Videos/Tag, Pro 3 €/Monat (10/Tag), Platin 7,99 €/Monat (unbegrenzt). Kontakt: ${CONTACT}</p>`)));
app.get('/privacy', (req, res) => res.send(page('Privacy Policy / Datenschutzerklärung', `
<p><i>Last updated: 2026-10-19</i></p>
<h2>1. Data we process</h2><p>When you sign in with TikTok we receive your TikTok open ID and username. We also store your IP address (for abuse prevention), your plan, daily usage counts, ban status and, if you pay, the payment code you submit.</p>
<h2>2. Purpose</h2><p>To provide the service, enforce plan limits, prevent abuse and bots, and verify payments.</p>
<h2>3. Sharing</h2><p>We do not sell your data. Data is processed on our hosting provider (Render). TikTok data is used only as permitted by TikTok's Developer Terms.</p>
<h2>4. Retention and deletion</h2><p>Data is kept while your account exists. To request deletion, contact ${CONTACT}.</p>
<h2>5. Your rights</h2><p>You may request access, correction or deletion of your data at any time.</p>
<h2>6. Contact</h2><p>${CONTACT}</p>
<hr><h2>Deutsch</h2><p>Wir verarbeiten TikTok-Nutzer-ID und Benutzername, IP-Adresse (Missbrauchsschutz), Plan, Nutzungszähler, Sperrstatus und ggf. den eingereichten Zahlungscode. Keine Weitergabe zu Werbezwecken. Auskunft und Löschung: ${CONTACT}</p>`)));

// ---- TikTok-Verbindung des Bot-Accounts (einmalig) ----
const PUBLIC_URL = process.env.PUBLIC_URL;
app.get('/tiktok/connect', (req, res) => {
  if (!process.env.BOT_SECRET || req.query.secret !== process.env.BOT_SECRET) return res.status(403).send('forbidden');
  const q = new URLSearchParams({ client_key: process.env.TIKTOK_CLIENT_KEY, scope: 'user.info.basic,video.publish', response_type: 'code', redirect_uri: PUBLIC_URL + '/tiktok/callback', state: req.query.secret });
  res.redirect('https://www.tiktok.com/v2/auth/authorize/?' + q);
});
app.get('/tiktok/callback', async (req, res) => {
  if (req.query.state !== process.env.BOT_SECRET || !req.query.code) return res.status(403).send('forbidden');
  const r = await fetch('https://open.tiktokapis.com/v2/oauth/token/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_key: process.env.TIKTOK_CLIENT_KEY, client_secret: process.env.TIKTOK_CLIENT_SECRET, code: req.query.code, grant_type: 'authorization_code', redirect_uri: PUBLIC_URL + '/tiktok/callback' }) });
  const t = await r.json();
  if (!t.access_token) return res.status(400).send('Fehler: ' + JSON.stringify(t));
  fs.writeFileSync('./tokens.json', JSON.stringify({ access_token: t.access_token, refresh_token: t.refresh_token, expires_at: Date.now() + t.expires_in * 1000 }));
  res.send('Bot-Account verbunden. Du kannst dieses Fenster schließen.');
});

app.post('/bot/run', (req, res) => {
  if (!process.env.BOT_SECRET || req.headers['x-bot-secret'] !== process.env.BOT_SECRET) return res.status(403).json({ error: 'forbidden' });
  execFile('node', ['bot.js'], (err, out) => console.log(err || out));
  res.json({ started: true });
});

app.listen(process.env.PORT || 3000, () => console.log('API läuft'));
