import express from 'express';
import fs from 'fs';
import crypto from 'crypto';
import { authenticator } from 'otplib';

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

app.listen(process.env.PORT || 3000, () => console.log('API läuft'));
