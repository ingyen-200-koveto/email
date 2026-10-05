const express = require("express"), nodemailer = require("nodemailer"), crypto = require("crypto"), fs = require("fs"), path = require("path");
const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "10kb" }));

// Adattárolás (teszthez egy fájl; az ingyenes tárhelyen újraindításkor törlődhet)
const FILE = path.join(__dirname, "data.json");
let db = { users: {}, sessions: {} };
try { db = JSON.parse(fs.readFileSync(FILE, "utf8")); } catch (e) {}
const save = () => { try { fs.writeFileSync(FILE, JSON.stringify(db)); } catch (e) { console.error("Mentési hiba:", e.message); } };

const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString("hex");
const same = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const ALPH = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const makeCode = () => Array.from({ length: 12 }, () => ALPH[crypto.randomInt(ALPH.length)]).join("");
const mask = e => e.replace(/^(.).*(@.*)$/, "$1***$2");
const pub = u => ({ name: u.name, email: u.email, coins: u.coins || 0 });
const fail = (res, code, error) => res.status(code).json({ error });

// Egyszerű kérésszám-korlát
const hits = {};
const limit = (max, ms) => (req, res, next) => {
  const k = req.ip + req.path, n = Date.now();
  hits[k] = (hits[k] || []).filter(t => n - t < ms);
  if (hits[k].length >= max) return fail(res, 429, "Túl sok kérés. Próbáld később.");
  hits[k].push(n); next();
};

// E-mail küldés (Gmail)
const mailer = process.env.GMAIL_USER && process.env.GMAIL_PASS
  ? nodemailer.createTransport({ service: "gmail", auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS } }) : null;
const base = req => process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || req.protocol + "://" + req.get("host");

async function sendCode(req, u, code) {
  if (!mailer) throw new Error("Az e-mail küldés nincs beállítva (GMAIL_USER, GMAIL_PASS).");
  const link = base(req) + "/?megerosites=" + u.name + ":" + code;
  const text = `Kedves ${u.name}!\nKöszönjük, hogy regisztráltál weboldalunkon!\nKattints a linkre, hogy megerősítsd a fiókod.\n${link}\nvagy a megerősítő oldalon az alábbi kódot másold/írd be.\n${code}\nÜdvözlettel, IceMine csapata!`;
  const html = `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:28px;background:#f2f8fc;color:#0a1e2b"><h2 style="margin:0 0 16px;color:#0b3a5b">IceMine</h2><p>Kedves <b>${u.name}</b>!</p><p>Köszönjük, hogy regisztráltál weboldalunkon!</p><p>Kattints a linkre, hogy megerősítsd a fiókod.</p><p><a href="${link}" style="display:inline-block;padding:12px 22px;background:#1c8ad6;color:#fff;border-radius:999px;text-decoration:none;font-weight:bold">Fiók megerősítése</a></p><p>vagy a megerősítő oldalon az alábbi kódot másold/írd be.</p><p style="font-size:24px;letter-spacing:3px;font-weight:bold;background:#fff;padding:14px;border-radius:10px;text-align:center">${code}</p><p>Üdvözlettel,<br>IceMine csapata!</p></div>`;
  await mailer.sendMail({ from: `IceMine <${process.env.GMAIL_USER}>`, to: u.email, subject: "IceMine – fiók megerősítése", text, html });
}
async function issue(req, u) {
  const code = makeCode();
  u.v = { h: sha(u.salt + code), exp: Date.now() + 864e5, tries: 0, sent: Date.now() };
  save();
  await sendCode(req, u, code);
}
function verifyCode(key, code) {
  const u = db.users[key];
  if (!u || !u.v) return "Ehhez a fiókhoz nincs függő megerősítés.";
  if (Date.now() > u.v.exp) return "A kód lejárt. Kérj újat.";
  if (u.v.tries >= 5) return "Túl sok hibás próbálkozás. Kérj új kódot.";
  if (!same(u.v.h, sha(u.salt + String(code).toUpperCase()))) { u.v.tries++; save(); return "Hibás kód."; }
  u.verified = true; delete u.v; save(); return "";
}
function session(u) {
  const t = crypto.randomBytes(32).toString("hex");
  db.sessions[sha(t)] = { k: u.name.toLowerCase(), exp: Date.now() + 30 * 864e5 };
  save(); return t;
}
function authUser(req) {
  const t = (req.headers.authorization || "").slice(7);
  const s = t && db.sessions[sha(t)];
  return s && s.exp > Date.now() ? db.users[s.k] || null : null;
}
const taken = (u) => u && (u.verified || (u.v && u.v.exp > Date.now()));

app.post("/api/register", limit(10, 36e5), async (req, res) => {
  const { name = "", email = "", password = "" } = req.body || {};
  if (!/^[A-Za-z0-9_]{3,16}$/.test(name)) return fail(res, 400, "A Minecraft név 3–16 karakter lehet: betű, szám, aláhúzás.");
  if (typeof email !== "string" || email.length > 100 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return fail(res, 400, "Adj meg érvényes e-mail címet.");
  if (typeof password !== "string" || password.length < 6 || password.length > 100) return fail(res, 400, "A jelszó legalább 6 karakter legyen.");
  const key = name.toLowerCase(), mail = email.toLowerCase();
  if (taken(db.users[key])) return fail(res, 409, "Ez a Minecraft név már foglalt.");
  if (Object.values(db.users).some(x => x.email === mail && taken(x))) return fail(res, 409, "Ezzel az e-mail címmel már van fiók.");
  const salt = crypto.randomBytes(16).toString("hex");
  const u = db.users[key] = { name, email: mail, salt, hash: hashPw(password, salt), verified: false, coins: 0, created: Date.now() };
  try { await issue(req, u); }
  catch (e) { delete db.users[key]; save(); console.error("E-mail hiba:", e.message); return fail(res, 502, "Nem sikerült elküldeni az e-mailt. Ellenőrizd a címet, vagy próbáld később."); }
  res.json({ ok: true, mail: mask(u.email) });
});

app.post("/api/verify", limit(30, 6e5), (req, res) => {
  const { name = "", code = "" } = req.body || {};
  const key = String(name).toLowerCase(), err = verifyCode(key, code);
  if (err) return fail(res, 400, err);
  const u = db.users[key];
  res.json({ ok: true, token: session(u), user: pub(u) });
});

app.post("/api/resend", limit(10, 6e5), async (req, res) => {
  const u = db.users[String((req.body || {}).name || "").toLowerCase()];
  if (!u || u.verified) return res.json({ ok: true });
  if (u.v && Date.now() - u.v.sent < 3e4) return fail(res, 429, "Várj fél percet az új kód kérése előtt.");
  try { await issue(req, u); } catch (e) { console.error("E-mail hiba:", e.message); return fail(res, 502, "Nem sikerült elküldeni az e-mailt."); }
  res.json({ ok: true, mail: mask(u.email) });
});

app.post("/api/login", limit(30, 6e5), async (req, res) => {
  const { name = "", password = "" } = req.body || {};
  const u = db.users[String(name).toLowerCase()];
  if (!u || typeof password !== "string" || !same(u.hash, hashPw(password, u.salt))) return fail(res, 401, "Hibás Minecraft név vagy jelszó.");
  if (!u.verified) {
    if (!u.v || Date.now() - u.v.sent > 3e4) { try { await issue(req, u); } catch (e) { console.error("E-mail hiba:", e.message); return fail(res, 502, "Nem sikerült elküldeni a megerősítő e-mailt."); } }
    return res.json({ needVerify: true, name: u.name, mail: mask(u.email) });
  }
  res.json({ ok: true, token: session(u), user: pub(u) });
});

app.get("/api/me", (req, res) => { const u = authUser(req); u ? res.json({ user: pub(u) }) : fail(res, 401, "Nem vagy bejelentkezve."); });
app.post("/api/logout", (req, res) => { const t = (req.headers.authorization || "").slice(7); if (t) { delete db.sessions[sha(t)]; save(); } res.json({ ok: true }); });
app.get("/api/status", (req, res) => res.json({ online: null })); // később a Minecraft szerverből

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.listen(process.env.PORT || 3000, () => console.log("IceMine fut"));
