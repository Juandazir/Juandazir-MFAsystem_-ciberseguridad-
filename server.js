const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');
const twilio = require('twilio');

const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'database', 'data.json');
const EMAIL_CONFIG_PATH = path.join(__dirname, 'database', 'email-config.json');
const SMS_CARRIERS_CONFIG_PATH = path.join(__dirname, 'database', 'sms-carriers.json');
const TWILIO_CONFIG_PATH = path.join(__dirname, 'database', 'twilio-config.json');
const CALLMEBOT_CONFIG_PATH = path.join(__dirname, 'database', 'callmebot-config.json');

// Carriers de Colombia con sus gateways email->SMS
const DEFAULT_SMS_CARRIERS = [
  { id: 'claro',       name: 'Claro Colombia',        gateway: 'iclaro.com.co' },
  { id: 'claro2',      name: 'Claro Colombia (alt)',   gateway: 'clarocolombia.com.co' },
  { id: 'movistar',    name: 'Movistar Colombia',      gateway: 'movistar.com.co' },
  { id: 'tigo',        name: 'Tigo Colombia',          gateway: 'sms.tigo.com.co' },
  { id: 'wom',         name: 'WOM Colombia',           gateway: 'wom.co' },
  { id: 'etb',         name: 'ETB Colombia',           gateway: 'etb.net.co' },
  { id: 'virgin',      name: 'Virgin Mobile Colombia',  gateway: 'movistar.com.co' },
  { id: 'other',       name: 'Otro (solo consola)',     gateway: '' },
];
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_EXPIRY = 3600 * 1000;
const LOCKOUT_THRESHOLD = 3;
const LOCKOUT_DURATION = 15 * 60 * 1000;
const TOTP_PERIOD = 30;
const TOTP_DIGITS = 6;
const MAX_LOGIN_ATTEMPTS_PER_MINUTE = 10;
const OTP_LENGTH = 6;
const OTP_EXPIRY = 5 * 60 * 1000;

const LOG_LEVELS = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
const LOG_LEVEL = LOG_LEVELS[process.env.LOG_LEVEL] || LOG_LEVELS.INFO;

function log(level, msg, meta) {
  if (LOG_LEVELS[level] < LOG_LEVEL) return;
  const line = `[${new Date().toISOString()}] [${level.padEnd(5)}] ${msg}${meta ? ' ' + JSON.stringify(meta) : ''}`;
  if (level === 'ERROR') console.error(line); else console.log(line);
}

// ─── OTP Store (in-memory) ──────────────────────────────────
const otpStore = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of otpStore) {
    if (now > val.expires) otpStore.delete(key);
  }
}, 60000);

function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function storeOTP(key, code) {
  otpStore.set(key, { code, expires: Date.now() + OTP_EXPIRY, attempts: 0 });
  log('INFO', 'OTP stored', { key });
}

function verifyOTP(key, code) {
  const entry = otpStore.get(key);
  if (!entry) return false;
  entry.attempts++;
  if (entry.attempts > 5) { otpStore.delete(key); return false; }
  if (Date.now() > entry.expires) { otpStore.delete(key); return false; }
  if (entry.code !== code) return false;
  otpStore.delete(key);
  return true;
}

// ─── TOTP ──────────────────────────────────────────────────
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = '', result = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  for (let i = 0; i + 5 <= bits.length; i += 5)
    result += BASE32[parseInt(bits.substring(i, i + 5), 2)];
  return result;
}

function base32Decode(str) {
  let bits = '';
  for (const c of str.toUpperCase()) {
    const idx = BASE32.indexOf(c);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8)
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  return Buffer.from(bytes);
}

function generateTOTPSecret(length = 20) {
  return base32Encode(crypto.randomBytes(length));
}

function computeTOTP(secret, timestamp = Date.now(), period = TOTP_PERIOD, digits = TOTP_DIGITS) {
  let counter = Math.floor(timestamp / 1000 / period);
  const counterBuf = Buffer.alloc(8);
  for (let i = 7; i >= 0; i--) {
    counterBuf[i] = counter & 0xff;
    counter >>= 8;
  }
  const hmac = crypto.createHmac('sha1', base32Decode(secret));
  hmac.update(counterBuf);
  const hash = hmac.digest();
  const offset = hash[hash.length - 1] & 0xf;
  const code = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
  return String(code % Math.pow(10, digits)).padStart(digits, '0');
}

function verifyTOTP(secret, code, window = 2) {
  const now = Date.now();
  for (let i = -window; i <= window; i++) {
    if (computeTOTP(secret, now + i * TOTP_PERIOD * 1000) === code) return true;
  }
  return false;
}

function generateOTPAuthURL(secret, email, issuer = 'MFASystem') {
  const params = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: TOTP_DIGITS, period: TOTP_PERIOD });
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?${params}`;
}

// ─── Password ─────────────────────────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  return crypto.scryptSync(password, salt, 64).toString('hex') === hash;
}

// ─── JWT ──────────────────────────────────────────────────
function createJWT(payload, expiresIn = JWT_EXPIRY) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, iat: Date.now(), exp: Date.now() + expiresIn })).toString('base64url');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${parts[0]}.${parts[1]}`).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(parts[2]))) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

// ─── Database (SQLite) ─────────────────────────────────────
const Database = require('better-sqlite3');

class DatabaseManager {
  constructor(filePath) {
    this.filePath = filePath;
    this.jsonPath = filePath.replace(/\.sqlite$/, '.json');
    this._ensureDir();
    // Open with WAL mode for concurrent reads
    this.db = new Database(filePath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this._setupSchema();
    this._migrateFromJson();
    log('INFO', 'Database opened', { path: filePath });
  }

  _ensureDir() {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }

  _setupSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        email           TEXT    UNIQUE NOT NULL,
        name            TEXT    NOT NULL DEFAULT '',
        password        TEXT    NOT NULL,
        role            TEXT    NOT NULL DEFAULT 'user',
        phone           TEXT    NOT NULL DEFAULT '',
        phone_verified  INTEGER NOT NULL DEFAULT 0,
        email_verified  INTEGER NOT NULL DEFAULT 0,
        mfa_totp_enabled  INTEGER NOT NULL DEFAULT 0,
        mfa_totp_secret   TEXT    NOT NULL DEFAULT '',
        mfa_sms_enabled   INTEGER NOT NULL DEFAULT 0,
        mfa_email_enabled INTEGER NOT NULL DEFAULT 0,
        failed_attempts   INTEGER NOT NULL DEFAULT 0,
        is_locked         INTEGER NOT NULL DEFAULT 0,
        lockout_until     TEXT,
        created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
        updated_at        TEXT    NOT NULL DEFAULT (datetime('now'))
      )
    `);
    // Add mfa_whatsapp_enabled column if it doesn't exist (migration)
    try { this.db.exec('ALTER TABLE users ADD COLUMN mfa_whatsapp_enabled INTEGER NOT NULL DEFAULT 0'); } catch (e) { /* already exists */ }
  }

  _migrateFromJson() {
    if (!fs.existsSync(this.jsonPath)) return;
    try {
      const json = JSON.parse(fs.readFileSync(this.jsonPath, 'utf8'));
      if (!json.users || json.users.length === 0) return;
      const insert = this.db.prepare(`
        INSERT OR IGNORE INTO users
          (id, email, name, password, role, phone, phone_verified, email_verified,
           mfa_totp_enabled, mfa_totp_secret, mfa_sms_enabled, mfa_email_enabled, mfa_whatsapp_enabled,
           failed_attempts, is_locked, lockout_until, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      const tx = this.db.transaction((users) => {
        for (const u of users) {
          insert.run(
            u.id, u.email.toLowerCase(), u.name || u.email.split('@')[0],
            u.password, u.role || 'user', u.phone || '',
            u.phone_verified ? 1 : 0, u.email_verified ? 1 : 0,
            (u.mfa_totp_enabled || u.mfa_enabled) ? 1 : 0,
            u.mfa_totp_secret || u.mfa_secret || generateTOTPSecret(),
            u.mfa_sms_enabled ? 1 : 0, u.mfa_email_enabled ? 1 : 0,
            u.mfa_whatsapp_enabled ? 1 : 0,
            u.failed_attempts || 0, u.is_locked ? 1 : 0,
            u.lockout_until || null,
            u.created_at || new Date().toISOString(),
            u.updated_at || new Date().toISOString()
          );
        }
      });
      tx(json.users);
      const count = this.db.prepare('SELECT COUNT(*) as count FROM users').get().count;
      log('INFO', 'Migrated from JSON', { users: count });
      // Rename JSON so it's not imported again
      fs.renameSync(this.jsonPath, this.jsonPath + '.backup');
    } catch (e) { log('ERROR', 'Migration failed', { error: e.message }); }
  }

  // Convert raw row from SQLite → JS object (booleans, remove sensitive fields)
  _sanitizeUser(row) {
    if (!row) return null;
    return {
      id: row.id, email: row.email, name: row.name, role: row.role,
      phone: row.phone, phone_verified: !!row.phone_verified,
      email_verified: !!row.email_verified,
      mfa_totp_enabled: !!row.mfa_totp_enabled,
      mfa_sms_enabled: !!row.mfa_sms_enabled,
      mfa_email_enabled: !!row.mfa_email_enabled,
      mfa_whatsapp_enabled: !!row.mfa_whatsapp_enabled,
      failed_attempts: row.failed_attempts,
      is_locked: !!row.is_locked, lockout_until: row.lockout_until,
      created_at: row.created_at, updated_at: row.updated_at,
    };
  }

  _rowToUser(row) {
    if (!row) return null;
    // Full user object with sensitive fields, booleans as JS booleans
    const u = { ...row };
    u.phone_verified = !!u.phone_verified;
    u.email_verified = !!u.email_verified;
    u.mfa_totp_enabled = !!u.mfa_totp_enabled;
    u.mfa_sms_enabled = !!u.mfa_sms_enabled;
    u.mfa_email_enabled = !!u.mfa_email_enabled;
    u.mfa_whatsapp_enabled = !!u.mfa_whatsapp_enabled;
    u.is_locked = !!u.is_locked;
    return u;
  }

  findUserByEmail(email) {
    return this._rowToUser(this.db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase()));
  }

  findUserById(id) {
    return this._rowToUser(this.db.prepare('SELECT * FROM users WHERE id = ?').get(id));
  }

  getAllUsers() {
    return this.db.prepare('SELECT * FROM users ORDER BY id').all().map(u => this._sanitizeUser(u));
  }

  getStats() {
    const s = this.db.prepare(`
      SELECT
        COUNT(*)                                              AS total,
        SUM(CASE WHEN is_locked = 1 THEN 1 ELSE 0 END)        AS locked,
        SUM(CASE WHEN mfa_totp_enabled=1 OR mfa_sms_enabled=1 OR mfa_email_enabled=1 OR mfa_whatsapp_enabled=1 THEN 1 ELSE 0 END) AS mfa_enabled,
        SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END)       AS admins
      FROM users
    `).get();
    return { total: s.total, locked: s.locked || 0, mfa_enabled: s.mfa_enabled || 0, admins: s.admins || 0 };
  }

  createUser(email, password, name) {
    const hashed = hashPassword(password);
    const now = new Date().toISOString();
    const secret = generateTOTPSecret();
    const stmt = this.db.prepare(`
      INSERT INTO users (email, name, password, mfa_totp_secret, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(email.toLowerCase(), name || email.split('@')[0], hashed, secret, now, now);
    const user = this.findUserById(result.lastInsertRowid);
    log('INFO', 'User registered', { id: user.id, email: user.email });
    return this._sanitizeUser(user);
  }

  updateUser(id, updates) {
    const allowed = ['name','email','password','phone','role','phone_verified','email_verified',
      'mfa_totp_enabled','mfa_totp_secret','mfa_sms_enabled','mfa_email_enabled','mfa_whatsapp_enabled',
      'failed_attempts','is_locked','lockout_until'];
    const sets = [];
    const vals = [];
    for (const key of allowed) {
      if (key in updates) {
        let val = updates[key];
        // Convert JS booleans → SQLite INTEGER
        if (['phone_verified','email_verified','mfa_totp_enabled','mfa_sms_enabled','mfa_whatsapp_enabled','mfa_email_enabled','is_locked'].includes(key)) {
          val = val ? 1 : 0;
        }
        sets.push(key + ' = ?');
        vals.push(val);
      }
    }
    if (sets.length === 0) return this._sanitizeUser(this.findUserById(id));
    vals.push(new Date().toISOString());
    vals.push(id);
    this.db.prepare(`UPDATE users SET ${sets.join(', ')}, updated_at = ? WHERE id = ?`).run(...vals);
    return this._sanitizeUser(this.findUserById(id));
  }

  deleteUser(id) {
    this.db.prepare('DELETE FROM users WHERE id = ?').run(id);
  }

  // For shutdown compatibility — SQLite saves automatically via WAL
  save() {}
}

const db = new DatabaseManager(DB_PATH.replace(/\.json$/, '.sqlite'));

// ─── Rate Limiter ──────────────────────────────────────────
const rateLimitMap = new Map();
function rateLimit(key, maxAttempts = MAX_LOGIN_ATTEMPTS_PER_MINUTE, windowMs = 60000) {
  if (!key.includes(':')) {
    log('WARN', 'Rate limit key missing prefix', { key });
    key = 'global:' + key;
  }
  const now = Date.now();
  const entry = rateLimitMap.get(key);
  if (!entry || now - entry.windowStart > windowMs) {
    rateLimitMap.set(key, { windowStart: now, count: 1 });
    return { allowed: true, remaining: maxAttempts - 1 };
  }
  entry.count++;
  if (entry.count > maxAttempts) return { allowed: false, remaining: 0, retryAfter: Math.ceil((windowMs - (now - entry.windowStart)) / 1000) };
  return { allowed: true, remaining: maxAttempts - entry.count };
}
setInterval(() => { const n = Date.now(); for (const [k, e] of rateLimitMap) { if (n - e.windowStart > 120000) rateLimitMap.delete(k); } }, 300000);

// ─── HTTP Helpers ──────────────────────────────────────────
const MIME_TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.ico': 'image/x-icon', '.svg': 'image/svg+xml', '.woff2': 'font/woff2' };

function sendJSON(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
  });
  res.end(body);
}

function sendError(res, status, message, code) { sendJSON(res, status, { error: message, code: code || `ERR_${status}` }); }

function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
  });
}

function getAuthUser(req) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return verifyJWT(auth.slice(7));
}

function serveStatic(url, res) {
  let filePath = path.join(__dirname, 'frontend', 'public', url === '/' ? 'index.html' : url);
  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';
  const securityHeaders = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'",
  };
  fs.readFile(filePath, (err, content) => {
    if (err) {
      fs.readFile(path.join(__dirname, 'frontend', 'public', 'index.html'), (err2, idx) => {
        if (err2) { res.writeHead(404, securityHeaders); res.end('404 Not Found'); }
        else { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...securityHeaders }); res.end(idx); }
      });
    } else {
      res.writeHead(200, { 'Content-Type': contentType, 'Cache-Control': ext === '.html' ? 'no-cache' : 'max-age=3600', ...securityHeaders });
      res.end(content);
    }
  });
}

// ─── Validation ────────────────────────────────────────────
function validateEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function validatePhone(phone) { return /^\+?[\d\s\-()]{7,20}$/.test(phone); }

// ─── Email ──────────────────────────────────────────────────
function getEmailConfig() {
  try {
    if (fs.existsSync(EMAIL_CONFIG_PATH)) {
      const cfg = JSON.parse(fs.readFileSync(EMAIL_CONFIG_PATH, 'utf8'));
      cfg.host = cfg.host || process.env.SMTP_HOST || 'smtp.gmail.com';
      cfg.port = cfg.port || parseInt(process.env.SMTP_PORT) || 587;
      cfg.user = cfg.user || process.env.SMTP_USER || '';
      cfg.pass = cfg.pass || process.env.SMTP_PASS || '';
      cfg.from = cfg.from || process.env.SMTP_FROM || cfg.user || '';
      return cfg;
    }
  } catch (e) { log('ERROR', 'Email config read error', { error: e.message }); }
  return { host: process.env.SMTP_HOST || 'smtp.gmail.com', port: parseInt(process.env.SMTP_PORT) || 587, user: process.env.SMTP_USER || '', pass: process.env.SMTP_PASS || '', from: process.env.SMTP_FROM || process.env.SMTP_USER || '' };
}

function saveEmailConfig(cfg) {
  try {
    const dir = path.dirname(EMAIL_CONFIG_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(EMAIL_CONFIG_PATH, JSON.stringify(cfg, null, 2));
    log('INFO', 'Email config saved');
    return true;
  } catch (e) { log('ERROR', 'Email config save error', { error: e.message }); return false; }
}

async function sendEmail(to, subject, text, html) {
  const config = getEmailConfig();
  if (!config.user || !config.pass) {
    log('WARN', 'Email not sent - SMTP not configured', { to, subject });
    return { sent: false, reason: 'SMTP no configurado. Configúralo en el panel de administración o con variables de entorno SMTP_USER y SMTP_PASS.' };
  }
  try {
    const transporter = nodemailer.createTransport({
      host: config.host, port: config.port,
      secure: config.port === 465,
      auth: { user: config.user, pass: config.pass },
    });
    await transporter.sendMail({ from: config.from || config.user, to, subject, text, html: html || text });
    log('INFO', 'Email sent', { to, subject });
    return { sent: true };
  } catch (e) {
    log('ERROR', 'Email send failed', { to, subject, error: e.message });
    return { sent: false, reason: e.message };
  }
}

// ─── SMS via Email-to-SMS Gateway ─────────────────────────
function getSmsCarriers() {
  const carriers = [...DEFAULT_SMS_CARRIERS];
  try {
    if (fs.existsSync(SMS_CARRIERS_CONFIG_PATH)) {
      const custom = JSON.parse(fs.readFileSync(SMS_CARRIERS_CONFIG_PATH, 'utf8'));
      if (Array.isArray(custom) && custom.length) return custom;
    }
  } catch (e) { /* ignore */ }
  return carriers;
}

function saveSmsCarriers(carriers) {
  try {
    const dir = path.dirname(SMS_CARRIERS_CONFIG_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(SMS_CARRIERS_CONFIG_PATH, JSON.stringify(carriers, null, 2));
    return true;
  } catch (e) { return false; }
}

async function sendSmsViaEmail(phoneNumber, carrierId, code) {
  const carriers = getSmsCarriers();
  const carrier = carriers.find(c => c.id === carrierId);
  if (!carrier || !carrier.gateway) {
    return { sent: false, reason: 'Carrier sin gateway email. El código solo se muestra en pantalla.' };
  }
  const smsEmail = `${phoneNumber.replace(/[^0-9]/g, '')}@${carrier.gateway}`;
  const text = `Tu código de verificación MFA es: ${code}`;
  const html = `<div style="font-family:sans-serif;max-width:400px;margin:0 auto;background:#1e293b;border-radius:12px;padding:32px;text-align:center;border:1px solid #334155;">
    <div style="font-size:40px;margin-bottom:12px;">📱</div>
    <h2 style="color:#f1f5f9;margin-bottom:16px;">Código de verificación</h2>
    <div style="font-size:36px;font-weight:700;letter-spacing:8px;color:#a5b4fc;background:#0f172a;padding:16px 32px;border-radius:8px;font-family:monospace;margin-bottom:16px;">${code}</div>
    <p style="color:#94a3b8;font-size:13px;">Recibiste este SMS vía email-to-SMS gateway de ${carrier.name}.</p>
    <p style="color:#64748b;font-size:11px;">El código expira en 5 minutos.</p>
  </div>`;
  return await sendEmail(smsEmail, `📱 Código MFA para ${phoneNumber}`, text, html);
}

// ─── Twilio SMS / WhatsApp ─────────────────────────────────
function getTwilioConfig() {
  try {
    if (fs.existsSync(TWILIO_CONFIG_PATH)) {
      return JSON.parse(fs.readFileSync(TWILIO_CONFIG_PATH, 'utf8'));
    }
  } catch (e) { /* ignore */ }
  return {
    accountSid: process.env.TWILIO_ACCOUNT_SID || '',
    authToken: process.env.TWILIO_AUTH_TOKEN || '',
    fromNumber: process.env.TWILIO_FROM_NUMBER || '',
    whatsappFrom: process.env.TWILIO_WHATSAPP_FROM || '',
  };
}

function saveTwilioConfig(cfg) {
  try {
    const dir = path.dirname(TWILIO_CONFIG_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(TWILIO_CONFIG_PATH, JSON.stringify(cfg, null, 2));
    log('INFO', 'Twilio config saved');
    return true;
  } catch (e) { log('ERROR', 'Twilio config save error', { error: e.message }); return false; }
}

function getTwilioClient() {
  const cfg = getTwilioConfig();
  if (!cfg.accountSid || !cfg.authToken) return null;
  return twilio(cfg.accountSid, cfg.authToken);
}

async function sendSmsViaTwilio(phoneNumber, code) {
  const cfg = getTwilioConfig();
  if (!cfg.accountSid || !cfg.authToken || !cfg.fromNumber) return { sent: false, reason: 'Twilio no configurado' };
  try {
    const client = twilio(cfg.accountSid, cfg.authToken);
    const msg = await client.messages.create({
      body: `🔐 Tu código MFA es: ${code}. Válido por 5 minutos. No lo compartas.`,
      from: cfg.fromNumber,
      to: phoneNumber,
    });
    log('INFO', 'SMS sent via Twilio', { to: phoneNumber, sid: msg.sid });
    return { sent: true, sid: msg.sid };
  } catch (e) {
    log('ERROR', 'Twilio SMS failed', { error: e.message });
    return { sent: false, reason: e.message };
  }
}

async function sendWhatsAppViaTwilio(phoneNumber, code) {
  const cfg = getTwilioConfig();
  if (!cfg.accountSid || !cfg.authToken || !cfg.whatsappFrom) return { sent: false, reason: 'Twilio WhatsApp no configurado' };
  try {
    const client = twilio(cfg.accountSid, cfg.authToken);
    const to = `whatsapp:${phoneNumber}`;
    const from = `whatsapp:${cfg.whatsappFrom}`;
    const msg = await client.messages.create({
      body: `🔐 *Tu código MFA es:* ${code}\n\nVálido por 5 minutos. No lo compartas con nadie.`,
      from, to,
    });
    log('INFO', 'WhatsApp sent via Twilio', { to: phoneNumber, sid: msg.sid });
    return { sent: true, sid: msg.sid };
  } catch (e) {
    log('ERROR', 'Twilio WhatsApp failed', { error: e.message });
    return { sent: false, reason: e.message };
  }
}

// ─── CallMeBot (free WhatsApp API) ────────────────────────
function getCallMeBotConfig() {
  try {
    if (fs.existsSync(CALLMEBOT_CONFIG_PATH)) {
      return JSON.parse(fs.readFileSync(CALLMEBOT_CONFIG_PATH, 'utf8'));
    }
  } catch (e) { /* ignore */ }
  return { apikey: process.env.CALLMEBOT_APIKEY || '' };
}

function saveCallMeBotConfig(cfg) {
  try {
    const dir = path.dirname(CALLMEBOT_CONFIG_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(CALLMEBOT_CONFIG_PATH, JSON.stringify(cfg, null, 2));
    log('INFO', 'CallMeBot config saved');
    return true;
  } catch (e) { log('ERROR', 'CallMeBot config save error', { error: e.message }); return false; }
}

async function sendWhatsAppViaCallMeBot(phoneNumber, code) {
  const cfg = getCallMeBotConfig();
  if (!cfg.apikey) return { sent: false, reason: 'CallMeBot no configurado' };
  try {
    const https = require('https');
    const text = `🔐 Tu código MFA es: ${code}. Válido por 5 minutos.`;
    const url = `https://api.callmebot.com/whatsapp.php?phone=${encodeURIComponent(phoneNumber)}&text=${encodeURIComponent(text)}&apikey=${encodeURIComponent(cfg.apikey)}`;
    await new Promise((resolve, reject) => {
      https.get(url, (res) => {
        let d = '';
        res.on('data', c => d += c);
        res.on('end', () => {
          if (d.includes('OK') || d.includes('Message sent')) resolve(d);
          else reject(new Error(d.substring(0, 100)));
        });
      }).on('error', reject);
    });
    log('INFO', 'WhatsApp sent via CallMeBot', { to: phoneNumber });
    return { sent: true };
  } catch (e) {
    log('ERROR', 'CallMeBot WhatsApp failed', { error: e.message });
    return { sent: false, reason: e.message };
  }
}

// ─── API Handler ───────────────────────────────────────────
async function handleAPI(req, res, pathname) {
  res.req = req;

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
    });
    res.end();
    return;
  }

  // ── POST /api/accounts/register/ ──
  if (pathname === '/api/accounts/register/' && req.method === 'POST') {
    const body = await parseBody(req);
    const { email, password, name } = body;
    if (!email || typeof email !== 'string') return sendError(res, 400, 'El email es obligatorio', 'INVALID_EMAIL');
    if (!password || typeof password !== 'string' || password.length < 6) return sendError(res, 400, 'La contraseña debe tener al menos 6 caracteres', 'WEAK_PASSWORD');
    if (!validateEmail(email)) return sendError(res, 400, 'Formato de email inválido', 'BAD_EMAIL');
    if (password.length > 128) return sendError(res, 400, 'La contraseña es demasiado larga', 'LONG_PASSWORD');
    if (db.findUserByEmail(email)) return sendError(res, 409, 'El email ya está registrado', 'EMAIL_EXISTS');
    const user = db.createUser(email, password, name);
    return sendJSON(res, 201, user);
  }

  // ── POST /api/accounts/login/ ──
  if (pathname === '/api/accounts/login/' && req.method === 'POST') {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const rl = rateLimit('login:' + ip);
    if (!rl.allowed) return sendJSON(res, 429, { error: 'Demasiados intentos. Intenta de nuevo en unos segundos.', retryAfter: rl.retryAfter, code: 'RATE_LIMITED' });

    const body = await parseBody(req);
    const { email, password } = body;
    if (!email || !password) return sendError(res, 400, 'Email y contraseña son obligatorios', 'MISSING_FIELDS');

    const user = db.findUserByEmail(email);
    if (!user) return sendError(res, 401, 'Credenciales inválidas', 'INVALID_CREDENTIALS');

    if (user.is_locked && user.lockout_until) {
      const lockRemaining = new Date(user.lockout_until).getTime() - Date.now();
      if (lockRemaining > 0) return sendJSON(res, 423, { error: 'Cuenta bloqueada por demasiados intentos fallidos', locked: true, retryAfter: Math.ceil(lockRemaining / 1000), code: 'ACCOUNT_LOCKED' });
      db.updateUser(user.id, { is_locked: false, failed_attempts: 0, lockout_until: null });
    }

    if (!verifyPassword(password, user.password)) {
      const newAttempts = user.failed_attempts + 1;
      if (newAttempts >= LOCKOUT_THRESHOLD) {
        const lockUntil = new Date(Date.now() + LOCKOUT_DURATION).toISOString();
        db.updateUser(user.id, { failed_attempts: newAttempts, is_locked: true, lockout_until: lockUntil });
        return sendJSON(res, 423, { error: 'Cuenta bloqueada por demasiados intentos fallidos', locked: true, retryAfter: LOCKOUT_DURATION / 1000, code: 'ACCOUNT_LOCKED' });
      }
      db.updateUser(user.id, { failed_attempts: newAttempts });
      return sendError(res, 401, 'Credenciales inválidas', 'INVALID_CREDENTIALS');
    }

    db.updateUser(user.id, { failed_attempts: 0, is_locked: false, lockout_until: null });
    log('INFO', 'Login success', { email });

    // Check which MFA methods are enabled
    const mfaMethods = [];
    if (user.mfa_totp_enabled) mfaMethods.push({ method: 'totp', label: 'App Autenticadora (TOTP)' });
    if (user.mfa_sms_enabled) mfaMethods.push({ method: 'sms', label: 'Código SMS' });
    if (user.mfa_whatsapp_enabled) mfaMethods.push({ method: 'whatsapp', label: 'Código por WhatsApp' });
    if (user.mfa_email_enabled) mfaMethods.push({ method: 'email', label: 'Código por Email' });

    if (mfaMethods.length > 0) {
      const tempToken = createJWT({ userId: user.id, purpose: 'mfa_verify' }, 300000);
      return sendJSON(res, 200, { message: 'Se requiere verificación MFA', user_id: user.id, mfa_required: true, mfa_methods: mfaMethods, temp_token: tempToken });
    }

    const accessToken = createJWT({ userId: user.id, email: user.email, mfa_methods: [] });
    return sendJSON(res, 200, { access: accessToken, user: db._sanitizeUser(user) });
  }

  // ── POST /api/accounts/verify-mfa/ ──
  if (pathname === '/api/accounts/verify-mfa/' && req.method === 'POST') {
    const rl = rateLimit('verifymfa:' + (req.headers['x-forwarded-for'] || req.socket.remoteAddress), 10, 60000);
    if (!rl.allowed) return sendJSON(res, 429, { error: 'Demasiados intentos. Espera un minuto.', retryAfter: rl.retryAfter, code: 'RATE_LIMITED' });

    const body = await parseBody(req);
    const { user_id, otp, method } = body;
    if (!user_id || !otp || !method) return sendError(res, 400, 'user_id, otp y method son obligatorios', 'MISSING_FIELDS');

    const user = db.findUserById(parseInt(user_id));
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    let verified = false;
    if (method === 'totp') {
      verified = verifyTOTP(user.mfa_totp_secret, String(otp).trim());
    } else if (method === 'sms') {
      verified = verifyOTP(`sms_verify:${user.phone}`, String(otp).trim());
    } else if (method === 'whatsapp') {
      verified = verifyOTP(`sms_verify:${user.phone}`, String(otp).trim());
    } else if (method === 'email') {
      verified = verifyOTP(`email_verify:${user.email}`, String(otp).trim());
    } else {
      return sendError(res, 400, 'Método MFA no válido', 'INVALID_METHOD');
    }

    if (!verified) return sendError(res, 401, 'Código inválido o expirado', 'INVALID_OTP');

    const activeMethods = [];
    if (user.mfa_totp_enabled) activeMethods.push('totp');
    if (user.mfa_sms_enabled) activeMethods.push('sms');
    if (user.mfa_whatsapp_enabled) activeMethods.push('whatsapp');
    if (user.mfa_email_enabled) activeMethods.push('email');

    const accessToken = createJWT({ userId: user.id, email: user.email, mfa_methods: activeMethods });
    log('INFO', 'MFA verification success', { user_id: user.id, method });

    return sendJSON(res, 200, { access: accessToken, user: db._sanitizeUser(user) });
  }

  // ── GET /api/accounts/profile/ ──
  if (pathname === '/api/accounts/profile/' && req.method === 'GET') {
    const auth = getAuthUser(req);
    if (!auth) return sendError(res, 401, 'No autorizado', 'UNAUTHORIZED');
    const user = db.findUserById(auth.userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');
    return sendJSON(res, 200, db._sanitizeUser(user));
  }

  // ── PUT /api/accounts/profile/ ──
  if (pathname === '/api/accounts/profile/' && req.method === 'PUT') {
    const auth = getAuthUser(req);
    if (!auth) return sendError(res, 401, 'No autorizado', 'UNAUTHORIZED');
    const user = db.findUserById(auth.userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    const body = await parseBody(req);
    const { name } = body;

    if (name !== undefined) {
      if (typeof name !== 'string' || name.trim().length < 2) return sendError(res, 400, 'El nombre debe tener al menos 2 caracteres', 'INVALID_NAME');
      db.updateUser(user.id, { name: name.trim() });
    }

    const updated = db.findUserById(user.id);
    log('INFO', 'Profile updated', { user_id: user.id });
    return sendJSON(res, 200, { success: true, user: db._sanitizeUser(updated) });
  }

  // ── POST /api/accounts/send-otp/ ──
  if (pathname === '/api/accounts/send-otp/' && req.method === 'POST') {
    const rl = rateLimit('sendotp:' + (req.headers['x-forwarded-for'] || req.socket.remoteAddress), 5, 60000);
    if (!rl.allowed) return sendJSON(res, 429, { error: 'Demasiados intentos. Espera un minuto.', retryAfter: rl.retryAfter, code: 'RATE_LIMITED' });

    const auth = getAuthUser(req);
    if (!auth) return sendError(res, 401, 'No autorizado', 'UNAUTHORIZED');
    const user = db.findUserById(auth.userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    const body = await parseBody(req);
    const { destination, type } = body; // type: 'email' or 'sms', destination: email or phone

    if (!destination || !type) return sendError(res, 400, 'destination y type son obligatorios', 'MISSING_FIELDS');

    const code = generateOTP();

    if (type === 'email') {
      if (!validateEmail(destination)) return sendError(res, 400, 'Email inválido', 'INVALID_EMAIL');
      otpStore.set(`email_verify:${destination}`, { code, expires: Date.now() + OTP_EXPIRY, attempts: 0 });
      log('INFO', '📧 Email OTP sent', { to: destination, code });
      console.log(`\n  ┌────────────────────────────────────────┐`);
      console.log(`  │  📧 Código OTP para ${destination.padEnd(21)} │`);
      console.log(`  │  🔑 ${code.padEnd(37)} │`);
      console.log(`  └────────────────────────────────────────┘\n`);
      // Send real email if SMTP is configured
      const html = `
        <div style="font-family:sans-serif;max-width:520px;margin:0 auto;background:#1e293b;border-radius:12px;padding:32px;border:1px solid #334155;">
          <div style="text-align:center;font-size:40px;margin-bottom:12px;">📧</div>
          <h2 style="color:#f1f5f9;text-align:center;margin-bottom:16px;">Tu código de verificación</h2>
          <p style="color:#94a3b8;font-size:14px;margin-bottom:12px;">Usa el siguiente código para verificar tu dirección de correo:</p>
          <div style="text-align:center;margin:20px 0;">
            <span style="font-size:36px;font-weight:700;letter-spacing:8px;color:#a5b4fc;background:#0f172a;padding:16px 32px;border-radius:8px;font-family:monospace;">${code}</span>
          </div>
          <p style="color:#64748b;font-size:11px;">Este código expira en 5 minutos.</p>
        </div>`;
      await sendEmail(destination, '📧 Código de verificación', `Tu código OTP es: ${code}`, html);
    } else if (type === 'sms') {
      if (!validatePhone(destination)) return sendError(res, 400, 'Teléfono inválido', 'INVALID_PHONE');
      otpStore.set(`sms_verify:${destination}`, { code, expires: Date.now() + OTP_EXPIRY, attempts: 0 });
      log('INFO', '📱 SMS OTP sent', { to: destination, code });
      console.log(`\n  ┌────────────────────────────────────────┐`);
      console.log(`  │  📱 Código SMS para ${destination.padEnd(22)} │`);
      console.log(`  │  🔑 ${code.padEnd(37)} │`);
      console.log(`  └────────────────────────────────────────┘\n`);
      // Try Twilio SMS first, then WhatsApp, then CallMeBot, then email-to-SMS
      let smsSent = false;
      const twilioResult = await sendSmsViaTwilio(destination, code);
      if (twilioResult.sent) { smsSent = true; }
      else {
        log('WARN', 'Twilio SMS failed, trying WhatsApp', { destination, reason: twilioResult.reason });
        const waResult = await sendWhatsAppViaTwilio(destination, code);
        if (waResult.sent) { smsSent = true; }
        else {
          log('WARN', 'Twilio WhatsApp also failed, trying CallMeBot', { reason: waResult.reason });
          const cmbResult = await sendWhatsAppViaCallMeBot(destination, code);
          if (cmbResult.sent) { smsSent = true; }
          else {
            log('WARN', 'CallMeBot also failed, trying email-to-SMS', { reason: cmbResult.reason });
            const carrierId = body.carrierId || body.carrier || '';
            const emailResult = await sendSmsViaEmail(destination, carrierId, code);
            if (!emailResult.sent) {
              log('WARN', 'All SMS delivery methods failed', { reason: emailResult.reason });
            }
          }
        }
      }
    } else if (type === 'whatsapp') {
      if (!validatePhone(destination)) return sendError(res, 400, 'Teléfono inválido', 'INVALID_PHONE');
      otpStore.set(`sms_verify:${destination}`, { code, expires: Date.now() + OTP_EXPIRY, attempts: 0 });
      log('INFO', '📱 WhatsApp OTP sent', { to: destination, code });
      console.log(`\n  ┌────────────────────────────────────────┐`);
      console.log(`  │  📱 WhatsApp OTP para ${destination.padEnd(18)} │`);
      console.log(`  │  🔑 ${code.padEnd(37)} │`);
      console.log(`  └────────────────────────────────────────┘\n`);
      const waResult = await sendWhatsAppViaTwilio(destination, code);
      if (!waResult.sent) {
        log('WARN', 'Twilio WhatsApp failed, trying CallMeBot', { destination, reason: waResult.reason });
        const cmbResult = await sendWhatsAppViaCallMeBot(destination, code);
        if (!cmbResult.sent) {
          log('WARN', 'All WhatsApp delivery methods failed', { reason: cmbResult.reason });
        }
      }
    } else {
      return sendError(res, 400, 'Tipo inválido. Use email o sms', 'INVALID_TYPE');
    }

    return sendJSON(res, 200, { success: true, message: `Código enviado a ${destination}`, code });
  }

  // ── POST /api/accounts/verify-otp/ ──
  if (pathname === '/api/accounts/verify-otp/' && req.method === 'POST') {
    const auth = getAuthUser(req);
    if (!auth) return sendError(res, 401, 'No autorizado', 'UNAUTHORIZED');
    const user = db.findUserById(auth.userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    const body = await parseBody(req);
    const { destination, type, code } = body;

    if (!destination || !type || !code) return sendError(res, 400, 'destination, type y code son obligatorios', 'MISSING_FIELDS');

    const key = `${type}_verify:${destination}`;
    if (!verifyOTP(key, String(code).trim())) return sendError(res, 401, 'Código inválido o expirado', 'INVALID_OTP');

    // Mark contact as verified
    if (type === 'email') {
      db.updateUser(user.id, { email: destination.toLowerCase(), email_verified: true });
    } else if (type === 'sms') {
      db.updateUser(user.id, { phone: destination, phone_verified: true });
    }

    const updated = db.findUserById(user.id);
    log('INFO', 'Contact verified', { user_id: user.id, type, destination });
    return sendJSON(res, 200, { success: true, message: `${type === 'email' ? 'Email' : 'Teléfono'} verificado correctamente`, user: db._sanitizeUser(updated) });
  }

  // ── POST /api/accounts/mfa/toggle/ ──
  if (pathname === '/api/accounts/mfa/toggle/' && req.method === 'POST') {
    const auth = getAuthUser(req);
    if (!auth) return sendError(res, 401, 'No autorizado', 'UNAUTHORIZED');
    const user = db.findUserById(auth.userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    const body = await parseBody(req);
    const { method, enabled } = body; // method: 'totp', 'sms', 'email', 'whatsapp'

    if (!['totp', 'sms', 'email', 'whatsapp'].includes(method)) return sendError(res, 400, 'Método no válido. Use: totp, sms, email, whatsapp', 'INVALID_METHOD');

    // Validate prerequisites
    if ((method === 'sms' || method === 'whatsapp') && enabled) {
      if (!user.phone || !user.phone_verified) return sendError(res, 400, 'Debes verificar un número de teléfono primero', 'PHONE_NOT_VERIFIED');
    }
    if (method === 'email' && enabled) {
      if (!user.email_verified) return sendError(res, 400, 'Debes verificar tu email primero', 'EMAIL_NOT_VERIFIED');
    }

    const updates = {};
    if (method === 'totp') {
      updates.mfa_totp_enabled = enabled;
      if (!enabled) updates.mfa_totp_secret = generateTOTPSecret(); // reset secret
    }
    if (method === 'sms') updates.mfa_sms_enabled = enabled;
    if (method === 'whatsapp') updates.mfa_whatsapp_enabled = enabled;
    if (method === 'email') updates.mfa_email_enabled = enabled;

    db.updateUser(user.id, updates);
    log('INFO', `MFA ${method} ${enabled ? 'enabled' : 'disabled'}`, { user_id: user.id });

    const updated = db.findUserById(user.id);
    return sendJSON(res, 200, { success: true, message: `MFA por ${method} ${enabled ? 'activado' : 'desactivado'}`, user: db._sanitizeUser(updated) });
  }

  // ── POST /api/accounts/setup-totp/ ──
  if (pathname === '/api/accounts/setup-totp/' && req.method === 'POST') {
    const auth = getAuthUser(req);
    if (!auth) return sendError(res, 401, 'No autorizado', 'UNAUTHORIZED');
    const user = db.findUserById(auth.userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    const newSecret = generateTOTPSecret();
    db.updateUser(user.id, { mfa_totp_secret: newSecret, mfa_totp_enabled: false });
    log('INFO', 'TOTP setup initiated', { user_id: user.id });

    const otpauthUrl = generateOTPAuthURL(newSecret, user.email);
    let qrDataUrl = '';
    try { qrDataUrl = await QRCode.toDataURL(otpauthUrl, { width: 300, margin: 2, color: { dark: '#000000', light: '#ffffff' } }); } catch (e) { log('ERROR', 'QR failed', { error: e.message }); }

    return sendJSON(res, 200, { secret: newSecret, otpauth_url: otpauthUrl, qr_data_url: qrDataUrl, email: user.email });
  }

  // ── POST /api/accounts/verify-totp-setup/ ──
  if (pathname === '/api/accounts/verify-totp-setup/' && req.method === 'POST') {
    const auth = getAuthUser(req);
    if (!auth) return sendError(res, 401, 'No autorizado', 'UNAUTHORIZED');
    const body = await parseBody(req);
    const { otp } = body;
    if (!otp) return sendError(res, 400, 'Código OTP requerido', 'MISSING_OTP');

    const user = db.findUserById(auth.userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    if (!verifyTOTP(user.mfa_totp_secret, String(otp).trim())) return sendError(res, 401, 'Código OTP inválido', 'INVALID_OTP');

    db.updateUser(user.id, { mfa_totp_enabled: true });
    log('INFO', 'TOTP verified and enabled', { user_id: user.id });
    return sendJSON(res, 200, { success: true, message: 'TOTP configurado correctamente', user: db._sanitizeUser(db.findUserById(user.id)) });
  }

  // ── POST /api/accounts/forgot-password/ ──
  if (pathname === '/api/accounts/forgot-password/' && req.method === 'POST') {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const rl = rateLimit('forgot:' + ip, 3, 60000);
    if (!rl.allowed) return sendJSON(res, 429, { error: 'Demasiados intentos. Espera un minuto.', retryAfter: rl.retryAfter, code: 'RATE_LIMITED' });

    const body = await parseBody(req);
    const { email } = body;
    if (!email || !validateEmail(email)) return sendError(res, 400, 'Email inválido', 'INVALID_EMAIL');

    const user = db.findUserByEmail(email);
    // Always return success to avoid email enumeration
    if (!user) {
      log('INFO', 'Password reset requested for non-existent email', { email });
      return sendJSON(res, 200, { success: true, message: 'Si el email existe, recibirás un enlace de recuperación.' });
    }

    const resetToken = createJWT({ userId: user.id, purpose: 'password_reset', email: user.email }, 900000);
    otpStore.set(`reset:${user.email}`, { code: resetToken, expires: Date.now() + 900000, attempts: 0 });

    const resetLink = `http://localhost:${PORT}/reset-password?token=${resetToken}`;
    log('INFO', '📧 Password reset email', { to: user.email, token: resetToken.substring(0, 20) + '...', link: resetLink });
    console.log(`\n  ┌────────────────────────────────────────────────────────────┐`);
    console.log(`  │  🔐 RECUPERACIÓN DE CONTRASEÑA                           │`);
    console.log(`  │  📧 ${user.email.padEnd(47)} │`);
    console.log(`  │                                                        │`);
    console.log(`  │  Token: ${resetToken.substring(0, 40)}...  │`);
    console.log(`  │  Link:  ${resetLink.padEnd(44)} │`);
    console.log(`  └────────────────────────────────────────────────────────────┘\n`);

    // Send real email if SMTP is configured
    const htmlEmail = `
      <div style="font-family:sans-serif;max-width:520px;margin:0 auto;background:#1e293b;border-radius:12px;padding:32px;border:1px solid #334155;">
        <div style="text-align:center;font-size:40px;margin-bottom:12px;">🔐</div>
        <h2 style="color:#f1f5f9;text-align:center;margin-bottom:16px;">Recuperación de Contraseña</h2>
        <p style="color:#94a3b8;font-size:14px;margin-bottom:20px;">Recibiste este correo porque solicitaste restablecer tu contraseña. Haz clic en el botón para continuar:</p>
        <div style="text-align:center;margin-bottom:20px;">
          <a href="${resetLink}" style="display:inline-block;padding:14px 32px;background:#6366f1;color:#fff;text-decoration:none;border-radius:8px;font-weight:600;font-size:14px;">Restablecer Contraseña</a>
        </div>
        <p style="color:#64748b;font-size:12px;">O copia este enlace en tu navegador:</p>
        <p style="color:#a5b4fc;font-size:11px;word-break:break-all;background:#0f172a;padding:12px;border-radius:6px;">${resetLink}</p>
        <p style="color:#64748b;font-size:11px;margin-top:16px;">Este enlace expira en 15 minutos. Si no solicitaste esto, ignora este correo.</p>
      </div>`;
    const emailResult = await sendEmail(user.email, '🔐 Recuperación de Contraseña', `Token: ${resetToken}\nLink: ${resetLink}`, htmlEmail);

    return sendJSON(res, 200, { success: true, message: 'Si el email existe, recibirás un enlace de recuperación.', email_sent: emailResult.sent, email_reason: emailResult.reason });
  }

  // ── POST /api/accounts/reset-password/ ──
  if (pathname === '/api/accounts/reset-password/' && req.method === 'POST') {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const rl = rateLimit('reset:' + ip, 5, 60000);
    if (!rl.allowed) return sendJSON(res, 429, { error: 'Demasiados intentos. Espera un minuto.', retryAfter: rl.retryAfter, code: 'RATE_LIMITED' });

    const body = await parseBody(req);
    const { token, newPassword } = body;

    if (!token || !newPassword) return sendError(res, 400, 'Token y nueva contraseña son obligatorios', 'MISSING_FIELDS');
    if (newPassword.length < 6) return sendError(res, 400, 'La contraseña debe tener al menos 6 caracteres', 'WEAK_PASSWORD');

    const payload = verifyJWT(token);
    if (!payload || payload.purpose !== 'password_reset') return sendError(res, 401, 'Token inválido o expirado', 'INVALID_TOKEN');

    const user = db.findUserById(payload.userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    // Verify it's the same email
    if (user.email !== payload.email) return sendError(res, 401, 'Token inválido', 'INVALID_TOKEN');

    // Check token hasn't been already used (must still exist in store)
    const stored = otpStore.get(`reset:${user.email}`);
    if (!stored || stored.code !== token) return sendError(res, 401, 'Este token ya fue utilizado o ha expirado', 'TOKEN_USED');

    // Remove used token
    otpStore.delete(`reset:${user.email}`);

    db.updateUser(user.id, { password: hashPassword(newPassword), failed_attempts: 0, is_locked: false, lockout_until: null });
    log('INFO', 'Password reset successful', { user_id: user.id, email: user.email });

    return sendJSON(res, 200, { success: true, message: 'Contraseña actualizada correctamente. Ya puedes iniciar sesión.' });
  }

  // ── PUT /api/accounts/change-password/ ──
  if (pathname === '/api/accounts/change-password/' && req.method === 'PUT') {
    const auth = getAuthUser(req);
    if (!auth) return sendError(res, 401, 'No autorizado', 'UNAUTHORIZED');
    const body = await parseBody(req);
    const { currentPassword, newPassword } = body;
    if (!currentPassword || !newPassword) return sendError(res, 400, 'Contraseña actual y nueva son requeridas', 'MISSING_FIELDS');
    if (newPassword.length < 6) return sendError(res, 400, 'La nueva contraseña debe tener al menos 6 caracteres', 'WEAK_PASSWORD');

    const user = db.findUserById(auth.userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');
    if (!verifyPassword(currentPassword, user.password)) return sendError(res, 401, 'Contraseña actual incorrecta', 'WRONG_PASSWORD');

    db.updateUser(user.id, { password: hashPassword(newPassword) });
    log('INFO', 'Password changed', { user_id: user.id });
    return sendJSON(res, 200, { success: true, message: 'Contraseña actualizada' });
  }

  // ── Dev: GET /api/dev/otp ──
  if (pathname === '/api/dev/otp' && req.method === 'GET') {
    const otps = {};
    for (const [key, val] of otpStore) {
      if (Date.now() < val.expires) {
        otps[key] = { code: val.code, expires: new Date(val.expires).toISOString(), attempts: val.attempts };
      }
    }
    return sendJSON(res, 200, { otps });
  }

  // ── Admin middleware ──
  function requireAdmin(req, res) {
    const auth = getAuthUser(req);
    if (!auth) { sendError(res, 401, 'No autorizado', 'UNAUTHORIZED'); return null; }
    const user = db.findUserById(auth.userId);
    if (!user || user.role !== 'admin') { sendError(res, 403, 'Acceso denegado. Se requieren permisos de administrador.', 'FORBIDDEN'); return null; }
    return user;
  }

  // ── GET /api/admin/users/ ──
  if (pathname === '/api/admin/users/' && req.method === 'GET') {
    const admin = requireAdmin(req, res);
    if (!admin) return;
    const users = db.getAllUsers();
    const stats = db.getStats();
    return sendJSON(res, 200, { users, stats });
  }

  // ── GET /api/admin/users/:id/ ──
  const adminUserMatch = pathname.match(/^\/api\/admin\/users\/(\d+)\/$/);
  if (adminUserMatch && req.method === 'GET') {
    const admin = requireAdmin(req, res);
    if (!admin) return;
    const user = db.findUserById(parseInt(adminUserMatch[1]));
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');
    return sendJSON(res, 200, db._sanitizeUser(user));
  }

  // ── PUT /api/admin/users/:id/ ──
  if (adminUserMatch && req.method === 'PUT') {
    const admin = requireAdmin(req, res);
    if (!admin) return;
    const userId = parseInt(adminUserMatch[1]);
    const user = db.findUserById(userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');
    if (user.id === admin.id) return sendError(res, 400, 'No puedes modificarte a ti mismo aquí. Usa el perfil.', 'SELF_MODIFY');

    const body = await parseBody(req);
    const updates = {};
    if (body.name !== undefined) { if (typeof body.name !== 'string' || body.name.trim().length < 2) return sendError(res, 400, 'Nombre inválido', 'INVALID_NAME'); updates.name = body.name.trim(); }
    if (body.email !== undefined) { if (!validateEmail(body.email)) return sendError(res, 400, 'Email inválido', 'INVALID_EMAIL'); updates.email = body.email.toLowerCase(); }
    if (body.role !== undefined) { if (!['user', 'admin'].includes(body.role)) return sendError(res, 400, 'Rol inválido', 'INVALID_ROLE'); updates.role = body.role; }

    db.updateUser(userId, updates);
    log('INFO', 'Admin updated user', { admin_id: admin.id, target_id: userId, updates: Object.keys(updates) });
    return sendJSON(res, 200, { success: true, message: 'Usuario actualizado', user: db._sanitizeUser(db.findUserById(userId)) });
  }

  // ── DELETE /api/admin/users/:id/ ──
  if (adminUserMatch && req.method === 'DELETE') {
    const admin = requireAdmin(req, res);
    if (!admin) return;
    const userId = parseInt(adminUserMatch[1]);
    const user = db.findUserById(userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');
    if (user.id === admin.id) return sendError(res, 400, 'No puedes eliminarte a ti mismo', 'SELF_DELETE');

    db.deleteUser(userId);
    log('INFO', 'Admin deleted user', { admin_id: admin.id, target_id: userId, email: user.email });
    return sendJSON(res, 200, { success: true, message: 'Usuario eliminado' });
  }

  // ── POST /api/admin/users/:id/toggle-lock/ ──
  if (pathname.match(/^\/api\/admin\/users\/(\d+)\/toggle-lock\/$/) && req.method === 'POST') {
    const admin = requireAdmin(req, res);
    if (!admin) return;
    const userId = parseInt(pathname.match(/^\/api\/admin\/users\/(\d+)\/toggle-lock\/$/)[1]);
    const user = db.findUserById(userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    const newLocked = !user.is_locked;
    db.updateUser(user.id, { is_locked: newLocked, failed_attempts: newLocked ? user.failed_attempts : 0, lockout_until: newLocked ? new Date(Date.now() + 3600000).toISOString() : null });
    log('INFO', 'Admin toggled user lock', { admin_id: admin.id, target_id: userId, locked: newLocked });
    return sendJSON(res, 200, { success: true, message: newLocked ? 'Cuenta bloqueada' : 'Cuenta desbloqueada', user: db._sanitizeUser(db.findUserById(user.id)) });
  }

  // ── POST /api/admin/users/:id/reset-mfa/ ──
  if (pathname.match(/^\/api\/admin\/users\/(\d+)\/reset-mfa\/$/) && req.method === 'POST') {
    const admin = requireAdmin(req, res);
    if (!admin) return;
    const userId = parseInt(pathname.match(/^\/api\/admin\/users\/(\d+)\/reset-mfa\/$/)[1]);
    const user = db.findUserById(userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    db.updateUser(user.id, {
      mfa_totp_enabled: false, mfa_sms_enabled: false, mfa_email_enabled: false, mfa_whatsapp_enabled: false,
      mfa_totp_secret: generateTOTPSecret(),
    });
    log('INFO', 'Admin reset MFA for user', { admin_id: admin.id, target_id: userId });
    return sendJSON(res, 200, { success: true, message: 'MFA reseteado. El usuario deberá configurarlo nuevamente.', user: db._sanitizeUser(db.findUserById(user.id)) });
  }

  // ── GET /api/sms/carriers/ ──
  if (pathname === '/api/sms/carriers/' && req.method === 'GET') {
    const auth = getAuthUser(req);
    if (!auth) return sendError(res, 401, 'No autorizado', 'UNAUTHORIZED');
    return sendJSON(res, 200, { carriers: getSmsCarriers() });
  }

  // ── GET /api/admin/twilio-config/ ──
  if (pathname === '/api/admin/twilio-config/') {
    const admin = requireAdmin(req, res);
    if (!admin) return;
    if (req.method === 'GET') {
      const cfg = getTwilioConfig();
      return sendJSON(res, 200, { ...cfg, authToken: cfg.authToken ? '********' : '' });
    }
    if (req.method === 'PUT') {
      const body = await parseBody(req);
      const cfg = getTwilioConfig();
      if (body.accountSid !== undefined) cfg.accountSid = body.accountSid;
      if (body.authToken !== undefined && body.authToken !== '********') cfg.authToken = body.authToken;
      if (body.fromNumber !== undefined) cfg.fromNumber = body.fromNumber;
      if (body.whatsappFrom !== undefined) cfg.whatsappFrom = body.whatsappFrom;
      saveTwilioConfig(cfg);
      // Test connection
      let testOk = false;
      try {
        const client = twilio(cfg.accountSid, cfg.authToken);
        await client.api.accounts(cfg.accountSid).fetch();
        testOk = true;
      } catch (e) { log('WARN', 'Twilio test failed', { error: e.message }); }
      return sendJSON(res, 200, { success: true, message: 'Configuración guardada' + (testOk ? '' : '. No se pudo conectar con Twilio. Revisa las credenciales.'), test_ok: testOk, ...cfg, authToken: '********' });
    }
    return sendError(res, 405, 'Método no permitido', 'METHOD_NOT_ALLOWED');
  }

  // ── GET /api/admin/callmebot-config/ ──
  if (pathname === '/api/admin/callmebot-config/') {
    const admin = requireAdmin(req, res);
    if (!admin) return;
    if (req.method === 'GET') {
      const cfg = getCallMeBotConfig();
      return sendJSON(res, 200, { ...cfg, apikey: cfg.apikey ? '********' : '' });
    }
    if (req.method === 'PUT') {
      const body = await parseBody(req);
      const cfg = getCallMeBotConfig();
      if (body.apikey !== undefined && body.apikey !== '********') cfg.apikey = body.apikey;
      saveCallMeBotConfig(cfg);
      return sendJSON(res, 200, { success: true, message: 'Configuración de CallMeBot guardada', ...cfg, apikey: '********' });
    }
    return sendError(res, 405, 'Método no permitido', 'METHOD_NOT_ALLOWED');
  }

  // ── GET /api/admin/email-config/ ──
  if (pathname === '/api/admin/email-config/') {
    const admin = requireAdmin(req, res);
    if (!admin) return;
    if (req.method === 'GET') {
      const cfg = getEmailConfig();
      return sendJSON(res, 200, { ...cfg, pass: cfg.pass ? '********' : '' });
    }
    if (req.method === 'PUT') {
      const body = await parseBody(req);
      const cfg = getEmailConfig();
      if (body.host !== undefined) cfg.host = body.host;
      if (body.port !== undefined) cfg.port = parseInt(body.port) || 587;
      if (body.user !== undefined) cfg.user = body.user;
      if (body.pass !== undefined && body.pass !== '********') cfg.pass = body.pass;
      if (body.from !== undefined) cfg.from = body.from;
      cfg.from = cfg.from || cfg.user;
      if (!cfg.user) return sendError(res, 400, 'El usuario SMTP es obligatorio', 'MISSING_SMTP_USER');
      if (!cfg.pass) return sendError(res, 400, 'La contraseña SMTP es obligatoria', 'MISSING_SMTP_PASS');
      saveEmailConfig(cfg);
      // Test connection
      let testOk = false;
      try {
        const t = nodemailer.createTransport({ host: cfg.host, port: cfg.port, secure: cfg.port === 465, auth: { user: cfg.user, pass: cfg.pass } });
        await t.verify();
        testOk = true;
      } catch (e) { log('WARN', 'SMTP test failed', { error: e.message }); }
      return sendJSON(res, 200, { success: true, message: 'Configuración guardada' + (testOk ? '' : '. No se pudo conectar al servidor SMTP.'), test_ok: testOk, ...cfg, pass: '********' });
    }
    return sendError(res, 405, 'Método no permitido', 'METHOD_NOT_ALLOWED');
  }

  // ── GET /api/ ──
  if (pathname === '/api/') {
    return sendJSON(res, 200, {
      name: 'MFA Authentication System API', version: '3.0.0',
      endpoints: {
        register: { method: 'POST', path: '/api/accounts/register/', desc: 'Registrar usuario' },
        login: { method: 'POST', path: '/api/accounts/login/', desc: 'Iniciar sesión' },
        verify_mfa: { method: 'POST', path: '/api/accounts/verify-mfa/', desc: 'Verificar MFA (totp/sms/email)' },
        profile: { method: 'GET', path: '/api/accounts/profile/', desc: 'Ver perfil', auth: true },
        update_profile: { method: 'PUT', path: '/api/accounts/profile/', desc: 'Actualizar perfil', auth: true },
        send_otp: { method: 'POST', path: '/api/accounts/send-otp/', desc: 'Enviar OTP (email/sms)', auth: true },
        verify_otp: { method: 'POST', path: '/api/accounts/verify-otp/', desc: 'Verificar OTP y confirmar contacto', auth: true },
        mfa_toggle: { method: 'POST', path: '/api/accounts/mfa/toggle/', desc: 'Activar/desactivar método MFA', auth: true },
        setup_totp: { method: 'POST', path: '/api/accounts/setup-totp/', desc: 'Obtener setup TOTP + QR', auth: true },
        verify_totp_setup: { method: 'POST', path: '/api/accounts/verify-totp-setup/', desc: 'Confirmar TOTP', auth: true },
        change_password: { method: 'PUT', path: '/api/accounts/change-password/', desc: 'Cambiar contraseña', auth: true },
        forgot_password: { method: 'POST', path: '/api/accounts/forgot-password/', desc: 'Solicitar recuperación de contraseña' },
        reset_password: { method: 'POST', path: '/api/accounts/reset-password/', desc: 'Restablecer contraseña con token' },
      },
      admin: {
        list_users: { method: 'GET', path: '/api/admin/users/', desc: 'Listar todos los usuarios (admin)', auth: true },
        get_user: { method: 'GET', path: '/api/admin/users/:id/', desc: 'Ver usuario (admin)', auth: true },
        update_user: { method: 'PUT', path: '/api/admin/users/:id/', desc: 'Actualizar usuario (admin)', auth: true },
        delete_user: { method: 'DELETE', path: '/api/admin/users/:id/', desc: 'Eliminar usuario (admin)', auth: true },
        toggle_lock: { method: 'POST', path: '/api/admin/users/:id/toggle-lock/', desc: 'Bloquear/desbloquear usuario (admin)', auth: true },
        reset_mfa: { method: 'POST', path: '/api/admin/users/:id/reset-mfa/', desc: 'Resetear MFA de usuario (admin)', auth: true },
      },
      server_time: new Date().toISOString(),
    });
  }

  return false;
}

// ─── Server ────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;
    log('INFO', `${req.method} ${pathname}`, { ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress });
    const handled = await handleAPI(req, res, pathname);
    if (handled !== false) return;
    serveStatic(pathname, res);
  } catch (err) {
    log('ERROR', 'Server error', { error: err.message, stack: err.stack?.split('\n').slice(0, 3) });
    if (!res.headersSent) sendError(res, 500, 'Error interno del servidor', 'SERVER_ERROR');
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  ┌──────────────────────────────────────────┐');
  console.log(`  │  🔐  MFA Auth System v3.0                │`);
  console.log(`  │  📡  http://localhost:${PORT}                    │`);
  console.log(`  │  📝  http://localhost:${PORT}/api/               │`);
  console.log('  └──────────────────────────────────────────┘');
  console.log('');
  log('INFO', 'Server started', { port: PORT, node: process.version, pid: process.pid });
});

function shutdown(signal) {
  log('INFO', `Received ${signal}, shutting down...`);
  server.close(() => { db.save(); log('INFO', 'Server shut down'); process.exit(0); });
  setTimeout(() => { log('ERROR', 'Forced shutdown'); process.exit(1); }, 5000);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('uncaughtException', (err) => log('ERROR', 'Uncaught exception', { error: err.message }));
process.on('unhandledRejection', (reason) => log('ERROR', 'Unhandled rejection', { reason: String(reason) }));
