const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const QRCode = require('qrcode');
const { EventEmitter } = require('events');

// ─── Configuration ───────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'database', 'data.json');
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_EXPIRY = 3600 * 1000;       // 1 hour
const LOCKOUT_THRESHOLD = 3;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 min
const TOTP_PERIOD = 30;               // 30 sec
const TOTP_DIGITS = 6;
const MAX_LOGIN_ATTEMPTS_PER_MINUTE = 10;

// ─── Logger ───────────────────────────────────────────────────────
const LOG_LEVELS = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
const LOG_LEVEL = LOG_LEVELS[process.env.LOG_LEVEL] || LOG_LEVELS.INFO;

function log(level, msg, meta) {
  if (LOG_LEVELS[level] < LOG_LEVEL) return;
  const entry = { ts: new Date().toISOString(), level, msg, ...(meta || {}) };
  const line = `[${entry.ts}] [${level.padEnd(5)}] ${msg}${meta ? ' ' + JSON.stringify(meta) : ''}`;
  if (level === 'ERROR') console.error(line);
  else console.log(line);
}

// ─── TOTP Implementation (RFC 6238) ─────────────────────────────
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
  const code = ((hash[offset] & 0x7f) << 24) |
               ((hash[offset + 1] & 0xff) << 16) |
               ((hash[offset + 2] & 0xff) << 8)  |
               (hash[offset + 3] & 0xff);
  return String(code % Math.pow(10, digits)).padStart(digits, '0');
}

function verifyTOTP(secret, code, window = 2) {
  const now = Date.now();
  for (let i = -window; i <= window; i++) {
    if (computeTOTP(secret, now + i * TOTP_PERIOD * 1000) === code) return true;
  }
  return false;
}

function getTOTPRemainingSeconds(timestamp = Date.now()) {
  return TOTP_PERIOD - (Math.floor(timestamp / 1000) % TOTP_PERIOD);
}

function generateOTPAuthURL(secret, email, issuer = 'MFASystem') {
  const params = new URLSearchParams({
    secret, issuer,
    algorithm: 'SHA1', digits: TOTP_DIGITS, period: TOTP_PERIOD
  });
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?${params}`;
}

// ─── Password Hashing (scrypt) ──────────────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  return crypto.scryptSync(password, salt, 64).toString('hex') === hash;
}

// ─── JWT Implementation ─────────────────────────────────────────
function createJWT(payload, expiresIn = JWT_EXPIRY) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({
    ...payload,
    iat: Date.now(),
    exp: Date.now() + expiresIn
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', JWT_SECRET)
    .update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const sig = crypto.createHmac('sha256', JWT_SECRET)
      .update(`${parts[0]}.${parts[1]}`).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(parts[2]))) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

// ─── Database ─────────────────────────────────────────────────────
class Database {
  constructor(filePath) {
    this.filePath = filePath;
    this.data = { users: [], nextId: 1 };
    this._ensureDir();
    this.load();
  }

  _ensureDir() {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }

  load() {
    try {
      if (fs.existsSync(this.filePath)) {
        this.data = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
        log('INFO', 'Database loaded', { path: this.filePath, users: this.data.users.length });
      } else {
        log('INFO', 'New database created', { path: this.filePath });
        this.save();
      }
    } catch (e) {
      log('ERROR', 'Failed to load database', { error: e.message });
    }
  }

  save() {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2));
    } catch (e) {
      log('ERROR', 'Failed to save database', { error: e.message });
    }
  }

  findUserByEmail(email) {
    return this.data.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  }

  findUserById(id) {
    return this.data.users.find(u => u.id === id);
  }

  createUser(email, password) {
    const hashed = hashPassword(password);
    const user = {
      id: this.data.nextId++,
      email: email.toLowerCase(),
      password: hashed,
      mfa_enabled: false,
      mfa_secret: generateTOTPSecret(),
      failed_attempts: 0,
      is_locked: false,
      lockout_until: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    this.data.users.push(user);
    this.save();
    log('INFO', 'User registered', { id: user.id, email: user.email });
    return this._sanitizeUser(user);
  }

  updateUser(id, updates) {
    const idx = this.data.users.findIndex(u => u.id === id);
    if (idx === -1) return null;
    const user = this.data.users[idx];
    Object.assign(user, updates, { updated_at: new Date().toISOString() });
    this.save();
    return this._sanitizeUser(user);
  }

  deleteUser(id) {
    const idx = this.data.users.findIndex(u => u.id === id);
    if (idx === -1) return false;
    this.data.users.splice(idx, 1);
    this.save();
    return true;
  }

  _sanitizeUser(user) {
    const { password, mfa_secret, ...safe } = user;
    return safe;
  }
}

const db = new Database(DB_PATH);

// ─── Rate Limiter ─────────────────────────────────────────────────
const rateLimitMap = new Map();

function rateLimit(key, maxAttempts = MAX_LOGIN_ATTEMPTS_PER_MINUTE, windowMs = 60000) {
  const now = Date.now();
  const entry = rateLimitMap.get(key);
  if (!entry || now - entry.windowStart > windowMs) {
    rateLimitMap.set(key, { windowStart: now, count: 1 });
    return { allowed: true, remaining: maxAttempts - 1 };
  }
  entry.count++;
  if (entry.count > maxAttempts) {
    return { allowed: false, remaining: 0, retryAfter: Math.ceil((windowMs - (now - entry.windowStart)) / 1000) };
  }
  return { allowed: true, remaining: maxAttempts - entry.count };
}

// Clean rate limit map every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitMap) {
    if (now - entry.windowStart > 120000) rateLimitMap.delete(key);
  }
}, 300000);

// ─── HTTP Server ──────────────────────────────────────────────────
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
  '.svg':  'image/svg+xml',
  '.woff2':'font/woff2',
};

function sendJSON(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
  log('DEBUG', 'Response', { status, method: res.req.method, url: res.req.url });
}

function sendError(res, status, message, code) {
  sendJSON(res, status, { error: message, code: code || `ERR_${status}` });
}

function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try { resolve(JSON.parse(body)); }
      catch { resolve({}); }
    });
  });
}

function getAuthUser(req) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return verifyJWT(auth.slice(7));
}

function serveStatic(url, res) {
  let filePath = path.join(__dirname, 'frontend', 'public',
    url === '/' ? 'index.html' : url);
  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      // SPA fallback: serve index.html for unknown routes
      fs.readFile(path.join(__dirname, 'frontend', 'public', 'index.html'), (err2, idx) => {
        if (err2) { res.writeHead(404); res.end('404 Not Found'); }
        else { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(idx); }
      });
    } else {
      res.writeHead(200, {
        'Content-Type': contentType,
        'Cache-Control': ext === '.html' ? 'no-cache' : 'max-age=3600',
      });
      res.end(content);
    }
  });
}

// ─── Request Logger Middleware ────────────────────────────────────
function logRequest(req) {
  log('INFO', `${req.method} ${req.url}`, {
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
    ua: (req.headers['user-agent'] || '').slice(0, 80),
  });
}

// ─── API Route Handler ────────────────────────────────────────────
async function handleAPI(req, res, pathname) {
  res.req = req; // for logger

  // ── OPTIONS (CORS preflight) ──
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    });
    res.end();
    return;
  }

  // ── POST /api/accounts/register/ ──
  if (pathname === '/api/accounts/register/' && req.method === 'POST') {
    const body = await parseBody(req);
    const { email, password } = body;

    if (!email || typeof email !== 'string')
      return sendError(res, 400, 'El email es obligatorio', 'INVALID_EMAIL');
    if (!password || typeof password !== 'string' || password.length < 6)
      return sendError(res, 400, 'La contraseña debe tener al menos 6 caracteres', 'WEAK_PASSWORD');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return sendError(res, 400, 'Formato de email inválido', 'BAD_EMAIL');
    if (password.length > 128)
      return sendError(res, 400, 'La contraseña es demasiado larga', 'LONG_PASSWORD');

    if (db.findUserByEmail(email))
      return sendError(res, 409, 'El email ya está registrado', 'EMAIL_EXISTS');

    const user = db.createUser(email, password);
    return sendJSON(res, 201, user);
  }

  // ── POST /api/accounts/login/ ──
  if (pathname === '/api/accounts/login/' && req.method === 'POST') {
    // Rate limit
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const rl = rateLimit(ip);
    if (!rl.allowed) {
      log('WARN', 'Rate limit exceeded', { ip });
      return sendJSON(res, 429, {
        error: 'Demasiados intentos. Intenta de nuevo en unos segundos.',
        retryAfter: rl.retryAfter,
        code: 'RATE_LIMITED'
      });
    }

    const body = await parseBody(req);
    const { email, password } = body;

    if (!email || !password)
      return sendError(res, 400, 'Email y contraseña son obligatorios', 'MISSING_FIELDS');

    const user = db.findUserByEmail(email);
    if (!user)
      return sendError(res, 401, 'Credenciales inválidas', 'INVALID_CREDENTIALS');

    // Check lockout
    if (user.is_locked && user.lockout_until) {
      const lockRemaining = new Date(user.lockout_until).getTime() - Date.now();
      if (lockRemaining > 0) {
        log('WARN', 'Locked account login attempt', { email, remaining: Math.ceil(lockRemaining / 1000) });
        return sendJSON(res, 423, {
          error: 'Cuenta bloqueada por demasiados intentos fallidos',
          locked: true,
          retryAfter: Math.ceil(lockRemaining / 1000),
          code: 'ACCOUNT_LOCKED'
        });
      }
      // Auto-unlock
      db.updateUser(user.id, { is_locked: false, failed_attempts: 0, lockout_until: null });
    }

    // Verify password
    if (!verifyPassword(password, user.password)) {
      const newAttempts = user.failed_attempts + 1;
      if (newAttempts >= LOCKOUT_THRESHOLD) {
        const lockUntil = new Date(Date.now() + LOCKOUT_DURATION).toISOString();
        db.updateUser(user.id, {
          failed_attempts: newAttempts,
          is_locked: true,
          lockout_until: lockUntil,
        });
        log('WARN', 'Account locked', { email, lockout_until: lockUntil });
        return sendJSON(res, 423, {
          error: 'Cuenta bloqueada por demasiados intentos fallidos',
          locked: true,
          retryAfter: LOCKOUT_DURATION / 1000,
          code: 'ACCOUNT_LOCKED'
        });
      }
      db.updateUser(user.id, { failed_attempts: newAttempts });
      log('WARN', 'Failed login', { email, attempts: newAttempts });
      return sendError(res, 401, 'Credenciales inválidas', 'INVALID_CREDENTIALS');
    }

    // Success — reset failures
    db.updateUser(user.id, { failed_attempts: 0, is_locked: false, lockout_until: null });
    log('INFO', 'Login success', { email, mfa: user.mfa_enabled });

    if (user.mfa_enabled) {
      const tempToken = createJWT({ userId: user.id, purpose: 'mfa_verify' }, 300000); // 5 min
      return sendJSON(res, 200, {
        message: 'Se requiere verificación MFA',
        user_id: user.id,
        mfa_required: true,
        temp_token: tempToken,
      });
    }

    const accessToken = createJWT({ userId: user.id, email: user.email, mfa: false });
    return sendJSON(res, 200, {
      access: accessToken,
      user: db._sanitizeUser(user),
    });
  }

  // ── POST /api/accounts/verify-mfa/ ──
  if (pathname === '/api/accounts/verify-mfa/' && req.method === 'POST') {
    const body = await parseBody(req);
    const { user_id, otp } = body;

    if (!user_id || !otp)
      return sendError(res, 400, 'user_id y otp son obligatorios', 'MISSING_FIELDS');

    const user = db.findUserById(parseInt(user_id));
    if (!user)
      return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    if (!verifyTOTP(user.mfa_secret, String(otp).trim())) {
      log('WARN', 'Invalid MFA code', { user_id });
      return sendError(res, 401, 'Código OTP inválido o expirado', 'INVALID_OTP');
    }

    // Enable MFA if not already (first-time setup)
    if (!user.mfa_enabled) {
      db.updateUser(user.id, { mfa_enabled: true });
      log('INFO', 'MFA enabled', { user_id: user.id, email: user.email });
    }

    const accessToken = createJWT({ userId: user.id, email: user.email, mfa: true });
    const refreshToken = createJWT({ userId: user.id, email: user.email, type: 'refresh' }, 86400000);
    log('INFO', 'MFA verification success', { user_id: user.id });

    return sendJSON(res, 200, {
      access: accessToken,
      refresh: refreshToken,
      user: { ...db._sanitizeUser(user), mfa_enabled: true },
    });
  }

  // ── GET /api/accounts/profile/ ──
  if (pathname === '/api/accounts/profile/' && req.method === 'GET') {
    const auth = getAuthUser(req);
    if (!auth) return sendError(res, 401, 'No autorizado', 'UNAUTHORIZED');

    const user = db.findUserById(auth.userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    return sendJSON(res, 200, db._sanitizeUser(user));
  }

  // ── POST /api/accounts/setup-mfa/ ──
  if (pathname === '/api/accounts/setup-mfa/' && req.method === 'POST') {
    const auth = getAuthUser(req);
    if (!auth) return sendError(res, 401, 'No autorizado', 'UNAUTHORIZED');

    const user = db.findUserById(auth.userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    // Generate new secret and return setup info
    const newSecret = generateTOTPSecret();
    db.updateUser(user.id, { mfa_secret: newSecret, mfa_enabled: false });
    log('INFO', 'MFA setup initiated', { user_id: user.id });

    const otpauthUrl = generateOTPAuthURL(newSecret, user.email);
    let qrDataUrl = '';
    try {
      qrDataUrl = await QRCode.toDataURL(otpauthUrl, {
        width: 300, margin: 2, color: { dark: '#000000', light: '#ffffff' }
      });
    } catch (e) {
      log('ERROR', 'Failed to generate QR code', { error: e.message });
    }

    return sendJSON(res, 200, {
      secret: newSecret,
      otpauth_url: otpauthUrl,
      qr_data_url: qrDataUrl,
      email: user.email,
    });
  }

  // ── POST /api/accounts/verify-setup/ ──
  if (pathname === '/api/accounts/verify-setup/' && req.method === 'POST') {
    const auth = getAuthUser(req);
    if (!auth) return sendError(res, 401, 'No autorizado', 'UNAUTHORIZED');

    const body = await parseBody(req);
    const { otp } = body;
    if (!otp) return sendError(res, 400, 'Código OTP requerido', 'MISSING_OTP');

    const user = db.findUserById(auth.userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    if (!verifyTOTP(user.mfa_secret, String(otp).trim())) {
      return sendError(res, 401, 'Código OTP inválido', 'INVALID_OTP');
    }

    db.updateUser(user.id, { mfa_enabled: true });
    log('INFO', 'MFA verified and enabled', { user_id: user.id });

    return sendJSON(res, 200, {
      success: true,
      message: 'MFA configurado correctamente',
      user: db._sanitizeUser(db.findUserById(user.id)),
    });
  }

  // ── POST /api/accounts/disable-mfa/ ──
  if (pathname === '/api/accounts/disable-mfa/' && req.method === 'POST') {
    const auth = getAuthUser(req);
    if (!auth) return sendError(res, 401, 'No autorizado', 'UNAUTHORIZED');

    const body = await parseBody(req);
    const { otp } = body;
    if (!otp) return sendError(res, 400, 'Código OTP requerido para deshabilitar MFA', 'MISSING_OTP');

    const user = db.findUserById(auth.userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');
    if (!user.mfa_enabled) return sendError(res, 400, 'MFA no está habilitado', 'MFA_NOT_ENABLED');

    if (!verifyTOTP(user.mfa_secret, String(otp).trim())) {
      return sendError(res, 401, 'Código OTP inválido', 'INVALID_OTP');
    }

    const newSecret = generateTOTPSecret();
    db.updateUser(user.id, { mfa_enabled: false, mfa_secret: newSecret });
    log('WARN', 'MFA disabled', { user_id: user.id });

    return sendJSON(res, 200, { success: true, message: 'MFA deshabilitado' });
  }

  // ── PUT /api/accounts/change-password/ ──
  if (pathname === '/api/accounts/change-password/' && req.method === 'PUT') {
    const auth = getAuthUser(req);
    if (!auth) return sendError(res, 401, 'No autorizado', 'UNAUTHORIZED');

    const body = await parseBody(req);
    const { currentPassword, newPassword } = body;

    if (!currentPassword || !newPassword)
      return sendError(res, 400, 'Contraseña actual y nueva son requeridas', 'MISSING_FIELDS');
    if (newPassword.length < 6)
      return sendError(res, 400, 'La nueva contraseña debe tener al menos 6 caracteres', 'WEAK_PASSWORD');

    const user = db.findUserById(auth.userId);
    if (!user) return sendError(res, 404, 'Usuario no encontrado', 'USER_NOT_FOUND');

    if (!verifyPassword(currentPassword, user.password))
      return sendError(res, 401, 'Contraseña actual incorrecta', 'WRONG_PASSWORD');

    db.updateUser(user.id, { password: hashPassword(newPassword) });
    log('INFO', 'Password changed', { user_id: user.id });

    return sendJSON(res, 200, { success: true, message: 'Contraseña actualizada' });
  }

  // ── GET /api/ ──
  if (pathname === '/api/') {
    return sendJSON(res, 200, {
      name: 'MFA Authentication System API',
      version: '2.0.0',
      endpoints: {
        register:      { method: 'POST', path: '/api/accounts/register/',      desc: 'Registrar nuevo usuario' },
        login:         { method: 'POST', path: '/api/accounts/login/',         desc: 'Iniciar sesión' },
        verify_mfa:    { method: 'POST', path: '/api/accounts/verify-mfa/',    desc: 'Verificar código MFA' },
        setup_mfa:     { method: 'POST', path: '/api/accounts/setup-mfa/',     desc: 'Obtener datos para configurar MFA', auth: true },
        verify_setup:  { method: 'POST', path: '/api/accounts/verify-setup/',  desc: 'Confirmar configuración MFA', auth: true },
        disable_mfa:   { method: 'POST', path: '/api/accounts/disable-mfa/',   desc: 'Deshabilitar MFA', auth: true },
        profile:       { method: 'GET',  path: '/api/accounts/profile/',       desc: 'Obtener perfil del usuario', auth: true },
        change_pass:   { method: 'PUT',  path: '/api/accounts/change-password/', desc: 'Cambiar contraseña', auth: true },
      },
      server_time: new Date().toISOString(),
      totp_config: { algorithm: 'SHA1', digits: TOTP_DIGITS, period: TOTP_PERIOD },
    });
  }

  return false; // not handled
}

// ─── Server ───────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;

    logRequest(req);

    // Try API handler first
    const handled = await handleAPI(req, res, pathname);
    if (handled !== false) return;

    // Serve static files
    serveStatic(pathname, res);
  } catch (err) {
    log('ERROR', 'Unhandled server error', { error: err.message, stack: err.stack?.split('\n').slice(0, 3) });
    if (!res.headersSent) {
      sendError(res, 500, 'Error interno del servidor', 'SERVER_ERROR');
    }
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  ┌──────────────────────────────────────────┐');
  console.log(`  │  🔐  MFA Authentication System v2.0      │`);
  console.log(`  │  📡  http://localhost:${PORT}                    │`);
  console.log(`  │  📝  http://localhost:${PORT}/api/               │`);
  console.log('  └──────────────────────────────────────────┘');
  console.log('');
  log('INFO', 'Server started', { port: PORT, node: process.version, pid: process.pid });
});

// ─── Graceful Shutdown ──────────────────────────────────────────
function shutdown(signal) {
  log('INFO', `Received ${signal}, shutting down gracefully...`);
  server.close(() => {
    db.save();
    log('INFO', 'Server shut down');
    process.exit(0);
  });
  setTimeout(() => { log('ERROR', 'Forced shutdown'); process.exit(1); }, 5000);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('uncaughtException', (err) => {
  log('ERROR', 'Uncaught exception', { error: err.message });
});
process.on('unhandledRejection', (reason) => {
  log('ERROR', 'Unhandled rejection', { reason: String(reason) });
});
