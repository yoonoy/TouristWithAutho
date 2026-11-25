'use strict';

/*
 * Visitor accounts for Travel Horizon.
 *
 * Procedures:
 *   POST /api/auth/register         create an account and e-mail a 6-digit code
 *   POST /api/auth/verify-email     confirm the e-mail with the code and sign in
 *   POST /api/auth/resend-code      e-mail a fresh code (verification or password reset)
 *   POST /api/auth/login            sign in with e-mail + password
 *   POST /api/auth/logout           sign out
 *   GET  /api/auth/me               who is signed in right now
 *   POST /api/auth/forgot-password  e-mail a password-reset code
 *   POST /api/auth/reset-password   set a new password using the code
 *   POST /api/auth/change-password  change password while signed in
 *
 * The admin panel keeps its own separate password login (admin_session cookie).
 */

const { createHash, randomBytes, randomInt, scrypt, timingSafeEqual } = require('node:crypto');
const { promisify } = require('node:util');

const scryptAsync = promisify(scrypt);

const SESSION_COOKIE = 'user_session';
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const CODE_TTL_MS = 10 * 60 * 1000;
const CODE_COOLDOWN_MS = 60 * 1000;
const MAX_CODE_ATTEMPTS = 5;
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };
const LOCALES = ['en', 'ky', 'ru'];

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function fail(status, code, message) {
  return Object.assign(new Error(message), { status, code });
}

/* ---------- validation ---------- */

function cleanEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && EMAIL_RE.test(email) ? email : null;
}

function cleanName(value) {
  if (typeof value !== 'string') return null;
  const name = value.trim().replace(/\s+/g, ' ');
  return name.length >= 1 && name.length <= 80 && !/[\u0000-\u001f<>]/.test(name) ? name : null;
}

function isStrongPassword(value) {
  return typeof value === 'string'
    && value.length >= 8
    && value.length <= 128
    && /\p{L}/u.test(value)
    && /\d/.test(value);
}

/* ---------- passwords ---------- */

async function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = await scryptAsync(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, N, r, p, saltB64, hashB64] = parts;
  const expected = Buffer.from(hashB64, 'base64');
  const actual = await scryptAsync(password, Buffer.from(saltB64, 'base64'), expected.length, {
    N: Number(N), r: Number(r), p: Number(p)
  });
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

let dummyHash;
// Spend the same time when the e-mail is unknown, so response time does not reveal which e-mails exist.
async function burnPasswordCheck(password) {
  dummyHash ??= await hashPassword('travel-horizon-dummy-password-1');
  await verifyPassword(password, dummyHash);
}

/* ---------- rate limiting (in memory) ---------- */

const buckets = new Map();

function allow(key, max, windowMs) {
  const now = Date.now();
  const hits = (buckets.get(key) || []).filter((time) => now - time < windowMs);
  if (hits.length >= max) {
    buckets.set(key, hits);
    return false;
  }
  hits.push(now);
  buckets.set(key, hits);
  if (buckets.size > 5000) {
    for (const [bucketKey, times] of buckets) {
      if (times.every((time) => now - time >= 60 * 60 * 1000)) buckets.delete(bucketKey);
    }
  }
  return true;
}

function clientAddress(request) {
  if (process.env.TRUST_PROXY === 'true') {
    const forwarded = String(request.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (forwarded) return forwarded;
  }
  return request.socket.remoteAddress || 'local';
}

function limitOrThrow(key, max, windowMs) {
  if (!allow(key, max, windowMs)) throw fail(429, 'rate_limited', 'Too many attempts. Please try again later.');
}

/* ---------- e-mail ---------- */

const MAIL_TEXT = {
  en: {
    verify: { subject: 'Confirm your email — Travel Horizon', lead: 'Your Travel Horizon verification code is:' },
    reset: { subject: 'Reset your password — Travel Horizon', lead: 'Your Travel Horizon password reset code is:' },
    hello: (name) => `Hello, ${name}!`,
    expires: 'The code works for 10 minutes. If you did not request it, you can safely ignore this email.'
  },
  ky: {
    verify: { subject: 'Почтаңызды тастыктаңыз — Travel Horizon', lead: 'Travel Horizon тастыктоо кодуңуз:' },
    reset: { subject: 'Сырсөздү калыбына келтирүү — Travel Horizon', lead: 'Travel Horizon сырсөздү калыбына келтирүү кодуңуз:' },
    hello: (name) => `Саламатсызбы, ${name}!`,
    expires: 'Код 10 мүнөт жарактуу. Эгер сиз сураган эмес болсоңуз, бул катты этибарга албай эле коюңуз.'
  },
  ru: {
    verify: { subject: 'Подтвердите почту — Travel Horizon', lead: 'Ваш код подтверждения Travel Horizon:' },
    reset: { subject: 'Сброс пароля — Travel Horizon', lead: 'Ваш код для сброса пароля Travel Horizon:' },
    hello: (name) => `Здравствуйте, ${name}!`,
    expires: 'Код действует 10 минут. Если вы его не запрашивали, просто проигнорируйте это письмо.'
  }
};

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

let transport;
function getTransport() {
  if (transport !== undefined) return transport;
  if (!process.env.SMTP_HOST) {
    transport = null;
    return transport;
  }
  const nodemailer = require('nodemailer');
  const port = Number(process.env.SMTP_PORT || 587);
  const secure = process.env.SMTP_SECURE ? process.env.SMTP_SECURE === 'true' : port === 465;
  transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS || '' } : undefined
  });
  return transport;
}

async function sendCodeEmail({ to, firstName, purpose, code, locale }) {
  const text = MAIL_TEXT[LOCALES.includes(locale) ? locale : 'en'];
  const { subject, lead } = text[purpose];
  let mailer;
  try {
    mailer = getTransport();
  } catch (error) {
    console.error('Could not load the e-mail library. Run "npm install" first.', error.message);
    throw fail(502, 'email_failed', 'The email could not be sent right now.');
  }

  if (!mailer) {
    if (process.env.NODE_ENV === 'production') {
      throw fail(503, 'email_not_configured', 'Email sending is not configured.');
    }
    // Local development without SMTP: show the code in the server console instead of sending it.
    console.log(`\n[mail:dev] SMTP is not configured. ${purpose} code for ${to}: ${code}\n`);
    return;
  }

  const from = process.env.MAIL_FROM || process.env.SMTP_USER;
  if (!from) throw fail(503, 'email_not_configured', 'MAIL_FROM is not configured.');

  const plain = `${text.hello(firstName)}\n\n${lead} ${code}\n\n${text.expires}`;
  const html = `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;color:#202b25">
  <h2 style="font-family:Georgia,serif;color:#294c3b">Travel Horizon</h2>
  <p>${escapeHtml(text.hello(firstName))}</p>
  <p>${escapeHtml(lead)}</p>
  <p style="font-size:34px;letter-spacing:8px;font-weight:700;background:#f3ede1;padding:14px 18px;border-radius:6px;text-align:center">${code}</p>
  <p style="color:#69726a;font-size:13px">${escapeHtml(text.expires)}</p>
</div>`;

  try {
    await mailer.sendMail({ from, to, subject, text: plain, html });
  } catch (error) {
    console.error('Sending the email failed:', error.message);
    throw fail(502, 'email_failed', 'The email could not be sent right now.');
  }
}

/* ---------- module factory ---------- */

function createAuth({ database, sendJson, readJson, checkSameOrigin }) {
  const hashToken = (token) => createHash('sha256').update(token).digest('hex');
  const hashCode = (userId, purpose, code) => createHash('sha256').update(`${purpose}:${userId}:${code}`).digest('hex');

  const publicUser = (row) => ({
    id: Number(row.id),
    email: row.email,
    firstName: row.first_name,
    lastName: row.last_name,
    createdAt: row.created_at
  });

  async function initialize() {
    await database.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        email_verified BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_login_at TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS email_codes (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        purpose TEXT NOT NULL CHECK (purpose IN ('verify', 'reset')),
        code_hash TEXT NOT NULL,
        attempts SMALLINT NOT NULL DEFAULT 0,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS email_codes_user_purpose ON email_codes (user_id, purpose);
      CREATE TABLE IF NOT EXISTS user_sessions (
        token_hash TEXT PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await cleanup();
    setInterval(() => cleanup().catch((error) => console.error('Auth cleanup failed:', error.message)), 60 * 60 * 1000).unref();
  }

  async function cleanup() {
    await database.query('DELETE FROM user_sessions WHERE expires_at < NOW()');
    await database.query('DELETE FROM email_codes WHERE expires_at < NOW()');
  }

  /* ----- users ----- */

  async function findUserByEmail(email) {
    const result = await database.query(
      'SELECT id, email, first_name, last_name, password_hash, email_verified FROM users WHERE email = $1',
      [email]
    );
    return result.rows[0] || null;
  }

  /* ----- one-time codes ----- */

  async function issueCode(userId, purpose, { force = false } = {}) {
    const latest = await database.query(
      'SELECT id, created_at FROM email_codes WHERE user_id = $1 AND purpose = $2 ORDER BY created_at DESC LIMIT 1',
      [userId, purpose]
    );
    const row = latest.rows[0];
    if (!force && row && Date.now() - new Date(row.created_at).getTime() < CODE_COOLDOWN_MS) return null;

    const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
    await database.query('DELETE FROM email_codes WHERE user_id = $1 AND purpose = $2', [userId, purpose]);
    await database.query(
      'INSERT INTO email_codes (user_id, purpose, code_hash, expires_at) VALUES ($1, $2, $3, $4)',
      [userId, purpose, hashCode(userId, purpose, code), new Date(Date.now() + CODE_TTL_MS)]
    );
    return code;
  }

  async function checkCode(userId, purpose, candidate) {
    const code = typeof candidate === 'string' ? candidate.trim() : '';
    if (!/^\d{6}$/.test(code)) throw fail(400, 'bad_code', 'That code is not correct.');

    const latest = await database.query(
      'SELECT id, code_hash, expires_at FROM email_codes WHERE user_id = $1 AND purpose = $2 ORDER BY created_at DESC LIMIT 1',
      [userId, purpose]
    );
    const row = latest.rows[0];
    if (!row) throw fail(400, 'bad_code', 'That code is not correct.');
    if (new Date(row.expires_at).getTime() < Date.now()) {
      await database.query('DELETE FROM email_codes WHERE user_id = $1 AND purpose = $2', [userId, purpose]);
      throw fail(400, 'code_expired', 'That code has expired. Request a new one.');
    }

    // Count the try first (atomically) so parallel guesses cannot beat the attempt limit.
    const counted = await database.query('UPDATE email_codes SET attempts = attempts + 1 WHERE id = $1 RETURNING attempts', [row.id]);
    const attempts = counted.rows[0]?.attempts;
    if (attempts === undefined) throw fail(400, 'bad_code', 'That code is not correct.');
    if (attempts > MAX_CODE_ATTEMPTS) {
      await database.query('DELETE FROM email_codes WHERE user_id = $1 AND purpose = $2', [userId, purpose]);
      throw fail(429, 'too_many_attempts', 'Too many wrong codes. Request a new one.');
    }

    const expected = Buffer.from(row.code_hash, 'hex');
    const actual = Buffer.from(hashCode(userId, purpose, code), 'hex');
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
      throw fail(400, 'bad_code', 'That code is not correct.');
    }
    await database.query('DELETE FROM email_codes WHERE user_id = $1 AND purpose = $2', [userId, purpose]);
  }

  /* ----- sessions ----- */

  function cookieFlags(request, maxAgeSeconds) {
    const secure = request.headers['x-forwarded-proto'] === 'https' || request.socket.encrypted;
    return `HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}${secure ? '; Secure' : ''}`;
  }

  function readToken(request) {
    return (request.headers.cookie || '').match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([a-f0-9]{64})`))?.[1] || null;
  }

  async function startSession(request, userId) {
    const token = randomBytes(32).toString('hex');
    await database.query(
      'INSERT INTO user_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)',
      [hashToken(token), userId, new Date(Date.now() + SESSION_TTL_MS)]
    );
    await database.query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [userId]);
    return { 'Set-Cookie': `${SESSION_COOKIE}=${token}; ${cookieFlags(request, SESSION_TTL_MS / 1000)}` };
  }

  async function currentUser(request) {
    const token = readToken(request);
    if (!token) return null;
    const result = await database.query(
      `SELECT u.id, u.email, u.first_name, u.last_name, u.created_at
         FROM user_sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = $1 AND s.expires_at > NOW() AND u.email_verified = TRUE`,
      [hashToken(token)]
    );
    return result.rows[0] ? { token, row: result.rows[0] } : null;
  }

  function requireOrigin(request) {
    if (!checkSameOrigin(request)) throw fail(403, 'origin', 'Request origin was not allowed.');
  }

  function bodyObject(body) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw fail(400, 'invalid_input', 'Request must be a JSON object.');
    return body;
  }

  const pickLocale = (value) => (LOCALES.includes(value) ? value : 'en');

  /* ----- procedures ----- */

  async function register(request, response) {
    requireOrigin(request);
    const body = bodyObject(await readJson(request));
    if (body.website) { // honeypot field that real visitors never fill in
      sendJson(response, 200, { ok: true, verificationRequired: true });
      return;
    }
    const email = cleanEmail(body.email);
    const firstName = cleanName(body.firstName);
    const lastName = cleanName(body.lastName);
    if (!email) throw fail(400, 'invalid_email', 'Enter a valid email address.');
    if (!firstName || !lastName) throw fail(400, 'invalid_name', 'Enter your name and surname.');
    if (!isStrongPassword(body.password)) {
      throw fail(400, 'weak_password', 'Use at least 8 characters, including a letter and a number.');
    }
    limitOrThrow(`register:ip:${clientAddress(request)}`, 8, 60 * 60 * 1000);
    limitOrThrow(`register:email:${email}`, 3, 60 * 60 * 1000);

    const passwordHash = await hashPassword(body.password);
    const existing = await findUserByEmail(email);
    let userId;
    if (existing?.email_verified) throw fail(409, 'email_taken', 'This email is already registered. Sign in instead.');
    if (existing) {
      // Unfinished registration: replace the pending details and send a brand-new code (old codes stop working).
      await database.query(
        'UPDATE users SET first_name = $2, last_name = $3, password_hash = $4 WHERE id = $1 AND email_verified = FALSE',
        [existing.id, firstName, lastName, passwordHash]
      );
      userId = existing.id;
    } else {
      try {
        const created = await database.query(
          'INSERT INTO users (email, first_name, last_name, password_hash) VALUES ($1, $2, $3, $4) RETURNING id',
          [email, firstName, lastName, passwordHash]
        );
        userId = created.rows[0].id;
      } catch (error) {
        if (error.code === '23505') throw fail(409, 'email_taken', 'This email is already registered. Sign in instead.');
        throw error;
      }
    }

    const code = await issueCode(userId, 'verify', { force: true });
    await sendCodeEmail({ to: email, firstName, purpose: 'verify', code, locale: pickLocale(body.locale) });
    sendJson(response, 201, { ok: true, verificationRequired: true, email });
  }

  async function verifyEmail(request, response) {
    requireOrigin(request);
    const body = bodyObject(await readJson(request));
    const email = cleanEmail(body.email);
    if (!email) throw fail(400, 'invalid_email', 'Enter a valid email address.');
    limitOrThrow(`verify:ip:${clientAddress(request)}`, 20, 60 * 60 * 1000);

    const user = await findUserByEmail(email);
    if (!user) throw fail(400, 'bad_code', 'That code is not correct.');
    await checkCode(user.id, 'verify', body.code);
    await database.query('UPDATE users SET email_verified = TRUE WHERE id = $1', [user.id]);
    const headers = await startSession(request, user.id);
    sendJson(response, 200, { ok: true, user: publicUser(user) }, headers);
  }

  async function resendCode(request, response) {
    requireOrigin(request);
    const body = bodyObject(await readJson(request));
    const email = cleanEmail(body.email);
    const purpose = body.purpose === 'reset' ? 'reset' : 'verify';
    if (!email) throw fail(400, 'invalid_email', 'Enter a valid email address.');
    limitOrThrow(`resend:ip:${clientAddress(request)}`, 10, 60 * 60 * 1000);
    limitOrThrow(`resend:email:${email}`, 6, 60 * 60 * 1000);

    const user = await findUserByEmail(email);
    // The answer is always "ok" so nobody can use this form to discover which emails are registered.
    if (user && (purpose === 'reset' || !user.email_verified)) {
      const code = await issueCode(user.id, purpose);
      if (code) await sendCodeEmail({ to: email, firstName: user.first_name, purpose, code, locale: pickLocale(body.locale) });
    }
    sendJson(response, 200, { ok: true });
  }

  async function login(request, response) {
    requireOrigin(request);
    const body = bodyObject(await readJson(request));
    const email = cleanEmail(body.email);
    const password = typeof body.password === 'string' && body.password.length <= 128 ? body.password : '';
    if (!email || !password) throw fail(401, 'bad_credentials', 'Email or password is not correct.');
    limitOrThrow(`login:ip:${clientAddress(request)}`, 20, 15 * 60 * 1000);
    limitOrThrow(`login:email:${email}`, 8, 15 * 60 * 1000);

    const user = await findUserByEmail(email);
    if (!user) {
      await burnPasswordCheck(password);
      throw fail(401, 'bad_credentials', 'Email or password is not correct.');
    }
    if (!(await verifyPassword(password, user.password_hash))) {
      throw fail(401, 'bad_credentials', 'Email or password is not correct.');
    }
    if (!user.email_verified) {
      const code = await issueCode(user.id, 'verify');
      if (code) await sendCodeEmail({ to: email, firstName: user.first_name, purpose: 'verify', code, locale: pickLocale(body.locale) });
      sendJson(response, 403, { error: 'Confirm your email first. We sent you a new code.', code: 'not_verified', email });
      return;
    }
    buckets.delete(`login:email:${email}`);
    const headers = await startSession(request, user.id);
    sendJson(response, 200, { ok: true, user: publicUser(user) }, headers);
  }

  async function logout(request, response) {
    requireOrigin(request);
    const token = readToken(request);
    if (token) await database.query('DELETE FROM user_sessions WHERE token_hash = $1', [hashToken(token)]);
    sendJson(response, 200, { ok: true }, { 'Set-Cookie': `${SESSION_COOKIE}=; ${cookieFlags(request, 0)}` });
  }

  async function me(request, response) {
    const session = await currentUser(request);
    sendJson(response, 200, { user: session ? publicUser(session.row) : null });
  }

  async function forgotPassword(request, response) {
    requireOrigin(request);
    const body = bodyObject(await readJson(request));
    const email = cleanEmail(body.email);
    if (!email) throw fail(400, 'invalid_email', 'Enter a valid email address.');
    limitOrThrow(`forgot:ip:${clientAddress(request)}`, 8, 60 * 60 * 1000);
    limitOrThrow(`forgot:email:${email}`, 4, 60 * 60 * 1000);

    const user = await findUserByEmail(email);
    if (user) {
      const code = await issueCode(user.id, 'reset');
      if (code) await sendCodeEmail({ to: email, firstName: user.first_name, purpose: 'reset', code, locale: pickLocale(body.locale) });
    }
    sendJson(response, 200, { ok: true });
  }

  async function resetPassword(request, response) {
    requireOrigin(request);
    const body = bodyObject(await readJson(request));
    const email = cleanEmail(body.email);
    if (!email) throw fail(400, 'invalid_email', 'Enter a valid email address.');
    if (!isStrongPassword(body.password)) {
      throw fail(400, 'weak_password', 'Use at least 8 characters, including a letter and a number.');
    }
    limitOrThrow(`reset:ip:${clientAddress(request)}`, 20, 60 * 60 * 1000);

    const user = await findUserByEmail(email);
    if (!user) throw fail(400, 'bad_code', 'That code is not correct.');
    await checkCode(user.id, 'reset', body.code);
    // Owning the code proves control of the mailbox, so the email counts as confirmed too.
    await database.query('UPDATE users SET password_hash = $2, email_verified = TRUE WHERE id = $1', [user.id, await hashPassword(body.password)]);
    await database.query('DELETE FROM user_sessions WHERE user_id = $1', [user.id]);
    await database.query('DELETE FROM email_codes WHERE user_id = $1', [user.id]);
    sendJson(response, 200, { ok: true });
  }

  async function changePassword(request, response) {
    requireOrigin(request);
    const session = await currentUser(request);
    if (!session) throw fail(401, 'unauthorized', 'Sign in to continue.');
    const body = bodyObject(await readJson(request));
    if (!isStrongPassword(body.newPassword)) {
      throw fail(400, 'weak_password', 'Use at least 8 characters, including a letter and a number.');
    }
    limitOrThrow(`change:user:${session.row.id}`, 10, 60 * 60 * 1000);

    const found = await database.query('SELECT password_hash FROM users WHERE id = $1', [session.row.id]);
    const current = typeof body.currentPassword === 'string' ? body.currentPassword : '';
    if (!found.rows[0] || !(await verifyPassword(current, found.rows[0].password_hash))) {
      throw fail(403, 'wrong_password', 'The current password is not correct.');
    }
    await database.query('UPDATE users SET password_hash = $2 WHERE id = $1', [session.row.id, await hashPassword(body.newPassword)]);
    // Sign out every other device, keep this one.
    await database.query('DELETE FROM user_sessions WHERE user_id = $1 AND token_hash <> $2', [session.row.id, hashToken(session.token)]);
    sendJson(response, 200, { ok: true });
  }

  const routes = new Map([
    ['POST /api/auth/register', register],
    ['POST /api/auth/verify-email', verifyEmail],
    ['POST /api/auth/resend-code', resendCode],
    ['POST /api/auth/login', login],
    ['POST /api/auth/logout', logout],
    ['GET /api/auth/me', me],
    ['POST /api/auth/forgot-password', forgotPassword],
    ['POST /api/auth/reset-password', resetPassword],
    ['POST /api/auth/change-password', changePassword]
  ]);

  // Returns true when the request belonged to the auth API (and has been answered).
  async function handle(request, response, url) {
    if (!url.pathname.startsWith('/api/auth/')) return false;
    const route = routes.get(`${request.method} ${url.pathname}`);
    if (!route) {
      sendJson(response, 404, { error: 'Not found.', code: 'not_found' });
      return true;
    }
    try {
      await route(request, response);
    } catch (error) {
      if (!error.status) throw error;
      sendJson(response, error.status, { error: error.message, code: error.code || 'error' });
    }
    return true;
  }

  return { initialize, handle };
}

module.exports = { createAuth, hashPassword, verifyPassword, isStrongPassword, cleanEmail };
