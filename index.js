require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

const app = express();

/* ============== Segurança básica ============== */
app.use(helmet());
app.use(cookieParser());
app.use(express.json({ limit: '10kb' }));

/* ============== CORS dinâmico via .env (wildcards) ============== */
const RAW_PATTERNS =
  process.env.ALLOWED_ORIGIN_PATTERNS ||
  process.env.ALLOWED_ORIGINS || // fallback
  '';

const ORIGIN_PATTERNS = RAW_PATTERNS.split(',')
  .map(s => s.trim())
  .filter(Boolean);

console.log('[CORS] patterns:', ORIGIN_PATTERNS);

function normalizeOrigin(s) {
  // remove barra final e força lowercase
  return s.replace(/\/+$/, '').toLowerCase();
}

function isAllowedOrigin(origin) {
  if (!origin) return true; // curl/postman
  let url;
  try { url = new URL(origin); } catch { return false; }
  const proto = url.protocol.toLowerCase();
  const host = url.hostname.toLowerCase();
  const normalizedOrigin = normalizeOrigin(origin);

  if (proto !== 'http:' && proto !== 'https:') return false;

  for (const patRaw of ORIGIN_PATTERNS) {
    const pat = normalizeOrigin(patRaw);

    // 1) exato com protocolo (http/https)
    if (/^https?:\/\//i.test(pat)) {
      if (normalizedOrigin === pat) return true;
      continue;
    }
    // 2) wildcard/base: *.dkdevs.com.br ou dkdevs.com.br
    const base = pat.replace(/^\*\./, '');
    if (host === base || host.endsWith(`.${base}`)) return true;
  }
  return false;
}

const corsOptions = {
  origin: (origin, cb) => {
    const ok = isAllowedOrigin(origin);
    if (ok) cb(null, true);
    else {
      console.error('⛔ CORS bloqueado para origem:', origin);
      cb(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'CSRF-Token', 'csrf-token'],
  exposedHeaders: ['CSRF-Token'],
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));


/* ============== Banco ============== */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false, // ajuste para seu provedor (true em alguns PaaS)
});

/* ============== E-mail ============== */
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: Number(process.env.SMTP_PORT) === 465,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});
async function sendMail({ to, subject, html }) {
  return transporter.sendMail({
    from: `"Portal" <${process.env.SMTP_USER}>`,
    to, subject,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto">
        ${html}
        <hr/>
        <p style="color:#666;font-size:12px">Se você não solicitou, ignore este e-mail.</p>
      </div>`,
  });
}

/* ============== Utils & rate limits ============== */
const now = () => new Date();
const minutes = n => n * 60 * 1000;
const hours = n => n * 60 * 60 * 1000;

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

/* ============== CSRF ============== */
app.get('/api/csrf-token', (req, res) => {
  const csrfToken = crypto.randomBytes(32).toString('hex');
  res.cookie('XSRF-TOKEN', csrfToken, {
    secure: (process.env.CSRF_COOKIE_SECURE || 'true') !== 'false',
    httpOnly: false,
    sameSite: 'None',
    maxAge: 86400000,
  });
  res.json({ token: csrfToken });
});

/* ============== Login / Logout ============== */
app.post('/api/login', loginLimiter, async (req, res) => {
  const { email, password, rememberMe } = req.body;

  // CSRF
  const csrfHeader = req.headers['csrf-token'];
  if (!csrfHeader || csrfHeader !== req.cookies['XSRF-TOKEN']) {
    return res.status(403).json({ message: 'Token CSRF inválido' });
    }

  try {
    const result = await pool.query(
      `SELECT u.id, u.email, u.password, u.profile, u.login_attempts, u.locked_until,
              c.access_url
         FROM users u
         JOIN companies c ON u.company_id = c.id
        WHERE u.email = $1`,
      [String(email || '').toLowerCase()]
    );
    const user = result.rows[0];

    if (!user) {
      await new Promise(r => setTimeout(r, 500));
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(403).json({ message: 'Conta temporariamente bloqueada' });
    }

    const match = await bcrypt.compare(String(password || ''), user.password || '');
    if (!match) {
      await pool.query(
        `UPDATE users
            SET login_attempts = login_attempts + 1,
                locked_until = CASE
                  WHEN login_attempts + 1 >= 5 THEN NOW() + INTERVAL '30 minutes'
                  ELSE locked_until
                END
          WHERE email = $1`,
        [email]
      );
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    await pool.query(
      'UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE email = $1',
      [email]
    );

    const tokenExpiration = rememberMe ? '7d' : '15m';
    const token = jwt.sign(
      { id: user.id, email: user.email, profile: user.profile },
      process.env.JWT_SECRET,
      { expiresIn: tokenExpiration }
    );

    res.cookie('authToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : undefined
    });

    res.json({
      token,
      redirectUrl: `${user.access_url}?token=${token}`,
      user: { id: user.id, email: user.email, profile: user.profile }
    });
  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ message: 'Erro no servidor' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('authToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
  res.json({ message: 'Logout realizado com sucesso' });
});

/* ============== Forgot password ============== */
app.post('/api/forgot-password', resetLimiter, async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.json({ ok: true });

  try {
    const q = await pool.query(
      `SELECT u.id AS user_id, u.email, u.company_id, c.access_url
         FROM users u
         JOIN companies c ON c.id = u.company_id
        WHERE u.email = $1`,
      [String(email).toLowerCase()]
    );
    const row = q.rows[0];
    if (!row) return res.json({ ok: true });

    const raw = crypto.randomBytes(32).toString('base64url');
    const hash = await bcrypt.hash(raw, 12);
    const tokenId = uuidv4();
    const expiresAt = new Date(Date.now() + minutes(30));

    await pool.query(
      `INSERT INTO password_tokens (id, user_id, company_id, type, token_hash, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [tokenId, row.user_id, row.company_id, 'reset', hash, expiresAt]
    );

    const link = `${row.access_url.replace(/\/+$/,'')}/auth/set-password?token=${encodeURIComponent(`${tokenId}.${raw}`)}`;

    await sendMail({
      to: row.email,
      subject: 'Redefinir sua senha',
      html: `<p>Recebemos um pedido para redefinir sua senha.</p>
             <p><a href="${link}">Clique aqui para definir a nova senha</a></p>
             <p>O link expira em 30 minutos.</p>`
    });

    res.json({ ok: true });
  } catch (e) {
    console.error('forgot-password error', e);
    res.json({ ok: true });
  }
});

/* ============== Invite ============== */
app.post('/api/invite', async (req, res) => {
  const { email, companySlug, companyId } = req.body || {};
  if (!email || (!companySlug && !companyId))
    return res.status(400).json({ message: 'email e companySlug/companyId são obrigatórios' });

  try {
    const comp = companyId
      ? await pool.query('SELECT id, access_url FROM companies WHERE id=$1', [companyId])
      : await pool.query('SELECT id, access_url FROM companies WHERE slug=$1', [companySlug]);
    const company = comp.rows[0];
    if (!company) return res.status(404).json({ message: 'Empresa não encontrada' });

    const lower = String(email).toLowerCase();
    const u = await pool.query(
      `INSERT INTO users (company_id, email)
       VALUES ($1,$2)
       ON CONFLICT (company_id, email) DO UPDATE SET updated_at = NOW()
       RETURNING id, email`,
      [company.id, lower]
    );
    const user = u.rows[0];

    const raw = crypto.randomBytes(32).toString('base64url');
    const hash = await bcrypt.hash(raw, 12);
    const tokenId = uuidv4();
    const expiresAt = new Date(Date.now() + hours(24));

    await pool.query(
      `INSERT INTO password_tokens (id, user_id, company_id, type, token_hash, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [tokenId, user.id, company.id, 'invite', hash, expiresAt]
    );

    const link = `${company.access_url.replace(/\/+$/,'')}/auth/set-password?token=${encodeURIComponent(`${tokenId}.${raw}`)}`;

    await sendMail({
      to: user.email,
      subject: 'Bem-vindo! Defina sua senha',
      html: `<p>Olá! Sua conta foi criada.</p>
             <p><a href="${link}">Definir senha</a></p>
             <p>O link expira em 24 horas.</p>`
    });

    res.json({ ok: true });
  } catch (e) {
    console.error('invite error', e);
    res.status(500).json({ message: 'Erro no servidor' });
  }
});

/* ============== Set password ============== */
app.post('/api/set-password', async (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword || String(newPassword).length < 8)
    return res.status(400).json({ message: 'token e senha (mín. 8) são obrigatórios' });

  const [tokenId, raw] = String(token).split('.');
  if (!tokenId || !raw) return res.status(400).json({ message: 'Token inválido' });

  const client = await pool.connect();
  try {
    const q = await client.query(
      `SELECT id, user_id, token_hash, expires_at, used_at
         FROM password_tokens
        WHERE id = $1`,
      [tokenId]
    );
    const rec = q.rows[0];
    if (!rec || rec.used_at || new Date(rec.expires_at) <= now())
      return res.status(400).json({ message: 'Token inválido ou expirado' });

    const ok = await bcrypt.compare(raw, rec.token_hash);
    if (!ok) return res.status(400).json({ message: 'Token inválido' });

    const pwdHash = await bcrypt.hash(String(newPassword), 12);

    await client.query('BEGIN');
    await client.query(
      'UPDATE users SET password = $1, updated_at = NOW() WHERE id = $2',
      [pwdHash, rec.user_id]
    );
    await client.query(
      'UPDATE password_tokens SET used_at = NOW() WHERE id = $1',
      [rec.id]
    );
    await client.query('COMMIT');

    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error('set-password error', e);
    res.status(500).json({ message: 'Erro no servidor' });
  } finally {
    client.release();
  }
});

/* ============== Health & errors ============== */
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', env: process.env.NODE_ENV });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Internal server error' });
});

/* ============== Start ============== */
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

