// index.js (AUTH)
require('dotenv').config();
const path = require('path');
const fs = require('fs');
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

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET ausente (AUTH). Configure a MESMA chave no ENDPOINTS.');
}

const app = express();
app.set('trust proxy', 1);

/* ====================== Segurança & Body ====================== */
app.use(helmet());
app.use(cookieParser());
app.use(express.json({ limit: '10kb' }));

/* ====================== CORS (wildcards via .env) ====================== */
const RAW_PATTERNS =
  process.env.ALLOWED_ORIGIN_PATTERNS ||
  process.env.ALLOWED_ORIGINS || '';
const ORIGIN_PATTERNS = RAW_PATTERNS.split(',').map(s => s.trim()).filter(Boolean);
console.log('[CORS] patterns:', ORIGIN_PATTERNS);

function normalizeOrigin(s) { return String(s || '').replace(/\/+$/, '').toLowerCase(); }
function isAllowedOrigin(origin) {
  if (!origin) return true;
  let url; try { url = new URL(origin); } catch { return false; }
  const proto = url.protocol.toLowerCase();
  const host  = url.hostname.toLowerCase();
  const normalizedOrigin = normalizeOrigin(origin);
  if (proto !== 'http:' && proto !== 'https:') return false;

  for (const raw of ORIGIN_PATTERNS) {
    const pat = normalizeOrigin(raw);
    if (/^https?:\/\//i.test(pat)) {
      if (normalizedOrigin === pat) return true;
      continue;
    }
    const base = pat.replace(/^\*\./, '');
    if (host === base || host.endsWith(`.${base}`)) return true;
  }
  return false;
}
const corsOptions = {
  origin: (origin, cb) => isAllowedOrigin(origin) ? cb(null, true) : cb(new Error('Not allowed by CORS')),
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'CSRF-Token', 'csrf-token', 'Cache-Control', 'Pragma', 'Authorization'],
  exposedHeaders: ['CSRF-Token'],
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

/* ====================== Banco ====================== */
if (!process.env.DATABASE_URL) {
  console.warn('⚠️  DATABASE_URL não definido. Rotas que usam DB vão falhar.');
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false,
});

/* ====================== Marca / Templates ====================== */
const BRAND = {
  name: 'NineChat',
  primary: '#635BFF',
  gradientFrom: '#6a61ff',
  gradientTo: '#2db6ff',
  text: '#111827',
  muted: '#6B7280',
  border: '#E5E7EB',
};
const localLogoPath = path.join(__dirname, 'ninechat_logo_icons.png');
const SMTP_LOGO_URL = process.env.SMTP_LOGO_URL || '';

function prepareLogo() {
  const existsLocal = fs.existsSync(localLogoPath);
  const useInline = !!process.env.LOGO_INLINE_BASE64;
  if (useInline && existsLocal) {
    try {
      const buf = fs.readFileSync(localLogoPath);
      const b64 = buf.toString('base64');
      return { mode: 'inline', tag: `<img src="data:image/png;base64,${b64}" width="64" height="64" alt="${BRAND.name}"/>`, attachments: undefined };
    } catch (e) { /* fallthrough */ }
  }
  if (existsLocal) {
    return {
      mode: 'cid',
      tag: `<img src="cid:ninechat-logo" width="64" height="64" alt="${BRAND.name}"/>`,
      attachments: [{ filename: 'ninechat-logo.png', path: localLogoPath, cid: 'ninechat-logo' }]
    };
  }
  if (SMTP_LOGO_URL) {
    return { mode: 'url', tag: `<img src="${SMTP_LOGO_URL}" width="64" height="64" alt="${BRAND.name}"/>`, attachments: undefined };
  }
  return { mode: 'none', tag: '', attachments: undefined };
}
function baseLayout({ preheader, bodyHtml, logoTag }) {
  return `
  <html><body style="margin:0;padding:0;background:#F3F4F6;">
    <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">${preheader || ''}</div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:24px 0;">
      <tr><td align="center">
        <table role="presentation" width="560" cellpadding="0" cellspacing="0"
               style="background:#fff;border:1px solid ${BRAND.border};border-radius:16px;overflow:hidden">
          <tr><td align="center" style="background:linear-gradient(135deg, ${BRAND.gradientFrom}, ${BRAND.gradientTo});padding:28px 24px">
            ${logoTag || ''}<div style="font:600 18px system-ui;color:#fff;margin-top:10px">${BRAND.name}</div>
          </td></tr>
          <tr><td style="padding:28px">${bodyHtml}</td></tr>
          <tr><td style="padding:12px 28px 28px;border-top:1px solid ${BRAND.border};color:${BRAND.muted};font:12px system-ui">
            © ${new Date().getFullYear()} ${BRAND.name}. Todos os direitos reservados.
          </td></tr>
        </table>
      </td></tr>
    </table>
  </body></html>`;
}
function ctaButton({ href, label }) {
  return `<a href="${href}" style="display:inline-block;padding:12px 20px;border-radius:10px;background:${BRAND.primary};color:#fff;font:600 15px system-ui;text-decoration:none">${label}</a>`;
}
function renderInviteEmail({ link }) {
  const { tag: logoTag, attachments } = prepareLogo();
  const subject = `Boas-vindas ao ${BRAND.name} — defina sua senha`;
  const preheader = `Sua conta no ${BRAND.name} foi criada.`;
  const bodyHtml = `
    <h2 style="font:600 20px system-ui;color:${BRAND.text};margin:0 0 8px">Bem-vindo!</h2>
    <p style="font:14px system-ui;color:${BRAND.muted};margin:0 0 16px">Sua conta foi criada. Defina sua senha clicando no botão abaixo. O link expira em 24 horas.</p>
    ${ctaButton({ href: link, label: 'Definir senha' })}
    <p style="font:12px system-ui;color:${BRAND.muted};margin:16px 0 0">Se você não solicitou, ignore este e-mail.</p>`;
  return { subject, html: baseLayout({ preheader, bodyHtml, logoTag }), attachments };
}
function renderResetEmail({ link }) {
  const { tag: logoTag, attachments } = prepareLogo();
  const subject = `Redefinição de senha — ${BRAND.name}`;
  const preheader = `Use o link para redefinir sua senha (30 min).`;
  const bodyHtml = `
    <h2 style="font:600 20px system-ui;color:${BRAND.text};margin:0 0 8px">Redefinir senha</h2>
    <p style="font:14px system-ui;color:${BRAND.muted};margin:0 0 16px">Recebemos um pedido para redefinir sua senha. Este link expira em 30 minutos.</p>
    ${ctaButton({ href: link, label: 'Criar nova senha' })}
    <p style="font:12px system-ui;color:${BRAND.muted};margin:16px 0 0">Se você não solicitou, ignore este e-mail.</p>`;
  return { subject, html: baseLayout({ preheader, bodyHtml, logoTag }), attachments };
}

/* ====================== E-mail ====================== */
const SMTP_FROM = process.env.SMTP_FROM || (process.env.SMTP_USER ? `"${BRAND.name}" <${process.env.SMTP_USER}>` : undefined);
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: Number(process.env.SMTP_PORT) === 465,
  auth: (process.env.SMTP_USER && process.env.SMTP_PASS) ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  logger: true,
  debug: true,
  tls: { minVersion: 'TLSv1.2' },
});
transporter.verify((err) => {
  if (err) console.error('❌ SMTP verify falhou:', err);
  else console.log('✅ SMTP pronto (verify ok)');
});
async function sendMail({ to, subject, html, attachments }) {
  if (!SMTP_FROM) throw new Error('SMTP_FROM ausente');
  const info = await transporter.sendMail({ from: SMTP_FROM, to, subject, html, attachments });
  return info;
}

/* ====================== Utils & rate limit ====================== */
const now = () => new Date();
const hours = n => n * 60 * 60 * 1000;
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
const resetLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });

/* ====================== Helpers de URL ====================== */
function tenantBaseUrl({ slug, fallbackAccessUrl }) {
  const base = process.env.TENANT_DOMAIN_BASE;
  if (base) return `https://${slug}.${base}`;
  return String(fallbackAccessUrl || '').replace(/\/+$/, '');
}
function buildResetLink({ slug, accessUrl, tokenValue }) {
  const resetBase = (process.env.RESET_BASE_URL || '').replace(/\/+$/, '');
  if (resetBase) return `https://${resetBase}/auth/set-password?token=${encodeURIComponent(tokenValue)}`;
  return `${tenantBaseUrl({ slug, fallbackAccessUrl: accessUrl })}/auth/set-password?token=${encodeURIComponent(tokenValue)}`;
}

/* ====================== CSRF ====================== */
app.get('/api/csrf-token', (req, res) => {
  const csrfToken = crypto.randomBytes(32).toString('hex');
  res.cookie('XSRF-TOKEN', csrfToken, {
    secure: (process.env.CSRF_COOKIE_SECURE || 'true') !== 'false',
    httpOnly: false,
    sameSite: 'None',
    maxAge: 24 * 60 * 60 * 1000,
  });
  res.json({ token: csrfToken });
});

/* ====================== LOGIN ====================== */
app.post('/api/login', loginLimiter, async (req, res) => {
  const { email, password, rememberMe } = req.body || {};
  const csrfHeader = req.headers['csrf-token'];
  if (!csrfHeader || csrfHeader !== req.cookies['XSRF-TOKEN']) {
    return res.status(403).json({ message: 'Token CSRF inválido' });
  }
  try {
    const result = await pool.query(
      `SELECT u.id, u.email, u.password, u.profile, u.login_attempts, u.locked_until,
              c.slug, c.access_url
         FROM users u
         JOIN companies c ON u.company_id = c.id
        WHERE u.email = $1`,
      [String(email || '').toLowerCase()]
    );
    const user = result.rows[0];
    if (!user) {
      await new Promise(r => setTimeout(r, 400));
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(403).json({ message: 'Conta temporariamente bloqueada' });
    }
    const ok = await bcrypt.compare(String(password || ''), user.password || '');
    if (!ok) {
      await pool.query(
        `UPDATE users
            SET login_attempts = login_attempts + 1,
                locked_until = CASE WHEN login_attempts + 1 >= 5
                                    THEN NOW() + INTERVAL '30 minutes' ELSE NULL END
          WHERE email = $1`,
        [email]
      );
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    await pool.query('UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE email = $1', [email]);

    // JWT "antigo" (compatível com seu front)
   const tokenExpiration = rememberMe ? '7d' : '15m';
   const tokenPayload = {
   id: user.id,
   email: user.email,
   profile: user.profile,
   slug: user.slug,         // <- ajuda no whoami
   persist: !!rememberMe    // <- para sessão "rolling"
   };
   const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: tokenExpiration });

    // Cookie httpOnly (não interfere, só mantém sessão)
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      path: '/',
      maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : undefined
    });

    // Descobre token default do tenant (via tenants.subdomain OU companies.slug)
    let defaultTokenId = null;
    try {
      const q1 = await pool.query(
        `SELECT t.id
           FROM public.tenants tn
           JOIN public.tenant_tokens t ON t.tenant_id = tn.id
          WHERE tn.subdomain = $1
            AND t.is_default = true
            AND t.status = 'active'
          LIMIT 1`,
        [user.slug]
      );
      defaultTokenId = q1.rows[0]?.id || null;
    } catch {}
    if (!defaultTokenId) {
      const q2 = await pool.query(
        `SELECT t.id
           FROM public.companies c
           JOIN public.tenant_tokens t ON t.tenant_id = c.id
          WHERE c.slug = $1
            AND t.is_default = true
            AND t.status = 'active'
          LIMIT 1`,
        [user.slug]
      );
      defaultTokenId = q2.rows[0]?.id || null;
    }

    // Emite o "assert" (NÃO expõe secret); o ENDPOINTS valida is_default + active
    if (defaultTokenId) {
      const defaultAssert = jwt.sign(
        { typ: 'default-assert', tenant: user.slug, tokenId: defaultTokenId },
        JWT_SECRET,
        { expiresIn: rememberMe ? '7d' : '15m' }
      );
      res.cookie('defaultAssert', defaultAssert, {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        domain: '.ninechat.com.br',
        path: '/api',
        maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 15 * 60 * 1000
      });
    }

    const baseUrl = tenantBaseUrl({ slug: user.slug, fallbackAccessUrl: user.access_url });
    const redirectUrl = `${baseUrl}?token=${encodeURIComponent(token)}`;
    res.setHeader('X-Redirect-To', redirectUrl);
    return res.json({ token, redirectUrl, user: { id: user.id, email: user.email, profile: user.profile } });
  } catch (err) {
    console.error('Erro no login:', err);
    return res.status(500).json({ message: 'Erro no servidor' });
  }
});

app.get('/api/whoami', async (req, res) => {
  const raw = req.cookies?.authToken;
  if (!raw) return res.status(401).json({ authenticated: false });

  try {
    const payload = jwt.verify(raw, JWT_SECRET);
    let { id, email, profile, slug, persist } = payload || {};
    let accessUrl;

    // Busca slug/access_url se não estiverem no token
    if (!slug) {
      try {
        const r = await pool.query(
          `SELECT c.slug, c.access_url
             FROM users u
             JOIN companies c ON u.company_id = c.id
            WHERE u.id = $1
            LIMIT 1`,
          [id]
        );
        slug = r.rows[0]?.slug || slug;
        accessUrl = r.rows[0]?.access_url || accessUrl;
      } catch (_) {}
    }

    const baseUrl = tenantBaseUrl({ slug, fallbackAccessUrl: accessUrl }) || 'https://portal.ninechat.com.br';

    // (Opcional) sessão rolling para “manter conectado”
    let tokenForUrl = raw;
    if (persist) {
      const nowSec = Math.floor(Date.now() / 1000);
      const timeLeft = (payload.exp || 0) - nowSec;
      const THREE_DAYS = 3 * 24 * 60 * 60;
      if (timeLeft > 0 && timeLeft < THREE_DAYS) {
        tokenForUrl = jwt.sign(
          { id, email, profile, slug, persist: true },
          JWT_SECRET,
          { expiresIn: '7d' }
        );
        res.cookie('authToken', tokenForUrl, {
          httpOnly: true,
          secure: true,
          sameSite: 'None',         // cross-site
          maxAge: 7 * 24 * 60 * 60 * 1000
        });
      }
    }

    // IMPORTANTE: incluir ?token= na URL de redirecionamento
    const redirectUrl = `${baseUrl}${baseUrl.includes('?') ? '&' : '?'}token=${encodeURIComponent(tokenForUrl)}`;

    res.set('Cache-Control', 'no-store');
    return res.json({
      authenticated: true,
      user: { id, email, profile },
      redirectUrl
    });
  } catch {
    return res.status(401).json({ authenticated: false });
  }
});



/* ====================== Logout ====================== */
app.post('/api/logout', (_req, res) => {
  // limpa sessão do AUTH (host-only)
  res.clearCookie('authToken', {
    httpOnly: true,
    secure: true,
    sameSite: 'None',
    path: '/',           // precisa bater com o set
  });

  // limpa o cookie multi-subdomínio usado pelos ENDPOINTS
  res.clearCookie('defaultAssert', {
    httpOnly: true,
    secure: true,
    sameSite: 'None',
    domain: '.ninechat.com.br',
    path: '/api',
  });

  res.set('Cache-Control', 'no-store');
  // 204 = sem body; evita CORS/JSON desnecessário
  return res.status(204).end();
});


/* ====================== Forgot/Invite/Set-password/Health/etc. (inalteradas) ====================== */
// ... (copie suas rotas de forgot/invite/set-password/test-mail/delete-user/health exatamente como já estão)

/* ====================== Start ====================== */
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`AUTH running on port ${PORT}`));




