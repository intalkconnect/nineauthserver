// index.js
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
  if (!origin) return true; // curl/postman
  let url; try { url = new URL(origin); } catch { return false; }
  const proto = url.protocol.toLowerCase();
  const host  = url.hostname.toLowerCase();
  const normalizedOrigin = normalizeOrigin(origin);
  if (proto !== 'http:' && proto !== 'https:') return false;

  for (const raw of ORIGIN_PATTERNS) {
    const pat = normalizeOrigin(raw);
    if (/^https?:\/\//i.test(pat)) { // origem exata
      if (normalizedOrigin === pat) return true;
      continue;
    }
    const base = pat.replace(/^\*\./, ''); // *.dkdevs.com.br -> dkdevs.com.br
    if (host === base || host.endsWith(`.${base}`)) return true;
  }
  return false;
}

const corsOptions = {
  origin: (origin, cb) => {
    if (isAllowedOrigin(origin)) cb(null, true);
    else {
      console.error('⛔ CORS bloqueado para origem:', origin);
      cb(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'CSRF-Token', 'csrf-token'],
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
  ssl: false, // ajuste se seu provedor exigir
});

/* ====================== Marca / Templates NineChat ====================== */
const BRAND = {
  name: 'NineChat',
  primary: '#635BFF',
  gradientFrom: '#6a61ff',
  gradientTo: '#2db6ff',
  text: '#111827',
  muted: '#6B7280',
  border: '#E5E7EB',
};

// Opções de logo:
// 1) arquivo local ao lado do index.js (padrão)
// 2) variável SMTP_LOGO_URL (https://...)
// 3) inline base64 (somente se LOGO_INLINE_BASE64 estiver setado)
const localLogoPath = path.join(__dirname, 'ninechat_logo_icons.png');
const SMTP_LOGO_URL = process.env.SMTP_LOGO_URL || '';

function prepareLogo() {
  const existsLocal = fs.existsSync(localLogoPath);
  const useInline = !!process.env.LOGO_INLINE_BASE64; // opcional
  if (useInline && existsLocal) {
    try {
      const buf = fs.readFileSync(localLogoPath);
      const b64 = buf.toString('base64');
      console.log('[MAIL:logo] usando inline base64 (local file).');
      return { mode: 'inline', tag: `<img src="data:image/png;base64,${b64}" width="64" height="64" alt="${BRAND.name}"/>`, attachments: undefined };
    } catch (e) {
      console.warn('[MAIL:logo] falha ao ler inline base64, caindo para CID/URL.', e.message);
    }
  }
  if (existsLocal) {
    console.log('[MAIL:logo] usando CID com arquivo local:', localLogoPath);
    return {
      mode: 'cid',
      tag: `<img src="cid:ninechat-logo" width="64" height="64" alt="${BRAND.name}"/>`,
      attachments: [{ filename: 'ninechat-logo.png', path: localLogoPath, cid: 'ninechat-logo' }]
    };
  }
  if (SMTP_LOGO_URL) {
    console.log('[MAIL:logo] arquivo local ausente. Usando URL:', SMTP_LOGO_URL);
    return { mode: 'url', tag: `<img src="${SMTP_LOGO_URL}" width="64" height="64" alt="${BRAND.name}"/>`, attachments: undefined };
  }
  console.warn('[MAIL:logo] sem arquivo local e sem SMTP_LOGO_URL — enviando sem imagem.');
  return { mode: 'none', tag: '', attachments: undefined };
}

function baseLayout({ preheader, bodyHtml, logoTag }) {
  // preheader escondido
  return `
  <html><body style="margin:0;padding:0;background:#F3F4F6;">
    <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">
      ${preheader || ''}
    </div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:24px 0;">
      <tr><td align="center">
        <table role="presentation" width="560" cellpadding="0" cellspacing="0"
               style="background:#fff;border:1px solid ${BRAND.border};border-radius:16px;overflow:hidden">
          <tr><td align="center" style="background:linear-gradient(135deg, ${BRAND.gradientFrom}, ${BRAND.gradientTo});padding:28px 24px">
            ${logoTag || ''}
            <div style="font:600 18px system-ui;color:#fff;margin-top:10px">${BRAND.name}</div>
          </td></tr>
          <tr><td style="padding:28px">
            ${bodyHtml}
          </td></tr>
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
    <p style="font:14px system-ui;color:${BRAND.muted};margin:0 0 16px">
      Sua conta foi criada. Defina sua senha clicando no botão abaixo. O link expira em 24 horas.
    </p>
    ${ctaButton({ href: link, label: 'Definir senha' })}
    <p style="font:12px system-ui;color:${BRAND.muted};margin:16px 0 0">Se você não solicitou, ignore este e-mail.</p>
  `;
  return { subject, html: baseLayout({ preheader, bodyHtml, logoTag }), attachments };
}

function renderResetEmail({ link }) {
  const { tag: logoTag, attachments } = prepareLogo();
  const subject = `Redefinição de senha — ${BRAND.name}`;
  const preheader = `Use o link para redefinir sua senha (30 min).`;
  const bodyHtml = `
    <h2 style="font:600 20px system-ui;color:${BRAND.text};margin:0 0 8px">Redefinir senha</h2>
    <p style="font:14px system-ui;color:${BRAND.muted};margin:0 0 16px">
      Recebemos um pedido para redefinir sua senha. Este link expira em 30 minutos.
    </p>
    ${ctaButton({ href: link, label: 'Criar nova senha' })}
    <p style="font:12px system-ui;color:${BRAND.muted};margin:16px 0 0">Se você não solicitou, ignore este e-mail.</p>
  `;
  return { subject, html: baseLayout({ preheader, bodyHtml, logoTag }), attachments };
}

/* ====================== E-mail (Nodemailer com debug/verify) ====================== */
const SMTP_FROM = process.env.SMTP_FROM || (process.env.SMTP_USER ? `"${BRAND.name}" <${process.env.SMTP_USER}>` : undefined);
if (!process.env.SMTP_HOST || !process.env.SMTP_PORT || !process.env.SMTP_USER) {
  console.warn('⚠️  Variáveis SMTP ausentes (SMTP_HOST/SMTP_PORT/SMTP_USER). Envio de e-mail pode falhar.');
}

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: Number(process.env.SMTP_PORT) === 465, // SMTPS
  auth: (process.env.SMTP_USER && process.env.SMTP_PASS) ? {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  } : undefined,
  logger: true,
  debug: true,
  tls: {
    minVersion: 'TLSv1.2',
    // rejectUnauthorized: false, // só se precisar
  },
});

transporter.verify((err) => {
  if (err) console.error('❌ SMTP verify falhou:', err);
  else console.log('✅ SMTP pronto para enviar (verify ok)');
});

async function sendMail({ to, subject, html, attachments }) {
  if (!SMTP_FROM) throw new Error('SMTP_FROM ausente');
  console.log(`[MAIL] -> to=${to} subject="${subject}" attachments=${attachments?.length || 0}`);
  const info = await transporter.sendMail({ from: SMTP_FROM, to, subject, html, attachments });
  console.log('[MAIL] accepted=%j rejected=%j response=%s id=%s',
    info.accepted, info.rejected, info.response || '', info.messageId);
  return info;
}

/* ====================== Utils & rate limit ====================== */
const now = () => new Date();
const minutes = n => n * 60 * 1000;
const hours   = n => n * 60 * 60 * 1000;

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false,
});
const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false,
});

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

    const match = await bcrypt.compare(String(password || ''), user.password || '');
    if (!match) {
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

    await pool.query(
      'UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE email = $1',
      [email]
    );

    // ===> A PARTIR DAQUI: gera token DE TENANT (não JWT) <===

    // 1) Obter tenant_id pelo slug do usuário (o guard usa public.tenants.subdomain)
    const t = await pool.query(
      'SELECT id FROM public.tenants WHERE subdomain = $1 LIMIT 1',
      [user.slug]
    );
    const tenantId = t.rows[0]?.id;
    if (!tenantId) {
      return res.status(404).json({ message: 'Tenant não encontrado para slug ' + user.slug });
    }

    // 2) Gerar id + secret plaintext e salvar secret_hash no banco
    const tokenId = uuidv4();                               // <uuid>
    const secret  = crypto.randomBytes(32).toString('hex'); // <hexsecret> (64 hex)
    const secretHash = await bcrypt.hash(secret, 10);

    await pool.query(
      `INSERT INTO public.tenant_tokens (id, tenant_id, secret_hash, status, is_default)
       VALUES ($1, $2, $3, 'active', false)`,
      [tokenId, tenantId, secretHash]
    );

    const bearerPlaintext = `${tokenId}.${secret}`; // o guard espera EXATAMENTE isso

    // 3) Setar cookie httpOnly com o plaintext (<uuid>.<hexsecret>)
    res.cookie('authToken', bearerPlaintext, {
      httpOnly: true,
      secure: true,                 // obrigatório com SameSite=None
      sameSite: 'None',             // cross-site: auth. -> {tenant}.
      domain: '.ninechat.com.br',   // vale para *.ninechat.com.br
      path: '/api',                 // só acompanha chamadas à API
      maxAge: rememberMe ? 7*24*60*60*1000 : 15*60*1000
    });

    // 4) Redireciono o front para o host do tenant (sem expor token)
    const baseUrl = tenantBaseUrl({ slug: user.slug, fallbackAccessUrl: user.access_url });
    // Se quiser manter o payload do response:
    res.json({
      ok: true,
      redirectUrl: baseUrl,
      user: { id: user.id, email: user.email, profile: user.profile }
      // IMPORTANTE: não retorne o token no JSON
    });

  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ message: 'Erro no servidor' });
  }
});


/* ====================== Logout ====================== */
app.post('/api/logout', (_req, res) => {
  res.clearCookie('authToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  res.json({ message: 'Logout realizado com sucesso' });
});

/* ====================== Forgot password ====================== */
app.post('/api/forgot-password', resetLimiter, async (req, res) => {
  try {
    const { email } = req.body || {};
    console.log('[forgot-password] origin=%s email=%s', req.headers.origin, email);
    if (!email) return res.status(200).json({ ok: true });

    const q = await pool.query(
      `SELECT u.id AS user_id, u.email, u.company_id, c.slug, c.access_url
         FROM users u
         JOIN companies c ON c.id = u.company_id
        WHERE u.email = $1`,
      [String(email).toLowerCase()]
    );
    const row = q.rows[0];
    if (!row) return res.status(200).json({ ok: true });

    const raw = crypto.randomBytes(32).toString('base64url');
    const hash = await bcrypt.hash(raw, 12);
    const tokenId = uuidv4();
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);

    await pool.query(
      `INSERT INTO password_tokens (id, user_id, company_id, type, token_hash, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [tokenId, row.user_id, row.company_id, 'reset', hash, expiresAt]
    );

    const tokenValue = `${tokenId}.${raw}`;
    const link = buildResetLink({ slug: row.slug, accessUrl: row.access_url, tokenValue });
    console.log('[forgot-password] reset link:', link);

    const tpl = renderResetEmail({ link });
    console.log('[forgot-password] template=reset attachments=%d', tpl.attachments?.length || 0);
    await sendMail({ to: row.email, subject: tpl.subject, html: tpl.html, attachments: tpl.attachments });

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('forgot-password error', e);
    return res.status(200).json({ ok: true }); // resposta neutra
  }
});

/* ====================== Invite (cria/garante user + e-mail) ====================== */
// body: { email, companySlug | companyId, profile? }
app.post('/api/invite', async (req, res) => {
  const { email, companySlug, companyId, profile } = req.body || {};
  if (!email || (!companySlug && !companyId)) {
    return res.status(400).json({ message: 'email e companySlug/companyId são obrigatórios' });
  }
  try {
    const comp = companyId
      ? await pool.query('SELECT id, slug, access_url FROM companies WHERE id=$1', [companyId])
      : await pool.query('SELECT id, slug, access_url FROM companies WHERE slug=$1', [companySlug]);
    const company = comp.rows[0];
    if (!company) return res.status(404).json({ message: 'Empresa não encontrada' });

    const lower = String(email).toLowerCase();
    const u = await pool.query(
      `INSERT INTO users (company_id, email, profile)
       VALUES ($1,$2,COALESCE($3,'user'))
       ON CONFLICT (company_id, email) DO UPDATE
         SET updated_at = NOW(),
             profile = COALESCE(EXCLUDED.profile, users.profile)
       RETURNING id, email, profile`,
      [company.id, lower, profile || null]
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

    const tokenValue = `${tokenId}.${raw}`;
    const link = buildResetLink({ slug: company.slug, accessUrl: company.access_url, tokenValue });
    console.log('[invite] invite link:', link);

    const tpl = renderInviteEmail({ link });
    console.log('[invite] template=invite attachments=%d', tpl.attachments?.length || 0);
    await sendMail({ to: user.email, subject: tpl.subject, html: tpl.html, attachments: tpl.attachments });

    res.json({ ok: true });
  } catch (e) {
    console.error('invite error', e);
    res.status(500).json({ message: 'Erro no servidor' });
  }
});

/* ====================== Set password ====================== */
// body: { token, newPassword }
app.post('/api/set-password', async (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword || String(newPassword).length < 8) {
    return res.status(400).json({ message: 'token e senha (mín. 8) são obrigatórios' });
  }

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
    if (!rec || rec.used_at || new Date(rec.expires_at) <= now()) {
      return res.status(400).json({ message: 'Token inválido ou expirado' });
    }

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

/* ====================== Health ====================== */
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', env: process.env.NODE_ENV });
});

/* ====================== Teste de e-mail ====================== */
// GET /api/test-mail?to=email@dominio
app.get('/api/test-mail', async (req, res) => {
  try {
    const to = String(req.query.to || '').trim();
    if (!to) return res.status(400).json({ message: 'Informe ?to=email@dominio' });

    const tokenValue = 'teste.token';
    const link = buildResetLink({ slug: 'hmg', accessUrl: '', tokenValue });

    const { subject, html, attachments } = renderInviteEmail({ link }); // usa o de boas-vindas
    const info = await sendMail({ to, subject: `[TESTE] ${subject}`, html, attachments });

    res.json({ ok: true, messageId: info.messageId, response: info.response || null });
  } catch (e) {
    console.error('test-mail error', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

/* ====================== Exclusão também em public.users ====================== */
/**
 * DELETE /api/users
 * body: { email, companySlug | companyId }
 * Remove o usuário da tabela "users" (public) pelo par (company_id, email).
 */
app.delete('/api/users', async (req, res) => {
  try {
    const { email, companySlug, companyId } = req.body || {};
    if (!email || (!companySlug && !companyId)) {
      return res.status(400).json({ message: 'email e companySlug/companyId são obrigatórios' });
    }
    const lower = String(email).toLowerCase();
    const comp = companyId
      ? await pool.query('SELECT id FROM companies WHERE id=$1', [companyId])
      : await pool.query('SELECT id FROM companies WHERE slug=$1', [companySlug]);
    const company = comp.rows[0];
    if (!company) return res.status(404).json({ message: 'Empresa não encontrada' });

    const del = await pool.query(
      'DELETE FROM users WHERE company_id=$1 AND email=$2',
      [company.id, lower]
    );
    console.log('[delete-user] company_id=%s email=%s rowCount=%s',
      company.id, lower, del.rowCount);

    res.json({ ok: true, deleted: del.rowCount });
  } catch (e) {
    console.error('delete-user error', e);
    res.status(500).json({ message: 'Erro ao excluir' });
  }
});

/* ====================== Error handler ====================== */
app.use((err, _req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Internal server error' });
});

/* ====================== Start ====================== */
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));


