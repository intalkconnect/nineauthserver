// mail/templates.js
const path = require('path');

// Anexo (CID) da logo — use o PNG quadrado enviado por você
function logoAttachment() {
  return [{
    filename: 'ninechat-logo.png',
    path: path.join(__dirname, 'assets/ninechat_logo_icons.png'), // ajuste o path
    cid: 'ninechat-logo' // << cid usado no <img>
  }];
}

const BRAND = {
  name: 'NineChat',
  primary: '#635BFF',        // roxo
  gradientFrom: '#6a61ff',
  gradientTo:   '#2db6ff',
  text: '#111827',
  muted: '#6B7280',
  border: '#E5E7EB',
};

function baseLayout({ title, preheader, bodyHtml }) {
  // estilos inline por compatibilidade máxima
  return `
<!doctype html>
<html lang="pt-BR">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="x-apple-disable-message-reformatting"/>
<title>${title}</title>
<style>
@media (prefers-color-scheme: dark) {
  .nc-card { background:#0b0f1a !important; }
  .nc-text { color:#e5e7eb !important; }
  .nc-muted { color:#9ca3af !important; }
  .nc-border { border-color:#1f2937 !important; }
  .nc-btn { color:#ffffff !important; }
}
</style>
</head>
<body style="margin:0;padding:0;background:#F3F4F6;">
  <!-- Preheader: escondido nos clients -->
  <div style="display:none;opacity:0;visibility:hidden;height:0;width:0;overflow:hidden;">
    ${preheader}
  </div>

  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F3F4F6;padding:24px 0;">
    <tr>
      <td align="center">
        <table role="presentation" class="nc-card" width="560" cellpadding="0" cellspacing="0"
               style="width:560px;max-width:560px;background:#FFFFFF;border:1px solid ${BRAND.border};
                      border-radius:16px;overflow:hidden;">
          <tr>
            <td align="center" style="background:linear-gradient(135deg, ${BRAND.gradientFrom}, ${BRAND.gradientTo});padding:28px 24px;">
              <img src="cid:ninechat-logo" width="64" height="64" alt="${BRAND.name}" style="display:block;border-radius:14px;border:0;"/>
              <div style="height:10px;"></div>
              <div style="font:600 18px system-ui, -apple-system, Segoe UI, Roboto, sans-serif;color:#fff;">
                ${BRAND.name}
              </div>
            </td>
          </tr>
          <tr>
            <td style="padding:28px 28px 8px 28px;">
              ${bodyHtml}
            </td>
          </tr>
          <tr>
            <td style="padding:8px 28px 28px 28px;">
              <table role="presentation" width="100%" class="nc-border" style="border-top:1px solid ${BRAND.border};">
                <tr><td style="height:18px;"></td></tr>
                <tr>
                  <td class="nc-muted" style="font:400 12px system-ui, -apple-system, Segoe UI, Roboto, sans-serif; color:${BRAND.muted};">
                    Se você não solicitou este e-mail, apenas ignore.  
                    © ${new Date().getFullYear()} ${BRAND.name}. Todos os direitos reservados.
                  </td>
                </tr>
                <tr><td style="height:8px;"></td></tr>
              </table>
            </td>
          </tr>
        </table>
        <div style="height:24px;"></div>
      </td>
    </tr>
  </table>
</body>
</html>
  `.trim();
}

// Botão “bulletproof”
function ctaButton({ href, label }) {
  return `
  <table role="presentation" cellspacing="0" cellpadding="0">
    <tr>
      <td align="center" bgcolor="${BRAND.primary}"
          style="border-radius:10px;">
        <a href="${href}"
           style="display:inline-block;padding:12px 20px;border-radius:10px;
                  font:600 15px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
                  color:#fff;text-decoration:none;background:${BRAND.primary}">
           ${label}
        </a>
      </td>
    </tr>
  </table>`;
}

/** === BOAS-VINDAS / CONVITE === */
function renderInviteEmail({ recipientName, link }) {
  const subject = `Boas-vindas ao ${BRAND.name} — defina sua senha`;
  const preheader = `Sua conta no ${BRAND.name} foi criada. Conclua configurando a senha.`;

  const bodyHtml = `
  <div class="nc-text" style="font:600 20px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:${BRAND.text};">
    Bem-vindo${recipientName ? `, ${recipientName}` : ''}!
  </div>
  <div style="height:6px;"></div>
  <div class="nc-muted" style="font:400 14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:${BRAND.muted}">
    Sua conta no <b>${BRAND.name}</b> foi criada. Para começar, defina sua senha clicando no botão abaixo.
    Este link expira em <b>24 horas</b>.
  </div>
  <div style="height:18px;"></div>
  ${ctaButton({ href: link, label: 'Definir senha' })}
  <div style="height:16px;"></div>
  <div class="nc-muted" style="font:400 12px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:${BRAND.muted}">
    Se o botão não funcionar, copie e cole esta URL no navegador:<br/>
    <span style="word-break:break-all;color:#4B5563">${link}</span>
  </div>
  `;

  const html = baseLayout({ title: subject, preheader, bodyHtml });
  const text = [
    `Boas-vindas ao ${BRAND.name}!`,
    recipientName ? `Olá, ${recipientName}.` : '',
    `Sua conta foi criada. Defina sua senha (expira em 24h):`,
    link,
    `Se você não solicitou, ignore este e-mail.`
  ].filter(Boolean).join('\n\n');

  return { subject, html, text, attachments: logoAttachment() };
}

/** === REDEFINIÇÃO DE SENHA === */
function renderResetEmail({ recipientName, link }) {
  const subject = `Redefinição de senha — ${BRAND.name}`;
  const preheader = `Use o link para redefinir sua senha. Ele expira em 30 minutos.`;

  const bodyHtml = `
  <div class="nc-text" style="font:600 20px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:${BRAND.text};">
    Redefinir senha
  </div>
  <div style="height:6px;"></div>
  <div class="nc-muted" style="font:400 14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:${BRAND.muted}">
    ${recipientName ? `Olá, <b>${recipientName}</b>!<br/>` : ''}
    Recebemos um pedido para redefinir sua senha no <b>${BRAND.name}</b>.
    O link abaixo expira em <b>30 minutos</b>.
  </div>
  <div style="height:18px;"></div>
  ${ctaButton({ href: link, label: 'Criar nova senha' })}
  <div style="height:16px;"></div>
  <div class="nc-muted" style="font:400 12px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:${BRAND.muted}">
    Caso não tenha solicitado, você pode ignorar este e-mail com segurança.
  </div>
  <div style="height:10px;"></div>
  <div class="nc-muted" style="font:400 12px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:${BRAND.muted}">
    Link direto:<br/>
    <span style="word-break:break-all;color:#4B5563">${link}</span>
  </div>
  `;

  const html = baseLayout({ title: subject, preheader, bodyHtml });
  const text = [
    `Redefinição de senha — ${BRAND.name}`,
    recipientName ? `Olá, ${recipientName}.` : '',
    `Use o link (expira em 30 minutos):`,
    link,
    `Se você não solicitou, ignore este e-mail.`
  ].filter(Boolean).join('\n\n');

  return { subject, html, text, attachments: logoAttachment() };
}

module.exports = {
  renderInviteEmail,
  renderResetEmail,
  logoAttachment
};
