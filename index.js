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

const app = express();

// 1. Configurações de Segurança
app.use(helmet());
app.use(cookieParser());

// Configuração detalhada do CORS
const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
      : [];

    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.error(`⛔ CORS bloqueado para origem: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'CSRF-Token'],
  exposedHeaders: ['CSRF-Token']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // para pré-flights (OPTIONS)


app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '10kb' }));

// 2. Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP'
});
app.use('/login', limiter);

// 3. Conexão com o Banco
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// 4. Endpoint CSRF Token
app.get('/api/csrf-token', (req, res) => {
  const csrfToken = crypto.randomBytes(32).toString('hex');
  res.cookie('XSRF-TOKEN', csrfToken, {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: false,
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
    maxAge: 86400000
  });
  res.json({ token: csrfToken });
});

// 5. Endpoint de Login
app.post('/api/login', async (req, res) => {
  const { email, password, csrfToken, rememberMe } = req.body;
  
  // Validação CSRF
  if (!csrfToken || csrfToken !== req.cookies['XSRF-TOKEN']) {
    return res.status(403).json({ message: 'Token CSRF inválido' });
  }

  try {
    const result = await pool.query(
      `SELECT u.id, u.email, u.password, u.profile, u.login_attempts, u.locked_until,
       c.access_url FROM users u JOIN companies c ON u.company_id = c.id WHERE u.email = $1`,
      [email.toLowerCase()]
    );

    const user = result.rows[0];
    
    if (!user) {
      await new Promise(resolve => setTimeout(resolve, 500));
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(403).json({ message: 'Conta temporariamente bloqueada' });
    }

    const match = await bcrypt.compare(password, user.password);
    
    if (!match) {
      await pool.query(
        `UPDATE users SET login_attempts = login_attempts + 1,
         locked_until = CASE WHEN login_attempts + 1 >= 5 THEN NOW() + INTERVAL '30 minutes' ELSE NULL END
         WHERE email = $1`, [email]
      );
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    await pool.query(
      'UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE email = $1',
      [email]
    );

    // Define a expiração do token baseado no "Lembrar-me"
    const tokenExpiration = rememberMe ? '7d' : '15m';
    const token = jwt.sign(
      { id: user.id, email: user.email, profile: user.profile },
      process.env.JWT_SECRET,
      { expiresIn: tokenExpiration }
    );

    // Configura o cookie de autenticação
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : undefined // 7 dias ou sessão
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

// 6. Health Checks
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', env: process.env.NODE_ENV });
});

// 7. Tratamento de Erros
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Internal server error' });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
