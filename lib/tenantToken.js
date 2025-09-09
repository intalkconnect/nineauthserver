// lib/tenantToken.js
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function mintTenantToken(tenantId, { isDefault = false } = {}) {
  const id = uuidv4();
  const secret = crypto.randomBytes(32).toString('hex'); // 64 hex chars
  const hash = await bcrypt.hash(secret, 10);

  await pool.query(
    `INSERT INTO public.tenant_tokens (id, tenant_id, secret_hash, status, is_default)
     VALUES ($1, $2, $3, 'active', $4)`,
    [id, tenantId, hash, isDefault]
  );

  // plaintext para cookie: <uuid>.<hexsecret>
  return { bearer: `${id}.${secret}`, id, secret };
}
