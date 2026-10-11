/**
 * AutoPost API — Cloudflare Worker + D1
 *
 * Required Worker binding:
 *   D1 database binding: DB -> autopost-db
 * Required secret:
 *   JWT_SECRET -> long random secret (set with `wrangler secret put JWT_SECRET`)
 *
 * This is a starter API, not a complete production payment integration.
 * Do not store plain-text passwords or activation codes.
 */

const corsHeaders = {
  "Access-Control-Allow-Origin": "*", // Replace with your exact site origin before production.
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json; charset=utf-8",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: corsHeaders });
}
function getBearer(request) {
  const h = request.headers.get("Authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}
function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function utf8(s) { return new TextEncoder().encode(s); }
async function sha256Hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", utf8(s));
  return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, "0")).join("");
}
async function derivePassword(password, saltHex) {
  const salt = Uint8Array.from(saltHex.match(/.{2}/g), b => parseInt(b, 16));
  const key = await crypto.subtle.importKey("raw", utf8(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 210000, hash: "SHA-256" }, key, 256);
  return [...new Uint8Array(bits)].map(x => x.toString(16).padStart(2, "0")).join("");
}
function randomHex(n = 16) {
  return [...crypto.getRandomValues(new Uint8Array(n))].map(x => x.toString(16).padStart(2, "0")).join("");
}
async function signToken(payload, secret) {
  const header = b64url(utf8(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = b64url(utf8(JSON.stringify(payload)));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey("raw", utf8(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, utf8(data));
  return `${data}.${b64url(new Uint8Array(sig))}`;
}
async function verifyToken(token, secret) {
  try {
    const [header, body, signature] = token.split(".");
    if (!header || !body || !signature) return null;
    const data = `${header}.${body}`;
    const key = await crypto.subtle.importKey("raw", utf8(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const sig = Uint8Array.from(atob(signature.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - signature.length % 4) % 4)), c => c.charCodeAt(0));
    if (!await crypto.subtle.verify("HMAC", key, sig, utf8(data))) return null;
    const payload = JSON.parse(atob(body.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - body.length % 4) % 4)));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}
async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}
function validEmail(email) {
  return typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
    const url = new URL(request.url);
    if (!env.DB) return json({ error: "D1 binding DB belum diatur." }, 500);
    if (!env.JWT_SECRET) return json({ error: "Secret JWT_SECRET belum diatur." }, 500);

    if (request.method === "GET" && url.pathname === "/") {
      return json({ name: "AutoPost API", status: "online", version: 1 });
    }

    if (request.method === "POST" && url.pathname === "/api/register") {
      const data = await readJson(request);
      if (!data || !validEmail(data.email) || typeof data.password !== "string" || data.password.length < 10 || data.password.length > 128) {
        return json({ error: "Masukkan email valid dan kata sandi 10–128 karakter." }, 400);
      }
      const email = data.email.trim().toLowerCase();
      const salt = randomHex(16);
      const hash = await derivePassword(data.password, salt);
      try {
        const result = await env.DB.prepare(
          "INSERT INTO users (email, password_hash) VALUES (?, ?)"
        ).bind(email, `${salt}:${hash}`).run();
        return json({ ok: true, userId: result.meta.last_row_id, message: "Akun berhasil dibuat. Silakan login." }, 201);
      } catch {
        return json({ error: "Email sudah terdaftar atau akun tidak dapat dibuat." }, 409);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/login") {
      const data = await readJson(request);
      if (!data || !validEmail(data.email) || typeof data.password !== "string") return json({ error: "Email atau kata sandi tidak valid." }, 400);
      const row = await env.DB.prepare("SELECT id, email, password_hash FROM users WHERE email = ?").bind(data.email.trim().toLowerCase()).first();
      if (!row || !row.password_hash || !row.password_hash.includes(":")) return json({ error: "Email atau kata sandi salah." }, 401);
      const [salt, stored] = row.password_hash.split(":");
      const candidate = await derivePassword(data.password, salt);
      if (candidate !== stored) return json({ error: "Email atau kata sandi salah." }, 401);
      const now = Math.floor(Date.now() / 1000);
      const token = await signToken({ sub: row.id, email: row.email, iat: now, exp: now + 60 * 60 * 24 * 7 }, env.JWT_SECRET);
      return json({ ok: true, token, user: { id: row.id, email: row.email }, tokenExpiresIn: 604800 });
    }

    if (request.method === "GET" && url.pathname === "/api/me") {
      const payload = await verifyToken(getBearer(request) || "", env.JWT_SECRET);
      if (!payload) return json({ error: "Token tidak valid atau sudah kedaluwarsa." }, 401);
      const sub = await env.DB.prepare(
        "SELECT plan, starts_at, expires_at, status FROM subscriptions WHERE user_id = ? AND status = 'active' ORDER BY expires_at DESC LIMIT 1"
      ).bind(payload.sub).first();
      const active = !!sub && Date.parse(sub.expires_at) > Date.now();
      return json({ user: { id: payload.sub, email: payload.email }, subscription: active ? sub : null });
    }

    if (request.method === "POST" && url.pathname === "/api/redeem") {
      const payload = await verifyToken(getBearer(request) || "", env.JWT_SECRET);
      if (!payload) return json({ error: "Silakan login terlebih dahulu." }, 401);
      const data = await readJson(request);
      if (!data || typeof data.code !== "string" || data.code.length < 8 || data.code.length > 100) return json({ error: "Kode aktivasi tidak valid." }, 400);
      const codeHash = await sha256Hex(data.code.trim().toUpperCase());
      const code = await env.DB.prepare(
        "SELECT id, plan, expires_at, redeemed_at FROM activation_codes WHERE code_hash = ?"
      ).bind(codeHash).first();
      if (!code || code.redeemed_at || Date.parse(code.expires_at) <= Date.now()) return json({ error: "Kode tidak valid, kedaluwarsa, atau sudah digunakan." }, 400);
      const days = code.plan === "starter" ? 7 : code.plan === "pro" ? 30 : 90;
      const now = new Date();
      const current = await env.DB.prepare(
        "SELECT expires_at FROM subscriptions WHERE user_id = ? AND status = 'active' ORDER BY expires_at DESC LIMIT 1"
      ).bind(payload.sub).first();
      const start = current && Date.parse(current.expires_at) > now.getTime() ? new Date(current.expires_at) : now;
      const end = new Date(start.getTime() + days * 86400000);
      // Batch makes the single-use claim and subscription insertion atomic.
      const claim = await env.DB.prepare(
        "UPDATE activation_codes SET redeemed_at = CURRENT_TIMESTAMP WHERE id = ? AND redeemed_at IS NULL AND expires_at > CURRENT_TIMESTAMP"
      ).bind(code.id);
      const result = await env.DB.batch([
        claim,
        env.DB.prepare("INSERT INTO subscriptions (user_id, plan, starts_at, expires_at, status) VALUES (?, ?, ?, ?, 'active')")
          .bind(payload.sub, code.plan, start.toISOString(), end.toISOString())
      ]);
      if (!result[0].meta.changes) return json({ error: "Kode sudah digunakan." }, 409);
      return json({ ok: true, plan: code.plan, startsAt: start.toISOString(), expiresAt: end.toISOString() });
    }

    return json({ error: "Endpoint tidak ditemukan." }, 404);
  }
};
