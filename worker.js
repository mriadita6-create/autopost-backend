/**
 * AutoPost API — Cloudflare Worker + D1
 *
 * Required Worker binding:
 *   D1 database binding: DB -> autopost-db
 * Required secret:
 *   JWT_SECRET -> long random secret (set with `wrangler secret put JWT_SECRET`)
 *
 * Starter API. Social OAuth connection is included; automatic publishing still requires Page selection, publishing routes, and Meta app review/permissions.
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
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
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



const META_GRAPH_VERSION = "v23.0";
const APP_ORIGIN = "https://calm-lab-1394.mriadita6.workers.dev";
const CALLBACK_PATH = "/auth/facebook/callback";

function htmlPage(title, message, ok = false) {
  const safeTitle = String(title).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const safeMessage = String(message).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  return new Response(`<!doctype html><html lang="id"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${safeTitle}</title><body style="font:16px system-ui;background:#0b1020;color:#f4f6ff;padding:32px;max-width:620px;margin:10vh auto"><h1>${safeTitle}</h1><p>${safeMessage}</p><p>Silakan kembali ke AutoPost.</p></body></html>`, { status: ok ? 200 : 400, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

function base64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromBase64url(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4);
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
async function encryptionKey(secret) {
  const digest = await crypto.subtle.digest("SHA-256", utf8(secret));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function encryptToken(token, secret) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await encryptionKey(secret);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, utf8(token));
  return `enc1.${base64url(iv)}.${base64url(new Uint8Array(ciphertext))}`;
}
async function decryptToken(value, secret) {
  const [version, ivPart, dataPart] = String(value).split(".");
  if (version !== "enc1" || !ivPart || !dataPart) throw new Error("Format token terenkripsi tidak dikenal.");
  const key = await encryptionKey(secret);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64url(ivPart) }, key, fromBase64url(dataPart));
  return new TextDecoder().decode(plain);
}
function requiredMetaConfig(env) {
  return !!(env.META_APP_ID && env.META_APP_SECRET && env.TOKEN_ENCRYPTION_KEY);
}
async function graphGet(path, params = {}) {
  const u = new URL(`https://graph.facebook.com/${META_GRAPH_VERSION}/${path.replace(/^\//, "")}`);
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null) u.searchParams.set(k, String(v));
  const r = await fetch(u.toString());
  const data = await r.json().catch(() => ({}));
  if (!r.ok || data.error) throw new Error(data.error?.message || `Meta Graph API error (${r.status})`);
  return data;
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


    // Start Facebook OAuth. The frontend must call this with its logged-in JWT.
    if (request.method === "POST" && url.pathname === "/api/facebook/connect") {
      const payload = await verifyToken(getBearer(request) || "", env.JWT_SECRET);
      if (!payload) return json({ error: "Silakan login ke AutoPost terlebih dahulu." }, 401);
      if (!requiredMetaConfig(env)) return json({ error: "Konfigurasi Meta belum lengkap. Periksa META_APP_ID, META_APP_SECRET, dan TOKEN_ENCRYPTION_KEY di Worker Secrets/Variables." }, 500);
      const state = randomHex(32);
      const expiresAt = Math.floor(Date.now() / 1000) + 600;
      await env.DB.prepare("INSERT INTO oauth_states (state, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(state, payload.sub, expiresAt).run();
      const redirectUri = `https://${url.host}${CALLBACK_PATH}`;
      const auth = new URL("https://www.facebook.com/" + META_GRAPH_VERSION + "/dialog/oauth");
      auth.searchParams.set("client_id", env.META_APP_ID);
      auth.searchParams.set("redirect_uri", redirectUri);
      auth.searchParams.set("state", state);
      auth.searchParams.set("response_type", "code");
      auth.searchParams.set("scope", "public_profile,email");
      return json({ ok: true, authUrl: auth.toString(), expiresIn: 600 });
    }

    // Meta redirects here after the user approves or cancels.
    if (request.method === "GET" && url.pathname === CALLBACK_PATH) {
      if (!requiredMetaConfig(env)) return htmlPage("AutoPost: konfigurasi belum lengkap", "Admin perlu mengatur kredensial Meta dan kunci enkripsi di Cloudflare.");
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const oauthError = url.searchParams.get("error_description") || url.searchParams.get("error");
      if (oauthError) return htmlPage("Koneksi Facebook dibatalkan", oauthError);
      if (!code || !state) return htmlPage("Koneksi Facebook gagal", "Meta tidak mengirimkan kode atau state yang diperlukan.");
      const row = await env.DB.prepare("SELECT state, user_id, expires_at FROM oauth_states WHERE state = ?").bind(state).first();
      await env.DB.prepare("DELETE FROM oauth_states WHERE state = ?").bind(state).run();
      if (!row || Number(row.expires_at) < Math.floor(Date.now() / 1000)) return htmlPage("Koneksi kedaluwarsa", "Mulai proses Hubungkan Facebook lagi dari dashboard AutoPost.");
      const redirectUri = `https://${url.host}${CALLBACK_PATH}`;
      const tokenData = await graphGet("oauth/access_token", {
        client_id: env.META_APP_ID,
        client_secret: env.META_APP_SECRET,
        redirect_uri: redirectUri,
        code
      }).catch(() => null);
      if (!tokenData?.access_token) return htmlPage("Koneksi Facebook gagal", "Meta tidak memberikan access token. Periksa Redirect URI, App ID, App Secret, dan status aplikasi.");
      const me = await graphGet("me", { fields: "id,name", access_token: tokenData.access_token }).catch(() => null);
      if (!me?.id) return htmlPage("Koneksi Facebook gagal", "Token diterima tetapi identitas Facebook tidak dapat dibaca.");
      const encrypted = await encryptToken(tokenData.access_token, env.TOKEN_ENCRYPTION_KEY);
      const expiresAt = tokenData.expires_in ? new Date(Date.now() + Number(tokenData.expires_in) * 1000).toISOString() : null;
      await env.DB.prepare(`INSERT INTO social_accounts (user_id, platform, platform_user_id, access_token, token_expires_at)
        VALUES (?, 'facebook', ?, ?, ?)
        ON CONFLICT(user_id, platform, platform_user_id) DO UPDATE SET access_token = excluded.access_token, token_expires_at = excluded.token_expires_at`)
        .bind(row.user_id, String(me.id), encrypted, expiresAt).run();
      return htmlPage("Facebook berhasil terhubung", `Akun Facebook ${me.name || "Anda"} sudah tersimpan di AutoPost. Tahap berikutnya adalah memilih Page dan menyambungkan Instagram profesional.`, true);
    }

    // List connected platforms without ever returning access tokens to the browser.
    if (request.method === "GET" && url.pathname === "/api/social-accounts") {
      const payload = await verifyToken(getBearer(request) || "", env.JWT_SECRET);
      if (!payload) return json({ error: "Silakan login terlebih dahulu." }, 401);
      const result = await env.DB.prepare("SELECT id, platform, platform_user_id, token_expires_at, created_at FROM social_accounts WHERE user_id = ? ORDER BY created_at DESC")
        .bind(payload.sub).all();
      return json({ accounts: result.results || [] });
    }

    // Return Facebook Pages the user can manage. Page tokens are not exposed by this endpoint.
    if (request.method === "GET" && url.pathname === "/api/facebook/pages") {
      const payload = await verifyToken(getBearer(request) || "", env.JWT_SECRET);
      if (!payload) return json({ error: "Silakan login terlebih dahulu." }, 401);
      if (!env.TOKEN_ENCRYPTION_KEY) return json({ error: "TOKEN_ENCRYPTION_KEY belum diatur." }, 500);
      const account = await env.DB.prepare("SELECT access_token FROM social_accounts WHERE user_id = ? AND platform = 'facebook' ORDER BY created_at DESC LIMIT 1")
        .bind(payload.sub).first();
      if (!account) return json({ error: "Facebook belum terhubung." }, 404);
      try {
        const accessToken = await decryptToken(account.access_token, env.TOKEN_ENCRYPTION_KEY);
        const result = await graphGet("me/accounts", { fields: "id,name,instagram_business_account{id,username}", access_token: accessToken });
        return json({ pages: (result.data || []).map(p => ({ id: p.id, name: p.name, instagram: p.instagram_business_account ? { id: p.instagram_business_account.id, username: p.instagram_business_account.username || null } : null })) });
      } catch (e) {
        return json({ error: `Tidak bisa mengambil daftar Page: ${e.message}` }, 502);
      }
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
