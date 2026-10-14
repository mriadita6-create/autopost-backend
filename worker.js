/**
 * AutoPost API — Cloudflare Worker + D1 + Midtrans
 * Mode pembayaran: SANDBOX
 */

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json; charset=utf-8",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders
  });
}

function getBearer(request) {
  const h = request.headers.get("Authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}

function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function utf8(s) {
  return new TextEncoder().encode(s);
}

async function sha256Hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", utf8(s));
  return [...new Uint8Array(buf)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function derivePassword(password, saltHex) {
  const salt = Uint8Array.from(
    saltHex.match(/.{2}/g),
    b => parseInt(b, 16)
  );

  const key = await crypto.subtle.importKey(
    "raw",
    utf8(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 210000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return [...new Uint8Array(bits)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function randomHex(n = 16) {
  return [...crypto.getRandomValues(new Uint8Array(n))]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function signToken(payload, secret) {
  const header = b64url(
    utf8(JSON.stringify({ alg: "HS256", typ: "JWT" }))
  );

  const body = b64url(utf8(JSON.stringify(payload)));
  const data = `${header}.${body}`;

  const key = await crypto.subtle.importKey(
    "raw",
    utf8(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    utf8(data)
  );

  return `${data}.${b64url(new Uint8Array(sig))}`;
}

async function verifyToken(token, secret) {
  try {
    const [header, body, signature] = token.split(".");
    if (!header || !body || !signature) return null;

    const data = `${header}.${body}`;

    const key = await crypto.subtle.importKey(
      "raw",
      utf8(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const sig = Uint8Array.from(
      atob(
        signature.replace(/-/g, "+").replace(/_/g, "/") +
        "=".repeat((4 - signature.length % 4) % 4)
      ),
      c => c.charCodeAt(0)
    );

    if (!await crypto.subtle.verify(
      "HMAC",
      key,
      sig,
      utf8(data)
    )) {
      return null;
    }

    const payload = JSON.parse(
      atob(
        body.replace(/-/g, "+").replace(/_/g, "/") +
        "=".repeat((4 - body.length % 4) % 4)
      )
    );

    if (payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function validEmail(email) {
  return typeof email === "string" &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function encryptToken(token, secret) {
  const keyBytes = await crypto.subtle.digest(
    "SHA-256",
    utf8(secret)
  );

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    utf8(token)
  );

  return `${b64url(iv)}.${b64url(new Uint8Array(ciphertext))}`;
}

function htmlPage(title, message, status = 200) {
  return new Response(
    `<!doctype html>
    <html lang="id">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${title}</title>
    <body style="font-family:system-ui;max-width:640px;margin:48px auto;padding:20px">
    <h2>${title}</h2>
    <p>${message}</p>
    <p>Kamu boleh menutup halaman ini dan kembali ke AutoPost.</p>
    </body></html>`,
    {
      status,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store"
      }
    }
  );
}

const PLANS = {
  starter: {
    name: "AutoPost Starter",
    amount: 5000,
    days: 7
  },
  pro: {
    name: "AutoPost Pro",
    amount: 15000,
    days: 30
  },
  premium: {
    name: "AutoPost Premium",
    amount: 35000,
    days: 90
  }
  export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    const url = new URL(request.url);

    if (!env.DB) {
      return json({ error: "D1 binding DB belum diatur." }, 500);
    }

    if (!env.JWT_SECRET) {
      return json({ error: "JWT_SECRET belum diatur." }, 500);
    }

    // MEMBUAT TRANSAKSI MIDTRANS
    if (
      request.method === "POST" &&
      url.pathname === "/api/payments/create"
    ) {
      const payload = await verifyToken(
        getBearer(request) || "",
        env.JWT_SECRET
      );

      if (!payload) {
        return json({ error: "Silakan login terlebih dahulu." }, 401);
      }

      if (!env.MIDTRANS_SERVER_KEY) {
        return json({
          error: "MIDTRANS_SERVER_KEY belum diatur."
        }, 500);
      }

      const data = await readJson(request);
      const plan = PLANS[data?.plan];

      if (!plan) {
        return json({ error: "Paket tidak valid." }, 400);
      }

      const orderId = "AP-" + Date.now() + "-" + randomHex(4);

      try {
        await env.DB.prepare(
          "INSERT INTO payments (order_id, user_id, plan, amount, status) VALUES (?, ?, ?, ?, 'pending')"
        ).bind(
          orderId,
          payload.sub,
          data.plan,
          plan.amount
        ).run();

        const response = await fetch(
          "https://app.sandbox.midtrans.com/snap/v1/transactions",
          {
            method: "POST",
            headers: {
              "Authorization":
                "Basic " + btoa(env.MIDTRANS_SERVER_KEY + ":"),
              "Content-Type": "application/json",
              "Accept": "application/json"
            },
            body: JSON.stringify({
              transaction_details: {
                order_id: orderId,
                gross_amount: plan.amount
              },
              item_details: [{
                id: data.plan,
                price: plan.amount,
                quantity: 1,
                name: plan.name
              }],
              customer_details: {
                email: payload.email
              }
            })
          }
        );

        const result = await response.json();

        if (!response.ok || !result.token || !result.redirect_url) {
          await env.DB.prepare(
            "UPDATE payments SET status = 'failed' WHERE order_id = ?"
          ).bind(orderId).run();

          return json({
            error: "Midtrans gagal membuat transaksi.",
            details: result
          }, 502);
        }

        return json({
          ok: true,
          orderId,
          plan: data.plan,
          amount: plan.amount,
          token: result.token,
          redirectUrl: result.redirect_url
        });

      } catch {
        return json({
          error: "Gagal membuat transaksi pembayaran."
        }, 500);
      }
    }

    // NOTIFIKASI PEMBAYARAN MIDTRANS
    if (
      request.method === "POST" &&
      url.pathname === "/api/payments/notification"
    ) {
      if (!env.MIDTRANS_SERVER_KEY) {
        return json({
          error: "MIDTRANS_SERVER_KEY belum diatur."
        }, 500);
      }

      const notice = await readJson(request);

      if (!notice || typeof notice.order_id !== "string") {
        return json({ error: "Notifikasi tidak valid." }, 400);
      }

      try {
        // Periksa status langsung ke server Midtrans.
        const response = await fetch(
          "https://api.sandbox.midtrans.com/v2/" +
          encodeURIComponent(notice.order_id) +
          "/status",
          {
            headers: {
              "Authorization":
                "Basic " + btoa(env.MIDTRANS_SERVER_KEY + ":"),
              "Accept": "application/json"
            }
          }
        );

        const tx = await response.json();

        if (!response.ok) {
          return json({
            error: "Gagal memverifikasi status Midtrans."
          }, 502);
        }

        const payment = await env.DB.prepare(
          "SELECT order_id, user_id, plan, amount, status FROM payments WHERE order_id = ?"
        ).bind(tx.order_id).first();

        if (!payment) {
          return json({ error: "Order tidak ditemukan." }, 404);
        }

        if (Number(tx.gross_amount) !== payment.amount) {
          return json({
            error: "Nominal transaksi tidak cocok."
          }, 400);
        }

        const paid =
          tx.transaction_status === "settlement" ||
          (
            tx.transaction_status === "capture" &&
            tx.fraud_status === "accept"
          );

        if (paid) {
          // Jangan aktifkan paket dua kali untuk order yang sama.
          const existing = await env.DB.prepare(
            "SELECT id FROM subscriptions WHERE payment_order_id = ? LIMIT 1"
          ).bind(payment.order_id).first();

          if (!existing) {
            const now = new Date();

            const current = await env.DB.prepare(
              "SELECT expires_at FROM subscriptions WHERE user_id = ? AND status = 'active' ORDER BY expires_at DESC LIMIT 1"
            ).bind(payment.user_id).first();

            const start =
              current && Date.parse(current.expires_at) > now.getTime()
                ? new Date(current.expires_at)
                : now;

            const end = new Date(
              start.getTime() + PLANS[payment.plan].days * 86400000
            );

            await env.DB.batch([
              env.DB.prepare(
                "INSERT INTO subscriptions (user_id, plan, starts_at, expires_at, status, payment_order_id) VALUES (?, ?, ?, ?, 'active', ?)"
              ).bind(
                payment.user_id,
                payment.plan,
                start.toISOString(),
                end.toISOString(),
                payment.order_id
              ),

              env.DB.prepare(
                "UPDATE payments SET status = 'paid', paid_at = COALESCE(paid_at, CURRENT_TIMESTAMP) WHERE order_id = ?"
              ).bind(payment.order_id)
            ]);
          } else {
            await env.DB.prepare(
              "UPDATE payments SET status = 'paid', paid_at = COALESCE(paid_at, CURRENT_TIMESTAMP) WHERE order_id = ?"
            ).bind(payment.order_id).run();
          }

        } else if (
          ["deny", "cancel", "expire", "failure"].includes(
            tx.transaction_status
          )
        ) {
          await env.DB.prepare(
            "UPDATE payments SET status = ? WHERE order_id = ? AND status != 'paid'"
          ).bind(
            tx.transaction_status,
            payment.order_id
          ).run();
        }

        return json({ ok: true });

      } catch {
        return json({
          error: "Pemrosesan notifikasi pembayaran gagal."
        }, 500);
      }
    }
};
    // ===== FACEBOOK OAUTH: MULAI KONEKSI =====
    if (
      request.method === "POST" &&
      url.pathname === "/api/facebook/connect"
    ) {
      const payload = await verifyToken(
        getBearer(request) || "",
        env.JWT_SECRET
      );

      if (!payload) {
        return json({
          error: "Silakan login ke AutoPost terlebih dahulu."
        }, 401);
      }

      if (
        !env.META_APP_ID ||
        !env.META_APP_SECRET ||
        !env.TOKEN_ENCRYPTION_KEY
      ) {
        return json({
          error: "Konfigurasi Meta belum lengkap."
        }, 500);
      }

      const state = randomHex(32);
      const expiresAt = Math.floor(Date.now() / 1000) + 600;

      await env.DB.prepare(
        "INSERT INTO oauth_states (state, user_id, expires_at) VALUES (?, ?, ?)"
      ).bind(state, payload.sub, expiresAt).run();

      const redirectUri = `${url.origin}/auth/facebook/callback`;
      const authUrl = new URL(
        "https://www.facebook.com/v23.0/dialog/oauth"
      );

      authUrl.searchParams.set("client_id", env.META_APP_ID);
      authUrl.searchParams.set("redirect_uri", redirectUri);
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set(
        "scope",
        "public_profile,email,pages_show_list,pages_read_engagement,pages_manage_posts,instagram_basic,instagram_content_publish"
      );

      return json({
        ok: true,
        authUrl: authUrl.toString(),
        redirectUri
      });
    }

    // ===== CALLBACK FACEBOOK =====
    if (
      request.method === "GET" &&
      url.pathname === "/auth/facebook/callback"
    ) {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");

      const oauthError =
        url.searchParams.get("error_description") ||
        url.searchParams.get("error");

      if (oauthError) {
        return htmlPage(
          "Login Facebook dibatalkan",
          "Izin Facebook tidak diberikan. Kembali ke AutoPost dan coba lagi.",
          400
        );
      }

      if (!code || !state) {
        return htmlPage(
          "Login Facebook gagal",
          "Parameter login tidak ditemukan.",
          400
        );
      }

      if (
        !env.META_APP_ID ||
        !env.META_APP_SECRET ||
        !env.TOKEN_ENCRYPTION_KEY
      ) {
        return htmlPage(
          "Konfigurasi belum lengkap",
          "Periksa konfigurasi Meta di Cloudflare.",
          500
        );
      }

      const savedState = await env.DB.prepare(
        "SELECT state, user_id, expires_at FROM oauth_states WHERE state = ?"
      ).bind(state).first();

      if (
        !savedState ||
        savedState.expires_at < Math.floor(Date.now() / 1000)
      ) {
        if (savedState) {
          await env.DB.prepare(
            "DELETE FROM oauth_states WHERE state = ?"
          ).bind(state).run();
        }

        return htmlPage(
          "Login Facebook kedaluwarsa",
          "Mulai koneksi Facebook dari AutoPost lagi.",
          400
        );
      }

      await env.DB.prepare(
        "DELETE FROM oauth_states WHERE state = ?"
      ).bind(state).run();

      const redirectUri = `${url.origin}/auth/facebook/callback`;
      const tokenUrl = new URL(
        "https://graph.facebook.com/v23.0/oauth/access_token"
      );

      tokenUrl.searchParams.set("client_id", env.META_APP_ID);
      tokenUrl.searchParams.set("client_secret", env.META_APP_SECRET);
      tokenUrl.searchParams.set("redirect_uri", redirectUri);
      tokenUrl.searchParams.set("code", code);

      const tokenResponse = await fetch(tokenUrl.toString());
      const tokenData = await tokenResponse.json();

      if (!tokenResponse.ok || !tokenData.access_token) {
        return htmlPage(
          "Login Facebook gagal",
          "Periksa App ID, App Secret, dan Redirect URI Meta.",
          502
        );
      }

      const profileResponse = await fetch(
        "https://graph.facebook.com/v23.0/me?fields=id,name&access_token=" +
        encodeURIComponent(tokenData.access_token)
      );

      const profile = await profileResponse.json();

      if (!profileResponse.ok || !profile.id) {
        return htmlPage(
          "Login Facebook gagal",
          "Profil Facebook tidak dapat dibaca.",
          502
        );
      }

      const encryptedToken = await encryptToken(
        tokenData.access_token,
        env.TOKEN_ENCRYPTION_KEY
      );

      const tokenExpiresAt = tokenData.expires_in
        ? new Date(
            Date.now() + tokenData.expires_in * 1000
          ).toISOString()
        : null;

      await env.DB.prepare(
        "INSERT INTO social_accounts (user_id, platform, platform_user_id, access_token, token_expires_at) VALUES (?, 'facebook', ?, ?, ?) ON CONFLICT(user_id, platform, platform_user_id) DO UPDATE SET access_token = excluded.access_token, token_expires_at = excluded.token_expires_at"
      ).bind(
        savedState.user_id,
        profile.id,
        encryptedToken,
        tokenExpiresAt
      ).run();

      const safeName = String(profile.name || "pengguna")
        .replace(/[&<>"]/g, "");

      return htmlPage(
        "Facebook berhasil terhubung",
        `Akun Facebook (${safeName}) sudah terhubung ke AutoPost.`
      );
    }

    // ===== STATUS BACKEND =====
    if (
      request.method === "GET" &&
      url.pathname === "/"
    ) {
      return json({
        name: "AutoPost API",
        status: "online",
        version: 2
      });
    }

    // ===== REGISTRASI =====
    if (
      request.method === "POST" &&
      url.pathname === "/api/register"
    ) {
      const data = await readJson(request);

      if (
        !data ||
        !validEmail(data.email) ||
        typeof data.password !== "string" ||
        data.password.length < 10 ||
        data.password.length > 128
      ) {
        return json({
          error: "Masukkan email valid dan kata sandi 10–128 karakter."
        }, 400);
      }

      const email = data.email.trim().toLowerCase();
      const salt = randomHex(16);
      const hash = await derivePassword(data.password, salt);

      try {
        const result = await env.DB.prepare(
          "INSERT INTO users (email, password_hash) VALUES (?, ?)"
        ).bind(email, `${salt}:${hash}`).run();

        return json({
          ok: true,
          userId: result.meta.last_row_id,
          message: "Akun berhasil dibuat. Silakan login."
        }, 201);
      } catch {
        return json({
          error: "Email sudah terdaftar atau akun tidak dapat dibuat."
        }, 409);
      }
    }

    // ===== LOGIN =====
    if (
      request.method === "POST" &&
      url.pathname === "/api/login"
    ) {
      const data = await readJson(request);

      if (
        !data ||
        !validEmail(data.email) ||
        typeof data.password !== "string"
      ) {
        return json({
          error: "Email atau kata sandi tidak valid."
        }, 400);
      }

      const row = await env.DB.prepare(
        "SELECT id, email, password_hash FROM users WHERE email = ?"
      ).bind(data.email.trim().toLowerCase()).first();

      if (
        !row ||
        !row.password_hash ||
        !row.password_hash.includes(":")
      ) {
        return json({
          error: "Email atau kata sandi salah."
        }, 401);
      }

      const [salt, stored] = row.password_hash.split(":");
      const candidate = await derivePassword(
        data.password,
        salt
      );

      if (candidate !== stored) {
        return json({
          error: "Email atau kata sandi salah."
        }, 401);
      }

      const now = Math.floor(Date.now() / 1000);

      const token = await signToken({
        sub: row.id,
        email: row.email,
        iat: now,
        exp: now + 60 * 60 * 24 * 7
      }, env.JWT_SECRET);

      return json({
        ok: true,
        token,
        user: {
          id: row.id,
          email: row.email
        },
        tokenExpiresIn: 604800
      });
    }

    // ===== CEK LANGGANAN =====
    if (
      request.method === "GET" &&
      url.pathname === "/api/me"
    ) {
      const payload = await verifyToken(
        getBearer(request) || "",
        env.JWT_SECRET
      );

      if (!payload) {
        return json({
          error: "Token tidak valid atau sudah kedaluwarsa."
        }, 401);
      }

      const sub = await env.DB.prepare(
        "SELECT plan, starts_at, expires_at, status FROM subscriptions WHERE user_id = ? AND status = 'active' ORDER BY expires_at DESC LIMIT 1"
      ).bind(payload.sub).first();

      const active =
        !!sub &&
        Date.parse(sub.expires_at) > Date.now();

      return json({
        user: {
          id: payload.sub,
          email: payload.email
        },
        subscription: active ? sub : null
      });
    }

    // ===== REDEEM KODE AKTIVASI =====
    if (
      request.method === "POST" &&
      url.pathname === "/api/redeem"
    ) {
      const payload = await verifyToken(
        getBearer(request) || "",
        env.JWT_SECRET
      );

      if (!payload) {
        return json({
          error: "Silakan login terlebih dahulu."
        }, 401);
      }

      const data = await readJson(request);

      if (
        !data ||
        typeof data.code !== "string" ||
        data.code.length < 8 ||
        data.code.length > 100
      ) {
        return json({
          error: "Kode aktivasi tidak valid."
        }, 400);
      }

      const codeHash = await sha256Hex(
        data.code.trim().toUpperCase()
      );

      const activation = await env.DB.prepare(
        "SELECT id, plan, expires_at, redeemed_at FROM activation_codes WHERE code_hash = ?"
      ).bind(codeHash).first();

      if (
        !activation ||
        activation.redeemed_at ||
        Date.parse(activation.expires_at) <= Date.now()
      ) {
        return json({
          error: "Kode tidak valid, kedaluwarsa, atau sudah digunakan."
        }, 400);
      }

      const days =
        activation.plan === "starter" ? 7 :
        activation.plan === "pro" ? 30 : 90;

      const now = new Date();

      const current = await env.DB.prepare(
        "SELECT expires_at FROM subscriptions WHERE user_id = ? AND status = 'active' ORDER BY expires_at DESC LIMIT 1"
      ).bind(payload.sub).first();

      const start =
        current && Date.parse(current.expires_at) > now.getTime()
          ? new Date(current.expires_at)
          : now;

      const end = new Date(
        start.getTime() + days * 86400000
      );

      const claim = env.DB.prepare(
        "UPDATE activation_codes SET redeemed_at = CURRENT_TIMESTAMP WHERE id = ? AND redeemed_at IS NULL AND expires_at > CURRENT_TIMESTAMP"
      ).bind(activation.id);

      const result = await env.DB.batch([
        claim,
        env.DB.prepare(
          "INSERT INTO subscriptions (user_id, plan, starts_at, expires_at, status) VALUES (?, ?, ?, ?, 'active')"
        ).bind(
          payload.sub,
          activation.plan,
          start.toISOString(),
          end.toISOString()
        )
      ]);

      if (!result[0].meta.changes) {
        return json({
          error: "Kode sudah digunakan."
        }, 409);
      }

      return json({
        ok: true,
        plan: activation.plan,
        startsAt: start.toISOString(),
        expiresAt: end.toISOString()
      });
    }

    // ===== ENDPOINT TIDAK DITEMUKAN =====
    return json({
      error: "Endpoint tidak ditemukan."
    }, 404);
  }
};
