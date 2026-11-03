import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const store = getStore("schoolterminal-auth");
const COOKIE = "st_auth";
const COOKIE_AGE = 60 * 60 * 24 * 365 * 10;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers }
  });
}
function parseCookies(header = "") {
  return Object.fromEntries(header.split(";").map(v => {
    const i = v.indexOf("=");
    return i < 0 ? [v.trim(), ""] : [v.slice(0, i).trim(), decodeURIComponent(v.slice(i + 1).trim())];
  }));
}
function cookie(value, maxAge = COOKIE_AGE) {
  return `${COOKIE}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}
function allowedOrigins() {
  return (process.env.ALLOWED_ORIGINS || [
    "https://schoolterminal.netlify.app",
    "https://3kh0g.netlify.app",
    "https://schoolported.netlify.app",
    "https://monkeyg2.netlify.app"
  ].join(",")).split(",").map(s => s.trim()).filter(Boolean);
}
function corsHeaders(origin) {
  if (!origin || !allowedOrigins().includes(origin)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Vary": "Origin"
  };
}
function randomToken() { return crypto.randomBytes(32).toString("base64url"); }
function hash(value) { return crypto.createHash("sha256").update(value).digest("base64url"); }
function constantTimeEqual(a, b) {
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
async function getSession(id) {
  if (!id) return null;
  return await store.get(`session:${id}`, { type: "json" });
}
async function issueCode(sessionId, returnTo, challenge) {
  const code = randomToken();
  await store.setJSON(`code:${hash(code)}`, {
    sessionId, returnTo, challenge, createdAt: Date.now()
  });
  return code;
}
function validReturnTo(value) {
  try {
    const u = new URL(value);
    return u.protocol === "https:" && allowedOrigins().includes(u.origin);
  } catch { return false; }
}

export default async (request) => {
  const url = new URL(request.url);
  const action = url.searchParams.get("action") || "";
  const origin = request.headers.get("origin") || "";
  const cors = corsHeaders(origin);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

  const cookies = parseCookies(request.headers.get("cookie") || "");
  const cookieSessionId = cookies[COOKIE];

  try {
    if (action === "status" && request.method === "GET") {
      const session = await getSession(cookieSessionId);
      return json({ authenticated: !!session }, 200, cors);
    }

    if (action === "login" && request.method === "POST") {
      const body = await request.json();
      const configured = process.env.AUTH_PASSWORD;
      if (!configured) return json({ error: "The site owner has not configured AUTH_PASSWORD in Netlify." }, 503, cors);
      if (!constantTimeEqual(body.password, configured)) {
        return json({ success: false, error: "Incorrect password. Please try again." }, 401, cors);
      }
      const sessionId = randomToken();
      await store.setJSON(`session:${sessionId}`, { createdAt: Date.now() });
      return json({ success: true }, 200, {
        ...cors,
        "Set-Cookie": cookie(sessionId)
      });
    }

    if (action === "authorize" && request.method === "POST") {
      const body = await request.json();
      if (!validReturnTo(body.returnTo) || typeof body.challenge !== "string" ||
          !/^[A-Za-z0-9_-]{40,100}$/.test(body.challenge)) {
        return json({ error: "Invalid return address or security challenge." }, 400, cors);
      }
      const session = await getSession(cookieSessionId);
      if (!session) return json({ authenticated: false }, 401, cors);
      const code = await issueCode(cookieSessionId, body.returnTo, body.challenge);
      return json({ authenticated: true, code, returnTo: body.returnTo }, 200, cors);
    }

    if (action === "exchange" && request.method === "POST") {
      const body = await request.json();
      if (typeof body.code !== "string" || typeof body.verifier !== "string") {
        return json({ error: "Missing authorization code." }, 400, cors);
      }
      const key = `code:${hash(body.code)}`;
      const record = await store.get(key, { type: "json" });
      if (!record) return json({ error: "This login link has expired or was already used." }, 401, cors);
      await store.delete(key);
      if (Date.now() - record.createdAt > 2 * 60 * 1000 ||
          hash(body.verifier) !== record.challenge) {
        return json({ error: "Login verification failed. Please try again." }, 401, cors);
      }
      const session = await getSession(record.sessionId);
      if (!session) return json({ error: "Your login has expired. Please sign in again." }, 401, cors);
      return json({ success: true, token: record.sessionId }, 200, cors);
    }

    if (action === "verify" && request.method === "GET") {
      const auth = request.headers.get("authorization") || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      const session = await getSession(token);
      return json({ authenticated: !!session }, session ? 200 : 401, cors);
    }

    if (action === "logout" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      const auth = request.headers.get("authorization") || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      const id = token || cookieSessionId;
      if (id) await store.delete(`session:${id}`);
      return json({ success: true }, 200, {
        ...cors,
        "Set-Cookie": cookie("", 0)
      });
    }

    return json({ error: "Unknown authentication action." }, 404, cors);
  } catch (error) {
    console.error("Authentication function error:", error);
    return json({ error: "Authentication service error. Check the Netlify function logs." }, 500, cors);
  }
};
