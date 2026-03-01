import Fastify from "fastify";
import cookie from "@fastify/cookie";
import replyFrom from "@fastify/reply-from";
import { request } from "undici";
import crypto from "crypto";

const app = Fastify({ logger: true });

await app.register(cookie);
await app.register(replyFrom, { undici: true });

const {
  PORT = "8080",
  PROJECT_SLUG,
  CONTROL_CENTER_URL,
  STUDIO_GATE_VERIFY_URL, // e.g. https://automation-n8n.cloud/api/studio-gate/verify
  CONTROL_CENTER_OPEN_STUDIO_PATH = "/open-studio",
  UPSTREAM_STUDIO_URL = "http://studio:3000",
  STUDIO_SESSION_COOKIE_NAME = "studio_session",
  STUDIO_SESSION_TTL_SECONDS = "3600",
  STUDIO_SESSION_SIGNING_SECRET, // enables strict cookie verification if set
  REQUIRE_CLOUDFLARE_ACCESS_HEADERS = "false"
} = process.env;

if (!PROJECT_SLUG) throw new Error("Missing env PROJECT_SLUG");
if (!CONTROL_CENTER_URL) throw new Error("Missing env CONTROL_CENTER_URL");
if (!STUDIO_GATE_VERIFY_URL) throw new Error("Missing env STUDIO_GATE_VERIFY_URL");

const ttlSeconds = Number(STUDIO_SESSION_TTL_SECONDS || "3600");
if (!Number.isFinite(ttlSeconds) || ttlSeconds < 60) throw new Error("Bad STUDIO_SESSION_TTL_SECONDS");

function wantsCloudflareHeaders() {
  return String(REQUIRE_CLOUDFLARE_ACCESS_HEADERS).toLowerCase() === "true";
}

function hasAccessHeaders(req) {
  // Lightweight MVP check. Later you can validate Access JWT properly.
  const email = req.headers["cf-access-authenticated-user-email"];
  const userId = req.headers["cf-access-userid"];
  return Boolean(email || userId);
}

function redirectToOpenStudio(req, reply) {
  const url = new URL(CONTROL_CENTER_URL);
  url.pathname = CONTROL_CENTER_OPEN_STUDIO_PATH;
  url.searchParams.set("project", PROJECT_SLUG);
  reply.redirect(302, url.toString());
}

function constantTimeEqual(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// Local signed session format (optional):
// base64url(JSON payload) + "." + hex(hmac)
function signSession(payloadObj) {
  if (!STUDIO_SESSION_SIGNING_SECRET) throw new Error("Missing STUDIO_SESSION_SIGNING_SECRET");
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const sig = crypto.createHmac("sha256", STUDIO_SESSION_SIGNING_SECRET).update(payload).digest("hex");
  return `${payload}.${sig}`;
}

function verifySession(token) {
  if (!token || !STUDIO_SESSION_SIGNING_SECRET) return null;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return null;

  const expected = crypto
    .createHmac("sha256", STUDIO_SESSION_SIGNING_SECRET)
    .update(payload)
    .digest("hex");

  if (!constantTimeEqual(sig, expected)) return null;

  try {
    const obj = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!obj || typeof obj !== "object") return null;
    if (typeof obj.exp !== "number") return null;
    if (Date.now() / 1000 > obj.exp) return null;
    if (obj.projectSlug !== PROJECT_SLUG) return null;
    return obj;
  } catch {
    return null;
  }
}

function setSessionCookie(reply, value) {
  reply.setCookie(STUDIO_SESSION_COOKIE_NAME, value, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: ttlSeconds
    // no `domain` => host-only cookie (per-project isolation)
  });
}

// Call upstream verify URL; returns { ok: true, session? } or { ok: false }.
async function verifyTokenWithUpstream(token) {
  const body = JSON.stringify({ token, projectSlug: PROJECT_SLUG });
  let res;
  try {
    res = await request(STUDIO_GATE_VERIFY_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "content-length": String(Buffer.byteLength(body))
      },
      body
    });
  } catch (e) {
    return { ok: false };
  }
  const text = await res.body.text();
  let data = null;
  try {
    data = JSON.parse(text);
  } catch {
    return { ok: false };
  }
  if (!data?.ok) return { ok: false };
  return { ok: true, session: data.session };
}

// POST /_gate/verify — body: { "token": "..." }; response: { "ok": true } | { "ok": false }
app.post("/_gate/verify", async (req, reply) => {
  if (wantsCloudflareHeaders() && !hasAccessHeaders(req)) {
    req.log.warn("Missing Cloudflare Access headers");
    return reply.code(403).send({ ok: false });
  }
  const token = req.body?.token;
  if (!token || typeof token !== "string") {
    return reply.code(400).send({ ok: false });
  }
  const result = await verifyTokenWithUpstream(token);
  return reply.send({ ok: result.ok });
});

// GET /_gate?t=TOKEN
app.get("/_gate", async (req, reply) => {
  if (wantsCloudflareHeaders() && !hasAccessHeaders(req)) {
    req.log.warn("Missing Cloudflare Access headers");
    return redirectToOpenStudio(req, reply);
  }

  const token = req.query?.t;
  if (!token) return reply.code(400).send("Missing token");

  const result = await verifyTokenWithUpstream(token);
  if (!result.ok) {
    return reply.code(403).send("Invalid or expired link. Please reopen from Control Center.");
  }

  // Preferred: Control Center returns `session` (opaque string)
  // Fallback: mint locally (signed) if Control Center doesn't provide one.
  let sessionValue = result.session;
  if (!sessionValue) {
    const now = Math.floor(Date.now() / 1000);
    sessionValue = signSession({ projectSlug: PROJECT_SLUG, exp: now + ttlSeconds });
  }

  setSessionCookie(reply, sessionValue);

  // You chose Studio home
  return reply.redirect(302, "/");
});

// Proxy everything else, requires cookie
app.all("/*", async (req, reply) => {
  if (wantsCloudflareHeaders() && !hasAccessHeaders(req)) {
    req.log.warn("Missing Cloudflare Access headers");
    return redirectToOpenStudio(req, reply);
  }

  const cookieVal = req.cookies?.[STUDIO_SESSION_COOKIE_NAME];
  if (!cookieVal) return redirectToOpenStudio(req, reply);

  // If you set STUDIO_SESSION_SIGNING_SECRET, we can strictly verify it.
  // If you rely on Control Center opaque sessions, omit secret (or add introspection later).
  if (STUDIO_SESSION_SIGNING_SECRET) {
    const ok = verifySession(cookieVal);
    if (!ok) return redirectToOpenStudio(req, reply);
  }

  const upstream = new URL(UPSTREAM_STUDIO_URL);
  const target = new URL(req.url, upstream);

  return reply.from(target.toString(), {
    rewriteRequestHeaders: (originalReq, headers) => {
      delete headers.connection;
      delete headers["keep-alive"];
      delete headers["proxy-authenticate"];
      delete headers["proxy-authorization"];
      delete headers.te;
      delete headers.trailer;
      delete headers["transfer-encoding"];
      delete headers.upgrade;
      headers.host = upstream.host;
      return headers;
    }
  });
});

app.listen({ port: Number(PORT), host: "0.0.0.0" });
