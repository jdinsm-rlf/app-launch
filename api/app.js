// Ramage Law Group: client app launch page.
// One serverless function handles Microsoft sign-in, the private page, and the change log API.
import { SignJWT, jwtVerify, createRemoteJWKSet } from "jose";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import crypto from "node:crypto";

const SESSION_COOKIE = "rlg_session";
const TX_COOKIE = "rlg_tx";
const SESSION_HOURS = 8;
const TYPES = { change: "Change request", question: "Question", comment: "Comment", approval: "Approval" };
const TYPE_LABELS = { change: "change-request", question: "question", comment: "comment", approval: "approval" };
const IN_PROGRESS = "in progress";

/* ---------- configuration ---------- */
const REQUIRED = ["ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET", "SESSION_SECRET", "GITHUB_TOKEN", "GITHUB_REPO"];
function config() {
  const e = process.env;
  return {
    tenant: e.ENTRA_TENANT_ID,
    clientId: e.ENTRA_CLIENT_ID,
    clientSecret: e.ENTRA_CLIENT_SECRET,
    secret: e.SESSION_SECRET,
    token: e.GITHUB_TOKEN,
    repo: e.GITHUB_REPO,
    domain: (e.ALLOWED_EMAIL_DOMAIN || "ramagelawfirm.com").toLowerCase().replace(/^@/, ""),
    admins: (e.ADMIN_EMAILS || "").toLowerCase().split(",").map(s => s.trim()).filter(Boolean),
    baseUrl: e.BASE_URL || ""
  };
}
function missingConfig() { return REQUIRED.filter(k => !process.env[k]); }

/* ---------- helpers ---------- */
const b64url = buf => Buffer.from(buf).toString("base64url");
const key = cfg => new TextEncoder().encode(cfg.secret);
function baseUrl(req, cfg) {
  if (cfg.baseUrl) return cfg.baseUrl.replace(/\/$/, "");
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `https://${host}`;
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach(p => {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function cookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "private, no-store");
  res.end(JSON.stringify(body));
}
function redirect(res, location, cookies) {
  res.statusCode = 302;
  if (cookies) res.setHeader("Set-Cookie", cookies);
  res.setHeader("Location", location);
  res.setHeader("Cache-Control", "no-store");
  res.end();
}
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function messagePage(res, status, title, text, link) {
  res.statusCode = status;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex, nofollow"><title>${escapeHtml(title)} | Ramage Law Group</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#1D243F;color:#F4F1E8;font:16px/1.6 "Segoe UI",system-ui,sans-serif;text-align:center;padding:24px}main{max-width:52ch}a{color:#E2C383;font-weight:700}</style></head>
<body><main><h1 style="font:600 34px/1.1 Georgia,serif;margin:0 0 10px">${escapeHtml(title)}</h1><p>${escapeHtml(text)}</p>${link ? `<p><a href="${escapeHtml(link.href)}">${escapeHtml(link.text)}</a></p>` : ""}</main></body></html>`);
}
async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") { try { return JSON.parse(req.body); } catch { return {}; } }
  return await new Promise(resolve => {
    let data = ""; req.on("data", c => { data += c; if (data.length > 20000) req.destroy(); });
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch { resolve({}); } });
    req.on("error", () => resolve({}));
  });
}

/* ---------- session ---------- */
async function getSession(req, cfg) {
  const raw = parseCookies(req)[SESSION_COOKIE];
  if (!raw) return null;
  try {
    const { payload } = await jwtVerify(raw, key(cfg), { issuer: "rlg-app-launch", audience: "rlg-app-launch" });
    if (!payload.email || !String(payload.email).endsWith("@" + cfg.domain)) return null;
    return { email: payload.email, name: payload.name || payload.email, admin: cfg.admins.includes(payload.email) };
  } catch { return null; }
}

/* ---------- Microsoft sign-in (OpenID Connect, authorization code + PKCE) ---------- */
let jwksCache = null;
function jwks(cfg) {
  if (!jwksCache) jwksCache = createRemoteJWKSet(new URL(`https://login.microsoftonline.com/${cfg.tenant}/discovery/v2.0/keys`));
  return jwksCache;
}
export const _internal = { setJwks(fn) { jwksCache = fn; } }; // used by local tests only

async function login(req, res, cfg) {
  const state = b64url(crypto.randomBytes(24));
  const nonce = b64url(crypto.randomBytes(24));
  const verifier = b64url(crypto.randomBytes(48));
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
  const tx = await new SignJWT({ state, nonce, verifier })
    .setProtectedHeader({ alg: "HS256" }).setIssuedAt().setExpirationTime("10m").sign(key(cfg));
  const params = new URLSearchParams({
    client_id: cfg.clientId, response_type: "code", response_mode: "query",
    redirect_uri: baseUrl(req, cfg) + "/auth/callback", scope: "openid profile email",
    state, nonce, code_challenge: challenge, code_challenge_method: "S256", prompt: "select_account"
  });
  redirect(res, `https://login.microsoftonline.com/${cfg.tenant}/oauth2/v2.0/authorize?${params}`, [cookie(TX_COOKIE, tx, 600)]);
}

async function callback(req, res, cfg) {
  const q = req.query || {};
  const clearTx = cookie(TX_COOKIE, "", 0);
  const retry = { href: "/auth/login", text: "Try signing in again" };
  if (q.error) return messagePage(res, 401, "Sign-in didn't finish", "Microsoft returned an error: " + String(q.error_description || q.error).slice(0, 200), retry);
  let tx;
  try { tx = (await jwtVerify(parseCookies(req)[TX_COOKIE] || "", key(cfg))).payload; }
  catch { return messagePage(res, 400, "Sign-in expired", "The sign-in took too long or was started in another browser.", retry); }
  if (!q.code || q.state !== tx.state) return messagePage(res, 400, "Sign-in didn't match", "Start the sign-in again from this browser.", retry);

  const tokenRes = await fetch(`https://login.microsoftonline.com/${cfg.tenant}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: cfg.clientId, client_secret: cfg.clientSecret, grant_type: "authorization_code",
      code: String(q.code), redirect_uri: baseUrl(req, cfg) + "/auth/callback", code_verifier: tx.verifier,
      scope: "openid profile email"
    })
  });
  const tokens = await tokenRes.json().catch(() => ({}));
  if (!tokenRes.ok || !tokens.id_token) {
    console.error("token exchange failed", tokenRes.status, tokens.error, tokens.error_description);
    return messagePage(res, 502, "Sign-in didn't finish", "Microsoft didn't accept the sign-in. Check the app registration's redirect URI and client secret.", retry);
  }
  let claims;
  try {
    claims = (await jwtVerify(tokens.id_token, jwks(cfg), {
      issuer: `https://login.microsoftonline.com/${cfg.tenant}/v2.0`, audience: cfg.clientId
    })).payload;
  } catch (e) {
    console.error("id token rejected", e && e.code);
    return messagePage(res, 401, "Sign-in couldn't be verified", "Microsoft's sign-in token didn't pass verification.", retry);
  }
  if (claims.nonce !== tx.nonce || claims.tid !== cfg.tenant) return messagePage(res, 401, "Sign-in couldn't be verified", "This account isn't part of the firm's Microsoft 365.", retry);
  const email = String(claims.email || claims.preferred_username || claims.upn || "").toLowerCase();
  if (!email.endsWith("@" + cfg.domain)) {
    return messagePage(res, 403, "This page is for firm staff", `Sign in with your @${cfg.domain} account to open it.`, retry);
  }
  const session = await new SignJWT({ email, name: String(claims.name || email) })
    .setProtectedHeader({ alg: "HS256" }).setSubject(String(claims.oid || email))
    .setIssuer("rlg-app-launch").setAudience("rlg-app-launch")
    .setIssuedAt().setExpirationTime(`${SESSION_HOURS}h`).sign(key(cfg));
  redirect(res, "/", [cookie(SESSION_COOKIE, session, SESSION_HOURS * 3600), clearTx]);
}

/* ---------- GitHub issues as the change log ---------- */
async function gh(cfg, path, init = {}) {
  const r = await fetch(`https://api.github.com/repos/${cfg.repo}${path}`, {
    ...init,
    headers: {
      Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
      Authorization: `Bearer ${cfg.token}`, "User-Agent": "rlg-app-launch",
      ...(init.body ? { "Content-Type": "application/json" } : {})
    }
  });
  const data = await r.json().catch(() => null);
  if (!r.ok) { const err = new Error("github " + r.status); err.status = r.status; err.detail = data && data.message; throw err; }
  return data;
}
const MARKER = /<!--\s*rlg\s+item:([\w-]+)\s+type:(\w+)\s+by:([^\s>]+)\s*-->/;
function toEntry(it, admin) {
  const body = it.body || "";
  const m = MARKER.exec(body);
  const labels = (it.labels || []).map(l => (typeof l === "string" ? l : l.name || "").toLowerCase());
  let type = m ? m[2] : "comment", item = m ? m[1] : "page", by = m ? m[3] : (it.user && it.user.login) || "", name = "";
  if (!m) {
    const tm = /^\[(Change request|Question|Comment|Approval)\]/i.exec(it.title || "");
    if (tm) type = { "change request": "change", question: "question", comment: "comment", approval: "approval" }[tm[1].toLowerCase()];
    name = by;
  } else {
    const fm = /^\*\*From:\*\*\s*(.+?)\s*\(/m.exec(body);
    name = fm ? fm[1] : by;
  }
  const text = m
    ? body.replace(MARKER, "").replace(/^\*\*(From|About|Type):\*\*.*$/gm, "").trim()
    : [it.title, body].filter(Boolean).join("\n\n");
  const status = it.state === "closed" ? (it.state_reason === "not_planned" ? "wontdo" : "done") : (labels.includes(IN_PROGRESS) ? "progress" : "open");
  const e = { number: it.number, type: TYPES[type] ? type : "comment", item, by, name, text, at: it.created_at, status, comments: it.comments || 0, closedAt: it.closed_at || null };
  if (admin) e.url = it.html_url;
  return e;
}

async function listNotes(res, cfg, me) {
  const all = [];
  for (let page = 1; page <= 3; page++) {
    const batch = await gh(cfg, `/issues?state=all&per_page=100&sort=created&direction=desc&page=${page}`);
    all.push(...batch.filter(i => !i.pull_request));
    if (batch.length < 100) break;
  }
  json(res, 200, { notes: all.map(i => toEntry(i, me.admin)) });
}

async function createNote(req, res, cfg, me) {
  const b = await readBody(req);
  const type = String(b.type || "");
  const item = String(b.item || "page");
  const label = String(b.itemLabel || "Whole page").replace(/[\r\n]/g, " ").slice(0, 120);
  const text = String(b.text || "").trim().slice(0, 4000);
  if (!TYPES[type] || !/^[\w-]{1,40}$/.test(item) || !text) return json(res, 400, { error: "invalid_note" });
  const short = text.replace(/\s+/g, " ");
  const title = `[${TYPES[type]}] ${label}: ${short.length > 60 ? short.slice(0, 57) + "..." : short}`;
  const safeName = me.name.replace(/[()\r\n*]/g, "").slice(0, 80);
  const body = `**From:** ${safeName} (${me.email})\n**About:** ${label}\n**Type:** ${TYPES[type]}\n\n${text.replace(/<!--|-->/g, "")}\n\n<!-- rlg item:${item} type:${type} by:${me.email} -->`;
  const it = await gh(cfg, "/issues", { method: "POST", body: JSON.stringify({ title, body, labels: [TYPE_LABELS[type]] }) });
  json(res, 201, { note: toEntry(it, me.admin) });
}

async function setStatus(req, res, cfg, me) {
  if (!me.admin) return json(res, 403, { error: "not_allowed" });
  const b = await readBody(req);
  const number = parseInt(b.number, 10), status = String(b.status || "");
  if (!number || !["open", "progress", "done", "wontdo"].includes(status)) return json(res, 400, { error: "invalid_status" });
  const cur = await gh(cfg, `/issues/${number}`);
  let labels = (cur.labels || []).map(l => (typeof l === "string" ? l : l.name)).filter(n => n.toLowerCase() !== IN_PROGRESS);
  if (status === "progress") labels.push(IN_PROGRESS);
  const patch = { labels };
  if (status === "open" || status === "progress") patch.state = "open";
  if (status === "done") { patch.state = "closed"; patch.state_reason = "completed"; }
  if (status === "wontdo") { patch.state = "closed"; patch.state_reason = "not_planned"; }
  const it = await gh(cfg, `/issues/${number}`, { method: "PATCH", body: JSON.stringify(patch) });
  json(res, 200, { note: toEntry(it, true) });
}

/* ---------- router ---------- */
export default async function handler(req, res) {
  const route = String((req.query && req.query.r) || "");
  const missing = missingConfig();
  if (missing.length) {
    console.error("missing environment variables:", missing.join(", "));
    return messagePage(res, 500, "Setup isn't finished", "Some settings are missing in Vercel: " + missing.join(", ") + ".");
  }
  const cfg = config();
  try {
    if (route === "login") return await login(req, res, cfg);
    if (route === "callback") return await callback(req, res, cfg);
    if (route === "logout") return redirect(res, "/signed-out.html", [cookie(SESSION_COOKIE, "", 0)]);

    const me = await getSession(req, cfg);
    if (route === "page") {
      if (!me) return redirect(res, "/auth/login");
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Cache-Control", "private, no-store");
      return res.end(readFileSync(join(process.cwd(), "private", "index.html")));
    }
    if (!me) return json(res, 401, { error: "signed_out" });
    if (route === "me") return json(res, 200, me);

    const isWrite = req.method === "POST";
    if (isWrite && req.headers["x-rlg"] !== "1") return json(res, 403, { error: "bad_request" });
    if (route === "notes" && req.method === "GET") return await listNotes(res, cfg, me);
    if (route === "notes" && isWrite) return await createNote(req, res, cfg, me);
    if (route === "status" && isWrite) return await setStatus(req, res, cfg, me);
    return json(res, 404, { error: "not_found" });
  } catch (e) {
    console.error("request failed", route, e && e.message, e && e.detail);
    if (route === "page") return messagePage(res, 500, "Something went wrong", "The page couldn't load. Try again in a minute.");
    return json(res, e && e.status === 404 ? 502 : 500, { error: "server_error" });
  }
}
