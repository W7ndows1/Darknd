import { createServer } from "node:http";
import { fileURLToPath } from "url";
import { hostname } from "node:os";
import { server as wisp, logging } from "@mercuryworkshop/wisp-js/server";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { libcurlPath } from "@mercuryworkshop/libcurl-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";

const publicPath = fileURLToPath(new URL("../public/", import.meta.url));

// ── File Paths ────────────────────────────────────────────────────────────────
const PASSWORDS_FILE    = path.resolve("passwords.txt");
const ADMIN_FILE        = path.resolve("admin.txt");
const KEY_META_FILE     = path.resolve("key-metadata.json");
const ANNOUNCEMENTS_FILE = path.resolve("announcements.json");
const CHAT_FILE          = path.resolve("chat.json");

// ── Password Helpers ──────────────────────────────────────────────────────────
function loadPasswords() {
	if (!fs.existsSync(PASSWORDS_FILE)) fs.writeFileSync(PASSWORDS_FILE, "", "utf8");
	return fs.readFileSync(PASSWORDS_FILE, "utf8")
		.split("\n").map(p => p.trim()).filter(p => p.length > 0);
}

function savePasswords(passwords) {
	fs.writeFileSync(PASSWORDS_FILE, passwords.join("\n") + "\n", "utf8");
}

function loadAdminPassword() {
	if (!fs.existsSync(ADMIN_FILE)) {
		console.error("ERROR: admin.txt not found.");
		process.exit(1);
	}
	const pw = fs.readFileSync(ADMIN_FILE, "utf8").trim();
	if (!pw) { console.error("ERROR: admin.txt is empty."); process.exit(1); }
	return pw;
}

function timingSafeCompare(a, b) {
	try {
		const ba = Buffer.from(a), bb = Buffer.from(b);
		return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
	} catch { return false; }
}

// ── Key Metadata (expiry) ─────────────────────────────────────────────────────
function loadKeyMeta() {
	if (!fs.existsSync(KEY_META_FILE)) return {};
	try { return JSON.parse(fs.readFileSync(KEY_META_FILE, "utf8")); }
	catch { return {}; }
}

function saveKeyMeta(meta) {
	fs.writeFileSync(KEY_META_FILE, JSON.stringify(meta, null, 2), "utf8");
}

function isKeyExpired(key) {
	const meta = loadKeyMeta();
	if (!meta[key]) return false;
	if (meta[key].expiresAt === null) return false;
	return Date.now() > meta[key].expiresAt;
}

function isValidPassword(input) {
	return loadPasswords().some(p => timingSafeCompare(p, input) && !isKeyExpired(p));
}

function isValidAdminPassword(input) {
	return timingSafeCompare(loadAdminPassword(), input);
}

// Clean expired keys every minute
function cleanExpiredKeys() {
	const passwords = loadPasswords();
	const meta = loadKeyMeta();
	const now = Date.now();
	const valid = passwords.filter(p => {
		const m = meta[p];
		return !(m && m.expiresAt !== null && now > m.expiresAt);
	});
	if (valid.length !== passwords.length) savePasswords(valid);
}
setInterval(cleanExpiredKeys, 60 * 1000);
cleanExpiredKeys(); // run on startup

// ── Announcements ─────────────────────────────────────────────────────────────
function loadAnnouncements() {
	if (!fs.existsSync(ANNOUNCEMENTS_FILE)) return [];
	try { return JSON.parse(fs.readFileSync(ANNOUNCEMENTS_FILE, "utf8")); }
	catch { return []; }
}

function saveAnnouncements(arr) {
	fs.writeFileSync(ANNOUNCEMENTS_FILE, JSON.stringify(arr, null, 2), "utf8");
}

// ── Chat (persisted to disk) ──────────────────────────────────────────────────
const MAX_CHAT = 100;

function loadChat() {
	if (!fs.existsSync(CHAT_FILE)) return [];
	try { return JSON.parse(fs.readFileSync(CHAT_FILE, "utf8")); }
	catch { return []; }
}

function saveChat(msgs) {
	fs.writeFileSync(CHAT_FILE, JSON.stringify(msgs, null, 2), "utf8");
}

// ── Session Store ─────────────────────────────────────────────────────────────
const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const sessions = new Map();
let totalLogins = 0;

function createSessionToken() { return crypto.randomBytes(32).toString("hex"); }

function isValidSession(token) {
	if (!token) return false;
	const session = sessions.get(token);
	if (!session) return false;
	if (Date.now() - session.createdAt > SESSION_MAX_AGE_MS) {
		sessions.delete(token); return false;
	}
	return true;
}

function isAdminSession(token) {
	if (!isValidSession(token)) return false;
	return sessions.get(token)?.isAdmin === true;
}

function getTokenFromCookie(cookieHeader) {
	if (!cookieHeader) return null;
	const match = cookieHeader.match(/(?:^|;\s*)sj_session=([A-Fa-f0-9]{64})/);
	return match ? match[1] : null;
}

setInterval(() => {
	const now = Date.now();
	for (const [token, session] of sessions) {
		if (now - session.createdAt > SESSION_MAX_AGE_MS) sessions.delete(token);
	}
}, 60 * 60 * 1000);

// ── Wisp Config ───────────────────────────────────────────────────────────────
logging.set_level(logging.NONE);
Object.assign(wisp.options, {
	allow_udp_streams: false,
	hostname_blacklist: [/example\.com/],
	dns_servers: ["1.1.1.3", "1.0.0.3"],
});

// ── Fastify Setup ─────────────────────────────────────────────────────────────
const fastify = Fastify({
	serverFactory: (handler) => {
		return createServer()
			.on("request", (req, res) => {
				res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
				res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
				handler(req, res);
			})
			.on("upgrade", (req, socket, head) => {
				const token = getTokenFromCookie(req.headers.cookie);
				if (!isValidSession(token)) {
					socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
					socket.destroy();
					return;
				}
				if (req.url.endsWith("/wisp/")) wisp.routeRequest(req, socket, head);
				else socket.end();
			});
	},
});

// ── Body Parsers ──────────────────────────────────────────────────────────────
fastify.addContentTypeParser(
	"application/x-www-form-urlencoded",
	{ parseAs: "string" },
	(_req, body, done) => {
		try { done(null, Object.fromEntries(new URLSearchParams(body))); }
		catch (e) { done(e); }
	}
);

fastify.addContentTypeParser(
	"application/json",
	{ parseAs: "string" },
	(_req, body, done) => {
		try { done(null, JSON.parse(body)); }
		catch (e) { done(e); }
	}
);

// ── Auth Hook ─────────────────────────────────────────────────────────────────
fastify.addHook("onRequest", async (req, reply) => {
	const url = req.url.split("?")[0];
	if (url === "/login" || url === "/logout" || url === "/admin/login" || url === "/admin/logout") return;

	const token = getTokenFromCookie(req.headers.cookie);

	if (url.startsWith("/admin")) {
		if (!isAdminSession(token)) return reply.code(302).header("Location", "/admin/login").send();
		return;
	}

	if (!isValidSession(token)) return reply.code(302).header("Location", "/login").send();
});

// ── Regular Auth Routes ───────────────────────────────────────────────────────
fastify.get("/login", async (req, reply) => {
	const token = getTokenFromCookie(req.headers.cookie);
	if (isValidSession(token)) return reply.code(302).header("Location", "/").send();
	return reply.code(200).type("text/html").sendFile("login.html");
});

fastify.post("/login", async (req, reply) => {
	const password = req.body?.password ?? "";
	if (isValidPassword(password)) {
		const token = createSessionToken();
		sessions.set(token, { createdAt: Date.now(), isAdmin: false });
		totalLogins++;
		return reply
			.code(302)
			.header("Set-Cookie", `sj_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MAX_AGE_MS / 1000}`)
			.header("Location", "/").send();
	}
	return reply.code(302).header("Location", "/login?error=1").send();
});

fastify.post("/logout", async (req, reply) => {
	const token = getTokenFromCookie(req.headers.cookie);
	if (token) sessions.delete(token);
	return reply
		.code(302)
		.header("Set-Cookie", "sj_session=; Path=/; HttpOnly; Max-Age=0")
		.header("Location", "/login").send();
});

// ── Admin Auth Routes ─────────────────────────────────────────────────────────
fastify.get("/admin/login", async (req, reply) => {
	const token = getTokenFromCookie(req.headers.cookie);
	if (isAdminSession(token)) return reply.code(302).header("Location", "/admin").send();
	return reply.code(200).type("text/html").sendFile("admin-login.html");
});

fastify.post("/admin/login", async (req, reply) => {
	const password = req.body?.password ?? "";
	if (isValidAdminPassword(password)) {
		const token = createSessionToken();
		sessions.set(token, { createdAt: Date.now(), isAdmin: true });
		return reply
			.code(302)
			.header("Set-Cookie", `sj_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MAX_AGE_MS / 1000}`)
			.header("Location", "/admin").send();
	}
	return reply.code(302).header("Location", "/admin/login?error=1").send();
});

fastify.post("/admin/logout", async (req, reply) => {
	const token = getTokenFromCookie(req.headers.cookie);
	if (token) sessions.delete(token);
	return reply
		.code(302)
		.header("Set-Cookie", "sj_session=; Path=/; HttpOnly; Max-Age=0")
		.header("Location", "/admin/login").send();
});

fastify.get("/admin", async (req, reply) => {
	return reply.code(200).type("text/html").sendFile("admin.html");
});

// ── Admin API: State ──────────────────────────────────────────────────────────
fastify.get("/admin/api/state", async (req, reply) => {
	const now = Date.now();
	const meta = loadKeyMeta();

	const sessionList = Array.from(sessions.entries())
		.filter(([, s]) => !s.isAdmin)
		.map(([token, s]) => ({
			token: token.slice(0, 8) + "...",
			fullToken: token,
			createdAt: s.createdAt,
			age: Math.floor((now - s.createdAt) / 1000 / 60),
		}));

	const passwords = loadPasswords().map(pw => ({
		key: pw,
		expiresAt: meta[pw]?.expiresAt ?? null,
	}));

	return reply.send({
		sessions: sessionList,
		passwords,
		totalLogins,
		activeSessions: sessionList.length,
	});
});

// ── Admin API: Passwords ──────────────────────────────────────────────────────
fastify.post("/admin/api/passwords/add", async (req, reply) => {
	const { password } = req.body ?? {};
	if (!password || password.trim().length === 0)
		return reply.code(400).send({ error: "Password cannot be empty" });
	const passwords = loadPasswords();
	if (passwords.includes(password.trim()))
		return reply.code(400).send({ error: "Password already exists" });
	passwords.push(password.trim());
	savePasswords(passwords);
	// Default to permanent
	const meta = loadKeyMeta();
	meta[password.trim()] = { expiresAt: null };
	saveKeyMeta(meta);
	return reply.send({ ok: true, passwords });
});

fastify.post("/admin/api/passwords/rename", async (req, reply) => {
	const { oldPassword, newPassword } = req.body ?? {};
	if (!oldPassword || !newPassword || newPassword.trim().length === 0)
		return reply.code(400).send({ error: "Invalid input" });
	const passwords = loadPasswords();
	const idx = passwords.indexOf(oldPassword);
	if (idx === -1) return reply.code(404).send({ error: "Password not found" });
	passwords[idx] = newPassword.trim();
	savePasswords(passwords);
	// Migrate metadata
	const meta = loadKeyMeta();
	if (meta[oldPassword]) { meta[newPassword.trim()] = meta[oldPassword]; delete meta[oldPassword]; }
	saveKeyMeta(meta);
	return reply.send({ ok: true, passwords });
});

fastify.post("/admin/api/passwords/delete", async (req, reply) => {
	const { password } = req.body ?? {};
	const passwords = loadPasswords();
	const filtered = passwords.filter(p => p !== password);
	if (filtered.length === passwords.length)
		return reply.code(404).send({ error: "Password not found" });
	savePasswords(filtered);
	// Remove metadata
	const meta = loadKeyMeta();
	delete meta[password];
	saveKeyMeta(meta);
	return reply.send({ ok: true, passwords: filtered });
});

// ── Admin API: Key Duration ───────────────────────────────────────────────────
fastify.post("/admin/api/keys/set-duration", async (req, reply) => {
	const { key, expiresAt } = req.body ?? {};
	if (!key) return reply.code(400).send({ error: "No key provided" });
	const passwords = loadPasswords();
	if (!passwords.includes(key)) return reply.code(404).send({ error: "Key not found" });
	const meta = loadKeyMeta();
	meta[key] = { expiresAt: expiresAt === null ? null : Number(expiresAt) };
	saveKeyMeta(meta);
	return reply.send({ ok: true });
});

// ── Admin API: Sessions ───────────────────────────────────────────────────────
fastify.post("/admin/api/sessions/revoke", async (req, reply) => {
	const { token } = req.body ?? {};
	if (!token) return reply.code(400).send({ error: "No token provided" });
	sessions.delete(token);
	return reply.send({ ok: true });
});

fastify.post("/admin/api/sessions/revokeAll", async (req, reply) => {
	for (const [token, session] of sessions) {
		if (!session.isAdmin) sessions.delete(token);
	}
	return reply.send({ ok: true });
});

// ── Admin API: Announcements ──────────────────────────────────────────────────
fastify.post("/admin/api/announcements/add", async (req, reply) => {
	const { text } = req.body ?? {};
	if (!text || text.trim().length === 0)
		return reply.code(400).send({ error: "Empty announcement" });
	const list = loadAnnouncements();
	list.push(text.trim());
	saveAnnouncements(list);
	return reply.send({ ok: true, announcements: list });
});

fastify.post("/admin/api/announcements/delete", async (req, reply) => {
	const { index } = req.body ?? {};
	const list = loadAnnouncements();
	if (index < 0 || index >= list.length)
		return reply.code(400).send({ error: "Invalid index" });
	list.splice(index, 1);
	saveAnnouncements(list);
	return reply.send({ ok: true, announcements: list });
});

// ── Public API: Announcements ─────────────────────────────────────────────────
fastify.get("/api/announcements", async (req, reply) => {
	return reply.send({ announcements: loadAnnouncements() });
});

// ── Public API: Chat ──────────────────────────────────────────────────────────
fastify.get("/api/chat", async (req, reply) => {
	return reply.send({ messages: loadChat().slice(-50) });
});

fastify.post("/api/chat/send", async (req, reply) => {
	const { username, text } = req.body ?? {};
	if (!text || text.trim().length === 0)
		return reply.code(400).send({ error: "Empty message" });
	const token = getTokenFromCookie(req.headers.cookie);
	const isAdmin = sessions.get(token)?.isAdmin === true;
	const msg = {
		username: (username || "Anonymous").slice(0, 20).replace(/</g, "&lt;"),
		text: text.trim().slice(0, 300).replace(/</g, "&lt;"),
		timestamp: Date.now(),
		isAdmin,
	};
	const msgs = loadChat();
	msgs.push(msg);
	if (msgs.length > MAX_CHAT) msgs.shift();
	saveChat(msgs);
	return reply.send({ ok: true });
});

// ── Admin API: Chat ───────────────────────────────────────────────────────────
fastify.post("/admin/api/chat/delete", async (req, reply) => {
	const { index } = req.body ?? {};
	const msgs = loadChat();
	if (index < 0 || index >= msgs.length)
		return reply.code(400).send({ error: "Invalid index" });
	msgs.splice(index, 1);
	saveChat(msgs);
	return reply.send({ ok: true, messages: msgs });
});

fastify.post("/admin/api/chat/clear", async (req, reply) => {
	saveChat([]);
	return reply.send({ ok: true });
});

// ── Static File Routes ────────────────────────────────────────────────────────
fastify.register(fastifyStatic, { root: publicPath, decorateReply: true });
fastify.register(fastifyStatic, { root: scramjetPath, prefix: "/scram/", decorateReply: false });
fastify.register(fastifyStatic, { root: libcurlPath, prefix: "/libcurl/", decorateReply: false });
fastify.register(fastifyStatic, { root: baremuxPath, prefix: "/baremux/", decorateReply: false });

fastify.setNotFoundHandler((_req, reply) => {
	return reply.code(404).type("text/html").sendFile("404.html");
});

// ── Startup / Shutdown ────────────────────────────────────────────────────────
fastify.server.on("listening", () => {
	const address = fastify.server.address();
	console.log("Scramjet proxy running (password protected)");
	console.log(`\thttp://localhost:${address.port}`);
	console.log(`\thttp://${hostname()}:${address.port}`);
	console.log(`\thttp://${address.family === "IPv6" ? `[${address.address}]` : address.address}:${address.port}`);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function shutdown() {
	console.log("SIGTERM signal received: closing HTTP server");
	fastify.close();
	process.exit(0);
}

let port = parseInt(process.env.PORT || "");
if (isNaN(port)) port = 8080;
fastify.listen({ port, host: "0.0.0.0" });
