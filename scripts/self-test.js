"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawn, spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const TEMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "vtuber-nexus-selftest-"));
const PORT = 33000 + Math.floor(Math.random() * 2000);
const BASE = `http://127.0.0.1:${PORT}`;
const DB_PATH = path.join(TEMP_ROOT, "test.db");
const UPLOAD_DIR = path.join(TEMP_ROOT, "uploads");
const MEDIA_DIR = path.join(TEMP_ROOT, "media");
const BACKUP_DIR = path.join(TEMP_ROOT, "backups");
const SESSION_DIR = path.join(TEMP_ROOT, "sessions");
const serverLog = [];
const tests = [];
let server;

function record(name, ok, detail = "") {
  tests.push({ name, ok, detail });
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? `: ${detail}` : ""}`);
}

function assert(name, condition, detail = "") {
  record(name, Boolean(condition), detail);
  if (!condition) throw new Error(`${name}${detail ? `: ${detail}` : ""}`);
}

function seedDatabase() {
  const seedCode = String.raw`
    const crypto = require("crypto");
    const { readData, writeData, closeDatabase } = require("./database");
    function hashPassword(password) {
      const salt = crypto.randomBytes(16).toString("hex");
      const hash = crypto.scryptSync(password, salt, 64).toString("hex");
      return salt + ":" + hash;
    }
    const data = readData();
    const profileDesign = {
      theme: "nexus", primaryColor: "#7c5cff", accentColor: "#35e0d0",
      backgroundColor: "#090b16", backgroundStyle: "gradient",
      cardStyle: "glass", backgroundImage: ""
    };
    const base = {
      bio: "Automatisches Testkonto", tags: [], schedule: [], languages: [],
      favoriteGames: [], clips: [], profileDesign,
      notificationPreferences: { applications: true, contacts: true, events: true, profileUpdates: true }
    };
    data.members = [
      { ...base, id: "audit-founder", name: "Audit Founder", role: "founder", account: { enabled: true, username: "auditfounder", passwordHash: hashPassword("AuditFounder123!") } },
      { ...base, id: "audit-moderator", name: "Audit Moderator", role: "moderator", account: { enabled: true, username: "auditmoderator", passwordHash: hashPassword("AuditModerator123!") } },
      { ...base, id: "audit-member", name: "Audit Member", role: "member", account: { enabled: true, username: "auditmember", passwordHash: hashPassword("AuditMember123!") } }
    ];
    writeData(data);
    closeDatabase();
  `;
  const result = spawnSync(process.execPath, ["-e", seedCode], {
    cwd: ROOT,
    env: { ...process.env, DATABASE_PATH: DB_PATH },
    encoding: "utf8"
  });
  if (result.status !== 0) throw new Error(result.stderr || "Testdatenbank konnte nicht erstellt werden.");
}

class Client {
  constructor() { this.cookie = ""; }
  async request(route, options = {}) {
    const headers = new Headers(options.headers || {});
    if (this.cookie) headers.set("cookie", this.cookie);
    const response = await fetch(`${BASE}${route}`, { redirect: "manual", ...options, headers });
    const setCookie = response.headers.get("set-cookie");
    if (setCookie) this.cookie = setCookie.split(";", 1)[0];
    return response;
  }
  async form(route, values) {
    return this.request(route, { method: "POST", body: new URLSearchParams(values) });
  }
}

async function waitForServer() {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${BASE}/health`);
      if (response.ok) return;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error(`Serverstart fehlgeschlagen.\n${serverLog.join("")}`);
}

async function login(username, password) {
  const client = new Client();
  const response = await client.form("/member-login", { username, password });
  return { client, response };
}

async function run() {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  fs.mkdirSync(MEDIA_DIR, { recursive: true });
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  fs.mkdirSync(SESSION_DIR, { recursive: true });
  seedDatabase();

  server = spawn(process.execPath, ["server.js"], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(PORT),
      NODE_ENV: "development",
      ADMIN_PASSWORD: "AuditLegacyAdmin123!",
      SESSION_SECRET: "Audit-Self-Test-Session-Secret-Long-Enough",
      DATABASE_PATH: DB_PATH,
      UPLOAD_DIR,
      MEDIA_DIR,
      BACKUP_DIR,
      SESSION_DIR,
      AUTO_BACKUP: "false",
      TWITCH_CLIENT_ID: "",
      TWITCH_CLIENT_SECRET: ""
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  server.stdout.on("data", chunk => serverLog.push(chunk.toString()));
  server.stderr.on("data", chunk => serverLog.push(chunk.toString()));
  await waitForServer();

  const publicRoutes = ["/", "/live", "/schedule", "/events", "/apply", "/impressum", "/datenschutz", "/kontakt", "/news", "/search", "/members", "/health"];
  for (const route of publicRoutes) {
    const response = await fetch(`${BASE}${route}`, { redirect: "manual" });
    assert(`Öffentliche Route ${route}`, response.status === 200, String(response.status));
  }

  let response = await fetch(`${BASE}/`, { redirect: "manual" });
  assert("Helmet-Sicherheitsheader", response.headers.get("x-content-type-options") === "nosniff", String(response.headers.get("x-content-type-options")));

  response = await fetch(`${BASE}/contact`, { redirect: "manual" });
  assert("Kontakt-Alias", response.status === 301 && response.headers.get("location") === "/kontakt", `${response.status} ${response.headers.get("location")}`);

  response = await fetch(`${BASE}/nicht-vorhanden`);
  assert("404-Seite", response.status === 404 && (await response.text()).includes("404"), String(response.status));

  response = await fetch(`${BASE}/admin`, { redirect: "manual" });
  assert("Gast wird bei Adminseite umgeleitet", response.status === 302 && response.headers.get("location").includes("/member-login"), `${response.status}`);

  const founderLogin = await login("auditfounder", "AuditFounder123!");
  assert("Gründer-Login", founderLogin.response.status === 302 && founderLogin.response.headers.get("location") === "/admin", String(founderLogin.response.status));
  const founderCookie = founderLogin.response.headers.get("set-cookie") || "";
  assert("Sicheres Sitzungscookie", /HttpOnly/i.test(founderCookie) && /SameSite=Lax/i.test(founderCookie), founderCookie.replace(/vn\.sid=[^;]+/, "vn.sid=<redacted>"));
  const founder = founderLogin.client;

  const moderatorLogin = await login("auditmoderator", "AuditModerator123!");
  assert("Moderator-Login", moderatorLogin.response.status === 302, String(moderatorLogin.response.status));
  const moderator = moderatorLogin.client;

  const memberLogin = await login("auditmember", "AuditMember123!");
  assert("Mitglieder-Login", memberLogin.response.status === 302 && memberLogin.response.headers.get("location") === "/member-area", String(memberLogin.response.status));
  const member = memberLogin.client;

  response = await founder.request("/admin");
  const adminHtml = await response.text();
  assert("Adminseite rendert", response.status === 200 && adminHtml.includes("Systemprüfung"), String(response.status));
  assert("Adminseite nicht im Browsercache", (response.headers.get("cache-control") || "").includes("no-store"), String(response.headers.get("cache-control")));
  assert("Feste Admin-Seitenleiste vorhanden", adminHtml.includes("admin-side-nav"), "Markierung gefunden");

  response = await moderator.request("/admin/system-check/download");
  assert("Moderator darf Gründerbericht nicht laden", response.status === 403, String(response.status));
  response = await member.request("/admin");
  assert("Mitglied erhält 403 im Adminbereich", response.status === 403, String(response.status));

  response = await founder.request("/admin/system-check/download");
  const systemReport = await response.text();
  assert("Systembericht funktioniert", response.status === 200 && systemReport.includes("SQLite-Integritätsprüfung bestanden"), String(response.status));
  assert("Systembericht verrät keine Geheimwerte", !systemReport.includes("Audit-Self-Test-Session-Secret"), "keine Secrets");

  response = await founder.request("/admin/backups/create", { method: "POST" });
  assert("SQLite-Backup erstellen", response.status === 302 && response.headers.get("location").includes("backup=created"), String(response.status));
  const backupNames = fs.readdirSync(BACKUP_DIR).filter(name => name.endsWith(".db"));
  assert("Backup-Datei erzeugt", backupNames.length === 1, backupNames.join(", "));

  response = await founder.request(`/admin/backups/${encodeURIComponent(backupNames[0])}/download`);
  const backupBytes = new Uint8Array(await response.arrayBuffer());
  assert("Backup herunterladen", response.status === 200 && backupBytes.length > 1000, `${response.status}, ${backupBytes.length} Bytes`);

  response = await founder.request(`/admin/backups/${encodeURIComponent(backupNames[0])}/restore`, { method: "POST" });
  assert("SQLite-Backup wiederherstellen", response.status === 302 && response.headers.get("location").includes("backup=restored"), String(response.status));

  response = await member.request("/member-area/media");
  assert("Medienbereich öffnet", response.status === 200, String(response.status));

  const mediaForm = new FormData();
  mediaForm.set("title", "Audit Testdatei");
  mediaForm.set("description", "Automatischer Test");
  mediaForm.set("category", "Dokument");
  mediaForm.set("visibility", "all");
  mediaForm.set("mediaFile", new Blob(["VTuber Nexus Selbsttest"], { type: "text/plain" }), "audit.txt");
  response = await member.request("/member-area/media", { method: "POST", body: mediaForm });
  assert("Mediendatei hochladen", response.status === 302, String(response.status));

  const stateJson = spawnSync(process.execPath, ["-e", 'const {readData,closeDatabase}=require("./database");console.log(JSON.stringify(readData()));closeDatabase();'], {
    cwd: ROOT, env: { ...process.env, DATABASE_PATH: DB_PATH }, encoding: "utf8"
  });
  const state = JSON.parse(stateJson.stdout.trim().split("\n").at(-1));
  const media = state.mediaFiles.find(item => item.title === "Audit Testdatei");
  assert("Medieneintrag gespeichert", Boolean(media), media?.id || "fehlt");

  response = await member.request(`/member-area/media/${media.id}/file`);
  assert("Mediendatei herunterladen", response.status === 200 && (await response.text()).includes("Selbsttest"), String(response.status));
  response = await member.request(`/member-area/media/${media.id}/delete`, { method: "POST" });
  assert("Eigene Mediendatei löschen", response.status === 302, String(response.status));

  response = await founder.request("/admin/backup");
  const jsonBackup = await response.text();
  assert("JSON-Backup exportieren", response.status === 200 && JSON.parse(jsonBackup).group, String(response.status));

  const jsonForm = new FormData();
  jsonForm.set("backupFile", new Blob([jsonBackup], { type: "application/json" }), "backup.json");
  response = await founder.request("/admin/restore", { method: "POST", body: jsonForm });
  assert("JSON-Backup wiederherstellen", response.status === 302 && response.headers.get("location").includes("json-restored"), String(response.status));

  const wrongBackupForm = new FormData();
  wrongBackupForm.set("backupFile", new Blob(["falsch"], { type: "text/plain" }), "backup.txt");
  response = await founder.request("/admin/restore", { method: "POST", body: wrongBackupForm });
  assert("Falsches Backupformat wird als Eingabefehler abgelehnt", response.status === 400, String(response.status));

  fs.writeFileSync(path.join(BACKUP_DIR, "nexus-ungueltig.db"), "keine sqlite datei", "utf8");
  response = await founder.request("/admin");
  const invalidHtml = await response.text();
  assert("Ungültiges Backup wird erkannt", response.status === 200 && invalidHtml.includes("UNGÜLTIG"), String(response.status));
  response = await founder.request("/admin/system-check/download");
  const invalidReport = await response.text();
  assert("Systemprüfung warnt vor ungültigem Backup", invalidReport.includes("[WARNUNG] Backup-Integrität"), "Warnung vorhanden");

  response = await member.request("/member-logout", { method: "POST" });
  assert("Logout funktioniert", response.status === 302 && response.headers.get("location").includes("loggedOut=1"), String(response.status));
  response = await member.request("/member-area", { redirect: "manual" });
  assert("Sitzung nach Logout beendet", response.status === 302 && response.headers.get("location").includes("/member-login"), String(response.status));

  const lockClient = new Client();
  let lastStatus = 0;
  for (let index = 0; index < 6; index += 1) {
    const locked = await lockClient.form("/member-login", { username: "audit-unknown", password: "falsch" });
    lastStatus = locked.status;
  }
  assert("Login-Sperre reagiert", lastStatus === 429, String(lastStatus));
}

(async () => {
  try {
    await run();
  } catch (error) {
    if (!tests.some(test => !test.ok)) record("Unerwarteter Testfehler", false, error.stack || error.message);
  } finally {
    if (server && !server.killed) {
      server.kill("SIGTERM");
      await new Promise(resolve => setTimeout(resolve, 500));
      if (!server.killed) server.kill("SIGKILL");
    }
    fs.rmSync(TEMP_ROOT, { recursive: true, force: true });

    const failed = tests.filter(test => !test.ok);
    console.log(`\nSelbsttest: ${tests.length - failed.length}/${tests.length} bestanden.`);
    if (failed.length) {
      console.error("\nFehler:");
      failed.forEach(test => console.error(`- ${test.name}: ${test.detail}`));
      if (serverLog.length) console.error(`\nServerprotokoll:\n${serverLog.join("")}`);
      process.exitCode = 1;
    }
  }
})();
