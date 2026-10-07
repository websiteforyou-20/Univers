require("dotenv").config();

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const multer = require("multer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const FileStore = require("session-file-store")(session);
const PACKAGE_INFO = require("./package.json");
const APP_VERSION = PACKAGE_INFO.version;
const {
  DB_FILE,
  readData,
  writeData,
  exportJson,
  importJson,
  closeDatabase,
  checkpointDatabase,
  readBackupState,
  checkDatabaseIntegrity
} = require("./database");
const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const SITE_URL = String(process.env.SITE_URL || "").trim().replace(/\/+$/, "");
const FORCE_HTTPS =
  IS_PRODUCTION && String(process.env.FORCE_HTTPS || "true") !== "false";
const PUBLIC_INDEXING =
  String(process.env.PUBLIC_INDEXING || "false") === "true";
const CSRF_ALLOW_NO_ORIGIN =
  !IS_PRODUCTION ||
  String(process.env.CSRF_ALLOW_NO_ORIGIN || "false") === "true";
const SESSION_HOURS = Math.max(
  1,
  Math.min(72, Number(process.env.SESSION_HOURS || 8))
);
const SESSION_SAME_SITE = ["lax", "strict", "none"].includes(
  String(process.env.SESSION_SAME_SITE || "lax").toLowerCase()
)
  ? String(process.env.SESSION_SAME_SITE || "lax").toLowerCase()
  : "lax";

app.disable("x-powered-by");

const trustProxyValue = String(
  process.env.TRUST_PROXY || (IS_PRODUCTION ? "1" : "false")
).trim();

if (trustProxyValue !== "false" && trustProxyValue !== "0") {
  const numericTrust = Number(trustProxyValue);
  app.set(
    "trust proxy",
    Number.isFinite(numericTrust) ? numericTrust : trustProxyValue
  );
}

function parsedSiteUrl() {
  if (!SITE_URL) return null;

  try {
    return new URL(SITE_URL);
  } catch {
    return null;
  }
}

function configuredAllowedHosts() {
  const hosts = new Set(
    String(process.env.ALLOWED_HOSTS || "")
      .split(",")
      .map(value => value.trim().toLowerCase())
      .filter(Boolean)
  );

  const site = parsedSiteUrl();
  if (site?.hostname) hosts.add(site.hostname.toLowerCase());

  return hosts;
}

function productionConfigurationProblems() {
  const problems = [];
  const adminPassword = String(process.env.ADMIN_PASSWORD || "");
  const sessionSecret = String(process.env.SESSION_SECRET || "");
  const site = parsedSiteUrl();

  if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
    problems.push("PORT muss eine gültige Zahl zwischen 1 und 65535 sein.");
  }

  if (adminPassword.length < 12) {
    problems.push("ADMIN_PASSWORD muss mindestens 12 Zeichen lang sein.");
  }

  if (
    ["admin123", "password", "passwort", "hier_ein_sicheres_passwort"]
      .includes(adminPassword.toLowerCase())
  ) {
    problems.push("ADMIN_PASSWORD darf kein bekanntes Standardpasswort sein.");
  }

  if (sessionSecret.length < 32) {
    problems.push("SESSION_SECRET muss mindestens 32 Zeichen lang sein.");
  }

  if (
    !sessionSecret ||
    sessionSecret === "bitte-in-env-aendern" ||
    /hier.*zuf[aä]llige/i.test(sessionSecret)
  ) {
    problems.push("SESSION_SECRET muss durch einen echten Zufallswert ersetzt werden.");
  }

  if (!site) {
    problems.push("SITE_URL fehlt oder ist ungültig.");
  } else if (
    site.protocol !== "https:" &&
    String(process.env.ALLOW_HTTP_SITE_URL || "false") !== "true"
  ) {
    problems.push("SITE_URL muss im Produktionsbetrieb mit https:// beginnen.");
  }

  if (
    SESSION_SAME_SITE === "none" &&
    String(process.env.SESSION_SECURE || "true") === "false"
  ) {
    problems.push(
      "SESSION_SAME_SITE=none ist nur zusammen mit sicheren Cookies erlaubt."
    );
  }

  const twitchId = Boolean(String(process.env.TWITCH_CLIENT_ID || "").trim());
  const twitchSecret = Boolean(
    String(process.env.TWITCH_CLIENT_SECRET || "").trim()
  );

  if (twitchId !== twitchSecret) {
    problems.push(
      "TWITCH_CLIENT_ID und TWITCH_CLIENT_SECRET müssen gemeinsam gesetzt werden."
    );
  }

  return problems;
}
const UPLOAD_DIR = process.env.UPLOAD_DIR
  ? path.resolve(process.env.UPLOAD_DIR)
  : path.join(__dirname, "public", "uploads");
const MEDIA_DIR = process.env.MEDIA_DIR
  ? path.resolve(process.env.MEDIA_DIR)
  : path.join(__dirname, "data", "media");
const BACKUP_DIR = process.env.BACKUP_DIR
  ? path.resolve(process.env.BACKUP_DIR)
  : path.join(__dirname, "data", "backups");
const SESSION_DIR = process.env.SESSION_DIR
  ? path.resolve(process.env.SESSION_DIR)
  : path.join(__dirname, "data", "sessions");
const AUTO_BACKUP_ENABLED = process.env.AUTO_BACKUP !== "false";

fs.mkdirSync(path.join(__dirname, "data"), { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(MEDIA_DIR, { recursive: true });
fs.mkdirSync(BACKUP_DIR, { recursive: true });
fs.mkdirSync(SESSION_DIR, { recursive: true });


function addActivity(data, type, message) {
  data.activityLog = data.activityLog || [];
  data.activityLog.unshift({
    id: `activity-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`,
    type,
    message,
    createdAt: new Date().toISOString()
  });
  data.activityLog = data.activityLog.slice(0, 100);
}


function escapeIcalText(value) {
  return String(value || "")
    .replace(/\\/g, "\\\\")
    .replace(/\n/g, "\\n")
    .replace(/,/g, "\\,")
    .replace(/;/g, "\\;");
}

function eventDateTime(event) {
  const date = String(event.date || "").replace(/-/g, "");
  const time = String(event.time || "00:00").replace(":", "");
  return `${date}T${time}00`;
}

function normalizeSearch(value) {
  return String(value || "").trim().toLowerCase();
}

function slugify(value) {
  return String(value)
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}


function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}


function secureTextEqual(left, right) {
  const leftBuffer = Buffer.from(String(left || ""), "utf8");
  const rightBuffer = Buffer.from(String(right || ""), "utf8");

  if (!leftBuffer.length || leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function verifyPassword(password, storedValue) {
  try {
    const [salt, storedHash] = String(storedValue || "").split(":");
    if (!salt || !storedHash) return false;

    const calculated = crypto.scryptSync(password, salt, 64);
    const stored = Buffer.from(storedHash, "hex");

    if (calculated.length !== stored.length) return false;
    return crypto.timingSafeEqual(calculated, stored);
  } catch {
    return false;
  }
}

function requireMember(req, res, next) {
  if (req.session?.memberId) {
    const data = readData();
    const memberExists = data.members.some(
      member => member.id === req.session.memberId
    );

    if (memberExists) return next();
    delete req.session.memberId;
  }

  const returnTo = req.method === "GET"
    ? `?returnTo=${encodeURIComponent(req.originalUrl || "/member-area")}`
    : "";

  return res.redirect(`/member-login${returnTo}`);
}

function normalizeProfileBio(value) {
  return String(value || "").trim().slice(0, 200);
}

function editableMemberFields(req, existing) {
  return {
    ...existing,
    bio: normalizeProfileBio(req.body.bio),
    streamTitle: String(req.body.streamTitle || "").trim(),
    tags: String(req.body.tags || "")
      .split(",")
      .map(value => value.trim())
      .filter(Boolean),
    schedule: String(req.body.schedule || "")
      .split(",")
      .map(value => value.trim())
      .filter(Boolean),
    twitch: String(req.body.twitch || "").trim(),
    twitchLogin: String(req.body.twitchLogin || "")
      .trim()
      .replace(/^@/, "")
      .toLowerCase(),
    youtube: String(req.body.youtube || "").trim(),
    tiktok: String(req.body.tiktok || "").trim(),
    discord: String(req.body.discord || "").trim(),
    pronouns: String(req.body.pronouns || "").trim(),
    languages: String(req.body.languages || "")
      .split(",")
      .map(value => value.trim())
      .filter(Boolean),
    favoriteGames: String(req.body.favoriteGames || "")
      .split(",")
      .map(value => value.trim())
      .filter(Boolean),
    debutDate: String(req.body.debutDate || "").trim(),
    artist: String(req.body.artist || "").trim(),
    rigger: String(req.body.rigger || "").trim(),
    clips: String(req.body.clips || "")
      .split(",")
      .map(value => value.trim())
      .filter(Boolean)
  };
}



function normalizeContactPreference(body = {}) {
  const method = body.contactMethod === "email" ? "email" : "discord";

  return {
    method,
    email: method === "email" ? String(body.email || "").trim() : "",
    discordName: method === "discord" ? String(body.discordName || "").trim() : "",
    discordId: method === "discord" ? String(body.discordId || "").trim() : ""
  };
}

function validateContactPreference(contact) {
  if (contact.method === "email") {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact.email)) {
      return "Bitte gib eine gültige E-Mail-Adresse ein.";
    }
  } else if (!contact.discordName || !/^\d{15,22}$/.test(contact.discordId)) {
    return "Bitte gib deinen vollständigen Discord-Namen und eine gültige numerische Discord-ID ein.";
  }

  return "";
}

let twitchTokenCache = { token: "", expiresAt: 0 };

function twitchConfigured() {
  return Boolean(process.env.TWITCH_CLIENT_ID && process.env.TWITCH_CLIENT_SECRET);
}

async function getTwitchAppToken() {
  if (!twitchConfigured()) return null;

  if (
    twitchTokenCache.token &&
    twitchTokenCache.expiresAt > Date.now() + 60_000
  ) {
    return twitchTokenCache.token;
  }

  const response = await fetch("https://id.twitch.tv/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: process.env.TWITCH_CLIENT_ID,
      client_secret: process.env.TWITCH_CLIENT_SECRET,
      grant_type: "client_credentials"
    })
  });

  if (!response.ok) {
    throw new Error(`Twitch-Tokenfehler ${response.status}`);
  }

  const payload = await response.json();
  twitchTokenCache = {
    token: payload.access_token,
    expiresAt: Date.now() + Number(payload.expires_in || 3600) * 1000
  };
  return twitchTokenCache.token;
}

async function enrichMembersWithTwitch(originalData) {
  const data = JSON.parse(JSON.stringify(originalData));
  const logins = [...new Set(
    data.members
      .map(member => String(member.twitchLogin || "").trim().toLowerCase())
      .filter(Boolean)
  )];

  const liveByLogin = new Map();
  data.twitchConfigured = twitchConfigured();
  data.twitchError = "";

  if (data.twitchConfigured && logins.length) {
    try {
      const token = await getTwitchAppToken();

      for (let i = 0; i < logins.length; i += 100) {
        const params = new URLSearchParams();
        logins.slice(i, i + 100).forEach(login => params.append("user_login", login));

        const response = await fetch(
          `https://api.twitch.tv/helix/streams?${params.toString()}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
              "Client-Id": process.env.TWITCH_CLIENT_ID
            }
          }
        );

        if (!response.ok) {
          throw new Error(`Twitch-Live-Abfrage ${response.status}`);
        }

        const payload = await response.json();
        for (const stream of payload.data || []) {
          liveByLogin.set(stream.user_login.toLowerCase(), {
            ...stream,
            thumbnail: stream.thumbnail_url
              .replace("{width}", "640")
              .replace("{height}", "360")
          });
        }
      }
    } catch (error) {
      console.error("Twitch:", error.message);
      data.twitchError = error.message;
    }
  }

  data.members = data.members.map(member => {
    const login = String(member.twitchLogin || "").trim().toLowerCase();
    const twitchStream = liveByLogin.get(login) || null;
    return {
      ...member,
      twitchStream,
      effectiveLive: Boolean(twitchStream) || Boolean(member.live)
    };
  });

  return data;
}

const ROLE_PERMISSION_CATALOG = [
  {
    key: "admin.access",
    group: "Grundzugriff",
    label: "Admin-Bereich öffnen",
    description: "Darf die Verwaltungsoberfläche öffnen. Ohne dieses Recht bleiben alle anderen Admin-Rechte praktisch unsichtbar."
  },
  {
    key: "communications.manage",
    group: "Team",
    label: "Nachrichten & Aufgaben",
    description: "Interne Nachrichten senden/löschen und Aufgaben für Mitglieder verwalten."
  },
  {
    key: "members.manage",
    group: "Mitglieder",
    label: "Mitgliederprofile verwalten",
    description: "Profile anlegen, bearbeiten und Live-Status ändern. Rollen bleiben Gründer-Sache."
  },
  {
    key: "members.delete",
    group: "Mitglieder",
    label: "Mitglieder löschen",
    description: "Darf Mitgliederprofile endgültig löschen. Gründerprofile bleiben immer geschützt."
  },
  {
    key: "member_accounts.manage",
    group: "Mitglieder",
    label: "Mitgliederkonten verwalten",
    description: "Login-Namen, Passwörter und Kontozugänge der Mitglieder verwalten."
  },
  {
    key: "events.manage",
    group: "Inhalte",
    label: "Events & Kalender verwalten",
    description: "Öffentliche Events, Teamkalender und Event-Anmeldungen verwalten."
  },
  {
    key: "requests.manage",
    group: "Inhalte",
    label: "Bewerbungen & Kontakt verwalten",
    description: "Bewerbungen und Kontaktanfragen lesen, bearbeiten und löschen."
  },
  {
    key: "news.manage",
    group: "Inhalte",
    label: "News verwalten",
    description: "News erstellen, veröffentlichen, ausblenden und löschen."
  },
  {
    key: "community.manage",
    group: "Community",
    label: "Pinnwand moderieren",
    description: "Community-Beiträge anheften und löschen."
  },
  {
    key: "projects.manage",
    group: "Community",
    label: "Projekte verwalten",
    description: "Teamprojekte erstellen, bearbeiten und löschen."
  },
  {
    key: "media.manage",
    group: "Community",
    label: "Medien verwalten",
    description: "Dateien im Admin-Medienbereich endgültig löschen."
  },
  {
    key: "polls.manage",
    group: "Community",
    label: "Abstimmungen verwalten",
    description: "Umfragen erstellen, anheften und löschen."
  },
  {
    key: "group.manage",
    group: "Gestaltung",
    label: "Gruppeninhalte verwalten",
    description: "Leitsatz, Beschreibung und Startseitenbanner ändern."
  },
  {
    key: "branding.manage",
    group: "Gestaltung",
    label: "Branding verwalten",
    description: "Website-Name, Logo, Kürzel, Favicon und Branding-Daten ändern."
  },
  {
    key: "appearance.manage",
    group: "Gestaltung",
    label: "Website-Design verwalten",
    description: "Website-Hintergrund, Kopfzeile und Design-Studio ändern."
  },
  {
    key: "animations.manage",
    group: "Gestaltung",
    label: "Animationen verwalten",
    description: "Globale Website-Animationen einstellen."
  },
  {
    key: "security.manage",
    group: "Sicherheit",
    label: "Sicherheit & Backups",
    description: "Systemprüfung, Sitzungen, Sicherheitsprotokoll und Backups verwalten."
  },
  {
    key: "legal.manage",
    group: "Sicherheit",
    label: "Rechtliche Angaben verwalten",
    description: "Impressum- und Datenschutzangaben bearbeiten."
  }
];

const ROLE_PERMISSION_KEYS = new Set(
  ROLE_PERMISSION_CATALOG.map(permission => permission.key)
);

function normalizedRole(member) {
  const explicitRaw = String(member?.roleId || "").trim().toLowerCase();

  if (["gründer", "gruender", "grunder", "founder"].includes(explicitRaw)) {
    return "founder";
  }
  if (["moderator", "moderatorin", "mod"].includes(explicitRaw)) {
    return "moderator";
  }
  if (["mitglied", "member"].includes(explicitRaw)) {
    return "member";
  }
  if (explicitRaw) return explicitRaw;

  const role = String(member?.role || "").trim().toLowerCase();
  if (["gründer", "gruender", "grunder", "founder"].includes(role)) return "founder";
  if (["moderator", "moderatorin", "mod"].includes(role)) return "moderator";
  if (["mitglied", "member"].includes(role)) return "member";
  return "member";
}

function roleDefinitionById(data, roleId) {
  return (data.roles || []).find(role => role.id === roleId) ||
    (data.roles || []).find(role => role.id === "member") ||
    {
      id: "member",
      name: "Mitglied",
      color: "#35d0b1",
      permissions: []
    };
}

function roleDefinitionForMember(data, member) {
  return roleDefinitionById(data, normalizedRole(member));
}

function accessHasPermission(access, permission) {
  if (!access) return false;
  if (access.isFounder) return true;
  const permissions = Array.isArray(access.permissions)
    ? access.permissions
    : [];
  return permissions.includes("*") || permissions.includes(permission);
}

function cleanRolePermissions(raw) {
  const values = Array.isArray(raw)
    ? raw
    : raw
      ? [raw]
      : [];

  const permissions = [...new Set(
    values
      .map(value => String(value || "").trim())
      .filter(value => ROLE_PERMISSION_KEYS.has(value))
  )];

  // Verwaltungsrechte benötigen immer den Grundzugriff.
  if (permissions.includes("members.delete") && !permissions.includes("members.manage")) {
    permissions.push("members.manage");
  }

  if (permissions.includes("member_accounts.manage") && !permissions.includes("members.manage")) {
    permissions.push("members.manage");
  }

  if (permissions.length && !permissions.includes("admin.access")) {
    permissions.unshift("admin.access");
  }

  return [...new Set(permissions)];
}

function safeCustomRoleId(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/ß/g, "ss")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}


const PROFILE_THEMES = {
  nexus:{label:"Nexus",primaryColor:"#7c5cff",accentColor:"#35e0d0",backgroundColor:"#090b16",backgroundStyle:"gradient",cardStyle:"glass"},
  ocean:{label:"Ozean",primaryColor:"#2388ff",accentColor:"#60e6ff",backgroundColor:"#061522",backgroundStyle:"waves",cardStyle:"glass"},
  ember:{label:"Glut",primaryColor:"#ff6a3d",accentColor:"#ffd166",backgroundColor:"#1b0907",backgroundStyle:"glow",cardStyle:"solid"},
  forest:{label:"Wald",primaryColor:"#42b883",accentColor:"#b7f36b",backgroundColor:"#07140e",backgroundStyle:"aurora",cardStyle:"glass"},
  pastel:{label:"Pastell",primaryColor:"#d98cff",accentColor:"#7ee8fa",backgroundColor:"#151020",backgroundStyle:"soft",cardStyle:"soft"},
  monochrome:{label:"Monochrom",primaryColor:"#d7d7df",accentColor:"#ffffff",backgroundColor:"#0b0b0d",backgroundStyle:"minimal",cardStyle:"solid"}
};
function defaultProfileDesign(){return {theme:"nexus",...PROFILE_THEMES.nexus,backgroundImage:""};}
function validHex(v,f){return /^#[0-9a-fA-F]{6}$/.test(String(v||""))?String(v):f;}
function normalizeProfileDesign(v={}){const k=PROFILE_THEMES[v.theme]?v.theme:"nexus",t=PROFILE_THEMES[k];return {theme:k,primaryColor:validHex(v.primaryColor,t.primaryColor),accentColor:validHex(v.accentColor,t.accentColor),backgroundColor:validHex(v.backgroundColor,t.backgroundColor),backgroundStyle:["gradient","waves","glow","aurora","soft","minimal"].includes(v.backgroundStyle)?v.backgroundStyle:t.backgroundStyle,cardStyle:["glass","solid","soft"].includes(v.cardStyle)?v.cardStyle:t.cardStyle,backgroundImage:String(v.backgroundImage||"")};}

function notificationId() {
  return `notification-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
}

function addNotification(data, notification) {
  data.notifications = data.notifications || [];
  data.notifications.push({
    id: notification.id || notificationId(),
    createdAt: notification.createdAt || new Date().toISOString(),
    title: String(notification.title || "Neue Meldung"),
    message: String(notification.message || ""),
    type: String(notification.type || "info"),
    targetMemberId: notification.targetMemberId || "",
    targetRoles: Array.isArray(notification.targetRoles)
      ? notification.targetRoles
      : [],
    targetPermissions: Array.isArray(notification.targetPermissions)
      ? notification.targetPermissions
      : [],
    link: String(notification.link || ""),
    readBy: Array.isArray(notification.readBy)
      ? notification.readBy
      : []
  });

  if (data.notifications.length > 500) {
    data.notifications = data.notifications.slice(-500);
  }
}

function notificationAudienceMatches(notification, access) {
  if (!notification) return false;

  if (notification.targetMemberId) {
    return access.member?.id === notification.targetMemberId;
  }

  if (notification.targetPermissions?.length) {
    return notification.targetPermissions.some(permission =>
      accessHasPermission(access, permission)
    );
  }

  if (notification.targetRoles?.length) {
    return notification.targetRoles.includes(access.role);
  }

  return Boolean(access.member);
}

function visibleNotifications(data, access) {
  return (data.notifications || [])
    .filter(notification => notificationAudienceMatches(notification, access))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

function profileCompletion(member) {
  const checks = [
    member.avatar,
    member.banner,
    member.bio,
    member.twitch,
    member.twitchLogin,
    member.youtube || member.tiktok,
    Array.isArray(member.languages) && member.languages.length,
    Array.isArray(member.favoriteGames) && member.favoriteGames.length,
    Array.isArray(member.schedule) && member.schedule.length,
    Array.isArray(member.clips) && member.clips.length
  ];

  return Math.round(
    checks.filter(Boolean).length / checks.length * 100
  );
}

function nextMemberStream(member) {
  const schedule = Array.isArray(member.schedule) ? member.schedule : [];
  return schedule[0] || "";
}


function internalItemId(prefix) {
  return `${prefix}-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
}

function memberInbox(data, memberId) {
  const messages = (data.internalMessages || [])
    .filter(item => item.targetMemberId === memberId)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  const tasks = (data.memberTasks || [])
    .filter(item => item.targetMemberId === memberId)
    .sort((a, b) => {
      if (a.status !== b.status) return a.status === "offen" ? -1 : 1;
      return new Date(b.createdAt) - new Date(a.createdAt);
    });

  return { messages, tasks };
}


function teamEventId() {
  return `team-event-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
}

function visibleTeamEvents(data, memberId) {
  const now = new Date();

  return (data.teamEvents || [])
    .filter(event => {
      if (event.visibility !== "private") return true;
      return (event.allowedMemberIds || []).includes(memberId);
    })
    .sort((a, b) => {
      const aDate = new Date(`${a.date}T${a.time || "00:00"}`);
      const bDate = new Date(`${b.date}T${b.time || "00:00"}`);
      return aDate - bDate;
    });
}

function eventResponseFor(data, eventId, memberId) {
  return (data.eventResponses || []).find(
    item => item.eventId === eventId && item.memberId === memberId
  ) || null;
}

function eventResponseCounts(data, eventId) {
  const responses = (data.eventResponses || []).filter(
    item => item.eventId === eventId
  );

  return {
    yes: responses.filter(item => item.status === "yes").length,
    maybe: responses.filter(item => item.status === "maybe").length,
    no: responses.filter(item => item.status === "no").length
  };
}


function communityItemId(prefix) {
  return `${prefix}-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
}

function communityAuthor(data, memberId) {
  const member = data.members.find(item => item.id === memberId);
  return member
    ? { id: member.id, name: member.name, role: member.role, avatar: member.avatar || "" }
    : { id: "", name: "Gelöschtes Mitglied", role: "Mitglied", avatar: "" };
}

function communityPostView(data, post) {
  const comments = (data.communityComments || [])
    .filter(comment => comment.postId === post.id)
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
    .map(comment => ({
      ...comment,
      author: communityAuthor(data, comment.authorMemberId)
    }));

  return {
    ...post,
    author: communityAuthor(data, post.authorMemberId),
    comments,
    commentCount: comments.length
  };
}

function sortedCommunityPosts(data) {
  return (data.communityPosts || [])
    .map(post => communityPostView(data, post))
    .sort((a, b) => {
      if (Boolean(a.pinned) !== Boolean(b.pinned)) return a.pinned ? -1 : 1;
      return new Date(b.updatedAt || b.createdAt) -
        new Date(a.updatedAt || a.createdAt);
    });
}


function projectId() {
  return `project-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
}

function projectView(data, project) {
  return {
    ...project,
    leader: data.members.find(member => member.id === project.leaderMemberId) || null,
    members: (project.memberIds || [])
      .map(id => data.members.find(member => member.id === id))
      .filter(Boolean)
  };
}

function projectsForMember(data, memberId) {
  return (data.projects || [])
    .filter(project =>
      project.visibility === "all" ||
      project.leaderMemberId === memberId ||
      (project.memberIds || []).includes(memberId)
    )
    .map(project => projectView(data, project))
    .sort((a, b) => new Date(b.updatedAt || b.createdAt) - new Date(a.updatedAt || a.createdAt));
}


function mediaItemId() {
  return `media-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
}

function mediaAllowedForMember(data, media, memberId) {
  if (!media) return false;
  if (media.visibility === "all") return true;
  if (media.uploaderMemberId === memberId) return true;

  if (media.visibility === "project") {
    const project = (data.projects || []).find(item => item.id === media.projectId);
    if (!project) return false;

    return project.visibility === "all" ||
      project.leaderMemberId === memberId ||
      (project.memberIds || []).includes(memberId);
  }

  return (media.allowedMemberIds || []).includes(memberId);
}

function visibleMediaFiles(data, memberId) {
  return (data.mediaFiles || [])
    .filter(media => mediaAllowedForMember(data, media, memberId))
    .map(media => ({
      ...media,
      uploader: data.members.find(member => member.id === media.uploaderMemberId) || null,
      project: (data.projects || []).find(project => project.id === media.projectId) || null
    }))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

function mediaIsPreviewable(media) {
  return Boolean(media && (
    String(media.mimeType || "").startsWith("image/") ||
    media.mimeType === "application/pdf"
  ));
}


function pollItemId(prefix) {
  return `${prefix}-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
}

function pollIsOpen(poll) {
  if (!poll) return false;
  if (!poll.endsAt) return true;
  return new Date(poll.endsAt) > new Date();
}

function pollAllowedForMember(poll, memberId) {
  if (!poll) return false;
  if (poll.visibility === "all") return true;
  return (poll.allowedMemberIds || []).includes(memberId);
}

function pollView(data, poll, memberId) {
  const votes = (data.pollVotes || []).filter(vote => vote.pollId === poll.id);
  const ownVote = votes.find(vote => vote.memberId === memberId) || null;

  const results = (poll.options || []).map(option => ({
    ...option,
    count: votes.filter(vote => vote.optionId === option.id).length
  }));

  return {
    ...poll,
    isOpen: pollIsOpen(poll),
    ownVote,
    totalVotes: votes.length,
    results
  };
}

function visiblePolls(data, memberId) {
  return (data.polls || [])
    .filter(poll => pollAllowedForMember(poll, memberId))
    .map(poll => pollView(data, poll, memberId))
    .sort((a, b) => {
      if (Boolean(a.pinned) !== Boolean(b.pinned)) return a.pinned ? -1 : 1;
      if (a.isOpen !== b.isOpen) return a.isOpen ? -1 : 1;
      return new Date(b.createdAt) - new Date(a.createdAt);
    });
}


const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCK_MINUTES = 15;
const BACKUP_INTERVAL_MS = 24 * 60 * 60 * 1000;

function clientAddress(req) {
  return String(
    req.headers["x-forwarded-for"] ||
    req.socket?.remoteAddress ||
    "unknown"
  ).split(",")[0].trim().slice(0, 120);
}

function addSecurityLog(data, action, details = {}) {
  data.securityLog = Array.isArray(data.securityLog) ? data.securityLog : [];
  data.securityLog.unshift({
    id: `security-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`,
    action: String(action || "unknown").slice(0, 100),
    actorName: String(details.actorName || "System").slice(0, 120),
    actorRole: String(details.actorRole || "").slice(0, 80),
    target: String(details.target || "").slice(0, 240),
    ip: String(details.ip || "").slice(0, 120),
    createdAt: new Date().toISOString()
  });
  data.securityLog = data.securityLog.slice(0, 1000);
}

function loginAttemptKey(req, username) {
  return `${clientAddress(req)}|${String(username || "").toLowerCase()}`;
}

function getLoginAttempt(data, key) {
  data.loginAttempts = data.loginAttempts && typeof data.loginAttempts === "object"
    ? data.loginAttempts
    : {};
  return data.loginAttempts[key] || { count: 0, lockedUntil: "" };
}

function loginIsLocked(attempt) {
  return Boolean(
    attempt?.lockedUntil &&
    new Date(attempt.lockedUntil).getTime() > Date.now()
  );
}

function registerFailedLogin(data, key) {
  const attempt = getLoginAttempt(data, key);
  attempt.count += 1;
  attempt.lastAttemptAt = new Date().toISOString();

  if (attempt.count >= LOGIN_MAX_ATTEMPTS) {
    attempt.lockedUntil = new Date(
      Date.now() + LOGIN_LOCK_MINUTES * 60 * 1000
    ).toISOString();
  }

  data.loginAttempts[key] = attempt;
  return attempt;
}

function databaseFilePath() {
  return DB_FILE;
}

function backupName(name) {
  const safe = path.basename(String(name || ""));
  return /^nexus-.*\.db$/i.test(safe) ? safe : "";
}

function inspectDatabaseBackup(filePath) {
  try {
    readBackupState(filePath);
    return { valid: true, error: "" };
  } catch (error) {
    return {
      valid: false,
      error: String(error.message || "Ungültiges Backup").slice(0, 240)
    };
  }
}

function listDatabaseBackups() {
  return fs.readdirSync(BACKUP_DIR)
    .filter(name => /^nexus-.*\.db$/i.test(name))
    .map(name => {
      const filePath = path.join(BACKUP_DIR, name);
      const stat = fs.statSync(filePath);
      return {
        name,
        size: stat.size,
        createdAt: stat.mtime.toISOString(),
        ...inspectDatabaseBackup(filePath)
      };
    })
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

function createDatabaseBackup(reason = "manual") {
  const source = databaseFilePath();
  if (!fs.existsSync(source)) throw new Error("Datenbank fehlt.");

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const safeReason = String(reason).replace(/[^a-z0-9_-]/gi, "-").slice(0, 40);
  const filename = `nexus-${stamp}-${safeReason}.db`;
  const target = path.join(BACKUP_DIR, filename);
  const temporaryTarget = `${target}.tmp`;

  checkpointDatabase();
  fs.copyFileSync(source, temporaryTarget);

  const inspection = inspectDatabaseBackup(temporaryTarget);
  if (!inspection.valid) {
    fs.rmSync(temporaryTarget, { force: true });
    throw new Error(`Backupprüfung fehlgeschlagen: ${inspection.error}`);
  }

  fs.renameSync(temporaryTarget, target);
  return filename;
}

function cleanupOldBackups(maxFiles = 30) {
  listDatabaseBackups().slice(maxFiles).forEach(item => {
    fs.rmSync(path.join(BACKUP_DIR, item.name), { force: true });
  });
}

function listStoredSessions(data) {
  const sessionDir = SESSION_DIR;
  if (!fs.existsSync(sessionDir)) return [];

  return fs.readdirSync(sessionDir)
    .filter(name => !name.startsWith("."))
    .map(name => {
      const fullPath = path.join(sessionDir, name);
      if (!fs.statSync(fullPath).isFile()) return null;

      let memberId = "";
      try {
        const parsed = JSON.parse(fs.readFileSync(fullPath, "utf8"));
        memberId = String(parsed.memberId || parsed.session?.memberId || "");
      } catch {}

      const stat = fs.statSync(fullPath);
      return {
        name,
        memberId,
        member: data.members.find(member => member.id === memberId) || null,
        updatedAt: stat.mtime.toISOString()
      };
    })
    .filter(Boolean)
    .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
}


function directoryStatus(label, directoryPath) {
  let exists = false;
  let writable = false;
  let message = "";

  try {
    fs.mkdirSync(directoryPath, { recursive: true });
    exists = fs.existsSync(directoryPath);

    const probe = path.join(
      directoryPath,
      `.vn-write-test-${process.pid}-${Date.now()}`
    );

    fs.writeFileSync(probe, "ok", "utf8");
    fs.rmSync(probe, { force: true });
    writable = true;
    message = "Ordner vorhanden und beschreibbar.";
  } catch (error) {
    message = error.message || "Ordner konnte nicht geprüft werden.";
  }

  return {
    label,
    path: directoryPath,
    ok: exists && writable,
    exists,
    writable,
    message
  };
}

function environmentStatus() {
  const site = parsedSiteUrl();
  const adminPassword = String(process.env.ADMIN_PASSWORD || "");
  const sessionSecret = String(process.env.SESSION_SECRET || "");

  const checks = [
    {
      key: "NODE_ENV",
      required: true,
      present: process.env.NODE_ENV === "production",
      ok: !IS_PRODUCTION || process.env.NODE_ENV === "production",
      message: IS_PRODUCTION
        ? "Produktionsmodus ist aktiv."
        : "Lokal läuft die Seite im Entwicklungsmodus."
    },
    {
      key: "SITE_URL",
      required: IS_PRODUCTION,
      present: Boolean(site),
      ok:
        !IS_PRODUCTION ||
        Boolean(
          site &&
          (
            site.protocol === "https:" ||
            String(process.env.ALLOW_HTTP_SITE_URL || "false") === "true"
          )
        ),
      message: site
        ? `Öffentliche Adresse: ${site.origin}`
        : "Für den Onlinegang fehlt eine gültige SITE_URL."
    },
    {
      key: "SESSION_SECRET",
      required: true,
      present: sessionSecret.length >= 32,
      ok: !IS_PRODUCTION || sessionSecret.length >= 32,
      message: sessionSecret.length >= 32
        ? "Sitzungsschlüssel hat eine ausreichende Länge."
        : "Mindestens 32 zufällige Zeichen verwenden."
    },
    {
      key: "ADMIN_PASSWORD",
      required: IS_PRODUCTION,
      present: adminPassword.length >= 12,
      ok: !IS_PRODUCTION || adminPassword.length >= 12,
      message: adminPassword.length >= 12
        ? "Adminpasswort hat mindestens 12 Zeichen."
        : "Für den Onlinegang mindestens 12 Zeichen verwenden."
    },
    {
      key: "FORCE_HTTPS",
      required: IS_PRODUCTION,
      present: FORCE_HTTPS,
      ok: !IS_PRODUCTION || FORCE_HTTPS,
      message: FORCE_HTTPS
        ? "HTTPS-Weiterleitung ist aktiv."
        : "HTTPS-Weiterleitung ist deaktiviert."
    },
    {
      key: "TRUST_PROXY",
      required: IS_PRODUCTION,
      present: trustProxyValue !== "false" && trustProxyValue !== "0",
      ok:
        !IS_PRODUCTION ||
        (trustProxyValue !== "false" && trustProxyValue !== "0"),
      message:
        trustProxyValue !== "false" && trustProxyValue !== "0"
          ? `Proxy-Vertrauen: ${trustProxyValue}`
          : "Hinter einem Reverse Proxy muss TRUST_PROXY gesetzt sein."
    },
    {
      key: "PUBLIC_INDEXING",
      required: false,
      present: PUBLIC_INDEXING,
      ok: true,
      message: PUBLIC_INDEXING
        ? "Suchmaschinen dürfen die Website aufnehmen."
        : "Suchmaschinen werden während des Testbetriebs ausgesperrt."
    },
    {
      key: "TWITCH",
      required: false,
      present: twitchConfigured(),
      ok:
        Boolean(process.env.TWITCH_CLIENT_ID) ===
        Boolean(process.env.TWITCH_CLIENT_SECRET),
      message: twitchConfigured()
        ? "Twitch-Zugangsdaten sind vollständig."
        : "Twitch ist nicht eingerichtet oder wird nicht benötigt."
    }
  ];

  return checks;
}

function runSystemDiagnostics() {
  const data = readData();
  const databasePath = databaseFilePath();

  let databaseIntegrity = {
    ok: false,
    message: "Datenbankprüfung nicht möglich."
  };

  try {
    if (!fs.existsSync(databasePath)) {
      databaseIntegrity = {
        ok: false,
        message: `Datenbankdatei nicht gefunden: ${databasePath}`
      };
    } else {
      const stat = fs.statSync(databasePath);
      const integrity = checkDatabaseIntegrity();
      databaseIntegrity = {
        ok: integrity.ok,
        message: integrity.ok
          ? `SQLite-Integritätsprüfung bestanden (${(stat.size / 1024 / 1024).toFixed(2)} MB).`
          : `SQLite meldet: ${integrity.messages.join("; ")}`
      };
    }
  } catch (error) {
    databaseIntegrity = {
      ok: false,
      message: error.message || "Datenbankprüfung fehlgeschlagen."
    };
  }

  const directories = [
    directoryStatus("Medienordner", MEDIA_DIR),
    directoryStatus("Backupordner", BACKUP_DIR),
    directoryStatus(
      "Uploadordner",
      path.join(__dirname, "public", "uploads")
    ),
    directoryStatus(
      "Sitzungsordner",
      SESSION_DIR
    )
  ];

  const environment = environmentStatus();
  const backups = listDatabaseBackups();
  const invalidBackups = backups.filter(backup => !backup.valid);

  const checks = [
    {
      label: "Datenbank",
      ok: databaseIntegrity.ok,
      message: databaseIntegrity.message
    },
    {
      label: "Backup-Integrität",
      ok: invalidBackups.length === 0,
      message: invalidBackups.length === 0
        ? `${backups.length} Backup(s) geprüft, alle gültig.`
        : `${invalidBackups.length} ungültige Backup-Datei(en): ${invalidBackups
            .map(backup => backup.name)
            .join(", ")}`
    },
    ...directories.map(item => ({
      label: item.label,
      ok: item.ok,
      message: item.message
    })),
    ...environment.map(item => ({
      label: `.env: ${item.key}`,
      ok: item.ok,
      message: item.message
    }))
  ];

  const passed = checks.filter(item => item.ok).length;
  const warnings = checks.length - passed;

  return {
    generatedAt: new Date().toISOString(),
    version: APP_VERSION,
    checks,
    passed,
    warnings,
    directories,
    environment,
    databaseIntegrity,
    counts: {
      members: (data.members || []).length,
      mediaFiles: (data.mediaFiles || []).length,
      backups: backups.length,
      invalidBackups: invalidBackups.length,
      sessions: listStoredSessions(data).length,
      securityEntries: (data.securityLog || []).length
    }
  };
}

function diagnosticsAsText(report) {
  const lines = [
    "VTUBER NEXUS SYSTEMPRÜFUNG",
    `Version: ${report.version}`,
    `Erstellt: ${new Date(report.generatedAt).toLocaleString("de-DE")}`,
    "",
    `Bestanden: ${report.passed}`,
    `Warnungen: ${report.warnings}`,
    "",
    "PRÜFPUNKTE"
  ];

  report.checks.forEach(item => {
    lines.push(`${item.ok ? "[OK]" : "[WARNUNG]"} ${item.label}`);
    lines.push(`  ${item.message}`);
  });

  lines.push(
    "",
    "BESTAND",
    `Mitglieder: ${report.counts.members}`,
    `Mediendateien: ${report.counts.mediaFiles}`,
    `Backups: ${report.counts.backups}`,
    `Ungültige Backups: ${report.counts.invalidBackups || 0}`,
    `Sitzungen: ${report.counts.sessions}`,
    `Sicherheitsprotokolle: ${report.counts.securityEntries}`,
    "",
    "Hinweis: Der Bericht enthält keine Passwörter oder geheimen .env-Werte."
  );

  return lines.join("\r\n");
}

function memberDashboardData(data, member) {
  const roleDefinition = roleDefinitionForMember(data, member);
  const isFounder = roleDefinition.id === "founder";
  const permissions = isFounder
    ? ["*"]
    : cleanRolePermissions(roleDefinition.permissions || []);
  const access = {
    canAdmin: isFounder || permissions.includes("admin.access"),
    isFounder,
    role: roleDefinition.id,
    roleName: roleDefinition.name,
    roleColor: roleDefinition.color || "#9b6cff",
    permissions,
    member
  };

  const notifications = visibleNotifications(data, access);
  const unreadNotifications = notifications.filter(
    item => !(item.readBy || []).includes(member.id)
  );

  const inbox = memberInbox(data, member.id);
  const recentInternalMessages = inbox.messages.slice(0, 3);
  const openMemberTasks = inbox.tasks
    .filter(item => item.status !== "erledigt")
    .slice(0, 4);

  const recentPolls = visiblePolls(data, member.id).slice(0, 3);
  const recentMediaFiles = visibleMediaFiles(data, member.id).slice(0, 4);
  const recentProjects = projectsForMember(data, member.id).slice(0, 4);
  const recentCommunityPosts = sortedCommunityPosts(data).slice(0, 4);

  const teamEvents = visibleTeamEvents(data, member.id);
  const upcomingTeamEvents = teamEvents
    .filter(event => new Date(`${event.date}T${event.time || "23:59"}`) >= new Date())
    .slice(0, 4)
    .map(event => ({
      ...event,
      response: eventResponseFor(data, event.id, member.id),
      counts: eventResponseCounts(data, event.id)
    }));

  const upcomingEvents = (data.events || [])
    .filter(event => {
      const eventDate = new Date(`${event.date || ""}T${event.time || "00:00"}`);
      return Number.isFinite(eventDate.getTime()) && eventDate >= new Date();
    })
    .sort((a, b) =>
      new Date(`${a.date}T${a.time || "00:00"}`) -
      new Date(`${b.date}T${b.time || "00:00"}`)
    )
    .slice(0, 3);

  return {
    notifications,
    unreadNotifications,
    profileCompletion: profileCompletion(member),
    nextStream: nextMemberStream(member),
    upcomingEvents,
    recentInternalMessages,
    openMemberTasks,
    upcomingTeamEvents,
    recentCommunityPosts,
    recentProjects,
    recentMediaFiles,
    recentPolls
  };
}

function currentAccess(req) {
  if (req.session?.isAdmin) {
    return {
      canAdmin: true,
      isFounder: true,
      role: "founder",
      roleName: "Gründer",
      roleColor: "#f6c75b",
      permissions: ["*"],
      member: null
    };
  }

  if (!req.session?.memberId) {
    return {
      canAdmin: false,
      isFounder: false,
      role: "guest",
      roleName: "Gast",
      roleColor: "#8b91a7",
      permissions: [],
      member: null
    };
  }

  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId) || null;
  if (!member) {
    return {
      canAdmin: false,
      isFounder: false,
      role: "guest",
      roleName: "Gast",
      roleColor: "#8b91a7",
      permissions: [],
      member: null
    };
  }

  const roleDefinition = roleDefinitionForMember(data, member);
  const role = roleDefinition.id;
  const isFounder = role === "founder";
  const permissions = isFounder
    ? ["*"]
    : cleanRolePermissions(roleDefinition.permissions || []);

  return {
    canAdmin: isFounder || permissions.includes("admin.access"),
    isFounder,
    role,
    roleName: roleDefinition.name,
    roleColor: roleDefinition.color || "#9b6cff",
    permissions,
    member
  };
}

function logDeniedAccess(req, access, requiredRole) {
  const data = readData();

  addSecurityLog(data, "access-denied", {
    actorName: access.member?.name || "Gast",
    actorRole: access.role,
    target: `${req.method} ${req.originalUrl} · benötigt: ${requiredRole}`,
    ip: clientAddress(req)
  });

  writeData(data);
}

function permissionLabel(permission) {
  return ROLE_PERMISSION_CATALOG.find(item => item.key === permission)?.label || permission;
}

function requirePermission(permission) {
  return (req, res, next) => {
    const access = currentAccess(req);

    if (accessHasPermission(access, permission)) {
      req.access = access;
      return next();
    }

    const label = permissionLabel(permission);
    logDeniedAccess(req, access, label);

    if (access.role === "guest") {
      const returnTo = encodeURIComponent(req.originalUrl || "/admin");
      return res.redirect(`/member-login?returnTo=${returnTo}&reason=admin`);
    }

    return res.status(403).render("forbidden", {
      data: readData(),
      message: `Deiner Rolle fehlt die Berechtigung „${label}“.`,
      requiredRole: label,
      currentRole: access.roleName || access.role
    });
  };
}

function requireAdmin(req, res, next) {
  return requirePermission("admin.access")(req, res, next);
}

function requireFounder(req, res, next) {
  const access = currentAccess(req);

  if (access.isFounder) {
    req.access = access;
    return next();
  }

  logDeniedAccess(req, access, "Gründer");

  if (access.role === "guest") {
    const returnTo = encodeURIComponent(req.originalUrl || "/admin");
    return res.redirect(`/member-login?returnTo=${returnTo}&reason=founder`);
  }

  return res.status(403).render("forbidden", {
    data: readData(),
    message: "Diese Funktion ist ausschließlich für den Gründer freigegeben.",
    requiredRole: "Gründer",
    currentRole: access.role
  });
}


function cleanBrandText(value, fallback, maximum = 80) {
  const text = String(value || "").trim().replace(/\s+/g, " ");
  return (text || fallback).slice(0, maximum);
}

function brandAbbreviation(value, fallback = "VN") {
  const direct = String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9ÄÖÜäöüß]/g, "")
    .slice(0, 5)
    .toUpperCase();

  return direct || fallback;
}

function abbreviationFromName(name, fallback = "VN") {
  const initials = String(name || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map(word => word.charAt(0))
    .join("")
    .replace(/[^a-zA-Z0-9ÄÖÜäöüß]/g, "")
    .slice(0, 5)
    .toUpperCase();

  return initials || fallback;
}

function validHexColor(value, fallback) {
  const color = String(value || "").trim();
  return /^#[0-9a-fA-F]{6}$/.test(color) ? color : fallback;
}

function safeOverlay(value, fallback = 82) {
  const number = Number(value);
  return Number.isFinite(number)
    ? Math.max(0, Math.min(95, Math.round(number)))
    : fallback;
}


function clampNumber(value, minimum, maximum, fallback) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.round(number)));
}

function allowedChoice(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback;
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const extension = path.extname(file.originalname).toLowerCase();
    const safeExtension = [".png", ".jpg", ".jpeg", ".webp", ".gif"].includes(extension)
      ? extension
      : ".png";
    cb(null, `${Date.now()}-${crypto.randomBytes(5).toString("hex")}${safeExtension}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ["image/png", "image/jpeg", "image/webp", "image/gif"];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("Nur PNG, JPG, WEBP oder GIF sind erlaubt."));
    }
    cb(null, true);
  }
});


const mediaStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, MEDIA_DIR),
  filename: (_req, file, cb) => {
    const extension = path.extname(file.originalname).toLowerCase();
    const allowedExtensions = [
      ".png", ".jpg", ".jpeg", ".webp", ".gif",
      ".pdf", ".txt", ".json", ".docx", ".zip"
    ];
    const safeExtension = allowedExtensions.includes(extension) ? extension : "";
    cb(null, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${safeExtension}`);
  }
});

const mediaUpload = multer({
  storage: mediaStorage,
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowedMimeTypes = [
      "image/png",
      "image/jpeg",
      "image/webp",
      "image/gif",
      "application/pdf",
      "text/plain",
      "application/json",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/zip",
      "application/x-zip-compressed"
    ];

    const extension = path.extname(file.originalname).toLowerCase();
    const allowedExtensions = [
      ".png", ".jpg", ".jpeg", ".webp", ".gif",
      ".pdf", ".txt", ".json", ".docx", ".zip"
    ];

    if (!allowedMimeTypes.includes(file.mimetype) || !allowedExtensions.includes(extension)) {
      return cb(new Error("Erlaubt sind PNG, JPG, WEBP, GIF, PDF, TXT, JSON, DOCX und ZIP."));
    }

    cb(null, true);
  }
});


const backupUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const extension = path.extname(file.originalname || "").toLowerCase();
    const allowedMimeTypes = [
      "application/json",
      "text/json",
      "text/plain",
      "application/octet-stream"
    ];

    if (extension !== ".json" || !allowedMimeTypes.includes(file.mimetype)) {
      return cb(new Error("Für diese Wiederherstellung ist nur eine JSON-Datei erlaubt."));
    }

    cb(null, true);
  }
});

app.set("view engine", "ejs");
app.locals.unreadNotificationCount = 0;
app.locals.isLoggedInMember = false;
app.locals.canAdmin = false;
app.locals.isFounder = false;

app.set("views", path.join(__dirname, "views"));

app.use((req, res, next) => {
  const incomingId = String(req.get("x-request-id") || "")
    .replace(/[^a-zA-Z0-9._-]/g, "")
    .slice(0, 80);

  req.requestId = incomingId ||
    `VN-${Date.now().toString(36).toUpperCase()}-${crypto
      .randomBytes(3)
      .toString("hex")
      .toUpperCase()}`;

  res.setHeader("X-Request-ID", req.requestId);

  if (!PUBLIC_INDEXING) {
    res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive");
  }

  next();
});

app.use((req, res, next) => {
  if (!IS_PRODUCTION) return next();

  const allowedHosts = configuredAllowedHosts();
  if (!allowedHosts.size) return next();

  const hostname = String(req.hostname || "").toLowerCase();

  if (!allowedHosts.has(hostname)) {
    return res.status(400).send("Ungültiger Hostname.");
  }

  next();
});

app.use((req, res, next) => {
  if (
    !FORCE_HTTPS ||
    req.secure ||
    req.path === "/health" ||
    req.path === "/ready"
  ) {
    return next();
  }

  const site = parsedSiteUrl();
  const targetHost = site?.host || req.get("host");

  return res.redirect(
    308,
    `https://${targetHost}${req.originalUrl}`
  );
});

app.use(express.urlencoded({
  extended: true,
  limit: process.env.FORM_BODY_LIMIT || "256kb",
  parameterLimit: 250
}));

app.use((req, res, next) => {
  if (
    req.path.startsWith("/admin") ||
    req.path.startsWith("/member-area") ||
    req.path.startsWith("/member-login")
  ) {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
  }

  next();
});
app.use(express.json({ limit: process.env.JSON_BODY_LIMIT || "256kb" }));
app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
        imgSrc: ["'self'", "data:", "blob:", "https:"],
        mediaSrc: ["'self'", "https:"],
        fontSrc: ["'self'", "data:"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        connectSrc: [
          "'self'",
          "https://api.twitch.tv",
          "https://id.twitch.tv"
        ],
        upgradeInsecureRequests: IS_PRODUCTION ? [] : null
      }
    },
    hsts: IS_PRODUCTION
      ? {
          maxAge: 31536000,
          includeSubDomains: true,
          preload: false
        }
      : false,
    referrerPolicy: {
      policy: "strict-origin-when-cross-origin"
    }
  })
);

app.use((_req, res, next) => {
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
  );
  next();
});

app.use(
  session({
    name: String(process.env.SESSION_COOKIE_NAME || "vn.sid"),
    store: new FileStore({
      path: SESSION_DIR,
      ttl: 60 * 60 * SESSION_HOURS,
      retries: 1,
      reapInterval: 60 * 60
    }),
    secret: process.env.SESSION_SECRET || "bitte-in-env-aendern",
    resave: false,
    saveUninitialized: false,
    rolling: true,
    proxy: IS_PRODUCTION,
    cookie: {
      httpOnly: true,
      sameSite: SESSION_SAME_SITE,
      secure:
        IS_PRODUCTION &&
        String(process.env.SESSION_SECURE || "true") !== "false",
      domain: process.env.COOKIE_DOMAIN || undefined,
      path: "/",
      maxAge: 1000 * 60 * 60 * SESSION_HOURS
    }
  })
);


function requestSourceOrigin(req) {
  const directOrigin = String(req.get("origin") || "").trim();

  if (directOrigin && directOrigin !== "null") {
    try {
      return new URL(directOrigin).origin;
    } catch {
      return "";
    }
  }

  const referer = String(req.get("referer") || "").trim();
  if (!referer) return "";

  try {
    return new URL(referer).origin;
  } catch {
    return "";
  }
}

function allowedRequestOrigins(req) {
  const origins = new Set();
  const site = parsedSiteUrl();

  if (site) origins.add(site.origin);

  String(process.env.EXTRA_ALLOWED_ORIGINS || "")
    .split(",")
    .map(value => value.trim())
    .filter(Boolean)
    .forEach(value => {
      try {
        origins.add(new URL(value).origin);
      } catch {}
    });

  const host = req.get("host");
  if (host) {
    origins.add(`${req.protocol}://${host}`);
  }

  return origins;
}

app.use((req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  const sourceOrigin = requestSourceOrigin(req);

  if (!sourceOrigin) {
    if (CSRF_ALLOW_NO_ORIGIN) return next();

    addSecurityLog(readData(), "csrf-blocked", {
      actorName: "Unbekannt",
      target: `${req.method} ${req.originalUrl} · Herkunft fehlt`,
      ip: clientAddress(req)
    });

    return res.status(403).send(
      "Die Anfrage wurde aus Sicherheitsgründen blockiert."
    );
  }

  if (!allowedRequestOrigins(req).has(sourceOrigin)) {
    const data = readData();

    addSecurityLog(data, "csrf-blocked", {
      actorName: currentAccess(req).member?.name || "Gast",
      actorRole: currentAccess(req).role,
      target: `${req.method} ${req.originalUrl} · ${sourceOrigin}`,
      ip: clientAddress(req)
    });
    writeData(data);

    return res.status(403).send(
      "Die Anfrage stammt nicht von dieser Website."
    );
  }

  next();
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.GENERAL_RATE_LIMIT || 600),
  standardHeaders: "draft-8",
  legacyHeaders: false,
  skip: req =>
    req.path === "/health" ||
    req.path === "/ready" ||
    req.path.startsWith("/styles.css") ||
    req.path.startsWith("/uploads/")
});

app.use(generalLimiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: "Zu viele Login-Versuche. Bitte warte 15 Minuten."
});

const formLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: "Zu viele Formularanfragen. Bitte versuche es später erneut."
});
app.use(
  express.static(path.join(__dirname, "public"), {
    etag: true,
    lastModified: true,
    maxAge: IS_PRODUCTION ? "1h" : 0,
    setHeaders: (res, filePath) => {
      if (filePath.includes(`${path.sep}uploads${path.sep}`)) {
        res.setHeader("Cache-Control", "public, max-age=3600");
      }
    }
  })
);

app.use((req, res, next) => {
  const access = currentAccess(req);
  res.locals.currentMember = access.member;
  res.locals.currentRole = access.role;
  res.locals.currentRoleName = access.roleName || access.role;
  res.locals.currentRoleColor = access.roleColor || "#9b6cff";
  res.locals.currentPermissions = access.permissions || [];
  res.locals.canPermission = permission => accessHasPermission(access, permission);
  res.locals.permissionCatalog = ROLE_PERMISSION_CATALOG;
  res.locals.canAdmin = access.canAdmin;
  res.locals.isFounder = access.isFounder;
  res.locals.isLoggedInMember = Boolean(req.session?.memberId);
  res.locals.profileThemes = PROFILE_THEMES;
  res.locals.query = req.query || {};
  res.locals.siteBaseUrl = SITE_URL;

  const readerId = access.member?.id || "";
  res.locals.unreadNotificationCount = readerId
    ? visibleNotifications(readData(), access).filter(
        item => !(item.readBy || []).includes(readerId)
      ).length
    : 0;

  next();
});

app.get("/robots.txt", (_req, res) => {
  res.type("text/plain");

  if (!PUBLIC_INDEXING) {
    return res.send("User-agent: *\nDisallow: /\n");
  }

  return res.send("User-agent: *\nAllow: /\n");
});

app.get("/", async (_req, res) => {
  const data = await enrichMembersWithTwitch(readData());
  res.render("index", { data });
});

app.get("/member/:id", async (req, res) => {
  const data = await enrichMembersWithTwitch(readData());
  const member = data.members.find(item => item.id === req.params.id);
  if (!member) return res.status(404).render("not-found", { data });
  res.render("member", { data, member });
});


app.get("/live", async (_req, res) => {
  const data = await enrichMembersWithTwitch(readData());
  const liveMembers = data.members.filter(member => member.effectiveLive);
  res.render("live", { data, liveMembers });
});

app.get("/schedule", (_req, res) => {
  const data = readData();
  res.render("schedule", { data });
});

app.get("/events", (_req, res) => {
  const data = readData();
  const events = [...(data.events || [])].sort((a, b) => {
    return `${a.date}T${a.time}`.localeCompare(`${b.date}T${b.time}`);
  });
  res.render("events", { data, events });
});


app.get("/apply", (_req, res) => {
  const data = readData();
  res.render("apply", { data, success: false, error: "", formData: {} });
});

app.post("/apply", formLimiter, upload.single("avatar"), (req, res) => {
  const data = readData();
  data.applications = data.applications || [];

  const name = String(req.body.name || "").trim();
  const age = String(req.body.age || "").trim();
  const platform = String(req.body.platform || "").trim();
  const channelUrl = String(req.body.channelUrl || "").trim();
  const message = String(req.body.message || "").trim();
  const contact = normalizeContactPreference(req.body);
  const contactError = validateContactPreference(contact);

  if (!name || !platform || !channelUrl || !message || contactError) {
    return res.status(400).render("apply", {
      data,
      success: false,
      error: contactError || "Bitte fülle alle Pflichtfelder aus.",
      formData: req.body
    });
  }

  const application = {
    id: `application-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`,
    createdAt: new Date().toISOString(),
    name,
    age,
    platform,
    channelUrl,
    discord: contact.discordName,
    contactMethod: contact.method,
    contactEmail: contact.email,
    contactDiscordName: contact.discordName,
    contactDiscordId: contact.discordId,
    message,
    avatar: req.file ? `/uploads/${req.file.filename}` : "",
    status: "offen"
  };

  data.applications.push(application);
  addActivity(data, "application", `Neue Bewerbung von ${application.name} ist eingegangen.`);
  addNotification(data, {
    targetPermissions: ["requests.manage"],
    type: "application",
    title: "Neue Bewerbung",
    message: `${application.name} hat eine neue Bewerbung eingereicht.`,
    link: `/admin/application/${application.id}`
  });
  writeData(data);

  res.render("apply", {
    data,
    success: true,
    error: "",
    formData: {}
  });
});


app.get("/impressum", (_req, res) => {
  const data = readData();
  res.render("impressum", { data });
});

app.get("/datenschutz", (_req, res) => {
  const data = readData();
  res.render("datenschutz", { data });
});

app.get("/kontakt", (_req, res) => {
  const data = readData();
  res.render("kontakt", { data, success: false, error: "", formData: {} });
});

app.get("/contact", (_req, res) => {
  res.redirect(301, "/kontakt");
});

app.post("/kontakt", formLimiter, (req, res) => {
  const data = readData();
  data.contactMessages = data.contactMessages || [];

  const name = String(req.body.name || "").trim();
  const subject = String(req.body.subject || "").trim();
  const message = String(req.body.message || "").trim();
  const contact = normalizeContactPreference(req.body);
  const contactError = validateContactPreference(contact);

  if (!name || !subject || !message || contactError) {
    return res.status(400).render("kontakt", {
      data,
      success: false,
      error: contactError || "Bitte fülle alle Pflichtfelder aus.",
      formData: req.body
    });
  }

  const contactMessage = {
    id: `contact-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`,
    createdAt: new Date().toISOString(),
    name,
    email: contact.email,
    contactMethod: contact.method,
    discordName: contact.discordName,
    discordId: contact.discordId,
    subject,
    message,
    status: "offen"
  };

  data.contactMessages.push(contactMessage);
  addNotification(data, {
    targetPermissions: ["requests.manage"],
    type: "contact",
    title: "Neue Kontaktanfrage",
    message: `${contactMessage.name} hat eine Kontaktanfrage gesendet.`,
    link: `/admin/contact/${contactMessage.id}`
  });

  writeData(data);
  res.render("kontakt", {
    data,
    success: true,
    error: "",
    formData: {}
  });
});


function renderMemberLogin(req, res, error = "") {
  if (req.session?.memberId) {
    return res.redirect("/member-area");
  }

  const data = readData();
  const reason = String(req.query?.reason || "");
  const accessMessage = reason === "founder"
    ? "Bitte melde dich mit einem Gründerkonto an."
    : reason === "admin"
      ? "Bitte melde dich mit einem Gründer- oder Moderatorenkonto an."
      : "";

  return res.render("member-login", {
    data,
    error: error || accessMessage,
    loggedOut: req.query?.loggedOut === "1"
  });
}

app.get("/member-login", (req, res) => {
  renderMemberLogin(req, res);
});

app.get("/anmelden", (_req, res) => {
  res.redirect(302, "/member-login");
});

app.get("/login-member", (_req, res) => {
  res.redirect(302, "/member-login");
});

app.post("/member-login", loginLimiter, (req, res, next) => {
  const data = readData();
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  const member = (data.members || []).find(item => {
    const account = item.account || {};
    return account.enabled &&
      String(account.username || "").trim().toLowerCase() === username;
  });

  const attemptKey = loginAttemptKey(req, username);
  const attempt = getLoginAttempt(data, attemptKey);

  if (loginIsLocked(attempt)) {
    const minutes = Math.max(
      1,
      Math.ceil((new Date(attempt.lockedUntil).getTime() - Date.now()) / 60000)
    );

    addSecurityLog(data, "login-blocked", {
      actorName: username || "Unbekannt",
      target: `${minutes} Minuten verbleibend`,
      ip: clientAddress(req)
    });
    writeData(data);

    return res.status(429).render("member-login", {
      data,
      error: `Zu viele Fehlversuche. Bitte warte noch etwa ${minutes} Minuten.`,
      loggedOut: false
    });
  }

  if (!member || !verifyPassword(password, member.account?.passwordHash)) {
    const failed = registerFailedLogin(data, attemptKey);

    addSecurityLog(data, "login-failed", {
      actorName: username || "Unbekannt",
      target: `${failed.count} Fehlversuche`,
      ip: clientAddress(req)
    });
    writeData(data);

    return res.status(401).render("member-login", {
      data,
      error: loginIsLocked(failed)
        ? `Zu viele Fehlversuche. Anmeldung für ${LOGIN_LOCK_MINUTES} Minuten gesperrt.`
        : "Benutzername oder Passwort ist nicht korrekt.",
      loggedOut: false
    });
  }

  delete data.loginAttempts[attemptKey];
  addSecurityLog(data, "login-success", {
    actorName: member.name,
    actorRole: normalizedRole(member),
    ip: clientAddress(req)
  });
  writeData(data);

  req.session.regenerate(error => {
    if (error) return next(error);

    req.session.memberId = member.id;

    req.session.save(saveError => {
      if (saveError) return next(saveError);

      const access = currentAccess(req);
      const requestedReturn = String(req.body.returnTo || req.query?.returnTo || "");
      const safeReturn = requestedReturn.startsWith("/") &&
        !requestedReturn.startsWith("//")
          ? requestedReturn
          : "";

      if (safeReturn) {
        if (safeReturn.startsWith("/admin") && !access.canAdmin) {
          return res.redirect("/member-area");
        }

        return res.redirect(safeReturn);
      }

      return res.redirect(access.canAdmin ? "/admin" : "/member-area");
    });
  });
});

function finishMemberLogout(req, res, next) {
  const clearOptions = {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PRODUCTION,
    path: "/"
  };

  if (!req.session) {
    res.clearCookie("vn.sid", clearOptions);
    return res.redirect("/member-login?loggedOut=1");
  }

  try {
    const data = readData();
    const member = data.members.find(item => item.id === req.session.memberId);

    if (member) {
      addSecurityLog(data, "logout", {
        actorName: member.name,
        actorRole: normalizedRole(member),
        ip: clientAddress(req)
      });
      writeData(data);
    }
  } catch (error) {
    console.error("Logout konnte nicht protokolliert werden:", error);
  }

  req.session.destroy(error => {
    if (error) return next(error);

    res.clearCookie("vn.sid", clearOptions);
    return res.redirect("/member-login?loggedOut=1");
  });
}

app.post("/member-logout", finishMemberLogout);
app.get("/member-logout", finishMemberLogout);


app.get("/owner-recovery", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);
  const access = currentAccess(req);

  if (access.isFounder) {
    return res.redirect("/admin");
  }

  return res.render("owner-recovery", {
    data,
    member,
    error: "",
    success: false
  });
});

app.post("/owner-recovery", requireMember, (req, res) => {
  const expected = String(process.env.ADMIN_PASSWORD || "");
  const supplied = String(req.body.adminPassword || "");

  if (
    expected.length < 12 ||
    ["admin123", "password", "passwort"].includes(expected.toLowerCase())
  ) {
    return res.status(503).render("owner-recovery", {
      data: readData(),
      member: readData().members.find(item => item.id === req.session.memberId),
      error:
        "Die Notfall-Reparatur benötigt ein sicheres ADMIN_PASSWORD in deiner .env (mindestens 12 Zeichen).",
      success: false
    });
  }

  if (!secureTextEqual(supplied, expected)) {
    const data = readData();
    const member = data.members.find(item => item.id === req.session.memberId);

    addSecurityLog(data, "owner-recovery-failed", {
      actorName: member?.name || "Unbekannt",
      actorRole: normalizedRole(member),
      target: "Falsches ADMIN_PASSWORD",
      ip: clientAddress(req)
    });
    writeData(data);

    return res.status(401).render("owner-recovery", {
      data,
      member,
      error: "Das ADMIN_PASSWORD ist nicht korrekt.",
      success: false
    });
  }

  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);

  if (!member) {
    return res.redirect("/member-login");
  }

  member.roleId = "founder";
  member.role = "Gründer";

  addSecurityLog(data, "owner-recovery-success", {
    actorName: member.name,
    actorRole: "founder",
    target: "Gründerrolle wiederhergestellt",
    ip: clientAddress(req)
  });

  writeData(data);

  return res.redirect("/admin?recovery=success");
});


app.get("/member-area", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);

  if (!member) {
    delete req.session.memberId;
    return res.redirect("/member-login");
  }

  member.profileDesign = normalizeProfileDesign(member.profileDesign || {});

  res.render("member-area", {
    data,
    member,
    ...memberDashboardData(data, member),
    message: ""
  });
});

app.post(
  "/member-area/profile",
  requireMember,
  upload.fields([
    { name: "avatar", maxCount: 1 },
    { name: "banner", maxCount: 1 }
  ]),
  (req, res) => {
    const data = readData();
    const index = data.members.findIndex(item => item.id === req.session.memberId);

    if (index < 0) {
      delete req.session.memberId;
      return res.redirect("/member-login");
    }

    const existing = data.members[index];
    const updated = editableMemberFields(req, existing);

    updated.avatar = req.files?.avatar?.[0]
      ? `/uploads/${req.files.avatar[0].filename}`
      : existing.avatar || "";

    updated.banner = req.files?.banner?.[0]
      ? `/uploads/${req.files.banner[0].filename}`
      : existing.banner || "";

    // Das Profilformular darf das separat gespeicherte Design niemals überschreiben.
    updated.profileDesign = normalizeProfileDesign(
      existing.profileDesign || defaultProfileDesign()
    );

    data.members[index] = updated;
    addNotification(data, {
      targetMemberId: updated.id,
      type: "profile",
      title: "Profil gespeichert",
      message: "Deine Profiländerungen wurden erfolgreich übernommen.",
      link: `/member/${updated.slug}`
    });
    writeData(data);
    res.redirect("/member-area?profileSaved=1");
  }
);

app.post(
  "/member-area/design",
  requireMember,
  upload.single("profileBackground"),
  (req, res) => {
    const data = readData();
    const member = data.members.find(item => item.id === req.session.memberId);

    if (!member) {
      delete req.session.memberId;
      return res.redirect("/member-login");
    }

    const currentDesign = normalizeProfileDesign(
      member.profileDesign || defaultProfileDesign()
    );

    const themeKey = PROFILE_THEMES[req.body.profileTheme]
      ? req.body.profileTheme
      : currentDesign.theme;

    const selectedTheme = PROFILE_THEMES[themeKey];

    member.profileDesign = normalizeProfileDesign({
      theme: themeKey,
      primaryColor: req.body.primaryColor || selectedTheme.primaryColor,
      accentColor: req.body.accentColor || selectedTheme.accentColor,
      backgroundColor: req.body.backgroundColor || selectedTheme.backgroundColor,
      backgroundStyle: req.body.backgroundStyle || selectedTheme.backgroundStyle,
      cardStyle: req.body.cardStyle || selectedTheme.cardStyle,
      backgroundImage: req.file
        ? `/uploads/${req.file.filename}`
        : currentDesign.backgroundImage
    });

    writeData(data);
    res.redirect("/member-area?designSaved=1");
  }
);


app.post("/member-area/design/reset", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);

  if (!member) {
    delete req.session.memberId;
    return res.redirect("/member-login");
  }

  member.profileDesign = defaultProfileDesign();
  writeData(data);
  res.redirect("/member-area?designReset=1");
});



app.get("/member-area/inbox", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);

  if (!member) {
    delete req.session.memberId;
    return res.redirect("/member-login");
  }

  const inbox = memberInbox(data, member.id);
  res.render("member-inbox", {
    data,
    member,
    messages: inbox.messages,
    tasks: inbox.tasks
  });
});

app.post("/member-area/message/:id/read", requireMember, (req, res) => {
  const data = readData();
  const item = (data.internalMessages || []).find(
    message =>
      message.id === req.params.id &&
      message.targetMemberId === req.session.memberId
  );

  if (item) {
    item.readAt = item.readAt || new Date().toISOString();
    writeData(data);
  }

  res.redirect("/member-area/inbox");
});

app.post("/member-area/task/:id/toggle", requireMember, (req, res) => {
  const data = readData();
  const task = (data.memberTasks || []).find(
    item =>
      item.id === req.params.id &&
      item.targetMemberId === req.session.memberId
  );

  if (task) {
    task.status = task.status === "erledigt" ? "offen" : "erledigt";
    task.completedAt =
      task.status === "erledigt" ? new Date().toISOString() : "";
    writeData(data);
  }

  res.redirect("/member-area/inbox");
});


app.get("/member-area/calendar", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);

  if (!member) {
    delete req.session.memberId;
    return res.redirect("/member-login");
  }

  const events = visibleTeamEvents(data, member.id).map(event => ({
    ...event,
    response: eventResponseFor(data, event.id, member.id),
    counts: eventResponseCounts(data, event.id)
  }));

  res.render("member-calendar", {
    data,
    member,
    events
  });
});

app.post("/member-area/calendar/:id/respond", requireMember, (req, res) => {
  const data = readData();
  const memberId = req.session.memberId;
  const event = visibleTeamEvents(data, memberId)
    .find(item => item.id === req.params.id);

  if (!event) {
    return res.status(404).send("Event nicht gefunden oder nicht freigegeben.");
  }

  const status = allowedChoice(req.body.status, ["yes", "maybe", "no"], "maybe");
  data.eventResponses = data.eventResponses || [];

  const existing = data.eventResponses.find(
    item => item.eventId === event.id && item.memberId === memberId
  );

  if (existing) {
    existing.status = status;
    existing.updatedAt = new Date().toISOString();
  } else {
    data.eventResponses.push({
      eventId: event.id,
      memberId,
      status,
      updatedAt: new Date().toISOString()
    });
  }

  writeData(data);
  res.redirect("/member-area/calendar");
});


app.get("/member-area/community", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);

  if (!member) {
    delete req.session.memberId;
    return res.redirect("/member-login");
  }

  const selectedCategory = allowedChoice(
    req.query.category,
    ["all", "announcement", "idea", "question", "project", "stream"],
    "all"
  );

  const posts = sortedCommunityPosts(data).filter(
    post => selectedCategory === "all" || post.category === selectedCategory
  );

  res.render("member-community", {
    data,
    member,
    posts,
    selectedCategory
  });
});

app.post("/member-area/community", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);
  const title = String(req.body.title || "").trim().slice(0, 120);
  const content = String(req.body.content || "").trim().slice(0, 4000);
  const category = allowedChoice(
    req.body.category,
    ["announcement", "idea", "question", "project", "stream"],
    "idea"
  );

  if (!member || !title || !content) {
    return res.status(400).send("Titel und Beitragstext sind erforderlich.");
  }

  const now = new Date().toISOString();
  const post = {
    id: communityItemId("post"),
    authorMemberId: member.id,
    category,
    title,
    content,
    pinned: false,
    createdAt: now,
    updatedAt: now
  };

  data.communityPosts = data.communityPosts || [];
  data.communityPosts.push(post);

  data.members
    .filter(item => item.id !== member.id)
    .forEach(target => addNotification(data, {
      targetMemberId: target.id,
      type: "community-post",
      title: `Neuer Pinnwand-Beitrag: ${title}`,
      message: `${member.name} hat einen neuen Beitrag veröffentlicht.`,
      link: `/member-area/community#${post.id}`
    }));

  writeData(data);
  res.redirect(`/member-area/community#${post.id}`);
});

app.post("/member-area/community/:id/edit", requireMember, (req, res) => {
  const data = readData();
  const post = (data.communityPosts || []).find(item => item.id === req.params.id);
  const access = currentAccess(req);

  if (!post) return res.status(404).send("Beitrag nicht gefunden.");
  if (post.authorMemberId !== req.session.memberId && !access.canAdmin) {
    return res.status(403).send("Du darfst diesen Beitrag nicht bearbeiten.");
  }

  const title = String(req.body.title || "").trim().slice(0, 120);
  const content = String(req.body.content || "").trim().slice(0, 4000);
  const category = allowedChoice(
    req.body.category,
    ["announcement", "idea", "question", "project", "stream"],
    post.category
  );

  if (!title || !content) {
    return res.status(400).send("Titel und Beitragstext sind erforderlich.");
  }

  post.title = title;
  post.content = content;
  post.category = category;
  post.updatedAt = new Date().toISOString();

  writeData(data);
  res.redirect(`/member-area/community#${post.id}`);
});

app.post("/member-area/community/:id/delete", requireMember, (req, res) => {
  const data = readData();
  const post = (data.communityPosts || []).find(item => item.id === req.params.id);
  const access = currentAccess(req);

  if (!post) return res.status(404).send("Beitrag nicht gefunden.");
  if (post.authorMemberId !== req.session.memberId && !access.canAdmin) {
    return res.status(403).send("Du darfst diesen Beitrag nicht löschen.");
  }

  data.communityPosts = (data.communityPosts || []).filter(item => item.id !== post.id);
  data.communityComments = (data.communityComments || [])
    .filter(comment => comment.postId !== post.id);

  writeData(data);
  res.redirect("/member-area/community");
});

app.post("/member-area/community/:id/comment", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);
  const post = (data.communityPosts || []).find(item => item.id === req.params.id);
  const content = String(req.body.content || "").trim().slice(0, 1500);

  if (!member || !post) return res.status(404).send("Beitrag nicht gefunden.");
  if (!content) return res.status(400).send("Der Kommentar darf nicht leer sein.");

  data.communityComments = data.communityComments || [];
  data.communityComments.push({
    id: communityItemId("comment"),
    postId: post.id,
    authorMemberId: member.id,
    content,
    createdAt: new Date().toISOString()
  });

  if (post.authorMemberId !== member.id) {
    addNotification(data, {
      targetMemberId: post.authorMemberId,
      type: "community-comment",
      title: `Neuer Kommentar zu: ${post.title}`,
      message: `${member.name} hat deinen Beitrag kommentiert.`,
      link: `/member-area/community#${post.id}`
    });
  }

  writeData(data);
  res.redirect(`/member-area/community#${post.id}`);
});

app.post("/member-area/community/comment/:id/delete", requireMember, (req, res) => {
  const data = readData();
  const comment = (data.communityComments || []).find(item => item.id === req.params.id);
  const access = currentAccess(req);

  if (!comment) return res.status(404).send("Kommentar nicht gefunden.");
  if (comment.authorMemberId !== req.session.memberId && !access.canAdmin) {
    return res.status(403).send("Du darfst diesen Kommentar nicht löschen.");
  }

  data.communityComments = (data.communityComments || [])
    .filter(item => item.id !== comment.id);

  writeData(data);
  res.redirect(`/member-area/community#${comment.postId}`);
});


app.get("/member-area/projects", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);
  if (!member) return res.redirect("/member-login");

  res.render("member-projects", {
    data,
    member,
    projects: projectsForMember(data, member.id)
  });
});

app.post("/member-area/projects/:id/progress", requireMember, (req, res) => {
  const data = readData();
  const project = (data.projects || []).find(item => item.id === req.params.id);
  const access = currentAccess(req);

  if (!project) return res.status(404).send("Projekt nicht gefunden.");
  if (!access.canAdmin && project.leaderMemberId !== req.session.memberId) {
    return res.status(403).send("Nur Projektleitung oder Teamverwaltung darf den Fortschritt ändern.");
  }

  project.progress = clampNumber(req.body.progress, 0, 100, project.progress || 0);
  project.updatedAt = new Date().toISOString();
  writeData(data);
  res.redirect(`/member-area/projects#${project.id}`);
});


app.get("/member-area/media", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);

  if (!member) {
    delete req.session.memberId;
    return res.redirect("/member-login");
  }

  res.render("member-media", {
    data,
    member,
    files: visibleMediaFiles(data, member.id)
  });
});

app.post(
  "/member-area/media",
  requireMember,
  mediaUpload.single("mediaFile"),
  (req, res) => {
    const data = readData();
    const member = data.members.find(item => item.id === req.session.memberId);

    if (!member || !req.file) {
      return res.status(400).send("Mitglied oder Datei fehlt.");
    }

    const title = String(req.body.title || "").trim().slice(0, 140) ||
      path.parse(req.file.originalname).name.slice(0, 140);
    const description = String(req.body.description || "").trim().slice(0, 2000);
    const category = allowedChoice(
      req.body.category,
      ["image", "logo", "overlay", "document", "archive", "other"],
      "other"
    );
    const visibility = allowedChoice(
      req.body.visibility,
      ["all", "project", "selected"],
      "all"
    );
    const projectId = String(req.body.projectId || "").trim();

    const allowedMemberIds = Array.isArray(req.body.allowedMemberIds)
      ? req.body.allowedMemberIds
      : req.body.allowedMemberIds
        ? [req.body.allowedMemberIds]
        : [];

    if (visibility === "project" && !(data.projects || []).some(item => item.id === projectId)) {
      fs.rmSync(req.file.path, { force: true });
      return res.status(400).send("Das ausgewählte Projekt wurde nicht gefunden.");
    }

    const media = {
      id: mediaItemId(),
      uploaderMemberId: member.id,
      title,
      description,
      category,
      visibility,
      projectId: visibility === "project" ? projectId : "",
      allowedMemberIds: visibility === "selected" ? allowedMemberIds : [],
      storedName: req.file.filename,
      originalName: String(req.file.originalname || "Datei").slice(0, 255),
      mimeType: req.file.mimetype,
      size: req.file.size,
      createdAt: new Date().toISOString()
    };

    data.mediaFiles = data.mediaFiles || [];
    data.mediaFiles.push(media);

    data.members
      .filter(target =>
        target.id !== member.id &&
        mediaAllowedForMember(data, media, target.id)
      )
      .forEach(target => addNotification(data, {
        targetMemberId: target.id,
        type: "media",
        title: `Neue Datei: ${title}`,
        message: `${member.name} hat eine Datei bereitgestellt.`,
        link: `/member-area/media#${media.id}`
      }));

    writeData(data);
    res.redirect(`/member-area/media#${media.id}`);
  }
);

app.get("/member-area/media/:id/file", requireMember, (req, res) => {
  const data = readData();
  const media = (data.mediaFiles || []).find(item => item.id === req.params.id);
  const access = currentAccess(req);

  if (!media) {
    return res.status(404).send("Datei nicht gefunden.");
  }

  if (!access.canAdmin && !mediaAllowedForMember(data, media, req.session.memberId)) {
    return res.status(403).send("Du darfst diese Datei nicht öffnen.");
  }

  const filePath = path.join(MEDIA_DIR, path.basename(media.storedName));
  if (!fs.existsSync(filePath)) {
    return res.status(404).send("Die gespeicherte Datei fehlt.");
  }

  const inline = mediaIsPreviewable(media) && req.query.download !== "1";
  res.type(media.mimeType || "application/octet-stream");
  res.setHeader(
    "Content-Disposition",
    `${inline ? "inline" : "attachment"}; filename*=UTF-8''${encodeURIComponent(media.originalName)}`
  );
  res.sendFile(filePath);
});

app.post("/member-area/media/:id/delete", requireMember, (req, res) => {
  const data = readData();
  const media = (data.mediaFiles || []).find(item => item.id === req.params.id);
  const access = currentAccess(req);

  if (!media) {
    return res.status(404).send("Datei nicht gefunden.");
  }

  if (!access.canAdmin && media.uploaderMemberId !== req.session.memberId) {
    return res.status(403).send("Nur der Uploader oder die Teamverwaltung darf diese Datei löschen.");
  }

  const filePath = path.join(MEDIA_DIR, path.basename(media.storedName));
  fs.rmSync(filePath, { force: true });
  data.mediaFiles = (data.mediaFiles || []).filter(item => item.id !== media.id);

  writeData(data);
  res.redirect("/member-area/media");
});


app.get("/member-area/polls", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);

  if (!member) {
    delete req.session.memberId;
    return res.redirect("/member-login");
  }

  res.render("member-polls", {
    data,
    member,
    polls: visiblePolls(data, member.id)
  });
});

app.post("/member-area/polls/:id/vote", requireMember, (req, res) => {
  const data = readData();
  const memberId = req.session.memberId;
  const poll = (data.polls || []).find(item => item.id === req.params.id);

  if (!poll || !pollAllowedForMember(poll, memberId)) {
    return res.status(404).send("Abstimmung nicht gefunden oder nicht freigegeben.");
  }

  if (!pollIsOpen(poll)) {
    return res.status(400).send("Diese Abstimmung ist beendet.");
  }

  const optionId = String(req.body.optionId || "").trim();
  if (!(poll.options || []).some(option => option.id === optionId)) {
    return res.status(400).send("Ungültige Antwortmöglichkeit.");
  }

  data.pollVotes = data.pollVotes || [];
  const existing = data.pollVotes.find(
    vote => vote.pollId === poll.id && vote.memberId === memberId
  );

  if (existing) {
    existing.optionId = optionId;
    existing.updatedAt = new Date().toISOString();
  } else {
    data.pollVotes.push({
      id: pollItemId("vote"),
      pollId: poll.id,
      memberId,
      optionId,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });
  }

  writeData(data);
  res.redirect(`/member-area/polls#${poll.id}`);
});

app.get("/member-area/notifications", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);

  if (!member) {
    delete req.session.memberId;
    return res.redirect("/member-login");
  }

  const access = currentAccess(req);
  const notifications = visibleNotifications(data, access);

  res.render("member-notifications", {
    data,
    member,
    notifications
  });
});

app.post("/member-area/notifications/:id/read", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);
  const notification = (data.notifications || []).find(
    item => item.id === req.params.id
  );

  if (!member || !notification) {
    return res.redirect("/member-area/notifications");
  }

  const access = currentAccess(req);
  if (!notificationAudienceMatches(notification, access)) {
    return res.status(403).render("forbidden", {
      data,
      message: "Diese Benachrichtigung gehört nicht zu deinem Konto."
    });
  }

  notification.readBy = Array.isArray(notification.readBy)
    ? notification.readBy
    : [];

  if (!notification.readBy.includes(member.id)) {
    notification.readBy.push(member.id);
  }

  writeData(data);
  res.redirect(notification.link || "/member-area/notifications");
});

app.post("/member-area/notifications/read-all", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);

  if (!member) {
    return res.redirect("/member-login");
  }

  const access = currentAccess(req);

  visibleNotifications(data, access).forEach(notification => {
    notification.readBy = Array.isArray(notification.readBy)
      ? notification.readBy
      : [];

    if (!notification.readBy.includes(member.id)) {
      notification.readBy.push(member.id);
    }
  });

  writeData(data);
  res.redirect("/member-area/notifications");
});

app.post("/member-area/password", requireMember, (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.session.memberId);

  if (!member) {
    return res.redirect("/member-login");
  }

  const renderWithMessage = (status, message) => res.status(status).render(
    "member-area",
    {
      data,
      member,
      ...memberDashboardData(data, member),
      message
    }
  );

  const currentPassword = String(req.body.currentPassword || "");
  const newPassword = String(req.body.newPassword || "");
  const confirmation = String(req.body.confirmation || "");

  if (!verifyPassword(currentPassword, member.account?.passwordHash)) {
    return renderWithMessage(400, "Das aktuelle Passwort ist nicht korrekt.");
  }

  if (newPassword.length < 12) {
    return renderWithMessage(400, "Das neue Passwort muss mindestens 12 Zeichen lang sein.");
  }

  if (newPassword !== confirmation) {
    return renderWithMessage(400, "Die neuen Passwörter stimmen nicht überein.");
  }

  member.account.passwordHash = hashPassword(newPassword);
  addNotification(data, {
    targetMemberId: member.id,
    type: "security",
    title: "Passwort geändert",
    message: "Dein Mitgliederpasswort wurde erfolgreich geändert.",
    link: "/member-area"
  });
  writeData(data);

  return renderWithMessage(200, "Passwort wurde geändert.");
});


app.get("/news", (_req, res) => {
  const data = readData();
  const news = [...(data.news || [])]
    .filter(item => item.published)
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  res.render("news", { data, news });
});

app.get("/news/:id", (req, res) => {
  const data = readData();
  const article = (data.news || []).find(item => item.id === req.params.id && item.published);
  if (!article) return res.status(404).render("not-found", { data });
  res.render("news-detail", { data, article });
});

app.post("/events/:id/register", formLimiter, (req, res) => {
  const data = readData();
  const event = (data.events || []).find(item => item.id === req.params.id);
  if (!event) return res.status(404).send("Event nicht gefunden.");

  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim();
  const note = String(req.body.note || "").trim();

  if (!name || !email) {
    return res.status(400).send("Name und E-Mail werden benötigt.");
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).send("Ungültige E-Mail-Adresse.");
  }

  event.registrations = event.registrations || [];

  const duplicate = event.registrations.find(
    item => String(item.email).toLowerCase() === email.toLowerCase()
  );

  if (!duplicate) {
    event.registrations.push({
      id: `registration-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`,
      name,
      email,
      note,
      createdAt: new Date().toISOString(),
      status: "angemeldet"
    });
    addActivity(data, "event-registration", `${name} hat sich für „${event.title}“ angemeldet.`);
    writeData(data);
  }

  res.redirect(`/events?registered=${encodeURIComponent(event.id)}`);
});


app.get("/search", async (req, res) => {
  const data = await enrichMembersWithTwitch(readData());
  const query = String(req.query.q || "").trim();
  const normalized = normalizeSearch(query);

  const members = normalized
    ? data.members.filter(member => {
        const haystack = [
          member.name,
          member.role,
          member.bio,
          member.streamTitle,
          ...(member.tags || []),
          ...(member.languages || []),
          ...(member.favoriteGames || [])
        ].join(" ").toLowerCase();
        return haystack.includes(normalized);
      })
    : [];

  const news = normalized
    ? (data.news || []).filter(article =>
        article.published &&
        [article.title, article.summary, article.content, article.author]
          .join(" ")
          .toLowerCase()
          .includes(normalized)
      )
    : [];

  const events = normalized
    ? (data.events || []).filter(event =>
        [event.title, event.description, event.date, event.time]
          .join(" ")
          .toLowerCase()
          .includes(normalized)
      )
    : [];

  res.render("search", { data, query, members, news, events });
});

app.get("/members", async (req, res) => {
  const data = await enrichMembersWithTwitch(readData());
  const language = String(req.query.language || "").trim();
  const tag = String(req.query.tag || "").trim();
  const status = String(req.query.status || "").trim();

  let members = [...data.members];

  if (language) {
    members = members.filter(member =>
      (member.languages || []).some(item => item.toLowerCase() === language.toLowerCase())
    );
  }

  if (tag) {
    members = members.filter(member =>
      (member.tags || []).some(item => item.toLowerCase() === tag.toLowerCase())
    );
  }

  if (status === "live") members = members.filter(member => member.effectiveLive);
  if (status === "offline") members = members.filter(member => !member.effectiveLive);

  const languages = [...new Set(data.members.flatMap(member => member.languages || []))].sort();
  const tags = [...new Set(data.members.flatMap(member => member.tags || []))].sort();

  res.render("members", {
    data,
    members,
    languages,
    tags,
    filters: { language, tag, status }
  });
});

app.get("/events/:id", (req, res) => {
  const data = readData();
  const event = (data.events || []).find(item => item.id === req.params.id);
  if (!event) return res.status(404).render("not-found", { data });
  res.render("event-detail", { data, event });
});

app.get("/events/:id/calendar.ics", (req, res) => {
  const data = readData();
  const event = (data.events || []).find(item => item.id === req.params.id);
  if (!event) return res.status(404).send("Event nicht gefunden.");

  const start = eventDateTime(event);
  const endDate = new Date(`${event.date}T${event.time || "00:00"}:00`);
  endDate.setHours(endDate.getHours() + 2);

  const end =
    `${endDate.getFullYear()}` +
    `${String(endDate.getMonth() + 1).padStart(2, "0")}` +
    `${String(endDate.getDate()).padStart(2, "0")}` +
    `T${String(endDate.getHours()).padStart(2, "0")}` +
    `${String(endDate.getMinutes()).padStart(2, "0")}00`;

  const ical = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    `PRODID:-//${escapeIcalText(data.group.name)}//Event Calendar//DE`,
    "CALSCALE:GREGORIAN",
    "BEGIN:VEVENT",
    `UID:${escapeIcalText(event.id)}@vtuber-nexus.local`,
    `DTSTAMP:${new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z")}`,
    `DTSTART:${start}`,
    `DTEND:${end}`,
    `SUMMARY:${escapeIcalText(event.title)}`,
    `DESCRIPTION:${escapeIcalText(event.description)}`,
    "END:VEVENT",
    "END:VCALENDAR"
  ].join("\r\n");

  res.setHeader("Content-Type", "text/calendar; charset=utf-8");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="${slugify(event.title) || "event"}.ics"`
  );
  res.send(ical);
});

app.get("/login", (req, res) => {
  if (req.session?.isAdmin) return res.redirect("/admin");
  res.render("login", { data: readData(), error: "" });
});

app.post("/login", loginLimiter, (req, res) => {
  const password = String(req.body.password || "");
  const expected = process.env.ADMIN_PASSWORD || "admin123";

  if (password !== expected) {
    return res.status(401).render("login", { data: readData(), error: "Das Passwort ist nicht korrekt." });
  }

  req.session.isAdmin = true;
  res.redirect("/admin");
});

app.post("/logout", requireAdmin, (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/admin", requireAdmin, (req, res) => {
  const data = readData();
  res.render("admin", {
    data,
    message: "",
    access: req.access || currentAccess(req),
    backups: listDatabaseBackups(),
    sessions: listStoredSessions(data),
    diagnostics: runSystemDiagnostics(),
    permissionCatalog: ROLE_PERMISSION_CATALOG
  });
});



app.post(
  "/admin/site-background",
  requirePermission("appearance.manage"),
  upload.single("siteBackgroundImage"),
  (req, res) => {
    const data = readData();

    const current = data.group.siteBackground || {
      mode: "gradient",
      color1: "#090b16",
      color2: "#10232d",
      image: "",
      overlay: 82,
      fixed: true
    };

    const mode = ["solid", "gradient", "image"].includes(req.body.mode)
      ? req.body.mode
      : "gradient";

    data.group.siteBackground = {
      mode,
      color1: validHexColor(req.body.color1, current.color1 || "#090b16"),
      color2: validHexColor(req.body.color2, current.color2 || "#10232d"),
      image: req.file
        ? `/uploads/${req.file.filename}`
        : current.image || "",
      overlay: safeOverlay(req.body.overlay, current.overlay ?? 82),
      fixed: req.body.fixed === "on"
    };

    writeData(data);
    res.redirect("/admin");
  }
);

app.post("/admin/site-background/reset", requirePermission("appearance.manage"), (req, res) => {
  const data = readData();

  data.group.siteBackground = {
    mode: "gradient",
    color1: "#090b16",
    color2: "#10232d",
    image: "",
    overlay: 82,
    fixed: true
  };

  writeData(data);
  res.redirect("/admin");
});




app.post(
  "/admin/branding",
  requirePermission("branding.manage"),
  upload.fields([
    { name: "brandLogo", maxCount: 1 },
    { name: "brandFavicon", maxCount: 1 },
    { name: "brandSocialImage", maxCount: 1 }
  ]),
  (req, res) => {
    const data = readData();
    const access = req.access || currentAccess(req);
    const current = data.group.branding || {};

    const siteName = cleanBrandText(
      req.body.siteName,
      data.group.name || "VTuber Nexus",
      80
    );

    const suggestedAbbreviation = abbreviationFromName(siteName, "VN");
    const abbreviation = brandAbbreviation(
      req.body.abbreviation,
      suggestedAbbreviation
    );

    const removeLogo = req.body.removeLogo === "on";
    const removeFavicon = req.body.removeFavicon === "on";
    const removeSocialImage = req.body.removeSocialImage === "on";

    const logo = removeLogo
      ? ""
      : req.files?.brandLogo?.[0]
        ? `/uploads/${req.files.brandLogo[0].filename}`
        : current.logo || data.group.logo || "";

    const favicon = removeFavicon
      ? ""
      : req.files?.brandFavicon?.[0]
        ? `/uploads/${req.files.brandFavicon[0].filename}`
        : current.favicon || "";

    const socialImage = removeSocialImage
      ? ""
      : req.files?.brandSocialImage?.[0]
        ? `/uploads/${req.files.brandSocialImage[0].filename}`
        : current.socialImage || "";

    data.group.branding = {
      siteName,
      subtitle: cleanBrandText(
        req.body.subtitle,
        current.subtitle || "Community Hub",
        80
      ),
      abbreviation,
      browserTitle: cleanBrandText(
        req.body.browserTitle,
        siteName,
        80
      ),
      adminName: cleanBrandText(
        req.body.adminName,
        current.adminName || "Admin",
        40
      ),
      adminAbbreviation: brandAbbreviation(
        req.body.adminAbbreviation,
        abbreviation
      ),
      footerName: cleanBrandText(
        req.body.footerName,
        siteName,
        80
      ),
      logo,
      favicon,
      socialImage
    };

    // Bestehende Seiten und Funktionen verwenden weiterhin diese Felder.
    data.group.name = siteName;
    data.group.logo = logo;

    addSecurityLog(data, "branding-updated", {
      actorName: access.member?.name || "Gründer",
      actorRole: access.role,
      target: `${siteName} · ${abbreviation}`,
      ip: clientAddress(req)
    });

    writeData(data);
    return res.redirect("/admin?branding=saved#branding-zentrale");
  }
);

app.post("/admin/branding/reset", requirePermission("branding.manage"), (req, res) => {
  const data = readData();
  const access = req.access || currentAccess(req);
  const siteName = String(data.group.name || "VTuber Nexus").trim() || "VTuber Nexus";
  const abbreviation = abbreviationFromName(siteName, "VN");

  data.group.branding = {
    siteName,
    subtitle: "Community Hub",
    abbreviation,
    browserTitle: siteName,
    adminName: "Admin",
    adminAbbreviation: abbreviation,
    footerName: siteName,
    logo: data.group.logo || "",
    favicon: "",
    socialImage: ""
  };

  addSecurityLog(data, "branding-reset", {
    actorName: access.member?.name || "Gründer",
    actorRole: access.role,
    target: siteName,
    ip: clientAddress(req)
  });

  writeData(data);
  return res.redirect("/admin?branding=reset#branding-zentrale");
});


app.post(
  "/admin/header-design",
  requirePermission("appearance.manage"),
  upload.single("headerBackgroundImage"),
  (req, res) => {
    const data = readData();
    const access = req.access || currentAccess(req);

    const current = data.group.headerDesign || {
      mode: "galaxy",
      color1: "#050818",
      color2: "#17103a",
      accent1: "#5767ff",
      accent2: "#be3cff",
      image: "",
      overlay: 76,
      blur: 18,
      shadow: true
    };

    const mode = allowedChoice(
      req.body.mode,
      ["galaxy", "gradient", "solid", "image"],
      "galaxy"
    );

    const removeImage = req.body.removeImage === "on";

    data.group.headerDesign = {
      mode,
      color1: validHexColor(req.body.color1, current.color1 || "#050818"),
      color2: validHexColor(req.body.color2, current.color2 || "#17103a"),
      accent1: validHexColor(req.body.accent1, current.accent1 || "#5767ff"),
      accent2: validHexColor(req.body.accent2, current.accent2 || "#be3cff"),
      image: removeImage
        ? ""
        : req.file
          ? `/uploads/${req.file.filename}`
          : current.image || "",
      overlay: safeOverlay(req.body.overlay, current.overlay ?? 76),
      blur: clampNumber(req.body.blur, 0, 30, current.blur ?? 18),
      shadow: req.body.shadow === "on"
    };

    addSecurityLog(data, "header-design-updated", {
      actorName: access.member?.name || "Gründer",
      actorRole: access.role,
      target: `Modus: ${mode}`,
      ip: clientAddress(req)
    });

    writeData(data);
    return res.redirect("/admin?headerDesign=saved#header-design");
  }
);

app.post("/admin/header-design/reset", requirePermission("appearance.manage"), (req, res) => {
  const data = readData();
  const access = req.access || currentAccess(req);

  data.group.headerDesign = {
    mode: "galaxy",
    color1: "#050818",
    color2: "#17103a",
    accent1: "#5767ff",
    accent2: "#be3cff",
    image: "",
    overlay: 76,
    blur: 18,
    shadow: true
  };

  addSecurityLog(data, "header-design-reset", {
    actorName: access.member?.name || "Gründer",
    actorRole: access.role,
    target: "Galaxy-Standard",
    ip: clientAddress(req)
  });

  writeData(data);
  return res.redirect("/admin?headerDesign=reset#header-design");
});


app.post("/admin/site-design", requirePermission("appearance.manage"), (req, res) => {
  const data = readData();

  data.group.siteDesign = {
    fontFamily: allowedChoice(
      req.body.fontFamily,
      ["system", "modern", "rounded", "editorial", "mono"],
      "system"
    ),
    baseFontSize: clampNumber(req.body.baseFontSize, 14, 22, 16),
    headingScale: clampNumber(req.body.headingScale, 80, 150, 100),
    textAlign: allowedChoice(
      req.body.textAlign,
      ["left", "center"],
      "left"
    ),
    heroAlign: allowedChoice(
      req.body.heroAlign,
      ["left", "center", "right"],
      "left"
    ),
    contentWidth: clampNumber(req.body.contentWidth, 900, 1600, 1200),
    sectionSpacing: clampNumber(req.body.sectionSpacing, 50, 160, 100),
    cardRadius: clampNumber(req.body.cardRadius, 0, 36, 18),
    buttonRadius: clampNumber(req.body.buttonRadius, 0, 30, 13),
    cardOpacity: clampNumber(req.body.cardOpacity, 60, 100, 94),
    navStyle: allowedChoice(
      req.body.navStyle,
      ["compact", "normal", "spacious"],
      "normal"
    ),
    showAnimations: true
  };

  writeData(data);
  res.redirect("/admin");
});

app.post("/admin/site-design/reset", requirePermission("appearance.manage"), (req, res) => {
  const data = readData();

  data.group.siteDesign = {
    fontFamily: "system",
    baseFontSize: 16,
    headingScale: 100,
    textAlign: "left",
    heroAlign: "left",
    contentWidth: 1200,
    sectionSpacing: 100,
    cardRadius: 18,
    buttonRadius: 13,
    cardOpacity: 94,
    navStyle: "normal",
    showAnimations: true
  };

  writeData(data);
  res.redirect("/admin");
});


app.post("/admin/internal-message", requirePermission("communications.manage"), (req, res) => {
  const data = readData();
  const target = data.members.find(item => item.id === req.body.targetMemberId);
  const access = req.access || currentAccess(req);
  const title = String(req.body.title || "").trim().slice(0, 100);
  const content = String(req.body.content || "").trim().slice(0, 2000);

  if (!target || !title || !content) {
    return res.status(400).send("Mitglied, Titel oder Nachricht fehlt.");
  }

  const item = {
    id: internalItemId("message"),
    targetMemberId: target.id,
    senderName: access.member?.name || "Gründer",
    senderRole: access.role,
    title,
    content,
    createdAt: new Date().toISOString(),
    readAt: ""
  };

  data.internalMessages = data.internalMessages || [];
  data.internalMessages.push(item);

  addNotification(data, {
    targetMemberId: target.id,
    type: "internal-message",
    title: `Neue Nachricht: ${title}`,
    message: `Du hast eine Nachricht von ${item.senderName} erhalten.`,
    link: "/member-area/inbox"
  });

  writeData(data);
  res.redirect("/admin#interne-kommunikation");
});

app.post("/admin/member-task", requirePermission("communications.manage"), (req, res) => {
  const data = readData();
  const target = data.members.find(item => item.id === req.body.targetMemberId);
  const access = req.access || currentAccess(req);
  const title = String(req.body.title || "").trim().slice(0, 100);
  const description = String(req.body.description || "").trim().slice(0, 2000);
  const dueDate = String(req.body.dueDate || "").trim();

  if (!target || !title) {
    return res.status(400).send("Mitglied oder Aufgabentitel fehlt.");
  }

  const task = {
    id: internalItemId("task"),
    targetMemberId: target.id,
    creatorName: access.member?.name || "Gründer",
    creatorRole: access.role,
    title,
    description,
    dueDate,
    status: "offen",
    createdAt: new Date().toISOString(),
    completedAt: ""
  };

  data.memberTasks = data.memberTasks || [];
  data.memberTasks.push(task);

  addNotification(data, {
    targetMemberId: target.id,
    type: "task",
    title: `Neue Aufgabe: ${title}`,
    message: dueDate ? `Frist: ${dueDate}` : "Neue Aufgabe ohne feste Frist.",
    link: "/member-area/inbox"
  });

  writeData(data);
  res.redirect("/admin#interne-kommunikation");
});

app.post("/admin/internal-message/:id/delete", requirePermission("communications.manage"), (req, res) => {
  const data = readData();
  data.internalMessages = (data.internalMessages || [])
    .filter(item => item.id !== req.params.id);
  writeData(data);
  res.redirect("/admin#interne-kommunikation");
});

app.post("/admin/member-task/:id/delete", requirePermission("communications.manage"), (req, res) => {
  const data = readData();
  data.memberTasks = (data.memberTasks || [])
    .filter(item => item.id !== req.params.id);
  writeData(data);
  res.redirect("/admin#interne-kommunikation");
});


app.post("/admin/site-animations", requirePermission("animations.manage"), (req, res) => {
  const data = readData();

  data.group.siteAnimations = {
    enabled: req.body.enabled === "on",
    type: allowedChoice(
      req.body.type,
      ["fade", "fade-up", "slide-left", "slide-right", "zoom", "float"],
      "fade-up"
    ),
    speed: allowedChoice(
      req.body.speed,
      ["slow", "normal", "fast"],
      "normal"
    ),
    intensity: clampNumber(req.body.intensity, 50, 150, 100),
    trigger: allowedChoice(
      req.body.trigger,
      ["load", "viewport"],
      "viewport"
    ),
    stagger: req.body.stagger === "on",
    hoverEffects: req.body.hoverEffects === "on"
  };

  writeData(data);
  res.redirect("/admin#animations-studio");
});

app.post("/admin/site-animations/reset", requirePermission("animations.manage"), (req, res) => {
  const data = readData();

  data.group.siteAnimations = {
    enabled: true,
    type: "fade-up",
    speed: "normal",
    intensity: 100,
    trigger: "viewport",
    stagger: true,
    hoverEffects: true
  };

  writeData(data);
  res.redirect("/admin#animations-studio");
});


app.post("/admin/team-event", requirePermission("events.manage"), (req, res) => {
  const data = readData();
  const access = req.access || currentAccess(req);
  const title = String(req.body.title || "").trim().slice(0, 120);
  const description = String(req.body.description || "").trim().slice(0, 3000);
  const date = String(req.body.date || "").trim();
  const time = String(req.body.time || "").trim();
  const location = String(req.body.location || "").trim().slice(0, 160);
  const visibility = allowedChoice(
    req.body.visibility,
    ["all", "private"],
    "all"
  );

  const allowedMemberIds = Array.isArray(req.body.allowedMemberIds)
    ? req.body.allowedMemberIds
    : req.body.allowedMemberIds
      ? [req.body.allowedMemberIds]
      : [];

  if (!title || !date) {
    return res.status(400).send("Titel und Datum sind erforderlich.");
  }

  const event = {
    id: teamEventId(),
    title,
    description,
    date,
    time,
    location,
    visibility,
    allowedMemberIds: visibility === "private" ? allowedMemberIds : [],
    createdByName: access.member?.name || "Gründer",
    createdByRole: access.role,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  data.teamEvents = data.teamEvents || [];
  data.teamEvents.push(event);

  const recipients = visibility === "private"
    ? data.members.filter(member => allowedMemberIds.includes(member.id))
    : data.members;

  recipients.forEach(member => {
    addNotification(data, {
      targetMemberId: member.id,
      type: "team-event",
      title: `Neues Team-Event: ${title}`,
      message: `${date}${time ? ` um ${time}` : ""}${location ? ` · ${location}` : ""}`,
      link: "/member-area/calendar"
    });
  });

  writeData(data);
  res.redirect("/admin#teamkalender");
});

app.post("/admin/team-event/:id/delete", requirePermission("events.manage"), (req, res) => {
  const data = readData();
  data.teamEvents = (data.teamEvents || []).filter(
    event => event.id !== req.params.id
  );
  data.eventResponses = (data.eventResponses || []).filter(
    response => response.eventId !== req.params.id
  );

  writeData(data);
  res.redirect("/admin#teamkalender");
});


app.post("/admin/community/:id/toggle-pin", requirePermission("community.manage"), (req, res) => {
  const data = readData();
  const post = (data.communityPosts || []).find(item => item.id === req.params.id);

  if (!post) return res.status(404).send("Beitrag nicht gefunden.");

  post.pinned = !post.pinned;
  post.updatedAt = new Date().toISOString();
  writeData(data);
  res.redirect("/admin#community-moderation");
});

app.post("/admin/community/:id/delete", requirePermission("community.manage"), (req, res) => {
  const data = readData();
  const post = (data.communityPosts || []).find(item => item.id === req.params.id);

  if (!post) return res.status(404).send("Beitrag nicht gefunden.");

  data.communityPosts = (data.communityPosts || []).filter(item => item.id !== post.id);
  data.communityComments = (data.communityComments || [])
    .filter(comment => comment.postId !== post.id);

  writeData(data);
  res.redirect("/admin#community-moderation");
});


app.post("/admin/project", requirePermission("projects.manage"), (req, res) => {
  const data = readData();
  const title = String(req.body.title || "").trim().slice(0, 140);
  if (!title) return res.status(400).send("Projekttitel fehlt.");

  const memberIds = Array.isArray(req.body.memberIds)
    ? req.body.memberIds
    : req.body.memberIds ? [req.body.memberIds] : [];

  const project = {
    id: projectId(),
    title,
    description: String(req.body.description || "").trim().slice(0, 5000),
    status: allowedChoice(req.body.status, ["idea","planned","active","done"], "idea"),
    visibility: allowedChoice(req.body.visibility, ["all","assigned"], "assigned"),
    leaderMemberId: String(req.body.leaderMemberId || ""),
    memberIds,
    dueDate: String(req.body.dueDate || ""),
    progress: clampNumber(req.body.progress, 0, 100, 0),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  data.projects = data.projects || [];
  data.projects.push(project);

  new Set([...memberIds, ...(project.leaderMemberId ? [project.leaderMemberId] : [])])
    .forEach(memberId => addNotification(data, {
      targetMemberId: memberId,
      type: "project",
      title: `Neues Projekt: ${title}`,
      message: "Du wurdest diesem Projekt zugewiesen.",
      link: `/member-area/projects#${project.id}`
    }));

  writeData(data);
  res.redirect("/admin#projektverwaltung");
});

app.post("/admin/project/:id/update", requirePermission("projects.manage"), (req, res) => {
  const data = readData();
  const project = (data.projects || []).find(item => item.id === req.params.id);
  if (!project) return res.status(404).send("Projekt nicht gefunden.");

  project.title = String(req.body.title || "").trim().slice(0, 140) || project.title;
  project.description = String(req.body.description || "").trim().slice(0, 5000);
  project.status = allowedChoice(req.body.status, ["idea","planned","active","done"], project.status);
  project.visibility = allowedChoice(req.body.visibility, ["all","assigned"], project.visibility);
  project.leaderMemberId = String(req.body.leaderMemberId || "");
  project.memberIds = Array.isArray(req.body.memberIds)
    ? req.body.memberIds
    : req.body.memberIds ? [req.body.memberIds] : [];
  project.dueDate = String(req.body.dueDate || "");
  project.progress = clampNumber(req.body.progress, 0, 100, project.progress || 0);
  project.updatedAt = new Date().toISOString();

  writeData(data);
  res.redirect("/admin#projektverwaltung");
});

app.post("/admin/project/:id/delete", requirePermission("projects.manage"), (req, res) => {
  const data = readData();
  data.projects = (data.projects || []).filter(item => item.id !== req.params.id);
  writeData(data);
  res.redirect("/admin#projektverwaltung");
});


app.post("/admin/poll", requirePermission("polls.manage"), (req, res) => {
  const data = readData();
  const access = currentAccess(req);
  const question = String(req.body.question || "").trim().slice(0, 240);
  const description = String(req.body.description || "").trim().slice(0, 3000);
  const visibility = allowedChoice(
    req.body.visibility,
    ["all", "selected"],
    "all"
  );
  const anonymous = req.body.anonymous === "on";
  const pinned = req.body.pinned === "on";
  const endsAt = String(req.body.endsAt || "").trim();

  const rawOptions = Array.isArray(req.body.options)
    ? req.body.options
    : req.body.options
      ? [req.body.options]
      : [];

  const options = rawOptions
    .map(text => String(text || "").trim().slice(0, 160))
    .filter(Boolean)
    .slice(0, 8)
    .map(text => ({
      id: pollItemId("option"),
      text
    }));

  const allowedMemberIds = Array.isArray(req.body.allowedMemberIds)
    ? req.body.allowedMemberIds
    : req.body.allowedMemberIds
      ? [req.body.allowedMemberIds]
      : [];

  if (!question || options.length < 2) {
    return res.status(400).send("Frage und mindestens zwei Antwortmöglichkeiten sind erforderlich.");
  }

  const poll = {
    id: pollItemId("poll"),
    question,
    description,
    options,
    visibility,
    allowedMemberIds: visibility === "selected" ? allowedMemberIds : [],
    anonymous,
    pinned,
    endsAt,
    createdByName: access.member?.name || "Gründer",
    createdAt: new Date().toISOString()
  };

  data.polls = data.polls || [];
  data.polls.push(poll);

  const recipients = visibility === "selected"
    ? data.members.filter(member => allowedMemberIds.includes(member.id))
    : data.members;

  recipients.forEach(member => addNotification(data, {
    targetMemberId: member.id,
    type: "poll",
    title: `Neue Abstimmung: ${question}`,
    message: endsAt ? `Teilnahme bis ${endsAt}` : "Neue interne Abstimmung verfügbar.",
    link: `/member-area/polls#${poll.id}`
  }));

  writeData(data);
  res.redirect("/admin#abstimmungen");
});

app.post("/admin/poll/:id/toggle-pin", requirePermission("polls.manage"), (req, res) => {
  const data = readData();
  const poll = (data.polls || []).find(item => item.id === req.params.id);

  if (!poll) return res.status(404).send("Abstimmung nicht gefunden.");

  poll.pinned = !poll.pinned;
  writeData(data);
  res.redirect("/admin#abstimmungen");
});

app.post("/admin/poll/:id/delete", requirePermission("polls.manage"), (req, res) => {
  const data = readData();

  data.polls = (data.polls || []).filter(poll => poll.id !== req.params.id);
  data.pollVotes = (data.pollVotes || []).filter(
    vote => vote.pollId !== req.params.id
  );

  writeData(data);
  res.redirect("/admin#abstimmungen");
});


app.post("/admin/media/:id/delete", requirePermission("media.manage"), (req, res) => {
  const data = readData();
  const media = (data.mediaFiles || []).find(item => item.id === req.params.id);

  if (!media) {
    return res.redirect("/admin?mediaDeleted=missing#medienverwaltung");
  }

  const storedName = path.basename(String(media.storedName || ""));
  const filePath = path.join(MEDIA_DIR, storedName);

  try {
    if (storedName && fs.existsSync(filePath)) {
      fs.rmSync(filePath, { force: true });
    }
  } catch (error) {
    console.error("Mediendatei konnte nicht gelöscht werden:", error);
    return res.redirect("/admin?mediaDeleted=error#medienverwaltung");
  }

  data.mediaFiles = (data.mediaFiles || []).filter(
    item => item.id !== media.id
  );

  writeData(data);
  return res.redirect("/admin?mediaDeleted=1#medienverwaltung");
});



app.get("/admin/system-check/download", requirePermission("security.manage"), (req, res) => {
  const report = runSystemDiagnostics();
  const filename = `vtuber-nexus-systemcheck-${new Date()
    .toISOString()
    .slice(0, 10)}.txt`;

  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="${filename}"`
  );

  return res.send(diagnosticsAsText(report));
});

app.post("/admin/backups/create", requirePermission("security.manage"), (req, res) => {
  const data = readData();
  const access = currentAccess(req);

  try {
    const filename = createDatabaseBackup("manual");
    cleanupOldBackups();

    addSecurityLog(data, "backup-created", {
      actorName: access.member?.name || "Gründer",
      actorRole: access.role,
      target: filename,
      ip: clientAddress(req)
    });
    writeData(data);

    return res.redirect("/admin?backup=created#sicherheit-backups");
  } catch (error) {
    console.error("Backup fehlgeschlagen:", error);
    return res.redirect("/admin?backup=error#sicherheit-backups");
  }
});

app.get("/admin/backups/:name/download", requirePermission("security.manage"), (req, res) => {
  const safeName = backupName(req.params.name);
  if (!safeName) return res.status(400).send("Ungültiger Backupname.");

  const filePath = path.join(BACKUP_DIR, safeName);
  if (!fs.existsSync(filePath)) return res.status(404).send("Backup nicht gefunden.");

  return res.download(filePath, safeName);
});

app.post("/admin/backups/:name/restore", requirePermission("security.manage"), (req, res) => {
  const safeName = backupName(req.params.name);
  if (!safeName) return res.status(400).send("Ungültiger Backupname.");

  const source = path.join(BACKUP_DIR, safeName);
  if (!fs.existsSync(source)) return res.status(404).send("Backup nicht gefunden.");

  try {
    createDatabaseBackup("before-restore");
    const restoredState = readBackupState(source);
    writeData(restoredState);

    const data = readData();
    const access = currentAccess(req);
    addSecurityLog(data, "backup-restored", {
      actorName: access.member?.name || "Gründer",
      actorRole: access.role,
      target: safeName,
      ip: clientAddress(req)
    });
    writeData(data);

    return res.redirect("/admin?backup=restored#sicherheit-backups");
  } catch (error) {
    console.error("Wiederherstellung fehlgeschlagen:", error);
    return res.redirect("/admin?backup=restore-error#sicherheit-backups");
  }
});

app.post("/admin/backups/:name/delete", requirePermission("security.manage"), (req, res) => {
  const safeName = backupName(req.params.name);
  if (!safeName) return res.status(400).send("Ungültiger Backupname.");

  fs.rmSync(path.join(BACKUP_DIR, safeName), { force: true });
  return res.redirect("/admin?backup=deleted#sicherheit-backups");
});

app.post("/admin/sessions/:name/delete", requirePermission("security.manage"), (req, res) => {
  const safeName = path.basename(String(req.params.name || ""));
  if (!safeName) return res.status(400).send("Ungültige Sitzung.");

  const sessionPath = path.join(__dirname, "data", "sessions", safeName);
  fs.rmSync(sessionPath, { force: true });

  const data = readData();
  const access = currentAccess(req);
  addSecurityLog(data, "session-ended", {
    actorName: access.member?.name || "Gründer",
    actorRole: access.role,
    target: safeName,
    ip: clientAddress(req)
  });
  writeData(data);

  return res.redirect("/admin?session=ended#sicherheit-backups");
});


app.post("/admin/roles", requireFounder, (req, res) => {
  const data = readData();
  const name = String(req.body.name || "").trim().slice(0, 50);
  const baseId = safeCustomRoleId(req.body.id || name);

  if (!name || !baseId) {
    return res.redirect("/admin?role=invalid#rollenverwaltung");
  }

  if (["founder", "moderator", "member"].includes(baseId)) {
    return res.redirect("/admin?role=reserved#rollenverwaltung");
  }

  if ((data.roles || []).some(role => role.id === baseId)) {
    return res.redirect("/admin?role=duplicate#rollenverwaltung");
  }

  const permissions = cleanRolePermissions(req.body.permissions);
  const role = {
    id: baseId,
    name,
    color: validHexColor(req.body.color, "#9b6cff"),
    system: false,
    protected: false,
    permissions
  };

  data.roles.push(role);
  addSecurityLog(data, "role-created", {
    actorName: (req.access || currentAccess(req)).member?.name || "Gründer",
    actorRole: "founder",
    target: `${role.name} (${role.id})`,
    ip: clientAddress(req)
  });
  writeData(data);

  return res.redirect("/admin?role=created#rollenverwaltung");
});

app.post("/admin/roles/:id", requireFounder, (req, res) => {
  const data = readData();
  const role = (data.roles || []).find(item => item.id === req.params.id);

  if (!role) {
    return res.redirect("/admin?role=missing#rollenverwaltung");
  }

  if (role.id === "founder") {
    return res.redirect("/admin?role=founder-protected#rollenverwaltung");
  }

  if (!role.system) {
    const name = String(req.body.name || role.name).trim().slice(0, 50);
    if (name) role.name = name;
  }

  role.color = validHexColor(req.body.color, role.color || "#9b6cff");
  role.permissions = cleanRolePermissions(req.body.permissions);

  // Die Mitgliedsrolle darf ohne Häkchen weiterhin eine reine Mitgliederrolle bleiben.
  // Der Gründer bleibt außerhalb dieses Formulars unveränderbar.
  for (const member of data.members || []) {
    if (member.roleId === role.id) member.role = role.name;
  }

  addSecurityLog(data, "role-updated", {
    actorName: (req.access || currentAccess(req)).member?.name || "Gründer",
    actorRole: "founder",
    target: `${role.name} (${role.id})`,
    ip: clientAddress(req)
  });
  writeData(data);

  return res.redirect("/admin?role=updated#rollenverwaltung");
});

app.post("/admin/roles/:id/delete", requireFounder, (req, res) => {
  const data = readData();
  const role = (data.roles || []).find(item => item.id === req.params.id);

  if (!role) {
    return res.redirect("/admin?role=missing#rollenverwaltung");
  }

  if (role.system || role.protected || ["founder", "moderator", "member"].includes(role.id)) {
    return res.redirect("/admin?role=system-protected#rollenverwaltung");
  }

  const fallback = roleDefinitionById(data, "member");
  let movedMembers = 0;

  for (const member of data.members || []) {
    if (member.roleId === role.id) {
      member.roleId = fallback.id;
      member.role = fallback.name;
      movedMembers += 1;
    }
  }

  data.roles = data.roles.filter(item => item.id !== role.id);
  addSecurityLog(data, "role-deleted", {
    actorName: (req.access || currentAccess(req)).member?.name || "Gründer",
    actorRole: "founder",
    target: `${role.name} · ${movedMembers} Mitglied(er) → ${fallback.name}`,
    ip: clientAddress(req)
  });
  writeData(data);

  return res.redirect(`/admin?role=deleted&roleMoved=${movedMembers}#rollenverwaltung`);
});

app.get("/admin/member/:id/edit", requirePermission("members.manage"), (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.params.id);
  if (!member) return res.redirect("/admin");
  res.render("edit-member", {
    data,
    member,
    roles: data.roles || [],
    permissionCatalog: ROLE_PERMISSION_CATALOG
  });
});

app.post("/admin/member/:id/edit", requirePermission("members.manage"), upload.fields([{ name: "avatar", maxCount: 1 }, { name: "banner", maxCount: 1 }]), (req, res) => {
  const data = readData();
  const index = data.members.findIndex(item => item.id === req.params.id);
  if (index < 0) return res.redirect("/admin");

  const existing = data.members[index];
  const name = String(req.body.name || "").trim();
  if (!name) return res.status(400).send("Name fehlt.");

  const updated = {
    ...existing,
    name,
    roleId: normalizedRole(existing) === "founder"
      ? "founder"
      : (req.access || currentAccess(req)).isFounder
        ? roleDefinitionById(
            data,
            String(req.body.roleId || existing.roleId || "member")
          ).id
        : existing.roleId || normalizedRole(existing),
    role: normalizedRole(existing) === "founder"
      ? "Gründer"
      : (req.access || currentAccess(req)).isFounder
        ? roleDefinitionById(
            data,
            String(req.body.roleId || existing.roleId || "member")
          ).name
        : existing.role,
    bio: normalizeProfileBio(req.body.bio),
    streamTitle: String(req.body.streamTitle || "").trim(),
    tags: String(req.body.tags || "")
      .split(",")
      .map(item => item.trim())
      .filter(Boolean),
    schedule: String(req.body.schedule || "")
      .split(",")
      .map(item => item.trim())
      .filter(Boolean),
    twitch: String(req.body.twitch || "").trim(),
    twitchLogin: String(req.body.twitchLogin || "").trim().replace(/^@/, "").toLowerCase(),
    youtube: String(req.body.youtube || "").trim(),
    tiktok: String(req.body.tiktok || "").trim(),
    live: req.body.live === "on",
    pronouns: String(req.body.pronouns || "").trim(),
    languages: String(req.body.languages || "").split(",").map(v=>v.trim()).filter(Boolean),
    favoriteGames: String(req.body.favoriteGames || "").split(",").map(v=>v.trim()).filter(Boolean),
    debutDate: String(req.body.debutDate || "").trim(),
    artist: String(req.body.artist || "").trim(),
    rigger: String(req.body.rigger || "").trim(),
    discord: String(req.body.discord || "").trim(),
    clips: String(req.body.clips || "").split(",").map(v=>v.trim()).filter(Boolean),
    avatar: req.files?.avatar?.[0] ? `/uploads/${req.files.avatar[0].filename}` : existing.avatar || "",
    banner: req.files?.banner?.[0] ? `/uploads/${req.files.banner[0].filename}` : existing.banner || "",
    color1: String(req.body.color1 || "#9b6cff"),
    color2: String(req.body.color2 || "#36d9c4")
  };

  data.members[index] = updated;
  writeData(data);
  res.redirect("/admin");
});

app.post(
  "/admin/group",
  requirePermission("group.manage"),
  upload.fields([{ name: "groupLogo", maxCount: 1 }, { name: "groupBanner", maxCount: 1 }]),
  (req, res) => {
    const data = readData();
    if (Object.prototype.hasOwnProperty.call(req.body, "name")) {
      const requestedName = String(req.body.name || "").trim();
      if (requestedName) {
        data.group.name = requestedName;
        data.group.branding = {
          ...(data.group.branding || {}),
          siteName: requestedName
        };
      }
    }

    data.group.tagline = String(req.body.tagline || "").trim();
    data.group.description = String(req.body.description || "").trim();

    if (req.files?.groupLogo?.[0]) {
      const groupLogo = `/uploads/${req.files.groupLogo[0].filename}`;
      data.group.logo = groupLogo;
      data.group.branding = {
        ...(data.group.branding || {}),
        logo: groupLogo
      };
    }

    if (req.files?.groupBanner?.[0]) {
      data.group.banner = `/uploads/${req.files.groupBanner[0].filename}`;
    }

    writeData(data);
    res.redirect("/admin");
  }
);

app.post(
  "/admin/member",
  requirePermission("members.manage"),
  upload.fields([
    { name: "avatar", maxCount: 1 },
    { name: "banner", maxCount: 1 }
  ]),
  (req, res) => {
    const data = readData();
    const access = req.access || currentAccess(req);
    const name = String(req.body.name || "").trim();

    if (!name) return res.status(400).send("Name fehlt.");

    const baseId = slugify(req.body.id || name) || `mitglied-${Date.now()}`;
    let id = baseId;
    let suffix = 2;

    // Ein neues Mitglied darf niemals versehentlich ein bestehendes Profil überschreiben.
    while (data.members.some(item => item.id === id)) {
      id = `${baseId}-${suffix}`;
      suffix += 1;
    }

    const selectedRole = access.isFounder
      ? roleDefinitionById(data, String(req.body.roleId || "member"))
      : roleDefinitionById(data, "member");
    const roleId = selectedRole.id;
    const role = selectedRole.name;

    const member = {
      id,
      name,
      roleId,
      role,
      bio: normalizeProfileBio(req.body.bio),
      streamTitle: String(req.body.streamTitle || "").trim(),
      tags: String(req.body.tags || "").split(",").map(item => item.trim()).filter(Boolean),
      schedule: String(req.body.schedule || "").split(",").map(item => item.trim()).filter(Boolean),
      twitch: String(req.body.twitch || "").trim(),
      twitchLogin: String(req.body.twitchLogin || "").trim().replace(/^@/, "").toLowerCase(),
      youtube: String(req.body.youtube || "").trim(),
      tiktok: String(req.body.tiktok || "").trim(),
      live: req.body.live === "on",
      pronouns: String(req.body.pronouns || "").trim(),
      languages: String(req.body.languages || "").split(",").map(value => value.trim()).filter(Boolean),
      favoriteGames: String(req.body.favoriteGames || "").split(",").map(value => value.trim()).filter(Boolean),
      debutDate: String(req.body.debutDate || "").trim(),
      artist: String(req.body.artist || "").trim(),
      rigger: String(req.body.rigger || "").trim(),
      discord: String(req.body.discord || "").trim(),
      clips: String(req.body.clips || "").split(",").map(value => value.trim()).filter(Boolean),
      avatar: req.files?.avatar?.[0] ? `/uploads/${req.files.avatar[0].filename}` : "",
      banner: req.files?.banner?.[0] ? `/uploads/${req.files.banner[0].filename}` : "",
      color1: validHexColor(req.body.color1, "#9b6cff"),
      color2: validHexColor(req.body.color2, "#36d9c4"),
      account: {
        username: "",
        passwordHash: "",
        enabled: false
      },
      profileDesign: defaultProfileDesign()
    };

    data.members.push(member);
    addActivity(data, "member", `${name} wurde als Mitglied angelegt.`);
    addNotification(data, {
    targetMemberId: member.id,
    type: "welcome",
    title: `Willkommen bei ${data.group.name}`,
    message: "Dein Mitgliederprofil wurde erstellt. Ergänze jetzt dein Profil und dein individuelles Design.",
    link: "/member-area"
  });
  writeData(data);
    res.redirect("/admin");
  }
);

app.post("/admin/member/:id/delete", requirePermission("members.delete"), (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.params.id);

  if (!member) {
    return res.status(404).send("Mitglied nicht gefunden.");
  }

  const role = normalizedRole(member);

  if (role === "founder") {
    return res.status(403).render("forbidden", {
      data,
      message: "Ein Gründerprofil kann aus Sicherheitsgründen nicht gelöscht werden."
    });
  }

  data.members = data.members.filter(item => item.id !== member.id);
  writeData(data);

  res.redirect("/admin");
});

app.post("/admin/member/:id/toggle-live", requirePermission("members.manage"), (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.params.id);
  if (member) {
    member.live = !member.live;
    writeData(data);
  }
  res.redirect("/admin");
});


app.post("/admin/event", requirePermission("events.manage"), (req, res) => {
  const data = readData();
  data.events = data.events || [];

  const title = String(req.body.title || "").trim();
  if (!title) return res.status(400).send("Event-Titel fehlt.");

  const event = {
    id: slugify(`${title}-${req.body.date}-${req.body.time}`) || `event-${Date.now()}`,
    title,
    date: String(req.body.date || "").trim(),
    time: String(req.body.time || "").trim(),
    description: String(req.body.description || "").trim()
  };

  data.events.push(event);
  addNotification(data, {
      type: "event",
      title: "Neues Community-Event",
      message: `${event.title} wurde als neues Event eingetragen.`,
      link: `/events/${event.id}`
    });
    writeData(data);
  res.redirect("/admin");
});

app.post("/admin/event/:id/delete", requirePermission("events.manage"), (req, res) => {
  const data = readData();
  data.events = (data.events || []).filter(event => event.id !== req.params.id);
  writeData(data);
  res.redirect("/admin");
});


app.post("/admin/application/:id/status", requirePermission("requests.manage"), (req, res) => {
  const data = readData();
  const application = (data.applications || []).find(item => item.id === req.params.id);
  if (!application) return res.redirect("/admin");

  const newStatus = String(req.body.status || "offen");
  application.status = newStatus;

  if (newStatus === "angenommen") {
    let memberId = slugify(application.name);
    if (!memberId) memberId = `mitglied-${Date.now()}`;

    const duplicate = data.members.find(member =>
      member.id === memberId ||
      member.name.toLowerCase() === application.name.toLowerCase()
    );

    if (!duplicate) {
      const links = {
        twitch: "",
        youtube: "",
        tiktok: ""
      };

      const platform = String(application.platform || "").toLowerCase();
      if (platform === "twitch") links.twitch = application.channelUrl;
      else if (platform === "youtube") links.youtube = application.channelUrl;
      else if (platform === "tiktok") links.tiktok = application.channelUrl;

      data.members.push({
        id: memberId,
        name: application.name,
        role: "Mitglied",
        bio: normalizeProfileBio(application.message),
        streamTitle: `${application.name} streamt auf ${application.platform}`,
        tags: [application.platform].filter(Boolean),
        schedule: [],
        twitch: links.twitch,
        youtube: links.youtube,
        tiktok: links.tiktok,
        live: false,
        pronouns: "",
        languages: [],
        favoriteGames: [],
        debutDate: "",
        artist: "",
        rigger: "",
        discord: application.contactDiscordName || application.discord || "",
        clips: [],
        avatar: application.avatar || "",
        banner: "",
        color1: "#9b6cff",
        color2: "#36d9c4",
        account: {
          username: "",
          passwordHash: "",
          enabled: false
        },
        profileDesign: defaultProfileDesign()
      });
      addActivity(data, "member", `${application.name} wurde als Mitglied aufgenommen.`);
    }
  }

  writeData(data);
  res.redirect("/admin");
});

app.post("/admin/application/:id/delete", requirePermission("requests.manage"), (req, res) => {
  const data = readData();
  const application = (data.applications || []).find(item => item.id === req.params.id);

  if (application?.avatar && application.avatar.startsWith("/uploads/")) {
    const filePath = path.join(__dirname, "public", application.avatar);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  }

  data.applications = (data.applications || []).filter(item => item.id !== req.params.id);
  writeData(data);
  res.redirect("/admin");
});

app.get("/admin/application/:id", requirePermission("requests.manage"), (req, res) => {
  const data = readData();
  const application = (data.applications || []).find(item => item.id === req.params.id);
  if (!application) return res.redirect("/admin");
  res.render("application-detail", { data, application });
});

app.post("/admin/application/:id/note", requirePermission("requests.manage"), (req, res) => {
  const data = readData();
  const application = (data.applications || []).find(item => item.id === req.params.id);
  if (application) { application.internalNote = String(req.body.internalNote || "").trim(); writeData(data); }
  res.redirect(`/admin/application/${req.params.id}`);
});


app.get("/admin/backup", requirePermission("security.manage"), (_req, res) => {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="vtuber-nexus-backup-${timestamp}.json"`
  );
  res.send(exportJson());
});

app.post("/admin/restore", requirePermission("security.manage"), backupUpload.single("backupFile"), (req, res) => {
  if (!req.file?.buffer) {
    return res.status(400).send("Keine JSON-Backup-Datei ausgewählt.");
  }

  try {
    createDatabaseBackup("before-json-restore");
    importJson(req.file.buffer.toString("utf8"));

    const data = readData();
    const access = currentAccess(req);
    addSecurityLog(data, "json-backup-restored", {
      actorName: access.member?.name || "Gründer",
      actorRole: access.role,
      target: req.file.originalname,
      ip: clientAddress(req)
    });
    writeData(data);

    return res.redirect("/admin?backup=json-restored#sicherheit-backups");
  } catch (error) {
    return res.status(400).send(
      `Backup konnte nicht importiert werden: ${error.message}`
    );
  }
});


app.post("/admin/legal", requirePermission("legal.manage"), (req, res) => {
  const data = readData();
  data.legal = {
    operatorName: String(req.body.operatorName || "").trim(),
    address: String(req.body.address || "").trim(),
    email: String(req.body.email || "").trim(),
    responsible: String(req.body.responsible || "").trim(),
    privacyContact: String(req.body.privacyContact || "").trim()
  };
  writeData(data);
  res.redirect("/admin");
});


app.get("/admin/contact/:id", requirePermission("requests.manage"), (req, res) => {
  const data = readData();
  const contact = (data.contactMessages || []).find(
    item => item.id === req.params.id
  );

  if (!contact) {
    return res.status(404).render("forbidden", {
      data,
      message: "Diese Kontaktanfrage wurde nicht gefunden oder bereits gelöscht."
    });
  }

  res.render("contact-detail", {
    data,
    contact
  });
});

app.post("/admin/contact/:id/status", requirePermission("requests.manage"), (req, res) => {
  const data = readData();
  const contact = (data.contactMessages || []).find(
    item => item.id === req.params.id
  );

  if (contact) {
    contact.status = String(req.body.status || "offen");
    writeData(data);
  }

  const returnTo = req.body.returnTo === "detail"
    ? `/admin/contact/${req.params.id}`
    : "/admin";

  res.redirect(returnTo);
});

app.post("/admin/contact/:id/delete", requirePermission("requests.manage"), (req, res) => {
  const data = readData();
  data.contactMessages = (data.contactMessages || []).filter(item => item.id !== req.params.id);
  writeData(data);
  res.redirect("/admin");
});


app.post("/admin/member/:id/account", requirePermission("member_accounts.manage"), (req, res) => {
  const data = readData();
  const member = data.members.find(item => item.id === req.params.id);
  if (!member) return res.redirect("/admin");

  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const enabled = req.body.enabled === "on";

  const duplicate = data.members.find(item =>
    item.id !== member.id &&
    String(item.account?.username || "").toLowerCase() === username &&
    username
  );

  if (duplicate) {
    return res.status(400).send("Dieser Benutzername wird bereits verwendet.");
  }

  member.account = member.account || {
    username: "",
    passwordHash: "",
    enabled: false
  };

  member.account.username = username;
  member.account.enabled = enabled;

  if (password) {
    if (password.length < 10) {
      return res.status(400).send("Das Passwort muss mindestens 10 Zeichen lang sein.");
    }
    member.account.passwordHash = hashPassword(password);
  }

  if (enabled && (!username || !member.account.passwordHash)) {
    return res.status(400).send("Für einen aktiven Zugang werden Benutzername und Passwort benötigt.");
  }

  writeData(data);
  res.redirect(`/admin/member/${member.id}/edit`);
});


app.post("/admin/news", requirePermission("news.manage"), (req, res) => {
  const data = readData();
  data.news = data.news || [];

  const title = String(req.body.title || "").trim();
  const summary = String(req.body.summary || "").trim();
  const content = String(req.body.content || "").trim();
  const author = String(req.body.author || "Admin").trim();

  if (!title || !content) {
    return res.status(400).send("Titel und Inhalt werden benötigt.");
  }

  const article = {
    id: slugify(`${title}-${Date.now()}`),
    title,
    summary,
    content,
    author,
    createdAt: new Date().toISOString(),
    published: req.body.published === "on"
  };

  data.news.unshift(article);
  addActivity(data, "news", `Neue Ankündigung erstellt: „${title}“`);
  writeData(data);
  res.redirect("/admin");
});

app.post("/admin/news/:id/toggle", requirePermission("news.manage"), (req, res) => {
  const data = readData();
  const article = (data.news || []).find(item => item.id === req.params.id);
  if (article) {
    article.published = !article.published;
    addActivity(
      data,
      "news",
      `Ankündigung „${article.title}“ wurde ${article.published ? "veröffentlicht" : "ausgeblendet"}.`
    );
    writeData(data);
  }
  res.redirect("/admin");
});

app.post("/admin/news/:id/delete", requirePermission("news.manage"), (req, res) => {
  const data = readData();
  const article = (data.news || []).find(item => item.id === req.params.id);
  data.news = (data.news || []).filter(item => item.id !== req.params.id);
  if (article) addActivity(data, "news", `Ankündigung gelöscht: „${article.title}“`);
  writeData(data);
  res.redirect("/admin");
});

app.post("/admin/event/:eventId/registration/:registrationId/status", requirePermission("events.manage"), (req, res) => {
  const data = readData();
  const event = (data.events || []).find(item => item.id === req.params.eventId);
  const registration = event?.registrations?.find(item => item.id === req.params.registrationId);

  if (registration) {
    registration.status = String(req.body.status || "angemeldet");
    addActivity(
      data,
      "event-registration",
      `${registration.name}: Teilnahme bei „${event.title}“ auf ${registration.status} gesetzt.`
    );
    writeData(data);
  }

  res.redirect("/admin");
});

app.post("/admin/event/:eventId/registration/:registrationId/delete", requirePermission("events.manage"), (req, res) => {
  const data = readData();
  const event = (data.events || []).find(item => item.id === req.params.eventId);
  if (event) {
    const registration = (event.registrations || []).find(item => item.id === req.params.registrationId);
    event.registrations = (event.registrations || []).filter(
      item => item.id !== req.params.registrationId
    );
    if (registration) {
      addActivity(
        data,
        "event-registration",
        `Event-Anmeldung von ${registration.name} bei „${event.title}“ gelöscht.`
      );
    }
    writeData(data);
  }
  res.redirect("/admin");
});

let serverReady = false;

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    version: APP_VERSION,
    uptimeSeconds: Math.round(process.uptime())
  });
});

app.get("/ready", (_req, res) => {
  let databaseOk = false;
  let storageOk = false;

  try {
    databaseOk = checkDatabaseIntegrity().ok;
    storageOk = [
      directoryStatus("Medien", MEDIA_DIR),
      directoryStatus("Backups", BACKUP_DIR),
      directoryStatus("Uploads", UPLOAD_DIR),
      directoryStatus("Sitzungen", SESSION_DIR)
    ].every(item => item.ok);
  } catch {
    databaseOk = false;
    storageOk = false;
  }

  const ready = serverReady && databaseOk && storageOk;

  return res.status(ready ? 200 : 503).json({
    ready,
    version: APP_VERSION,
    database: databaseOk,
    storage: storageOk
  });
});

app.use((_req, res) => {
  const data = readData();
  res.status(404).render("not-found", { data });
});


app.use((err, req, res, _next) => {
  const requestId = req.requestId || `VN-${Date.now().toString(36).toUpperCase()}`;

  console.error(`[${requestId}]`, err);

  const data = readData();
  addSecurityLog(data, "server-error", {
    actorName: req.access?.member?.name || "System",
    actorRole: req.access?.role || "",
    target: `${requestId} · ${req.method} ${req.originalUrl}`,
    ip: clientAddress(req)
  });
  writeData(data);

  const isUploadError = err instanceof multer.MulterError || [
    "Nur PNG, JPG, WEBP oder GIF sind erlaubt.",
    "Erlaubt sind PNG, JPG, WEBP, GIF, PDF, TXT, JSON, DOCX und ZIP.",
    "Für diese Wiederherstellung ist nur eine JSON-Datei erlaubt."
  ].includes(String(err.message || ""));
  const statusCode = isUploadError ? 400 : err.status || 500;

  res.status(statusCode).render("error", {
    data,
    requestId,
    message: IS_PRODUCTION
      ? "Die Anfrage konnte nicht verarbeitet werden."
      : err.message || "Unbekannter Fehler"
  });
});

if (IS_PRODUCTION) {
  const configurationProblems = productionConfigurationProblems();

  if (configurationProblems.length) {
    console.error("Produktionsstart abgebrochen:");
    configurationProblems.forEach(problem => {
      console.error(`- ${problem}`);
    });
    closeDatabase();
    process.exit(1);
  }
}

function runAutomaticBackup() {
  try {
    const latest = listDatabaseBackups()[0];
    const recent = latest &&
      Date.now() - new Date(latest.createdAt).getTime() < BACKUP_INTERVAL_MS;

    if (!recent) {
      createDatabaseBackup("automatic");
      cleanupOldBackups();
      console.log("Automatisches Datenbank-Backup erstellt.");
    }
  } catch (error) {
    console.error("Automatisches Backup fehlgeschlagen:", error);
  }
}

if (AUTO_BACKUP_ENABLED) {
  runAutomaticBackup();
  setInterval(runAutomaticBackup, BACKUP_INTERVAL_MS).unref();
}

const httpServer = app.listen(PORT, () => {
  serverReady = true;

  const publicAddress = SITE_URL || `http://localhost:${PORT}`;
  console.log(`${readData().group.name} läuft auf ${publicAddress}`);
  console.log(`Version: ${APP_VERSION}`);
  console.log(`Modus: ${IS_PRODUCTION ? "production" : "development"}`);
  console.log(`SQLite-Datenbank: ${DB_FILE}`);

  if (!IS_PRODUCTION && !process.env.ADMIN_PASSWORD) {
    console.log(
      "Hinweis: Lokales Standard-Adminpasswort ist admin123. Vor dem Onlinegang ändern."
    );
  }
});

httpServer.requestTimeout = Number(process.env.REQUEST_TIMEOUT_MS || 30_000);
httpServer.headersTimeout = Number(process.env.HEADERS_TIMEOUT_MS || 35_000);
httpServer.keepAliveTimeout = Number(process.env.KEEP_ALIVE_TIMEOUT_MS || 5_000);
httpServer.maxRequestsPerSocket = Number(
  process.env.MAX_REQUESTS_PER_SOCKET || 1000
);

let shuttingDown = false;

function shutdown(signal, exitCode = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  serverReady = false;

  console.log(`\n${signal} empfangen. Server wird sauber beendet...`);

  httpServer.close(() => {
    try {
      checkpointDatabase();
    } catch {}

    closeDatabase();
    process.exit(exitCode);
  });

  setTimeout(() => {
    closeDatabase();
    process.exit(exitCode || 1);
  }, 10_000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

process.on("unhandledRejection", error => {
  console.error("Unbehandelte Promise-Ablehnung:", error);
  shutdown("unhandledRejection", 1);
});

process.on("uncaughtException", error => {
  console.error("Unbehandelter Programmfehler:", error);
  shutdown("uncaughtException", 1);
});
