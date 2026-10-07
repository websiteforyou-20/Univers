const path = require("path");
const fs = require("fs");
const { DatabaseSync } = require("node:sqlite");

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = process.env.DATABASE_PATH
  ? path.resolve(process.env.DATABASE_PATH)
  : path.join(DATA_DIR, "nexus.db");
const LEGACY_JSON_FILE = path.join(DATA_DIR, "site.json");

fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });

const db = new DatabaseSync(DB_FILE);

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  PRAGMA busy_timeout = 5000;

  CREATE TABLE IF NOT EXISTS app_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    state_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
  );
`);


const DEFAULT_MODERATOR_PERMISSIONS = [
  "admin.access",
  "communications.manage",
  "members.manage",
  "events.manage",
  "requests.manage",
  "news.manage",
  "community.manage",
  "projects.manage",
  "media.manage",
  "polls.manage"
];

function defaultRoles() {
  return [
    {
      id: "founder",
      name: "Gründer",
      color: "#f6c75b",
      system: true,
      protected: true,
      permissions: ["*"]
    },
    {
      id: "moderator",
      name: "Moderator",
      color: "#7c8cff",
      system: true,
      protected: true,
      permissions: [...DEFAULT_MODERATOR_PERMISSIONS]
    },
    {
      id: "member",
      name: "Mitglied",
      color: "#35d0b1",
      system: true,
      protected: true,
      permissions: []
    }
  ];
}

function safeRoleId(value, fallback = "member") {
  const normalized = String(value || "")
    .trim()
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/ß/g, "ss")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);

  return normalized || fallback;
}

function legacyRoleId(value) {
  const role = String(value || "").trim().toLowerCase();
  if (["gründer", "gruender", "grunder", "founder"].includes(role)) return "founder";
  if (["moderator", "moderatorin", "mod"].includes(role)) return "moderator";
  if (["mitglied", "member"].includes(role)) return "member";
  return "";
}

function normalizeRoles(input) {
  const defaults = defaultRoles();
  const source = Array.isArray(input) ? input : [];
  const result = [];
  const usedIds = new Set();

  for (const defaultRole of defaults) {
    const existing = source.find(item => safeRoleId(item?.id, "") === defaultRole.id);
    const role = existing && typeof existing === "object" ? existing : {};

    result.push({
      ...defaultRole,
      name: defaultRole.id === "founder"
        ? "Gründer"
        : String(role.name || defaultRole.name).trim().slice(0, 50) || defaultRole.name,
      color: /^#[0-9a-fA-F]{6}$/.test(String(role.color || ""))
        ? String(role.color)
        : defaultRole.color,
      permissions: defaultRole.id === "founder"
        ? ["*"]
        : Array.isArray(role.permissions)
          ? [...new Set(role.permissions.map(String))]
          : [...defaultRole.permissions],
      system: true,
      protected: true
    });
    usedIds.add(defaultRole.id);
  }

  for (const item of source) {
    if (!item || typeof item !== "object") continue;
    const id = safeRoleId(item.id || item.name, "");
    if (!id || usedIds.has(id)) continue;

    const name = String(item.name || id).trim().slice(0, 50);
    if (!name) continue;

    result.push({
      id,
      name,
      color: /^#[0-9a-fA-F]{6}$/.test(String(item.color || ""))
        ? String(item.color)
        : "#9b6cff",
      permissions: Array.isArray(item.permissions)
        ? [...new Set(item.permissions.map(String))]
        : [],
      system: false,
      protected: false
    });
    usedIds.add(id);
  }

  return result;
}

function defaultState() {
  return {
    group: {
      name: "VTuber Nexus",
      tagline: "Unabhängig. Kreativ. Gemeinsam live.",
      description: "Eine unabhängige VTuber- und Streamer-Community.",
      logo: "",
      banner: "",
      siteBackground: {
        mode: "gradient",
        color1: "#090b16",
        color2: "#10232d",
        image: "",
        overlay: 82,
        fixed: true
      },
      headerDesign: {
        mode: "galaxy",
        color1: "#050818",
        color2: "#17103a",
        accent1: "#5767ff",
        accent2: "#be3cff",
        image: "",
        overlay: 76,
        blur: 18,
        shadow: true
      },
      branding: {
        siteName: "VTuber Nexus",
        subtitle: "Community Hub",
        abbreviation: "VN",
        browserTitle: "VTuber Nexus",
        adminName: "Admin",
        adminAbbreviation: "VN",
        footerName: "VTuber Nexus",
        logo: "",
        favicon: "",
        socialImage: ""
      },
      siteDesign: {
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
      },
      siteAnimations: {
        enabled: true,
        type: "fade-up",
        speed: "normal",
        intensity: 100,
        trigger: "viewport",
        stagger: true,
        hoverEffects: true
      }
    },
    roles: defaultRoles(),
    members: [],
    events: [],
    applications: [],
    contactMessages: [],
    news: [],
    activityLog: [],
    notifications: [],
    internalMessages: [],
    memberTasks: [],
    teamEvents: [],
    eventResponses: [],
    communityPosts: [],
    communityComments: [],
    projects: [],
    mediaFiles: [],
    polls: [],
    pollVotes: [],
    securityLog: [],
    loginAttempts: {},
    legal: {
      operatorName: "HIER DEINEN NAMEN EINTRAGEN",
      address: "HIER DEINE LADUNGSFÄHIGE ANSCHRIFT EINTRAGEN",
      email: "HIER DEINE KONTAKT-E-MAIL EINTRAGEN",
      responsible: "HIER VERANTWORTLICHE PERSON EINTRAGEN",
      privacyContact: "HIER DATENSCHUTZ-KONTAKT EINTRAGEN"
    }
  };
}

function defaultProfileDesign() {
  return {
    theme: "nexus", primaryColor: "#7c5cff", accentColor: "#35e0d0",
    backgroundColor: "#090b16", backgroundStyle: "gradient", cardStyle: "glass", backgroundImage: ""
  };
}

function normalizeState(input) {
  const state = input && typeof input === "object" ? input : defaultState();

  state.group = state.group || defaultState().group;
  state.group.siteBackground = {
    ...defaultState().group.siteBackground,
    ...(state.group.siteBackground || {})
  };
  state.group.headerDesign = {
    ...defaultState().group.headerDesign,
    ...(state.group.headerDesign || {})
  };

  const legacyBrandName =
    String(state.group.name || defaultState().group.name).trim() ||
    defaultState().group.name;

  const legacyAbbreviation =
    legacyBrandName
      .split(/\s+/)
      .filter(Boolean)
      .map(word => word.charAt(0))
      .join("")
      .slice(0, 5)
      .toUpperCase() || "VN";

  state.group.branding = {
    ...defaultState().group.branding,
    siteName: legacyBrandName,
    browserTitle: legacyBrandName,
    footerName: legacyBrandName,
    abbreviation: legacyAbbreviation,
    adminAbbreviation: legacyAbbreviation,
    logo: state.group.logo || "",
    ...(state.group.branding || {})
  };

  state.group.branding.siteName =
    String(state.group.branding.siteName || legacyBrandName).trim() ||
    legacyBrandName;

  state.group.branding.browserTitle =
    String(
      state.group.branding.browserTitle ||
      state.group.branding.siteName
    ).trim() || state.group.branding.siteName;

  state.group.branding.footerName =
    String(
      state.group.branding.footerName ||
      state.group.branding.siteName
    ).trim() || state.group.branding.siteName;

  state.group.name = state.group.branding.siteName;
  state.group.logo = state.group.branding.logo || "";

  state.group.siteDesign = {
    ...defaultState().group.siteDesign,
    ...(state.group.siteDesign || {})
  };
  state.group.siteAnimations = {
    ...defaultState().group.siteAnimations,
    ...(state.group.siteAnimations || {})
  };
  state.roles = normalizeRoles(state.roles);
  state.members = Array.isArray(state.members) ? state.members : [];
  state.events = Array.isArray(state.events) ? state.events : [];
  state.applications = Array.isArray(state.applications) ? state.applications : [];
  state.contactMessages = Array.isArray(state.contactMessages) ? state.contactMessages : [];
  state.news = Array.isArray(state.news) ? state.news : [];
  state.activityLog = Array.isArray(state.activityLog) ? state.activityLog : [];
  state.notifications = Array.isArray(state.notifications) ? state.notifications : [];
  state.internalMessages = Array.isArray(state.internalMessages) ? state.internalMessages : [];
  state.memberTasks = Array.isArray(state.memberTasks) ? state.memberTasks : [];
  state.teamEvents = Array.isArray(state.teamEvents) ? state.teamEvents : [];
  state.eventResponses = Array.isArray(state.eventResponses) ? state.eventResponses : [];
  state.communityPosts = Array.isArray(state.communityPosts) ? state.communityPosts : [];
  state.communityComments = Array.isArray(state.communityComments) ? state.communityComments : [];
  state.projects = Array.isArray(state.projects) ? state.projects : [];
  state.mediaFiles = Array.isArray(state.mediaFiles) ? state.mediaFiles : [];
  state.polls = Array.isArray(state.polls) ? state.polls : [];
  state.pollVotes = Array.isArray(state.pollVotes) ? state.pollVotes : [];
  state.securityLog = Array.isArray(state.securityLog) ? state.securityLog : [];
  state.loginAttempts = state.loginAttempts && typeof state.loginAttempts === "object"
    ? state.loginAttempts
    : {};
  state.legal = state.legal || defaultState().legal;

  // Reparatur für Version 30.1:
  // Die erste Rollen-Migration konnte bestehende Gründerkonten versehentlich
  // als "Mitglied" speichern. Frühere Sicherheitsprotokolle liefern hier ein
  // belastbares Signal, dass das Konto zuvor Gründerrechte hatte.
  const historicalFounderNames = new Set(
    (state.securityLog || [])
      .filter(entry => legacyRoleId(entry?.actorRole) === "founder")
      .map(entry => String(entry?.actorName || "").trim().toLowerCase())
      .filter(Boolean)
  );

  const configuredFounderUsernames = new Set(
    String(process.env.FOUNDER_USERNAMES || "")
      .split(",")
      .map(value => value.trim().toLowerCase())
      .filter(Boolean)
  );

  for (const member of state.members) {
    const rawRoleId = String(member.roleId || "").trim();
    const normalizedRawRoleId = safeRoleId(rawRoleId, "");
    const legacyRoleIdFromId = legacyRoleId(rawRoleId);
    const legacyRoleIdFromName = legacyRoleId(member.role);

    // Wichtig für bestehende Datenbanken:
    // ältere Fassungen konnten roleId als „Gründer“, „gruender“ usw. speichern.
    // Erst eine tatsächlich vorhandene Rollen-ID akzeptieren. Danach alte
    // Systemrollenbezeichnungen und zuletzt den sichtbaren Rollennamen prüfen.
    let requestedRoleId = "";

    if (normalizedRawRoleId && state.roles.some(role => role.id === normalizedRawRoleId)) {
      requestedRoleId = normalizedRawRoleId;
    } else if (legacyRoleIdFromId) {
      requestedRoleId = legacyRoleIdFromId;
    } else if (legacyRoleIdFromName) {
      requestedRoleId = legacyRoleIdFromName;
    }

    if (!requestedRoleId) {
      const rawVisibleRole = String(member.role || "").trim().toLowerCase();
      const matchingRole = state.roles.find(role =>
        String(role.name || "").trim().toLowerCase() === rawVisibleRole
      );
      requestedRoleId = matchingRole?.id || "member";
    }

    const memberNameKey = String(member.name || "").trim().toLowerCase();
    const memberUsernameKey = String(member.account?.username || "")
      .trim()
      .toLowerCase();

    const historicallyFounder =
      historicalFounderNames.has(memberNameKey) ||
      configuredFounderUsernames.has(memberUsernameKey);

    if (historicallyFounder && requestedRoleId === "member") {
      requestedRoleId = "founder";
    }

    const assignedRole =
      state.roles.find(role => role.id === requestedRoleId) ||
      state.roles.find(role => role.id === "member");

    member.roleId = assignedRole?.id || "member";
    member.role = assignedRole?.name || "Mitglied";
    member.tags = Array.isArray(member.tags) ? member.tags : [];
    member.schedule = Array.isArray(member.schedule) ? member.schedule : [];
    member.languages = Array.isArray(member.languages) ? member.languages : [];
    member.favoriteGames = Array.isArray(member.favoriteGames) ? member.favoriteGames : [];
    member.clips = Array.isArray(member.clips) ? member.clips : [];
    member.account = member.account || {
      username: "",
      passwordHash: "",
      enabled: false
    };
    member.notificationPreferences = {
      applications: true,
      contacts: true,
      events: true,
      profileUpdates: true,
      ...(member.notificationPreferences || {})
    };
    member.profileDesign = { ...defaultProfileDesign(), ...(member.profileDesign || {}) };
  }

  for (const event of state.events) {
    event.registrations = Array.isArray(event.registrations) ? event.registrations : [];
  }

  return state;
}

const getStateStatement = db.prepare(
  "SELECT state_json FROM app_state WHERE id = 1"
);

const saveStateStatement = db.prepare(`
  INSERT INTO app_state (id, state_json, updated_at)
  VALUES (?, ?, ?)
  ON CONFLICT(id) DO UPDATE SET
    state_json = excluded.state_json,
    updated_at = excluded.updated_at
`);

function saveState(state) {
  db.exec("BEGIN IMMEDIATE");

  try {
    saveStateStatement.run(
      1,
      JSON.stringify(normalizeState(state)),
      new Date().toISOString()
    );
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function initialize() {
  const existing = getStateStatement.get();
  if (existing) return;

  let initialState = defaultState();

  if (fs.existsSync(LEGACY_JSON_FILE)) {
    try {
      initialState = JSON.parse(fs.readFileSync(LEGACY_JSON_FILE, "utf8"));
      console.log("Bestehende data/site.json wird einmalig nach SQLite importiert.");
    } catch (error) {
      console.error("site.json konnte nicht importiert werden:", error.message);
    }
  }

  saveState(initialState);
}

function readData() {
  const row = getStateStatement.get();

  if (!row) {
    initialize();
    return readData();
  }

  return normalizeState(JSON.parse(row.state_json));
}

function writeData(state) {
  saveState(state);
}

function exportJson() {
  return JSON.stringify(readData(), null, 2);
}

function importJson(raw) {
  const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;

  if (!parsed || !parsed.group || !Array.isArray(parsed.members)) {
    throw new Error("Die Datei ist kein gültiges VTuber-Nexus-Backup.");
  }

  writeData(parsed);
}


function checkpointDatabase() {
  db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
}

function checkDatabaseIntegrity() {
  const rows = db.prepare("PRAGMA integrity_check").all();
  const messages = rows.map(row => String(Object.values(row)[0] || ""));
  return {
    ok: messages.length === 1 && messages[0].toLowerCase() === "ok",
    messages
  };
}

function readBackupState(filePath) {
  const backupDb = new DatabaseSync(filePath, { readOnly: true });

  try {
    const integrityRows = backupDb.prepare("PRAGMA integrity_check").all();
    const integrityMessages = integrityRows.map(
      row => String(Object.values(row)[0] || "")
    );

    if (
      integrityMessages.length !== 1 ||
      integrityMessages[0].toLowerCase() !== "ok"
    ) {
      throw new Error(
        `SQLite-Integritätsprüfung fehlgeschlagen: ${integrityMessages.join("; ")}`
      );
    }

    const row = backupDb.prepare(
      "SELECT state_json FROM app_state WHERE id = 1"
    ).get();

    if (!row?.state_json) {
      throw new Error("Das Backup enthält keinen gültigen VTuber-Nexus-Datenstand.");
    }

    return normalizeState(JSON.parse(row.state_json));
  } finally {
    backupDb.close();
  }
}

function closeDatabase() {
  try {
    db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  } finally {
    db.close();
  }
}

initialize();

module.exports = {
  DB_FILE,
  readData,
  writeData,
  exportJson,
  importJson,
  closeDatabase,
  checkpointDatabase,
  readBackupState,
  checkDatabaseIntegrity
};
