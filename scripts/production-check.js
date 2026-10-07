require("dotenv").config();

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const packageInfo = require("../package.json");

const checks = [];

function result(label, ok, detail) {
  checks.push({ label, ok, detail });
}

function directoryWritable(label, directory) {
  try {
    fs.mkdirSync(directory, { recursive: true });
    const probe = path.join(
      directory,
      `.production-check-${process.pid}-${Date.now()}`
    );
    fs.writeFileSync(probe, "ok", "utf8");
    fs.rmSync(probe, { force: true });
    result(label, true, `${directory} ist beschreibbar.`);
  } catch (error) {
    result(label, false, error.message);
  }
}

const adminPassword = String(process.env.ADMIN_PASSWORD || "");
const sessionSecret = String(process.env.SESSION_SECRET || "");
const siteUrl = String(process.env.SITE_URL || "").trim();

result(
  "Node.js",
  Number(process.versions.node.split(".")[0]) >= 22,
  `Installiert: ${process.versions.node}, benötigt: mindestens 22`
);

result(
  "NODE_ENV",
  process.env.NODE_ENV === "production",
  process.env.NODE_ENV === "production"
    ? "Produktionsmodus aktiv."
    : "NODE_ENV muss production sein."
);

result(
  "ADMIN_PASSWORD",
  adminPassword.length >= 12 &&
    !["admin123", "password", "passwort"].includes(adminPassword.toLowerCase()),
  "Mindestens 12 Zeichen und kein Standardpasswort."
);

result(
  "SESSION_SECRET",
  sessionSecret.length >= 32 &&
    sessionSecret !== "bitte-in-env-aendern",
  "Mindestens 32 zufällige Zeichen."
);

let parsedUrl = null;
try {
  parsedUrl = new URL(siteUrl);
} catch {}

result(
  "SITE_URL",
  Boolean(parsedUrl && parsedUrl.protocol === "https:"),
  parsedUrl
    ? `Gefunden: ${parsedUrl.origin}`
    : "Gültige HTTPS-Adresse erforderlich."
);

const dataDir = path.resolve(process.env.DATA_DIR || path.join(__dirname, "..", "data"));
const uploadDir = path.resolve(
  process.env.UPLOAD_DIR || path.join(__dirname, "..", "public", "uploads")
);
const mediaDir = path.resolve(
  process.env.MEDIA_DIR || path.join(dataDir, "media")
);
const backupDir = path.resolve(
  process.env.BACKUP_DIR || path.join(dataDir, "backups")
);
const sessionDir = path.resolve(
  process.env.SESSION_DIR || path.join(dataDir, "sessions")
);

directoryWritable("Datenordner", dataDir);
directoryWritable("Uploadordner", uploadDir);
directoryWritable("Medienordner", mediaDir);
directoryWritable("Backupordner", backupDir);
directoryWritable("Sitzungsordner", sessionDir);

const failed = checks.filter(check => !check.ok);

console.log(`\nONLINE-PRÜFUNG VERSION ${packageInfo.version}\n`);

checks.forEach(check => {
  console.log(`${check.ok ? "[OK]" : "[FEHLER]"} ${check.label}`);
  console.log(`  ${check.detail}`);
});

console.log(
  `\nErgebnis: ${checks.length - failed.length}/${checks.length} Prüfungen bestanden.`
);

if (failed.length) {
  console.error(
    "\nDer Produktionsstart ist noch nicht freigegeben. "
    + "Behebe zuerst die markierten Punkte."
  );
  process.exit(1);
}

console.log("\nDie Grundkonfiguration ist für den Onlinegang bereit.");
console.log(
  `Beispiel für SESSION_SECRET: ${crypto.randomBytes(32).toString("hex")}`
);
