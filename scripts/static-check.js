"use strict";

const fs = require("fs");
const path = require("path");
const ejs = require("ejs");

const ROOT = path.resolve(__dirname, "..");
const failures = [];
const warnings = [];
let passed = 0;

function check(condition, label, detail = "") {
  if (condition) {
    passed += 1;
    console.log(`✓ ${label}${detail ? `: ${detail}` : ""}`);
  } else {
    failures.push(`${label}${detail ? `: ${detail}` : ""}`);
    console.error(`✗ ${label}${detail ? `: ${detail}` : ""}`);
  }
}

function walk(directory) {
  const items = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) items.push(...walk(fullPath));
    else items.push(fullPath);
  }
  return items;
}

let closeDatabase = () => {};
const forbiddenBeforeCheck = walk(ROOT).filter(file => /(?:-wal|-shm)$/.test(file));

try {
  const serverPath = path.join(ROOT, "server.js");
  const serverSource = fs.readFileSync(serverPath, "utf8");

  const routeRegex = /app\.(get|post|put|delete)\(\s*["'`]([^"'`]+)["'`]/g;
  const routes = [];
  const routeCounts = new Map();
  let match;
  while ((match = routeRegex.exec(serverSource))) {
    const method = match[1].toUpperCase();
    const route = match[2];
    const key = `${method} ${route}`;
    routes.push({ method, route });
    routeCounts.set(key, (routeCounts.get(key) || 0) + 1);
  }

  const duplicates = [...routeCounts.entries()].filter(([, count]) => count > 1);
  check(routes.length >= 100, "Routen erkannt", `${routes.length}`);
  check(duplicates.length === 0, "Keine doppelten Routen", duplicates.map(([key]) => key).join(", "));

  const ejsFiles = walk(path.join(ROOT, "views")).filter(file => file.endsWith(".ejs"));
  const missingIncludes = [];
  const internalStaticLinks = [];

  for (const file of ejsFiles) {
    const source = fs.readFileSync(file, "utf8");
    try {
      ejs.compile(source, { filename: file });
    } catch (error) {
      failures.push(`EJS ${path.relative(ROOT, file)}: ${error.message}`);
    }

    for (const include of source.matchAll(/include\(["']([^"']+)["']/g)) {
      let target = path.resolve(path.dirname(file), include[1]);
      if (!path.extname(target)) target += ".ejs";
      if (!fs.existsSync(target)) missingIncludes.push(`${path.relative(ROOT, file)} -> ${include[1]}`);
    }

    for (const link of source.matchAll(/<a\b[^>]*\bhref=["']([^"']+)["']/gi)) {
      const href = link[1];
      if (href.startsWith("/") && !href.includes("<%") && !href.includes("#")) {
        internalStaticLinks.push({ file: path.relative(ROOT, file), href });
      }
    }
  }

  check(failures.filter(item => item.startsWith("EJS ")).length === 0, "Alle EJS-Dateien kompilieren", `${ejsFiles.length}`);
  check(missingIncludes.length === 0, "Alle EJS-Includes vorhanden", missingIncludes.join(", "));

  const getRoutes = routes.filter(item => item.method === "GET").map(item => item.route);
  function matchesGetRoute(href) {
    return getRoutes.some(route => {
      const pattern = `^${route
        .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
        .replace(/\\:([A-Za-z0-9_]+)/g, "[^/]+")}$`;
      return new RegExp(pattern).test(href);
    });
  }

  const brokenLinks = internalStaticLinks.filter(item => !matchesGetRoute(item.href));
  check(brokenLinks.length === 0, "Statische interne Links besitzen GET-Routen", brokenLinks.map(item => `${item.href} in ${item.file}`).join(", "));

  check(forbiddenBeforeCheck.length === 0, "Keine WAL-/SHM-Restdateien im Paket", forbiddenBeforeCheck.map(file => path.relative(ROOT, file)).join(", "));

  const databaseApi = require("../database");
  const { checkDatabaseIntegrity, readBackupState } = databaseApi;
  closeDatabase = databaseApi.closeDatabase;

  const integrity = checkDatabaseIntegrity();
  check(integrity.ok, "SQLite-Integritätsprüfung", integrity.messages.join("; "));

  const backupDirectory = path.join(ROOT, "data", "backups");
  if (fs.existsSync(backupDirectory)) {
    const invalidBackups = [];
    for (const name of fs.readdirSync(backupDirectory).filter(name => /^nexus-.*\.db$/i.test(name))) {
      try {
        readBackupState(path.join(backupDirectory, name));
      } catch (error) {
        invalidBackups.push(`${name}: ${error.message}`);
      }
    }
    check(invalidBackups.length === 0, "Gespeicherte SQLite-Backups sind gültig", invalidBackups.join(" | "));
  }

  check(!fs.existsSync(path.join(ROOT, ".env")), "Keine echte .env im Weitergabe-Paket");


  if (warnings.length) {
    console.warn("\nWarnungen:");
    warnings.forEach(item => console.warn(`- ${item}`));
  }

  console.log(`\nStatische Prüfung: ${passed} bestanden, ${failures.length} fehlgeschlagen.`);
  if (failures.length) {
    console.error(failures.map(item => `- ${item}`).join("\n"));
    process.exitCode = 1;
  }
} finally {
  closeDatabase();
  for (const file of walk(ROOT).filter(file => /(?:-wal|-shm)$/.test(file))) {
    fs.rmSync(file, { force: true });
  }
}
