const path = require("path");
const fs = require("fs");

const jsonFile = path.join(__dirname, "..", "data", "site.json");

if (!fs.existsSync(jsonFile)) {
  console.log("Keine data/site.json gefunden. Nichts zu importieren.");
  process.exit(0);
}

const { importJson, DB_FILE, closeDatabase } = require("../database");

try {
  const raw = fs.readFileSync(jsonFile, "utf8");
  importJson(raw);
  console.log(`Migration erfolgreich. Datenbank: ${DB_FILE}`);
} catch (error) {
  console.error("Migration fehlgeschlagen:", error.message);
  process.exitCode = 1;
} finally {
  closeDatabase();
}
