"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-role-test-"));
process.env.DATABASE_PATH = path.join(temp, "roles.db");
const { readData, writeData, closeDatabase } = require("../database");
try {
  const data = readData();
  const ids = data.roles.map(role => role.id);
  if (!ids.includes("founder") || !ids.includes("moderator") || !ids.includes("member")) {
    throw new Error("Systemrollen fehlen.");
  }
  const founder = data.roles.find(role => role.id === "founder");
  if (!founder.permissions.includes("*")) throw new Error("Gründer besitzt nicht alle Rechte.");
  const moderator = data.roles.find(role => role.id === "moderator");
  if (!moderator.permissions.includes("admin.access") || !moderator.permissions.includes("events.manage")) {
    throw new Error("Moderator-Migration unvollständig.");
  }
  data.roles.push({ id:"event-team", name:"Event-Team", color:"#123456", permissions:["admin.access","events.manage"], system:false, protected:false });
  data.members.push({ id:"role-test", name:"Role Test", role:"Event-Team", roleId:"event-team" });
  writeData(data);
  const reread = readData();
  const member = reread.members.find(item => item.id === "role-test");
  if (member.roleId !== "event-team" || member.role !== "Event-Team") throw new Error("Eigene Rolle wurde nicht gespeichert.");
  console.log("Rollen-Test: OK");
} finally {
  closeDatabase();
  fs.rmSync(temp, { recursive:true, force:true });
}
