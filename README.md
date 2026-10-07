# VTuber Nexus 29.9

Lokale VTuber- und Streamer-Community-Webseite mit Mitgliederkonten, Rollen, Admin-Bereich, Medien, Projekten, Abstimmungen, Backups und Systemprüfung.

## Start unter Windows

1. ZIP vollständig entpacken.
2. Die eigene `.env` in den Hauptordner kopieren.
3. `start.bat` doppelt anklicken.
4. Webseite öffnen: `http://localhost:3000`
5. Status öffnen: `http://localhost:3000/health`

`start.bat` prüft Node.js, npm und die benötigten Pakete. Fehlende oder beschädigte Pakete werden mit `npm.cmd install` repariert.

## Benötigte Version

- Node.js 22 oder neuer
- npm, wird normalerweise zusammen mit Node.js installiert

## Wichtige Daten

- Datenbank: `data/nexus.db`
- Medien: `data/media`
- Datenbank-Backups: `data/backups`
- Bilder: `public/uploads`
- Sitzungen: `data/sessions`

Die Datei `.env` enthält geheime Werte und gehört nicht in weitergegebene ZIP-Dateien.

## Prüfungen

```text
npm.cmd run check
npm.cmd run self-test
```

`check` prüft Syntax, EJS-Dateien, interne Links, Routen, Datenbank und vorhandene Backups.

`self-test` startet eine vollständig isolierte Testinstanz mit eigener temporärer Datenbank. Die echten Daten werden dabei nicht verändert.

## Version 29.9

- echte SQLite-Integritätsprüfung
- Erkennung ungültiger Backups
- atomare und geprüfte Backup-Erstellung
- sichere JSON-Wiederherstellung
- korrekte Unterstützung von `DATABASE_PATH` aus `.env`
- isolierbare Speicherordner für Tests und Hosting
- reparierter Kontaktlink
- stabilere Sitzungs- und Logout-Behandlung
- verbesserter Windows-Start
- integrierter automatischer Selbsttest

Die Anwendung ist weiterhin für lokalen Betrieb und Tests vorgesehen. Vor dem öffentlichen Onlinegang folgen Hosting, HTTPS, externe Backups und die finale Datenschutzprüfung.
