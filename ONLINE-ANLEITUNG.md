# VTuber Nexus Version 30: Online-Vorbereitung

## Was Version 30 erledigt

Die Anwendung ist für den Betrieb hinter HTTPS und einem Reverse Proxy
vorbereitet. Sie besitzt sichere Produktionscookies, Host-Prüfung,
Herkunftsschutz für Formulare, Sicherheitsheader, Rate-Limits,
Liveness- und Readiness-Endpunkte sowie eine strengere Startprüfung.

## Empfohlener Aufbau

Internet → Domain/HTTPS → Nginx oder Caddy → Node.js auf 127.0.0.1:3000

Die Node-Anwendung sollte nicht direkt über Port 3000 öffentlich erreichbar sein.

## Vor dem ersten Start

1. Node.js 22 LTS oder Docker installieren.
2. `.env.production.example` als `.env.production` kopieren.
3. Alle Platzhalter durch echte Werte ersetzen.
4. `SITE_URL` und `ALLOWED_HOSTS` auf die eigene Domain einstellen.
5. `PUBLIC_INDEXING=false` für den privaten Testbetrieb lassen.
6. `node scripts/production-check.js` ausführen.
7. Ein manuelles Datenbank-Backup erstellen.
8. Datenschutz und Impressum mit echten Angaben prüfen.

## Start mit Docker

```bash
mkdir -p storage/data storage/uploads
sudo chown -R 1000:1000 storage
docker compose build
docker compose up -d
docker compose ps
```

Die Anwendung ist danach nur lokal unter `127.0.0.1:3000` erreichbar.
Nginx oder Caddy übernimmt Domain und HTTPS.

## Prüf-Adressen

- `/health`: Der Node-Prozess lebt.
- `/ready`: Datenbank und Speicher sind einsatzbereit.
- `/robots.txt`: Im privaten Testbetrieb wird Suchmaschinenzugriff blockiert.

## Freigabe für Suchmaschinen

Erst nach Abschluss aller Tests:

```env
PUBLIC_INDEXING=true
```

Danach Container oder Server neu starten.

## Wichtige Regeln

- `.env.production` niemals hochladen oder öffentlich teilen.
- `data`, `public/uploads` und externe Backups regelmäßig sichern.
- Port 3000 nur an `127.0.0.1` binden.
- Nur HTTPS verwenden.
- Vor jedem Update ein Backup erstellen.
