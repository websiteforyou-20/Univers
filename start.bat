@echo off
setlocal
title Community Website Server

echo.
echo VTuber Nexus Version 30.1.2 wird gestartet...
echo.

for /f "tokens=1 delims=." %%V in ('node -p "process.versions.node" 2^>nul') do set NODE_MAJOR=%%V

if not defined NODE_MAJOR (
  echo Node.js wurde nicht gefunden.
  echo Bitte Node.js 22 LTS installieren und den PC danach neu starten.
  pause
  exit /b 1
)

if %NODE_MAJOR% LSS 22 (
  echo Diese Version benoetigt Node.js 22 oder neuer.
  node --version
  pause
  exit /b 1
)

where npm.cmd >nul 2>&1
if errorlevel 1 (
  echo npm wurde nicht gefunden.
  echo Bitte Node.js 22 LTS erneut installieren und npm mitinstallieren.
  pause
  exit /b 1
)

if exist node_modules\better-sqlite3 (
  echo Alte better-sqlite3-Installation wird entfernt...
  rmdir /s /q node_modules
)

set NEED_INSTALL=0
if not exist node_modules set NEED_INSTALL=1
if exist node_modules (
  node -e "require('express');require('ejs');require('dotenv');require('helmet');require('multer');require('express-session');require('express-rate-limit');require('session-file-store')" >nul 2>&1
  if errorlevel 1 set NEED_INSTALL=1
)

if "%NEED_INSTALL%"=="1" (
  echo Pakete werden installiert oder repariert...
  call npm.cmd install --no-audit --no-fund
  if errorlevel 1 (
    echo.
    echo Installation fehlgeschlagen.
    echo Pruefe die Internetverbindung und starte diese Datei erneut.
    pause
    exit /b 1
  )
)

echo.
echo Das eingebaute SQLite von Node.js wird verwendet.
echo Webseite: http://localhost:3000
echo Admin:    http://localhost:3000/admin
echo Status:   http://localhost:3000/health
echo.
call npm.cmd start
pause
endlocal
