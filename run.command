#!/usr/bin/env bash
#
# AttackGen — one-click launcher.
# Double-click in Finder (or run `./run.command`) to start the whole stack:
#   1. Database  (PostgreSQL — local Homebrew PG if present, else Docker)
#   2. Backend   (FastAPI / Uvicorn  :8000)
#   3. Frontend  (Vite / React        :5173)
#
# Closing this window (or Ctrl+C) stops the backend and frontend it started.

set -u
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

# Load .env (DB creds + Azure OpenAI key for story generation), if present.
[ -f .env ] && { set -a; . ./.env; set +a; }

DB_URL="${DATABASE_URL:-postgresql://attackgen:changeme@localhost:5432/attackgen}"
export DATABASE_URL="$DB_URL"
PG_HOST="localhost"; PG_PORT="5432"; PG_DB="attackgen"; PG_USER="attackgen"

# Colors
B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; R=$'\033[31m'; X=$'\033[0m'

say() { printf "%s\n" "$1"; }
hr()  { printf '%s\n' "────────────────────────────────────────────────────────"; }

BACKEND_PID=""; FRONTEND_PID=""
cleanup() {
  echo
  say "${Y}Shutting down…${X}"
  [ -n "$BACKEND_PID" ]  && kill "$BACKEND_PID"  2>/dev/null
  [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null
  exit 0
}
trap cleanup INT TERM EXIT

clear
say "${B}🛡  AttackGen — Red Team Attack Generator${X}"
hr

# ── Free our ports if a previous run left something behind ────────────────
for P in 8000 5173; do
  PIDS=$(lsof -nP -iTCP:$P -sTCP:LISTEN -t 2>/dev/null)
  [ -n "$PIDS" ] && { say "${Y}• freeing port $P (stale process)${X}"; kill -9 $PIDS 2>/dev/null; }
done

# ── 1. Database ───────────────────────────────────────────────────────────
say "${B}[1/3] Database${X}"
DB_DESC=""
ensure_seeded() {
  local cnt
  cnt=$(psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" -tAc \
        "SELECT count(*) FROM command_lines" 2>/dev/null || echo 0)
  if [ "${cnt:-0}" -lt 1 ]; then
    say "   • loading schema + sample seed…"
    psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" -q -f sql/schema.sql
    psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" -q -f sql/seed_sample_commands.sql
  fi
}

if command -v pg_isready >/dev/null 2>&1 && pg_isready -h "$PG_HOST" -p "$PG_PORT" >/dev/null 2>&1; then
  # Local PostgreSQL is up — ensure role + db + seed exist (idempotent).
  psql -h "$PG_HOST" -p "$PG_PORT" -d postgres -tAc \
       "SELECT 1 FROM pg_roles WHERE rolname='$PG_USER'" 2>/dev/null | grep -q 1 \
    || psql -h "$PG_HOST" -p "$PG_PORT" -d postgres -q -c \
       "CREATE ROLE $PG_USER LOGIN PASSWORD 'changeme'" 2>/dev/null
  psql -h "$PG_HOST" -p "$PG_PORT" -d postgres -tAc \
       "SELECT 1 FROM pg_database WHERE datname='$PG_DB'" 2>/dev/null | grep -q 1 \
    || psql -h "$PG_HOST" -p "$PG_PORT" -d postgres -q -c \
       "CREATE DATABASE $PG_DB OWNER $PG_USER" 2>/dev/null
  ensure_seeded
  DB_DESC="local PostgreSQL"
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  say "   • starting Docker PostgreSQL (auto-seeds)…"
  docker compose up -d >/dev/null 2>&1
  for _ in $(seq 1 30); do
    docker exec attackgen-postgres pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1 && break
    sleep 1
  done
  DB_DESC="Docker PostgreSQL"
else
  say "${R}   ✗ No PostgreSQL on :5432 and Docker is not running.${X}"
  say "${R}     Start Postgres (or Docker Desktop) and run again.${X}"
  exit 1
fi
say "${G}   ✓ ${DB_DESC} ready${X}"

# ── Dependencies — isolated in a project venv (reproducible, PEP 668-safe) ──
# Pick a stable base interpreter for the venv (avoid bleeding-edge Homebrew builds).
BASEPY=""
for cand in python3.12 python3.11 python3.10 /usr/bin/python3 python3; do
  command -v "$cand" >/dev/null 2>&1 && { BASEPY="$cand"; break; }
done
PYBIN=".venv/bin/python"
if [ ! -x "$PYBIN" ]; then
  say "   • creating virtualenv (.venv) with ${BASEPY}…"
  "$BASEPY" -m venv .venv
fi
"$PYBIN" -c "import fastapi, uvicorn, psycopg" >/dev/null 2>&1 || {
  say "   • installing Python deps into .venv…"
  "$PYBIN" -m pip install -q --upgrade pip >/dev/null 2>&1
  "$PYBIN" -m pip install -q -r requirements.txt
}
[ -d frontend/node_modules ] || { say "   • installing frontend deps…"; ( cd frontend && npm install --silent ); }

# ── 2. Backend ──────────────────────────────────────────────────────────────
say "${B}[2/3] Backend${X}"
"$PYBIN" -m uvicorn api:app --host 127.0.0.1 --port 8000 > /tmp/attackgen_backend.log 2>&1 &
BACKEND_PID=$!
for _ in $(seq 1 30); do
  curl -sf localhost:8000/api/health >/dev/null 2>&1 && break
  sleep 0.5
done
if curl -sf localhost:8000/api/health >/dev/null 2>&1; then
  say "${G}   ✓ API up (health: $(curl -s localhost:8000/api/health))${X}"
else
  say "${R}   ✗ backend failed — see /tmp/attackgen_backend.log${X}"; tail -5 /tmp/attackgen_backend.log
fi

# ── 3. Frontend ───────────────────────────────────────────────────────────
say "${B}[3/3] Frontend${X}"
( cd frontend && npm run dev > /tmp/attackgen_frontend.log 2>&1 ) &
FRONTEND_PID=$!
for _ in $(seq 1 40); do
  curl -sf localhost:5173 >/dev/null 2>&1 && break
  sleep 0.5
done
say "${G}   ✓ UI up${X}"

# ── Summary ─────────────────────────────────────────────────────────────────
echo
hr
say "${B}✅  AttackGen is running${X}"
hr
say "  🗄  ${B}Database${X}  ${C}${DB_URL}${X}   (${DB_DESC})"
say "  ⚙  ${B}Backend${X}   ${C}http://localhost:8000${X}   (API docs: http://localhost:8000/docs)"
say "  🎨  ${B}Frontend${X}  ${C}http://localhost:5173${X}   ← open this"
hr
say "  Logs:  backend → /tmp/attackgen_backend.log   frontend → /tmp/attackgen_frontend.log"
say "  ${Y}Press Ctrl+C (or close this window) to stop everything.${X}"
echo

# Open the UI in the default browser.
( sleep 1; open http://localhost:5173 ) >/dev/null 2>&1 &

# Keep running until interrupted; surface a crash if either dies (bash 3.2 safe).
while kill -0 "$BACKEND_PID" 2>/dev/null && kill -0 "$FRONTEND_PID" 2>/dev/null; do
  sleep 2
done
say "${R}A service exited. Stopping the rest…${X}"
cleanup
