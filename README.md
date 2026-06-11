# Red Team — Attack Generator

Tool for the AI Red vs. Blue Bootcamp. Given a process-level attack scenario, it
generates a dataset of ~220 process commands (**exactly 20 malicious** + ~200 benign
noise) with columns `process_name, command_line, label`, plus a written attack story.

> **Two skills drive generation (both via Azure OpenAI):** the `command-picker`
> skill selects the best 20 malicious + 200 benign commands from the pool and orders
> them into an attack, and the `attack-story-writer` skill writes the narrative.
> Both live in `.claude/skills/`. With no LLM key configured, generation falls back
> to the deterministic composer/template — the demo never fails.

## Stack
- **Database:** PostgreSQL — the `command_lines` pool (`sql/schema.sql` + `sql/seed_sample_commands.sql`)
- **Backend:** Python `attackgen/` composer + **FastAPI** HTTP layer (`api.py`, port 8000)
- **Frontend:** React + Vite + TypeScript + Tailwind (`frontend/`, port 5173)

## ▶️ One-click run

Double-click **`run.command`** (or `./run.command` in a terminal). It starts all three
tiers, seeds the DB if needed, and prints where each is running:

```
🗄  Database  postgresql://attackgen:changeme@localhost:5432/attackgen
⚙  Backend   http://localhost:8000   (API docs: http://localhost:8000/docs)
🎨  Frontend  http://localhost:5173   ← open this
```

It uses a local PostgreSQL on `:5432` if one is running, otherwise `docker compose up`.
Python deps are isolated in a `.venv`. Press **Ctrl+C** (or close the window) to stop everything.

## Manual run

```bash
# 1. Database (Docker)
docker compose up -d

# 2. Backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL="postgresql://attackgen:changeme@localhost:5432/attackgen"
uvicorn api:app --reload --port 8000

# 3. Frontend (proxies /api → :8000)
cd frontend && npm install && npm run dev
```

## Use
1. Select one or more **attack methods** (cards).
2. Choose target OS (**Linux** — the sample DB is Linux-only for now).
3. **Generate Attack** → review the story, stats, and dataset table.
4. Download the labeled / scored / ground-truth CSVs.

## API
- `GET  /api/health` → `{ status, db }`
- `GET  /api/scenarios` → scenario cards
- `POST /api/generate` `{ scenarios: string[], os_profile: "linux"|"windows", seed? }` →
  `{ story, scenario, totals, rows[{process_name,command_line,label,attack_type}], malicious[...] }`
  — exactly 20 malicious + 200 benign, blended.

> `attack_type` is for UI display only; it (and `label`) are stripped from the Blue team's scored CSV.
> See `INTEGRATION.md` for the full architecture and integration details.
