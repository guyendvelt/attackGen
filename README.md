# Red Team — Attack Generator

Tool for the AI Red vs. Blue Bootcamp. Given a process-level attack scenario, it
generates a CSV of ~220 process commands (**exactly 20 malicious** + ~200 benign
noise) plus a written attack story.

> **LLM phase (current):** `generate_dataset` first asks Claude — via the
> `command-picker` skill — to choose the best commands from the pool
> (`backend/picker.py`). Set `ANTHROPIC_API_KEY` to enable it; with no key it
> falls back to the mock generator. The API contract and UI are unchanged.

## Enable the LLM picker

1. Copy the env template: `cp .env.example .env`
2. Paste your key into `.env`: `ANTHROPIC_API_KEY=sk-ant-...`
   (get one at https://platform.claude.com → API Keys; `.env` is gitignored)
3. Restart the backend. `POST /api/generate` now picks commands with
   `claude-opus-4-8` driven by `.claude/skills/command-picker/SKILL.md`.

Without a key (or with the `sk-ant-REPLACE_ME` placeholder) the backend logs a
fallback notice and serves the mock dataset — the demo never fails.

## Stack
- **Backend:** FastAPI (`backend/`)
- **Frontend:** React + Vite + TypeScript + Tailwind (`frontend/`)

## Run

**Backend** (port 8000):
```bash
cd backend
pip install -r requirements.txt
python3 -m uvicorn main:app --reload --port 8000
```

**Frontend** (port 5173, proxies `/api` → backend):
```bash
cd frontend
npm install
npm run dev
```
Open http://localhost:5173.

## Use
1. Pick an attack scenario card (or type a free-text scenario in **Vibe Generate**).
2. Choose target OS (Windows / Linux).
3. **Generate Attack** → review the story, stats, and dataset preview.
4. Download: **labeled CSV**, **scored CSV** (no label column, for the Blue team),
   or the **ground-truth list** of the 20 malicious commands.

## API
- `GET /api/scenarios` → preset scenario cards
- `POST /api/generate` `{ scenario_id?, vibe?, os, seed? }` →
  `{ story, rows[{process_name,command_line,label}], malicious[{process_name,command_line}] }`
