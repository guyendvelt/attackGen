# Red Team — Attack Generator

Tool for the AI Red vs. Blue Bootcamp. Given a process-level attack scenario, it
generates a CSV of ~220 process commands (**exactly 20 malicious** + ~200 benign
noise) plus a written attack story.

> **Phase 1 (current):** full UI + generate→preview→download flow backed by a
> **mock generator**. The real LLM (Anthropic API) plugs into
> `backend/generator.py:generate_dataset` next — the API contract and UI stay the same.

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
