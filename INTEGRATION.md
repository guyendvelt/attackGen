# AttackGen — UI ↔ Backend Integration Guide

> **Goal:** wire the React UI (`ui_branch`) to the Python generator + Postgres DB (`main`) so a
> user picks an OS and attack scenario(s), clicks **Generate**, and the UI renders an attack story
> plus a clean table of ~220 process commands (exactly 20 malicious / ~200 benign).
>
> **Saved as `INTEGRATION.md`** on purpose — `main` already has a different `instructions.md`
> (the project guide). Rename if you prefer.

---

## 0. Current State & Key Gaps (read first)

The two branches have **diverged structures**, and the backend is **not yet an HTTP service**.
The integration is mostly about adding a thin API layer and a translation step. Concretely:

| Area | `main` (backend + DB) | `ui_branch` (frontend) | Action needed |
|---|---|---|---|
| Layout | `attackgen/` package, `sql/`, `docker-compose.yml`, `requirements.txt` at **repo root** | `frontend/` (React/Vite) **+ a stale `backend/`** (old mock) | Monorepo: keep `main` root + add `frontend/`; delete the stale `backend/` |
| Entry point | **CLI only** — `python -m attackgen.cli --request ...` | calls `fetch('/api/...')` | **Add a FastAPI app (`api.py`)** that wraps `compose()` |
| Request shape | `Request{scenario, os_profile, benign_categories{Σ=200}, malicious_categories{Σ=20}, seed}` | `{scenario_ids[], os, seed?}` (currently a **GET**) | API layer **translates** UI request → composer `Request`; switch UI to **POST** |
| Story | **Not generated in code** — produced by a separate Claude skill into `attack_story.md` | expects `story` string in the JSON | **Add `story.py`** (LLM with deterministic fallback) |
| OS coverage | sample seed is **Linux only** | UI offers Windows **and** Linux | Lock UI to `linux` for now **or** add Windows rows to the DB |
| Output | writes CSV files to disk (`exporters.py`) | wants **JSON** (rows + story) | API returns JSON built from the in-memory `Dataset` (no file I/O needed) |

**What we reuse as-is (do not rewrite):**
- `attackgen/composer.py` → `compose(request, source, seed)` returns a validated, blended `Dataset`
  (enforces the exact 200/20/220 split, no duplicates, malicious blended throughout).
- `attackgen/postgres_command_source.py` → `PostgresCommandSource` / `InMemoryCommandSource`.
- `attackgen/models.py` → `CommandRow.to_export_dict()` (the 3 exported columns).
- `attackgen/config.py` → `DbConfig.from_env()`.
- `sql/schema.sql` + `sql/seed_sample_commands.sql` + `docker-compose.yml` → local DB.

---

## 1. Repository & Branch Setup

We target a **single monorepo** rooted on `main`: backend at the root, UI under `frontend/`,
served as two processes in dev (Vite + Uvicorn), proxied so the browser only talks to Vite.

### 1.1 Create an integration branch off `main`

```bash
git fetch origin
git checkout main && git pull origin main
git checkout -b integration
```

### 1.2 Bring the frontend over from `ui_branch` (path-scoped, avoids the stale backend)

```bash
# Pull ONLY the frontend directory from ui_branch into the working tree.
git checkout ui_branch -- frontend

# Sanity check: you should NOT have ui_branch's stale top-level backend/.
# (The path checkout above does not bring it; if it exists locally, remove it.)
git rm -r --cached backend 2>/dev/null || true   # only if a stale ./backend was tracked

git add frontend
git commit -m "chore: add React frontend from ui_branch into monorepo"
```

### 1.3 Add the new integration files (created in §3 and §5 of this guide)

```
attackgen/                # unchanged
frontend/                 # from ui_branch (React/Vite/TS/Tailwind)
sql/                      # unchanged
api.py                    # NEW — FastAPI app (the seam)
scenario_profiles.py      # NEW — maps UI scenarios -> category counts
story.py                  # NEW — attack-story generator (LLM + fallback)
requirements.txt          # UPDATED — add fastapi, uvicorn, anthropic
docker-compose.yml        # unchanged
```

After adding them:

```bash
git add api.py scenario_profiles.py story.py requirements.txt
git commit -m "feat: add FastAPI layer, scenario->category mapping, story generator"
git push -u origin integration
# Open a PR: integration -> main
```

### 1.4 Final target tree

```
attackGen/
├─ api.py                 # FastAPI: POST /api/generate, GET /api/scenarios, GET /api/health
├─ scenario_profiles.py   # scenario(s) + os -> (benign_categories, malicious_categories)
├─ story.py               # generate_story(dataset) -> str
├─ attackgen/             # composer, DB source, models, config, exporters (reused)
├─ sql/                   # schema + sample seed
├─ docker-compose.yml     # local Postgres (auto-seeds)
├─ requirements.txt
└─ frontend/              # React + Vite + TS + Tailwind
   └─ src/ (api.ts, types.ts, App.tsx, components/, csv.ts, ...)
```

> **Why not literally merge `ui_branch` into `main`?** A full merge drags in `ui_branch`'s stale
> top-level `backend/` (the earlier mock), which conflicts conceptually with `attackgen/`. The
> path-scoped checkout in §1.2 keeps history clean and avoids two competing backends.

---

## 2. API Contract Specification

One primary endpoint plus two helpers. The browser talks to these via the Vite dev proxy (§4.4),
so in development the UI calls same-origin `/api/...` paths.

### 2.1 `POST /api/generate`

Generate a dataset + story for the selected scenario(s) and OS.

**Request body (UI-friendly form — recommended):**

```json
{
  "scenarios": ["ransomware"],
  "os_profile": "linux",
  "seed": 42
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `scenarios` | `string[]` | yes | One or more scenario themes from `GET /api/scenarios` (e.g. `ransomware`, `crypto_miner`, `lateral_movement`). The backend maps these to kill-chain category counts. |
| `os_profile` | `"linux" \| "windows"` | yes | Must have matching rows in the DB. Sample seed = **linux only**. |
| `seed` | `int` | no | Deterministic selection + blending. Omit for random. |

**Advanced form (power users / CLI parity — also accepted):** supply explicit counts and skip the
mapping. If `benign_categories` **and** `malicious_categories` are present, they are used verbatim
(they must sum to exactly 200 and 20 respectively).

```json
{
  "scenario": "ransomware",
  "os_profile": "linux",
  "benign_categories":   { "linux_admin": 40, "devops": 35, "logs": 35, "backup": 45, "app_runtime": 25, "package_management": 20 },
  "malicious_categories":{ "discovery": 4, "staging": 4, "persistence": 3, "execution": 5, "cleanup": 2, "impact": 2 },
  "seed": 42
}
```

**Response `200 OK`:**

```json
{
  "scenario": "ransomware",
  "os_profile": "linux",
  "seed": 42,
  "totals": { "benign": 200, "malicious": 20, "total": 220 },
  "story": "Beginning… middle… end. A coherent narrative of the simulated attack.",
  "rows": [
    { "process_name": "systemctl", "command_line": "systemctl status app-worker@3.service", "label": "benign",    "attack_type": "linux_admin" },
    { "process_name": "openssl",   "command_line": "openssl enc -aes-256-cbc -salt -in /srv/data/file-7 -out /srv/data/file-7.enc", "label": "malicious", "attack_type": "impact" }
  ],
  "malicious": [
    { "process_name": "openssl", "command_line": "openssl enc -aes-256-cbc ...", "attack_type": "impact" }
  ]
}
```

| Field | Type | Notes |
|---|---|---|
| `totals` | object | Always `{benign:200, malicious:20, total:220}` on success. |
| `story` | string | Generated narrative (LLM if `ANTHROPIC_API_KEY` is set, else template). |
| `rows` | array | All 220 rows, **already blended** (malicious spread throughout). Display order = dataset order. |
| `rows[].label` | `"benign" \| "malicious"` | The ground-truth label. |
| `rows[].attack_type` | string | **Display only** — the internal `category`. **Never include it in an exported CSV** (the scored CSV is `process_name, command_line` only; the labeled CSV adds `label`). |
| `malicious` | array | The 20 malicious rows = the ground-truth answer key. |

**Error responses (clear, typed):**

| Status | When | Body |
|---|---|---|
| `400` | counts don't sum to 200/20, or unknown scenario | `{ "detail": "malicious category counts must total exactly 20, got 18" }` |
| `422` | malformed JSON / missing required fields | FastAPI validation error |
| `503` | DB unreachable, or a category lacks enough rows (e.g. Windows requested with Linux-only seed) | `{ "detail": "category 'impact' (malicious, windows) has 0 commands in PostgreSQL but 2 were requested" }` |

### 2.2 `GET /api/scenarios`

Returns the scenario cards for the UI (id + display metadata).

```json
[
  { "id": "ransomware",       "name": "Ransomware",        "icon": "🔒", "description": "Encrypts/destroys data under cover of backup noise.", "color": "#ef4444" },
  { "id": "crypto_miner",     "name": "Crypto Miner",      "icon": "⛏️", "description": "Hidden high-CPU workloads.",                          "color": "#f59e0b" },
  { "id": "lateral_movement", "name": "Lateral Movement",  "icon": "↔️", "description": "Remote exec across hosts.",                            "color": "#8b5cf6" }
]
```

### 2.3 `GET /api/health`

```json
{ "status": "ok", "db": "connected" }
```

---

## 3. Backend Integration Steps

Three new files at the repo root. They **wrap** the existing `attackgen` package — no changes to
`composer.py`, `models.py`, or the DB layer.

### 3.1 Update `requirements.txt`

```diff
 psycopg[binary]>=3.1
 pytest>=8.0
+fastapi>=0.115
+uvicorn[standard]>=0.30
+anthropic>=0.40          # optional — only needed for LLM-written stories
```

### 3.2 `scenario_profiles.py` — translate UI scenarios → category counts

The UI sends scenario themes; the composer needs per-category counts that sum to exactly 200 / 20.
This module owns that mapping. The default below uses **only the categories present in the sample
Linux seed**, so it works out-of-the-box.

```python
"""Map UI scenario theme(s) + OS into composer category counts.

The UI stays simple (pick a theme + OS). All count logic lives here. Counts must
sum to exactly 200 (benign) and 20 (malicious); see attackgen.models.
"""
from __future__ import annotations

# Benign mix (Σ = 200) — only categories present in the sample Linux seed.
_DEFAULT_BENIGN = {
    "linux_admin": 40, "devops": 35, "logs": 35,
    "backup": 45, "app_runtime": 25, "package_management": 20,
}
# Malicious mix (Σ = 20) — kill-chain phases present in the sample seed.
_DEFAULT_MALICIOUS = {
    "discovery": 4, "staging": 4, "persistence": 3,
    "execution": 5, "cleanup": 2, "impact": 2,
}

# Per-scenario tweaks (still Σ = 20). Extend as the DB owner adds rows/categories.
_SCENARIO_MALICIOUS = {
    "ransomware":       {"discovery": 3, "staging": 4, "persistence": 2, "execution": 4, "cleanup": 2, "impact": 5},
    "crypto_miner":     {"discovery": 3, "staging": 3, "persistence": 4, "execution": 7, "cleanup": 2, "impact": 1},
    "data_exfiltration":{"discovery": 4, "staging": 6, "persistence": 2, "execution": 4, "cleanup": 2, "impact": 2},
    "lateral_movement": {"discovery": 5, "staging": 3, "persistence": 3, "execution": 6, "cleanup": 2, "impact": 1},
    "persistence":      {"discovery": 2, "staging": 2, "persistence": 8, "execution": 4, "cleanup": 2, "impact": 2},
}

KNOWN_SCENARIOS = set(_SCENARIO_MALICIOUS) | {"default"}


def build_categories(scenarios: list[str]) -> tuple[dict[str, int], dict[str, int], str]:
    """Return (benign_categories, malicious_categories, primary_scenario).

    For a single known scenario we use its tuned malicious mix; otherwise the
    default. `primary_scenario` is used as the DB scenario_tag preference + story title.
    """
    primary = scenarios[0] if scenarios else "default"
    malicious = dict(_SCENARIO_MALICIOUS.get(primary, _DEFAULT_MALICIOUS))
    benign = dict(_DEFAULT_BENIGN)

    # Hard guarantees the composer also enforces — fail fast here with a clear msg.
    assert sum(benign.values()) == 200, f"benign must sum to 200, got {sum(benign.values())}"
    assert sum(malicious.values()) == 20, f"malicious must sum to 20, got {sum(malicious.values())}"
    return benign, malicious, primary
```

### 3.3 `story.py` — generate the attack narrative (LLM + deterministic fallback)

Runs after composition. Uses Claude if `ANTHROPIC_API_KEY` is set; otherwise emits a solid
template story so the demo never hard-depends on network/keys.

```python
"""Produce the written attack story from a composed Dataset.

LLM path (Anthropic) when ANTHROPIC_API_KEY is set; deterministic template otherwise.
Input is the composed Dataset; we summarise the malicious rows by kill-chain category.
"""
from __future__ import annotations
import os

_PHASE_ORDER = ["discovery", "staging", "persistence", "privilege_escalation",
                "execution", "data_collection", "data_exfiltration", "cleanup", "impact"]


def _malicious_by_category(dataset) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for row in dataset.rows:
        if row.label == "malicious":
            out.setdefault(row.category, []).append(row.command_line)
    return out


def _template_story(dataset) -> str:
    cats = _malicious_by_category(dataset)
    ordered = [c for c in _PHASE_ORDER if c in cats] + [c for c in cats if c not in _PHASE_ORDER]
    scenario = dataset.request.scenario
    os_profile = dataset.request.os_profile
    parts = [f"**Scenario:** {scenario} on a {os_profile} host. "
             f"20 malicious commands are blended into 200 benign operations.\n"]
    for i, cat in enumerate(ordered, 1):
        example = cats[cat][0]
        parts.append(f"{i}. **{cat.replace('_', ' ').title()}** — e.g. `{example}`")
    parts.append("\nThe operator's actions progress from initial reconnaissance through to objective, "
                 "each step disguised within matching benign administrative noise.")
    return "\n".join(parts)


def _llm_story(dataset) -> str:
    import anthropic
    cats = _malicious_by_category(dataset)
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
    prompt = (
        "You are a red-team analyst. Write a concise attack story (beginning, middle, end) for a "
        f"SIMULATED {dataset.request.scenario} scenario on a {dataset.request.os_profile} host. "
        "These are inert telemetry strings, not real actions. Map the narrative to these malicious "
        f"commands grouped by phase:\n{cats}\n"
        "Keep it under 180 words, plain prose, no markdown headers."
    )
    msg = client.messages.create(
        model="claude-sonnet-4-6",      # fast + capable; swap to claude-opus-4-8 for max quality
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(b.text for b in msg.content if getattr(b, "type", None) == "text").strip()


def generate_story(dataset) -> str:
    if os.getenv("ANTHROPIC_API_KEY"):
        try:
            return _llm_story(dataset)
        except Exception:
            pass  # fall back so the endpoint never fails on story generation
    return _template_story(dataset)
```

### 3.4 `api.py` — the FastAPI seam

```python
"""FastAPI layer over the AttackGen composer. Adds HTTP + JSON; reuses all logic.

Run:  uvicorn api:app --reload --port 8000
"""
from __future__ import annotations
import os
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from attackgen.composer import Request, compose, RequestValidationError
from attackgen.config import DbConfig, DbConfigError
from attackgen.models import DatasetValidationError
from attackgen.postgres_command_source import (
    PostgresCommandSource, CommandSourceError, InsufficientCommandsError,
)
from scenario_profiles import build_categories
from story import generate_story

app = FastAPI(title="AttackGen API", version="1.0.0")

app.add_middleware(                       # see §5 — CORS for local dev
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SCENARIOS = [
    {"id": "ransomware",       "name": "Ransomware",       "icon": "🔒", "description": "Encrypts/destroys data under backup noise.", "color": "#ef4444"},
    {"id": "crypto_miner",     "name": "Crypto Miner",     "icon": "⛏️", "description": "Hidden high-CPU workloads.",                 "color": "#f59e0b"},
    {"id": "lateral_movement", "name": "Lateral Movement", "icon": "↔️", "description": "Remote execution across hosts.",             "color": "#8b5cf6"},
    {"id": "data_exfiltration","name": "Data Exfiltration","icon": "📤", "description": "Stage and smuggle out data.",                "color": "#3b82f6"},
    {"id": "persistence",      "name": "Persistence",      "icon": "🚪", "description": "Cron/service/startup footholds.",            "color": "#06b6d4"},
]


class GenerateRequest(BaseModel):
    # UI-friendly form
    scenarios: Optional[list[str]] = None
    os_profile: Literal["linux", "windows"] = "linux"
    seed: Optional[int] = None
    # Advanced form (optional explicit counts)
    scenario: Optional[str] = None
    benign_categories: Optional[dict[str, int]] = None
    malicious_categories: Optional[dict[str, int]] = None


def _source():
    try:
        return PostgresCommandSource(DbConfig.from_env())
    except DbConfigError as exc:
        raise HTTPException(status_code=503, detail=f"DB config error: {exc}")


@app.get("/api/health")
def health():
    src = _source()
    try:
        src.connect()
        return {"status": "ok", "db": "connected"}
    except CommandSourceError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    finally:
        src.close()


@app.get("/api/scenarios")
def scenarios():
    return SCENARIOS


@app.post("/api/generate")
def generate(req: GenerateRequest):
    # 1) Resolve category counts: explicit (advanced) or mapped from scenarios.
    if req.benign_categories and req.malicious_categories:
        benign, malicious = req.benign_categories, req.malicious_categories
        scenario = req.scenario or (req.scenarios[0] if req.scenarios else "custom")
    else:
        if not req.scenarios:
            raise HTTPException(status_code=400, detail="provide 'scenarios' or explicit category counts")
        benign, malicious, scenario = build_categories(req.scenarios)

    composer_req = Request(
        scenario=scenario,
        os_profile=req.os_profile,
        benign_categories=benign,
        malicious_categories=malicious,
        seed=req.seed,
    )

    # 2) Compose (validates 200/20/220, blends, dedupes) — reused as-is.
    src = _source()
    try:
        dataset = compose(composer_req, src, seed=req.seed)
    except RequestValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (InsufficientCommandsError, CommandSourceError) as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except DatasetValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        src.close()

    # 3) Story (LLM or template) + 4) JSON response.
    rows = [
        {**r.to_export_dict(), "attack_type": r.category}   # attack_type = display only
        for r in dataset.rows
    ]
    malicious_rows = [
        {"process_name": r.process_name, "command_line": r.command_line, "attack_type": r.category}
        for r in dataset.malicious_rows
    ]
    return {
        "scenario": dataset.request.scenario,
        "os_profile": dataset.request.os_profile,
        "seed": dataset.seed,
        "totals": {"benign": len(dataset.benign_rows), "malicious": len(dataset.malicious_rows), "total": len(dataset.rows)},
        "story": generate_story(dataset),
        "rows": rows,
        "malicious": malicious_rows,
    }
```

> **Offline/demo without Postgres (optional):** swap `_source()` to return
> `InMemoryCommandSource(seed_rows)` behind an `ATTACKGEN_SOURCE=memory` env flag, loading a small
> in-memory list of `CommandRow`s. Useful if the DB owner's pool isn't ready at demo time.

---

## 4. Frontend Integration Steps

The UI already has the state (multi-select scenarios + OS toggle) and a results view. The changes
are: **switch the request to POST**, align the **types**, and ensure the **dev proxy** points at the API.

### 4.1 `frontend/src/types.ts` — align the request shape

```diff
 export interface GenerateRequest {
-  scenario_ids: string[];
-  os: TargetOS;
+  scenarios: string[];
+  os_profile: TargetOS;
   seed?: number;
 }

+export interface Totals { benign: number; malicious: number; total: number; }
 export interface GenerateResult {
   story: string;
   rows: Row[];
   malicious: MaliciousCmd[];
+  totals?: Totals;
+  scenario?: string;
 }
```
`Row.attack_type` already exists and stays **display-only** (keep it out of any exported CSV).

### 4.2 `frontend/src/api.ts` — POST JSON instead of GET

```ts
import type { GenerateRequest, GenerateResult, Scenario } from "./types";

export async function fetchScenarios(): Promise<Scenario[]> {
  const res = await fetch("/api/scenarios");
  if (!res.ok) throw new Error(`scenarios failed: ${res.status}`);
  return res.json();
}

export async function generate(req: GenerateRequest): Promise<GenerateResult> {
  const res = await fetch("/api/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    // Surface the backend's typed error detail (e.g. "no windows commands").
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail?.detail ?? `generate failed: ${res.status}`);
  }
  return res.json();
}
```

### 4.3 `frontend/src/App.tsx` — send the new payload

```diff
   const onGenerate = async () => {
     setLoading(true);
     setError(null);
     try {
-      const res = await generate({ scenario_ids: selectedIds, os });
+      const res = await generate({ scenarios: selectedIds, os_profile: os });
       setResult(res);
     } catch (e) {
-      setError(String(e));
+      setError(e instanceof Error ? e.message : String(e));
     } finally {
       setLoading(false);
     }
   };
```
Loading/error states already exist (`loading`, `error`, the disabled `GenerateButton`, and the red
error banner). The `ResultView` already renders the story panel + a scannable table with malicious
rows highlighted — no change needed beyond the data now coming from the live API.

### 4.4 `frontend/vite.config.ts` — proxy `/api` to the backend (no CORS needed in dev)

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": "http://localhost:8000" },   // Uvicorn
  },
});
```
With the proxy, the browser calls same-origin `/api/...` and Vite forwards to `:8000`. The CORS
config in §5 is the belt-and-suspenders fallback for any direct cross-origin call.

---

## 5. Cross-Origin Resource Sharing (CORS)

The Vite proxy (§4.4) avoids CORS in dev by keeping calls same-origin. **But** if the frontend ever
calls the API directly (e.g. `fetch("http://localhost:8000/api/...")`, a deployed split origin, or
testing from a different port), the browser will block it without CORS headers. Enable it on the
backend — already included in `api.py`:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite dev
        "http://127.0.0.1:5173",
        # add your deployed UI origin here
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

> **Do not** ship `allow_origins=["*"]` together with `allow_credentials=True` — browsers reject it
> and it's unsafe. List explicit origins.

---

## 6. Verification & Testing Checklist

Run top-to-bottom. Two terminals (backend, frontend).

### 6.1 Database

```bash
docker compose up -d
docker compose ps          # postgres healthy
# Confirm the pool is seeded (sample = linux only):
docker exec -it attackgen-postgres psql -U attackgen -d attackgen \
  -c "SELECT label, os_profile, count(*) FROM command_lines GROUP BY 1,2 ORDER BY 1,2;"
```
- [ ] Rows exist for `benign/linux` and `malicious/linux`.

### 6.2 Backend

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export $(grep -v '^#' .env 2>/dev/null | xargs) 2>/dev/null || true   # or set POSTGRES_* / DATABASE_URL
uvicorn api:app --reload --port 8000
```
```bash
curl -s localhost:8000/api/health
curl -s localhost:8000/api/scenarios | head
curl -s -X POST localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -d '{"scenarios":["ransomware"],"os_profile":"linux","seed":42}' \
  | python -m json.tool | head -40
```
- [ ] `/api/health` → `{"status":"ok","db":"connected"}`
- [ ] `/api/generate` → `totals` = `{benign:200, malicious:20, total:220}`
- [ ] `rows` has **220** items; exactly **20** have `label:"malicious"`
- [ ] `malicious` has **20** items (the ground truth)
- [ ] `story` is a non-empty string
- [ ] malicious rows are **spread throughout** `rows`, not clustered at the end
- [ ] Same `seed` → identical output (determinism)

### 6.3 Frontend

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173
```
- [ ] Page loads; scenario cards populate from `GET /api/scenarios`
- [ ] Select a scenario + OS, click **Generate** → button shows loading state
- [ ] Story renders; table shows ~220 rows with malicious rows highlighted
- [ ] Download CSV (if used) contains **only** `process_name, command_line[, label]` — **no `attack_type`**

### 6.4 Error / edge paths

- [ ] `os_profile:"windows"` (with linux-only seed) → UI shows a clear error (`503` "… 0 commands … requested"), not a crash
- [ ] Empty `scenarios` → `400` "provide 'scenarios' or explicit category counts"
- [ ] Backend stopped → UI shows a friendly fetch error, app stays usable

---

## 7. Known Constraints & Risks

| Risk | Impact | Mitigation |
|---|---|---|
| **Windows data missing** in sample seed | Windows requests fail with `503` | Lock UI OS toggle to Linux for the demo, **or** have the DB owner add `windows` rows across all categories |
| **Category names must match** between `scenario_profiles.py` and the DB | A typo'd category → `InsufficientCommandsError` | Keep the profile categories == seed categories; add a startup check that every profile category exists in the DB |
| **Counts must sum to 200 / 20 exactly** | `compose()` raises `RequestValidationError` (returned as `400`) | The `assert`s in `build_categories` fail fast; keep edits balanced |
| **LLM story** needs `ANTHROPIC_API_KEY` + network | No key → no AI story | `generate_story` falls back to a deterministic template automatically |
| **Per-category inventory** in the real pool must exceed requested counts | Short category → `503` | DB owner ensures ≥ requested rows per category; composer fails loudly (by design) |
| **Stale `backend/` on `ui_branch`** | Confusion / duplicate backend | §1.2 path-checkout avoids it; delete it if present |

---

## 8. Execution Checklist (for an AI assistant or engineer)

1. [ ] Branch: `integration` off `main`; bring `frontend/` via `git checkout ui_branch -- frontend` (§1).
2. [ ] Add `api.py`, `scenario_profiles.py`, `story.py`; update `requirements.txt` (§3).
3. [ ] Edit `frontend/src/{types.ts, api.ts, App.tsx}` and `frontend/vite.config.ts` (§4).
4. [ ] `docker compose up -d`; confirm seed (§6.1).
5. [ ] `pip install -r requirements.txt`; `uvicorn api:app --port 8000`; curl checks pass (§6.2).
6. [ ] `cd frontend && npm install && npm run dev`; end-to-end click-through passes (§6.3).
7. [ ] Error paths behave (§6.4); open PR `integration → main`.

