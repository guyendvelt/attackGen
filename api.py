"""FastAPI layer over the AttackGen composer. Adds HTTP + JSON; reuses all logic.

Run:  uvicorn api:app --reload --port 8000
"""
from __future__ import annotations
import os
import random
import sys
from types import SimpleNamespace
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

# The command-picker (LLM, skill-driven) lives under backend/.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
import picker  # noqa: E402

app = FastAPI(title="AttackGen API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCENARIOS = [
    {"id": "ransomware",           "name": "Ransomware",           "icon": "🔒", "description": "Mass file archiving/encryption vs. legitimate system backups.",          "color": "#ef4444"},
    {"id": "lateral_movement",     "name": "Lateral Movement",     "icon": "↔️", "description": "Remote exec (wmic/psexec) vs. legal IT mass deployments.",               "color": "#8b5cf6"},
    {"id": "persistence",          "name": "Persistence",          "icon": "🚪", "description": "Malicious scheduled tasks/services vs. legit updates/cron-jobs.",         "color": "#06b6d4"},
    {"id": "credential_dumping",   "name": "Credential Dumping",   "icon": "🔑", "description": "Copying SAM/registry/browser DBs vs. standard admin backup tasks.",       "color": "#ec4899"},
    {"id": "reverse_shell",        "name": "Reverse Shell",        "icon": "🐚", "description": "Interactive shell pipes vs. automated DevOps remoting.",                 "color": "#14b8a6"},
    {"id": "data_exfiltration",    "name": "Data Exfiltration",    "icon": "📤", "description": "Compress + curl/certutil upload vs. routine log syncing.",               "color": "#3b82f6"},
    {"id": "sql_exploitation",     "name": "SQL Exploitation",     "icon": "🗄️", "description": "OS commands under db users (mssql/postgres) vs. heavy DB maintenance.",   "color": "#a855f7"},
    {"id": "crypto_miner",         "name": "Crypto Miner",         "icon": "⛏️", "description": "Hidden heavy-compute loops vs. intense QA stress-testing.",               "color": "#f59e0b"},
    {"id": "privilege_escalation", "name": "Privilege Escalation", "icon": "⬆️", "description": "Unquoted service paths/runas vs. legal admin overrides.",                 "color": "#10b981"},
    {"id": "defense_evasion",      "name": "Defense Evasion",      "icon": "🥷", "description": "Altering firewall/logging (netsh/sc) vs. official security policy updates.", "color": "#64748b"},
]


class GenerateRequest(BaseModel):
    scenarios: Optional[list[str]] = None
    os_profile: Literal["linux", "windows"] = "linux"
    seed: Optional[int] = None
    # Advanced form (optional explicit counts)
    scenario: Optional[str] = None
    benign_categories: Optional[dict[str, int]] = None
    malicious_categories: Optional[dict[str, int]] = None


def _source() -> PostgresCommandSource:
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


def _blend(malicious: list, benign: list, seed: Optional[int]) -> list:
    """Spread malicious rows evenly across benign rows (preserving story order)."""
    rng = random.Random(f"{seed}:blend") if seed is not None else random.Random()
    benign = list(benign)
    rng.shuffle(benign)
    total, m = len(benign) + len(malicious), len(malicious)
    positions: list[int] = []
    used: set[int] = set()
    for i in range(m):
        start, end = (i * total) // m, ((i + 1) * total) // m
        if end <= start:
            end = start + 1
        pos = rng.randrange(start, end)
        while pos in used:
            pos = (pos + 1) % total
        used.add(pos)
        positions.append(pos)
    mal_by_pos = dict(zip(sorted(positions), malicious))  # story order across positions
    out, bi = [], iter(benign)
    for pos in range(total):
        out.append(mal_by_pos[pos] if pos in mal_by_pos else next(bi))
    return out


def _shim_dataset(mal: list, ben: list, scenario: str, os_profile: str):
    """Adapt picker dict-rows into the object shape story.generate_story expects."""
    def row(d):
        return SimpleNamespace(
            process_name=d["process_name"], command_line=d["command_line"],
            label=d["label"], category=d.get("attack_type", "benign"),
        )
    mal_o, ben_o = [row(d) for d in mal], [row(d) for d in ben]
    return SimpleNamespace(
        rows=mal_o + ben_o, benign_rows=ben_o, malicious_rows=mal_o,
        request=SimpleNamespace(scenario=scenario, os_profile=os_profile),
    )


def _picker_response(picked: dict, scenarios: list, os_profile: str, seed: Optional[int]) -> dict:
    """Build the API response from a command-picker result (+ attack-story-writer)."""
    mal, ben = picked["malicious"], picked["benign"]
    scenario = scenarios[0] if len(scenarios) == 1 else " + ".join(scenarios)
    rows = _blend(mal, ben, seed)
    try:
        story = generate_story(_shim_dataset(mal, ben, scenario, os_profile))
    except Exception:
        story = picked.get("story") or "LLM-selected attack dataset."
    return {
        "scenario": scenario,
        "os_profile": os_profile,
        "seed": seed,
        "source": "command-picker",
        "totals": {"benign": len(ben), "malicious": len(mal), "total": len(rows)},
        "story": story,
        "rows": [
            {"process_name": r["process_name"], "command_line": r["command_line"],
             "label": r["label"], "attack_type": r.get("attack_type", "benign")}
            for r in rows
        ],
        "malicious": [
            {"process_name": r["process_name"], "command_line": r["command_line"],
             "attack_type": r.get("attack_type", "")}
            for r in mal
        ],
    }


@app.post("/api/generate")
def generate(req: GenerateRequest):
    # 1) Resolve category counts: explicit (advanced) or mapped from scenarios.
    if req.benign_categories and req.malicious_categories:
        benign, malicious = req.benign_categories, req.malicious_categories
        scenario = req.scenario or (req.scenarios[0] if req.scenarios else "custom")
    else:
        if not req.scenarios:
            raise HTTPException(status_code=400, detail="provide 'scenarios' or explicit category counts")
        # PRIMARY PATH: the command-picker skill (LLM) selects commands from the
        # 30k-row pool (data/template2.csv). Returns None if no LLM key / failure,
        # in which case we fall through to the deterministic Postgres composer.
        picked = picker.pick_dataset(req.scenarios, req.os_profile, seed=req.seed)
        if picked is not None:
            return _picker_response(picked, req.scenarios, req.os_profile, req.seed)
        benign, malicious, scenario = build_categories(req.scenarios)

    # NOTE: PostgresCommandSource treats `scenario` as a HARD SQL tag filter
    # (`scenario_tags && ...`), unlike InMemoryCommandSource which treats tags as
    # a preference. With the sample seed, most benign categories aren't tagged for
    # a given scenario, so a hard filter starves them. We compose WITHOUT the tag
    # filter (scenario="") and restore the scenario name afterwards for the
    # story/response. Selection is still correct (by label/category/os_profile).
    composer_req = Request(
        scenario="",
        os_profile=req.os_profile,
        benign_categories=benign,
        malicious_categories=malicious,
        seed=req.seed,
    )

    # 2) Compose (validates 200/20/220, blends, dedupes) — reused as-is.
    src = _source()
    try:
        dataset = compose(composer_req, src, seed=req.seed)
        composer_req.scenario = scenario  # restore theme for story + response
    except RequestValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (InsufficientCommandsError, CommandSourceError) as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except DatasetValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        src.close()

    # 3) Story (LLM or template) + 4) JSON response.
    rows = [{**r.to_export_dict(), "attack_type": r.category} for r in dataset.rows]
    malicious_rows = [
        {"process_name": r.process_name, "command_line": r.command_line, "attack_type": r.category}
        for r in dataset.malicious_rows
    ]
    return {
        "scenario": dataset.request.scenario,
        "os_profile": dataset.request.os_profile,
        "seed": dataset.seed,
        "source": "composer",
        "totals": {
            "benign": len(dataset.benign_rows),
            "malicious": len(dataset.malicious_rows),
            "total": len(dataset.rows),
        },
        "story": generate_story(dataset),
        "rows": rows,
        "malicious": malicious_rows,
    }
