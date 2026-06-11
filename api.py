"""FastAPI layer over the AttackGen composer. Adds HTTP + JSON; reuses all logic.

Run:  uvicorn api:app --reload --port 8000
"""
from __future__ import annotations
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
        "totals": {
            "benign": len(dataset.benign_rows),
            "malicious": len(dataset.malicious_rows),
            "total": len(dataset.rows),
        },
        "story": generate_story(dataset),
        "rows": rows,
        "malicious": malicious_rows,
    }
