"""FastAPI app for the Red Team Attack Generator.

Endpoints:
  GET  /api/scenarios  -> preset scenario cards
  POST /api/generate   -> dataset {story, rows[], malicious[]}

Generation is currently a mock (generator.generate_dataset); the LLM phase swaps
that function's internals while keeping this contract.
"""

from typing import List, Literal, Optional

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import generator
import scenarios as S

app = FastAPI(title="Red Team Attack Generator", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # hackathon/local dev
    allow_methods=["*"],
    allow_headers=["*"],
)


class Row(BaseModel):
    process_name: str
    command_line: str
    label: str
    attack_type: str


class Malicious(BaseModel):
    process_name: str
    command_line: str
    attack_type: str


class GenerateResponse(BaseModel):
    story: str
    rows: List[Row]
    malicious: List[Malicious]


@app.get("/api/scenarios")
def list_scenarios():
    return S.SCENARIO_META


@app.get("/api/generate", response_model=GenerateResponse)
def generate(
    scenario_ids: List[str] = Query(default=[]),
    os: Literal["windows", "linux"] = "windows",
    seed: Optional[int] = None,
):
    return generator.generate_dataset(
        scenario_ids=scenario_ids,
        os_name=os,
        seed=seed,
    )


@app.get("/api/health")
def health():
    return {"status": "ok"}
