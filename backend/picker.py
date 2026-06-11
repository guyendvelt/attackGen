"""LLM command picker (the real generation phase).

Samples candidate commands per category from the command pool, asks Claude —
with the .claude/skills/command-picker/SKILL.md text as system prompt — to pick
the best malicious + benign subset via structured outputs, validates the
answer, and returns rows. Every command is inert text; nothing is executed.

`pick_dataset` returns None whenever the picker can't run (no API key, API
error, bad pool); the caller falls back to the mock generator.
"""

from __future__ import annotations

import csv
import json
import os
import random
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

SKILL_PATH = ROOT / ".claude" / "skills" / "command-picker" / "SKILL.md"
POOL_CSV = ROOT / "data" / "template2.csv"

VALID_LABELS = {"benign", "malicious"}
KNOWN_CATEGORIES = {
    "ransomware", "lateral_movement", "persistence", "credential_dumping",
    "reverse_shell", "data_exfiltration", "sql_exploitation", "crypto_miner",
    "privilege_escalation", "defense_evasion",
}

MALICIOUS_TARGET = 20
BENIGN_TARGET = 200


class PickerError(Exception):
    pass


_pool_cache: Optional[List[Dict[str, str]]] = None


def load_pool_csv(path: Path = POOL_CSV) -> List[Dict[str, str]]:
    """Load the command pool, skipping malformed rows."""
    rows: List[Dict[str, str]] = []
    with open(path, newline="", encoding="utf-8") as f:
        for rec in csv.DictReader(f):
            if not rec.get("process_name") or not rec.get("command_line"):
                continue
            if rec.get("label") not in VALID_LABELS:
                continue
            if rec.get("attack_type") not in KNOWN_CATEGORIES:
                continue
            rows.append({
                "process_name": rec["process_name"],
                "command_line": rec["command_line"],
                "label": rec["label"],
                "attack_type": rec["attack_type"],
            })
    return rows


def _get_pool() -> List[Dict[str, str]]:
    global _pool_cache
    if _pool_cache is None:
        _pool_cache = load_pool_csv()
    return _pool_cache


def sample_candidates(
    pool: List[Dict[str, str]],
    categories: List[str],
    *,
    mal_per_cat: int,
    ben_per_cat: int,
    rnd: random.Random,
) -> List[Dict]:
    """Random per-category sample of candidates, with 1-based sequential ids."""
    out: List[Dict] = []
    for cat in categories:
        for label, n in (("malicious", mal_per_cat), ("benign", ben_per_cat)):
            bucket = [r for r in pool if r["attack_type"] == cat and r["label"] == label]
            for row in rnd.sample(bucket, min(n, len(bucket))):
                out.append(dict(row))
    for i, c in enumerate(out, start=1):
        c["id"] = i
    return out


def finalize_selection(
    mal_ids: List[int],
    ben_ids: List[int],
    candidates: List[Dict],
    *,
    mal_target: int,
    ben_target: int,
) -> tuple:
    """Resolve Claude's id picks into rows, fixing count/label mistakes.

    Keeps valid picks in the order Claude gave (story order matters for the
    malicious list), drops invalid/duplicate/wrong-label ids, trims extras, and
    backfills shortfalls from unused same-label candidates. Raises PickerError
    only when the candidate pool itself can't satisfy the targets.
    """
    by_id = {c["id"]: c for c in candidates}

    def resolve(ids: List[int], label: str, target: int, used: set) -> List[Dict]:
        rows: List[Dict] = []
        for i in ids:
            c = by_id.get(i)
            if c is None or c["label"] != label or i in used:
                continue
            used.add(i)
            rows.append(c)
            if len(rows) == target:
                break
        if len(rows) < target:
            for c in candidates:
                if c["label"] == label and c["id"] not in used:
                    used.add(c["id"])
                    rows.append(c)
                    if len(rows) == target:
                        break
        if len(rows) < target:
            raise PickerError(
                f"pool has only {len(rows)} {label} candidates, need {target}"
            )
        return rows

    used: set = set()
    mal = resolve(mal_ids, "malicious", mal_target, used)
    ben = resolve(ben_ids, "benign", ben_target, used)
    return mal, ben


MODEL = "claude-opus-4-8"
MAL_CAND_FACTOR = 3   # candidates per category = factor x per-category target
BEN_CAND_FACTOR = 2

_SCHEMA = {
    "type": "object",
    "properties": {
        "malicious_ids": {"type": "array", "items": {"type": "integer"}},
        "benign_ids": {"type": "array", "items": {"type": "integer"}},
        "story": {"type": "string"},
    },
    "required": ["malicious_ids", "benign_ids", "story"],
    "additionalProperties": False,
}


def _split_counts(total: int, n: int) -> List[int]:
    base, rem = divmod(total, n)
    return [base + (1 if i < rem else 0) for i in range(n)]


def _call_claude(system: str, user: str, schema: dict) -> dict:
    """One structured-output call. Isolated so tests can stub it."""
    import anthropic

    client = anthropic.Anthropic()
    response = client.messages.create(
        model=MODEL,
        max_tokens=16000,
        thinking={"type": "adaptive"},
        system=system,
        messages=[{"role": "user", "content": user}],
        output_config={"format": {"type": "json_schema", "schema": schema}},
    )
    if response.stop_reason == "refusal":
        raise PickerError("model refused the request")
    text = next(b.text for b in response.content if b.type == "text")
    return json.loads(text)


def _build_user_prompt(
    scenario_ids: List[str], os_name: str,
    mal_target: int, ben_target: int, candidates: List[Dict],
) -> str:
    lines = [
        f"Scenario: {', '.join(scenario_ids)} on a {os_name} host.",
        f"Pick exactly {mal_target} malicious ids (attack-story order) and "
        f"exactly {ben_target} benign ids from the candidates below.",
        "",
        "Candidates (id | process_name | command_line | label | attack_type):",
    ]
    for c in candidates:
        lines.append(
            f"{c['id']} | {c['process_name']} | {c['command_line']} | "
            f"{c['label']} | {c['attack_type']}"
        )
    return "\n".join(lines)


def pick_dataset(
    scenario_ids: List[str],
    os_name: str,
    seed: Optional[int] = None,
    *,
    mal_target: int = MALICIOUS_TARGET,
    ben_target: int = BENIGN_TARGET,
) -> Optional[dict]:
    """Return {story, malicious: [rows], benign: [rows]} or None on any failure."""
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key or key.startswith("sk-ant-REPLACE"):
        return None
    try:
        pool = _get_pool()
        cats = [c for c in scenario_ids if c in KNOWN_CATEGORIES] or ["lateral_movement"]
        rnd = random.Random(seed)
        mal_per_cat = max(12, MAL_CAND_FACTOR * max(_split_counts(mal_target, len(cats))))
        ben_per_cat = BEN_CAND_FACTOR * max(_split_counts(ben_target, len(cats)))
        candidates = sample_candidates(
            pool, cats, mal_per_cat=mal_per_cat, ben_per_cat=ben_per_cat, rnd=rnd
        )
        system = SKILL_PATH.read_text(encoding="utf-8")
        user = _build_user_prompt(cats, os_name, mal_target, ben_target, candidates)
        answer = _call_claude(system, user, _SCHEMA)
        mal, ben = finalize_selection(
            answer.get("malicious_ids", []), answer.get("benign_ids", []),
            candidates, mal_target=mal_target, ben_target=ben_target,
        )
        story = str(answer.get("story", "")).strip() or "LLM-selected attack dataset."

        def to_row(c: Dict) -> Dict[str, str]:
            return {
                "process_name": c["process_name"],
                "command_line": c["command_line"],
                "label": c["label"],
                "attack_type": c["attack_type"] if c["label"] == "malicious" else "benign",
            }

        return {
            "story": story,
            "malicious": [to_row(c) for c in mal],
            "benign": [to_row(c) for c in ben],
        }
    except Exception as exc:  # any failure -> caller falls back to mock
        print(f"[picker] falling back to mock generator: {exc}")
        return None
