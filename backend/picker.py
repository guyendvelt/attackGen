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
