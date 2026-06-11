# Command-Picker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** LLM-driven command selection — a `command-picker` Claude skill whose text becomes the system prompt of one Anthropic API call that picks the best 20 malicious + 200 benign commands from the command pool, with graceful fallback to the existing mock generator.

**Architecture:** `backend/picker.py` samples candidate commands per category from `data/template2.csv` (CSV pool; Postgres optional later), sends them with the SKILL.md system prompt to `claude-opus-4-8` using structured outputs, validates/backfills the returned ids, and returns rows. `backend/generator.py` tries the picker first and falls back to the mock path on any failure. `ANTHROPIC_API_KEY` comes from `attackGen/.env` via python-dotenv.

**Tech Stack:** Python 3, FastAPI, `anthropic` SDK (structured outputs via `output_config.format`), `python-dotenv`, pytest.

**Spec:** `docs/superpowers/specs/2026-06-11-command-picker-design.md`

---

### Task 1: Project setup (venv, deps, .env.example)

**Files:**
- Modify: `backend/requirements.txt`
- Modify: `.env.example`

- [ ] **Step 1: Create venv and install existing deps**

```bash
cd /Users/yoavnesher/RedTeam/attackGen
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r backend/requirements.txt
```

Expected: installs succeed; `.venv/` is already gitignored (`.venv/` in `.gitignore`).

- [ ] **Step 2: Add new backend deps**

Append to `backend/requirements.txt`:

```
anthropic>=0.50
python-dotenv>=1.0
```

Then:

```bash
.venv/bin/pip install -r backend/requirements.txt
```

- [ ] **Step 3: Add the API key placeholder to `.env.example`**

Append to `.env.example`:

```
# Anthropic API key for the command-picker agent (backend/picker.py).
# Get one at https://platform.claude.com -> API Keys. Never commit the real key.
ANTHROPIC_API_KEY=sk-ant-REPLACE_ME
```

- [ ] **Step 4: Commit**

```bash
git add backend/requirements.txt .env.example
git commit -m "chore: add anthropic + python-dotenv deps and ANTHROPIC_API_KEY placeholder"
```

---

### Task 2: The `command-picker` skill

**Files:**
- Create: `.claude/skills/command-picker/SKILL.md`

- [ ] **Step 1: Write the skill**

Create `.claude/skills/command-picker/SKILL.md` with exactly this content:

```markdown
---
name: command-picker
description: Use when you have a list of candidate process commands (id, process_name, command_line, label, attack_type) and need to pick the best subset for an AttackGen dataset — exactly the requested number of malicious commands forming a coherent attack story, plus benign lookalike commands that camouflage them. Treats every command as inert text; never executes anything.
---

# Command Picker

Select the best commands from a candidate pool for an AttackGen dataset. The
dataset hides exactly N malicious commands (default 20) inside M benign
operational commands (default 200), and a Blue Team detector will try to find
them. Your job is to make detection genuinely hard **without breaking realism**.

## Absolute safety rules (read first)

- **Text only.** Every candidate is an inert telemetry string. Never execute,
  run, spawn, or "try" any command. You only select rows by id.
- **No invented content.** Pick only from the provided candidates by their ids.
  Never write new command lines or modify existing ones.

## Inputs

A request containing:

- **Scenario context** — the attack story (e.g. "ransomware on a Linux web server").
- **OS profile** — `linux` or `windows`.
- **Targets** — how many malicious and benign commands to pick per category
  (malicious totals 20, benign totals 200 unless stated otherwise).
- **Candidates** — a numbered list, one per line:
  `id | process_name | command_line | label | attack_type`

## Selection criteria

1. **Story coherence (malicious).** The malicious picks must read as one
   plausible multi-phase attack in order: discovery → staging → persistence /
   privilege escalation → execution → collection → exfiltration / impact →
   cleanup. Prefer commands that chain (same paths, artifacts, hosts).
2. **Stealth.** Prefer living-off-the-land commands that resemble legitimate
   admin/DevOps work. Avoid cartoonish payloads, joke strings, or anything that
   screams "I am the attack."
3. **Lookalike pairing (benign).** Benign picks must camouflage the malicious
   activity: choose benign commands whose binaries, paths, and flags resemble
   the chosen malicious ones (backup jobs masking ransomware staging, CI/CD
   remoting masking reverse shells, etc.).
4. **Diversity.** No near-duplicate command lines among picks; vary processes,
   targets, and arguments.
5. **OS consistency.** Picks must match the OS profile.

## Output

Respond with **JSON only**, matching this exact shape:

```json
{
  "malicious_ids": [3, 17, 42],
  "benign_ids": [1, 2, 5, 8],
  "story": "2-4 sentence narrative of the attack the malicious picks tell, in phase order."
}
```

- `malicious_ids`: ids of chosen malicious candidates, **in attack-story order**,
  exactly the requested malicious total.
- `benign_ids`: ids of chosen benign candidates, exactly the requested benign total.
- Use each id at most once. Use only ids that exist in the candidate list and
  whose label matches the list you put them in.
```

- [ ] **Step 2: Commit**

```bash
git add .claude/skills/command-picker/SKILL.md
git commit -m "feat: add command-picker skill"
```

---

### Task 3: Candidate sampling (`backend/picker.py` part 1)

**Files:**
- Create: `backend/picker.py`
- Create: `tests/test_picker.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_picker.py`:

```python
"""Tests for backend/picker.py — no network calls anywhere."""
import random
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

import picker  # noqa: E402


@pytest.fixture()
def pool():
    rows = []
    for cat in ("ransomware", "persistence"):
        for i in range(30):
            rows.append({
                "process_name": "bash",
                "command_line": f"{cat}-mal-{i}",
                "label": "malicious",
                "attack_type": cat,
            })
        for i in range(60):
            rows.append({
                "process_name": "bash",
                "command_line": f"{cat}-ben-{i}",
                "label": "benign",
                "attack_type": cat,
            })
    return rows


def test_sample_candidates_counts_and_ids(pool):
    rnd = random.Random(7)
    cands = picker.sample_candidates(
        pool, ["ransomware", "persistence"], mal_per_cat=10, ben_per_cat=20, rnd=rnd
    )
    mal = [c for c in cands if c["label"] == "malicious"]
    ben = [c for c in cands if c["label"] == "benign"]
    assert len(mal) == 20 and len(ben) == 40
    # ids are unique and sequential from 1
    assert [c["id"] for c in cands] == list(range(1, len(cands) + 1))


def test_sample_candidates_caps_at_available(pool):
    rnd = random.Random(7)
    cands = picker.sample_candidates(
        pool, ["ransomware"], mal_per_cat=999, ben_per_cat=999, rnd=rnd
    )
    mal = [c for c in cands if c["label"] == "malicious"]
    assert len(mal) == 30  # only 30 available


def test_load_pool_csv_skips_malformed(tmp_path):
    p = tmp_path / "pool.csv"
    p.write_text(
        "process_name,command_line,label,attack_type\n"
        "bash,echo hi,benign,ransomware\n"
        "bash,broken row,who-knows,stderr\n"
        "pwsh,Get-Date,malicious,persistence\n"
    )
    rows = picker.load_pool_csv(p)
    assert len(rows) == 2
    assert {r["label"] for r in rows} == {"benign", "malicious"}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest tests/test_picker.py -v
```

Expected: FAIL / error — `ModuleNotFoundError: No module named 'picker'`.

- [ ] **Step 3: Implement sampling in `backend/picker.py`**

Create `backend/picker.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest tests/test_picker.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add backend/picker.py tests/test_picker.py
git commit -m "feat: picker candidate sampling from CSV pool"
```

---

### Task 4: Selection validation + backfill (`backend/picker.py` part 2)

**Files:**
- Modify: `backend/picker.py`
- Modify: `tests/test_picker.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_picker.py`:

```python
def _cands(n_mal, n_ben):
    cands = []
    i = 1
    for _ in range(n_mal):
        cands.append({"id": i, "process_name": "bash", "command_line": f"m{i}",
                      "label": "malicious", "attack_type": "ransomware"})
        i += 1
    for _ in range(n_ben):
        cands.append({"id": i, "process_name": "bash", "command_line": f"b{i}",
                      "label": "benign", "attack_type": "ransomware"})
        i += 1
    return cands


def test_finalize_happy_path():
    cands = _cands(5, 8)
    mal, ben = picker.finalize_selection([1, 2, 3], [6, 7, 8, 9], cands,
                                         mal_target=3, ben_target=4)
    assert [r["command_line"] for r in mal] == ["m1", "m2", "m3"]
    assert len(ben) == 4 and all(r["label"] == "benign" for r in ben)


def test_finalize_backfills_and_trims():
    cands = _cands(5, 8)
    # too few malicious (and one wrong-label id), too many benign
    mal, ben = picker.finalize_selection([1, 6], [6, 7, 8, 9, 10, 11], cands,
                                         mal_target=3, ben_target=4)
    assert len(mal) == 3 and all(r["label"] == "malicious" for r in mal)
    assert mal[0]["command_line"] == "m1"  # valid pick kept first
    assert len(ben) == 4
    # ids 6.. appear once across both lists
    all_ids = [r["id"] for r in mal + ben]
    assert len(all_ids) == len(set(all_ids))


def test_finalize_raises_when_insufficient():
    cands = _cands(2, 8)
    with pytest.raises(picker.PickerError):
        picker.finalize_selection([1], [3, 4], cands, mal_target=3, ben_target=4)
```

- [ ] **Step 2: Run tests to verify the new ones fail**

```bash
.venv/bin/python -m pytest tests/test_picker.py -v
```

Expected: 3 passed, 3 failed (`AttributeError: ... finalize_selection`).

- [ ] **Step 3: Implement `finalize_selection`**

Append to `backend/picker.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest tests/test_picker.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add backend/picker.py tests/test_picker.py
git commit -m "feat: picker selection validation with backfill/trim"
```

---

### Task 5: The Anthropic call + `pick_dataset` orchestration

**Files:**
- Modify: `backend/picker.py`
- Modify: `tests/test_picker.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_picker.py`:

```python
def test_pick_dataset_returns_none_without_api_key(monkeypatch, pool):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(picker, "_get_pool", lambda: pool)
    assert picker.pick_dataset(["ransomware"], "linux", seed=1) is None


def test_pick_dataset_uses_stubbed_claude(monkeypatch, pool):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(picker, "_get_pool", lambda: pool)

    def fake_call(system, user, schema):
        cands = picker.sample_candidates(
            pool, ["ransomware"],
            mal_per_cat=picker.MAL_CAND_FACTOR * 2,
            ben_per_cat=picker.BEN_CAND_FACTOR * 3,
            rnd=random.Random(1),
        )
        mal = [c["id"] for c in cands if c["label"] == "malicious"][:2]
        ben = [c["id"] for c in cands if c["label"] == "benign"][:3]
        return {"malicious_ids": mal, "benign_ids": ben, "story": "test story"}

    monkeypatch.setattr(picker, "_call_claude", fake_call)
    result = picker.pick_dataset(["ransomware"], "linux", seed=1,
                                 mal_target=2, ben_target=3)
    assert result is not None
    assert result["story"] == "test story"
    assert len(result["malicious"]) == 2 and len(result["benign"]) == 3
    assert all(r["label"] == "malicious" for r in result["malicious"])


def test_pick_dataset_none_on_api_error(monkeypatch, pool):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(picker, "_get_pool", lambda: pool)

    def boom(system, user, schema):
        raise RuntimeError("api down")

    monkeypatch.setattr(picker, "_call_claude", boom)
    assert picker.pick_dataset(["ransomware"], "linux", seed=1) is None
```

- [ ] **Step 2: Run tests to verify the new ones fail**

```bash
.venv/bin/python -m pytest tests/test_picker.py -v
```

Expected: 6 passed, 3 failed (`AttributeError: ... pick_dataset` / `MAL_CAND_FACTOR`).

- [ ] **Step 3: Implement the call + orchestration**

Append to `backend/picker.py`:

```python
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
    if not os.environ.get("ANTHROPIC_API_KEY"):
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
        to_row = lambda c: {  # noqa: E731
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest tests/test_picker.py -v
```

Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add backend/picker.py tests/test_picker.py
git commit -m "feat: picker Claude call with structured outputs and mock fallback"
```

---

### Task 6: Wire picker into the generator

**Files:**
- Modify: `backend/generator.py` (function `generate_dataset`, near line 170)
- Modify: `tests/test_picker.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_picker.py`:

```python
def test_generator_falls_back_to_mock_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    import generator
    result = generator.generate_dataset(scenario_ids=["ransomware"],
                                        os_name="linux", seed=42)
    mal = [r for r in result["rows"] if r["label"] == "malicious"]
    ben = [r for r in result["rows"] if r["label"] == "benign"]
    assert len(mal) == 20 and len(ben) == 200
    assert result["story"]


def test_generator_uses_picker_when_it_returns(monkeypatch):
    import generator
    fake = {
        "story": "picker story",
        "malicious": [{"process_name": "bash", "command_line": f"m{i}",
                       "label": "malicious", "attack_type": "ransomware"}
                      for i in range(20)],
        "benign": [{"process_name": "bash", "command_line": f"b{i}",
                    "label": "benign", "attack_type": "benign"}
                   for i in range(200)],
    }
    monkeypatch.setattr(generator.picker, "pick_dataset",
                        lambda *a, **k: fake)
    result = generator.generate_dataset(scenario_ids=["ransomware"],
                                        os_name="linux", seed=42)
    assert result["story"] == "picker story"
    assert len(result["rows"]) == 220
    assert len(result["malicious"]) == 20
```

- [ ] **Step 2: Run tests to verify the new ones fail**

```bash
.venv/bin/python -m pytest tests/test_picker.py -v
```

Expected: `test_generator_uses_picker_when_it_returns` FAILS (`AttributeError: module 'generator' has no attribute 'picker'`). The fallback test may pass already.

- [ ] **Step 3: Hook the picker into `generate_dataset`**

In `backend/generator.py`, add the import after `import scenarios as S` (line ~22):

```python
import picker
```

Then inside `generate_dataset`, immediately after `resolved = _resolve_scenarios(scenario_ids)`, insert:

```python
    # LLM phase: ask Claude (command-picker skill) for the best commands.
    # Any failure returns None and we fall through to the mock path below.
    picked = picker.pick_dataset(resolved, os_name, seed)
    if picked is not None:
        rows = picked["malicious"] + picked["benign"]
        rnd.shuffle(rows)
        return {
            "story": picked["story"],
            "rows": rows,
            "malicious": [
                {
                    "process_name": c["process_name"],
                    "command_line": c["command_line"],
                    "attack_type": c["attack_type"],
                }
                for c in picked["malicious"]
            ],
        }
```

- [ ] **Step 4: Run the full test suite**

```bash
.venv/bin/python -m pytest tests/ -v
```

Expected: all tests pass (the pre-existing attackgen tests must stay green; `test_postgres_command_source.py` may skip without a DB).

- [ ] **Step 5: Commit**

```bash
git add backend/generator.py tests/test_picker.py
git commit -m "feat: generator tries LLM picker before mock path"
```

---

### Task 7: End-to-end smoke test

**Files:** none (verification only)

- [ ] **Step 1: Create `.env` if missing and check key presence**

```bash
test -f .env || cp .env.example .env
grep -q "^ANTHROPIC_API_KEY=sk-ant-" .env && echo "key line present"
```

(The user pastes their real key into `.env`; with the placeholder still in
place the picker call fails auth and the mock fallback is exercised instead —
both paths are valid smoke tests.)

- [ ] **Step 2: Run the backend and hit /api/generate**

```bash
cd backend
../.venv/bin/python -m uvicorn main:app --port 8000 &
sleep 2
curl -s "http://localhost:8000/api/generate?scenario_ids=ransomware&os=linux" \
  | ../.venv/bin/python -c "import json,sys; d=json.load(sys.stdin); \
print('story:', d['story'][:80]); \
print('rows:', len(d['rows']), 'malicious:', sum(1 for r in d['rows'] if r['label']=='malicious'))"
kill %1
```

Expected: `rows: 220 malicious: 20`. With a real key the story is Claude's; without one, the server log shows `[picker] falling back to mock generator:` and the mock story appears.

- [ ] **Step 3: Final commit if anything changed, and report**

Report: where the key goes (`attackGen/.env`, line `ANTHROPIC_API_KEY=sk-ant-...`), and that the picker is live with mock fallback.
