# Command-Picker Design

**Date:** 2026-06-11
**Branch:** `command-picker`
**Goal:** Replace random command selection with an LLM-driven picker. A new Claude
skill (`command-picker`) instructs Claude to choose the best commands per category
for the generated CSV; the FastAPI backend loads that skill as the system prompt of
a single Anthropic API call.

## Architecture

```
POST /api/generate
   ├─ 1. Sample candidate commands per requested category
   │     (Postgres command_pool via CommandPoolSource; fallback: data/template2.csv)
   ├─ 2. ONE Anthropic API call
   │     system  = .claude/skills/command-picker/SKILL.md (file content)
   │     user    = scenario, OS, category counts, numbered candidate list
   │     output_config.format = json_schema
   │     → {malicious_ids: [...], benign_ids: [...], story: "..."}
   └─ 3. Validate counts → backfill/trim from candidates → compose CSV outputs
```

## Components

### 1. Skill: `.claude/skills/command-picker/SKILL.md`

Same format as the existing `attack-story-writer` skill. Given scenario, OS
profile, category counts, and a numbered candidate list
(`id, process_name, command_line, label, attack_type`), pick exactly the
requested counts (20 malicious / 200 benign total) by:

- **Story coherence** — malicious picks form an ordered, plausible attack chain
  across phases (discovery → staging → persistence → … → impact).
- **Stealth** — prefer living-off-the-land style commands that resemble
  legitimate operations; avoid cartoonishly obvious payloads.
- **Lookalike pairing** — benign picks emphasize categories that camouflage the
  chosen malicious activity (instructions.md §11).
- **Diversity** — no near-duplicate command lines.
- **Safety** — all rows are inert text telemetry; never execute anything.

Output contract: strict JSON `{malicious_ids, benign_ids, story}` referencing
candidate ids only.

The skill doubles as an interactive Claude Code skill and as the backend
agent's system prompt — single source of truth.

### 2. Backend: `backend/picker.py` (new) + hook in `backend/generator.py`

- Candidate sampling: ~100 per requested category from Postgres
  (`command_pool` table); CSV fallback (`data/template2.csv`) when no DB.
- Anthropic call: `claude-opus-4-8`, `thinking={"type": "adaptive"}`,
  structured outputs via `output_config.format` (json_schema) —
  guaranteed-parseable response.
- Post-validation: exactly 20 malicious / 200 benign. Wrong counts →
  backfill/trim from remaining candidates; fail loudly only when candidates are
  insufficient.
- **Graceful fallback:** missing `ANTHROPIC_API_KEY` or API error → current
  random/mock selection. The demo never 500s.
- Deps: `anthropic`, `python-dotenv` added to `backend/requirements.txt`.

### 3. Configuration

- `ANTHROPIC_API_KEY` in `attackGen/.env` (gitignored, never committed).
- `.env.example` gains the placeholder line.
- Backend loads `.env` at startup via `python-dotenv`.

## Error handling

| Failure | Behavior |
|---|---|
| No API key | Fall back to mock/random selection, log a warning |
| API error / refusal / timeout | Same fallback |
| Wrong counts in Claude's answer | Backfill/trim from candidates deterministically |
| Insufficient candidates in a category | Fail loudly with a clear message (per instructions.md §8) |

## Testing

- Unit tests for candidate sampling, response validation, and backfill/trim
  logic (no network).
- The Anthropic call wrapped in a function that tests can stub.

## Safety boundary

All commands are simulated process-command telemetry strings only. The picker
selects and labels text rows; nothing is ever executed (instructions.md §3).
