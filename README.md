# AttackGen

Red Team **process-command telemetry generator** for the AI Red Team vs. Blue Team
Bootcamp challenge. AttackGen composes a labeled dataset that hides exactly **20
malicious** process commands inside about **200 benign** operational commands, then
exports it for the Blue Team to detect.

> **Everything here is simulated telemetry text only.** AttackGen never executes,
> spawns, or shells out to any command line it generates. There is no real
> exploitation, no real network or infrastructure activity, and no real credentials
> or secrets anywhere in this project. See [`instructions.md`](instructions.md) for
> the full project guide, safety boundaries, and data contracts.

This repository implements **Yoav's component** — the CSV generator and dataset
composer — plus a Claude Code skill that writes the attack story. The UI and the
full command database are owned by other teammates.

## What it produces

Running the composer writes four files into the output directory:

| File | Columns | Contents |
|------|---------|----------|
| `attack_dataset_labeled.csv` | `process_name, command_line, label` | 220 rows (200 benign + 20 malicious), blended |
| `attack_dataset_unlabeled.csv` | `process_name, command_line` | Same rows/order, no label — the Blue Team's input |
| `ground_truth_malicious.csv` | `process_name, command_line, label` | The 20 malicious rows (answer key) |
| `summary.json` | — | Scenario, OS profile, totals, per-category counts, seed, secret-free source info, validation status |

It also writes `story_context.json` (malicious rows grouped by category) to help the
story skill. The composer **does not** write `attack_story.md` — that is produced by
the `attack-story-writer` Claude Code skill (see below).

## Quick start

```bash
# 1. Create a virtualenv and install dependencies
python3 -m venv .venv
.venv/bin/pip install -U pip "psycopg[binary]" pytest

# 2. Start a local PostgreSQL with sample (simulated) data
docker compose up -d          # applies sql/schema.sql + sql/seed_sample_commands.sql

# 3. Point AttackGen at the database
cp .env.example .env          # then export the values, or pass --database-url
export DATABASE_URL="postgresql://attackgen:changeme@localhost:5432/attackgen"

# 4. Compose a dataset from a request
.venv/bin/python -m attackgen.cli --request sample_request.json --output-dir outputs
```

## Running the composer

```bash
python -m attackgen.cli --request sample_request.json --output-dir outputs
```

Options:

- `--request PATH` (required) — the request JSON file.
- `--output-dir DIR` — overrides `output_dir` from the request.
- `--database-url URL` — PostgreSQL URL; otherwise read from the environment.
- `--seed N` — deterministic selection and blending; overrides the request's `seed`.

```bash
# Pass the connection explicitly instead of via the environment
python -m attackgen.cli --request sample_request.json \
    --database-url "$DATABASE_URL" --output-dir outputs
```

On success it prints the scenario, OS profile, total/benign/malicious counts, seed,
and the output paths.

## Request JSON format

The composer receives **category counts, not raw command text**. Benign counts must
total exactly **200** and malicious counts exactly **20**.

```json
{
  "scenario": "ransomware",
  "os_profile": "linux",
  "benign_categories": {
    "linux_admin": 40, "devops": 35, "logs": 35,
    "backup": 45, "app_runtime": 25, "package_management": 20
  },
  "malicious_categories": {
    "discovery": 4, "staging": 4, "persistence": 3,
    "execution": 5, "cleanup": 2, "impact": 2
  },
  "seed": 42,
  "output_dir": "outputs"
}
```

| Field | Meaning |
|-------|---------|
| `scenario` | Attack scenario; also used as a soft `scenario_tags` preference when selecting rows. |
| `os_profile` | e.g. `linux` or `windows`. |
| `benign_categories` | Map of benign category → count (must sum to 200). |
| `malicious_categories` | Map of malicious category → count (must sum to 20). |
| `seed` *(optional)* | Makes selection and blending reproducible. |
| `output_dir` *(optional)* | Default output directory (CLI `--output-dir` overrides). |

## PostgreSQL setup

Commands come from a `command_lines` table. Credentials are read from the environment
— **never hardcoded**.

Provide **either** a single URL:

- `DATABASE_URL` — e.g. `postgresql://user:pass@host:5432/attackgen`

**or** the individual settings:

- `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`

See [`.env.example`](.env.example) for placeholders. The schema lives in
[`sql/schema.sql`](sql/schema.sql). [`sql/seed_sample_commands.sql`](sql/seed_sample_commands.sql)
contains **simulated placeholder sample data only** so you can run the pipeline
locally — it is not the real command pool (that is the command-database teammate's
responsibility). `docker compose up -d` applies both automatically.

The source uses **parameterized SQL** only, selects deterministically when a seed is
given, avoids duplicate rows, and fails clearly if the database is unreachable or a
requested category has too few matching commands.

## Generating the attack story

`attack_story.md` is written by the **`attack-story-writer`** Claude Code skill in
[`.claude/skills/attack-story-writer/`](.claude/skills/attack-story-writer/SKILL.md),
not by the composer.

1. Run the composer to produce `outputs/attack_dataset_labeled.csv`, `summary.json`,
   and `story_context.json`.
2. In Claude Code, invoke the skill and give it the CSV path, e.g.
   *"use attack-story-writer on `outputs/attack_dataset_labeled.csv`"*.
3. The skill reads the CSV (and `summary.json` / `story_context.json` if present),
   groups the malicious rows by attack phase, infers the narrative, and writes
   `outputs/attack_story.md` with Title, Scenario, Executive Summary, Attack Timeline,
   Malicious Command Breakdown, Benign Lookalike Strategy, Why This Is Challenging for
   Blue Team, and a Safety Note.

The skill treats every command line as text only and never executes anything.

## Validation

The composer fails loudly with a clear message if any of these is violated: benign
total ≠ 200, malicious total ≠ 20, total ≠ 220, a category has too few commands in
PostgreSQL, the database is unreachable, a row is missing `process_name` or
`command_line`, a label is invalid, or a duplicate row is selected.

## Project layout

```
attackgen/
  models.py                  # CommandRow + validation + constants
  config.py                  # DbConfig (env / URL), secret redaction
  postgres_command_source.py # CommandSource abstraction, InMemory + Postgres sources
  composer.py                # request loading/validation, compose(), blending
  exporters.py               # CSV + summary.json + story_context.json writers
  cli.py                     # python -m attackgen.cli entry point
tests/                       # pytest suite
sql/                         # schema.sql + simulated sample seed
.claude/skills/attack-story-writer/SKILL.md
sample_request.json
.env.example
docker-compose.yml
```

## Running the tests

```bash
.venv/bin/python -m pytest -q
```
