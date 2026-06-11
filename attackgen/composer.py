"""Dataset composer: turn a category-count request into a blended 220-row dataset.

The composer receives *counts*, not command text. It pulls matching rows from a
``CommandSource``, enforces every challenge rule (exact 200/20/220 split, valid
fields and labels, no duplicate rows), then blends the malicious rows throughout
the benign rows so they are not clustered.

It never writes ``attack_story.md`` — the narrative is produced separately by the
``attack-story-writer`` Claude Code skill.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field

from attackgen.models import (
    BENIGN_TOTAL,
    MALICIOUS_TOTAL,
    TOTAL_ROWS,
    CommandRow,
    DatasetValidationError,
    validate_row,
)
from attackgen.postgres_command_source import CommandSource


class RequestValidationError(Exception):
    """Raised when a request's category counts do not meet the requirements."""


@dataclass
class Request:
    scenario: str
    os_profile: str
    benign_categories: dict[str, int]
    malicious_categories: dict[str, int]
    seed: int | None = None
    output_dir: str = "outputs"

    @property
    def benign_total(self) -> int:
        return sum(self.benign_categories.values())

    @property
    def malicious_total(self) -> int:
        return sum(self.malicious_categories.values())


@dataclass
class Dataset:
    rows: list[CommandRow]
    request: Request
    seed: int | None = None
    benign_rows: list[CommandRow] = field(default_factory=list)
    malicious_rows: list[CommandRow] = field(default_factory=list)


def load_request(path: str) -> Request:
    """Load and parse a request JSON file into a ``Request``."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    required = ("scenario", "os_profile", "benign_categories", "malicious_categories")
    missing = [k for k in required if k not in data]
    if missing:
        raise RequestValidationError(
            f"request is missing required field(s): {', '.join(missing)}"
        )

    return Request(
        scenario=data["scenario"],
        os_profile=data["os_profile"],
        benign_categories=dict(data["benign_categories"]),
        malicious_categories=dict(data["malicious_categories"]),
        seed=data.get("seed"),
        output_dir=data.get("output_dir", "outputs"),
    )


def validate_request(request: Request) -> None:
    """Validate category-count totals before touching the database."""
    if request.benign_total != BENIGN_TOTAL:
        raise RequestValidationError(
            f"benign category counts must total exactly {BENIGN_TOTAL}, "
            f"got {request.benign_total}"
        )
    if request.malicious_total != MALICIOUS_TOTAL:
        raise RequestValidationError(
            f"malicious category counts must total exactly {MALICIOUS_TOTAL}, "
            f"got {request.malicious_total}"
        )


def _row_key(row: CommandRow):
    if row.id is not None:
        return ("id", row.id)
    return ("text", row.process_name, row.command_line, row.label)


def _pull(source, label, categories, request, seed):
    rows: list[CommandRow] = []
    for category, count in categories.items():
        rows.extend(
            source.fetch(
                label=label,
                category=category,
                os_profile=request.os_profile,
                count=count,
                scenario_tags=[request.scenario] if request.scenario else None,
                seed=seed,
            )
        )
    return rows


def _blend(benign, malicious, seed):
    """Insert malicious rows across benign rows with even spacing plus jitter.

    Each malicious row lands in its own window of the timeline, so malicious rows
    are spread throughout and never appended in a block at the end.
    """
    rng = random.Random(f"{seed}:blend") if seed is not None else random.Random()
    benign = list(benign)
    malicious = list(malicious)
    rng.shuffle(benign)
    rng.shuffle(malicious)

    total = len(benign) + len(malicious)
    m = len(malicious)

    positions: list[int] = []
    used: set[int] = set()
    for i in range(m):
        start = (i * total) // m
        end = ((i + 1) * total) // m
        if end <= start:
            end = start + 1
        pos = rng.randrange(start, end)
        while pos in used:
            pos = (pos + 1) % total
        used.add(pos)
        positions.append(pos)

    malicious_by_pos = dict(zip(sorted(positions), malicious))
    result: list[CommandRow] = []
    benign_iter = iter(benign)
    for pos in range(total):
        if pos in malicious_by_pos:
            result.append(malicious_by_pos[pos])
        else:
            result.append(next(benign_iter))
    return result


def compose(request: Request, source: CommandSource, seed: int | None = None) -> Dataset:
    """Compose the full validated, blended 220-row dataset."""
    validate_request(request)
    effective_seed = seed if seed is not None else request.seed

    benign = _pull(source, "benign", request.benign_categories, request, effective_seed)
    malicious = _pull(source, "malicious", request.malicious_categories, request, effective_seed)

    # Row-level validation: fields present, labels valid.
    for row in (*benign, *malicious):
        validate_row(row)

    # The label on each row must match the bucket it was pulled for.
    for row in benign:
        if row.label != "benign":
            raise DatasetValidationError(
                f"expected benign row but got label {row.label!r}: {row.command_line!r}"
            )
    for row in malicious:
        if row.label != "malicious":
            raise DatasetValidationError(
                f"expected malicious row but got label {row.label!r}: {row.command_line!r}"
            )

    # Exact split.
    if len(benign) != BENIGN_TOTAL:
        raise DatasetValidationError(
            f"expected {BENIGN_TOTAL} benign rows, composed {len(benign)}"
        )
    if len(malicious) != MALICIOUS_TOTAL:
        raise DatasetValidationError(
            f"expected {MALICIOUS_TOTAL} malicious rows, composed {len(malicious)}"
        )

    # No duplicate rows (replacement is not enabled).
    seen: set = set()
    for row in (*benign, *malicious):
        key = _row_key(row)
        if key in seen:
            raise DatasetValidationError(
                f"duplicate row selected: {row.process_name} / {row.command_line!r}"
            )
        seen.add(key)

    rows = _blend(benign, malicious, effective_seed)

    if len(rows) != TOTAL_ROWS:
        raise DatasetValidationError(
            f"expected {TOTAL_ROWS} total rows after blending, got {len(rows)}"
        )

    return Dataset(
        rows=rows,
        request=request,
        seed=effective_seed,
        benign_rows=benign,
        malicious_rows=malicious,
    )
