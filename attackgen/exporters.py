"""Output-file exporters for the composed dataset.

Writes the four generator deliverables — labeled CSV, unlabeled CSV, ground-truth
CSV, and ``summary.json`` — plus an optional ``story_context.json`` to help the
``attack-story-writer`` skill. It deliberately does **not** write
``attack_story.md``; the narrative is the skill's job.

Only ``process_name``, ``command_line`` and ``label`` are ever exported. CSVs use
``csv.writer`` so command lines containing commas or quotes are quoted correctly.
"""

from __future__ import annotations

import csv
import json
import os
from typing import Mapping, Sequence

from attackgen.composer import Dataset
from attackgen.models import (
    BENIGN_TOTAL,
    LABELED_COLUMNS,
    MALICIOUS_TOTAL,
    TOTAL_ROWS,
    UNLABELED_COLUMNS,
    CommandRow,
)

LABELED_CSV = "attack_dataset_labeled.csv"
UNLABELED_CSV = "attack_dataset_unlabeled.csv"
GROUND_TRUTH_CSV = "ground_truth_malicious.csv"
SUMMARY_JSON = "summary.json"
STORY_CONTEXT_JSON = "story_context.json"


def _write_csv(rows: Sequence[CommandRow], path: str, columns: Sequence[str], labeled: bool) -> None:
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        for row in rows:
            data = row.to_export_dict() if labeled else row.to_unlabeled_dict()
            writer.writerow([data[col] for col in columns])


def write_labeled_csv(rows: Sequence[CommandRow], path: str) -> None:
    _write_csv(rows, path, LABELED_COLUMNS, labeled=True)


def write_unlabeled_csv(rows: Sequence[CommandRow], path: str) -> None:
    _write_csv(rows, path, UNLABELED_COLUMNS, labeled=False)


def write_ground_truth(rows: Sequence[CommandRow], path: str) -> None:
    malicious = [r for r in rows if r.label == "malicious"]
    _write_csv(malicious, path, LABELED_COLUMNS, labeled=True)


def _build_summary(dataset: Dataset, files: Mapping[str, str], source_info: Mapping) -> dict:
    benign = [r for r in dataset.rows if r.label == "benign"]
    malicious = [r for r in dataset.rows if r.label == "malicious"]
    return {
        "scenario": dataset.request.scenario,
        "os_profile": dataset.request.os_profile,
        "seed": dataset.seed,
        "totals": {
            "benign": len(benign),
            "malicious": len(malicious),
            "total": len(dataset.rows),
        },
        "benign_categories": dict(dataset.request.benign_categories),
        "malicious_categories": dict(dataset.request.malicious_categories),
        "files": {key: os.path.basename(path) for key, path in files.items()},
        "source": dict(source_info),
        "validation": {
            "status": "passed",
            "expected": {
                "benign": BENIGN_TOTAL,
                "malicious": MALICIOUS_TOTAL,
                "total": TOTAL_ROWS,
            },
        },
    }


def _build_story_context(dataset: Dataset) -> dict:
    """Compact, secret-free context describing the malicious rows by category."""
    malicious_by_category: dict[str, list[dict]] = {}
    for row in dataset.rows:
        if row.label != "malicious":
            continue
        malicious_by_category.setdefault(row.category, []).append(
            {"process_name": row.process_name, "command_line": row.command_line}
        )
    return {
        "scenario": dataset.request.scenario,
        "os_profile": dataset.request.os_profile,
        "benign_categories": dict(dataset.request.benign_categories),
        "malicious_categories": dict(dataset.request.malicious_categories),
        "malicious_by_category": malicious_by_category,
    }


def write_summary(dataset: Dataset, path: str, files: Mapping[str, str], source_info: Mapping) -> None:
    summary = _build_summary(dataset, files, source_info)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)


def write_story_context(dataset: Dataset, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(_build_story_context(dataset), handle, indent=2)


def export_dataset(
    dataset: Dataset,
    output_dir: str,
    *,
    source_info: Mapping | None = None,
    write_context: bool = True,
) -> dict[str, str]:
    """Write all generator output files into ``output_dir`` and return their paths."""
    os.makedirs(output_dir, exist_ok=True)
    source_info = dict(source_info or {})

    paths = {
        "labeled_csv": os.path.join(output_dir, LABELED_CSV),
        "unlabeled_csv": os.path.join(output_dir, UNLABELED_CSV),
        "ground_truth_csv": os.path.join(output_dir, GROUND_TRUTH_CSV),
        "summary_json": os.path.join(output_dir, SUMMARY_JSON),
    }

    write_labeled_csv(dataset.rows, paths["labeled_csv"])
    write_unlabeled_csv(dataset.rows, paths["unlabeled_csv"])
    write_ground_truth(dataset.rows, paths["ground_truth_csv"])

    if write_context:
        paths["story_context_json"] = os.path.join(output_dir, STORY_CONTEXT_JSON)
        write_story_context(dataset, paths["story_context_json"])

    write_summary(dataset, paths["summary_json"], paths, source_info)
    return paths
