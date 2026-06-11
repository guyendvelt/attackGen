"""Tests for the dataset composer (request loading, validation, blending)."""

import json

import pytest

from attackgen.composer import (
    Request,
    RequestValidationError,
    compose,
    load_request,
)
from attackgen.models import (
    BENIGN_TOTAL,
    MALICIOUS_TOTAL,
    TOTAL_ROWS,
    CommandRow,
    DatasetValidationError,
)
from attackgen.postgres_command_source import InMemoryCommandSource


# --- helpers ---------------------------------------------------------------

BENIGN_CATEGORIES = {
    "linux_admin": 40,
    "devops": 35,
    "logs": 35,
    "backup": 45,
    "app_runtime": 25,
    "package_management": 20,
}
MALICIOUS_CATEGORIES = {
    "discovery": 4,
    "staging": 4,
    "persistence": 3,
    "execution": 5,
    "cleanup": 2,
    "impact": 2,
}


def build_source(extra_per_category=10, os_profile="linux"):
    """An in-memory source with comfortably more than enough rows per category."""
    rows = []
    cid = 0
    for label, cats in (("benign", BENIGN_CATEGORIES), ("malicious", MALICIOUS_CATEGORIES)):
        for category, count in cats.items():
            for _ in range(count + extra_per_category):
                rows.append(
                    CommandRow(
                        process_name=f"proc_{category}",
                        command_line=f"{category} command {cid}",
                        label=label,
                        category=category,
                        os_profile=os_profile,
                        scenario_tags=["ransomware"],
                        id=cid,
                    )
                )
                cid += 1
    return InMemoryCommandSource(rows)


def make_request(**overrides):
    base = dict(
        scenario="ransomware",
        os_profile="linux",
        benign_categories=dict(BENIGN_CATEGORIES),
        malicious_categories=dict(MALICIOUS_CATEGORIES),
        seed=42,
        output_dir="outputs",
    )
    base.update(overrides)
    return Request(**base)


# --- request loading -------------------------------------------------------

def test_load_request_reads_json(tmp_path):
    payload = {
        "scenario": "ransomware",
        "os_profile": "linux",
        "benign_categories": BENIGN_CATEGORIES,
        "malicious_categories": MALICIOUS_CATEGORIES,
        "seed": 42,
        "output_dir": "outputs",
    }
    path = tmp_path / "request.json"
    path.write_text(json.dumps(payload))

    request = load_request(str(path))

    assert request.scenario == "ransomware"
    assert request.os_profile == "linux"
    assert request.benign_categories == BENIGN_CATEGORIES
    assert request.seed == 42


# --- valid composition -----------------------------------------------------

def test_valid_request_creates_exactly_220_rows():
    dataset = compose(make_request(), build_source())
    assert len(dataset.rows) == TOTAL_ROWS == 220


def test_valid_request_has_200_benign_and_20_malicious():
    dataset = compose(make_request(), build_source())
    benign = [r for r in dataset.rows if r.label == "benign"]
    malicious = [r for r in dataset.rows if r.label == "malicious"]
    assert len(benign) == BENIGN_TOTAL == 200
    assert len(malicious) == MALICIOUS_TOTAL == 20


# --- request count validation ----------------------------------------------

def test_invalid_benign_count_raises():
    bad = make_request(benign_categories={**BENIGN_CATEGORIES, "logs": 1})
    with pytest.raises(RequestValidationError, match="benign"):
        compose(bad, build_source())


def test_invalid_malicious_count_raises():
    bad = make_request(malicious_categories={**MALICIOUS_CATEGORIES, "impact": 99})
    with pytest.raises(RequestValidationError, match="malicious"):
        compose(bad, build_source())


# --- row-level validation ---------------------------------------------------

def test_missing_required_row_field_raises():
    src = build_source()
    # Corrupt one row so it is missing a command_line.
    src._rows[0].command_line = "   "
    with pytest.raises(DatasetValidationError, match="command_line"):
        compose(make_request(), src)


def test_invalid_label_raises():
    # Simulate a source that hands back a row with an invalid label; the
    # composer must reject it rather than emit it.
    base = build_source()

    class FaultySource(InMemoryCommandSource):
        def fetch(self, **kwargs):
            rows = super().fetch(**kwargs)
            rows[0].label = "weird"
            return rows

    faulty = FaultySource(base._rows)
    with pytest.raises(DatasetValidationError, match="label"):
        compose(make_request(), faulty)


# --- inventory --------------------------------------------------------------

def test_not_enough_commands_in_category_raises():
    # Only 1 row per category available, but the request needs many more.
    sparse = build_source(extra_per_category=-44)  # backup needs 45, gets 1
    from attackgen.postgres_command_source import InsufficientCommandsError

    with pytest.raises(InsufficientCommandsError):
        compose(make_request(), sparse)


# --- determinism ------------------------------------------------------------

def test_seeded_generation_is_deterministic():
    a = compose(make_request(seed=123), build_source())
    b = compose(make_request(seed=123), build_source())
    assert [r.command_line for r in a.rows] == [r.command_line for r in b.rows]


# --- blending ---------------------------------------------------------------

def test_malicious_rows_are_blended_not_clustered():
    dataset = compose(make_request(seed=7), build_source())
    indices = [i for i, r in enumerate(dataset.rows) if r.label == "malicious"]
    assert len(indices) == 20
    # Not all bunched at the end.
    assert min(indices) < TOTAL_ROWS // 2
    # Spread across the dataset, not one contiguous block of 20.
    assert max(indices) - min(indices) > 20
    # No long contiguous malicious run.
    longest_run = 1
    run = 1
    for prev, cur in zip(indices, indices[1:]):
        run = run + 1 if cur == prev + 1 else 1
        longest_run = max(longest_run, run)
    assert longest_run <= 2
