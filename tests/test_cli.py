"""Tests for the command-line entry point (no live database required)."""

import json
import os

from attackgen import cli
from attackgen.postgres_command_source import InMemoryCommandSource
from tests.test_composer import (
    BENIGN_CATEGORIES,
    MALICIOUS_CATEGORIES,
    build_source,
)


def write_request(tmp_path):
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
    return path


def in_memory_factory(request, args):
    return build_source(), {"type": "in_memory"}


def test_cli_writes_four_output_files(tmp_path, capsys):
    request_path = write_request(tmp_path)
    out_dir = tmp_path / "outputs"

    code = cli.main(
        ["--request", str(request_path), "--output-dir", str(out_dir)],
        source_factory=in_memory_factory,
    )

    assert code == 0
    for name in (
        "attack_dataset_labeled.csv",
        "attack_dataset_unlabeled.csv",
        "ground_truth_malicious.csv",
        "summary.json",
    ):
        assert (out_dir / name).exists()
    # The composer must not produce the story file.
    assert not (out_dir / "attack_story.md").exists()


def test_cli_prints_success_summary(tmp_path, capsys):
    request_path = write_request(tmp_path)
    out_dir = tmp_path / "outputs"
    cli.main(
        ["--request", str(request_path), "--output-dir", str(out_dir)],
        source_factory=in_memory_factory,
    )
    out = capsys.readouterr().out
    assert "ransomware" in out
    assert "linux" in out
    assert "220" in out
    assert "200" in out
    assert "20" in out
    assert str(out_dir) in out


def test_cli_seed_override(tmp_path):
    request_path = write_request(tmp_path)
    out_dir = tmp_path / "outputs"
    cli.main(
        ["--request", str(request_path), "--output-dir", str(out_dir), "--seed", "999"],
        source_factory=in_memory_factory,
    )
    summary = json.loads((out_dir / "summary.json").read_text())
    assert summary["seed"] == 999


def test_cli_invalid_request_returns_error(tmp_path, capsys):
    payload = {
        "scenario": "ransomware",
        "os_profile": "linux",
        "benign_categories": {"logs": 10},  # not 200
        "malicious_categories": MALICIOUS_CATEGORIES,
    }
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload))

    code = cli.main(
        ["--request", str(path), "--output-dir", str(tmp_path / "out")],
        source_factory=in_memory_factory,
    )
    assert code != 0
    err = capsys.readouterr().err
    assert "benign" in err.lower()
