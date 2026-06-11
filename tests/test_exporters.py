"""Tests for the output-file exporters."""

import csv
import json

from attackgen.composer import Request, compose
from attackgen.models import CommandRow
from attackgen.exporters import export_dataset
from attackgen.postgres_command_source import InMemoryCommandSource
from tests.test_composer import build_source, make_request


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        rows = list(reader)
    return rows[0], rows[1:]


def export_to(tmp_path):
    dataset = compose(make_request(seed=5), build_source())
    source_info = {"type": "in_memory"}
    paths = export_dataset(dataset, str(tmp_path), source_info=source_info)
    return dataset, paths


def test_labeled_csv_has_exact_columns_and_220_rows(tmp_path):
    _, paths = export_to(tmp_path)
    header, body = read_csv(paths["labeled_csv"])
    assert header == ["process_name", "command_line", "label"]
    assert len(body) == 220


def test_unlabeled_csv_has_two_columns_same_order(tmp_path):
    dataset, paths = export_to(tmp_path)
    header, body = read_csv(paths["unlabeled_csv"])
    assert header == ["process_name", "command_line"]
    assert len(body) == 220
    # Same rows, same order as the labeled CSV (minus the label column).
    _, labeled_body = read_csv(paths["labeled_csv"])
    assert [row[:2] for row in labeled_body] == body


def test_ground_truth_has_exactly_20_malicious(tmp_path):
    _, paths = export_to(tmp_path)
    header, body = read_csv(paths["ground_truth_csv"])
    assert header == ["process_name", "command_line", "label"]
    assert len(body) == 20
    assert all(row[2] == "malicious" for row in body)


def test_summary_json_contents(tmp_path):
    dataset, paths = export_to(tmp_path)
    with open(paths["summary_json"], encoding="utf-8") as handle:
        summary = json.load(handle)
    assert summary["scenario"] == "ransomware"
    assert summary["os_profile"] == "linux"
    assert summary["totals"] == {"benign": 200, "malicious": 20, "total": 220}
    assert summary["benign_categories"]
    assert summary["malicious_categories"]
    assert summary["seed"] == 5
    assert summary["validation"]["status"] == "passed"
    assert "files" in summary
    assert summary["source"] == {"type": "in_memory"}


def test_summary_never_contains_secrets(tmp_path):
    dataset = compose(make_request(seed=5), build_source())
    source_info = {"type": "postgres", "host": "h", "dbname": "d", "user": "u", "password": "***"}
    paths = export_dataset(dataset, str(tmp_path), source_info=source_info)
    raw = open(paths["summary_json"], encoding="utf-8").read()
    assert "topsecret" not in raw
    assert '"password": "***"' in raw


def test_export_does_not_create_attack_story(tmp_path):
    export_to(tmp_path)
    assert not (tmp_path / "attack_story.md").exists()


def test_csv_quoting_roundtrips_commas(tmp_path):
    row = CommandRow(
        process_name="bash",
        command_line='tar -czf "a,b.tgz" /var, /etc',
        label="benign",
        category="backup",
        os_profile="linux",
        id=1,
    )
    # Build a minimal dataset by hand to check quoting on a tricky command.
    benign = [row]
    from attackgen.exporters import write_labeled_csv

    out = tmp_path / "x.csv"
    write_labeled_csv([row], str(out))
    _, body = read_csv(str(out))
    assert body[0][1] == 'tar -czf "a,b.tgz" /var, /etc'
