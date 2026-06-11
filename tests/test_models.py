"""Tests for the shared command data model and validation helpers."""

import pytest

from attackgen import models
from attackgen.models import CommandRow, DatasetValidationError, validate_row


def test_constants_match_challenge_requirements():
    assert models.BENIGN_TOTAL == 200
    assert models.MALICIOUS_TOTAL == 20
    assert models.TOTAL_ROWS == 220
    assert models.LABELED_COLUMNS == ["process_name", "command_line", "label"]
    assert models.UNLABELED_COLUMNS == ["process_name", "command_line"]
    assert models.VALID_LABELS == {"benign", "malicious"}


def test_command_row_export_dict_only_has_export_columns():
    row = CommandRow(
        process_name="bash",
        command_line="tar -czf /backup/app.tgz /var/www",
        label="benign",
        category="backup",
        os_profile="linux",
        scenario_tags=["ransomware"],
        stealth_level=2,
        weight=1.0,
        id=7,
    )
    assert row.to_export_dict() == {
        "process_name": "bash",
        "command_line": "tar -czf /backup/app.tgz /var/www",
        "label": "benign",
    }
    assert row.to_unlabeled_dict() == {
        "process_name": "bash",
        "command_line": "tar -czf /backup/app.tgz /var/www",
    }


def test_validate_row_accepts_valid_row():
    row = CommandRow(
        process_name="cron",
        command_line="run-parts /etc/cron.daily",
        label="benign",
        category="persistence",
        os_profile="linux",
    )
    validate_row(row)  # should not raise


def test_validate_row_rejects_missing_process_name():
    row = CommandRow(
        process_name="   ",
        command_line="something",
        label="benign",
        category="logs",
        os_profile="linux",
    )
    with pytest.raises(DatasetValidationError, match="process_name"):
        validate_row(row)


def test_validate_row_rejects_missing_command_line():
    row = CommandRow(
        process_name="bash",
        command_line="",
        label="benign",
        category="logs",
        os_profile="linux",
    )
    with pytest.raises(DatasetValidationError, match="command_line"):
        validate_row(row)


def test_validate_row_rejects_invalid_label():
    row = CommandRow(
        process_name="bash",
        command_line="echo hi",
        label="suspicious",
        category="logs",
        os_profile="linux",
    )
    with pytest.raises(DatasetValidationError, match="label"):
        validate_row(row)
