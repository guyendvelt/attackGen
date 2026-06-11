"""Shared data model and validation rules for the AttackGen composer.

Everything here is text-only telemetry. A ``CommandRow`` is a row of simulated
process-command data. Nothing in this project executes, spawns, or shells out to
any command line it carries — command lines are inert strings.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --- Challenge requirements (strict) ---------------------------------------
BENIGN_TOTAL = 200
MALICIOUS_TOTAL = 20
TOTAL_ROWS = BENIGN_TOTAL + MALICIOUS_TOTAL  # 220

LABELED_COLUMNS = ["process_name", "command_line", "label"]
UNLABELED_COLUMNS = ["process_name", "command_line"]
VALID_LABELS = {"benign", "malicious"}


class DatasetValidationError(Exception):
    """Raised when a row or dataset violates the challenge requirements."""


@dataclass
class CommandRow:
    """A single simulated process-command telemetry row.

    Only ``process_name``, ``command_line`` and ``label`` are ever exported.
    The remaining fields are internal metadata used to select and compose the
    dataset; they are stripped before any CSV is written.
    """

    process_name: str
    command_line: str
    label: str
    category: str
    os_profile: str
    scenario_tags: list[str] = field(default_factory=list)
    stealth_level: int | None = None
    weight: float | None = None
    id: int | None = None

    def to_export_dict(self) -> dict[str, str]:
        """Return only the three exported, labeled columns."""
        return {
            "process_name": self.process_name,
            "command_line": self.command_line,
            "label": self.label,
        }

    def to_unlabeled_dict(self) -> dict[str, str]:
        """Return only the two exported columns, without the label."""
        return {
            "process_name": self.process_name,
            "command_line": self.command_line,
        }


def validate_row(row: CommandRow) -> None:
    """Validate a single row, raising ``DatasetValidationError`` on any problem."""
    if not (row.process_name or "").strip():
        raise DatasetValidationError(f"row is missing process_name: {row!r}")
    if not (row.command_line or "").strip():
        raise DatasetValidationError(f"row is missing command_line: {row!r}")
    if row.label not in VALID_LABELS:
        raise DatasetValidationError(
            f"invalid label {row.label!r}; must be one of {sorted(VALID_LABELS)}"
        )
