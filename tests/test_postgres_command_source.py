"""Tests for the command-source abstraction and the PostgreSQL source.

The PostgreSQL source is exercised with a fake connection/cursor so the tests
need no live database. They assert it issues *parameterized* SQL (values passed
separately, never string-interpolated) and fails clearly on connection problems
and insufficient inventory.
"""

import pytest

from attackgen.config import DbConfig
from attackgen.models import CommandRow
from attackgen.postgres_command_source import (
    CommandSourceError,
    InMemoryCommandSource,
    InsufficientCommandsError,
    PostgresCommandSource,
)


def make_rows():
    rows = []
    for i in range(10):
        rows.append(
            CommandRow(
                process_name="bash",
                command_line=f"backup-job --id {i}",
                label="benign",
                category="backup",
                os_profile="linux",
                scenario_tags=["ransomware"] if i % 2 == 0 else [],
                id=i,
            )
        )
    rows.append(
        CommandRow(
            process_name="openssl",
            command_line="openssl enc -aes-256-cbc -in /data -out /data.enc",
            label="malicious",
            category="impact",
            os_profile="linux",
            id=99,
        )
    )
    return rows


# --- InMemoryCommandSource --------------------------------------------------

def test_in_memory_fetch_filters_by_label_category_os():
    src = InMemoryCommandSource(make_rows())
    rows = src.fetch(label="benign", category="backup", os_profile="linux", count=3)
    assert len(rows) == 3
    assert all(r.label == "benign" and r.category == "backup" for r in rows)
    assert all(r.os_profile == "linux" for r in rows)


def test_in_memory_fetch_is_deterministic_with_seed():
    src = InMemoryCommandSource(make_rows())
    a = src.fetch(label="benign", category="backup", os_profile="linux", count=4, seed=42)
    b = src.fetch(label="benign", category="backup", os_profile="linux", count=4, seed=42)
    assert [r.id for r in a] == [r.id for r in b]


def test_in_memory_fetch_no_duplicate_rows_without_replacement():
    src = InMemoryCommandSource(make_rows())
    rows = src.fetch(label="benign", category="backup", os_profile="linux", count=10, seed=1)
    ids = [r.id for r in rows]
    assert len(ids) == len(set(ids))


def test_in_memory_fetch_raises_when_insufficient():
    src = InMemoryCommandSource(make_rows())
    with pytest.raises(InsufficientCommandsError, match="backup"):
        src.fetch(label="benign", category="backup", os_profile="linux", count=999)


# --- PostgresCommandSource (fake connection) --------------------------------

class FakeCursor:
    def __init__(self, rows):
        self._rows = rows
        self.executed = []  # list of (sql, params)

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchall(self):
        return self._rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeConnection:
    def __init__(self, rows):
        self._cursor = FakeCursor(rows)

    def cursor(self):
        return self._cursor

    def close(self):
        pass


def pg_tuple(i, label="benign", category="backup", os_profile="linux"):
    # Column order: id, process_name, command_line, label, category,
    #               os_profile, scenario_tags, stealth_level, weight
    return (i, "bash", f"cmd {i}", label, category, os_profile, ["ransomware"], 1, 1.0)


def test_postgres_uses_parameterized_query_no_interpolation():
    rows = [pg_tuple(i) for i in range(5)]
    conn = FakeConnection(rows)
    src = PostgresCommandSource(DbConfig.from_url("postgresql://u:p@h:5432/d"),
                                connect=lambda cfg: conn)

    src.fetch(label="benign", category="backup", os_profile="linux", count=3, seed=7)

    sql, params = conn._cursor.executed[-1]
    # Values must travel as parameters, not be baked into the SQL string.
    assert "%s" in sql
    assert "backup" not in sql
    assert "benign" not in sql
    assert params[:3] == ("benign", "backup", "linux")


def test_postgres_returns_command_rows():
    rows = [pg_tuple(i) for i in range(5)]
    conn = FakeConnection(rows)
    src = PostgresCommandSource(DbConfig.from_url("postgresql://u:p@h:5432/d"),
                                connect=lambda cfg: conn)
    result = src.fetch(label="benign", category="backup", os_profile="linux", count=2, seed=1)
    assert len(result) == 2
    assert all(isinstance(r, CommandRow) for r in result)
    assert all(r.label == "benign" for r in result)


def test_postgres_raises_clear_error_when_insufficient_inventory():
    rows = [pg_tuple(i) for i in range(2)]
    conn = FakeConnection(rows)
    src = PostgresCommandSource(DbConfig.from_url("postgresql://u:p@h:5432/d"),
                                connect=lambda cfg: conn)
    with pytest.raises(InsufficientCommandsError, match="backup"):
        src.fetch(label="benign", category="backup", os_profile="linux", count=50)


def test_postgres_connection_failure_is_clear():
    def boom(cfg):
        raise OSError("connection refused")

    src = PostgresCommandSource(DbConfig.from_url("postgresql://u:p@h:5432/d"),
                                connect=boom)
    with pytest.raises(CommandSourceError, match="connect"):
        src.fetch(label="benign", category="backup", os_profile="linux", count=1)
