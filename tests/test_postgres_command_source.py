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
    CommandPoolSource,
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


# --- CommandPoolSource (live command_pool table, fake connection) -----------

def pool_tuple(i, label="malicious", attack_type="ransomware"):
    # command_pool column order: id, process_name, command_line, label, attack_type
    return (i, "reg.exe", f"reg save HKLM\\SAM out{i}", label, attack_type)


def test_command_pool_uses_parameterized_random_query():
    rows = [pool_tuple(i) for i in range(20)]
    conn = FakeConnection(rows)
    src = CommandPoolSource(DbConfig.from_url("postgresql://u:p@h:5432/d"),
                            connect=lambda cfg: conn)

    src.fetch(label="malicious", category="ransomware", os_profile="linux", count=20)

    sql, params = conn._cursor.executed[-1]
    assert "%s" in sql
    assert "command_pool" in sql
    assert "ORDER BY RANDOM()" in sql
    assert "LIMIT %s" in sql
    # Values travel as parameters, never baked into the SQL string.
    assert "ransomware" not in sql
    assert "malicious" not in sql
    assert params == ("malicious", "ransomware", 20)


def test_command_pool_maps_attack_type_to_category():
    rows = [pool_tuple(i, label="benign", attack_type="reverse_shell") for i in range(5)]
    conn = FakeConnection(rows)
    src = CommandPoolSource(DbConfig.from_url("postgresql://u:p@h:5432/d"),
                            connect=lambda cfg: conn)

    result = src.fetch(label="benign", category="reverse_shell", os_profile="linux", count=5)

    assert len(result) == 5
    assert all(isinstance(r, CommandRow) for r in result)
    assert all(r.category == "reverse_shell" and r.label == "benign" for r in result)
    assert all(r.os_profile == "linux" for r in result)


def test_command_pool_seed_calls_setseed_in_range():
    rows = [pool_tuple(i) for i in range(20)]
    conn = FakeConnection(rows)
    src = CommandPoolSource(DbConfig.from_url("postgresql://u:p@h:5432/d"),
                            connect=lambda cfg: conn)

    src.fetch(label="malicious", category="ransomware", os_profile="linux", count=20, seed=42)

    first_sql, first_params = conn._cursor.executed[0]
    assert "setseed" in first_sql
    assert -1.0 <= first_params[0] <= 1.0


def test_command_pool_insufficient_inventory_raises():
    rows = [pool_tuple(i) for i in range(3)]
    conn = FakeConnection(rows)
    src = CommandPoolSource(DbConfig.from_url("postgresql://u:p@h:5432/d"),
                            connect=lambda cfg: conn)
    with pytest.raises(InsufficientCommandsError, match="ransomware"):
        src.fetch(label="malicious", category="ransomware", os_profile="linux", count=20)
