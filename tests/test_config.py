"""Tests for database configuration loading (no secrets in code)."""

import pytest

from attackgen.config import DbConfig, DbConfigError


def test_from_url_parses_components():
    cfg = DbConfig.from_url("postgresql://alice:s3cret@db.example:6543/attackgen")
    assert cfg.host == "db.example"
    assert cfg.port == 6543
    assert cfg.dbname == "attackgen"
    assert cfg.user == "alice"
    assert cfg.password == "s3cret"


def test_from_env_prefers_database_url():
    env = {"DATABASE_URL": "postgresql://u:p@h:5432/d"}
    cfg = DbConfig.from_env(env)
    assert cfg.host == "h"
    assert cfg.dbname == "d"


def test_from_env_uses_postgres_vars_when_no_url():
    env = {
        "POSTGRES_HOST": "localhost",
        "POSTGRES_PORT": "5432",
        "POSTGRES_DB": "attackgen",
        "POSTGRES_USER": "redteam",
        "POSTGRES_PASSWORD": "pw",
    }
    cfg = DbConfig.from_env(env)
    assert cfg.host == "localhost"
    assert cfg.user == "redteam"
    assert cfg.dbname == "attackgen"


def test_from_env_raises_when_nothing_configured():
    with pytest.raises(DbConfigError):
        DbConfig.from_env({})


def test_redacted_hides_password():
    cfg = DbConfig.from_url("postgresql://u:topsecret@h:5432/d")
    redacted = cfg.redacted()
    assert "topsecret" not in str(redacted)
    assert redacted["password"] == "***"
    assert redacted["host"] == "h"
    assert redacted["dbname"] == "d"
