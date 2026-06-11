"""Database connection configuration.

Credentials come from the environment (``DATABASE_URL`` or ``POSTGRES_*``), never
from source code. ``redacted()`` produces a secret-free view suitable for logging
and for the run summary.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import unquote, urlparse


class DbConfigError(Exception):
    """Raised when database configuration is missing or malformed."""


@dataclass
class DbConfig:
    host: str
    port: int
    dbname: str
    user: str
    password: str

    @classmethod
    def from_url(cls, url: str) -> "DbConfig":
        parsed = urlparse(url)
        if parsed.scheme not in ("postgres", "postgresql"):
            raise DbConfigError(
                f"unsupported database URL scheme: {parsed.scheme!r} (expected postgresql)"
            )
        if not parsed.hostname or not (parsed.path or "").strip("/"):
            raise DbConfigError("database URL must include a host and database name")
        return cls(
            host=parsed.hostname,
            port=parsed.port or 5432,
            dbname=parsed.path.lstrip("/"),
            user=unquote(parsed.username or ""),
            password=unquote(parsed.password or ""),
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "DbConfig":
        env = os.environ if env is None else env
        url = env.get("DATABASE_URL")
        if url:
            return cls.from_url(url)

        required = ("POSTGRES_HOST", "POSTGRES_DB", "POSTGRES_USER")
        missing = [k for k in required if not env.get(k)]
        if missing:
            raise DbConfigError(
                "no database configuration found. Set DATABASE_URL, or set "
                f"POSTGRES_HOST/POSTGRES_DB/POSTGRES_USER (missing: {', '.join(missing)})."
            )
        return cls(
            host=env["POSTGRES_HOST"],
            port=int(env.get("POSTGRES_PORT", "5432")),
            dbname=env["POSTGRES_DB"],
            user=env["POSTGRES_USER"],
            password=env.get("POSTGRES_PASSWORD", ""),
        )

    def to_psycopg_kwargs(self) -> dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "dbname": self.dbname,
            "user": self.user,
            "password": self.password,
        }

    def redacted(self) -> dict[str, object]:
        """A secret-free view safe for logs and the run summary."""
        return {
            "host": self.host,
            "port": self.port,
            "dbname": self.dbname,
            "user": self.user,
            "password": "***" if self.password else "",
        }
