"""Command-source abstraction and a PostgreSQL-backed implementation.

A ``CommandSource`` returns simulated process-command rows (``CommandRow``) to the
composer. Two implementations are provided:

* ``InMemoryCommandSource`` — used by tests and offline/demo runs.
* ``PostgresCommandSource`` — pulls rows from the ``command_lines`` table using
  parameterized SQL only. Credentials come from configuration, never code.
* ``CommandPoolSource`` — pulls rows from the live ``command_pool`` table keyed on
  ``attack_type``, selecting a fresh draw per run with ``ORDER BY RANDOM()``.

For ``PostgresCommandSource`` selection is performed in Python with a seeded RNG so
that, given a seed, the chosen rows are deterministic regardless of database row
ordering. ``CommandPoolSource`` selects in SQL (``ORDER BY RANDOM() LIMIT n``) for a
fresh variant each run, made reproducible by ``setseed`` when a seed is supplied.
Rows are treated strictly as text; nothing here executes a command line.
"""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from typing import Callable, Iterable, Sequence

from attackgen.config import DbConfig
from attackgen.models import CommandRow


class CommandSourceError(Exception):
    """Raised for connection or query failures in a command source."""


class InsufficientCommandsError(CommandSourceError):
    """Raised when a category does not have enough matching commands."""


# Column order used by the PostgreSQL table and the SELECT statement.
_COLUMNS = (
    "id",
    "process_name",
    "command_line",
    "label",
    "category",
    "os_profile",
    "scenario_tags",
    "stealth_level",
    "weight",
)


def _select_rows(
    candidates: Sequence[CommandRow],
    count: int,
    *,
    seed: int | None,
    scenario_tags: Iterable[str] | None,
    allow_replacement: bool,
    salt: str,
) -> list[CommandRow]:
    """Deterministically pick ``count`` rows from ``candidates``.

    Rows whose ``scenario_tags`` overlap the requested tags are preferred. With a
    seed, the choice is reproducible; the salt keeps different (label, category)
    requests from drawing identical orderings.
    """
    rng = random.Random(f"{seed}:{salt}") if seed is not None else random.Random()

    tag_set = set(scenario_tags or [])
    preferred = [r for r in candidates if tag_set and (set(r.scenario_tags) & tag_set)]
    others = [r for r in candidates if r not in preferred]
    rng.shuffle(preferred)
    rng.shuffle(others)
    ordered = preferred + others

    if allow_replacement:
        if not ordered:
            raise InsufficientCommandsError("no candidate commands to sample from")
        return rng.choices(ordered, k=count)

    if len(ordered) < count:
        raise InsufficientCommandsError(
            f"category {ordered[0].category if ordered else '?'!r} has "
            f"{len(ordered)} matching commands but {count} were requested"
        )
    return ordered[:count]


class CommandSource(ABC):
    """Abstract source of simulated command-telemetry rows."""

    @abstractmethod
    def fetch(
        self,
        *,
        label: str,
        category: str,
        os_profile: str,
        count: int,
        scenario_tags: Iterable[str] | None = None,
        seed: int | None = None,
        allow_replacement: bool = False,
    ) -> list[CommandRow]:
        """Return ``count`` rows matching the given label/category/os_profile."""

    def close(self) -> None:  # pragma: no cover - default no-op
        pass


class InMemoryCommandSource(CommandSource):
    """In-memory command source backed by a list of ``CommandRow`` objects."""

    def __init__(self, rows: Sequence[CommandRow]):
        self._rows = list(rows)

    def fetch(
        self,
        *,
        label,
        category,
        os_profile,
        count,
        scenario_tags=None,
        seed=None,
        allow_replacement=False,
    ) -> list[CommandRow]:
        candidates = [
            r
            for r in self._rows
            if r.label == label
            and r.category == category
            and r.os_profile == os_profile
        ]
        if not candidates and not allow_replacement:
            raise InsufficientCommandsError(
                f"category {category!r} ({label}, {os_profile}) has no matching commands"
            )
        return _select_rows(
            candidates,
            count,
            seed=seed,
            scenario_tags=scenario_tags,
            allow_replacement=allow_replacement,
            salt=f"{label}:{category}:{os_profile}",
        )


class PostgresCommandSource(CommandSource):
    """PostgreSQL-backed command source. Uses parameterized SQL exclusively."""

    TABLE = "command_lines"

    def __init__(
        self,
        config: DbConfig,
        connect: Callable[[DbConfig], object] | None = None,
    ):
        self._config = config
        self._connect = connect or self._default_connect
        self._conn = None

    @staticmethod
    def _default_connect(config: DbConfig):
        import psycopg  # imported lazily so tests/offline use need no driver

        return psycopg.connect(**config.to_psycopg_kwargs())

    def connect(self):
        if self._conn is None:
            try:
                self._conn = self._connect(self._config)
            except Exception as exc:  # noqa: BLE001 - surface a clear message
                raise CommandSourceError(
                    f"could not connect to PostgreSQL at "
                    f"{self._config.host}:{self._config.port}/{self._config.dbname}: {exc}"
                ) from exc
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def _build_query(self, scenario_tags: Iterable[str] | None):
        columns = ", ".join(_COLUMNS)
        sql = (
            f"SELECT {columns} FROM {self.TABLE} "
            f"WHERE label = %s AND category = %s AND os_profile = %s"
        )
        if scenario_tags:
            sql += " AND scenario_tags && %s"
        sql += " ORDER BY id"
        return sql

    @staticmethod
    def _to_row(record: Sequence) -> CommandRow:
        data = dict(zip(_COLUMNS, record))
        return CommandRow(
            id=data.get("id"),
            process_name=data["process_name"],
            command_line=data["command_line"],
            label=data["label"],
            category=data["category"],
            os_profile=data["os_profile"],
            scenario_tags=list(data.get("scenario_tags") or []),
            stealth_level=data.get("stealth_level"),
            weight=data.get("weight"),
        )

    def fetch(
        self,
        *,
        label,
        category,
        os_profile,
        count,
        scenario_tags=None,
        seed=None,
        allow_replacement=False,
    ) -> list[CommandRow]:
        conn = self.connect()
        tags = list(scenario_tags or [])
        sql = self._build_query(tags)
        params: list[object] = [label, category, os_profile]
        if tags:
            params.append(tags)

        try:
            with conn.cursor() as cur:
                cur.execute(sql, tuple(params))
                records = cur.fetchall()
        except Exception as exc:  # noqa: BLE001
            raise CommandSourceError(
                f"query failed for category {category!r} ({label}, {os_profile}): {exc}"
            ) from exc

        candidates = [self._to_row(r) for r in records]
        if len(candidates) < count and not allow_replacement:
            raise InsufficientCommandsError(
                f"category {category!r} ({label}, {os_profile}) has "
                f"{len(candidates)} commands in PostgreSQL but {count} were requested"
            )
        return _select_rows(
            candidates,
            count,
            seed=seed,
            scenario_tags=tags,
            allow_replacement=allow_replacement,
            salt=f"{label}:{category}:{os_profile}",
        )


class CommandPoolSource(PostgresCommandSource):
    """PostgreSQL source backed by the live ``command_pool`` table.

    ``command_pool`` has the flat schema ``(id, process_name, command_line, label,
    attack_type)``. The composer calls :meth:`fetch` with the ``category`` argument
    carrying the requested ``attack_type``; selection happens in SQL via
    ``ORDER BY RANDOM() LIMIT count`` so each run produces a fresh challenge variant.
    Passing a ``seed`` calls ``setseed`` first to make the draw reproducible.
    Parameterized SQL only; ``os_profile``/``scenario_tags`` are not columns here and
    are not used for filtering.
    """

    TABLE = "command_pool"
    _POOL_COLUMNS = ("id", "process_name", "command_line", "label", "attack_type")

    @staticmethod
    def _normalize_seed(seed: int) -> float:
        # ``setseed`` requires a double in [-1, 1]; map any int there, stably.
        return ((int(seed) % 1999) - 999) / 1000.0

    def _pool_to_row(self, record: Sequence, *, os_profile: str | None) -> CommandRow:
        data = dict(zip(self._POOL_COLUMNS, record))
        return CommandRow(
            id=data.get("id"),
            process_name=data["process_name"],
            command_line=data["command_line"],
            label=data["label"],
            category=data["attack_type"],  # attack_type is the selection key here
            os_profile=os_profile or "linux",
            scenario_tags=[],
        )

    def fetch(
        self,
        *,
        label,
        category,
        os_profile,
        count,
        scenario_tags=None,
        seed=None,
        allow_replacement=False,
    ) -> list[CommandRow]:
        attack_type = category  # composer passes the attack_type as ``category``
        conn = self.connect()
        columns = ", ".join(self._POOL_COLUMNS)
        sql = (
            f"SELECT {columns} FROM {self.TABLE} "
            f"WHERE label = %s AND attack_type = %s "
            f"ORDER BY RANDOM() LIMIT %s"
        )
        params = (label, attack_type, count)

        try:
            with conn.cursor() as cur:
                if seed is not None:
                    cur.execute("SELECT setseed(%s)", (self._normalize_seed(seed),))
                cur.execute(sql, params)
                records = cur.fetchall()
        except Exception as exc:  # noqa: BLE001
            raise CommandSourceError(
                f"query failed for attack_type {attack_type!r} ({label}): {exc}"
            ) from exc

        rows = [self._pool_to_row(r, os_profile=os_profile) for r in records]
        if len(rows) < count and not allow_replacement:
            raise InsufficientCommandsError(
                f"attack_type {attack_type!r} ({label}) has {len(rows)} commands "
                f"in {self.TABLE} but {count} were requested"
            )
        return rows
