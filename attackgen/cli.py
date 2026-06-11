"""Command-line entry point for the AttackGen dataset composer.

Usage::

    python -m attackgen.cli --request sample_request.json --output-dir outputs

PostgreSQL connection settings are read from ``DATABASE_URL`` or the
``POSTGRES_*`` environment variables, or passed with ``--database-url``. The CLI
loads the request, composes the dataset, writes the four output files, and prints
a concise success summary. It never executes any command line from the dataset.
"""

from __future__ import annotations

import argparse
import sys

from attackgen.composer import RequestValidationError, compose, load_request
from attackgen.config import DbConfig, DbConfigError
from attackgen.exporters import export_dataset
from attackgen.models import DatasetValidationError
from attackgen.postgres_command_source import (
    CommandPoolSource,
    CommandSourceError,
    PostgresCommandSource,
)


def _postgres_factory(request, args):
    """Default source factory: build a PostgreSQL-backed source from env/args.

    Selects :class:`CommandPoolSource` (the live ``command_pool`` table, keyed on
    ``attack_type``) when the request is in attack_type mode or ``--table
    command_pool`` is given; otherwise the original :class:`PostgresCommandSource`
    (the ``command_lines`` table).
    """
    if args.database_url:
        config = DbConfig.from_url(args.database_url)
    else:
        config = DbConfig.from_env()

    table = getattr(args, "table", None)
    use_pool = table == "command_pool" or (table is None and getattr(request, "attack_type", None))
    if use_pool:
        source = CommandPoolSource(config)
        source_info = {"type": "postgres", "table": "command_pool", **config.redacted()}
    else:
        source = PostgresCommandSource(config)
        source_info = {"type": "postgres", "table": "command_lines", **config.redacted()}
    return source, source_info


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attackgen",
        description="Compose a simulated process-command telemetry dataset (text only).",
    )
    parser.add_argument("--request", required=True, help="Path to the request JSON file.")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory (overrides output_dir in the request).",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="PostgreSQL URL (otherwise read from DATABASE_URL / POSTGRES_* env vars).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Seed for deterministic selection and blending (overrides request seed).",
    )
    parser.add_argument(
        "--table",
        choices=("command_pool", "command_lines"),
        default=None,
        help=(
            "Source table override. Defaults to command_pool for attack_type "
            "requests and command_lines otherwise."
        ),
    )
    return parser


def main(argv=None, source_factory=_postgres_factory) -> int:
    args = build_parser().parse_args(argv)

    try:
        request = load_request(args.request)
    except (OSError, ValueError, RequestValidationError) as exc:
        print(f"error: could not load request: {exc}", file=sys.stderr)
        return 2

    if args.seed is not None:
        request.seed = args.seed
    output_dir = args.output_dir or request.output_dir

    try:
        source, source_info = source_factory(request, args)
    except (DbConfigError, CommandSourceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    try:
        dataset = compose(request, source)
        paths = export_dataset(dataset, output_dir, source_info=source_info)
    except RequestValidationError as exc:
        print(f"error: invalid request — {exc}", file=sys.stderr)
        return 4
    except (DatasetValidationError, CommandSourceError) as exc:
        print(f"error: dataset composition failed — {exc}", file=sys.stderr)
        return 5
    finally:
        source.close()

    benign = sum(1 for r in dataset.rows if r.label == "benign")
    malicious = sum(1 for r in dataset.rows if r.label == "malicious")
    print("AttackGen dataset composed successfully.")
    print(f"  scenario:    {dataset.request.scenario}")
    print(f"  os_profile:  {dataset.request.os_profile}")
    print(f"  total rows:  {len(dataset.rows)}")
    print(f"  benign:      {benign}")
    print(f"  malicious:   {malicious}")
    print(f"  seed:        {dataset.seed}")
    print(f"  output dir:  {output_dir}")
    print("  files:")
    for key, path in paths.items():
        print(f"    - {path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
