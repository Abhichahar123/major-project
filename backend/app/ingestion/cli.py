"""Command-line entry point: ``python -m app.ingestion <command>``.

Examples::

    python -m app.ingestion seed                       # bounded demo dataset
    python -m app.ingestion sync kev
    python -m app.ingestion sync cve5 --mode from_kev --limit 500
    python -m app.ingestion sync cve5 --mode ids --ids CVE-2021-44228 CVE-2023-30861
    python -m app.ingestion sync cve5 --mode delta     # incremental refresh
    python -m app.ingestion sync nvd --mode ids --ids CVE-2021-44228
    python -m app.ingestion sync attack
    python -m app.ingestion jobs
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from app.core.config import load_settings
from app.core.logging import configure_logging
from app.ingestion.demo_dataset import DEFAULT_KEV_CVE_LIMIT, PACKAGE_DEMO_CVES
from app.ingestion.jobs import JobConflictError, latest_jobs, run_now
from app.ingestion.runtime import make_http_client, make_ingestion_engine, make_session_factory
from app.ingestion.sources import ParamError, get_adapter


def _params(args: argparse.Namespace) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for name in ("mode", "ids", "limit", "modified_since", "max_new", "since_hours"):
        value = getattr(args, name, None)
        if value is not None:
            params[name] = value
    if getattr(args, "include_new", False):
        params["include_new"] = True
    if getattr(args, "all_cves", False):
        params["only_tracked"] = False
    return params


def _print_job(job: Any) -> None:
    print(
        f"job {job.id}: {job.status} fetched={job.records_fetched} "
        f"inserted={job.records_inserted} updated={job.records_updated} "
        f"unchanged={job.records_unchanged} failed={job.records_failed}"
        + (f" - {job.error_summary}" if job.error_summary else "")
    )
    if job.details:
        print("  details:", json.dumps(job.details, default=str)[:500])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.ingestion")
    sub = parser.add_subparsers(dest="command", required=True)

    sync = sub.add_parser("sync", help="run one source")
    sync.add_argument("source", choices=["kev", "cve5", "nvd", "attack", "capec", "embeddings"])
    sync.add_argument("--mode")
    sync.add_argument("--ids", nargs="+")
    sync.add_argument("--limit", type=int)
    sync.add_argument("--modified-since", dest="modified_since")
    sync.add_argument("--include-new", action="store_true")
    sync.add_argument("--max-new", dest="max_new", type=int)
    sync.add_argument("--since-hours", dest="since_hours", type=int)
    sync.add_argument("--all-cves", action="store_true", help="nvd: also store untracked CVEs")

    seed = sub.add_parser("seed", help="load the bounded demo dataset")
    seed.add_argument("--kev-limit", type=int, default=DEFAULT_KEV_CVE_LIMIT)
    seed.add_argument("--skip-attack", action="store_true")
    seed.add_argument("--skip-embeddings", action="store_true")

    jobs = sub.add_parser("jobs", help="list recent jobs")
    jobs.add_argument("--limit", type=int, default=20)

    args = parser.parse_args(argv)
    settings = load_settings()
    configure_logging(settings)
    engine = make_ingestion_engine(settings)
    session_factory = make_session_factory(engine)

    def run(source: str, params: dict[str, Any]) -> bool:
        try:
            job = run_now(
                get_adapter(source),
                params,
                settings,
                session_factory,
                lambda: make_http_client(settings),
                trigger="cli",
            )
        except (ParamError, JobConflictError) as exc:
            print(f"{source}: {exc}", file=sys.stderr)
            return False
        _print_job(job)
        return job.status in {"succeeded", "partial"}

    try:
        if args.command == "jobs":
            with session_factory() as session:
                for job in latest_jobs(session, args.limit):
                    _print_job(job)
            return 0
        if args.command == "sync":
            return 0 if run(args.source, _params(args)) else 1

        ok = run("kev", {})
        ok &= run("capec", {})
        if not args.skip_attack:
            ok &= run("attack", {})
        ok &= run("cve5", {"mode": "from_kev", "limit": args.kev_limit})
        ok &= run("cve5", {"mode": "ids", "ids": PACKAGE_DEMO_CVES})
        if not args.skip_embeddings and "embeddings" in _available_sources():
            ok &= run("embeddings", {})
        return 0 if ok else 1
    finally:
        engine.dispose()


def _available_sources() -> set[str]:
    from app.ingestion.sources import ADAPTERS

    return set(ADAPTERS)


if __name__ == "__main__":
    raise SystemExit(main())
