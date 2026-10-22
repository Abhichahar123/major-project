"""Source adapters: CISA KEV, CVE Program records, NVD, MITRE ATT&CK and CAPEC.

Each adapter validates its parameters (so the admin API cannot pass arbitrary values),
fetches from the configured URLs only, and writes through ``app.ingestion.store``.
Records are written one savepoint at a time in batches, so one bad record cannot abort
the batch.
"""

from __future__ import annotations

import json
import logging
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar, TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import KevEntry, Vulnerability
from app.ingestion.http import SourceError, SourceNotFoundError
from app.ingestion.jobs import Adapter, JobContext
from app.ingestion.normalize import (
    CVE_ID_RE,
    SUPPORTED_ECOSYSTEMS,
    RecordError,
    attack_version,
    content_hash,
    cve5_record_path,
    normalize_cve_id,
    parse_attack_technique,
    parse_capec_pattern,
    parse_cve5,
    parse_datetime,
    parse_kev_catalog,
    parse_kev_entry,
    parse_nvd,
    parse_osv,
    stix_objects,
)
from app.ingestion.store import (
    Change,
    delete_advisory,
    record_seen,
    remove_kev_entries_not_in,
    upsert_advisory,
    upsert_capec,
    upsert_kev,
    upsert_technique,
    upsert_vulnerability,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")
BATCH_SIZE = 200
MAX_IDS = 5000


class ParamError(ValueError):
    """Invalid job parameters."""


def _int_param(params: dict[str, Any], name: str, default: int, lo: int, hi: int) -> int:
    value = params.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise ParamError(f"{name} must be an integer between {lo} and {hi}")
    return value


def _bool_param(params: dict[str, Any], name: str, default: bool) -> bool:
    value = params.get(name, default)
    if not isinstance(value, bool):
        raise ParamError(f"{name} must be true or false")
    return value


def _ids_param(params: dict[str, Any], limit: int = MAX_IDS) -> list[str]:
    ids = params.get("ids")
    if not isinstance(ids, list) or not ids:
        raise ParamError("ids must be a non-empty list of CVE IDs")
    if len(ids) > limit:
        raise ParamError(f"at most {limit} ids per job")
    try:
        return list(dict.fromkeys(normalize_cve_id(i) for i in ids))
    except RecordError as exc:
        raise ParamError(str(exc)) from None


def _reject_unknown(params: dict[str, Any], allowed: set[str]) -> None:
    unknown = set(params) - allowed
    if unknown:
        raise ParamError(f"unknown parameter(s): {', '.join(sorted(unknown))}")


def _batches(items: Iterable[T], size: int = BATCH_SIZE) -> Iterator[list[T]]:
    batch: list[T] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def _write_batches(
    ctx: JobContext,
    items: Iterable[T],
    key: Callable[[T], str],
    write: Callable[[Session, T], Change],
) -> None:
    """Write each item in its own savepoint; commit per batch and publish progress."""
    for batch in _batches(items):
        with ctx.session_factory.begin() as session:
            for item in batch:
                record_key = key(item)
                try:
                    with session.begin_nested():
                        ctx.count(write(session, item))
                except RecordError as exc:
                    ctx.fail(record_key, "normalize", str(exc))
                except Exception as exc:  # database constraint or unexpected data
                    ctx.fail(record_key, "store", f"{type(exc).__name__}: {exc}")
        ctx.flush_progress()


# --------------------------------------------------------------------------- KEV


class KevAdapter:
    code = "kev"

    def validate_params(self, params: dict[str, Any]) -> dict[str, Any]:
        _reject_unknown(params, set())
        return {}

    def run(self, ctx: JobContext) -> None:
        catalog: Any = None
        errors: list[str] = []
        for url in ctx.settings.kev_feed_urls:
            try:
                catalog = ctx.http.get_json(url)
                ctx.details["feed_url"] = url
                break
            except SourceError as exc:
                errors.append(str(exc))
                logger.warning("KEV feed unavailable, trying next", extra={"reason": str(exc)})
        if catalog is None:
            raise SourceError("all KEV feeds failed: " + "; ".join(errors))

        version, entries = parse_kev_catalog(catalog)
        ctx.fetched = len(entries)
        ctx.details["catalog_version"] = version
        seen_ids: set[str] = set()

        def key(item: Any) -> str:
            return str(item.get("cveID", "?"))[:40] if isinstance(item, dict) else "?"

        def write(session: Session, item: Any) -> Change:
            kev = parse_kev_entry(item)
            seen_ids.add(kev.cve_id)
            changed = record_seen(
                session,
                source_id=ctx.source_id,
                record_key=kev.cve_id,
                digest=content_hash(kev.raw),
                job_id=ctx.job_id,
                source_url=ctx.details["feed_url"],
            )
            if not changed and session.get(KevEntry, kev.cve_id) is not None:
                return Change.UNCHANGED
            return upsert_kev(session, kev, version)

        _write_batches(ctx, entries, key, write)

        # Mirror removals only when the whole catalog was understood.
        if ctx.failed == 0 and seen_ids:
            with ctx.session_factory.begin() as session:
                removed = remove_kev_entries_not_in(session, seen_ids)
            ctx.details["removed"] = len(removed)
            ctx.details["removed_ids"] = removed[:50]


# ------------------------------------------------------------- CVE Program (CVE 5)


class Cve5Adapter:
    """Fetch CVE JSON 5 records from the CVEProject/cvelistV5 repository.

    Modes:
      ``ids``      the given CVE IDs
      ``from_kev`` the most recently added KEV entries (``limit``)
      ``tracked``  every CVE already stored (refresh)
      ``delta``    CVEs changed since the last run according to ``deltaLog.json``;
                   only tracked CVEs unless ``include_new`` (bounded by ``max_new``)
    """

    code = "cve5"
    modes: ClassVar[frozenset[str]] = frozenset({"ids", "from_kev", "tracked", "delta"})

    def validate_params(self, params: dict[str, Any]) -> dict[str, Any]:
        _reject_unknown(params, {"mode", "ids", "limit", "include_new", "max_new", "since_hours"})
        mode = params.get("mode", "from_kev")
        if mode not in self.modes:
            raise ParamError(f"mode must be one of {sorted(self.modes)}")
        out: dict[str, Any] = {"mode": mode}
        if mode == "ids":
            out["ids"] = _ids_param(params)
        elif mode == "from_kev":
            out["limit"] = _int_param(params, "limit", 300, 1, MAX_IDS)
        elif mode == "delta":
            out["include_new"] = _bool_param(params, "include_new", False)
            out["max_new"] = _int_param(params, "max_new", 100, 0, 1000)
            out["since_hours"] = _int_param(params, "since_hours", 24, 1, 24 * 30)
        return out

    def _target_ids(self, ctx: JobContext) -> list[str]:
        mode = ctx.params["mode"]
        if mode == "ids":
            return list(ctx.params["ids"])
        with ctx.session_factory() as session:
            if mode == "from_kev":
                return list(
                    session.scalars(
                        select(KevEntry.cve_id)
                        .order_by(KevEntry.date_added.desc(), KevEntry.cve_id)
                        .limit(ctx.params["limit"])
                    )
                )
            tracked = set(session.scalars(select(Vulnerability.cve_id)))
        if mode == "tracked":
            return sorted(tracked)
        return self._delta_ids(ctx, tracked)

    def _delta_ids(self, ctx: JobContext, tracked: set[str]) -> list[str]:
        log = ctx.http.get_json(f"{ctx.settings.cve5_base_url}/deltaLog.json")
        if not isinstance(log, list):
            raise SourceError("deltaLog.json is not a list")
        if ctx.watermark and ctx.watermark.get("fetch_time"):
            since = parse_datetime(ctx.watermark["fetch_time"])
        else:
            since = datetime.now(UTC) - timedelta(hours=ctx.params["since_hours"])
        newest: datetime | None = None
        changed: dict[str, None] = {}
        new_ids: dict[str, None] = {}
        for entry in log:
            fetched = parse_datetime((entry or {}).get("fetchTime"))
            if fetched is None or (since and fetched <= since):
                continue
            newest = max(newest, fetched) if newest else fetched
            for bucket in ("new", "updated"):
                for item in entry.get(bucket, []) or []:
                    cve_id = str((item or {}).get("cveId", ""))
                    if not CVE_ID_RE.match(cve_id):
                        continue
                    if cve_id in tracked:
                        changed[cve_id] = None
                    elif ctx.params["include_new"]:
                        new_ids[cve_id] = None
        selected = list(changed) + list(new_ids)[: ctx.params["max_new"]]
        ctx.details["delta_since"] = since.isoformat() if since else None
        ctx.details["delta_new_skipped"] = max(0, len(new_ids) - ctx.params["max_new"])
        if newest:
            ctx.new_watermark = {"fetch_time": newest.isoformat()}
        elif ctx.watermark:
            ctx.new_watermark = ctx.watermark
        return selected

    def _fetch(self, ctx: JobContext, cve_id: str) -> tuple[str, Any, str | None]:
        url = f"{ctx.settings.cve5_base_url}/{cve5_record_path(cve_id)}"
        try:
            return cve_id, ctx.http.get_json(url, max_bytes=5 * 1024 * 1024), url
        except SourceNotFoundError:
            return cve_id, SourceNotFoundError(f"{cve_id}: record not found"), url
        except SourceError as exc:
            return cve_id, exc, url

    def run(self, ctx: JobContext) -> None:
        ids = self._target_ids(ctx)
        ctx.details["requested"] = len(ids)
        if not ids:
            return
        with ThreadPoolExecutor(max_workers=ctx.settings.ingestion_concurrency) as pool:
            results = pool.map(lambda cid: self._fetch(ctx, cid), ids)
            fetched: list[tuple[str, Any, str | None]] = []
            for cve_id, payload, url in results:
                if isinstance(payload, Exception):
                    ctx.fail(cve_id, "fetch", str(payload))
                else:
                    ctx.fetched += 1
                    fetched.append((cve_id, payload, url))

        def write(session: Session, item: tuple[str, Any, str | None]) -> Change:
            cve_id, record, url = item
            vuln = parse_cve5(record)
            if vuln.cve_id != cve_id:
                raise RecordError(f"{cve_id}: record contains {vuln.cve_id}")
            changed = record_seen(
                session,
                source_id=ctx.source_id,
                record_key=cve_id,
                digest=content_hash(record),
                job_id=ctx.job_id,
                source_url=url,
            )
            exists = session.scalar(select(Vulnerability.id).where(Vulnerability.cve_id == cve_id))
            if not changed and exists:
                return Change.UNCHANGED
            return upsert_vulnerability(session, vuln, "cve5")

        _write_batches(ctx, fetched, lambda item: item[0], write)


# --------------------------------------------------------------------------- NVD


class NvdAdapter:
    """NVD CVE API 2.0 enrichment (CVSS, CWE, CPE configurations).

    Modes: ``ids`` (at most 200, one request each) or ``modified`` (a lastModified window,
    split into the API's 120-day maximum, paginated). By default only CVEs already stored
    are written (``only_tracked``), which keeps the dataset bounded.
    """

    code = "nvd"
    page_size = 2000
    max_window_days = 120

    def __init__(self, sleep: Callable[[float], None] = time.sleep) -> None:
        self._sleep = sleep

    def validate_params(self, params: dict[str, Any]) -> dict[str, Any]:
        _reject_unknown(params, {"mode", "ids", "modified_since", "only_tracked"})
        mode = params.get("mode", "modified")
        out: dict[str, Any] = {
            "mode": mode,
            "only_tracked": _bool_param(params, "only_tracked", True),
        }
        if mode == "ids":
            out["ids"] = _ids_param(params, limit=200)
        elif mode == "modified":
            since = params.get("modified_since")
            if since is not None:
                parsed = parse_datetime(since) if isinstance(since, str) else None
                if parsed is None:
                    raise ParamError("modified_since must be an ISO 8601 datetime")
                out["modified_since"] = parsed.isoformat()
        else:
            raise ParamError("mode must be 'ids' or 'modified'")
        return out

    def _headers(self, ctx: JobContext) -> dict[str, str]:
        key = ctx.settings.nvd_api_key
        return {"apiKey": key.get_secret_value()} if key else {}

    def _delay(self, ctx: JobContext) -> float:
        # NVD guidance: about 5 requests per 30 s without a key, 50 with one.
        return 0.6 if ctx.settings.nvd_api_key else 6.0

    def _pages(self, ctx: JobContext) -> Iterator[list[Any]]:
        url = ctx.settings.nvd_api_url
        first = True
        if ctx.params["mode"] == "ids":
            for cve_id in ctx.params["ids"]:
                if not first:
                    self._sleep(self._delay(ctx))
                first = False
                data = ctx.http.get_json(url, params={"cveId": cve_id}, headers=self._headers(ctx))
                yield list((data or {}).get("vulnerabilities", []) or [])
            return

        end = datetime.now(UTC)
        since = ctx.params.get("modified_since")
        if since:
            start = datetime.fromisoformat(since)
        elif ctx.watermark and ctx.watermark.get("last_modified_end"):
            start = datetime.fromisoformat(ctx.watermark["last_modified_end"])
        else:
            start = end - timedelta(days=7)
        ctx.details["window"] = [start.isoformat(), end.isoformat()]
        window_start = start
        while window_start < end:
            window_end = min(end, window_start + timedelta(days=self.max_window_days))
            index = 0
            while True:
                if not first:
                    self._sleep(self._delay(ctx))
                first = False
                data = ctx.http.get_json(
                    url,
                    params={
                        "lastModStartDate": window_start.isoformat(timespec="milliseconds"),
                        "lastModEndDate": window_end.isoformat(timespec="milliseconds"),
                        "startIndex": index,
                        "resultsPerPage": self.page_size,
                    },
                    headers=self._headers(ctx),
                )
                items = list((data or {}).get("vulnerabilities", []) or [])
                yield items
                total = int((data or {}).get("totalResults", 0) or 0)
                index += len(items)
                if not items or index >= total:
                    break
            window_start = window_end
        ctx.new_watermark = {"last_modified_end": end.isoformat()}

    def run(self, ctx: JobContext) -> None:
        with ctx.session_factory() as session:
            tracked = set(session.scalars(select(Vulnerability.cve_id)))
        skipped = 0

        def key(item: Any) -> str:
            return str(((item or {}).get("cve") or {}).get("id", "?"))[:40]

        def write(session: Session, item: Any) -> Change:
            vuln = parse_nvd(item)
            changed = record_seen(
                session,
                source_id=ctx.source_id,
                record_key=vuln.cve_id,
                digest=content_hash(item),
                job_id=ctx.job_id,
                source_url=f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}",
            )
            if not changed:
                return Change.UNCHANGED
            return upsert_vulnerability(session, vuln, "nvd")

        for page in self._pages(ctx):
            ctx.fetched += len(page)
            selected = page
            if ctx.params["only_tracked"]:
                selected = [i for i in page if key(i) in tracked]
                skipped += len(page) - len(selected)
            _write_batches(ctx, selected, key, write)
        ctx.details["skipped_untracked"] = skipped


# ------------------------------------------------------------------ ATT&CK / CAPEC


class AttackAdapter:
    code = "attack"

    def validate_params(self, params: dict[str, Any]) -> dict[str, Any]:
        _reject_unknown(params, set())
        return {}

    def run(self, ctx: JobContext) -> None:
        bundle = ctx.http.get_json(ctx.settings.attack_stix_url)
        objects = stix_objects(bundle)
        version = attack_version(objects)
        ctx.details["attack_version"] = version
        patterns = [o for o in objects if o.get("type") == "attack-pattern"]
        ctx.fetched = len(patterns)

        # Technique IDs are unique in the table; prefer the active object over a revoked one.
        by_tid: dict[str, Any] = {}
        for obj in patterns:
            try:
                tech = parse_attack_technique(obj)
            except RecordError as exc:
                ctx.fail(str(obj.get("id", "?"))[:100], "normalize", str(exc))
                continue
            current = by_tid.get(tech.technique_id)
            if current is None or (current.revoked and not tech.revoked):
                by_tid[tech.technique_id] = tech
            else:
                ctx.unchanged += 1  # superseded duplicate

        def write(session: Session, tech: Any) -> Change:
            changed = record_seen(
                session,
                source_id=ctx.source_id,
                record_key=tech.stix_id,
                digest=content_hash(tech.raw),
                job_id=ctx.job_id,
                source_url=tech.url,
            )
            if not changed:
                return Change.UNCHANGED
            return upsert_technique(session, tech, version)

        _write_batches(ctx, list(by_tid.values()), lambda t: t.technique_id, write)


class CapecAdapter:
    code = "capec"

    def validate_params(self, params: dict[str, Any]) -> dict[str, Any]:
        _reject_unknown(params, set())
        return {}

    def run(self, ctx: JobContext) -> None:
        objects = stix_objects(ctx.http.get_json(ctx.settings.capec_stix_url))
        patterns = [o for o in objects if o.get("type") == "attack-pattern"]
        ctx.fetched = len(patterns)

        def write(session: Session, obj: Any) -> Change:
            pattern = parse_capec_pattern(obj)
            changed = record_seen(
                session,
                source_id=ctx.source_id,
                record_key=pattern.capec_id,
                digest=content_hash(obj),
                job_id=ctx.job_id,
                source_url=pattern.url,
            )
            if not changed:
                return Change.UNCHANGED
            return upsert_capec(session, pattern)

        _write_batches(ctx, patterns, lambda o: str(o.get("id", "?"))[:100], write)


# --------------------------------------------------------------------------- OSV


class OsvAdapter:
    """OSV advisories for one ecosystem from the official OSV data exports.

    ``full`` downloads ``<ecosystem>/all.zip``; ``incremental`` reads
    ``<ecosystem>/modified_id.csv`` and fetches only records modified since the last run
    (at most ``max_records``; beyond that a full run is required). ``MAL-`` records
    (malicious-package reports) are skipped: they describe malware, not vulnerabilities
    in legitimate package versions. Withdrawn advisories are deleted.
    """

    code = "osv"
    max_zip_bytes = 400 * 1024 * 1024
    max_member_bytes = 5 * 1024 * 1024
    max_total_uncompressed = 4 * 1024 * 1024 * 1024
    max_members = 1_000_000

    def validate_params(self, params: dict[str, Any]) -> dict[str, Any]:
        _reject_unknown(params, {"ecosystem", "mode", "max_records"})
        ecosystem = params.get("ecosystem", "PyPI")
        if ecosystem not in SUPPORTED_ECOSYSTEMS:
            raise ParamError(f"ecosystem must be one of {list(SUPPORTED_ECOSYSTEMS)}")
        mode = params.get("mode", "auto")
        if mode not in {"auto", "full", "incremental"}:
            raise ParamError("mode must be auto, full or incremental")
        return {
            "ecosystem": ecosystem,
            "mode": mode,
            "max_records": _int_param(params, "max_records", 2000, 1, 20_000),
        }

    def _records_from_zip(self, ctx: JobContext, ecosystem: str) -> Iterator[dict[str, Any]]:
        url = f"{ctx.settings.osv_data_base_url}/{ecosystem}/all.zip"
        with tempfile.TemporaryFile() as tmp:
            size = ctx.http.download(url, tmp, max_bytes=self.max_zip_bytes)
            ctx.details["download_bytes"] = size
            try:
                archive = zipfile.ZipFile(tmp)
            except zipfile.BadZipFile as exc:
                raise SourceError("OSV export is not a valid zip file") from exc
            with archive:
                members = archive.infolist()
                if len(members) > self.max_members:
                    raise SourceError("OSV export has too many members")
                total = 0
                for info in members:
                    name = info.filename
                    if info.is_dir() or not name.endswith(".json") or "/" in name:
                        continue
                    if name.startswith("MAL-"):
                        ctx.details["skipped_malware_reports"] = (
                            ctx.details.get("skipped_malware_reports", 0) + 1
                        )
                        continue
                    # Zip-bomb guards: per-member and cumulative uncompressed size.
                    total += info.file_size
                    if (
                        info.file_size > self.max_member_bytes
                        or total > self.max_total_uncompressed
                    ):
                        ctx.fail(name[:100], "fetch", "zip member too large; skipped")
                        continue
                    with archive.open(info) as handle:
                        data = handle.read(self.max_member_bytes + 1)
                    try:
                        yield json.loads(data)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        ctx.fail(name[:100], "normalize", "invalid JSON in OSV export")

    def _changed_ids(self, ctx: JobContext, ecosystem: str, since: datetime) -> list[str]:
        url = f"{ctx.settings.osv_data_base_url}/{ecosystem}/modified_id.csv"
        body = ctx.http.get_bytes(url, max_bytes=100 * 1024 * 1024).decode("utf-8", "replace")
        ids: list[str] = []
        for line in body.splitlines():
            stamp, _, osv_id = line.partition(",")
            modified = parse_datetime(stamp.strip())
            if modified is None or modified <= since:
                break  # the file is sorted newest first
            osv_id = osv_id.strip().split("/")[-1]
            if osv_id and not osv_id.startswith("MAL-"):
                ids.append(osv_id)
        return list(dict.fromkeys(ids))

    def run(self, ctx: JobContext) -> None:
        ecosystem = ctx.params["ecosystem"]
        marks = dict(ctx.watermark or {})
        since = parse_datetime(marks.get(ecosystem))
        mode = ctx.params["mode"]
        if mode == "auto":
            mode = "incremental" if since else "full"
        ctx.details.update({"ecosystem": ecosystem, "mode": mode})
        started = datetime.now(UTC)

        if mode == "full":
            records: Iterable[Any] = self._records_from_zip(ctx, ecosystem)
        else:
            if since is None:
                raise ParamError("incremental mode needs a previous full run")
            ids = self._changed_ids(ctx, ecosystem, since)
            ctx.details["changed"] = len(ids)
            if len(ids) > ctx.params["max_records"]:
                raise SourceError(
                    f"{len(ids)} advisories changed since {since.isoformat()}; "
                    "run mode=full instead"
                )
            base = f"{ctx.settings.osv_data_base_url}/{ecosystem}"

            def fetch(osv_id: str) -> Any:
                try:
                    return ctx.http.get_json(
                        f"{base}/{osv_id}.json", max_bytes=self.max_member_bytes
                    )
                except SourceError as exc:
                    return exc

            with ThreadPoolExecutor(max_workers=ctx.settings.ingestion_concurrency) as pool:
                fetched = list(pool.map(fetch, ids))
            records = []
            for osv_id, item in zip(ids, fetched, strict=True):
                if isinstance(item, Exception):
                    ctx.fail(osv_id, "fetch", str(item))
                else:
                    records.append(item)

        removed = 0

        def counted(items: Iterable[Any]) -> Iterator[Any]:
            for item in items:
                ctx.fetched += 1
                yield item

        def write(session: Session, record: Any) -> Change:
            nonlocal removed
            advisory = parse_osv(record)
            if advisory.withdrawn:
                if delete_advisory(session, advisory.id):
                    removed += 1
                return Change.SKIPPED
            if not advisory.packages:
                # Only GIT commit ranges (or other ecosystems): nothing to match versions on.
                return Change.SKIPPED
            changed = record_seen(
                session,
                source_id=ctx.source_id,
                record_key=advisory.id,
                digest=content_hash(record),
                job_id=ctx.job_id,
                source_url=f"https://osv.dev/vulnerability/{advisory.id}",
            )
            if not changed:
                return Change.UNCHANGED
            return upsert_advisory(session, advisory)

        def key(record: Any) -> str:
            return str((record or {}).get("id", "?"))[:100] if isinstance(record, dict) else "?"

        _write_batches(ctx, counted(records), key, write)
        ctx.details["withdrawn_removed"] = removed
        marks[ecosystem] = started.isoformat()
        ctx.new_watermark = marks


ADAPTERS: dict[str, Callable[[], Adapter]] = {
    "kev": KevAdapter,
    "cve5": Cve5Adapter,
    "nvd": NvdAdapter,
    "attack": AttackAdapter,
    "capec": CapecAdapter,
    "osv": OsvAdapter,
}


def _embeddings_adapter() -> Adapter:
    # Imported lazily: the retrieval package depends on this module.
    from app.retrieval.indexer import EmbeddingsAdapter

    return EmbeddingsAdapter()


ADAPTERS["embeddings"] = _embeddings_adapter


def get_adapter(code: str) -> Adapter:
    try:
        return ADAPTERS[code]()
    except KeyError:
        raise ParamError(f"unknown source {code!r}; expected one of {sorted(ADAPTERS)}") from None
