"""Version parsing and range evaluation for PyPI (PEP 440) and npm (SemVer 2.0).

``osv_affected`` implements the OSV range semantics: events are sorted by version and
walked in order; ``introduced`` opens an affected interval, ``fixed`` closes it (the fixed
version is not affected) and ``last_affected`` closes it after that version. Any
comparison that cannot be made returns ``None`` (unknown) rather than guessing.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import total_ordering
from typing import Any

from packaging.version import InvalidVersion, Version

_SEMVER = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$"
)


@total_ordering
@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    def _key(self) -> tuple[Any, ...]:
        # A release sorts after its pre-releases; numeric identifiers sort before text ones.
        pre: tuple[Any, ...] = tuple(
            (0, int(p), "") if p.isdigit() else (1, 0, p) for p in self.prerelease
        )
        return (self.major, self.minor, self.patch, 0 if self.prerelease else 1, pre)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._key() < other._key()


def parse_semver(text: str) -> SemVer | None:
    match = _SEMVER.match(text.strip())
    if not match:
        return None
    major, minor, patch, pre = match.groups()
    return SemVer(int(major), int(minor), int(patch), tuple(pre.split(".")) if pre else ())


def parse_pep440(text: str) -> Version | None:
    try:
        return Version(text.strip())
    except InvalidVersion:
        return None


Parser = Callable[[str], Any]

PARSERS: dict[str, Parser] = {"PyPI": parse_pep440, "npm": parse_semver}


def parse_version(ecosystem: str, text: str | None) -> Any:
    if not text:
        return None
    parser = PARSERS.get(ecosystem)
    return parser(text) if parser else None


def _event_version(ecosystem: str, value: str) -> Any:
    if value == "0":
        return _MINIMUM
    return parse_version(ecosystem, value)


class _Minimum:
    """Sorts before every version (OSV's ``introduced: "0"``)."""

    def __lt__(self, other: object) -> bool:
        return not isinstance(other, _Minimum)

    def __le__(self, other: object) -> bool:
        return True

    def __gt__(self, other: object) -> bool:
        return False

    def __ge__(self, other: object) -> bool:
        return isinstance(other, _Minimum)


_MINIMUM = _Minimum()


def osv_affected(
    ecosystem: str, version_text: str, ranges: list[dict[str, Any]], versions: list[str]
) -> bool | None:
    """True/False if the version is (not) affected; None if it cannot be determined."""
    if version_text in versions:
        return True
    version = parse_version(ecosystem, version_text)
    if version is None:
        return None
    undetermined = False
    for rng in ranges:
        events: list[tuple[Any, str]] = []
        for event in rng.get("events", []):
            for kind in ("introduced", "fixed", "last_affected"):
                if kind in event:
                    parsed = _event_version(ecosystem, event[kind])
                    if parsed is None:
                        undetermined = True
                    else:
                        events.append((parsed, kind))
        # Stable sort by version; at equal versions apply introduced before closing events.
        order = {"introduced": 0, "fixed": 1, "last_affected": 2}
        events.sort(key=lambda e: order[e[1]])
        events.sort(key=lambda e: _SortKey(e[0]))
        affected = False
        for event_version, kind in events:
            if kind == "introduced" and version >= event_version:
                affected = True
            elif kind == "fixed":
                affected = affected and not version >= event_version
            elif kind == "last_affected":
                affected = affected and not version > event_version
        if affected:
            return True
    return None if undetermined else False


class _SortKey:
    def __init__(self, value: Any) -> None:
        self.value = value

    def __lt__(self, other: _SortKey) -> bool:
        if isinstance(self.value, _Minimum):
            return not isinstance(other.value, _Minimum)
        if isinstance(other.value, _Minimum):
            return False
        return bool(self.value < other.value)


# --------------------------------------------------- CVE JSON 5 / NVD version entries

_TEXT_BOUND = re.compile(
    r"^(?:(?:all\s+)?versions?\s+)?(prior\s+to|before|earlier\s+than|<)\s*=?\s*v?(?P<v>[\w.+-]+)$"
    r"|^(?:(?:all\s+)?versions?\s+)?(through|up\s+to(?:\s+and\s+including)?|<=)\s*v?(?P<w>[\w.+-]+)$",
    re.IGNORECASE,
)
# Lower bounds CNAs use to mean "from the first version".
_NO_LOWER_BOUND = frozenset({"0", "*", "unspecified", "n/a", "unknown", "all", "-"})
_COMPARATOR = re.compile(r"^(>=|>|<=|<|==|=)\s*v?([\w.+-]+)$")


_OPERATORS: dict[str, Callable[[Any, Any], Any]] = {
    ">=": operator.ge,
    ">": operator.gt,
    "<=": operator.le,
    "<": operator.lt,
    "==": operator.eq,
    "=": operator.eq,
}


def _compare(op: str, version: Any, bound: Any) -> bool:
    return bool(_OPERATORS[op](version, bound))


def cve_entry_affected(ecosystem: str, version_text: str, entry: dict[str, Any]) -> bool | None:
    """Evaluate one CVE JSON 5 ``versions`` item (or the NVD-derived equivalent)."""
    if entry.get("status", "affected") != "affected":
        return False
    version = parse_version(ecosystem, version_text)
    if version is None:
        return None
    start_text = entry.get("version")
    less_than, less_equal = entry.get("lessThan"), entry.get("lessThanOrEqual")

    if start_text and not less_than and not less_equal:
        text = start_text.strip()
        if "," in text or _COMPARATOR.match(text):
            # GitHub CNA style: ">= 2.3.0, < 2.3.2" or "< 2.2.5".
            results = []
            for part in (p.strip() for p in text.split(",")):
                match = _COMPARATOR.match(part)
                bound = parse_version(ecosystem, match.group(2)) if match else None
                if match is None or bound is None:
                    return None
                results.append(_compare(match.group(1), version, bound))
            return all(results)
        match = _TEXT_BOUND.match(text)
        if match:
            if match.group("v"):
                bound = parse_version(ecosystem, match.group("v"))
                return None if bound is None else version < bound
            bound = parse_version(ecosystem, match.group("w"))
            return None if bound is None else version <= bound
        exact = parse_version(ecosystem, text)
        return None if exact is None else version == exact

    lower: Any = None
    if start_text and start_text.strip().lower() not in _NO_LOWER_BOUND:
        lower = parse_version(ecosystem, start_text)
        if lower is None:
            return None
    if lower is not None and version < lower:
        return False
    if entry.get("versionStartExcluding"):
        excl = parse_version(ecosystem, entry["versionStartExcluding"])
        if excl is None:
            return None
        if version <= excl:
            return False
    if less_than and less_than != "*":
        bound = parse_version(ecosystem, less_than)
        if bound is None:
            return None
        return bool(version < bound)
    if less_equal and less_equal != "*":
        bound = parse_version(ecosystem, less_equal)
        if bound is None:
            return None
        return bool(version <= bound)
    return None if lower is None else True
