"""Unit tests for manifest parsing and version-range evaluation."""

from __future__ import annotations

import json

import pytest

from app.dependencies.parsers import (
    MAX_BYTES,
    ManifestError,
    detect_format,
    parse_manifest,
    parse_package_json,
    parse_package_lock,
    parse_requirements,
)
from app.dependencies.versions import cve_entry_affected, osv_affected, parse_semver

# ---------------------------------------------------------------------- parsing


def test_requirements_pins_ranges_and_skips() -> None:
    text = """
# comment
Flask==2.2.4  # inline comment
requests[socks]==2.30.0 ; python_version >= "3.8"
Django>=4.2,<5
numpy
pkg==1.0 \\
    --hash=sha256:abcdef
-r other.txt
-e git+https://github.com/x/y.git#egg=y
https://example.org/pkg.whl
--index-url https://pypi.example/simple
not a requirement!!
star==1.*
"""
    manifest = parse_requirements(text)
    deps = {d.normalized_name: d for d in manifest.dependencies}

    assert deps["flask"].pinned and deps["flask"].version == "2.2.4"
    assert deps["requests"].version == "2.30.0"  # extras and markers handled
    assert not deps["django"].pinned and deps["django"].specifier == "<5,>=4.2"
    assert not deps["numpy"].pinned and deps["numpy"].specifier is None
    assert deps["pkg"].version == "1.0"  # line continuation and --hash
    assert not deps["star"].pinned  # wildcard pins are ranges
    reasons = [n["reason"] for n in manifest.not_checked]
    assert "included files are not read" in reasons
    assert sum("URL" in r for r in reasons) == 2
    assert "not a valid requirement" in reasons


def test_package_lock_v3_and_v1() -> None:
    v3 = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/a/node_modules/@scope/pkg": {"version": "1.0.0", "dev": True},
            "node_modules/linked": {"link": True, "resolved": "../linked"},
            "node_modules/local": {"version": "file:../local"},
        },
    }
    manifest = parse_package_lock(json.dumps(v3))
    names = {(d.name, d.version, d.dev) for d in manifest.dependencies}
    assert names == {("lodash", "4.17.20", False), ("@scope/pkg", "1.0.0", True)}
    assert manifest.not_checked[0]["reason"] == "non-registry source"

    v1 = {
        "lockfileVersion": 1,
        "dependencies": {
            "express": {"version": "4.18.2", "dependencies": {"qs": {"version": "6.11.0"}}}
        },
    }
    names_v1 = {(d.name, d.version) for d in parse_package_lock(json.dumps(v1)).dependencies}
    assert names_v1 == {("express", "4.18.2"), ("qs", "6.11.0")}


def test_package_json_ranges_are_unpinned() -> None:
    manifest = parse_package_json(
        json.dumps(
            {
                "dependencies": {"lodash": "^4.17.0", "express": "4.18.2", "x": "file:../x"},
                "devDependencies": {"semver": "~7.5.0"},
            }
        )
    )
    deps = {d.name: d for d in manifest.dependencies}
    assert deps["express"].pinned and deps["express"].version == "4.18.2"
    assert not deps["lodash"].pinned and deps["semver"].dev
    assert manifest.warnings and manifest.not_checked[0]["reason"] == "non-registry source"


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("requirements.txt", "requirements.txt"),
        ("requirements-dev.txt", "requirements.txt"),
        ("sub/dir/package-lock.json", "package-lock.json"),
        ("package.json", "package.json"),
    ],
)
def test_detect_format(filename: str, expected: str) -> None:
    assert detect_format(filename) == expected


@pytest.mark.parametrize(
    "filename", ["setup.py", "notes.txt", "pom.xml", "../../etc/passwd", "package-lock.json.exe"]
)
def test_unsupported_files(filename: str) -> None:
    with pytest.raises(ManifestError, match="unsupported"):
        detect_format(filename)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"flask==1\x00", "binary"),
        (b"\xff\xfe\x00bad", "binary"),
        (b"caf\xe9==1", "UTF-8"),
        (b"a" * (MAX_BYTES + 1), "exceeds"),
    ],
)
def test_unsafe_content_is_rejected(content: bytes, message: str) -> None:
    with pytest.raises(ManifestError, match=message):
        parse_manifest("requirements.txt", content)


def test_invalid_json_and_shapes() -> None:
    with pytest.raises(ManifestError, match="invalid JSON"):
        parse_manifest("package-lock.json", b"{nope")
    with pytest.raises(ManifestError, match="JSON object"):
        parse_manifest("package.json", b"[]")
    with pytest.raises(ManifestError, match="no 'packages'"):
        parse_manifest("package-lock.json", b"{}")


def test_bom_is_accepted() -> None:
    manifest = parse_manifest("requirements.txt", b"\xef\xbb\xbfflask==2.2.4\n")
    assert manifest.dependencies[0].name == "flask"


# --------------------------------------------------------------------- versions

FLASK_RANGES = [
    {"type": "ECOSYSTEM", "events": [{"introduced": "2.3.0"}, {"fixed": "2.3.2"}]},
    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.5"}]},
]


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("0.1", True),
        ("2.2.4", True),
        ("2.2.5", False),
        ("2.2.6", False),
        ("2.3.0", True),
        ("2.3.1", True),
        ("2.3.2", False),
        ("3.0.0", False),
        ("2.3.0rc1", False),
        ("bogus", None),
    ],
)
def test_osv_ranges_pypi(version: str, expected: bool | None) -> None:
    assert osv_affected("PyPI", version, FLASK_RANGES, []) is expected


def test_osv_last_affected_and_explicit_versions() -> None:
    ranges = [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"last_affected": "1.4.2"}]}]
    assert osv_affected("npm", "1.4.2", ranges, []) is True
    assert osv_affected("npm", "1.4.3", ranges, []) is False
    assert osv_affected("npm", "0.9.0", [], ["0.9.0"]) is True
    assert osv_affected("npm", "not-semver", ranges, []) is None


def test_osv_unsorted_events_are_sorted() -> None:
    ranges = [{"type": "SEMVER", "events": [{"fixed": "2.0.0"}, {"introduced": "1.0.0"}]}]
    assert osv_affected("npm", "1.5.0", ranges, []) is True
    assert osv_affected("npm", "2.0.0", ranges, []) is False


def test_semver_precedence() -> None:
    assert parse_semver("1.0.0-alpha") < parse_semver("1.0.0-alpha.1") < parse_semver("1.0.0")
    assert parse_semver("1.0.0-alpha.2") < parse_semver("1.0.0-alpha.10")  # type: ignore[operator]
    assert parse_semver("1.0") is None


@pytest.mark.parametrize(
    ("entry", "version", "expected"),
    [
        ({"version": ">= 2.3.0, < 2.3.2", "status": "affected"}, "2.3.1", True),
        ({"version": ">= 2.3.0, < 2.3.2", "status": "affected"}, "2.3.2", False),
        ({"version": "< 2.2.5", "status": "affected"}, "2.2.4", True),
        ({"version": "prior to 4.17.21", "status": "affected"}, "4.17.20", True),
        ({"version": "before 4.17.21"}, "4.17.21", False),
        ({"version": "through 1.2.3"}, "1.2.3", True),
        ({"version": "1.0.0", "lessThan": "1.2.0", "status": "affected"}, "1.1.0", True),
        ({"version": "1.0.0", "lessThan": "1.2.0", "status": "affected"}, "0.9.0", False),
        ({"version": "unspecified", "lessThan": "3.7"}, "3.6", True),
        ({"version": "0", "lessThanOrEqual": "2.0"}, "2.0", True),
        ({"version": "2.0.0", "status": "unaffected"}, "2.0.0", False),
        ({"version": "1.5.0"}, "1.5.0", True),
        ({"version": "Ver2.20", "lessThan": "Ver8.00 Update 5"}, "3.0", None),
        ({"version": "log4j-core 2.0", "lessThan": "2.15.0"}, "2.14.1", None),
    ],
)
def test_cve_version_entries(entry: dict, version: str, expected: bool | None) -> None:
    assert cve_entry_affected("PyPI", version, entry) is expected
