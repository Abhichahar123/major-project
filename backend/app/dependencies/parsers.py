"""Manifest parsers. Files are read as text or JSON only: nothing is executed, installed,
resolved over the network, or included from other files.

Supported:

* ``requirements.txt`` (PyPI): exact pins (``==``) are checkable; ranges are reported as
  unpinned. ``-r``/``-c`` includes, editable installs, URLs and VCS references are listed
  as not checked.
* ``package-lock.json`` (npm lockfile v1, v2 and v3): exact resolved versions.
* ``package.json`` (npm): declared ranges, so matches are uncertain unless an exact
  version is given.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from packaging.requirements import InvalidRequirement, Requirement

from app.ingestion.normalize import normalize_package_name

MAX_BYTES = 512 * 1024
MAX_DEPENDENCIES = 5000
MAX_LINE = 2000

ManifestFormat = Literal["requirements.txt", "package-lock.json", "package.json"]


class ManifestError(ValueError):
    """The file cannot be parsed as the declared or detected format."""


@dataclass
class Dependency:
    name: str
    normalized_name: str
    ecosystem: str
    version: str | None  # exact version when pinned/resolved
    specifier: str | None  # raw declared requirement, e.g. ">=4.0,<5"
    pinned: bool
    location: str  # line number or lockfile path
    dev: bool = False


@dataclass
class Manifest:
    format: ManifestFormat
    ecosystem: str
    dependencies: list[Dependency] = field(default_factory=list)
    not_checked: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def detect_format(filename: str) -> ManifestFormat:
    name = filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name == "package-lock.json":
        return "package-lock.json"
    if name == "package.json":
        return "package.json"
    if name.endswith(".txt") and ("requirements" in name or name.startswith("req")):
        return "requirements.txt"
    raise ManifestError(
        f"unsupported file {name!r}: upload requirements*.txt, package-lock.json or package.json"
    )


def decode(content: bytes) -> str:
    if len(content) > MAX_BYTES:
        raise ManifestError(f"file exceeds {MAX_BYTES // 1024} KB")
    if b"\x00" in content:
        raise ManifestError("binary content is not accepted")
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ManifestError("the file must be UTF-8 text") from None


def _limit(manifest: Manifest) -> Manifest:
    if len(manifest.dependencies) > MAX_DEPENDENCIES:
        raise ManifestError(f"more than {MAX_DEPENDENCIES} dependencies")
    return manifest


# ------------------------------------------------------------------- requirements


def _logical_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if len(raw) > MAX_LINE:
            raise ManifestError(f"line {number} is too long")
        if not buffer:
            start = number
        if raw.rstrip().endswith("\\"):
            buffer += raw.rstrip()[:-1] + " "
            continue
        lines.append((start, buffer + raw))
        buffer = ""
    if buffer:
        lines.append((start, buffer))
    return lines


def parse_requirements(text: str) -> Manifest:
    manifest = Manifest(format="requirements.txt", ecosystem="PyPI")
    for number, line in _logical_lines(text):
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if not line:
            continue
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            manifest.not_checked.append(
                {"entry": line[:200], "reason": "included files are not read"}
            )
            continue
        if line.startswith("-") and not line.startswith(("-e", "--editable")):
            continue  # pip options such as --index-url or --hash on their own line
        if (
            line.startswith(("-e", "--editable"))
            or "://" in line
            or line.startswith(("git+", ".", "/"))
        ):
            manifest.not_checked.append(
                {"entry": line[:200], "reason": "URL, path or editable install"}
            )
            continue
        line = re.split(r"\s--hash[=\s]", line)[0].strip()
        try:
            req = Requirement(line)
        except InvalidRequirement:
            manifest.not_checked.append({"entry": line[:200], "reason": "not a valid requirement"})
            continue
        if req.url:
            manifest.not_checked.append({"entry": line[:200], "reason": "direct URL reference"})
            continue
        specs = list(req.specifier)
        exact = [s for s in specs if s.operator in {"==", "==="} and "*" not in s.version]
        pinned = len(specs) == 1 and len(exact) == 1
        manifest.dependencies.append(
            Dependency(
                name=req.name,
                normalized_name=normalize_package_name("PyPI", req.name),
                ecosystem="PyPI",
                version=exact[0].version if pinned else None,
                specifier=str(req.specifier) or None,
                pinned=pinned,
                location=f"line {number}",
            )
        )
    return _limit(manifest)


# -------------------------------------------------------------------------- npm


def _load_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid JSON at line {exc.lineno}") from None


def _npm_name_from_path(path: str) -> str | None:
    marker = "node_modules/"
    index = path.rfind(marker)
    return path[index + len(marker) :] if index >= 0 else None


_NPM_NAME = re.compile(r"^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$", re.IGNORECASE)


def parse_package_lock(text: str) -> Manifest:
    data = _load_json(text)
    if not isinstance(data, dict):
        raise ManifestError("package-lock.json must be a JSON object")
    manifest = Manifest(format="package-lock.json", ecosystem="npm")
    seen: set[tuple[str, str]] = set()

    def add(name: str, version: Any, location: str, dev: bool) -> None:
        if not isinstance(version, str) or not _NPM_NAME.match(name):
            manifest.not_checked.append({"entry": location[:200], "reason": "no resolved version"})
            return
        if version.startswith(("file:", "link:", "git", "http")):
            manifest.not_checked.append(
                {"entry": f"{name}@{version}"[:200], "reason": "non-registry source"}
            )
            return
        key = (name.lower(), version)
        if key in seen:
            return
        seen.add(key)
        manifest.dependencies.append(
            Dependency(
                name=name,
                normalized_name=normalize_package_name("npm", name),
                ecosystem="npm",
                version=version,
                specifier=None,
                pinned=True,
                location=location,
                dev=dev,
            )
        )

    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2 and v3
        for path, info in packages.items():
            if not path or not isinstance(info, dict) or info.get("link"):
                continue
            name = info.get("name") or _npm_name_from_path(path)
            if name:
                add(name, info.get("version"), path, bool(info.get("dev")))
    elif isinstance(data.get("dependencies"), dict):  # lockfile v1, nested
        stack: list[tuple[str, dict[str, Any]]] = [("", data["dependencies"])]
        while stack:
            prefix, deps = stack.pop()
            for name, info in deps.items():
                if not isinstance(info, dict):
                    continue
                location = f"{prefix}node_modules/{name}"
                add(name, info.get("version"), location, bool(info.get("dev")))
                if isinstance(info.get("dependencies"), dict):
                    stack.append((location + "/", info["dependencies"]))
                if len(manifest.dependencies) > MAX_DEPENDENCIES:
                    break
    else:
        raise ManifestError("no 'packages' or 'dependencies' section found")
    manifest.dependencies.sort(key=lambda d: (d.normalized_name, d.version or ""))
    return _limit(manifest)


_EXACT_NPM = re.compile(r"^=?v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")


def parse_package_json(text: str) -> Manifest:
    data = _load_json(text)
    if not isinstance(data, dict):
        raise ManifestError("package.json must be a JSON object")
    manifest = Manifest(format="package.json", ecosystem="npm")
    manifest.warnings.append(
        "package.json declares ranges; upload package-lock.json for exact "
        "versions and confirmed matches."
    )
    for section, dev in (
        ("dependencies", False),
        ("devDependencies", True),
        ("optionalDependencies", False),
    ):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(name, str) or not _NPM_NAME.match(name) or not isinstance(spec, str):
                manifest.not_checked.append({"entry": str(name)[:200], "reason": "invalid entry"})
                continue
            if any(spec.startswith(p) for p in ("file:", "link:", "git", "http", "npm:")):
                manifest.not_checked.append(
                    {"entry": f"{name}@{spec}"[:200], "reason": "non-registry source"}
                )
                continue
            exact = bool(_EXACT_NPM.match(spec.strip()))
            manifest.dependencies.append(
                Dependency(
                    name=name,
                    normalized_name=normalize_package_name("npm", name),
                    ecosystem="npm",
                    version=spec.strip().lstrip("=v") if exact else None,
                    specifier=spec[:200],
                    pinned=exact,
                    location=f"{section}.{name}",
                    dev=dev,
                )
            )
    return _limit(manifest)


PARSERS = {
    "requirements.txt": parse_requirements,
    "package-lock.json": parse_package_lock,
    "package.json": parse_package_json,
}


def parse_manifest(filename: str, content: bytes) -> Manifest:
    fmt = detect_format(filename)
    return PARSERS[fmt](decode(content))
