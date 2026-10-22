# Sample dependency manifests

Hand-written files for demonstrating `POST /api/v1/dependencies/analyze`. They pin older
releases of popular packages; whether a version is affected is decided by the analysis
against the ingested OSV and CVE data, not by these files.

| File | Format | What it shows |
|---|---|---|
| `requirements-demo.txt` | PyPI requirements | pinned (checkable), unpinned (uncertain), includes and VCS URLs (not checked) |
| `package-lock-demo.json` | npm lockfile v3 | exact resolved versions, nested and dev dependencies, a linked local package |
| `package-demo.json` | npm package.json | declared ranges only, so matches are uncertain |

```bash
curl -F "file=@samples/dependencies/requirements-demo.txt" \
     http://localhost:8000/api/v1/dependencies/analyze
```
