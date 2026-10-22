"""The bounded demo dataset loaded by ``python -m app.ingestion seed``.

It is the full CISA KEV catalog, MITRE ATT&CK Enterprise and CAPEC, plus CVE Program
records for:

* the most recently added KEV entries (``DEFAULT_KEV_CVE_LIMIT``), and
* a fixed list of well-known CVEs in widely used open-source packages, so that the
  dependency-analysis demo has package-level data to match against.

Every ID below is a real, published CVE; records are fetched from the CVE Program, never
written by hand.
"""

DEFAULT_KEV_CVE_LIMIT = 300

PACKAGE_DEMO_CVES = [
    "CVE-2021-44228",  # Apache Log4j2 (Log4Shell)
    "CVE-2021-45046",  # Apache Log4j2
    "CVE-2022-22965",  # Spring Framework (Spring4Shell)
    "CVE-2023-30861",  # pallets/flask
    "CVE-2023-32681",  # psf/requests
    "CVE-2024-35195",  # psf/requests
    "CVE-2024-34064",  # pallets/jinja
    "CVE-2024-22195",  # pallets/jinja
    "CVE-2023-46136",  # pallets/werkzeug
    "CVE-2024-34069",  # pallets/werkzeug
    "CVE-2023-43804",  # urllib3
    "CVE-2023-45803",  # urllib3
    "CVE-2024-3651",  # idna
    "CVE-2023-37920",  # certifi
    "CVE-2021-23337",  # lodash
    "CVE-2020-8203",  # lodash
    "CVE-2021-44906",  # minimist
    "CVE-2022-25883",  # semver (npm)
    "CVE-2024-4068",  # braces
    "CVE-2023-26136",  # tough-cookie
    "CVE-2024-29041",  # express
    "CVE-2023-45857",  # axios
    "CVE-2022-24999",  # qs
    "CVE-2021-3807",  # ansi-regex
]
