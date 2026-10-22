"""The documented correlation rules.

Every relationship returned by the correlation service names one of these rules.
``authoritative`` rules restate what a source publishes. ``inferred`` rules derive a
link by joining sources; their output is a lead for an analyst, not a fact, and is
labelled that way in every API response.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class Rule:
    id: str
    kind: Literal["authoritative", "inferred"]
    name: str
    description: str
    evidence: str
    limitations: str


RULES: dict[str, Rule] = {
    r.id: r
    for r in [
        Rule(
            id="kev_listing",
            kind="authoritative",
            name="Listed in CISA KEV",
            description="The CVE appears in the CISA Known Exploited Vulnerabilities catalog.",
            evidence="kev_entries row for the CVE (CISA catalog version recorded).",
            limitations="Absence from KEV does not mean a CVE is not exploited.",
        ),
        Rule(
            id="cve_cwe_assignment",
            kind="authoritative",
            name="Weakness assigned to the CVE",
            description="A CNA, CISA-ADP, NVD or the KEV catalog assigns the CWE to the CVE.",
            evidence="vulnerability_cwes rows (with the assigning provider) or KEV cwes.",
            limitations="Providers can disagree; every provider is listed.",
        ),
        Rule(
            id="osv_alias",
            kind="authoritative",
            name="Package advisory aliasing the CVE",
            description="An OSV advisory lists the CVE among its aliases.",
            evidence="advisories.cve_ids contains the CVE.",
            limitations="Covers the ingested ecosystems only (PyPI, npm).",
        ),
        Rule(
            id="cwe_capec_mapping",
            kind="authoritative",
            name="Attack pattern exploiting the weakness",
            description="MITRE CAPEC lists the CWE as a related weakness of the attack pattern.",
            evidence="capec_cwe_mappings row (from the CAPEC STIX bundle).",
            limitations="Deprecated and obsolete patterns are excluded. A pattern relating to "
            "a weakness does not mean it applies to every vulnerability with that weakness.",
        ),
        Rule(
            id="capec_attack_mapping",
            kind="authoritative",
            name="ATT&CK technique mapped to the attack pattern",
            description="MITRE CAPEC maps the attack pattern to the ATT&CK technique.",
            evidence="capec_attack_mappings row (from the CAPEC STIX bundle).",
            limitations="Only a minority of CAPEC patterns carry ATT&CK mappings.",
        ),
        Rule(
            id="cve_cwe_capec_attack_chain",
            kind="inferred",
            name="Technique reachable through weakness and attack pattern",
            description="CVE -> assigned CWE -> CAPEC pattern for that CWE -> ATT&CK "
            "technique mapped to the pattern.",
            evidence="The full path (CWE, CAPEC) is returned with every technique.",
            limitations="The chain links categories, not this specific CVE. Treat it as a "
            "hypothesis of how such a flaw may be used; more independent paths make it "
            "more plausible, not certain.",
        ),
        Rule(
            id="shared_product",
            kind="inferred",
            name="Affects the same product",
            description="Another CVE lists the same vendor and product (case-insensitive).",
            evidence="affected_products rows of both CVEs.",
            limitations="Names are not normalized across providers, so some matches are missed "
            "and generic names can over-match.",
        ),
        Rule(
            id="shared_weakness",
            kind="inferred",
            name="Shares a weakness",
            description="Another CVE is assigned the same CWE.",
            evidence="vulnerability_cwes rows of both CVEs.",
            limitations="Broad CWEs (e.g. CWE-20) connect unrelated vulnerabilities.",
        ),
    ]
}


def rule_dicts(ids: list[str] | None = None) -> list[dict[str, Any]]:
    return [asdict(RULES[i]) for i in (ids or list(RULES))]
