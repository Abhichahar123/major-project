"""Input and output safeguards for the RAG pipeline.

Threat model: both the user question and retrieved documents are untrusted. A CVE
description, KEV note or ATT&CK text could contain text that tries to steer the model
("ignore previous instructions"), close the evidence delimiter early, or plant fake
identifiers. These checks reduce that risk; they do not make prompt injection
impossible, so answers are always shown with their citations and a disclaimer.
"""

from __future__ import annotations

import re

CVE_IN_TEXT = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CITATION = re.compile(r"\[(E\d{1,3})\]")

# Phrases typical of instruction injection. A match is reported, never obeyed.
_INJECTION = re.compile(
    r"(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+"
    r"(instructions|rules|prompts?)|you\s+are\s+now\b|system\s+prompt|developer\s+mode|"
    r"<\s*/?\s*(system|assistant|evidence|instructions?)\b|\bjailbreak\b",
    re.IGNORECASE,
)

# Requests for offensive capability. The platform supports defensive analysis only.
_OFFENSIVE = re.compile(
    r"\b(write|create|generate|build|give\s+me|provide)\b.{0,40}\b(working\s+)?"
    r"(exploit|payload|shellcode|malware|ransomware|reverse\s+shell|weaponi[sz]ed?)\b|"
    r"\bhow\s+(do|can)\s+i\s+(hack|exploit|attack|break\s+into)\b",
    re.IGNORECASE,
)

REFUSAL = (
    "This assistant supports defensive analysis: understanding vulnerabilities, their "
    "impact, exploitation status and remediation. It does not provide exploit code, "
    "payloads or instructions for attacking systems."
)


def looks_like_injection(text: str) -> bool:
    return bool(_INJECTION.search(text))


def is_offensive_request(question: str) -> bool:
    return bool(_OFFENSIVE.search(question))


def neutralize(text: str) -> str:
    """Make untrusted text safe to place inside an evidence block.

    Angle brackets are replaced so the text cannot open or close prompt tags, and
    control characters are removed.
    """
    text = "".join(ch for ch in text if ch in "\n\t" or ord(ch) >= 32)
    # Single angle quotation marks look alike to a reader but cannot form tags.
    return text.replace("<", "\u2039").replace(">", "\u203a")


def extract_cve_ids(text: str) -> list[str]:
    return list(dict.fromkeys(m.upper() for m in CVE_IN_TEXT.findall(text)))
