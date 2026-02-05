from __future__ import annotations

import json
from typing import Iterable, TextIO

from ..core_types import Finding


def generate_json(findings: Iterable[Finding]) -> str:
    payload = [
        {
            "rule_id": f.rule_id,
            "message": f.message,
            "file": f.file_path,
            "line": f.line,
            "category": f.category,
            "severity": f.severity.level.value,
            "severity_message": f.severity.message,
            "why_it_matters": f.why_it_matters,
            "recommendation": f.recommendation,
            "owasp_llm_top10_ids": f.owasp_llm_top10_ids,
            "owasp_top10_ids": f.owasp_top10_ids,
            "ml_top10_ids": f.ml_top10_ids,
        }
        for f in findings
    ]
    return json.dumps(payload, indent=2)


def write_json(findings: Iterable[Finding], stream: TextIO) -> None:
    stream.write(generate_json(findings))
    stream.write("\n")

