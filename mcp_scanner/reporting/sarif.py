from __future__ import annotations

import json
from typing import Iterable

from ..core_types import Finding


def generate_sarif(findings: Iterable[Finding]) -> str:
    results = []
    rules = {}

    for finding in findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.rule_id,
            "fullDescription": {"text": finding.message},
            "help": {
                "text": finding.recommendation,
                "markdown": finding.recommendation,
            },
        }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": finding.severity.level.value,
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path or ""},
                            "region": {"startLine": finding.line or 0},
                        }
                    }
                ],
            }
        )

    sarif_payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cebus-mcp-scanner",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif_payload, indent=2)

