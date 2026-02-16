"""
Built-in security rules and the all_rules() registry used by Scanner by default.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List

from ..ast_common import CallNode, LiteralNode, walk_ast
from ..patterns import (
    SHELL_EXECUTION_PATTERNS,
    HTTP_CLIENT_PATTERNS,
    SECRET_PATTERNS,
    FILE_ACCESS_PATTERNS,
    DANGEROUS_URL_SCHEMES,
)
from ..settings import ScanMode, Severity, SeverityLevel
from ..core_types import Finding
from .base import Rule, RuleMetadata, ScanContext

def _relative_path(source_file_path: Path, project_root: str) -> str:
    return str(source_file_path.relative_to(Path(project_root)))


def _is_string_literal(node: object) -> bool:
    return isinstance(node, LiteralNode) and isinstance(node.value, str)


def _matches_any(callee: str, patterns: Iterable[str]) -> bool:
    callee_lower = callee.lower()
    return any(pattern.lower() in callee_lower for pattern in patterns)


class DangerousShellExecutionRule(Rule):
    metadata = RuleMetadata(
        rule_id="RCE001",
        name="Unbounded Shell Execution",
        category="RCE / Excessive Rights",
        description="Detect use of subprocess or os.system that may allow shell execution.",
        owasp_llm_top10_ids=["LLM04"],
        owasp_top10_ids=["A01"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.HIGH,
                message="Shell execution reachable inside shared deployment.",
            )
        return Severity(
            level=SeverityLevel.LOW,
            message="Shell execution found; ensure usage is intentional in local mode.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        for source_file in analyzer.iter_source_files():
            language_patterns = SHELL_EXECUTION_PATTERNS.get(source_file.language, [])
            if not language_patterns:
                continue

            for node in walk_ast(source_file.tree):
                if isinstance(node, CallNode) and node.callee in language_patterns:
                    yield Finding(
                        rule_id=self.metadata.rule_id,
                        message=f"Shell execution via `{node.callee}`.",
                        file_path=_relative_path(source_file.path, context.project_root),
                        line=node.line,
                        category=self.metadata.category,
                        severity=severity,
                        why_it_matters="Arbitrary shell commands in shared environments enable RCE.",
                        recommendation="Validate input, restrict commands, or remove shell access for shared deployments.",
                        owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                        owasp_top10_ids=self.metadata.owasp_top10_ids,
                        ml_top10_ids=self.metadata.ml_top10_ids,
                    )


class UserControlledHttpRule(Rule):
    metadata = RuleMetadata(
        rule_id="SSRF001",
        name="HTTP Client Without Allow-List",
        category="SSRF & Network Access",
        description="Detect HTTP requests using dynamic URLs without validation.",
        owasp_llm_top10_ids=["LLM02", "LLM05"],
        owasp_top10_ids=["A10"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.HIGH,
                message="Dynamic HTTP calls allow SSRF/data exfiltration in shared mode.",
            )
        return Severity(
            level=SeverityLevel.LOW,
            message="Dynamic HTTP calls detected; consider allow-listing for remote use.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        for source_file in analyzer.iter_source_files():
            language_patterns = HTTP_CLIENT_PATTERNS.get(source_file.language, [])
            if not language_patterns:
                continue

            for node in walk_ast(source_file.tree):
                if not isinstance(node, CallNode):
                    continue

                # Check if callee matches HTTP client patterns
                if not _matches_any(node.callee, language_patterns):
                    continue

                # Check if URL argument is dynamic (not a constant)
                if not node.arguments:
                    continue

                url_arg = node.arguments[0]
                if _is_string_literal(url_arg):
                    continue  # constant strings are acceptable base case

                yield Finding(
                    rule_id=self.metadata.rule_id,
                    message=f"Dynamic URL used in `{node.callee}` call.",
                    file_path=_relative_path(source_file.path, context.project_root),
                    line=node.line,
                    category=self.metadata.category,
                    severity=severity,
                    why_it_matters="Dynamic URLs without allow-lists expose internal services to SSRF.",
                    recommendation="Validate URLs against an allow-list and restrict protocols/hosts.",
                    owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                    owasp_top10_ids=self.metadata.owasp_top10_ids,
                    ml_top10_ids=self.metadata.ml_top10_ids,
                )


class RepositorySecretRule(Rule):
    metadata = RuleMetadata(
        rule_id="SENS001",
        name="Secrets in Repository",
        category="Sensitive Data Exposure",
        description="Detect potential secrets committed in repository files.",
        owasp_llm_top10_ids=["LLM06"],
        owasp_top10_ids=["A02"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            level = SeverityLevel.MEDIUM
            message = "Secrets in repo could leak to multi-tenant users."
        else:
            level = SeverityLevel.LOW
            message = "Potential secret found; confirm and rotate if valid."
        return Severity(level=level, message=message)

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        severity = self.severity_for_mode(context.mode)

        for source_file in context.analyzer.iter_source_files():
            # Regex-based rules work across all languages
            for pattern_str in SECRET_PATTERNS:
                pattern = re.compile(pattern_str)
                matches = list(pattern.finditer(source_file.content))
                for match in matches:
                    line_no = source_file.content[: match.start()].count("\n") + 1
                    yield Finding(
                        rule_id=self.metadata.rule_id,
                        message=f"Potential secret discovered: `{match.group(0).split('=')[0].strip()}`.",
                        file_path=_relative_path(source_file.path, context.project_root),
                        line=line_no,
                        category=self.metadata.category,
                        severity=severity,
                        why_it_matters="Secrets in source expose credentials if repository is shared.",
                        recommendation="Use environment variables or secret storage; rotate exposed credentials.",
                        owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                        owasp_top10_ids=self.metadata.owasp_top10_ids,
                        ml_top10_ids=self.metadata.ml_top10_ids,
                    )


class UnconstrainedToolExecutionRule(Rule):
    """Detect flows where LLM output is directly used without validation."""
    metadata = RuleMetadata(
        rule_id="PROMPT001",
        name="Unconstrained Tool Execution from Model Output",
        category="Prompt Injection & Excessive Agency",
        description="Detect flows where LLM response is parsed and directly used as shell/HTTP/DB without validation.",
        owasp_llm_top10_ids=["LLM01", "LLM05"],
        owasp_top10_ids=["A03"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.HIGH,
                message="Unconstrained tool execution from model output in shared mode enables injection attacks.",
            )
        return Severity(
            level=SeverityLevel.INFO,
            message="Model output used directly in tool calls; consider validation for production.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        parse_keywords = ("parse", "extract", "response", "output")

        for source_file in analyzer.iter_source_files():
            language_patterns = (
                SHELL_EXECUTION_PATTERNS.get(source_file.language, [])
                + HTTP_CLIENT_PATTERNS.get(source_file.language, [])
            )

            if not language_patterns:
                continue

            parse_calls = [
                node
                for node in walk_ast(source_file.tree)
                if isinstance(node, CallNode)
                and any(keyword in node.callee.lower() for keyword in parse_keywords)
            ]

            if not parse_calls:
                continue

            risky_calls = [
                node
                for node in walk_ast(source_file.tree)
                if isinstance(node, CallNode) and _matches_any(node.callee, language_patterns)
            ]

            if not risky_calls:
                continue

            for node in parse_calls:
                yield Finding(
                    rule_id=self.metadata.rule_id,
                    message="Potential unconstrained tool execution: model output parsing may flow into tool calls.",
                    file_path=_relative_path(source_file.path, context.project_root),
                    line=node.line,
                    category=self.metadata.category,
                    severity=severity,
                    why_it_matters="LLM output used directly in tool calls enables prompt injection attacks.",
                    recommendation="Validate and sanitize model output before using in tool invocations.",
                    owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                    owasp_top10_ids=self.metadata.owasp_top10_ids,
                    ml_top10_ids=self.metadata.ml_top10_ids,
                )


class MissingGuardrailsRule(Rule):
    """Detect missing guardrails around tool-calling prompts."""
    metadata = RuleMetadata(
        rule_id="PROMPT002",
        name="Missing Guardrails Around Tool-Calling Prompts",
        category="Prompt Injection & Excessive Agency",
        description="Detect tools that can hit internal networks, run commands, or read arbitrary files with no guard prompts.",
        owasp_llm_top10_ids=["LLM01", "LLM05"],
        owasp_top10_ids=["A03"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.MEDIUM,
                message="Missing guardrails in shared mode allow excessive tool agency.",
            )
        return Severity(
            level=SeverityLevel.INFO,
            message="Consider adding system-level instructions restricting tool usage.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        # Look for tool definitions without constraints
        for source_file in analyzer.iter_source_files():
            content = source_file.content.lower()
            
            # Heuristic: if we see tool definitions but no guard keywords
            has_tools = any(x in content for x in ["@tool", "def tool", "register_tool", "mcp_tool"])
            has_guards = any(x in content for x in ["allowlist", "allow-list", "whitelist", "restrict", "validate", "constraint"])
            
            if has_tools and not has_guards:
                # Check if dangerous operations are present
                has_dangerous = any(x in content for x in ["subprocess", "requests.get", "open(", "os.system"])
                if has_dangerous:
                    yield Finding(
                        rule_id=self.metadata.rule_id,
                        message="Tool definitions found without apparent guardrails or constraints.",
                        file_path=_relative_path(source_file.path, context.project_root),
                        line=None,
                        category=self.metadata.category,
                        severity=severity,
                        why_it_matters="Tools without guardrails can be invoked inappropriately by LLM agents.",
                        recommendation="Add system-level instructions restricting tool usage and implement allow-lists.",
                        owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                        owasp_top10_ids=self.metadata.owasp_top10_ids,
                        ml_top10_ids=self.metadata.ml_top10_ids,
                    )


class SystemPromptLeakageRule(Rule):
    """Detect system prompt or config leakage in error paths."""
    metadata = RuleMetadata(
        rule_id="PROMPT003",
        name="System Prompt / Config Leakage",
        category="Prompt Injection & Excessive Agency",
        description="Detect returning raw system prompts or internal config in error paths / debug endpoints.",
        owasp_llm_top10_ids=["LLM08"],
        owasp_top10_ids=["A01"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.MEDIUM,
                message="System prompt leakage in shared mode exposes internal instructions.",
            )
        return Severity(
            level=SeverityLevel.LOW,
            message="System prompts exposed in responses; consider redaction for production.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        for source_file in analyzer.iter_source_files():
            content = source_file.content
            
            # Look for patterns that might leak prompts/config
            leak_patterns = [
                (r"system_prompt", "System prompt"),
                (r"system_message", "System message"),
                (r"internal_config", "Internal config"),
                (r"debug.*prompt", "Debug prompt"),
            ]
            
            for pattern, desc in leak_patterns:
                import re
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                for match in matches:
                    # Check if it's in a return/response context
                    lines = content[:match.start()].split("\n")
                    line_no = len(lines)
                    context_line = lines[-1] if lines else ""
                    if any(x in context_line for x in ["return", "response", "json.dumps", "str("]):
                        yield Finding(
                            rule_id=self.metadata.rule_id,
                            message=f"{desc} may be exposed in response: `{match.group(0)}`.",
                            file_path=_relative_path(source_file.path, context.project_root),
                            line=line_no,
                            category=self.metadata.category,
                            severity=severity,
                            why_it_matters="Exposing system prompts reveals internal instructions and enables better injection attacks.",
                            recommendation="Redact or sanitize system prompts and config in error responses and debug output.",
                            owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                            owasp_top10_ids=self.metadata.owasp_top10_ids,
                            ml_top10_ids=self.metadata.ml_top10_ids,
                        )


class OverLoggingRule(Rule):
    """Detect over-logging of sensitive data."""
    metadata = RuleMetadata(
        rule_id="SENS002",
        name="Over-Logging of Sensitive Data",
        category="Sensitive Data Exposure",
        description="Detect logging of full prompts, tool request bodies, or environment variables.",
        owasp_llm_top10_ids=["LLM06"],
        owasp_top10_ids=["A02"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.MEDIUM,
                message="Over-logging in shared mode can expose sensitive data to logs.",
            )
        return Severity(
            level=SeverityLevel.LOW,
            message="Sensitive data logged; ensure logs are properly secured.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        for source_file in analyzer.iter_source_files():
            content = source_file.content
            
            # Look for logging of sensitive patterns
            sensitive_patterns = [
                (r"log.*prompt", "Full prompt"),
                (r"log.*request.*body", "Request body"),
                (r"log.*env", "Environment variables"),
                (r"logger\.(debug|info).*password", "Password in log"),
                (r"logger\.(debug|info).*token", "Token in log"),
            ]
            
            import re
            for pattern, desc in sensitive_patterns:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                for match in matches:
                    line_no = content[:match.start()].count("\n") + 1
                    yield Finding(
                        rule_id=self.metadata.rule_id,
                        message=f"{desc} may be logged: `{match.group(0)}`.",
                        file_path=_relative_path(source_file.path, context.project_root),
                        line=line_no,
                        category=self.metadata.category,
                        severity=severity,
                        why_it_matters="Logging sensitive data can expose credentials, prompts, or internal state.",
                        recommendation="Redact sensitive fields before logging or use structured logging with field filtering.",
                        owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                        owasp_top10_ids=self.metadata.owasp_top10_ids,
                        ml_top10_ids=self.metadata.ml_top10_ids,
                    )


class UnredactedInternalUrlsRule(Rule):
    """Detect unredacted internal URLs/paths in responses."""
    metadata = RuleMetadata(
        rule_id="SENS003",
        name="Unredacted Internal URLs / Paths",
        category="Sensitive Data Exposure",
        description="Detect canned responses that echo internal topology.",
        owasp_llm_top10_ids=["LLM06"],
        owasp_top10_ids=["A02"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.LOW,
                message="Internal URLs in responses reveal topology in shared mode.",
            )
        return Severity(
            level=SeverityLevel.INFO,
            message="Internal URLs exposed; consider redaction for production deployments.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        # RFC1918 private IP ranges
        internal_ip_pattern = re.compile(r"(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)")
        
        for source_file in analyzer.iter_source_files():
            content = source_file.content

            for match in re.finditer(r"(localhost|127\.0\.0\.1)", content, re.IGNORECASE):
                line_no = content[:match.start()].count("\n") + 1
                line = content.splitlines()[line_no - 1] if line_no <= content.count("\n") + 1 else ""
                if any(x in line.lower() for x in ["return", "response", "json", "reply"]):
                    yield Finding(
                        rule_id=self.metadata.rule_id,
                        message=f"Internal URL/IP may be exposed: `{match.group(0)}`.",
                        file_path=_relative_path(source_file.path, context.project_root),
                        line=line_no,
                        category=self.metadata.category,
                        severity=severity,
                        why_it_matters="Internal URLs in responses reveal network topology to attackers.",
                        recommendation="Redact internal URLs and IPs in responses or use external-facing endpoints.",
                        owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                        owasp_top10_ids=self.metadata.owasp_top10_ids,
                        ml_top10_ids=self.metadata.ml_top10_ids,
                    )

            for match in internal_ip_pattern.finditer(content):
                line_no = content[:match.start()].count("\n") + 1
                line = content.splitlines()[line_no - 1] if line_no <= content.count("\n") + 1 else ""
                if any(x in line.lower() for x in ["return", "response", "json", "reply"]):
                    yield Finding(
                        rule_id=self.metadata.rule_id,
                        message=f"Internal URL/IP may be exposed: `{match.group(0)}`.",
                        file_path=_relative_path(source_file.path, context.project_root),
                        line=line_no,
                        category=self.metadata.category,
                        severity=severity,
                        why_it_matters="Internal URLs in responses reveal network topology to attackers.",
                        recommendation="Redact internal URLs and IPs in responses or use external-facing endpoints.",
                        owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                        owasp_top10_ids=self.metadata.owasp_top10_ids,
                        ml_top10_ids=self.metadata.ml_top10_ids,
                    )


class ArbitraryPortProtocolRule(Rule):
    """Detect tools allowing arbitrary schemes or ports."""
    metadata = RuleMetadata(
        rule_id="SSRF002",
        name="Arbitrary Port / Protocol",
        category="SSRF & Network Access",
        description="Flag tools that allow arbitrary schemes (ftp, file, gopher) or connect to RFC1918 ranges without restriction.",
        owasp_llm_top10_ids=["LLM02", "LLM05"],
        owasp_top10_ids=["A10"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.HIGH,
                message="Arbitrary protocols/ports in shared mode enable SSRF attacks.",
            )
        return Severity(
            level=SeverityLevel.LOW,
            message="Arbitrary protocols detected; restrict to http/https for production.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        for source_file in analyzer.iter_source_files():
            language_patterns = HTTP_CLIENT_PATTERNS.get(source_file.language, [])
            if not language_patterns:
                continue

            for node in walk_ast(source_file.tree):
                if not isinstance(node, CallNode):
                    continue

                if not _matches_any(node.callee, language_patterns):
                    continue

                for arg in node.arguments:
                    if _is_string_literal(arg):
                        url_lower = arg.value.lower()
                        for scheme in DANGEROUS_URL_SCHEMES:
                            if url_lower.startswith(scheme):
                                yield Finding(
                                    rule_id=self.metadata.rule_id,
                                    message=f"Dangerous URL scheme detected: `{scheme}` in `{node.callee}` call.",
                                    file_path=_relative_path(source_file.path, context.project_root),
                                    line=node.line,
                                    category=self.metadata.category,
                                    severity=severity,
                                    why_it_matters="Arbitrary URL schemes enable SSRF and local file access attacks.",
                                    recommendation="Restrict URL schemes to http/https and validate hostnames.",
                                    owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                                    owasp_top10_ids=self.metadata.owasp_top10_ids,
                                    ml_top10_ids=self.metadata.ml_top10_ids,
                                )


class ArbitraryFileAccessRule(Rule):
    """Detect tools that read/write arbitrary paths based on untrusted input."""
    metadata = RuleMetadata(
        rule_id="RCE002",
        name="Arbitrary File Access",
        category="RCE / Excessive Rights",
        description="Detect tools that read/write arbitrary paths based on untrusted input.",
        owasp_llm_top10_ids=["LLM04"],
        owasp_top10_ids=["A01"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.HIGH,
                message="Arbitrary file access in shared mode enables path traversal attacks.",
            )
        return Severity(
            level=SeverityLevel.LOW,
            message="Arbitrary file access detected; consider path allow-lists for production.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        for source_file in analyzer.iter_source_files():
            language_patterns = FILE_ACCESS_PATTERNS.get(source_file.language, [])
            if not language_patterns:
                continue

            for node in walk_ast(source_file.tree):
                if not isinstance(node, CallNode):
                    continue

                if not _matches_any(node.callee, language_patterns):
                    continue

                if node.arguments:
                    path_arg = node.arguments[0]
                    if not _is_string_literal(path_arg):
                        # Dynamic path - heuristic: non-constant could be user-controlled
                        yield Finding(
                            rule_id=self.metadata.rule_id,
                            message=f"Dynamic file path used in `{node.callee}` call.",
                            file_path=_relative_path(source_file.path, context.project_root),
                            line=node.line,
                            category=self.metadata.category,
                            severity=severity,
                            why_it_matters="Arbitrary file paths enable path traversal attacks and unauthorized file access.",
                            recommendation="Validate and restrict file paths using allow-lists or chroot-like constraints.",
                            owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                            owasp_top10_ids=self.metadata.owasp_top10_ids,
                            ml_top10_ids=self.metadata.ml_top10_ids,
                        )


class NoAuthenticationRule(Rule):
    """Detect MCP endpoints without authentication."""
    metadata = RuleMetadata(
        rule_id="AUTH001",
        name="No Authentication on Powerful Endpoints",
        category="AuthN / AuthZ & Multi-Tenancy",
        description="Detect MCP server endpoints that run tools, manage configs, or access secrets with no auth checks.",
        owasp_llm_top10_ids=["LLM07"],
        owasp_top10_ids=["A01", "A07"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.HIGH,
                message="Missing authentication in shared mode allows unauthorized access.",
            )
        return Severity(
            level=SeverityLevel.INFO,
            message="Endpoints without authentication; add auth for production deployments.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        for source_file in analyzer.iter_source_files():
            content = source_file.content.lower()
            
            # Look for endpoint definitions without auth
            has_endpoints = any(x in content for x in ["@app.route", "@router", "def handle", "async def", "endpoint"])
            has_auth = any(x in content for x in ["@require_auth", "@authenticate", "check_auth", "verify_token", "jwt", "oauth"])
            
            if has_endpoints and not has_auth:
                # Check if it's a tool/secret/config endpoint
                is_powerful = any(x in content for x in ["tool", "secret", "config", "admin"])
                if is_powerful:
                    yield Finding(
                        rule_id=self.metadata.rule_id,
                        message="Powerful endpoint found without apparent authentication checks.",
                        file_path=_relative_path(source_file.path, context.project_root),
                        line=None,
                        category=self.metadata.category,
                        severity=severity,
                        why_it_matters="Endpoints without authentication allow unauthorized access to tools and secrets.",
                        recommendation="Add authentication middleware or decorators to protect endpoints.",
                        owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                        owasp_top10_ids=self.metadata.owasp_top10_ids,
                        ml_top10_ids=self.metadata.ml_top10_ids,
                    )


class MissingTenantIsolationRule(Rule):
    """Detect shared storage without tenant scoping."""
    metadata = RuleMetadata(
        rule_id="AUTH002",
        name="Missing Per-Tenant Isolation",
        category="AuthN / AuthZ & Multi-Tenancy",
        description="Detect shared storage without tenant scoping (e.g. single bucket / dir).",
        owasp_llm_top10_ids=["LLM07"],
        owasp_top10_ids=["A01"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.MEDIUM,
                message="Missing tenant isolation in shared mode allows data leakage between users.",
            )
        return Severity(
            level=SeverityLevel.INFO,
            message="Shared storage detected; consider tenant scoping for multi-tenant deployments.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        for source_file in analyzer.iter_source_files():
            content = source_file.content.lower()
            
            # Look for storage operations without tenant context
            has_storage = any(x in content for x in ["bucket", "database", "storage", "s3", "gcs", "azure"])
            has_tenant = any(x in content for x in ["tenant", "user_id", "organization", "scope", "namespace"])
            
            if has_storage and not has_tenant:
                yield Finding(
                    rule_id=self.metadata.rule_id,
                    message="Storage operations found without apparent tenant scoping.",
                    file_path=_relative_path(source_file.path, context.project_root),
                    line=None,
                    category=self.metadata.category,
                    severity=severity,
                    why_it_matters="Shared storage without tenant isolation allows data leakage between users.",
                    recommendation="Implement tenant scoping using user_id, organization, or namespace prefixes.",
                    owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                    owasp_top10_ids=self.metadata.owasp_top10_ids,
                    ml_top10_ids=self.metadata.ml_top10_ids,
                )


class HardcodedTrustedUsersRule(Rule):
    """Detect hard-coded trusted users or bypass flags."""
    metadata = RuleMetadata(
        rule_id="AUTH003",
        name="Hard-coded Trusted Users Logic",
        category="AuthN / AuthZ & Multi-Tenancy",
        description="Detect magic usernames/IDs in code (admin, test) or bypass flags.",
        owasp_llm_top10_ids=["LLM07"],
        owasp_top10_ids=["A01"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.HIGH,
                message="Hard-coded trusted users in shared mode create security bypasses.",
            )
        return Severity(
            level=SeverityLevel.LOW,
            message="Hard-coded user logic found; remove for production deployments.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        trusted_patterns = [
            (r"user.*==.*['\"]admin['\"]", "Hard-coded admin user"),
            (r"user.*==.*['\"]test['\"]", "Hard-coded test user"),
            (r"bypass.*=.*true", "Bypass flag"),
            (r"skip.*auth", "Skip auth"),
        ]
        
        import re
        for source_file in analyzer.iter_source_files():
            content = source_file.content
            
            for pattern, desc in trusted_patterns:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                for match in matches:
                    line_no = content[:match.start()].count("\n") + 1
                    yield Finding(
                        rule_id=self.metadata.rule_id,
                        message=f"{desc} detected: `{match.group(0)}`.",
                        file_path=_relative_path(source_file.path, context.project_root),
                        line=line_no,
                        category=self.metadata.category,
                        severity=severity,
                        why_it_matters="Hard-coded trusted users or bypass flags create security vulnerabilities.",
                        recommendation="Remove hard-coded user logic and use proper authentication/authorization systems.",
                        owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                        owasp_top10_ids=self.metadata.owasp_top10_ids,
                        ml_top10_ids=self.metadata.ml_top10_ids,
                    )


class InsecureHttpRule(Rule):
    """Detect insecure HTTP usage in shared mode."""
    metadata = RuleMetadata(
        rule_id="TRANSPORT001",
        name="Insecure HTTP",
        category="Config & Transport Security",
        description="Detect MCP API / callbacks / tool endpoints using plain HTTP in shared mode.",
        owasp_llm_top10_ids=["LLM09"],
        owasp_top10_ids=["A02"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.HIGH,
                message="Plain HTTP in shared mode exposes traffic to interception.",
            )
        return Severity(
            level=SeverityLevel.INFO,
            message="Plain HTTP detected; use HTTPS for production deployments.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        for source_file in analyzer.iter_source_files():
            content = source_file.content
            
            # Look for http:// URLs (not https://)
            import re
            http_matches = list(re.finditer(r"http://[^\s\"']+", content))
            for match in http_matches:
                line_no = content[:match.start()].count("\n") + 1
                yield Finding(
                    rule_id=self.metadata.rule_id,
                    message=f"Insecure HTTP URL detected: `{match.group(0)[:50]}`.",
                    file_path=_relative_path(source_file.path, context.project_root),
                    line=line_no,
                    category=self.metadata.category,
                    severity=severity,
                    why_it_matters="Plain HTTP exposes traffic to interception and man-in-the-middle attacks.",
                    recommendation="Use HTTPS for all external communications in production.",
                    owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                    owasp_top10_ids=self.metadata.owasp_top10_ids,
                    ml_top10_ids=self.metadata.ml_top10_ids,
                )


class PermissiveCorsRule(Rule):
    """Detect overly permissive CORS configuration."""
    metadata = RuleMetadata(
        rule_id="TRANSPORT002",
        name="Overly Permissive CORS",
        category="Config & Transport Security",
        description="Detect overly permissive CORS (* with credentials) or missing CSRF protection.",
        owasp_llm_top10_ids=["LLM09"],
        owasp_top10_ids=["A05"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.MEDIUM,
                message="Permissive CORS in shared mode enables cross-origin attacks.",
            )
        return Severity(
            level=SeverityLevel.INFO,
            message="Permissive CORS detected; restrict for production deployments.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        for source_file in analyzer.iter_source_files():
            content = source_file.content.lower()
            
            # Look for permissive CORS patterns
            if "cors" in content or "cross-origin" in content:
                if "*" in content and "credentials" in content:
                    line_no = content.count("\n") // 2  # Approximate
                    yield Finding(
                        rule_id=self.metadata.rule_id,
                        message="Overly permissive CORS: wildcard with credentials.",
                        file_path=_relative_path(source_file.path, context.project_root),
                        line=line_no,
                        category=self.metadata.category,
                        severity=severity,
                        why_it_matters="Permissive CORS with credentials enables cross-origin attacks.",
                        recommendation="Restrict CORS to specific origins and avoid wildcard with credentials.",
                        owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                        owasp_top10_ids=self.metadata.owasp_top10_ids,
                        ml_top10_ids=self.metadata.ml_top10_ids,
                    )


class NoTimeoutRule(Rule):
    """Detect missing timeouts on HTTP calls."""
    metadata = RuleMetadata(
        rule_id="RESOURCE001",
        name="No Timeout on HTTP Calls",
        category="Resource Abuse / Unbounded Consumption",
        description="Detect HTTP calls without timeout configuration.",
        owasp_llm_top10_ids=["LLM10"],
        owasp_top10_ids=["A05"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.MEDIUM,
                message="Missing timeouts in shared mode enable DoS attacks.",
            )
        return Severity(
            level=SeverityLevel.LOW,
            message="HTTP calls without timeouts; add timeout configuration.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        for source_file in analyzer.iter_source_files():
            language_patterns = HTTP_CLIENT_PATTERNS.get(source_file.language, [])
            if not language_patterns:
                continue

            for node in walk_ast(source_file.tree):
                if not isinstance(node, CallNode):
                    continue

                if not _matches_any(node.callee, language_patterns):
                    continue

                has_timeout = "timeout" in node.keyword_arguments
                if not has_timeout:
                    yield Finding(
                        rule_id=self.metadata.rule_id,
                        message=f"HTTP call without timeout: `{node.callee}`.",
                        file_path=_relative_path(source_file.path, context.project_root),
                        line=node.line,
                        category=self.metadata.category,
                        severity=severity,
                        why_it_matters="HTTP calls without timeouts can hang indefinitely, enabling DoS attacks.",
                        recommendation="Add timeout parameter to all HTTP calls.",
                        owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                        owasp_top10_ids=self.metadata.owasp_top10_ids,
                        ml_top10_ids=self.metadata.ml_top10_ids,
                    )


class NoInputSizeLimitRule(Rule):
    """Detect missing input size limits for file-processing tools."""
    metadata = RuleMetadata(
        rule_id="RESOURCE002",
        name="No Input Size Limits",
        category="Resource Abuse / Unbounded Consumption",
        description="Detect file-processing tools without input size limits.",
        owasp_llm_top10_ids=["LLM10"],
        owasp_top10_ids=["A05"],
        ml_top10_ids=[],
    )

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        if mode is ScanMode.SHARED:
            return Severity(
                level=SeverityLevel.MEDIUM,
                message="Missing input size limits in shared mode enable DoS attacks.",
            )
        return Severity(
            level=SeverityLevel.LOW,
            message="File processing without size limits; add input validation.",
        )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        analyzer = context.analyzer
        severity = self.severity_for_mode(context.mode)

        for source_file in analyzer.iter_source_files():
            content = source_file.content.lower()
            
            # Look for file processing operations
            has_file_ops = any(x in content for x in ["read(", "open(", "upload", "process_file"])
            has_size_check = any(x in content for x in ["size", "length", "limit", "max", "mb", "kb"])
            
            if has_file_ops and not has_size_check:
                yield Finding(
                    rule_id=self.metadata.rule_id,
                    message="File processing operation found without apparent size limits.",
                    file_path=_relative_path(source_file.path, context.project_root),
                    line=None,
                    category=self.metadata.category,
                    severity=severity,
                    why_it_matters="File processing without size limits enables DoS attacks via large file uploads.",
                    recommendation="Add input size validation and limits for file-processing operations.",
                    owasp_llm_top10_ids=self.metadata.owasp_llm_top10_ids,
                    owasp_top10_ids=self.metadata.owasp_top10_ids,
                    ml_top10_ids=self.metadata.ml_top10_ids,
                )


def all_rules() -> List[Rule]:
    return [
        # RCE / Excessive Rights
        DangerousShellExecutionRule(),
        ArbitraryFileAccessRule(),
        # SSRF & Network Access
        UserControlledHttpRule(),
        ArbitraryPortProtocolRule(),
        # Sensitive Data Exposure
        RepositorySecretRule(),
        OverLoggingRule(),
        UnredactedInternalUrlsRule(),
        # Prompt Injection & Excessive Agency
        UnconstrainedToolExecutionRule(),
        MissingGuardrailsRule(),
        SystemPromptLeakageRule(),
        # AuthN / AuthZ
        NoAuthenticationRule(),
        MissingTenantIsolationRule(),
        HardcodedTrustedUsersRule(),
        # Transport Security
        InsecureHttpRule(),
        PermissiveCorsRule(),
        # Resource Abuse
        NoTimeoutRule(),
        NoInputSizeLimitRule(),
    ]
