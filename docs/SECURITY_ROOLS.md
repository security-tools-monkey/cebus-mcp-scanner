# Security Rules

## Rule List With Descriptions And Algorithms

1. **RCE001 - Unbounded Shell Execution**
    - Description: Detect use of subprocess or os.system that may allow shell execution.
    - Algorithm: Walk the AST for call nodes that match shell execution patterns per language and emit a finding for each match.
2. **RCE002 - Arbitrary File Access**
    - Description: Detect tools that read/write arbitrary paths based on untrusted input.
    - Algorithm: Find file access calls and flag when the first path argument is not a string literal.
3. **SSRF001 - HTTP Client Without Allow-List**
    - Description: Detect HTTP requests using dynamic URLs without validation.
    - Algorithm: Find HTTP client calls, then flag calls where the first URL argument is not a string literal.
4. **SSRF002 - Arbitrary Port / Protocol**
    - Description: Flag tools that allow arbitrary schemes (ftp, file, gopher) or connect to RFC1918 ranges without restriction.
    - Algorithm: Find HTTP client calls and flag when a string literal URL argument uses a dangerous scheme.
5. **SENS001 - Secrets in Repository**
    - Description: Detect potential secrets committed in repository files.
    - Algorithm: Run regex patterns across file contents and emit a finding for each match with the matched line number.
6. **SENS002 - Over-Logging of Sensitive Data**
    - Description: Detect logging of full prompts, tool request bodies, or environment variables.
    - Algorithm: Regex-scan file contents for logging patterns that include prompts, request bodies, env vars, passwords, or tokens.
7. **SENS003 - Unredacted Internal URLs / Paths**
    - Description: Detect canned responses that echo internal topology.
    - Algorithm: Find localhost or RFC1918 IPs in content and flag when they appear on response/return lines.
8. **PROMPT001 - Unconstrained Tool Execution from Model Output**
    - Description: Detect flows where LLM response is parsed and directly used as shell/HTTP/DB without validation.
    - Algorithm: Identify parse/extract/output-related calls and, if any risky tool calls exist in the same file, emit findings for those parse calls.
9. **PROMPT002 - Missing Guardrails Around Tool-Calling Prompts**
    - Description: Detect tools that can hit internal networks, run commands, or read arbitrary files with no guard prompts.
    - Algorithm: In each file, detect tool definitions without guard keywords and flag if dangerous operations are present.
10. **PROMPT003 - System Prompt / Config Leakage**
    - Description: Detect returning raw system prompts or internal config in error paths / debug endpoints.
    - Algorithm: Search for prompt/config keywords and flag occurrences that appear on return/response lines.
11. **AUTH001 - No Authentication on Powerful Endpoints**
    - Description: Detect MCP server endpoints that run tools, manage configs, or access secrets with no auth checks.
    - Algorithm: Look for endpoint patterns without auth indicators and flag when tool/secret/config/admin keywords are present.
12. **AUTH002 - Missing Per-Tenant Isolation**
    - Description: Detect shared storage without tenant scoping (e.g. single bucket / dir).
    - Algorithm: Flag files that reference storage keywords without any tenant/user/org scoping keywords.
13. **AUTH003 - Hard-coded Trusted Users Logic**
    - Description: Detect magic usernames/IDs in code (admin, test) or bypass flags.
    - Algorithm: Regex-scan for hard-coded admin/test comparisons or bypass/skip auth flags.
14. **TRANSPORT001 - Insecure HTTP**
    - Description: Detect MCP API / callbacks / tool endpoints using plain HTTP in shared mode.
    - Algorithm: Regex-scan for `http://` URLs and emit a finding for each match.
15. **TRANSPORT002 - Overly Permissive CORS**
    - Description: Detect overly permissive CORS (* with credentials) or missing CSRF protection.
    - Algorithm: If CORS is referenced and wildcard plus credentials appear, emit a finding.
16. **RESOURCE001 - No Timeout on HTTP Calls**
    - Description: Detect HTTP calls without timeout configuration.
    - Algorithm: Find HTTP client calls and flag those without a `timeout` keyword argument.
17. **RESOURCE002 - No Input Size Limits**
    - Description  : Detect file-processing tools without input size limits.
    - Algorithm: Flag files that contain file operations but no size/limit keywords.

## Rules Table

| rule_id | name | category | description | owasp_llm_top10_ids | owasp_top10_ids |
| --- | --- | --- | --- | --- | --- |
| RCE001 | Unbounded Shell Execution | RCE / Excessive Rights | Detect use of subprocess or os.system that may allow shell execution. | LLM04 | A01 |
| RCE002 | Arbitrary File Access | RCE / Excessive Rights | Detect tools that read/write arbitrary paths based on untrusted input. | LLM04 | A01 |
| SSRF001 | HTTP Client Without Allow-List | SSRF & Network Access | Detect HTTP requests using dynamic URLs without validation. | LLM02, LLM05 | A10 |
| SSRF002 | Arbitrary Port / Protocol | SSRF & Network Access | Flag tools that allow arbitrary schemes (ftp, file, gopher) or connect to RFC1918 ranges without restriction. | LLM02, LLM05 | A10 |
| SENS001 | Secrets in Repository | Sensitive Data Exposure | Detect potential secrets committed in repository files. | LLM06 | A02 |
| SENS002 | Over-Logging of Sensitive Data | Sensitive Data Exposure | Detect logging of full prompts, tool request bodies, or environment variables. | LLM06 | A02 |
| SENS003 | Unredacted Internal URLs / Paths | Sensitive Data Exposure | Detect canned responses that echo internal topology. | LLM06 | A02 |
| PROMPT001 | Unconstrained Tool Execution from Model Output | Prompt Injection & Excessive Agency | Detect flows where LLM response is parsed and directly used as shell/HTTP/DB without validation. | LLM01, LLM05 | A03 |
| PROMPT002 | Missing Guardrails Around Tool-Calling Prompts | Prompt Injection & Excessive Agency | Detect tools that can hit internal networks, run commands, or read arbitrary files with no guard prompts. | LLM01, LLM05 | A03 |
| PROMPT003 | System Prompt / Config Leakage | Prompt Injection & Excessive Agency | Detect returning raw system prompts or internal config in error paths / debug endpoints. | LLM08 | A01 |
| AUTH001 | No Authentication on Powerful Endpoints | AuthN / AuthZ & Multi-Tenancy | Detect MCP server endpoints that run tools, manage configs, or access secrets with no auth checks. | LLM07 | A01, A07 |
| AUTH002 | Missing Per-Tenant Isolation | AuthN / AuthZ & Multi-Tenancy | Detect shared storage without tenant scoping (e.g. single bucket / dir). | LLM07 | A01 |
| AUTH003 | Hard-coded Trusted Users Logic | AuthN / AuthZ & Multi-Tenancy | Detect magic usernames/IDs in code (admin, test) or bypass flags. | LLM07 | A01 |
| TRANSPORT001 | Insecure HTTP | Config & Transport Security | Detect MCP API / callbacks / tool endpoints using plain HTTP in shared mode. | LLM09 | A02 |
| TRANSPORT002 | Overly Permissive CORS | Config & Transport Security | Detect overly permissive CORS (* with credentials) or missing CSRF protection. | LLM09 | A05 |
| RESOURCE001 | No Timeout on HTTP Calls | Resource Abuse / Unbounded Consumption | Detect HTTP calls without timeout configuration. | LLM10 | A05 |
| RESOURCE002 | No Input Size Limits | Resource Abuse / Unbounded Consumption | Detect file-processing tools without input size limits. | LLM10 | A05 |

## OWASP Top 10 Mapping

| owasp_top10_id | mapped_rules |
| --- | --- |
| A01 | RCE001, RCE002, PROMPT003, AUTH001, AUTH002, AUTH003 |
| A02 | SENS001, SENS002, SENS003, TRANSPORT001 |
| A03 | PROMPT001, PROMPT002 |
| A04 |  |
| A05 | TRANSPORT002, RESOURCE001, RESOURCE002 |
| A06 |  |
| A07 | AUTH001 |
| A08 |  |
| A09 |  |
| A10 | SSRF001, SSRF002 |

## OWASP LLM Top 10 Mapping

| owasp_llm_top10_id | mapped_rules |
| --- | --- |
| LLM01 | PROMPT001, PROMPT002 |
| LLM02 | SSRF001, SSRF002 |
| LLM03 |  |
| LLM04 | RCE001, RCE002 |
| LLM05 | SSRF001, SSRF002, PROMPT001, PROMPT002 |
| LLM06 | SENS001, SENS002, SENS003 |
| LLM07 | AUTH001, AUTH002, AUTH003 |
| LLM08 | PROMPT003 |
| LLM09 | TRANSPORT001, TRANSPORT002 |
| LLM10 | RESOURCE001, RESOURCE002 |
