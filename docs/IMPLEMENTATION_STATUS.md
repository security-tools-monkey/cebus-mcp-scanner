# Multi-Language Support Implementation Status

## ✅ Completed: Phase 1–3 (Foundation + Python Migration + JS/TS)

### Phase 1: Foundation ✅

1. **Unified AST Abstraction** (`mcp_scanner/ast_common.py`)
   - Created language-agnostic AST node types:
     - `ASTNode` (base class)
     - `CallNode`, `LiteralNode`, `VariableNode`
     - `ImportNode`, `AssignmentNode`, `BinaryOpNode`, `AttributeNode`
   - `SourceFile` class for unified file representation
   - `walk_ast()` utility for traversing unified AST

2. **Language Analyzer Base** (`mcp_scanner/analyzers/base.py`)
   - `LanguageAnalyzer` abstract base class
   - Defines interface: `language`, `iter_source_files()`, `load_source_file()`, `parse_to_unified_ast()`

3. **Language Detection** (`mcp_scanner/analyzers/language_detector.py`)
   - Auto-detection of languages by file extensions and config files
   - Supports: Python, JavaScript, TypeScript, Go
   - Rust is not auto-detected (no `.rs`/`Cargo.toml` checks yet)
   - Excludes build/dependency directories

4. **Multi-Language Analyzer** (`mcp_scanner/analyzers/multi_analyzer.py`)
   - `MultiLanguageAnalyzer` orchestrates multiple language analyzers
   - Auto-detects or accepts explicit language list
   - Provides unified interface: `iter_all_source_files()`, `get_files_by_language()`

5. **Updated Analyzer Interface** (`mcp_scanner/rules/base.py`)
   - Unified `Analyzer` base class for multi-language scanning
   - No Python-only helper methods remain on the interface

### Phase 2: Python Migration ✅

1. **Python AST Mapper** (`mcp_scanner/analyzers/python_mapper.py`)
   - `PythonASTMapper` converts Python AST → Unified AST
   - Maps all common Python AST node types
   - Handles: calls, literals, variables, imports, assignments, binary ops, attributes

2. **New Python Analyzer** (`mcp_scanner/analyzers/python_analyzer_v2.py`)
   - `PythonAnalyzer` implements `LanguageAnalyzer` interface
   - Uses `PythonASTMapper` to produce unified AST
   - Fully compatible with multi-language system

3. **Updated Scanner** (`mcp_scanner/scanner.py`)
   - Scanner uses `MultiLanguageAnalyzer`
   - Added `languages` parameter for explicit language specification

4. **Pattern System** (`mcp_scanner/patterns.py`)
   - Language-specific pattern dictionaries:
     - `SHELL_EXECUTION_PATTERNS`
     - `HTTP_CLIENT_PATTERNS`
     - `FILE_ACCESS_PATTERNS`
     - `DANGEROUS_URL_SCHEMES`
     - `SECRET_PATTERNS`
   - Ready for JavaScript/TypeScript/Go patterns

5. **Refactored Rules** (Unified pipeline)
   - All 17 rules now run through the unified analyzer interface
   - AST-driven rules: `RCE001`, `RCE002`, `SSRF001`, `SSRF002`, `PROMPT001`, `RESOURCE001`
   - Regex/heuristic rules: `SENS001-003`, `PROMPT002-003`, `AUTH001-003`,
     `TRANSPORT001-002`, `RESOURCE002`

### Phase 3: JavaScript/TypeScript Support ✅

1. **Tree-sitter Integration**
   - Optional extra: `.[js_ts]`
   - JS/TS parsing enabled when the extra is installed

2. **JS/TS Analyzers**
   - `JavaScriptAnalyzer` and `TypeScriptAnalyzer` implemented via tree-sitter
   - Unified AST mappers for JS/TS node types

3. **Patterns + Tests**
   - JS/TS patterns added to `patterns.py`
   - JS/TS analyzer tests added

## 🔄 Current State

### Working Features
- ✅ Python scanning with unified AST
- ✅ JavaScript/TypeScript scanning (requires `.[js_ts]` extra)
- ✅ Go scanning (requires `.[go]` extra, limited unified AST mapping)
- ✅ Rust scanning (requires `.[rust]` extra, limited unified AST mapping)
- ✅ Auto-detection of project languages (Python/JS/TS/Go only)
- ✅ Multi-language analyzer infrastructure
- ✅ Pattern-based rule logic (ready for other languages)
- ✅ All rules run through the unified analyzer pipeline
- ✅ Zip input support for project scans (with extraction limits)
 
### Current Limitations
- Rust is only analyzed when explicitly requested (not auto-detected).
- JS/TS/Go/Rust mappers are conservative; only a subset of node types are specialized.
- `RESOURCE001` (timeouts) only detects Python keyword arguments; non-Python calls will
  currently be flagged even if timeouts are handled positionally or by defaults.
- Multi-language rule fixtures beyond Python are not yet in the test suite.

## 🧩 Phase 4: Go Support (baseline complete, limited coverage)
1. Decision: use tree-sitter-go via `tree-sitter` + `tree-sitter-languages` (optional `go` extra) ✅
2. `GoAnalyzer` implemented (tree-sitter-go) ✅
3. Go → Unified AST mapper (minimal coverage for calls/selectors/imports/literals) ✅
4. Go patterns added to `patterns.py` ✅
5. Tests cover basic Go analyzer behavior ✅
6. Limitations: mapper is conservative; some node types are not yet specialized, and only a subset of rules are fully validated against Go code

## 🧩 Phase 5: Rust Support (baseline complete, limited coverage)
1. Decision: use tree-sitter-rust via `tree-sitter` + `tree-sitter-languages` (optional `rust` extra) ✅
2. Rust analyzer + mapper implemented (minimal unified AST mapping) ✅
3. Rust patterns added to `patterns.py` ✅
4. Tests cover basic Rust analyzer behavior ✅
5. Limitations: mapper is conservative; some node types are not yet specialized, and only a subset of rules are fully validated against Rust code

## 🧩 Phase 6: Rule Migration + Validation (in progress)
1. Migrate all rules to unified analyzer interface ✅
2. Remove legacy fallback code ✅
3. Validate rules across JS/TS/Go/Rust fixtures 🔄
4. Add multi-language regression fixtures for high-risk rules 🔄
5. Performance optimization 🔄
6. Limitations: rule validation is still Python-heavy; Rust/Go/JS/TS coverage gaps remain

## 📋 Next Steps: Phase 7
1. Validate each rule against Python/JS/TS/Go fixtures
2. Add multi-language regression fixtures for high-risk rules
3. Track gaps and add mapper coverage as needed

## 🧪 Testing

To test the new system:

```python
from mcp_scanner.scanner import Scanner
from mcp_scanner.settings import ScanMode

# New multi-language system (default)
scanner = Scanner()
result = scanner.scan("/path/to/project", ScanMode.SHARED)

# Explicit languages
scanner = Scanner(languages=["python", "javascript"])
result = scanner.scan("/path/to/project", ScanMode.SHARED)
```

## 📝 Notes

- Breaking change (2026-02-16): removed the Python-only analyzer and the `use_legacy_analyzer` flag. The unified multi-language pipeline is now the only supported analysis path.
- Breaking change (2026-02-16): removed Python-only analyzer helper methods from `Analyzer`; external consumers must use the unified API (`iter_source_files()`, `get_files_by_language()`, `open_file()`).

- JavaScript/TypeScript parsing is optional. Without the `js_ts` extra, JS/TS analyzers return an empty module AST and the scan continues for other languages.
- Go parsing will be optional. Without the `go` extra, the Go analyzer will return an empty module AST and scans will continue for other languages.
- Rust parsing is optional. Without the `rust` extra, the Rust analyzer will return an empty module AST and scans will continue for other languages.
- The system is designed to be extensible: adding new languages requires implementing `LanguageAnalyzer` and creating a mapper
- Pattern-based approach makes rules language-agnostic
- Performance impact is minimal: unified AST is created once per file by the language analyzer

## 🐛 Known Issues / Gaps

- Rust is not auto-detected by `language_detector` (requires explicit `languages=["rust"]`).
- Multi-language rule coverage is limited to Python fixtures; JS/TS/Go/Rust rules need dedicated fixtures.
- `RESOURCE001` timeout detection only understands Python keyword arguments.
