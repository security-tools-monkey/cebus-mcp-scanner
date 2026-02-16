# Multi-Language Support Design Plan

## Executive Summary

This document outlines the architectural changes needed to extend the MCP scanner from Python-only to support multiple languages (Python, JavaScript, TypeScript, Go) while keeping rules language-agnostic and minimizing changes to existing rule logic.

## Current Architecture Analysis

### Current Limitations

1. **Language-Specific Analyzer Interface**
   - Python-only helper methods for file iteration and AST access
   - Rules directly call these Python-specific helpers

2. **Direct AST Dependency**
   - Rules use Python's `ast` module directly (`ast.Call`, `ast.Constant`, `ast.walk()`)
   - Rules access Python-specific AST attributes (`node.lineno`, `node.func`, `node.args`)

3. **Hardcoded Language Patterns**
   - Rules check Python-specific patterns (`os.system`, `subprocess.run`, `requests.get`)
   - No abstraction for language-specific function/module naming

### Current Rule Patterns

Rules typically follow this pattern:

```python
for source_file in analyzer.get_files_by_language("python"):
    for node in ast.walk(source_file.tree):
        if isinstance(node, ast.Call):
            target_name = self._get_full_name(node.func)
            # Check against Python-specific patterns
```

## Design Goals

1. **Language-Agnostic Rules**: Rules should work across languages without language-specific code
2. **Minimal Rule Changes**: Refactor rules to use abstract interfaces, not rewrite them
3. **Extensibility**: Easy to add new languages in the future
4. **Backward Compatibility**: Existing Python scanning continues to work
5. **Configurable**: Allow users to specify languages or auto-detect

## Proposed Architecture

### 1. Unified AST Abstraction Layer

Create a language-agnostic AST node hierarchy that all language parsers map to:

```python
# mcp_scanner/ast_common.py

@dataclass
class SourceFile:
    """Unified representation of a source file."""
    path: Path
    content: str
    language: str  # "python", "javascript", "typescript", "go"
    tree: "ASTNode"  # Root of unified AST

@dataclass
class ASTNode:
    """Base class for all AST nodes."""
    node_type: str  # "call", "literal", "variable", "import", etc.
    line: int | None
    column: int | None
    parent: "ASTNode | None" = None

@dataclass
class CallNode(ASTNode):
    """Represents a function/method call."""
    callee: str  # Full qualified name: "os.system", "child_process.exec", "exec.Command"
    arguments: List["ASTNode"]
    language: str  # Original language for context

@dataclass
class LiteralNode(ASTNode):
    """Represents a literal value."""
    value: Any
    literal_type: str  # "string", "number", "boolean", etc.

@dataclass
class VariableNode(ASTNode):
    """Represents a variable reference."""
    name: str

@dataclass
class ImportNode(ASTNode):
    """Represents an import statement."""
    module: str
    imports: List[str]  # What's imported from the module
```

### 2. Language-Specific Analyzers

Each language gets its own analyzer that implements a unified interface:

```python
# mcp_scanner/analyzers/base.py

class LanguageAnalyzer(abc.ABC):
    """Base class for language-specific analyzers."""
    
    @property
    @abc.abstractmethod
    def language(self) -> str:
        """Return language identifier: 'python', 'javascript', etc."""
    
    @abc.abstractmethod
    def iter_source_files(self) -> Iterable[str]:
        """Iterate over source files for this language."""
    
    @abc.abstractmethod
    def load_source_file(self, path: str) -> SourceFile:
        """Load and parse a source file, returning unified AST."""
    
    @abc.abstractmethod
    def parse_to_unified_ast(self, content: str, path: str) -> ASTNode:
        """Convert language-specific AST to unified AST."""
```

**Language-Specific Implementations:**

- `PythonAnalyzer`: Maps Python AST → Unified AST
- `JavaScriptAnalyzer`: Uses `esprima` or `tree-sitter` → Unified AST  
- `TypeScriptAnalyzer`: Uses `typescript` parser → Unified AST
- `GoAnalyzer`: Uses `go/ast` via `go/parser` or tree-sitter → Unified AST

### 3. Multi-Analyzer Context

Scanner uses multiple analyzers and provides unified interface to rules:

```python
# mcp_scanner/analyzers/multi_analyzer.py

class MultiLanguageAnalyzer:
    """Orchestrates multiple language analyzers."""
    
    def __init__(self, root: str, languages: List[str] | None = None):
        self.root = Path(root)
        self.analyzers: List[LanguageAnalyzer] = []
        
        # Auto-detect or use specified languages
        if languages:
            self._init_analyzers(languages)
        else:
            self._auto_detect_languages()
    
    def iter_all_source_files(self) -> Iterable[SourceFile]:
        """Iterate over all source files across all languages."""
        for analyzer in self.analyzers:
            for path in analyzer.iter_source_files():
                yield analyzer.load_source_file(path)
    
    def get_files_by_language(self, language: str) -> Iterable[SourceFile]:
        """Get files for a specific language."""
        analyzer = next((a for a in self.analyzers if a.language == language), None)
        if analyzer:
            for path in analyzer.iter_source_files():
                yield analyzer.load_source_file(path)
```

### 4. Updated Analyzer Interface

Replace Python-specific `Analyzer` with language-agnostic interface:

```python
# mcp_scanner/rules/base.py

class Analyzer(abc.ABC):
    """Language-agnostic analyzer interface."""
    
    @abc.abstractmethod
    def iter_source_files(self) -> Iterable[SourceFile]:
        """Iterate over all source files (all languages)."""
    
    @abc.abstractmethod
    def get_files_by_language(self, language: str) -> Iterable[SourceFile]:
        """Get files for a specific language."""
    
    @abc.abstractmethod
    def open_file(self, path: str) -> str:
        """Get raw file content."""
```

### 5. Rule Refactoring Strategy

**Pattern 1: Direct AST Traversal → Unified AST**

Before:

```python
for source_file in analyzer.get_files_by_language("python"):
    for node in ast.walk(source_file.tree):
        if isinstance(node, ast.Call):
            target_name = self._get_full_name(node.func)
```

After:

```python
for source_file in analyzer.iter_source_files():
    for node in self._walk_ast(source_file.tree):
        if isinstance(node, CallNode):
            callee = node.callee
```

**Pattern 2: Language-Specific Patterns → Language-Agnostic Patterns**

Create a pattern matching system:

```python
# mcp_scanner/patterns.py

SHELL_EXECUTION_PATTERNS = {
    "python": ["os.system", "os.popen", "subprocess.run", "subprocess.Popen"],
    "javascript": ["child_process.exec", "child_process.spawn", "execSync"],
    "typescript": ["child_process.exec", "child_process.spawn", "execSync"],
    "go": ["os/exec.Command", "exec.Command", "exec.Run"],
}

HTTP_CLIENT_PATTERNS = {
    "python": ["requests.get", "httpx.get", "urllib.urlopen"],
    "javascript": ["fetch", "axios.get", "http.get", "https.get"],
    "typescript": ["fetch", "axios.get", "http.get", "https.get"],
    "go": ["http.Get", "http.Post", "http.Client.Get"],
}
```

Rules use patterns:

```python
patterns = SHELL_EXECUTION_PATTERNS.get(source_file.language, [])
if node.callee in patterns:
    yield Finding(...)
```

**Pattern 3: Helper Methods for Common Operations**

Create utility methods that work across languages:

```python
# mcp_scanner/rules/base.py

class Rule(abc.ABC):
    # ... existing code ...
    
    def _walk_ast(self, node: ASTNode) -> Iterable[ASTNode]:
        """Recursively walk unified AST."""
        yield node
        for child in getattr(node, 'children', []):
            yield from self._walk_ast(child)
    
    def _is_constant(self, node: ASTNode) -> bool:
        """Check if node is a constant literal."""
        return isinstance(node, LiteralNode)
    
    def _is_dynamic(self, node: ASTNode) -> bool:
        """Check if node is dynamic (not constant)."""
        return not self._is_constant(node)
```

### 6. Language Detection

```python
# mcp_scanner/analyzers/language_detector.py

def detect_languages(root: Path) -> List[str]:
    """Auto-detect languages in project."""
    languages = []
    
    # Check for language-specific files
    if any(root.rglob("*.py")):
        languages.append("python")
    if any(root.rglob("*.js")) and not any(root.rglob("tsconfig.json")):
        languages.append("javascript")
    if any(root.rglob("*.ts")) or any(root.rglob("tsconfig.json")):
        languages.append("typescript")
    if any(root.rglob("*.go")):
        languages.append("go")
    
    return languages or ["python"]  # Default fallback
```

### 7. Configuration Extensions

```python
# mcp_scanner/config.py

@dataclass
class ScannerConfig:
    # ... existing fields ...
    languages: List[str] | None = None  # None = auto-detect
    language_patterns: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    # Allows per-language pattern customization
```

## Implementation Phases

### Phase 1: Foundation (Week 1)
1. Create unified AST node classes (`ast_common.py`)
2. Create `LanguageAnalyzer` base class
3. Refactor `PythonAnalyzer` to implement new interface
4. Create `MultiLanguageAnalyzer` orchestrator
5. Update `ScanContext` to use new analyzer interface

### Phase 2: Python Migration (Week 1-2)
1. Create Python → Unified AST mapper
2. Update `Scanner` to use `MultiLanguageAnalyzer`
3. Refactor 2-3 simple rules as proof of concept
4. Ensure backward compatibility

### Phase 3: JavaScript/TypeScript Support (Week 2-3)
1. Implement `JavaScriptAnalyzer` (using `esprima` or `tree-sitter`)
2. Implement `TypeScriptAnalyzer`
3. Create JS/TS → Unified AST mappers
4. Test with real JS/TS projects

### Phase 4: Go Support (Week 3-4)
1. Implement `GoAnalyzer` (using `go/parser` or tree-sitter)
2. Create Go → Unified AST mapper
3. Test with real Go projects

### Phase 5: Rule Migration (Week 4-5)
1. Refactor all remaining rules to use unified AST
2. Extract language-specific patterns to configuration
3. Update tests for multi-language scenarios
4. Performance optimization

### Phase 6: Documentation & Polish (Week 5)
1. Update architecture documentation
2. Add language detection documentation
3. Create migration guide for custom rules
4. Performance benchmarking

## Key Design Decisions

### Decision 1: Unified AST vs. Language-Specific ASTs

**Chosen: Unified AST**
- **Pros**: Rules become truly language-agnostic, easier to maintain
- **Cons**: Some language-specific features may be lost in translation
- **Mitigation**: Include `language` field in nodes for context, allow access to raw AST if needed

### Decision 2: Pattern Matching Strategy

**Chosen: Configuration-Based Patterns**
- **Pros**: Easy to extend, users can customize patterns
- **Cons**: Requires maintaining pattern lists
- **Mitigation**: Ship with comprehensive defaults, allow overrides

### Decision 3: Backward Compatibility

**Chosen: Maintain Python-First Compatibility**
- **Pros**: Existing code continues to work
- **Cons**: Some technical debt
- **Mitigation**: Deprecate old methods gradually, provide migration path

### Decision 4: Parser Libraries

**Chosen:**
- **Python**: Keep `ast` module (stdlib)
- **JavaScript/TypeScript**: `tree-sitter` (unified API, good performance)
- **Go**: `tree-sitter-go` or `go/parser` via subprocess

**Rationale**: `tree-sitter` provides consistent API across languages, good error recovery, incremental parsing.

## Example: Refactored Rule

### Before (Python-Specific)

```python
def scan(self, context: ScanContext) -> Iterable[Finding]:
    analyzer = context.analyzer
    for source_file in analyzer.get_files_by_language("python"):
        for node in ast.walk(source_file.tree):
            if isinstance(node, ast.Call):
                target_name = self._get_full_name(node.func)
                if target_name in {"os.system", "subprocess.run"}:
                    yield Finding(...)
```

### After (Language-Agnostic)

```python
def scan(self, context: ScanContext) -> Iterable[Finding]:
    analyzer = context.analyzer
    patterns = SHELL_EXECUTION_PATTERNS
    
    for source_file in analyzer.iter_source_files():
        language_patterns = patterns.get(source_file.language, [])
        for node in self._walk_ast(source_file.tree):
            if isinstance(node, CallNode):
                if node.callee in language_patterns:
                    yield Finding(
                        file_path=str(source_file.path.relative_to(context.project_root)),
                        line=node.line,
                        ...
                    )
```

## Testing Strategy

1. **Unit Tests**: Test each language analyzer independently
2. **Integration Tests**: Test rules with multi-language projects
3. **Regression Tests**: Ensure Python scanning still works
4. **Pattern Tests**: Verify pattern matching across languages
5. **Performance Tests**: Compare single vs. multi-language scanning

## Migration Path for Existing Rules

1. Rules continue to work during transition (backward compatibility)
2. Provide helper methods to ease migration
3. Gradual migration: start with simple rules, then complex ones
4. Document migration examples

## Open Questions

1. **Regex-based rules** (like `RepositorySecretRule`): Should these remain language-agnostic by design, or need language-specific regex patterns?
   - **Answer**: Keep regex-based rules as-is (they already work across languages)

2. **Content-based rules** (like `MissingGuardrailsRule`): These search for keywords in content - should they be language-aware?
   - **Answer**: Make keyword lists language-configurable but keep logic the same

3. **Performance**: Will multi-language scanning be significantly slower?
   - **Answer**: Likely minimal impact; analyzers run in parallel where possible, tree-sitter is fast

4. **Error Handling**: What if a language parser fails?
   - **Answer**: Log error, continue with other languages, emit finding if critical

## Success Criteria

1. ✅ All existing Python rules work unchanged
2. ✅ Rules can scan JavaScript/TypeScript/Go projects
3. ✅ Same rule logic works across all languages
4. ✅ Performance impact < 20% for Python-only projects
5. ✅ Language detection works reliably
6. ✅ Configuration allows pattern customization

## Next Steps

1. Review and approve this design
2. Create implementation tickets
3. Set up development environment with tree-sitter dependencies
4. Begin Phase 1 implementation

