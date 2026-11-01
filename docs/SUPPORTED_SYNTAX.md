# Supported JavaScript Syntax

CodeUnveil utilizes `esprima` v4.0+ for AST mapping and custom AST Generators for Source Reconstruction.

## Fully Supported
* **ES5 / ES6 (ES2015)**: Variables (`let`, `const`), Arrow Functions, Template Literals, Destructuring, Spread Syntax.
* **Control Flow**: `if`, `while`, `do-while`, `for`, `for-in`, `for-of`, `switch`, `try-catch`.
* **Classes & Modules**: `class` structures, `import`, `export`, `require`, `module.exports`.

## Conservatively Handled (Partially Supported)
* **Async / Await / Generators**: Handled safely in the AST, but Symbolic Execution (`sym_engine.py`) currently treats asynchronous bounds as "Unknown" constraints to prevent state-explosion.
* **BigInt & Optional Chaining**: Modern ES2021+ syntax may trigger parser tolerance fallbacks depending on the exact token layout. The engine will gracefully reject and isolate the node rather than crashing.

## Unsupported
* Non-Standard JSX (unless heavily sanitized).
* TypeScript Type Annotations (Must be compiled to JS before uploading to CodeUnveil).
