# C++ Coding Style Guide

- **Standards:** Use C++20 or C++23 standards.
- **Formatting:** Use 4 spaces for indentation, braces on new lines (Allman style), and `clang-format` if available.
  - **Exception:** Namespace braces should be on the same line as the namespace declaration.
- **Strong Typing:** Always prefer strong typing (e.g., enums, type aliases, class types) over primitive types. Avoid `int`, `void*`, and other weakly-typed parameters unless absolutely necessary. Use `enum class` and custom types for clarity and safety.
 - **Const Declaration Style:** Always declare `const` as `T const t` (not `const T t`) for parameters, variables, and members.
 - **Pointer and reference formatting:** Use the following formatting for pointers and references: `T const &t`, `T &t`, `T *p`, `T const *p`. Place the `const` nearest the type it qualifies (e.g., `T const *p` for pointer-to-const).
 - **Template spacing:** Templates should include a space before the closing angle bracket. Prefer `template< T >` style in code and `std::vector< T >` for instantiations where reasonable to improve readability (e.g., write `<T >` rather than `<T>`).
- **Naming:**
    - **Parameters and local variables:** `snake_case` (all lowercase with underscores)
    - **Members:** `snake_case_` (all lowercase with underscores, ending with underscore)
    - **Types (classes, structs, enums, typedefs, type aliases):** `PascalCase`
      - Acronyms should be all uppercase (e.g., `JWK`, `JWT`, `JSON`, `HTTP`)
    - **Namespaces:** `PascalCase`
    - **Functions (both free and member):** `camelCase` (start lowercase, must begin with a verb)
      - Acronyms stay uppercase within the name (e.g., `toJSON`, `fromJSON`, `generateRSA`)
      - Where only a verb suffices, use only that verb (e.g., `validate` not `validateKey`)
      - Examples: `generateRSA`, `fromJSON`, `toJSON`, `getKeyType`, `setKeyId`, `validate`
    - **Enum constants:** `snake_case` (e.g., `rsa`, `ec`, `signature`, `encryption`)
    - **Global/static constants:** `snake_case` (e.g., `default_timeout`, `max_size`)
    - **Macros:** `UPPER_CASE` (e.g., `#define MAX_BUFFER_SIZE 1024`)
    - **Do not abbreviate common words** (e.g., write `Manager`, `validate`, `implementation`)
      - Exceptions: well-known acronyms like `JSON`, `JWT`, `JWK`, `JWS`, `JWE`, `HTTP`, `URL`
- **Namespaces:**
    - The outer namespace should be `Vlinder`
    - Inner namespaces follow PascalCase naming
    - Namespace braces stay on the same line (not Allman style)
  - **`.cpp` files** must open with `using namespace` directives immediately after the `#include` block (e.g. `using namespace std;`, `using namespace Vlinder::JOSE::Private;`).
  - **In `.cpp` files**, do not qualify names with `std::` (or other imported namespaces) when a corresponding `using namespace`/alias is present. Prefer unqualified names by default.
  - **Exception:** Keep qualification only where unqualified lookup would be ambiguous or incorrect (for example, to avoid ADL/Koenig lookup pitfalls or symbol collisions).
  - For project/third-party namespaces used repeatedly in a `.cpp`, prefer a local namespace alias or `using namespace` (for example, `using json = Vlinder::JOSE::Private::json;`) instead of repeated fully qualified names.
    - **Header files** must never contain `using namespace`. All names must be fully qualified (e.g. `std::vector`, `std::unique_ptr`) to avoid polluting includers' namespaces.
- **Modern C++:**
    - Use `auto` for type deduction when readable.
    - Use `nullptr` instead of `NULL` or `0`.
    - Use range-based for loops.
    - Use smart pointers (`std::unique_ptr`, `std::shared_ptr`) instead of `new`/`delete`.
    - Use `std::string` and `std::vector` instead of C-style arrays.
- **Structure:**
    - Use `#pragma once` for header guards.
    - Organize headers: C++ Standard Library, Third-party, Project headers.
- **Comments:** Use `///` for documentation comments to enable Doxygen formatting.
- **Linting:** This project uses `clang-tidy` to enforce naming conventions. Run before committing.

## Workspace Bootstrap and Environment Conventions

### Windows (PowerShell) — Primary Development Environment

Run `.\Bootstrap.ps1` from the repo root **once per new clone or shell session** before using `cmake` or the linting tools:

```powershell
.\Bootstrap.ps1
```

What it does:
- Detects the active Visual Studio installation via `vswhere.exe` (Visual Studio Community/Professional/Enterprise with C++ workload required).
- Adds the VS LLVM `bin` folder to `$env:Path` for the current session → makes `clang-format` and `clang-tidy` available.
- Adds the VS-bundled CMake `bin` folder to `$env:Path` → makes `cmake` available.
- Adds the OpenSSL `bin` folder to `$env:Path` if OpenSSL is installed at the standard location.
- Writes `CMakeUserPresets.json` with the detected generator (`Visual Studio 18 2026` or similar) and preset names (`vs-latest-x64-debug`, `vs-latest-x64-release`).
- Updates `.vscode/settings.json` with the cmake path, preset, and generator.
- Sets `core.hooksPath` to `.githooks` in git config so pre-commit hooks run automatically.

Optional flags:
```powershell
.\Bootstrap.ps1 -Configure          # also runs cmake --preset vs-latest-x64-debug
.\Bootstrap.ps1 -Configure -Build   # configure + build
.\Bootstrap.ps1 -Configuration Release -Architecture x64
```

After bootstrap, build using:
```powershell
cmake --build .\build\vs-latest-x64-debug\
ctest --test-dir .\build\vs-latest-x64-debug\ --output-on-failure
```

**Important:** `cmake`, `clang-format`, and `clang-tidy` are **only on PATH within the bootstrapped session**. Re-run `.\Bootstrap.ps1` (or source it) in each new terminal. Copilot agent sessions must also call the bootstrap before running any build or lint commands.

### Linux / macOS — CI and Hook Scripts

The `bootstrap` file (no extension, Bash) is intended only for hook scripts; it is not the primary developer bootstrap:

```bash
. ./bootstrap       # source it; never execute it directly
```

- Validates `clang-format`, `clang-tidy`, and (on Linux) `jq` are on `PATH`.
- Returns non-zero with a descriptive message if any tool is missing; never calls `exit`.
- Hook scripts source bootstrap with `CPP_JOSE_BOOTSTRAP_AUTO_CHECK=0` and call `hookBootstrapCheckTools` explicitly.

### Required Tools

| Tool | Windows install | Linux install |
|------|----------------|---------------|
| `clang-format` | VS component "C++ Clang tools for Windows" or `winget install LLVM.LLVM` | `sudo apt-get install clang-format` |
| `clang-tidy` | Same as above | `sudo apt-get install clang-tidy` |
| `cmake` | Bundled with Visual Studio C++ workload | `sudo apt-get install cmake` |
| `jq` | `winget install jqlang.jq` | `sudo apt-get install jq` |
| OpenSSL (Windows) | Standard installer to `C:\Program Files\OpenSSL-Win64\` | System package |

### Generated Files — Do Not Commit

- `CMakeUserPresets.json` — regenerated by `Bootstrap.ps1`; do not commit.
- `.vscode/settings.json` — machine-specific; do not commit.

### Environment File Pattern

- **Secrets handling:** `.env` must remain gitignored. `dot-env` (tracked) contains keys/placeholders only.
- **Sync rule:** When adding required environment variables, update `dot-env` in the same change.
- **Hook integration:** Hook scripts source `bootstrap` with `CPP_JOSE_BOOTSTRAP_AUTO_CHECK=0` then call `hookBootstrapCheckTools` explicitly.

### Known Limitation: JWKSet Pimpl and CLI TUs

`JWKSet` has `= default` move operations declared in its header against a `unique_ptr<Impl>` member where `Impl` is forward-declared. This means **any TU without `Impl`'s definition (e.g. `cli/jose.cpp`) must not trigger JWKSet's move-assignment operator** — doing so forces instantiation of `unique_ptr<Impl>::reset()`, which requires `Impl` to be complete.

Safe pattern (C++17 guaranteed copy elision avoids the move constructor at the call site):

```cpp
JWKSet ks = JWKSet::fromJSON(key_json);  // OK — direct initialisation, no move needed
```

Unsafe pattern (triggers move-assignment, breaks outside the library TU):

```cpp
optional<JWKSet> ks;
ks = JWKSet::fromJSON(key_json);         // FAILS — optional::operator= calls JWKSet::operator=(JWKSet&&)
```

## Development Process Overview

This project follows a strict TDD/BDD workflow. Detailed per-phase instructions live in `.github/instructions/` and are loaded automatically by Copilot based on which files you are editing:

| Phase | Instruction file | Activates when editing |
|-------|-----------------|------------------------|
| **1 — Design** | [`01-design.instructions.md`](.github/instructions/01-design.instructions.md) | `include/**/*.hpp`, `src/**/*.hpp` |
| **2 — Test (TDD/BDD)** | [`02-tdd-bdd.instructions.md`](.github/instructions/02-tdd-bdd.instructions.md) | `tests/**/*.cpp`, `tests/**/*.hpp` |
| **3 — Implementation** | [`03-implementation.instructions.md`](.github/instructions/03-implementation.instructions.md) | `src/**/*.cpp`, `cli/**/*.cpp`, `examples/**/*.cpp` |
| **4 — Code Review** | [`04-review.instructions.md`](.github/instructions/04-review.instructions.md) | All files (`**`) |
| **5 — Pull Request** | [`05-pull-request.instructions.md`](.github/instructions/05-pull-request.instructions.md) | All files (`**`) |

### Process in Brief

1. **Design** — Finalise the header/interface first. Trace every addition to an RFC in `doc/`.
2. **Write failing tests** — Use Catch2 `SCENARIO`/`GIVEN`/`WHEN`/`THEN` for behaviour tests; `TEST_CASE` for unit-level checks. Include RFC 7520 test vectors for any serialisation change.
3. **Implement** — Make the tests green with the minimum necessary code. Run `clang-format` and `clang-tidy` before committing.
4. **Review** — Every PR must pass the style checklist in `04-review.instructions.md`. Coverage on modified `src/` files must be ≥ **85 %**.
5. **PR** — Use the PR description template, ensure the CI matrix is fully green, and squash-merge into `dev`.
