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
    - **`.cpp` files** must open with `using namespace` directives immediately after the `#include` block (e.g. `using namespace std;`, `using namespace Vlinder::JOSE::Private;`). This means names like `vector`, `string`, `unique_ptr` and project types are used unqualified throughout the file.
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

- **Bootstrap location and usage:** The workspace bootstrap file is the repo-root file named `bootstrap` (no `.sh` extension). It is intended to be sourced: `. ./bootstrap`.
- **Bootstrap behavior:** Sourcing `bootstrap` must validate required tooling and return non-zero with a clear message when tooling is missing. It must never terminate the user terminal session (do not `exit` from sourced bootstrap logic).
- **Linux tooling requirement:** On Linux, `jq` is required. If `jq` is missing, bootstrap validation fails.
- **Hook integration:** Hook scripts may source `bootstrap` with `CPP_JOSE_BOOTSTRAP_AUTO_CHECK=0` and invoke `hookBootstrapCheckTools` explicitly so hooks can control JSON error output.

- **Environment file pattern:** If the workspace depends on environment variables, include a tracked `dot-env` template and an untracked `.env` file for local values.
- **Secrets handling:** `.env` must remain gitignored and must not be committed. `dot-env` should contain keys/placeholders only (no secrets).
- **Sync rule:** When adding or changing required environment variables, update `dot-env` in the same change.
