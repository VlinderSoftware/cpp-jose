---
applyTo: "**"
---

# Code Review Instructions

When reviewing code changes in this repository, verify every item below. A review is not complete until every section shows **PASS** or **N/A**. Block the review on any **FAIL**.

---

## 1. Style Enforcement

### 1.0 Reformat Script (`clang-format`)

- [ ] `scripts/Reformat.ps1 -CheckOnly` exits **0** — no files need reformatting.

```powershell
# Run from the repo root after bootstrapping
.\scripts\Reformat.ps1 -CheckOnly
```

The script checks all `.cpp` / `.hpp` / `.h` / `.ipp` / `.inl` files under `src/`, `include/`, `tests/`, and `examples/`. Any exit code other than 0 is a **FAIL** — block the review until the author re-runs `./scripts/Reformat.ps1` (without `-CheckOnly`) and pushes the formatted commit.

### 1.1 `const` Placement (East-const)

- [ ] All `const` qualifiers appear **after** the type: `T const t`, `T const &t`, `T const *p`.
- Patterns that must **not** appear: `const T`, `const T &`, `const T *`.

```cpp
// PASS
string const name = "test";
void foo(JWK const &key);

// FAIL — block the review
const string name = "test";
void foo(const JWK &key);
```

### 1.2 Naming Conventions

Check every new/changed identifier:

| Kind | Expected | Common Violation |
|------|----------|-----------------|
| Local variable | `snake_case` | `camelCase`, `PascalCase` |
| Member variable | `snake_case_` (trailing `_`) | Missing trailing `_` |
| Function (free or member) | `camelCase`, verb-first | Noun-only name, `PascalCase` |
| Class / struct / enum | `PascalCase`; acronyms ALL-CAPS | `Jwk` instead of `JWK` |
| Enum constant | `snake_case` | `RSA`, `EC` (all-caps) |
| Macro | `UPPER_CASE` | `lowerCase` |
| Namespace | `PascalCase` | `jose`, `vlinder` |

- [ ] No abbreviations of common words (write `implementation` not `impl` as a class/type name; `impl` is acceptable as a local variable or member).
- [ ] Acronyms in function names are all-caps: `toJSON`, `generateRSA`, `encryptAES`.

### 1.3 Template Spacing

- [ ] Templates use a space before `>`: `vector< T >`, `pair< string, JWK >`, `template< typename T >`.

### 1.4 Namespace Braces

- [ ] Namespace opening braces are on the **same line**: `namespace Vlinder::JOSE {`
- [ ] All other braces follow Allman style (opening brace on a new line).

### 1.5 Header File Rules

- [ ] No `using namespace` in any `.hpp` file.
- [ ] All names are fully qualified in headers (`std::vector`, `std::unique_ptr`).
- [ ] `#pragma once` at the top of every header.
- [ ] Include order: stdlib → third-party → project.

### 1.6 `.cpp` File Rules

- [ ] `using namespace std;` and the relevant project namespaces appear immediately after the `#include` block.
- [ ] No `std::` qualification when `using namespace std;` is in scope (unless needed for disambiguation).

### 1.7 Pointer / Reference Formatting

- [ ] `T *p` — pointer is attached to the type, not the variable.
- [ ] `T &r` — reference is attached to the type.
- [ ] No `T* p` or `T& r`.

---

## 2. TDD and Test Coverage

### 2.1 Test-First Evidence

- [ ] The PR contains test additions that predate or accompany every feature change.
- [ ] No new public API surface was added without a corresponding test case.

### 2.2 Coverage Threshold

- [ ] Coverage on modified files is ≥ **85 %** (check the CI coverage report).
- [ ] Any new branch (if/else, switch branch, exception path) has a corresponding test.

### 2.3 BDD Test Structure

For behaviour-level tests, verify `SCENARIO`/`GIVEN`/`WHEN`/`THEN` is used (not plain `TEST_CASE`) where it aids clarity:

- [ ] `SCENARIO` names describe observable behaviour in plain language.
- [ ] `GIVEN` establishes preconditions.
- [ ] `WHEN` performs the action under test.
- [ ] `THEN` asserts expected outcomes.
- [ ] `AND_WHEN` / `AND_THEN` are used for branching scenarios rather than deeply nested `if` blocks.

### 2.4 RFC 7520 Test Vectors

If the change touches JWS, JWE, JWK, or JWT serialisation:
- [ ] At least one `TEST_CASE`/`SCENARIO` uses a test vector from `doc/rfc7520.txt` or another relevant RFC in `doc/`.
- [ ] The test tag includes the RFC section reference, e.g. `[rfc7520][section-4-1]`.

### 2.5 Error Paths Tested

- [ ] Each new validation check (missing field, bad value, wrong algorithm for key type) has a corresponding negative test that verifies the exception/error is thrown.
- [ ] Negative tests use `REQUIRE_THROWS` or `REQUIRE_THROWS_AS`.

---

## 3. Security

- [ ] No private key material is printed, logged, or included in exception messages.
- [ ] All JSON parsing uses `j.at(key)` (throws on missing) for required fields; `j.value(key, default)` for optional.
- [ ] No raw `new` / `delete` — smart pointers only.
- [ ] No `rand()` / `std::rand()` — all randomness through the crypto backend.
- [ ] No plaintext secrets in comments, test payloads, or example files.
- [ ] Input validation is performed at the public API boundary (parsing functions), not deep in the call stack.

---

## 4. Architecture

### 4.1 Layer Separation

- [ ] Public headers (`include/jose/`) contain no OpenSSL or CNG types.
- [ ] Crypto operations in `src/jw*.cpp` go exclusively through `BackEndFactory`/`BackEnd`.
- [ ] OpenSSL-specific code lives only in `src/private/openssl_back_end.*`.
- [ ] CNG-specific code lives only in `src/private/cng_back_end.*`.

### 4.2 New Algorithms or Key Types

- [ ] The `BackEnd` interface in `src/private/back_end.hpp` has a new virtual method.
- [ ] Both `OpenSSLBackEnd` and `CNGBackEnd` implement the method (or explicitly `= 0` with a tracking issue if deferring CNG).
- [ ] The `JWA` enums in `include/jose/jwa.hpp` are updated.
- [ ] Test coverage includes both backends (at least via CI matrix).

---

## 5. Build System

- [ ] New source files are added to `CMakeLists.txt` (or `tests/CMakeLists.txt`).
- [ ] New backend-conditional sources use `if(JOSE_BACKEND STREQUAL "CNG")` guards.
- [ ] No new `find_package` or `FetchContent` without discussion — dependencies are intentionally minimal.

---

## 6. Documentation

- [ ] Public API functions have `///` Doxygen comments.
- [ ] RFC section references appear in comments next to non-obvious logic.
- [ ] `TODO.txt` is updated if the change is partial or defers something.

---

## Review Decision Matrix

| All sections PASS | Decision |
|-------------------|----------|
| Yes | Approve |
| Style failures only | Request changes (non-blocking **only** if `Reformat.ps1` will auto-fix; block otherwise) |
| Coverage < 85 % | Block — request additional tests |
| Security failure | Block immediately |
| Architecture violation | Block — discuss before proceeding |
