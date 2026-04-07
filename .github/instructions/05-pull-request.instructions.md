---
applyTo: "**"
---

# Pull Request Preparation Instructions

These instructions apply when preparing a branch for pull request, writing a PR description, or reviewing a PR before merge into `dev` or `main`.

## Target Branches

| Source branch pattern | Merges into |
|-----------------------|-------------|
| `rlc/*`, feature branches | `dev` |
| `dev` | `main` (release only) |

CI runs on both `dev` and `main` pushes, and on all PRs targeting them (see `.github/workflows/ci.yml`).

---

## Pre-PR Checklist: Author

Complete every item before opening the PR or marking it ready for review.

### Code Quality

- [ ] `clang-format` has been run on **all modified** `.cpp` and `.hpp` files.
  ```powershell
  # Windows (VS LLVM tools path is added by Enforce-Cpp-Style.ps1)
  clang-format -i (git diff --name-only HEAD | Where-Object { $_ -match '\.(cpp|hpp)$' })
  ```
- [ ] `clang-tidy` reports no new warnings on modified files.
  ```bash
  # Linux / macOS
  clang-tidy src/jws.cpp -- -std=c++20 -I include -DJOSE_USE_OPENSSL
  ```
- [ ] No new compiler warnings at `-Wall -Wextra` (Linux/macOS CI flags).

### Tests

- [ ] All new behaviour is covered by `SCENARIO`/`GIVEN`/`WHEN`/`THEN` tests (BDD-style) or descriptive `TEST_CASE` tests.
- [ ] All existing tests still pass:
  ```powershell
  cmake --build .\build\vs-latest-x64-debug --target jose_tests
  ctest --test-dir .\build\vs-latest-x64-debug --output-on-failure
  ```
- [ ] Coverage on **modified** source files is ≥ **85 %**. Run locally if available:
  ```bash
  cmake -B build/cov -DCMAKE_BUILD_TYPE=Debug -DJOSE_BACKEND=OpenSSL \
        -DCMAKE_CXX_FLAGS="--coverage" -DCMAKE_EXE_LINKER_FLAGS="--coverage"
  cmake --build build/cov --target jose_tests
  ctest --test-dir build/cov
  lcov --capture --directory build/cov -o cov.info
  lcov --remove cov.info '/usr/*' '*/tests/*' '*/examples/*' '*/cli/*' \
       '*/nlohmann/*' '*/Catch2/*' -o cov_src.info
  lcov --list cov_src.info
  genhtml cov_src.info -o coverage-report
  ```
- [ ] RFC 7520 tests pass without modification.

### Security

- [ ] No secrets, private keys, or credentials appear in diff.
- [ ] No `rand()` or platform-specific PRNG calls in src (use backend CSPRNG).
- [ ] All new JSON parsing validates required fields with `j.at()`.

### Architecture

- [ ] No OpenSSL or CNG types leak into `include/jose/` headers.
- [ ] Both OpenSSL and CNG backends compile (CI matrix covers this, but verify locally for the primary platform).
- [ ] New source files are registered in `CMakeLists.txt`.

---

## PR Description Template

Use this template when opening a PR:

```markdown
## Summary
<!-- One sentence: what does this change do? -->

## Motivation
<!-- Why is this change needed? Reference RFC sections if applicable. -->
RFC reference: <!-- e.g. RFC 7515 §5.1 -->

## Changes
- 
- 

## Test Coverage
<!-- Describe the new test cases added and what they cover. -->
- New BDD scenarios: <!-- list SCENARIO names -->
- RFC test vectors added: <!-- list RFC section references -->
- Estimated coverage delta: <!-- e.g. +3% on src/jws.cpp -->

## Checklist
- [ ] clang-format run on all modified files
- [ ] clang-tidy reports no new warnings
- [ ] All tests pass locally
- [ ] Coverage ≥ 85% on modified src files
- [ ] No private key material in diff
- [ ] TODO.txt updated if work is partial
```

---

## CI Matrix Reference

The CI runs the following matrix (`.github/workflows/ci.yml`). All must be green before merge:

| Job | OS | Compiler | Backend | Coverage |
|-----|----|----------|---------|----------|
| Linux GCC Debug | ubuntu-24.04 | gcc/g++ | OpenSSL | lcov-gcov |
| Linux GCC Release | ubuntu-24.04 | gcc/g++ | OpenSSL | — |
| Linux Clang Debug | ubuntu-24.04 | clang/clang++ | OpenSSL | llvm-cov-instr |
| Linux Clang Release | ubuntu-24.04 | clang/clang++ | OpenSSL | — |
| Linux ARM64 GCC Debug | ubuntu-24.04-arm | gcc/g++ | OpenSSL | lcov-gcov |
| Linux ARM64 Clang Debug | ubuntu-24.04-arm | clang/clang++ | OpenSSL | llvm-cov-instr |
| macOS Clang Debug | macos-latest | clang/clang++ | OpenSSL | — |

Coverage reports are uploaded by the `coverage: true` jobs. The 85 % threshold is enforced against `src/` only (`tests/`, `examples/`, and `cli/` are excluded).

---

## Reviewer Assignment

- At least one reviewer must be assigned before merging.
- The reviewer must complete the [code review checklist](04-review.instructions.md) before approving.
- Auto-merge is disabled on `main`.

---

## Commit Message Convention

```
<type>(<scope>): <short description>

<body — optional, wrap at 72 chars>

RFC: <RFC number and section if applicable>
Fixes: #<issue number if applicable>
```

Types: `feat`, `fix`, `test`, `refactor`, `docs`, `build`, `ci`, `chore`.

Examples:
```
feat(jws): add EdDSA signing with Ed25519 keys

Implements RFC 8037 OKP key support in the JWS signing path.
Both CNG (future) and OpenSSL backends are plumbed.

RFC: RFC 8037 §2
```

```
test(jws): add BDD scenarios for HS256 sign/verify round-trip
```

---

## Merge Policy

- Squash merge into `dev` for feature branches.
- Merge commit (no squash) from `dev` into `main` to preserve release history.
- Delete the source branch after merge.
