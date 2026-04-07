---
applyTo:
  - "tests/**/*.cpp"
  - "tests/**/*.hpp"
---

# TDD / BDD Test-Writing Instructions

These instructions apply when creating or modifying **test files** in `tests/`.

## Mandatory Workflow: Test First

Follow the Red-Green-Refactor cycle strictly:

1. **Red** — Write a failing test that specifies the desired behaviour. Commit the failing test.
2. **Green** — Write the minimal implementation that makes it pass. No more, no less.
3. **Refactor** — Clean up both implementation and test while keeping green.

Never create or modify a `.cpp` implementation file to add a feature without first having a corresponding failing test.

## Test Framework: Catch2 v3

All tests use Catch2 v3 macros. Use `catch2/catch_test_macros.hpp`.

The test executable target is `jose_tests` (see `tests/CMakeLists.txt`).

### Preferred Style: BDD With SCENARIO

For behaviour-level tests, use Gherkin-style `SCENARIO`/`GIVEN`/`WHEN`/`THEN`:

```cpp
#include <catch2/catch_test_macros.hpp>
#include "jose/jose.hpp"

using namespace std;
using namespace Vlinder::JOSE;

SCENARIO("a symmetric key can sign and verify a compact JWS", "[jws][hmac]")
{
    GIVEN("a 256-bit oct key for signing")
    {
        JWK const key = JWK::generateOct(JWK::Use::signature, 256);

        WHEN("a payload is signed with HS256")
        {
            auto const jws = sign(key, JWA::SignatureAlgorithm::hs256,
                                  std::span< char const >("hello", 5));
            string const token = jws.toCompact();

            THEN("the compact token is non-empty and has three dot-delimited parts")
            {
                REQUIRE_FALSE(token.empty());
                size_t const first_dot  = token.find('.');
                size_t const second_dot = token.find('.', first_dot + 1);
                REQUIRE(string::npos != first_dot);
                REQUIRE(string::npos != second_dot);
            }

            AND_WHEN("the token is verified with the same key")
            {
                bool const valid = verify(key, jws);

                THEN("verification succeeds")
                {
                    REQUIRE(valid);
                }
            }
        }
    }
}
```

### Acceptable Alternative: Descriptive TEST_CASE

For unit-level tests of a single function or property, `TEST_CASE` is acceptable when the scenario structure would be forced:

```cpp
TEST_CASE("JWK_GenerateRSA_ProducesKeyWithCorrectType", "[jwk][rsa]")
{
    JWK const key = JWK::generateRSA(JWK::Use::signature, 2048);
    REQUIRE(JWK::KeyType::rsa == key.getKeyType());
    REQUIRE(key.hasPrivateKey());
}
```

**Test name format:** `ClassName_MethodOrBehaviour_Scenario` — PascalCase with underscores as separators.

## Coverage Target: 85 %

Every code path added to `src/` must be reachable by at least one test. The CI enforces an **85 % line and branch coverage** threshold.

Strategies to reach 85 %:
- Test each algorithm variant (every `JWA::SignatureAlgorithm`, `JWA::KeyEncryptionAlgorithm`, `JWA::ContentEncryptionAlgorithm`).
- Test both happy-path and all documented error conditions.
- Use RFC 7520 test vectors for round-trip compliance (see `test_rfc7520_examples.cpp`).
- Mock the `BackEnd` where crypto is not under test (`test_concat_kdf.cpp` shows the pattern).

## Test Organisation

| File | Purpose |
|------|---------|
| `test_<module>.cpp` | Tests for `src/<module>.cpp` or `include/jose/<module>.hpp`. One file per module. |
| `test_rfc7520_examples.cpp` | RFC 7520 interoperability test vectors. Never skip these. |
| `test_backend_factory.cpp` | Smoke tests for backend selection. |
| `test_cng_*.cpp` (conditional) | CNG-specific tests, compiled only when `JOSE_BACKEND=CNG`. |

Add new test files to `target_sources(jose_tests PRIVATE ...)` in `tests/CMakeLists.txt`.

## RFC Test Vectors Are Mandatory

For any new algorithm or serialisation format:
1. Find the corresponding section in `doc/rfc75*.txt` or `doc/rfc9*.txt`.
2. Add at minimum one `TEST_CASE` or `SCENARIO` that exercises the exact values from the RFC.
3. Tag the test with its RFC section, e.g. `[rfc7515][section-a1]`.

## Error-Path Coverage

Every public API function that validates input must have tests for invalid inputs:

```cpp
SCENARIO("fromJSON rejects a JWK with an unknown key type", "[jwk][error]")
{
    GIVEN("a JSON object with kty set to an unrecognised value")
    {
        string const bad_json = R"({"kty":"UNKNOWN"})";

        WHEN("fromJSON is called")
        {
            THEN("an exception is thrown")
            {
                REQUIRE_THROWS(JWK::fromJSON(bad_json));
            }
        }
    }
}
```

## Backend-Conditional Tests

Tests that only make sense for one backend must be guarded:

```cpp
// In CMakeLists.txt — add to jose_tests only for CNG:
if(JOSE_BACKEND STREQUAL "CNG")
    target_sources(jose_tests PRIVATE test_cng_specific.cpp)
endif()
```

Do not use `#ifdef JOSE_USE_CNG` inside a shared test file to hide large blocks; instead, split into a separate file.

## Mock Backend Pattern

When testing higher-level code that depends on `BackEnd`, implement a minimal mock:

```cpp
struct MockBackEnd : Vlinder::JOSE::Private::BackEnd
{
    // override only the methods under test; leave others as default stubs
    std::unique_ptr< Vlinder::JOSE::Private::Key >
    generateOct(std::size_t bits) override { /* ... */ }
};
```

See `tests/test_concat_kdf.cpp` for a working example.

## Naming and Style in Tests

- Apply the same `const`-qualifier style as production code: `T const &t`.
- Apply the same include ordering: stdlib → Catch2 → project.
- `using namespace std;` and `using namespace Vlinder::JOSE;` are permitted (and required) at file scope in `.cpp` test files.
- Do **not** add `using namespace` to any `.hpp` test helper.
- Magic numbers are **permitted** in test assertions (the `.clang-tidy` in `tests/` disables `readability-magic-numbers`).
- Test functions must not be `static`; Catch2 discovers them via macros.

## Running Tests

```bash
# Build and run all tests
cmake --build build/vs-latest-x64-debug --target jose_tests
ctest --test-dir build/vs-latest-x64-debug --output-on-failure

# Run a single test case by name
ctest --test-dir build/vs-latest-x64-debug -R "JWK_Generate"

# Run with coverage (Linux, GCC)
cmake -B build/coverage -DCMAKE_BUILD_TYPE=Debug -DJOSE_BACKEND=OpenSSL \
      -DCMAKE_CXX_FLAGS="--coverage"
cmake --build build/coverage
ctest --test-dir build/coverage
lcov --capture --directory build/coverage --output-file coverage.info
lcov --remove coverage.info '/usr/*' '*/tests/*' '*/examples/*' \
     --output-file coverage_filtered.info
lcov --list coverage_filtered.info
```
