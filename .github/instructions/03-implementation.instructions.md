---
applyTo:
  - "src/**/*.cpp"
  - "src/**/*.hpp"
  - "cli/**/*.cpp"
  - "examples/**/*.cpp"
---

# Implementation Phase Instructions

These instructions apply when writing or modifying **source files** in `src/`, `cli/`, and `examples/`.

## Pre-Implementation Gate

Before touching any `.cpp`:
- [ ] The corresponding header in `include/jose/` or `src/private/` exists and is finalised.
- [ ] At least one failing Catch2 test exists that covers the behaviour being implemented.
- [ ] All RFC requirements for the feature have been read from `doc/`.

## `.cpp` File Structure

```cpp
// 1. Project/local headers first if this is a private impl file
#include "private/my_feature.hpp"

// 2. Then public API headers
#include "jose/jwk.hpp"

// 3. C++ Standard Library
#include <memory>
#include <stdexcept>
#include <string>

// 4. Third-party
#include <nlohmann/json.hpp>

// 5. using-namespace directives — required immediately after includes
using namespace std;
using namespace Vlinder::JOSE;
using namespace Vlinder::JOSE::Private;
```

`using namespace std;` (and project namespaces) is **required** at file scope in every `.cpp`. Do not use `std::` qualification when `using namespace std;` is in scope, except to resolve ambiguity.

## Naming — Enforced by clang-tidy

| Construct | Convention |
|-----------|-----------|
| Local variable / parameter | `snake_case` |
| Member variable | `snake_case_` (trailing underscore) |
| Free / member function | `camelCase`, begins with a verb |
| Type (class, struct, alias) | `PascalCase`; acronyms all-caps |
| Enum class constant | `snake_case` |
| Macro | `UPPER_CASE` |

Acronyms in function names stay all-caps: `toJSON`, `fromJSON`, `generateRSA`, `encryptAES`.

## `const` Placement — East-const Style

```cpp
// CORRECT — const east of the type
string const name = "hello";
JWK const &key_ref = get_key();
char const *p = data.data();

// WRONG
const string name = "hello";
const JWK &key_ref = get_key();
const char *p = data.data();
```

Apply this to **every** local variable, parameter, and member declaration you write or modify.

## Modern C++ Idioms

- Use `auto` when the type is obvious from the right-hand side or returned by a factory.
- Use range-based `for` loops; never index-based unless an index is genuinely needed.
- Use `std::unique_ptr` / `std::shared_ptr`; never raw `new` / `delete`.
- Use `nullptr`; never `NULL` or `0` as a pointer value.
- Use `std::string` and `std::vector`; never C-style arrays or `char *` buffers.
- Use `std::span< T const >` for non-owning views of contiguous data.
- Prefer structured bindings (`auto const &[k, v]`) over `.first` / `.second`.

## Template Spacing

```cpp
// CORRECT
vector< pair< string, JWK > > keys;
make_unique< OpenSSLBackEnd >();

// WRONG
vector<pair<string, JWK>> keys;
make_unique<OpenSSLBackEnd>();
```

## Error Handling

- Throw `std::invalid_argument` for invalid caller-supplied values.
- Throw `std::runtime_error` for backend / crypto failures.
- Never silently swallow exceptions; propagate or translate.
- Do not add error handling for code paths that are unreachable by construction.

## Backend Dispatch

All cryptographic operations go through `BackEndFactory::get().createBackEnd()`. Never call OpenSSL or CNG APIs directly from `src/jw*.cpp` files — those belong in `src/private/openssl_back_end.cpp` and `src/private/cng_back_end.cpp` respectively.

```cpp
// CORRECT — in jwk.cpp
auto back_end = BackEndFactory::get().createBackEnd();
impl_.key_ = move(back_end->generateRSA(bits));

// WRONG — in jwk.cpp
EVP_PKEY *pkey = EVP_PKEY_new();  // OpenSSL leaking into public layer
```

## JSON Handling

Use `nlohmann::json` (imported via `FetchContent`). Prefer the type-safe accessors:

```cpp
auto j = json::parse(input);
string const kty = j.at("kty").get< string >();   // throws on missing key
string const kid = j.value("kid", string{});       // defaulted optional field
```

Do not use `j["kty"]` (no `at`) for required fields — it silently inserts a null.

## Security Requirements

- **Never log or print private key material.** Strip private fields before any diagnostic output.
- Validate all external input (JSON, compact serialisations) at the point of parsing; reject early rather than propagating malformed state.
- Use constant-time comparisons for secret material (relevant to MAC verification).
- RSA key generation hardening: respect `JOSE_RSA_GENERATION_MAX_ATTEMPTS` where retry loops are needed.
- Do not call `std::rand()` or `rand()` anywhere; use the backend's CSPRNG exclusively.

## Namespace Braces — Exception to Allman Style

Namespace opening braces stay on the **same line**:

```cpp
// CORRECT
namespace Vlinder::JOSE {
class JWK
{
    // ...
};
} // namespace Vlinder::JOSE

// WRONG
namespace Vlinder::JOSE
{
```

All other braces follow Allman style (opening brace on a new line).

## After Writing Code

1. Run the repo reformat script to apply `clang-format` to **all** source files in `src/`, `include/`, `tests/`, and `examples/`:
   ```powershell
   .\scripts\Reformat.ps1
   ```
   Then verify the result is clean (script exits 0, nothing left to format):
   ```powershell
   .\scripts\Reformat.ps1 -CheckOnly
   ```
   The `-CheckOnly` flag exits 1 and lists any files still needing formatting — **the check must pass before committing**.

   > **Never** run `clang-format` on individual files in isolation; always use `Reformat.ps1` so the scope matches the CI check exactly.

2. Run `clang-tidy`:
   ```powershell
   clang-tidy src/jws.cpp -- -std=c++20 -I include
   ```
3. Re-run the test suite and confirm all tests pass:
   ```powershell
   cmake --build .\build\vs-latest-x64-debug --target jose_tests
   ctest --test-dir .\build\vs-latest-x64-debug --output-on-failure
   ```
4. Verify coverage has not dropped below **85 %** on files you touched.
