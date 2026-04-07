---
applyTo:
  - "include/**/*.hpp"
  - "src/**/*.hpp"
  - "src/private/**/*.hpp"
---

# Design Phase Instructions

These instructions apply when creating or modifying **header files** — the public API surface and internal interface definitions.

## Core Principle: Interface First

Design the public API before writing any implementation. Headers define contracts; `.cpp` files fulfil them. If you are about to edit a `.cpp` before the corresponding header exists and is reviewed, stop.

## RFC Alignment

This library implements JOSE standards. Every new type or function must trace directly to a normative reference:

| Header | Standard |
|--------|----------|
| `jose/jwa.hpp` | RFC 7518 — Algorithms |
| `jose/jwe.hpp` | RFC 7516 — JSON Web Encryption |
| `jose/jwk.hpp` | RFC 7517 — JSON Web Key |
| `jose/jws.hpp` | RFC 7515 — JSON Web Signature |
| `jose/jwt.hpp` | RFC 7519 — JSON Web Token |
| `jose/jwk_thumbprint.hpp` | RFC 7638 |
| `jose/base64url.hpp` | RFC 4648 §5 |

Before designing a new interface:
1. Locate the relevant RFC section in `doc/`.
2. Note any MUST/MUST NOT requirements — these become invariants enforced via preconditions or strong types.
3. Note algorithm identifiers and parameter names; mirror them in enum constants and field names.

## Header File Rules

- Use `#pragma once`.
- Include order: C++ Standard Library → third-party → project headers.
- **Never** add `using namespace` to a header.
- All names must be fully qualified (`std::vector`, `std::unique_ptr`, etc.).
- Doxygen `///` or `/** */` comments on every public type, function, and enum value.

### Doxygen Correctness Rules

Every Doxygen comment must accurately describe the declaration it precedes. Common mistakes to avoid:

| Mistake | Correct approach |
|---------|----------------|
| `@return` describes a type that no longer matches (e.g. "Pair of X and Y" when the function returns `std::optional<X>`) | Mirror the actual return type word-for-word |
| `@param` name does not match the parameter name in the signature | Copy the exact identifier from the declaration |
| `@param` documents a parameter that does not exist in the signature | Remove the `@param` |
| Unnamed (tag-type) parameters with a `@param` entry | Remove the `@param`; describe the overload's behaviour in `@brief` instead |
| `@brief` describes a different operation than what the function does | Re-read the function signature before writing the brief |

Specific patterns for this project:

```cpp
// WRONG — return type mismatch
/// @return Pair of optional JWS object and success flag
std::optional< JWS > fromJSON(std::string const &json, std::nothrow_t const &) noexcept;

// CORRECT
/// @return std::optional<JWS> containing the loaded token if valid, or empty
///         if the input could not be parsed.
std::optional< JWS > fromJSON(std::string const &json, std::nothrow_t const &) noexcept;

// WRONG — @param name does not match the declared identifier
/// @param input  Compact or JSON serialization string
static JWS fromCompact(std::string const &compact);

// CORRECT
/// @param compact  Compact (three-part dot-delimited) serialization string
static JWS fromCompact(std::string const &compact);

// WRONG — documents a parameter that does not exist in this overload
/// @param type    Type header field (e.g., "JWT")
JWS sign(JWK const &key, JWA::SignatureAlgorithm alg, std::string const &payload);

// CORRECT — no @param type when the overload has no type parameter
JWS sign(JWK const &key, JWA::SignatureAlgorithm alg, std::string const &payload);
```

## Naming in Headers

| Construct | Convention | Example |
|-----------|-----------|---------|
| Namespace (outer) | `Vlinder` | `namespace Vlinder {` |
| Namespace (inner) | `PascalCase` | `namespace JOSE {` |
| Class / struct / typedef | `PascalCase`, acronyms all-caps | `JWK`, `BackEndFactory` |
| Member function | `camelCase`, verb-first | `generateRSA`, `fromJSON`, `toJSON` |
| Member variable | `snake_case_` (trailing `_`) | `key_type_`, `key_id_` |
| Enum class | `PascalCase` | `enum class KeyType` |
| Enum constant | `snake_case` | `rsa`, `ec`, `signature` |
| Parameter / local | `snake_case` | `key_bits`, `algorithm` |
| Global/static const | `snake_case` | `default_key_bits` |

## `const` and Pointer/Reference Style

```cpp
// CORRECT
T const &ref;
T const *ptr;
T &mut_ref;
T *mut_ptr;
void foo(std::string const &name);

// WRONG
const T &ref;   // const on the wrong side
const T *ptr;
```

## Template Spacing

```cpp
// CORRECT
template< typename T >
std::vector< T > doSomething(std::map< std::string, T > const &input);

// WRONG
template<typename T>
std::vector<T> doSomething(std::map<std::string, T> const &input);
```

## Strong Typing — Non-Negotiable

- Never pass an `int` where a domain concept exists. Wrap it.
- Use `enum class` for all categorical values (key type, key use, algorithm, curve).
- Use `std::span< std::byte const >` or `std::span< char const >` for binary payloads, not raw pointers.
- Public API functions that accept algorithm identifiers must accept the corresponding `JWA::*` enum, not a raw string.

## Pimpl / Internal Separation

- Public headers (`include/jose/`) must expose **no implementation details**.
- Use the Pimpl idiom (`struct Impl; std::unique_ptr< Impl > impl_;`) when the implementation requires third-party types (OpenSSL, CNG).
- Internal types live in `src/private/`; they must never appear in `include/`.

## Backend Abstraction

When designing a feature that requires cryptographic operations:
1. Add the operation to the `BackEnd` abstract interface in `src/private/back_end.hpp`.
2. Define what CNG and OpenSSL implementations must provide.
3. Only then design the public API header.

The public API must be backend-agnostic — no OpenSSL or CNG types may appear in `include/`.

## API Shape Preferences

These rules are derived from the reviewed headers (JWA, JWK, JWKSet, JWKThumbprint, Base64URL) and apply to all new headers.

### Free Functions and Immutable Value Objects, Not Builders

Operations that produce a new JOSE object must be expressed as **free functions or static factories that return an immutable value type**, not as a mutable builder that accumulates state.

```cpp
// CORRECT — JWS pattern: free function returns typed result
JWS sign(JWK const &key, JWA::SignatureAlgorithm alg, std::span< char const > payload);
bool verify(JWS const &jws, JWK const &key);

// WRONG — builder pattern: JWE original anti-pattern
JWE jwe;
jwe.setPlaintext("data");           // builder accumulation
jwe.setKeyEncryptionAlgorithm(...);
std::string token = jwe.encrypt(key); // returns raw string, not typed object
```

When the result of an operation is a JOSE structure (JWS, JWE, JWT), the function must return that typed object, not a raw `std::string`. Raw-string serialisation is a separate step (`toCompact()`, `toJSON()`).

### Strong Typing for Algorithms — Never Raw Strings

Algorithm identifiers must use `JWA` enum types, never raw `std::string`:

```cpp
// CORRECT
JWS sign(JWK const &key, JWA::SignatureAlgorithm alg, ...);

// WRONG — raw string, not strongly typed
std::string sign(JWK const &key, std::string const &algorithm); // e.g. "RS256"
```

This applies to JWT operations as well: `jwt.sign(key, "RS256")` is not acceptable.

### Strong Typing for Durations — Never `int`

Time-related parameters (leeway, not-before offsets, expiry) must use `std::chrono` duration types:

```cpp
// CORRECT
bool validate(std::string const &issuer,
              std::string const &audience,
              std::chrono::seconds leeway = std::chrono::seconds{0}) const;

// WRONG
bool validate(std::string const &issuer, std::string const &audience, int leeway = 0) const;
```

### Nothrow Overloads Return `std::optional< T >`

When a nothrow parsing overload is needed, it returns `std::optional< T >`, **not** `std::pair< std::optional< T >, bool >`. An empty optional signals failure; no separate boolean is needed.

```cpp
// CORRECT — new pattern (JWS is the reference implementation)
static std::optional< JWS > fromCompact(std::string const &compact, std::nothrow_t const &) noexcept;

// WRONG — old pattern; do not use for new types
static std::pair< std::optional< JWE >, bool > fromJSON(std::string const &json, std::nothrow_t const &);
```

Note: JWK and JWKSet still carry the old `pair` pattern as a known deficiency (tracked in `TODO.txt`). Do not propagate it to any new type.

### `<iostream>` Must Not Be Included in Public Headers

If a class exposes stream operators (`operator<<`), forward-declare or include only `<iosfwd>` in the header. The heavy `<iostream>` include belongs in `.cpp` files.

```cpp
// CORRECT in a .hpp
#include <iosfwd>
std::ostream &operator<<(std::ostream &os, JWS const &jws);

// WRONG in a .hpp
#include <iostream>  // pulls in the full stream implementation
```

### Comparison Operators for Value Types

Types that represent JOSE values (tokens, thumbprints) should expose the full comparison operator set, as `JWKThumbprint` does:

```cpp
bool operator==(T const &lhs, T const &rhs);
bool operator!=(T const &lhs, T const &rhs);
bool operator<(T const &lhs, T const &rhs);
bool operator<=(T const &lhs, T const &rhs);
bool operator>(T const &lhs, T const &rhs);
bool operator>=(T const &lhs, T const &rhs);
```

### `std::span` for Binary Payloads

Parameters that accept opaque binary input use `std::span< unsigned char const >` or `std::span< char const >`. Do not accept `std::string` as a binary payload parameter; keep convenience overloads separate and clearly named.

### Attorney Pattern for Controlled Construction

When a class's constructor must be private (e.g. `JWS` may only be created by `sign()`), use the **Attorney–Client** pattern:

- Define a `SomethingAttorney` class in the header.
- Make the relevant free function a `friend` of the attorney only.
- The attorney delegates to the private constructor via a named `construct()` static.

This prevents accidental direct construction while keeping the header self-documenting.

---

## Testability Checklist Before Finalising a Header

- [ ] Can every constructor/factory be called without a live crypto backend (for unit-testing with a mock)?
- [ ] Are error paths expressible without exceptions leaking implementation detail types?
- [ ] Does the interface allow RFC 7520 test vectors to be exercised end-to-end?
- [ ] Is there a clear seam for injecting a mock `BackEnd` in tests?
- [ ] Nothrow overloads return `std::optional< T >`, not a pair?
- [ ] All algorithm parameters use `JWA` enum types, not `std::string`?
- [ ] All duration parameters use `std::chrono` types, not `int`?
- [ ] No `<iostream>` included (use `<iosfwd>` if stream operators are needed)?
