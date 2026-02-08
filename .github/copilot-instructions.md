# Copilot Instructions for cpp-jose

## Code Style

### Bracing Style
- Use **Allman style** (BSD style) for all braces
- Opening braces always on a new line
- This applies to functions, classes, namespaces, control structures, etc.

### Naming Conventions

#### Acronyms
- **PascalCase**: All caps (e.g., `JWT`, `JOSE`, `JWK`, `JWS`, `JWE`)
- **snake_case**: All lowercase (e.g., `jwt_token`, `jose_header`)
- **camelCase**: Uppercase unless at start (e.g., `parseJWT()`, `createJWK()`)
  - Exception: At the start of identifiers, use lowercase for functions starting with verbs

#### General Naming
- Classes/Structs: PascalCase (e.g., `JsonValue`, `Base64Url`)
- Functions/Methods: camelCase (e.g., `encodeData()`, `verifySignature()`)
- Variables: camelCase (e.g., `keyId`, `tokenData`)
- Constants: UPPER_SNAKE_CASE (e.g., `MAX_KEY_SIZE`)
- Private members: camelCase with trailing underscore (e.g., `impl_`)

### Namespace
- All code must be wrapped in `namespace Vlinder { namespace jose { ... } }`
- Use nested namespaces for organization

### Formatting
- Follow the .clang-format configuration
- Maximum line length: 100 characters
- Indent with 4 spaces (no tabs)
- Pointer/reference alignment: Left (e.g., `int* ptr`, `const std::string& str`)

### Comments
- Use `/** ... */` for API documentation (Doxygen style)
- Use `//` for inline comments
- Document all public APIs with parameter descriptions and return values

## Architecture

### Modern C++ Standards
- Use C++17 features
- Prefer `std::unique_ptr`/`std::shared_ptr` over raw pointers
- Use PIMPL idiom for implementation hiding
- Leverage RAII for resource management

### Cryptography
- Use OpenSSL 3.0+ for all cryptographic operations
- Support post-quantum signature algorithms where applicable
- Always use secure random number generation

### Testing
- Write comprehensive unit tests using GoogleTest
- Aim for >80% code coverage
- Include RFC 7520 example tests for validation

### Error Handling
- Use exceptions for error conditions
- Provide descriptive error messages
- Clean up resources properly in all error paths

## RFC Compliance

Implement according to:
- RFC 7515 (JWS)
- RFC 7516 (JWE)
- RFC 7517 (JWK)
- RFC 7518 (JWA)
- RFC 7519 (JWT)
- RFC 7520 (Examples)
- RFC 7638 (JWK Thumbprint)

Ensure full compliance with the specifications.
