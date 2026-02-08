# cpp-jose Examples

This directory contains example programs demonstrating the cpp-jose library functionality.

## Building the Examples

The examples are built automatically when you build the library with `BUILD_EXAMPLES=ON` (enabled by default):

```bash
mkdir build
cd build
cmake ..
make
```

The example executables will be in `build/examples/`.

## Running the Examples

From the build directory:

```bash
cd examples
./jwt_example
./jws_example
./jwe_example
./jwk_example
```

## Example Programs

### 1. jwt_example.cpp - JSON Web Token (JWT)

Demonstrates the complete JWT workflow:
- Creating JWTs with standard claims (iss, sub, aud, exp, nbf, iat, jti)
- Adding custom claims
- Signing JWTs with different algorithms (HS256, RS256)
- Verifying JWT signatures
- Parsing JWTs with and without verification
- Validating JWT claims (issuer, audience, time-based claims)

**Key Concepts:**
- Standard JWT claims
- Time-based claim validation with leeway
- Custom claims
- Symmetric (HMAC) and asymmetric (RSA) signing

### 2. jws_example.cpp - JSON Web Signature (JWS)

Demonstrates JWS signing and verification with various algorithms:
- HMAC signatures (HS256, HS384, HS512)
- RSA signatures (RS256, PS256)
- Elliptic Curve signatures (ES256)
- Custom header parameters
- JWS compact serialization format
- Error handling and verification failures

**Key Concepts:**
- Different signature algorithms
- Symmetric vs asymmetric signatures
- JWS header customization
- Compact serialization (Header.Payload.Signature)

### 3. jwe_example.cpp - JSON Web Encryption (JWE)

Demonstrates JWE encryption and decryption:
- RSA key encryption (RSA-OAEP, RSA-OAEP-256)
- AES key wrapping (A128KW, A256KW)
- Different content encryption algorithms (AES-GCM, AES-CBC-HMAC)
- JWE header inspection
- Encrypting JSON payloads
- JWE compact serialization format

**Key Concepts:**
- Key encryption algorithms (KEK)
- Content encryption algorithms (CEK)
- Two-layer encryption (key wrapping + content encryption)
- JWE format (Header.EncryptedKey.IV.Ciphertext.Tag)

### 4. jwk_example.cpp - JSON Web Key (JWK)

Demonstrates JWK generation, serialization, and thumbprints:
- Generating RSA, EC, and symmetric keys
- JWK serialization (public and private)
- JWK deserialization from JSON
- JWK Sets (JWKS) - managing multiple keys
- JWK Thumbprints (RFC 7638)
- Key metadata (kid, use, alg)
- Public/private key pairs

**Key Concepts:**
- Different key types (RSA, EC, oct)
- Public vs private key serialization
- JWK Sets for key rotation
- Thumbprints for key identification
- Key metadata and discovery

## Code Style

All examples follow these conventions:
- Use `Vlinder::jose` namespace
- Include `jose/jose.hpp` for all JOSE functionality
- Use Allman style bracing
- Clear console output showing each step
- Error handling with try-catch blocks
- Production-ready code patterns

## Example Output

Each example produces clear, structured output showing:
- What operation is being performed
- Input data
- Generated tokens/keys/encrypted data
- Verification results
- Success/failure indicators (✓/✗)

## Use Cases

These examples demonstrate patterns for:
- **Authentication**: Creating and validating JWTs for user sessions
- **Authorization**: Using JWT claims for access control
- **API Security**: Signing and verifying API requests with JWS
- **Data Protection**: Encrypting sensitive data with JWE
- **Key Management**: Managing cryptographic keys with JWK/JWKS

## Further Reading

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 7516 - JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [RFC 7638 - JSON Web Key (JWK) Thumbprint](https://tools.ietf.org/html/rfc7638)
