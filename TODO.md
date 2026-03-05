[ ] Add functional tests for import & export:
    [x] Import an RSA from JSON, exported public key only, use the validate signature
    [ ] Import an RSA from JSON, exported private key, use the validate signature
    [ ] Import an RSA from JSON, exported public key only, use the encrypt/decrypt
    [ ] Import an RSA from JSON, exported private key, use the encrypt/decrypt
    [ ] Import an EC from JSON, exported public key only, use the validate signature
    [ ] Import an EC from JSON, exported private key, use the validate signature
    [ ] Import an EC from JSON, exported public key only, use the encrypt/decrypt
    [ ] Import an EC from JSON, exported private key, use the encrypt/decrypt
    [ ] Import an OCT from JSON, exported public key only, use the validate signature
    [ ] Import an OCT from JSON, exported private key, use the validate signature
    [ ] Import an OCT from JSON, exported public key only, use the encrypt/decrypt
    [ ] Import an OCT from JSON, exported private key, use the encrypt/decrypt
    [ ] Import an OKP from JSON, exported public key only, use the validate signature
    [ ] Import an OKP from JSON, exported private key, use the validate signature
    [ ] Import an OKP from JSON, exported public key only, use the encrypt/decrypt
    [ ] Import an OKP from JSON, exported private key, use the encrypt/decrypt
[ ] Add permissive tests for algo names
[ ] Test against Node and Python reference implementations
[ ] Add permissive tests for missing use, missing alg

[ ] Expand and run full test list:
    [x] test_base64url.cpp
    [x] test_jwk.cpp
    [x] test_endian.cpp
    [x] test_concat_kdf.cpp
    [ ] test_cng_base64.cpp (CNG backend only)
    [ ] test_cng_generate_key.cpp (CNG backend only)

[ ] Add OpenSSL-only OKP test coverage:
    [x] Generate Ed25519 and X25519 keys
    [x] Round-trip OKP JSON (public and private)
    [ ] Import known OKP JWKs (public and private)

[ ] Re-enable full JOSE test targets in tests/CMakeLists.txt:
    [ ] test_jwa.cpp
    [ ] test_jws.cpp
    [ ] test_jwe.cpp
    [ ] test_jwt.cpp
    [ ] test_jwk_thumbprint.cpp
    [ ] test_rfc7520_examples.cpp

[ ] Complete CNG JWA implementation:
    [ ] Implement JWA::sign / JWA::verify in src/private/cng_jwa.cpp
    [ ] Implement JWA::encryptKey / JWA::decryptKey in src/private/cng_jwa.cpp
    [ ] Implement JWA::encryptContent / JWA::decryptContent in src/private/cng_jwa.cpp
    [ ] Add backend-parity tests for OpenSSL vs CNG behavior