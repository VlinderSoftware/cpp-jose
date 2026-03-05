[ ] Add functional tests for import & export:
    [ ] Import an RSA from JSON, exported public key only, use the validate signature
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
    [ ] test_base64url.cpp
    [ ] test_jwk.cpp
    [ ] test_endian.cpp
    [ ] test_concat_kdf.cpp
    [ ] test_cng_base64.cpp (Windows only)
    [ ] test_cng_generate_key.cpp (Windows only)

[ ] Add OpenSSL-only OKP test coverage:
    [ ] Generate Ed25519 and X25519 keys
    [ ] Round-trip OKP JSON (public and private)
    [ ] Import known OKP JWKs (public and private)