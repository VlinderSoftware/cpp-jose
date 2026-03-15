[ ] Add functional tests for import & export:
    [x] Import an RSA from JSON, exported public key only, use the validate 
        signature
    [ ] Import an RSA from JSON, exported private key, use the validate signature
    [ ] Import an RSA from JSON, exported public key only, use the encrypt/
        decrypt
    [ ] Import an RSA from JSON, exported private key, use the encrypt/decrypt
    [ ] Import an EC from JSON, exported public key only, use the validate 
        signature
    [ ] Import an EC from JSON, exported private key, use the validate signature
    [ ] Import an EC from JSON, exported public key only, use the encrypt/decrypt
    [ ] Import an EC from JSON, exported private key, use the encrypt/decrypt
    [ ] Import an OCT from JSON, exported public key only, use the validate 
        signature
    [ ] Import an OCT from JSON, exported private key, use the validate signature
    [ ] Import an OCT from JSON, exported public key only, use the encrypt/
        decrypt
    [ ] Import an OCT from JSON, exported private key, use the encrypt/decrypt
    [ ] Import an OKP from JSON, exported public key only, use the validate 
        signature
    [ ] Import an OKP from JSON, exported private key, use the validate signature
    [ ] Import an OKP from JSON, exported public key only, use the encrypt/
        decrypt
    [ ] Import an OKP from JSON, exported private key, use the encrypt/decrypt
[ ] Test against Node and Python reference implementations (interop tests -- see 
    below)
[ ] Add permissive tests for missing use, missing alg

[x] Expand and run full test list:
    [x] test_base64url.cpp
    [x] test_jwk.cpp
    [x] test_endian.cpp
    [x] test_concat_kdf.cpp
    [x] test_cng_base64.cpp (CNG backend only)
    [x] test_cng_generate_key.cpp (CNG backend only)

[ ] Add OpenSSL-only OKP test coverage:
    [x] Generate Ed25519 and X25519 keys
    [x] Round-trip OKP JSON (public and private)
    [ ] Import known OKP JWKs (public and private)

[x] Re-enable full JOSE test targets in tests/CMakeLists.txt:
    [x] test_jwa.cpp
    [x] test_jws.cpp
    [x] test_jwe.cpp
    [x] test_jwt.cpp
    [x] test_jwk_thumbprint.cpp
    [x] test_rfc7520_examples.cpp

[x] Complete CNG JWA implementation:
    [x] Implement JWA::sign / JWA::verify in src/private/cng_jwa.cpp
    [x] Implement JWA::encryptKey / JWA::decryptKey in src/private/cng_jwa.cpp
    [x] Implement JWA::encryptContent / JWA::decryptContent in src/private/
        cng_jwa.cpp
    [x] Add backend-parity tests for OpenSSL vs CNG behavior

[ ] Style:
    [ ] All if blocks should be block statements

[ ]  RFC 7517:
     [ ] add support for "x5u" (X.509 URL) Parameter
     [ ] add support for "x5c" (X.509 Certificate Chain) Parameter
     [ ] add support for "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter
     [ ] add support for "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) parameter

[ ] Interop tests:
    [ ] CLI vs. Python
    [ ] CLI vs. Node
    [ ] Validate JWK String Comparison Rules
    [ ] Validate Encrypted JWK and Encrypted JWK Set Formats
    [ ] JWK duplicate members: |
        The member names within a JWK MUST be unique; JWK parsers MUST either
        reject JWKs with duplicate member names or use a JSON parser that
        returns only the lexically last duplicate member name, as specified
        in Section 15.12 (The JSON Object) of ECMAScript 5.1 [ECMAScript].
    [ ] JWK key use and ops validation: |
        The "use" and "key_ops" JWK members SHOULD NOT be used together;
        however, if both are used, the information they convey MUST be
        consistent.  Applications should specify which of these members they
        use, if either is to be used by the application.
    [ ] JWK sets: validate they can contain more than one key with the same kid
    [ ] JWK: validate kid is optional on parse and can be omitted when serialized
        if we are re-serializing a key that didn't have one (i.e. do not
        gratuitously add a kid)
    [ ] JWK: x5u parameters are reserialized when parsed
    [ ] JWK: x5c parameters are reserialized when parsed
    [ ] JWK: x5t parameters are reserialized when parsed
    [ ] JWK: x5t#S256 parameters are reserialized when parsed
    [ ] JWK: validate that x5u, x5c, x5t, and x5t#S256 are not mutually exclusive
    [ ] JWKS: validate that parsing an empty set works, provided the keys 
        parameter is present
    [ ] JWKS: validate that the CLI will cowardly refuse to produce an empty set 
        (and will use that wording)
    [ ] JWKS: functionally ignore but reserialize unknown members|
        Additional members can be present in the JWK Set; if not understood
        by implementations encountering them, they MUST be ignored.
    [ ] JWKS: functionally ignore but reserialize keys with unknown types or 
        missing members |
        Implementations SHOULD ignore JWKs within a JWK Set that use "kty"
        (key type) values that are not understood by them, that are missing
        required members, or for which values are out of the supported
        ranges.
    [ ] JWKS: validate that the order of keys in the set is preserved on 
        reserialization
    [ ] JWS: permit the use of larger-than-necessary keys for HMAC validation
    [ ] JWS: CLI to cowardly refuse to sign something with a bigger-than-needed
        key unless forced
    [ ] JWE: when encrypting with ECDH-ES, the local private key is always 
        ephemeral and fresh
        [ ] epk header parameter is a JWK with minimal parameters for the 
            represented public key
        [ ] on parse, if additional header parameters are present they are 
            checked for consistency
    [ ] JWE: validate that the encrypting key's intended use is for encryption
    [ ] JWE: validate that is a signing key's public key is used to encrypt a 
        key *to*, the CLI will refuse unless forced
    [ ] JWE: validate we don't encrypt *to* a signing key unless forced

[ ] CLI
    [ ] JWK sets
    [ ] validate streaming with jq
    [ ] JWK: allow specification of a x5u parameter
    [ ] JWK: (Nice to have) use the x5u to validate the public key, use, and alg
        parameters
    [ ] JWK: allow taking a certificate chain as input and generating the JWK 
        from the leaf certificate (which should by convention be first). Allow 
        optionally including x5c parameter (which is the base64-encoded DER 
        representation of those same certificates, starting with the leaf).
    [ ] JWK: allow taking a certificate as input and generating the JWK from it,
        and optionally adding an x5t and/or x5t#S256 parameter
    [ ] JKWS: cowardly refuse to serialize an unencrypted set that contains 
        private keys unless forced
    [ ] JWS: refuse "none" alg signatures unless told to accept them

[ ] COSE support
    nlohmann library already supports CBOR

[ ] Documentation
    [ ] For JWE ECDH-ES, explains OtherInfo according to NIST.SP.800-56A: |
        OtherInfo: A bit string equal to the following concatenation: 
            AlgorithmID || PartyUInfo || PartyVInfo
            {|| SuppPubInfo }{|| SuppPrivInfo } 
        where the subfields are defined as follows:   
        AlgorithmID: A bit string that indicates how the derived keying material 
            will be parsed and for which algorithm(s) the derived secret keying
            material will be used. For example, AlgorithmID might indicate that
            bits 1-80 are to be used as an 80-bit HMAC key and that bits 81-208 
            are to be used as a 128-bit AES key.
            In JOSE, this is the UTF-8 encoded "alg" parameter
        PartyUInfo: A bit string containing public information that is required
            by the application using this KDF to be contributed by party U to 
            the key derivation process. At a minimum, PartyUInfo shall include
            IDU, the identifier of party U. (...))
            In JOSE, this is the contents of the "apu" parameter, which should
            be a unique identifier of the sender.
            Recommend this to be the sender's `kid` of the key used to sign the 
            message (as ECDH-ES does not itself authenticate the sender due to 
            its using an ephemeral key).
        PartyVInfo: A bit string containing public information that is required 
            by the application using this KDF to be contributed by party V to 
            the key derivation process. At a minimum, PartyVInfo shall include 
            IDV, the identifier of party V. See the notes below.
            Recommend this to be the recipient `kid`.
        SuppPubInfo: A bit string containing additional, mutually-known public 
            information. 
            In JOSE, this is the length of the key in bits
        SuppPrivInfo: A bit string containing additional, mutually-known private 
            information (for example, a shared secret symmetric key that has
            been communicated through a separate channel). 
            In JOSE this is not used and empty.
