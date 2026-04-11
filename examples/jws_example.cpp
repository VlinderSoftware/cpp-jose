/**
 * @file jws_example.cpp
 * @brief JWS signing and verification example
 *
 * Demonstrates:
 * - Creating and signing JWS with different algorithms
 * - HMAC signatures (HS256, HS384, HS512)
 * - RSA signatures (RS256, PS256)
 * - Elliptic Curve signatures (ES256)
 * - Verifying JWS signatures
 * - Working with JWS headers and payloads
 */

#include <exception>
#include <iostream>

#include "jose/jose.hpp"

using namespace std;

using namespace Vlinder::JOSE;

void demonstrateAlgorithm(string const &alg_name, JWA::SignatureAlgorithm alg, const JWK &key)
{
    cout << "\n--- " << alg_name << " ---" << endl;

    auto payload = string("This is a test message for " + alg_name);

    string signed_jws =
        sign(key, alg, "JWS", span<char const>(payload.data(), payload.size())).toCompact();
    cout << "Signed JWS: " << signed_jws.substr(0, 60) << "..." << endl;

    auto parsed = JWS::fromCompact(signed_jws);

    bool verified = verify(parsed, key);
    cout << "Verification: " << (verified ? "✓ SUCCESS" : "✗ FAILED") << endl;
    cout << "Payload: " << parsed.getPayload<string>() << endl;
}

int main()
{
    try
    {
        cout << "=== JWS Example ===" << endl;
        cout << "\nJSON Web Signature (JWS) provides digital signature" << endl;
        cout << "and MAC functionality for arbitrary payloads." << endl;

        // Example 1: HMAC Signatures
        cout << "\n\n1. HMAC Signatures (Symmetric Keys)" << endl;
        cout << "==========================================" << endl;

        JWK hmac_key_256 = JWK::generateOct(JWK::Use::signature);
        demonstrateAlgorithm("HS256", JWA::SignatureAlgorithm::hs256, hmac_key_256);

        JWK hmac_key_384 = JWK::generateOct(JWK::Use::signature, 384, "HS384");
        demonstrateAlgorithm("HS384", JWA::SignatureAlgorithm::hs384, hmac_key_384);

        JWK hmac_key_512 = JWK::generateOct(JWK::Use::signature, 512, "HS512");
        demonstrateAlgorithm("HS512", JWA::SignatureAlgorithm::hs512, hmac_key_512);

        // Example 2: RSA Signatures
        cout << "\n\n2. RSA Signatures (Asymmetric Keys)" << endl;
        cout << "==========================================" << endl;

        cout << "\nGenerating 2048-bit RSA key..." << endl;
        JWK rsa_key = JWK::generateRSA(JWK::Use::signature);
        cout << "RSA key generated with auto-generated ID: " << rsa_key.getKeyID() << endl;
        cout << "Algorithm (auto-selected): " << rsa_key.getAlgorithm() << endl;

        demonstrateAlgorithm("RS256", JWA::SignatureAlgorithm::rs256, rsa_key);
        demonstrateAlgorithm("PS256", JWA::SignatureAlgorithm::ps256, rsa_key);

        // Example 3: Elliptic Curve Signatures
        cout << "\n\n3. Elliptic Curve Signatures" << endl;
        cout << "==========================================" << endl;

        cout << "\nGenerating P-256 EC key..." << endl;
        JWK ec_key = JWK::generateEC(JWK::Use::signature);
        cout << "EC key generated with auto-generated ID: " << ec_key.getKeyID() << endl;
        cout << "Algorithm (auto-selected): " << ec_key.getAlgorithm() << endl;

        demonstrateAlgorithm("ES256", JWA::SignatureAlgorithm::es256, ec_key);

        // Example 4: Working with Headers
        cout << "\n\n4. Custom Headers" << endl;
        cout << "==========================================" << endl;

        auto payload = string("{\"userId\":\"12345\",\"action\":\"login\"}");
        auto custom_signed = sign(hmac_key_256,
                                  JWA::SignatureAlgorithm::hs256,
                                  "JWT",
                                  {{"cty", "application/json"}, {"custom", "header-value"}},
                                  span<char const>(payload.data(), payload.size()))
                                 .toCompact();

        cout << "\nSigned JWS with custom headers" << endl;

        JWS custom_parsed = JWS::fromCompact(custom_signed);

        // TODO
        //  cout << "Header: " << custom_parsed.getHeader() << endl;
        //  cout << "Payload: " << custom_parsed.getPayload() << endl;

        bool custom_verified = verify(custom_parsed, hmac_key_256);
        cout << "Verification: " << (custom_verified ? "✓ SUCCESS" : "✗ FAILED") << endl;

        // Example 5: Compact Serialization Format
        cout << "\n\n5. JWS Compact Serialization" << endl;
        cout << "==========================================" << endl;

        string format_payload =
            "This is a test message to demonstrate JWS compact serialization format.";
        auto format_example = sign(hmac_key_256,
                                   JWA::SignatureAlgorithm::hs256,
                                   "JWS",
                                   span<char const>(format_payload.data(), format_payload.size()));

        string compact_jws = format_example.toCompact();
        cout << "\nJWS Compact Format: Header.Payload.Signature" << endl;
        cout << "Full JWS: " << compact_jws << endl;

        size_t first_dot = compact_jws.find('.');
        size_t second_dot = compact_jws.find('.', first_dot + 1);

        cout << "\nComponents:" << endl;
        cout << "  Header:    " << compact_jws.substr(0, first_dot) << endl;
        cout << "  Payload:   " << compact_jws.substr(first_dot + 1, second_dot - first_dot - 1)
             << endl;
        cout << "  Signature: " << compact_jws.substr(second_dot + 1) << endl;

        // Example 6: Error Handling
        cout << "\n\n6. Error Handling" << endl;
        cout << "==========================================" << endl;

        JWK wrong_key = JWK::generateOct(JWK::Use::signature);

        cout << "\nAttempting verification with wrong key..." << endl;
        bool wrong_verification = verify(JWS::fromCompact(compact_jws), wrong_key);
        cout << "Verification: " << (wrong_verification ? "✓ SUCCESS" : "✗ FAILED") << endl;
        cout << "(Expected failure - wrong key used)" << endl;

        cout << "\n\n=== JWS Example Complete ===" << endl;
        return 0;
    }
    catch (exception const &e)
    {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
}
