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

using namespace Vlinder::JOSE;

void demonstrateAlgorithm(const std::string& alg_name, JWA::SignatureAlgorithm alg, const JWK& key)
{
    std::cout << "\n--- " << alg_name << " ---" << std::endl;

    JWS jws;
    jws.setPayload("This is a test message for " + alg_name);
    jws.setAlgorithm(alg);
    jws.setKeyID(key.getKeyID());
    jws.setType("JWS");

    std::string signed_jws = jws.sign(key);
    std::cout << "Signed JWS: " << signed_jws.substr(0, 60) << "..." << std::endl;

    bool verified = JWS::verify(signed_jws, key);
    std::cout << "Verification: " << (verified ? "✓ SUCCESS" : "✗ FAILED") << std::endl;

    JWS parsed = JWS::parse(signed_jws);
    std::cout << "Payload: " << parsed.getPayload() << std::endl;
}

int main()
{
    try
    {
        std::cout << "=== JWS Example ===" << std::endl;
        std::cout << "\nJSON Web Signature (JWS) provides digital signature" << std::endl;
        std::cout << "and MAC functionality for arbitrary payloads." << std::endl;

        // Example 1: HMAC Signatures
        std::cout << "\n\n1. HMAC Signatures (Symmetric Keys)" << std::endl;
        std::cout << "==========================================" << std::endl;

        JWK hmac_key_256 = JWK::generateOct(256);
        demonstrateAlgorithm("HS256", JWA::SignatureAlgorithm::hs256, hmac_key_256);

        JWK hmac_key_384 = JWK::generateOct(384);
        demonstrateAlgorithm("HS384", JWA::SignatureAlgorithm::hs384, hmac_key_384);

        JWK hmac_key_512 = JWK::generateOct(512);
        demonstrateAlgorithm("HS512", JWA::SignatureAlgorithm::hs512, hmac_key_512);

        // Example 2: RSA Signatures
        std::cout << "\n\n2. RSA Signatures (Asymmetric Keys)" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\nGenerating 2048-bit RSA key..." << std::endl;
        JWK rsa_key = JWK::generateRSA(2048);
        std::cout << "RSA key generated with auto-generated ID: " << rsa_key.getKeyID() << std::endl;

        demonstrateAlgorithm("RS256", JWA::SignatureAlgorithm::rs256, rsa_key);
        demonstrateAlgorithm("PS256", JWA::SignatureAlgorithm::ps256, rsa_key);

        // Example 3: Elliptic Curve Signatures
        std::cout << "\n\n3. Elliptic Curve Signatures" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\nGenerating P-256 EC key..." << std::endl;
        JWK ec_key = JWK::generateEC("P-256");
        std::cout << "EC key generated with auto-generated ID: " << ec_key.getKeyID() << std::endl;

        demonstrateAlgorithm("ES256", JWA::SignatureAlgorithm::es256, ec_key);

        // Example 4: Working with Headers
        std::cout << "\n\n4. Custom Headers" << std::endl;
        std::cout << "==========================================" << std::endl;

        JWS custom_jws;
        custom_jws.setPayload("{\"userId\":\"12345\",\"action\":\"login\"}");
        custom_jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);
        custom_jws.setKeyID(hmac_key_256.getKeyID());  // Use auto-generated key ID
        custom_jws.setType("JWT");
        custom_jws.setHeaderParam("cty", "application/json");
        custom_jws.setHeaderParam("custom", "header-value");

        std::string custom_signed = custom_jws.sign(hmac_key_256);
        std::cout << "\nSigned JWS with custom headers" << std::endl;

        JWS custom_parsed = JWS::parse(custom_signed);
        std::cout << "Header: " << custom_parsed.getHeader() << std::endl;
        std::cout << "Payload: " << custom_parsed.getPayload() << std::endl;

        bool custom_verified = JWS::verify(custom_signed, hmac_key_256);
        std::cout << "Verification: " << (custom_verified ? "✓ SUCCESS" : "✗ FAILED") << std::endl;

        // Example 5: Compact Serialization Format
        std::cout << "\n\n5. JWS Compact Serialization" << std::endl;
        std::cout << "==========================================" << std::endl;

        JWS format_example;
        format_example.setPayload("Understanding JWS format");
        format_example.setAlgorithm(JWA::SignatureAlgorithm::hs256);

        std::string compact_jws = format_example.sign(hmac_key_256);
        std::cout << "\nJWS Compact Format: Header.Payload.Signature" << std::endl;
        std::cout << "Full JWS: " << compact_jws << std::endl;

        size_t first_dot = compact_jws.find('.');
        size_t second_dot = compact_jws.find('.', first_dot + 1);

        std::cout << "\nComponents:" << std::endl;
        std::cout << "  Header:    " << compact_jws.substr(0, first_dot) << std::endl;
        std::cout << "  Payload:   " << compact_jws.substr(first_dot + 1, second_dot - first_dot - 1)
                  << std::endl;
        std::cout << "  Signature: " << compact_jws.substr(second_dot + 1) << std::endl;

        // Example 6: Error Handling
        std::cout << "\n\n6. Error Handling" << std::endl;
        std::cout << "==========================================" << std::endl;

        JWK wrong_key = JWK::generateOct(256);

        std::cout << "\nAttempting verification with wrong key..." << std::endl;
        bool wrong_verification = JWS::verify(compact_jws, wrong_key);
        std::cout << "Verification: " << (wrong_verification ? "✓ SUCCESS" : "✗ FAILED")
                  << std::endl;
        std::cout << "(Expected failure - wrong key used)" << std::endl;

        std::cout << "\n\n=== JWS Example Complete ===" << std::endl;
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
