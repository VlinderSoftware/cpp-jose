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

#include "jose/jose.hpp"
#include <iostream>
#include <exception>

using namespace Vlinder::jose;

void demonstrateAlgorithm(const std::string& algName, 
                          JWA::SignatureAlgorithm alg,
                          const JWK& key)
{
    std::cout << "\n--- " << algName << " ---" << std::endl;
    
    JWS jws;
    jws.setPayload("This is a test message for " + algName);
    jws.setAlgorithm(alg);
    jws.setKeyId(key.getKeyId());
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
        
        JWK hmacKey256 = JWK::generateOct(256);
        hmacKey256.setKeyId("hmac-key-256");
        demonstrateAlgorithm("HS256", JWA::SignatureAlgorithm::HS256, hmacKey256);
        
        JWK hmacKey384 = JWK::generateOct(384);
        hmacKey384.setKeyId("hmac-key-384");
        demonstrateAlgorithm("HS384", JWA::SignatureAlgorithm::HS384, hmacKey384);
        
        JWK hmacKey512 = JWK::generateOct(512);
        hmacKey512.setKeyId("hmac-key-512");
        demonstrateAlgorithm("HS512", JWA::SignatureAlgorithm::HS512, hmacKey512);

        // Example 2: RSA Signatures
        std::cout << "\n\n2. RSA Signatures (Asymmetric Keys)" << std::endl;
        std::cout << "==========================================" << std::endl;
        
        std::cout << "\nGenerating 2048-bit RSA key..." << std::endl;
        JWK rsaKey = JWK::generateRSA(2048);
        rsaKey.setKeyId("rsa-key-2048");
        std::cout << "RSA key generated." << std::endl;
        
        demonstrateAlgorithm("RS256", JWA::SignatureAlgorithm::RS256, rsaKey);
        demonstrateAlgorithm("PS256", JWA::SignatureAlgorithm::PS256, rsaKey);

        // Example 3: Elliptic Curve Signatures
        std::cout << "\n\n3. Elliptic Curve Signatures" << std::endl;
        std::cout << "==========================================" << std::endl;
        
        std::cout << "\nGenerating P-256 EC key..." << std::endl;
        JWK ecKey = JWK::generateEC("P-256");
        ecKey.setKeyId("ec-key-p256");
        std::cout << "EC key generated." << std::endl;
        
        demonstrateAlgorithm("ES256", JWA::SignatureAlgorithm::ES256, ecKey);

        // Example 4: Working with Headers
        std::cout << "\n\n4. Custom Headers" << std::endl;
        std::cout << "==========================================" << std::endl;
        
        JWS customJws;
        customJws.setPayload("{\"userId\":\"12345\",\"action\":\"login\"}");
        customJws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
        customJws.setKeyId("custom-key-id");
        customJws.setType("JWT");
        customJws.setHeaderParam("cty", "application/json");
        customJws.setHeaderParam("custom", "header-value");
        
        std::string customSigned = customJws.sign(hmacKey256);
        std::cout << "\nSigned JWS with custom headers" << std::endl;
        
        JWS customParsed = JWS::parse(customSigned);
        std::cout << "Header: " << customParsed.getHeader() << std::endl;
        std::cout << "Payload: " << customParsed.getPayload() << std::endl;
        
        bool customVerified = JWS::verify(customSigned, hmacKey256);
        std::cout << "Verification: " << (customVerified ? "✓ SUCCESS" : "✗ FAILED") << std::endl;

        // Example 5: Compact Serialization Format
        std::cout << "\n\n5. JWS Compact Serialization" << std::endl;
        std::cout << "==========================================" << std::endl;
        
        JWS formatExample;
        formatExample.setPayload("Understanding JWS format");
        formatExample.setAlgorithm(JWA::SignatureAlgorithm::HS256);
        
        std::string compactJws = formatExample.sign(hmacKey256);
        std::cout << "\nJWS Compact Format: Header.Payload.Signature" << std::endl;
        std::cout << "Full JWS: " << compactJws << std::endl;
        
        size_t firstDot = compactJws.find('.');
        size_t secondDot = compactJws.find('.', firstDot + 1);
        
        std::cout << "\nComponents:" << std::endl;
        std::cout << "  Header:    " << compactJws.substr(0, firstDot) << std::endl;
        std::cout << "  Payload:   " << compactJws.substr(firstDot + 1, secondDot - firstDot - 1)
                  << std::endl;
        std::cout << "  Signature: " << compactJws.substr(secondDot + 1) << std::endl;

        // Example 6: Error Handling
        std::cout << "\n\n6. Error Handling" << std::endl;
        std::cout << "==========================================" << std::endl;
        
        JWK wrongKey = JWK::generateOct(256);
        wrongKey.setKeyId("wrong-key");
        
        std::cout << "\nAttempting verification with wrong key..." << std::endl;
        bool wrongVerification = JWS::verify(compactJws, wrongKey);
        std::cout << "Verification: " << (wrongVerification ? "✓ SUCCESS" : "✗ FAILED")
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
