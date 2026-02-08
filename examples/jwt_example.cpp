/**
 * @file jwt_example.cpp
 * @brief Complete JWT workflow example
 *
 * Demonstrates:
 * - Creating JWTs with standard claims
 * - Signing JWTs with different algorithms
 * - Verifying and parsing JWTs
 * - Validating JWT claims
 */

#include <chrono>
#include <exception>
#include <iomanip>
#include <iostream>

#include "jose/jose.hpp"

using namespace Vlinder::jose;

void printTimestamp(const std::string& label, std::chrono::system_clock::time_point tp)
{
    auto time = std::chrono::system_clock::to_time_t(tp);
    std::cout << label << ": " << std::put_time(std::gmtime(&time), "%Y-%m-%d %H:%M:%S UTC")
              << std::endl;
}

int main()
{
    try
    {
        std::cout << "=== JWT Example ===" << std::endl << std::endl;

        // Generate a signing key (using HMAC with symmetric key)
        std::cout << "1. Generating symmetric key (HS256)..." << std::endl;
        JWK key = JWK::generateOct(256);
        key.setKeyId("my-key-2024");
        key.setAlgorithm("HS256");
        std::cout << "   Key generated with ID: " << key.getKeyId() << std::endl << std::endl;

        // Create a JWT with standard claims
        std::cout << "2. Creating JWT with standard claims..." << std::endl;
        JWT jwt;
        jwt.setIssuer("https://auth.example.com");
        jwt.setSubject("user@example.com");
        jwt.setAudience("https://api.example.com");

        auto now = std::chrono::system_clock::now();
        jwt.setIssuedAt(now);
        jwt.setNotBefore(now);
        jwt.setExpiration(now + std::chrono::hours(1));
        jwt.setJwtId("unique-jwt-id-12345");

        // Add custom claims
        jwt.setClaim("role", "admin");
        jwt.setClaim("department", "engineering");

        std::cout << "   Issuer: " << jwt.getIssuer() << std::endl;
        std::cout << "   Subject: " << jwt.getSubject() << std::endl;
        printTimestamp("   Issued At", jwt.getIssuedAt());
        printTimestamp("   Expires At", jwt.getExpiration());
        std::cout << "   Custom claim 'role': " << jwt.getClaim("role") << std::endl << std::endl;

        // Sign the JWT
        std::cout << "3. Signing JWT with HS256..." << std::endl;
        std::string token = jwt.sign(key, "HS256");
        std::cout << "   Token: " << token.substr(0, 50) << "..." << std::endl
                  << "   (Length: " << token.length() << " characters)" << std::endl
                  << std::endl;

        // Verify and parse the JWT
        std::cout << "4. Verifying and parsing JWT..." << std::endl;
        JWT verified = JWT::verify(token, key);
        std::cout << "   ✓ Signature verified successfully" << std::endl;
        std::cout << "   Subject: " << verified.getSubject() << std::endl;
        std::cout << "   JWT ID: " << verified.getJwtId() << std::endl;
        std::cout << "   Custom claim 'department': " << verified.getClaim("department")
                  << std::endl
                  << std::endl;

        // Validate claims
        std::cout << "5. Validating JWT claims..." << std::endl;
        bool isValid = verified.validate("https://auth.example.com",  // Expected issuer
                                         "https://api.example.com",   // Expected audience
                                         5  // 5 seconds leeway for time-based claims
        );
        std::cout << "   Validation result: " << (isValid ? "✓ VALID" : "✗ INVALID") << std::endl
                  << std::endl;

        // Try with RSA keys
        std::cout << "6. Creating JWT with RSA signature (RS256)..." << std::endl;
        JWK rsaKey = JWK::generateRSA(2048);
        rsaKey.setKeyId("rsa-key-2024");

        JWT jwtRsa;
        jwtRsa.setIssuer("https://secure.example.com");
        jwtRsa.setSubject("admin@example.com");
        jwtRsa.setExpiration(now + std::chrono::hours(2));

        std::string rsaToken = jwtRsa.sign(rsaKey, "RS256");
        std::cout << "   Token created with RS256" << std::endl;
        std::cout << "   Token length: " << rsaToken.length() << " characters" << std::endl;

        JWT verifiedRsa = JWT::verify(rsaToken, rsaKey);
        std::cout << "   ✓ RSA signature verified" << std::endl;
        std::cout << "   Subject: " << verifiedRsa.getSubject() << std::endl << std::endl;

        // Parse without verification (useful for inspecting tokens)
        std::cout << "7. Parsing JWT without verification..." << std::endl;
        JWT parsed = JWT::parse(token);
        std::cout << "   Issuer: " << parsed.getIssuer() << std::endl;
        std::cout << "   Subject: " << parsed.getSubject() << std::endl;
        std::cout << "   Note: This only parses, does NOT verify the signature!" << std::endl
                  << std::endl;

        // Demonstrate validation failure
        std::cout << "8. Testing validation with wrong issuer..." << std::endl;
        bool invalidResult = verified.validate("https://wrong-issuer.com",  // Wrong issuer
                                               "https://api.example.com", 5);
        std::cout << "   Validation result: " << (invalidResult ? "✓ VALID" : "✗ INVALID")
                  << std::endl;
        std::cout << "   (Expected failure due to issuer mismatch)" << std::endl << std::endl;

        std::cout << "=== JWT Example Complete ===" << std::endl;
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
