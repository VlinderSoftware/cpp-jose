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

using namespace std;

using namespace Vlinder::JOSE;

void printTimestamp(const string &label, chrono::system_clock::time_point tp)
{
    auto time = chrono::system_clock::to_time_t(tp);
    cout << label << ": " << put_time(gmtime(&time), "%Y-%m-%d %H:%M:%S UTC") << endl;
}

int main()
{
    try
    {
        cout << "=== JWT Example ===" << endl << endl;

        // Generate a signing key (using HMAC with symmetric key)
        cout << "1. Generating symmetric key (HS256)..." << endl;
        JWK key = JWK::generateOct(JWK::Use::signature);
        cout << "   Key generated with auto-generated ID: " << key.getKeyID() << endl;
        cout << "   Algorithm (auto-selected): " << key.getAlgorithm() << endl << endl;

        // Create a JWT with standard claims
        cout << "2. Creating JWT with standard claims..." << endl;
        JWT jwt;
        jwt.setIssuer("https://auth.example.com");
        jwt.setSubject("user@example.com");
        jwt.setAudience("https://api.example.com");

        auto now = chrono::system_clock::now();
        jwt.setIssuedAt(now);
        jwt.setNotBefore(now);
        jwt.setExpiration(now + chrono::hours(1));
        jwt.setJWTID("unique-jwt-id-12345");

        // Add custom claims
        jwt.setClaim("role", "admin");
        jwt.setClaim("department", "engineering");

        cout << "   Issuer: " << jwt.getIssuer() << endl;
        cout << "   Subject: " << jwt.getSubject() << endl;
        printTimestamp("   Issued At", jwt.getIssuedAt());
        printTimestamp("   Expires At", jwt.getExpiration());
        cout << "   Custom claim 'role': " << jwt.getClaim("role") << endl << endl;

        // Sign the JWT
        cout << "3. Signing JWT with HS256..." << endl;
        string token = jwt.sign(key, "HS256");
        cout << "   Token: " << token.substr(0, 50) << "..." << endl
             << "   (Length: " << token.length() << " characters)" << endl
             << endl;

        // Verify and parse the JWT
        cout << "4. Verifying and parsing JWT..." << endl;
        JWT verified = JWT::verify(token, key);
        cout << "   ✓ Signature verified successfully" << endl;
        cout << "   Subject: " << verified.getSubject() << endl;
        cout << "   JWT ID: " << verified.getJWTID() << endl;
        cout << "   Custom claim 'department': " << verified.getClaim("department") << endl << endl;

        // Validate claims
        cout << "5. Validating JWT claims..." << endl;
        bool is_valid = verified.validate("https://auth.example.com",  // Expected issuer
                                          "https://api.example.com",   // Expected audience
                                          5  // 5 seconds leeway for time-based claims
        );
        cout << "   Validation result: " << (is_valid ? "✓ VALID" : "✗ INVALID") << endl << endl;

        // Try with RSA keys
        cout << "6. Creating JWT with RSA signature (RS256)..." << endl;
        JWK rsa_key = JWK::generateRSA(JWK::Use::signature);
        cout << "   RSA key generated with auto-generated ID: " << rsa_key.getKeyID() << endl;
        cout << "   Algorithm (auto-selected): " << rsa_key.getAlgorithm() << endl;

        JWT jwt_rsa;
        jwt_rsa.setIssuer("https://secure.example.com");
        jwt_rsa.setSubject("admin@example.com");
        jwt_rsa.setExpiration(now + chrono::hours(2));

        string rsa_token = jwt_rsa.sign(rsa_key, "RS256");
        cout << "   Token created with RS256" << endl;
        cout << "   Token length: " << rsa_token.length() << " characters" << endl;

        JWT verified_rsa = JWT::verify(rsa_token, rsa_key);
        cout << "   ✓ RSA signature verified" << endl;
        cout << "   Subject: " << verified_rsa.getSubject() << endl << endl;

        // Parse without verification (useful for inspecting tokens)
        cout << "7. Parsing JWT without verification..." << endl;
        JWT parsed = JWT::parse(token);
        cout << "   Issuer: " << parsed.getIssuer() << endl;
        cout << "   Subject: " << parsed.getSubject() << endl;
        cout << "   Note: This only parses, does NOT verify the signature!" << endl << endl;

        // Demonstrate validation failure
        cout << "8. Testing validation with wrong issuer..." << endl;
        bool invalid_result = verified.validate("https://wrong-issuer.com",  // Wrong issuer
                                                "https://api.example.com",
                                                5);
        cout << "   Validation result: " << (invalid_result ? "✓ VALID" : "✗ INVALID") << endl;
        cout << "   (Expected failure due to issuer mismatch)" << endl << endl;

        cout << "=== JWT Example Complete ===" << endl;
        return 0;
    }
    catch (const exception &e)
    {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
}
