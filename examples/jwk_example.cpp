/**
 * @file jwk_example.cpp
 * @brief JWK generation, serialization, and thumbprint example
 *
 * Demonstrates:
 * - Generating different types of JWKs (RSA, EC, symmetric)
 * - JWK serialization (public and private)
 * - JWK deserialization from JSON
 * - JWK Sets (JWKS)
 * - JWK Thumbprints (RFC 7638)
 * - Key metadata (kid, use, alg)
 */

#include <exception>
#include <iostream>

#include "jose/jose.hpp"

using namespace Vlinder::JOSE;

void printSeparator()
{
    std::cout << "\n--------------------------------------------------" << std::endl;
}

int main()
{
    try
    {
        std::cout << "=== JWK Example ===" << std::endl;
        std::cout << "\nJSON Web Key (JWK) provides a standardized way" << std::endl;
        std::cout << "to represent cryptographic keys in JSON format." << std::endl;

        // Example 1: Generate RSA Key
        std::cout << "\n\n1. Generating RSA Keys" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\nGenerating 2048-bit RSA key..." << std::endl;
        JWK rsa_key = JWK::generateRSA(2048, "RS256");

        std::cout << "✓ RSA key generated" << std::endl;
        std::cout << "  Key ID (SHA-512 thumbprint): " << rsa_key.getKeyID() << std::endl;
        std::cout << "  Algorithm: " << rsa_key.getAlgorithm() << std::endl;
        std::cout << "  Has Private Key: " << (rsa_key.hasPrivateKey() ? "Yes" : "No") << std::endl;

        std::cout << "\nPublic Key (JSON):" << std::endl;
        std::cout << rsa_key.toJSON(false) << std::endl;

        std::cout << "\nPrivate Key (JSON - first 200 chars):" << std::endl;
        std::string private_json = rsa_key.toJSON(true);
        std::cout << private_json.substr(0, 200) << "..." << std::endl;

        // Example 2: Generate EC Keys
        std::cout << "\n\n2. Generating Elliptic Curve Keys" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\n--- P-256 Curve ---" << std::endl;
        JWK ec_key_256 = JWK::generateEC("P-256", "ES256");

        std::cout << "✓ EC P-256 key generated" << std::endl;
        std::cout << "  Key ID (SHA-512 thumbprint): " << ec_key_256.getKeyID() << std::endl;
        std::cout << "Public Key: " << ec_key_256.toJSON(false) << std::endl;

        std::cout << "\n--- P-384 Curve ---" << std::endl;
        JWK ec_key_384 = JWK::generateEC("P-384", "ES384");
        std::cout << "✓ EC P-384 key generated" << std::endl;
        std::cout << "  Key ID (SHA-512 thumbprint): " << ec_key_384.getKeyID() << std::endl;

        std::cout << "\n--- P-521 Curve ---" << std::endl;
        JWK ec_key_521 = JWK::generateEC("P-521", "ES512");
        std::cout << "✓ EC P-521 key generated" << std::endl;
        std::cout << "  Key ID (SHA-512 thumbprint): " << ec_key_521.getKeyID() << std::endl;

        // Example 3: Generate Symmetric Keys
        std::cout << "\n\n3. Generating Symmetric Keys" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\n--- 128-bit Key ---" << std::endl;
        JWK oct_key_128 = JWK::generateOct(128, "HS256");
        std::cout << "✓ 128-bit symmetric key generated" << std::endl;
        std::cout << "  Key ID (SHA-512 thumbprint): " << oct_key_128.getKeyID() << std::endl;

        std::cout << "\n--- 256-bit Key ---" << std::endl;
        JWK oct_key_256 = JWK::generateOct(256, "HS256");
        std::cout << "✓ 256-bit symmetric key generated" << std::endl;
        std::cout << "  Key ID (SHA-512 thumbprint): " << oct_key_256.getKeyID() << std::endl;
        std::cout << "Public representation: " << oct_key_256.toJSON(false) << std::endl;

        // Example 4: JWK Serialization and Deserialization
        std::cout << "\n\n4. JWK Serialization and Deserialization" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::string serialized = rsa_key.toJSON(true);
        std::cout << "\nSerializing RSA key to JSON..." << std::endl;
        std::cout << "JSON length: " << serialized.length() << " characters" << std::endl;

        std::cout << "\nDeserializing from JSON..." << std::endl;
        JWK deserialized = JWK::fromJSON(serialized);
        std::cout << "✓ Key deserialized successfully" << std::endl;
        std::cout << "  Key ID: " << deserialized.getKeyID() << std::endl;
        std::cout << "  Algorithm: " << deserialized.getAlgorithm() << std::endl;
        std::cout << "  Has Private Key: " << (deserialized.hasPrivateKey() ? "Yes" : "No")
                  << std::endl;

        // Example 5: JWK Sets (JWKS)
        std::cout << "\n\n5. JSON Web Key Sets (JWKS)" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\nCreating JWK Set with multiple keys..." << std::endl;
        JWKSet jwks;

        JWK key1 = JWK::generateRSA(2048, "RS256");
        jwks.addKey(key1);
        std::cout << "  Added RSA key with ID: " << key1.getKeyID() << std::endl;

        JWK key2 = JWK::generateEC("P-256", "ES256");
        jwks.addKey(key2);
        std::cout << "  Added EC key with ID: " << key2.getKeyID() << std::endl;

        JWK key3 = JWK::generateOct(256, "HS256");
        jwks.addKey(key3);
        std::cout << "  Added Oct key with ID: " << key3.getKeyID() << std::endl;

        std::cout << "✓ Added 3 keys to JWKS" << std::endl;

        std::string jwks_json = jwks.toJSON();
        std::cout << "\nJWKS (first 300 chars):" << std::endl;
        std::cout << jwks_json.substr(0, 300) << "..." << std::endl;

        std::cout << "\nRetrieving key by ID..." << std::endl;
        JWK retrieved_key = jwks.getKey(key2.getKeyID());
        std::cout << "✓ Retrieved key: " << retrieved_key.getKeyID() << std::endl;
        std::cout << "  Algorithm: " << retrieved_key.getAlgorithm() << std::endl;

        std::vector<JWK> allKeys = jwks.getKeys();
        std::cout << "\nTotal keys in set: " << allKeys.size() << std::endl;

        // Example 6: JWK Thumbprints (RFC 7638)
        std::cout << "\n\n6. JWK Thumbprints (RFC 7638)" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\nComputing thumbprints for different key types..." << std::endl;

        std::cout << "\n--- RSA Key Thumbprint ---" << std::endl;
        std::string rsa_thumbprint = JWKThumbprint::compute(rsa_key);
        std::cout << "SHA-256: " << rsa_thumbprint << std::endl;

        std::string rsa_thumbprint_384 = JWKThumbprint::compute(rsa_key, "SHA-384");
        std::cout << "SHA-384: " << rsa_thumbprint_384 << std::endl;

        std::cout << "\n--- EC Key Thumbprint ---" << std::endl;
        try
        {
            std::string ec_thumbprint = JWKThumbprint::compute(ec_key_256);
            std::cout << "SHA-256: " << ec_thumbprint << std::endl;
        }
        catch (const std::exception& e)
        {
            std::cout << "Note: EC key thumbprint computation requires curve parameters"
                      << std::endl;
            std::cout << "(Some implementations may not export all required fields)" << std::endl;
        }

        std::cout << "\n--- Symmetric Key Thumbprint ---" << std::endl;
        try
        {
            std::string oct_thumbprint = JWKThumbprint::compute(oct_key_256);
            std::cout << "SHA-256: " << oct_thumbprint << std::endl;
        }
        catch (const std::exception& e)
        {
            std::cout << "Note: Symmetric key thumbprint requires key material" << std::endl;
            std::cout << "(Public representation doesn't include key value)" << std::endl;
        }

        // Example 7: Automatic Thumbprints as Key IDs
        std::cout << "\n\n7. Automatic Thumbprints as Key IDs" << std::endl;
        std::cout << "=========================================="<< std::endl;

        std::cout << "\nAll generated keys automatically use SHA-512 thumbprint as Key ID:" << std::endl;
        
        JWK auto_key = JWK::generateRSA(2048);
        std::string auto_thumbprint_sha512 = JWKThumbprint::compute(auto_key, "SHA-512");
        std::string auto_thumbprint_sha256 = JWKThumbprint::compute(auto_key, "SHA-256");
        
        std::cout << "\nAuto-generated Key ID: " << auto_key.getKeyID() << std::endl;
        std::cout << "SHA-512 thumbprint:    " << auto_thumbprint_sha512 << std::endl;
        std::cout << "SHA-256 thumbprint:    " << auto_thumbprint_sha256 << std::endl;
        std::cout << "\n✓ Key ID matches SHA-512 thumbprint: " 
                  << (auto_key.getKeyID() == auto_thumbprint_sha512 ? "Yes" : "No") << std::endl;
        std::cout << "SHA-512 length: " << auto_thumbprint_sha512.length() << " characters" << std::endl;

        // Example 8: Key Metadata
        std::cout << "\n\n8. Working with Key Metadata" << std::endl;
        std::cout << "==========================================" << std::endl;

        JWK metadata_key = JWK::generateRSA(2048, "RS256");

        std::cout << "\nKey with metadata set during generation:" << std::endl;
        std::cout << "  Key ID (auto): " << metadata_key.getKeyID() << std::endl;
        std::cout << "  Use: Signature" << std::endl;
        std::cout << "  Algorithm: " << metadata_key.getAlgorithm() << std::endl;
        std::cout << "  Key Type: RSA" << std::endl;
        
        std::cout << "\nNote: 'use' and 'alg' fields are OPTIONAL metadata." << std::endl;
        std::cout << "They're useful for key management in JWKS but not required" << std::endl;
        std::cout << "for cryptographic operations. You can omit them entirely." << std::endl;

        std::cout << "\nPublic JWK:" << std::endl;
        std::cout << metadata_key.toJSON(false) << std::endl;

        // Example 9: Public/Private Key Pairs
        std::cout << "\n\n9. Public/Private Key Pairs" << std::endl;
        std::cout << "==========================================" << std::endl;

        JWK key_pair = JWK::generateEC("P-256");

        std::cout << "\nGenerated EC key pair" << std::endl;
        std::cout << "Auto-generated Key ID: " << key_pair.getKeyID() << std::endl;
        std::cout << "Has private key: " << (key_pair.hasPrivateKey() ? "Yes" : "No") << std::endl;

        std::string public_only = key_pair.toJSON(false);
        std::cout << "\nPublic key only:" << std::endl;
        std::cout << public_only << std::endl;

        std::string with_private = key_pair.toJSON(true);
        std::cout << "\nWith private key (length): " << with_private.length() << " characters"
                  << std::endl;

        JWK public_key = JWK::fromJSON(public_only);
        std::cout << "\nParsed public key:" << std::endl;
        std::cout << "Has private key: " << (public_key.hasPrivateKey() ? "Yes" : "No") << std::endl;

        // Example 10: Key Type Identification
        std::cout << "\n\n10. Key Type Identification" << std::endl;
        std::cout << "==========================================" << std::endl;

        auto print_key_type = [](const JWK& key, const std::string& name)
        {
            std::cout << "\n" << name << ":" << std::endl;
            JWK::KeyType type = key.getKeyType();
            std::string type_str;
            switch (type)
            {
                case JWK::KeyType::rsa:
                    type_str = "RSA";
                    break;
                case JWK::KeyType::ec:
                    type_str = "Elliptic Curve";
                    break;
                case JWK::KeyType::okp:
                    type_str = "Octet Key Pair";
                    break;
                case JWK::KeyType::oct:
                    type_str = "Symmetric (oct)";
                    break;
            }
            std::cout << "  Type: " << type_str << std::endl;
        };

        print_key_type(rsa_key, "RSA Key");
        print_key_type(ec_key_256, "EC Key");
        print_key_type(oct_key_256, "Symmetric Key");

        std::cout << "\n\n=== JWK Example Complete ===" << std::endl;
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
