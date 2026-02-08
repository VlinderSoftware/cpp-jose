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

using namespace Vlinder::jose;

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
        JWK rsaKey = JWK::generateRSA(2048);
        rsaKey.setKeyId("rsa-2048-key");
        rsaKey.setUse(JWK::Use::Signature);
        rsaKey.setAlgorithm("RS256");

        std::cout << "✓ RSA key generated" << std::endl;
        std::cout << "  Key ID: " << rsaKey.getKeyId() << std::endl;
        std::cout << "  Algorithm: " << rsaKey.getAlgorithm() << std::endl;
        std::cout << "  Has Private Key: " << (rsaKey.hasPrivateKey() ? "Yes" : "No") << std::endl;

        std::cout << "\nPublic Key (JSON):" << std::endl;
        std::cout << rsaKey.toJson(false) << std::endl;

        std::cout << "\nPrivate Key (JSON - first 200 chars):" << std::endl;
        std::string privateJson = rsaKey.toJson(true);
        std::cout << privateJson.substr(0, 200) << "..." << std::endl;

        // Example 2: Generate EC Keys
        std::cout << "\n\n2. Generating Elliptic Curve Keys" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\n--- P-256 Curve ---" << std::endl;
        JWK ecKey256 = JWK::generateEC("P-256");
        ecKey256.setKeyId("ec-p256-key");
        ecKey256.setUse(JWK::Use::Signature);
        ecKey256.setAlgorithm("ES256");

        std::cout << "✓ EC P-256 key generated" << std::endl;
        std::cout << "Public Key: " << ecKey256.toJson(false) << std::endl;

        std::cout << "\n--- P-384 Curve ---" << std::endl;
        JWK ecKey384 = JWK::generateEC("P-384");
        ecKey384.setKeyId("ec-p384-key");
        ecKey384.setAlgorithm("ES384");
        std::cout << "✓ EC P-384 key generated" << std::endl;

        std::cout << "\n--- P-521 Curve ---" << std::endl;
        JWK ecKey521 = JWK::generateEC("P-521");
        ecKey521.setKeyId("ec-p521-key");
        ecKey521.setAlgorithm("ES512");
        std::cout << "✓ EC P-521 key generated" << std::endl;

        // Example 3: Generate Symmetric Keys
        std::cout << "\n\n3. Generating Symmetric Keys" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\n--- 128-bit Key ---" << std::endl;
        JWK octKey128 = JWK::generateOct(128);
        octKey128.setKeyId("oct-128-key");
        octKey128.setAlgorithm("HS256");
        std::cout << "✓ 128-bit symmetric key generated" << std::endl;

        std::cout << "\n--- 256-bit Key ---" << std::endl;
        JWK octKey256 = JWK::generateOct(256);
        octKey256.setKeyId("oct-256-key");
        octKey256.setAlgorithm("HS256");
        std::cout << "✓ 256-bit symmetric key generated" << std::endl;
        std::cout << "Public representation: " << octKey256.toJson(false) << std::endl;

        // Example 4: JWK Serialization and Deserialization
        std::cout << "\n\n4. JWK Serialization and Deserialization" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::string serialized = rsaKey.toJson(true);
        std::cout << "\nSerializing RSA key to JSON..." << std::endl;
        std::cout << "JSON length: " << serialized.length() << " characters" << std::endl;

        std::cout << "\nDeserializing from JSON..." << std::endl;
        JWK deserialized = JWK::fromJson(serialized);
        std::cout << "✓ Key deserialized successfully" << std::endl;
        std::cout << "  Key ID: " << deserialized.getKeyId() << std::endl;
        std::cout << "  Algorithm: " << deserialized.getAlgorithm() << std::endl;
        std::cout << "  Has Private Key: " << (deserialized.hasPrivateKey() ? "Yes" : "No")
                  << std::endl;

        // Example 5: JWK Sets (JWKS)
        std::cout << "\n\n5. JSON Web Key Sets (JWKS)" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\nCreating JWK Set with multiple keys..." << std::endl;
        JWKSet jwks;

        JWK key1 = JWK::generateRSA(2048);
        key1.setKeyId("key-1");
        key1.setAlgorithm("RS256");
        jwks.addKey(key1);

        JWK key2 = JWK::generateEC("P-256");
        key2.setKeyId("key-2");
        key2.setAlgorithm("ES256");
        jwks.addKey(key2);

        JWK key3 = JWK::generateOct(256);
        key3.setKeyId("key-3");
        key3.setAlgorithm("HS256");
        jwks.addKey(key3);

        std::cout << "✓ Added 3 keys to JWKS" << std::endl;

        std::string jwksJson = jwks.toJson();
        std::cout << "\nJWKS (first 300 chars):" << std::endl;
        std::cout << jwksJson.substr(0, 300) << "..." << std::endl;

        std::cout << "\nRetrieving key by ID..." << std::endl;
        JWK retrievedKey = jwks.getKey("key-2");
        std::cout << "✓ Retrieved key: " << retrievedKey.getKeyId() << std::endl;
        std::cout << "  Algorithm: " << retrievedKey.getAlgorithm() << std::endl;

        std::vector<JWK> allKeys = jwks.getKeys();
        std::cout << "\nTotal keys in set: " << allKeys.size() << std::endl;

        // Example 6: JWK Thumbprints (RFC 7638)
        std::cout << "\n\n6. JWK Thumbprints (RFC 7638)" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\nComputing thumbprints for different key types..." << std::endl;

        std::cout << "\n--- RSA Key Thumbprint ---" << std::endl;
        std::string rsaThumbprint = JWKThumbprint::compute(rsaKey);
        std::cout << "SHA-256: " << rsaThumbprint << std::endl;

        std::string rsaThumbprint384 = JWKThumbprint::compute(rsaKey, "SHA-384");
        std::cout << "SHA-384: " << rsaThumbprint384 << std::endl;

        std::cout << "\n--- EC Key Thumbprint ---" << std::endl;
        try
        {
            std::string ecThumbprint = JWKThumbprint::compute(ecKey256);
            std::cout << "SHA-256: " << ecThumbprint << std::endl;
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
            std::string octThumbprint = JWKThumbprint::compute(octKey256);
            std::cout << "SHA-256: " << octThumbprint << std::endl;
        }
        catch (const std::exception& e)
        {
            std::cout << "Note: Symmetric key thumbprint requires key material" << std::endl;
            std::cout << "(Public representation doesn't include key value)" << std::endl;
        }

        // Example 7: Using Thumbprints as Key IDs
        std::cout << "\n\n7. Using Thumbprints as Key IDs" << std::endl;
        std::cout << "==========================================" << std::endl;

        JWK thumbprintKey = JWK::generateRSA(2048);
        std::string thumbprint = JWKThumbprint::compute(thumbprintKey);
        thumbprintKey.setKeyId(thumbprint);

        std::cout << "\nGenerated RSA key with thumbprint as Key ID:" << std::endl;
        std::cout << "Key ID: " << thumbprintKey.getKeyId() << std::endl;
        std::cout << "Length: " << thumbprintKey.getKeyId().length() << " characters" << std::endl;

        // Example 8: Key Metadata
        std::cout << "\n\n8. Working with Key Metadata" << std::endl;
        std::cout << "==========================================" << std::endl;

        JWK metadataKey = JWK::generateRSA(2048);
        metadataKey.setKeyId("prod-signing-key-2024");
        metadataKey.setUse(JWK::Use::Signature);
        metadataKey.setAlgorithm("RS256");

        std::cout << "\nKey with full metadata:" << std::endl;
        std::cout << "  Key ID: " << metadataKey.getKeyId() << std::endl;
        std::cout << "  Use: Signature" << std::endl;
        std::cout << "  Algorithm: " << metadataKey.getAlgorithm() << std::endl;
        std::cout << "  Key Type: RSA" << std::endl;

        std::cout << "\nPublic JWK:" << std::endl;
        std::cout << metadataKey.toJson(false) << std::endl;

        // Example 9: Public/Private Key Pairs
        std::cout << "\n\n9. Public/Private Key Pairs" << std::endl;
        std::cout << "==========================================" << std::endl;

        JWK keyPair = JWK::generateEC("P-256");
        keyPair.setKeyId("ec-keypair");

        std::cout << "\nGenerated EC key pair" << std::endl;
        std::cout << "Has private key: " << (keyPair.hasPrivateKey() ? "Yes" : "No") << std::endl;

        std::string publicOnly = keyPair.toJson(false);
        std::cout << "\nPublic key only:" << std::endl;
        std::cout << publicOnly << std::endl;

        std::string withPrivate = keyPair.toJson(true);
        std::cout << "\nWith private key (length): " << withPrivate.length() << " characters"
                  << std::endl;

        JWK publicKey = JWK::fromJson(publicOnly);
        std::cout << "\nParsed public key:" << std::endl;
        std::cout << "Has private key: " << (publicKey.hasPrivateKey() ? "Yes" : "No") << std::endl;

        // Example 10: Key Type Identification
        std::cout << "\n\n10. Key Type Identification" << std::endl;
        std::cout << "==========================================" << std::endl;

        auto printKeyType = [](const JWK& key, const std::string& name)
        {
            std::cout << "\n" << name << ":" << std::endl;
            JWK::KeyType type = key.getKeyType();
            std::string typeStr;
            switch (type)
            {
                case JWK::KeyType::RSA:
                    typeStr = "RSA";
                    break;
                case JWK::KeyType::EC:
                    typeStr = "EC";
                    break;
                case JWK::KeyType::OKP:
                    typeStr = "OKP";
                    break;
                case JWK::KeyType::oct:
                    typeStr = "Symmetric (oct)";
                    break;
            }
            std::cout << "  Type: " << typeStr << std::endl;
        };

        printKeyType(rsaKey, "RSA Key");
        printKeyType(ecKey256, "EC Key");
        printKeyType(octKey256, "Symmetric Key");

        std::cout << "\n\n=== JWK Example Complete ===" << std::endl;
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
