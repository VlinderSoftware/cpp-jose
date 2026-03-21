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

using namespace std;

using namespace Vlinder::JOSE;

void printSeparator()
{
    cout << "\n--------------------------------------------------" << endl;
}

int main()
{
    try
    {
        cout << "=== JWK Example ===" << endl;
        cout << "\nJSON Web Key (JWK) provides a standardized way" << endl;
        cout << "to represent cryptographic keys in JSON format." << endl;

        // Example 1: Generate RSA Key
        cout << "\n\n1. Generating RSA Keys" << endl;
        cout << "==========================================" << endl;

        cout << "\nGenerating 2048-bit RSA key..." << endl;
        JWK rsa_key = JWK::generateRSA(JWK::Use::signature);

        cout << "✓ RSA key generated" << endl;
        cout << "  Key ID (SHA-512 thumbprint): " << rsa_key.getKeyID() << endl;
        cout << "  Algorithm (auto-selected): " << rsa_key.getAlgorithm() << endl;
        cout << "  Has Private Key: " << (rsa_key.hasPrivateKey() ? "Yes" : "No") << endl;

        cout << "\nPublic Key (JSON):" << endl;
        cout << rsa_key.toJSON(false) << endl;

        cout << "\nPrivate Key (JSON - first 200 chars):" << endl;
        string private_json = rsa_key.toJSON(true);
        cout << private_json.substr(0, 200) << "..." << endl;

        // Example 2: Generate EC Keys
        cout << "\n\n2. Generating Elliptic Curve Keys" << endl;
        cout << "==========================================" << endl;

        cout << "\n--- P-256 Curve ---" << endl;
        JWK ec_key_256 = JWK::generateEC(JWK::Use::signature);

        cout << "✓ EC P-256 key generated" << endl;
        cout << "  Key ID (SHA-512 thumbprint): " << ec_key_256.getKeyID() << endl;
        cout << "  Algorithm (auto-selected): " << ec_key_256.getAlgorithm() << endl;
        cout << "Public Key: " << ec_key_256.toJSON(false) << endl;

        cout << "\n--- P-384 Curve ---" << endl;
        JWK ec_key_384 = JWK::generateEC(JWK::Use::signature, "P-384");
        cout << "✓ EC P-384 key generated" << endl;
        cout << "  Key ID (SHA-512 thumbprint): " << ec_key_384.getKeyID() << endl;
        cout << "  Algorithm (auto-selected): " << ec_key_384.getAlgorithm() << endl;

        cout << "\n--- P-521 Curve ---" << endl;
        JWK ec_key_521 = JWK::generateEC(JWK::Use::signature, "P-521");
        cout << "✓ EC P-521 key generated" << endl;
        cout << "  Key ID (SHA-512 thumbprint): " << ec_key_521.getKeyID() << endl;
        cout << "  Algorithm (auto-selected): " << ec_key_521.getAlgorithm() << endl;

        // Example 3: Generate Symmetric Keys
        cout << "\n\n3. Generating Symmetric Keys" << endl;
        cout << "==========================================" << endl;

        cout << "\n--- 128-bit Key ---" << endl;
        JWK oct_key_128 = JWK::generateOct(JWK::Use::signature, 128);
        cout << "✓ 128-bit symmetric key generated" << endl;
        cout << "  Key ID (SHA-512 thumbprint): " << oct_key_128.getKeyID() << endl;
        cout << "  Algorithm (auto-selected): " << oct_key_128.getAlgorithm() << endl;

        cout << "\n--- 256-bit Key ---" << endl;
        JWK oct_key_256 = JWK::generateOct(JWK::Use::signature);
        cout << "✓ 256-bit symmetric key generated" << endl;
        cout << "  Key ID (SHA-512 thumbprint): " << oct_key_256.getKeyID() << endl;
        cout << "  Algorithm (auto-selected): " << oct_key_256.getAlgorithm() << endl;
        cout << "Public representation: " << oct_key_256.toJSON(false) << endl;

        // Example 4: JWK Serialization and Deserialization
        cout << "\n\n4. JWK Serialization and Deserialization" << endl;
        cout << "==========================================" << endl;

        string serialized = rsa_key.toJSON(true);
        cout << "\nSerializing RSA key to JSON..." << endl;
        cout << "JSON length: " << serialized.length() << " characters" << endl;

        cout << "\nDeserializing from JSON..." << endl;
        JWK deserialized = JWK::fromJSON(serialized);
        cout << "✓ Key deserialized successfully" << endl;
        cout << "  Key ID: " << deserialized.getKeyID() << endl;
        cout << "  Algorithm: " << deserialized.getAlgorithm() << endl;
        cout << "  Has Private Key: " << (deserialized.hasPrivateKey() ? "Yes" : "No") << endl;

        // Example 5: JWK Sets (JWKS)
        cout << "\n\n5. JSON Web Key Sets (JWKS)" << endl;
        cout << "==========================================" << endl;

        cout << "\nCreating JWK Set with multiple keys..." << endl;
        JWKSet jwks;

        JWK key1 = JWK::generateRSA(JWK::Use::signature);
        jwks.addKey(key1);
        cout << "  Added RSA key with ID: " << key1.getKeyID() << endl;

        JWK key2 = JWK::generateEC(JWK::Use::signature);
        jwks.addKey(key2);
        cout << "  Added EC key with ID: " << key2.getKeyID() << endl;

        JWK key3 = JWK::generateOct(JWK::Use::signature);
        jwks.addKey(key3);
        cout << "  Added Oct key with ID: " << key3.getKeyID() << endl;

        cout << "✓ Added 3 keys to JWKS" << endl;

        string jwks_json = jwks.toJSON();
        cout << "\nJWKS (first 300 chars):" << endl;
        cout << jwks_json.substr(0, 300) << "..." << endl;

        cout << "\nRetrieving key by ID..." << endl;
        JWK retrieved_key = get<JWK>(jwks.getKey(key2.getKeyID()));
        cout << "✓ Retrieved key: " << retrieved_key.getKeyID() << endl;
        cout << "  Algorithm: " << retrieved_key.getAlgorithm() << endl;

        auto allKeys = jwks.getKeys();
        cout << "\nTotal keys in set: " << allKeys.size() << endl;

        // Example 6: JWK Thumbprints (RFC 7638)
        cout << "\n\n6. JWK Thumbprints (RFC 7638)" << endl;
        cout << "==========================================" << endl;

        cout << "\nComputing thumbprints for different key types..." << endl;

        cout << "\n--- RSA Key Thumbprint ---" << endl;
        auto rsa_thumbprint = JWKThumbprint::compute(rsa_key);
        cout << "SHA-256: " << rsa_thumbprint << endl;

        auto rsa_thumbprint_384 = JWKThumbprint::compute(rsa_key, "SHA-384");
        cout << "SHA-384: " << rsa_thumbprint_384 << endl;

        cout << "\n--- EC Key Thumbprint ---" << endl;
        try
        {
            auto ec_thumbprint = JWKThumbprint::compute(ec_key_256);
            cout << "SHA-256: " << ec_thumbprint << endl;
        }
        catch (exception const &)
        {
            cout << "Note: EC key thumbprint computation requires curve parameters" << endl;
            cout << "(Some implementations may not export all required fields)" << endl;
        }

        cout << "\n--- Symmetric Key Thumbprint ---" << endl;
        try
        {
            auto oct_thumbprint = JWKThumbprint::compute(oct_key_256);
            cout << "SHA-256: " << oct_thumbprint << endl;
        }
        catch (exception const &)
        {
            cout << "Note: Symmetric key thumbprint requires key material" << endl;
            cout << "(Public representation doesn't include key value)" << endl;
        }

        // Example 7: Automatic Thumbprints as Key IDs
        cout << "\n\n7. Automatic Thumbprints as Key IDs" << endl;
        cout << "==========================================" << endl;

        cout << "\nAll generated keys automatically use SHA-512 thumbprint as Key ID:" << endl;

        JWK auto_key = JWK::generateRSA(JWK::Use::signature, 2048);
        auto auto_thumbprint_sha512 = JWKThumbprint::compute(auto_key, "SHA-512");
        auto auto_thumbprint_sha256 = JWKThumbprint::compute(auto_key, "SHA-256");

        cout << "\nAuto-generated Key ID: " << auto_key.getKeyID() << endl;
        cout << "SHA-512 thumbprint:    " << auto_thumbprint_sha512 << endl;
        cout << "SHA-256 thumbprint:    " << auto_thumbprint_sha256 << endl;
        cout << "\n✓ Key ID matches SHA-512 thumbprint: "
             << (auto_key.getKeyID() == auto_thumbprint_sha512.get() ? "Yes" : "No") << endl;
        cout << "SHA-512 length: " << auto_thumbprint_sha512.get().length() << " characters" << endl;

        // Example 8: Key Metadata and Validation
        cout << "\n\n8. Key Metadata and Algorithm Validation" << endl;
        cout << "==========================================" << endl;

        cout << "\nGenerating keys with auto-selected algorithms:" << endl;
        JWK sig_key = JWK::generateRSA(JWK::Use::signature);
        JWK enc_key = JWK::generateRSA(JWK::Use::encryption);

        cout << "  Signature key algorithm: " << sig_key.getAlgorithm() << " (RS256 default)"
             << endl;
        cout << "  Encryption key algorithm: " << enc_key.getAlgorithm()
             << " (RSA-OAEP-256 default)" << endl;

        cout << "\nOverriding with custom algorithm:" << endl;
        JWK custom_key = JWK::generateRSA(JWK::Use::signature, 2048, "PS256");
        cout << "  Custom algorithm: " << custom_key.getAlgorithm() << endl;

        cout << "\nNote: Algorithm is validated against key type + use." << endl;
        cout << "Try using an invalid algorithm and the library will throw an error." << endl;

        cout << "\nPublic JWK (custom key):" << endl;
        cout << custom_key.toJSON(false) << endl;

        // Example 9: Public/Private Key Pairs
        cout << "\n\n9. Public/Private Key Pairs" << endl;
        cout << "==========================================" << endl;

        JWK key_pair = JWK::generateEC(JWK::Use::signature);

        cout << "\nGenerated EC key pair" << endl;
        cout << "Auto-generated Key ID: " << key_pair.getKeyID() << endl;
        cout << "Algorithm: " << key_pair.getAlgorithm() << endl;
        cout << "Has private key: " << (key_pair.hasPrivateKey() ? "Yes" : "No") << endl;

        string public_only = key_pair.toJSON(false);
        cout << "\nPublic key only:" << endl;
        cout << public_only << endl;

        string with_private = key_pair.toJSON(true);
        cout << "\nWith private key (length): " << with_private.length() << " characters" << endl;

        JWK public_key = JWK::fromJSON(public_only);
        cout << "\nParsed public key:" << endl;
        cout << "Has private key: " << (public_key.hasPrivateKey() ? "Yes" : "No") << endl;

        // Example 10: Key Type Identification
        cout << "\n\n10. Key Type Identification" << endl;
        cout << "==========================================" << endl;

        auto print_key_type = [](const JWK &key, string const &name)
        {
            cout << "\n" << name << ":" << endl;
            JWK::KeyType type = key.getKeyType();
            string type_str;
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
            cout << "  Type: " << type_str << endl;
        };

        print_key_type(rsa_key, "RSA Key");
        print_key_type(ec_key_256, "EC Key");
        print_key_type(oct_key_256, "Symmetric Key");

        cout << "\n\n=== JWK Example Complete ===" << endl;
        return 0;
    }
    catch (exception const &e)
    {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
}
