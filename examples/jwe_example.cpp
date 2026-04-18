/**
 * @file jwe_example.cpp
 * @brief JWE encryption and decryption example
 *
 * Demonstrates:
 * - Creating and encrypting JWE using the free-function API
 * - Different key encryption algorithms (RSA-OAEP, AES Key Wrap, ECDH-ES, direct)
 * - Different content encryption algorithms (AES-GCM, AES-CBC-HMAC)
 * - Decrypting JWE
 * - Working with JWE headers via observers
 * - Round-trip through compact and JSON serialisation
 */

#include <exception>
#include <iostream>
#include <span>
#include <string>

#include "jose/jose.hpp"

using namespace std;
using namespace Vlinder::JOSE;

int main()
{
    try
    {
        cout << "=== JWE Example ===" << endl;
        cout << "\nJSON Web Encryption (JWE) provides encryption" << endl;
        cout << "functionality for arbitrary content." << endl;

        // Example 1: RSA-OAEP + AES256-GCM
        cout << "\n\n1. RSA-OAEP + AES256-GCM Encryption" << endl;
        cout << "==========================================" << endl;

        cout << "\nGenerating 2048-bit RSA key for encryption..." << endl;
        JWK rsa_key = JWK::generateRSA(JWK::Use::encryption);
        cout << "RSA key generated with auto-generated ID: " << rsa_key.getKeyID() << endl;

        string sensitive_data = "This is highly confidential information!";
        cout << "\nPlaintext: " << sensitive_data << endl;

        JWE jwe = encrypt(rsa_key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          "JWE",
                          sensitive_data);

        string compact = jwe.toCompact();
        cout << "\nEncrypted JWE: " << compact.substr(0, 80) << "..." << endl;
        cout << "Length: " << compact.length() << " characters" << endl;

        cout << "\nDecrypting JWE..." << endl;
        auto decrypted_bytes = decrypt(jwe, rsa_key);
        string decrypted(decrypted_bytes.begin(), decrypted_bytes.end());
        cout << "Decrypted: " << decrypted << endl;
        cout << "Match: " << (decrypted == sensitive_data ? "SUCCESS" : "FAILED") << endl;

        // Example 2: Different Content Encryption Algorithms
        cout << "\n\n2. Different Content Encryption Algorithms" << endl;
        cout << "==========================================" << endl;

        string payload = "Testing different encryption algorithms";

        cout << "\n--- AES128-GCM ---" << endl;
        {
            JWE j128 = encrypt(rsa_key,
                               JWA::KeyEncryptionAlgorithm::rsa_oaep,
                               JWA::ContentEncryptionAlgorithm::a128gcm,
                               payload);
            auto dec128 = decrypt(j128, rsa_key);
            string s(dec128.begin(), dec128.end());
            cout << "Match: " << (s == payload ? "OK" : "FAILED") << endl;
        }

        cout << "\n--- AES256-CBC-HMAC-SHA512 ---" << endl;
        {
            JWE jcbc = encrypt(rsa_key,
                               JWA::KeyEncryptionAlgorithm::rsa_oaep,
                               JWA::ContentEncryptionAlgorithm::a256cbc_hs512,
                               payload);
            auto deccbc = decrypt(jcbc, rsa_key);
            string s(deccbc.begin(), deccbc.end());
            cout << "Match: " << (s == payload ? "OK" : "FAILED") << endl;
        }

        // Example 3: AES Key Wrap
        cout << "\n\n3. AES Key Wrap + AES-GCM" << endl;
        cout << "==========================================" << endl;

        JWK kek_key = JWK::generateOct(JWK::Use::encryption);
        cout << "Symmetric KEK generated with ID: " << kek_key.getKeyID() << endl;

        string secret_message = "Secret message encrypted with AES Key Wrap";
        JWE jwe_kw = encrypt(kek_key,
                             JWA::KeyEncryptionAlgorithm::a256kw,
                             JWA::ContentEncryptionAlgorithm::a256gcm,
                             secret_message);
        auto dec_kw = decrypt(jwe_kw, kek_key);
        string s_kw(dec_kw.begin(), dec_kw.end());
        cout << "Decrypted: " << s_kw << endl;
        cout << "Match: " << (s_kw == secret_message ? "SUCCESS" : "FAILED") << endl;

        // Example 4: Direct Encryption
        cout << "\n\n4. Direct Encryption (DIR)" << endl;
        cout << "==========================================" << endl;
        {
            JWK dir_key = JWK::generateOct(JWK::Use::encryption, 256);
            JWE jdir = encrypt(dir_key,
                               JWA::KeyEncryptionAlgorithm::dir,
                               JWA::ContentEncryptionAlgorithm::a256gcm,
                               "Direct encryption example");
            auto dec_dir = decrypt(jdir, dir_key);
            string s(dec_dir.begin(), dec_dir.end());
            cout << "Match: " << (s == "Direct encryption example" ? "SUCCESS" : "FAILED") << endl;
        }

        // Example 5: Header Observers
        cout << "\n\n5. JWE Header Inspection" << endl;
        cout << "==========================================" << endl;
        {
            JWE jh = encrypt(rsa_key,
                             JWA::KeyEncryptionAlgorithm::rsa_oaep_256,
                             JWA::ContentEncryptionAlgorithm::a256gcm,
                             "JWE",
                             "Inspecting JWE headers");
            cout << "alg : " << JWA::toString(jh.getKeyEncryptionAlgorithm()) << endl;
            cout << "enc : " << JWA::toString(jh.getContentEncryptionAlgorithm()) << endl;
            cout << "kid : " << jh.getKeyID() << endl;
            cout << "typ : " << jh.getType() << endl;
            cout << "header JSON: " << jh.getHeader() << endl;
        }

        // Example 6: Compact Serialisation Format
        cout << "\n\n6. JWE Compact Serialisation Format" << endl;
        cout << "==========================================" << endl;
        cout << "JWE format: Header.EncKey.IV.Ciphertext.Tag" << endl;
        {
            size_t dot_count = 0;
            for (char c : compact)
                if (c == '.')
                    ++dot_count;
            cout << "Number of dots (should be 4): " << dot_count << endl;
        }

        // Example 7: Round-trip through compact/JSON serialisation
        cout << "\n\n7. Round-trip compact -> fromCompact -> toJSON -> fromJSON" << endl;
        cout << "==========================================" << endl;
        {
            JWE parsed = JWE::fromCompact(compact);
            string json_form = parsed.toJSON();
            JWE from_json = JWE::fromJSON(json_form);
            auto rt_bytes = decrypt(from_json, rsa_key);
            string rt(rt_bytes.begin(), rt_bytes.end());
            cout << "Round-trip match: " << (rt == sensitive_data ? "SUCCESS" : "FAILED") << endl;
        }

        cout << "\n\n=== JWE Example Complete ===" << endl;
        return 0;
    }
    catch (exception const &e)
    {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
}
