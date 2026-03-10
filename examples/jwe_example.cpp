/**
 * @file jwe_example.cpp
 * @brief JWE encryption and decryption example
 *
 * Demonstrates:
 * - Creating and encrypting JWE
 * - Different key encryption algorithms (RSA-OAEP, AES Key Wrap)
 * - Different content encryption algorithms (AES-GCM, AES-CBC-HMAC)
 * - Decrypting JWE
 * - Working with JWE headers
 * - Direct encryption with symmetric keys
 */

#include <exception>
#include <iostream>

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

        // Example 1: RSA Key Encryption with AES-GCM
        cout << "\n\n1. RSA-OAEP + AES256-GCM Encryption" << endl;
        cout << "==========================================" << endl;

        cout << "\nGenerating 2048-bit RSA key for encryption..." << endl;
        JWK rsa_key = JWK::generateRSA(JWK::Use::encryption);
        cout << "RSA key generated with auto-generated ID: " << rsa_key.getKeyID() << endl;
        cout << "Algorithm (auto-selected): " << rsa_key.getAlgorithm() << endl;

        string sensitive_data = "This is highly confidential information!";
        cout << "\nPlaintext: " << sensitive_data << endl;

        JWE jwe;
        jwe.setPlaintext(sensitive_data);
        jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
        jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a256gcm);
        jwe.setKeyID(rsa_key.getKeyID());
        jwe.setType("JWE");

        string encrypted = jwe.encrypt(rsa_key);
        cout << "\nEncrypted JWE: " << encrypted.substr(0, 80) << "..." << endl;
        cout << "Length: " << encrypted.length() << " characters" << endl;

        cout << "\nDecrypting JWE..." << endl;
        string decrypted = JWE::decrypt(encrypted, rsa_key);
        cout << "Decrypted: " << decrypted << endl;
        cout << "Match: " << (decrypted == sensitive_data ? "✓ SUCCESS" : "✗ FAILED") << endl;

        // Example 2: Different Content Encryption Algorithms
        cout << "\n\n2. Different Content Encryption Algorithms" << endl;
        cout << "==========================================" << endl;

        string payload = "Testing different encryption algorithms";

        // AES128-GCM
        cout << "\n--- AES128-GCM ---" << endl;
        JWE jwe128;
        jwe128.setPlaintext(payload);
        jwe128.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
        jwe128.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

        string enc128 = jwe128.encrypt(rsa_key);
        string dec128 = JWE::decrypt(enc128, rsa_key);
        cout << "Encrypted and decrypted with A128GCM" << endl;
        cout << "Match: " << (dec128 == payload ? "✓" : "✗") << endl;

        // AES256-CBC-HMAC-SHA512
        cout << "\n--- AES256-CBC-HMAC-SHA512 ---" << endl;
        JWE jwe_cbc;
        jwe_cbc.setPlaintext(payload);
        jwe_cbc.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
        jwe_cbc.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a256cbc_hs512);

        string enc_cbc = jwe_cbc.encrypt(rsa_key);
        string dec_cbc = JWE::decrypt(enc_cbc, rsa_key);
        cout << "Encrypted and decrypted with A256CBC-HS512" << endl;
        cout << "Match: " << (dec_cbc == payload ? "✓" : "✗") << endl;

        // Example 3: AES Key Wrap
        cout << "\n\n3. AES Key Wrap + AES-GCM" << endl;
        cout << "==========================================" << endl;

        cout << "\nGenerating 256-bit symmetric key..." << endl;
        JWK kek_key = JWK::generateOct(JWK::Use::encryption);  // Key Encryption Key
        cout << "Symmetric KEK generated with auto-generated ID: " << kek_key.getKeyID() << endl;
        cout << "Algorithm (auto-selected): " << kek_key.getAlgorithm() << endl;

        string secret_message = "Secret message encrypted with AES Key Wrap";
        cout << "\nPlaintext: " << secret_message << endl;

        JWE jwe_kw;
        jwe_kw.setPlaintext(secret_message);
        jwe_kw.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::a256kw);
        jwe_kw.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a256gcm);
        jwe_kw.setKeyID(kek_key.getKeyID());

        string enc_kw = jwe_kw.encrypt(kek_key);
        cout << "\nEncrypted with A256KW + A256GCM" << endl;

        string dec_kw = JWE::decrypt(enc_kw, kek_key);
        cout << "Decrypted: " << dec_kw << endl;
        cout << "Match: " << (dec_kw == secret_message ? "✓ SUCCESS" : "✗ FAILED") << endl;

        // Example 4: Direct Encryption (No Key Wrapping)
        cout << "\n\n4. Direct Encryption (DIR)" << endl;
        cout << "==========================================" << endl;

        cout << "\nNote: DIR algorithm uses direct encryption with pre-shared key" << endl;
        cout << "(Implementation may vary by library - skipping for compatibility)" << endl;

        // Example 5: Working with Headers
        cout << "\n\n5. JWE Header Inspection" << endl;
        cout << "==========================================" << endl;

        JWE header_example;
        header_example.setPlaintext("Inspecting JWE headers");
        header_example.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep_256);
        header_example.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a256gcm);
        header_example.setKeyID(rsa_key.getKeyID());  // Use auto-generated key ID
        header_example.setType("JWE");
        header_example.setHeaderParam("cty", "application/json");

        string enc_header = header_example.encrypt(rsa_key);

        JWE parsed_header = JWE::parse(enc_header);
        cout << "\nJWE Header: " << parsed_header.getHeader() << endl;

        // Example 6: JWE Compact Serialization Format
        cout << "\n\n6. JWE Compact Serialization Format" << endl;
        cout << "==========================================" << endl;

        cout << "\nJWE format: Header.EncKey.IV.Ciphertext.Tag" << endl;
        cout << "Full JWE length: " << encrypted.length() << " characters" << endl;

        int dot_count = 0;
        for (char c : encrypted)
        {
            if (c == '.')
                dot_count++;
        }
        cout << "Number of dots (should be 4): " << dot_count << endl;

        cout << "\nFirst 100 characters: " << encrypted.substr(0, 100) << "..." << endl;

        // Example 7: JSON Payload Encryption
        cout << "\n\n7. Encrypting JSON Data" << endl;
        cout << "==========================================" << endl;

        string json_payload = R"({
  "userId": "12345",
  "email": "user@example.com",
  "creditCard": "4111-1111-1111-1111",
  "ssn": "123-45-6789"
})";

        cout << "\nJSON Payload:\n" << json_payload << endl;

        JWE jwe_json;
        jwe_json.setPlaintext(json_payload);
        jwe_json.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
        jwe_json.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a256gcm);
        jwe_json.setHeaderParam("cty", "application/json");

        string enc_json = jwe_json.encrypt(rsa_key);
        cout << "\n✓ JSON payload encrypted" << endl;

        string dec_json = JWE::decrypt(enc_json, rsa_key);
        cout << "\nDecrypted JSON:\n" << dec_json << endl;
        cout << "\nMatch: " << (dec_json == json_payload ? "✓ SUCCESS" : "✗ FAILED") << endl;

        cout << "\n\n=== JWE Example Complete ===" << endl;
        return 0;
    }
    catch (exception const &e)
    {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
}
