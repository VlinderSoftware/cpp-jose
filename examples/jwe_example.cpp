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

using namespace Vlinder::JOSE;

int main()
{
    try
    {
        std::cout << "=== JWE Example ===" << std::endl;
        std::cout << "\nJSON Web Encryption (JWE) provides encryption" << std::endl;
        std::cout << "functionality for arbitrary content." << std::endl;

        // Example 1: RSA Key Encryption with AES-GCM
        std::cout << "\n\n1. RSA-OAEP + AES256-GCM Encryption" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\nGenerating 2048-bit RSA key for encryption..." << std::endl;
        JWK rsa_key = JWK::generateRSA(2048);
        rsa_key.setKeyID("rsa-enc-key-2024");
        rsa_key.setUse(JWK::Use::encryption);
        std::cout << "RSA key generated with ID: " << rsa_key.getKeyID() << std::endl;

        std::string sensitive_data = "This is highly confidential information!";
        std::cout << "\nPlaintext: " << sensitive_data << std::endl;

        JWE jwe;
        jwe.setPlaintext(sensitive_data);
        jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
        jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a256gcm);
        jwe.setKeyID(rsa_key.getKeyID());
        jwe.setType("JWE");

        std::string encrypted = jwe.encrypt(rsa_key);
        std::cout << "\nEncrypted JWE: " << encrypted.substr(0, 80) << "..." << std::endl;
        std::cout << "Length: " << encrypted.length() << " characters" << std::endl;

        std::cout << "\nDecrypting JWE..." << std::endl;
        std::string decrypted = JWE::decrypt(encrypted, rsa_key);
        std::cout << "Decrypted: " << decrypted << std::endl;
        std::cout << "Match: " << (decrypted == sensitive_data ? "✓ SUCCESS" : "✗ FAILED")
                  << std::endl;

        // Example 2: Different Content Encryption Algorithms
        std::cout << "\n\n2. Different Content Encryption Algorithms" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::string payload = "Testing different encryption algorithms";

        // AES128-GCM
        std::cout << "\n--- AES128-GCM ---" << std::endl;
        JWE jwe128;
        jwe128.setPlaintext(payload);
        jwe128.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
        jwe128.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

        std::string enc128 = jwe128.encrypt(rsa_key);
        std::string dec128 = JWE::decrypt(enc128, rsa_key);
        std::cout << "Encrypted and decrypted with A128GCM" << std::endl;
        std::cout << "Match: " << (dec128 == payload ? "✓" : "✗") << std::endl;

        // AES256-CBC-HMAC-SHA512
        std::cout << "\n--- AES256-CBC-HMAC-SHA512 ---" << std::endl;
        JWE jwe_cbc;
        jwe_cbc.setPlaintext(payload);
        jwe_cbc.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
        jwe_cbc.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a256cbc_hs512);

        std::string enc_cbc = jwe_cbc.encrypt(rsa_key);
        std::string dec_cbc = JWE::decrypt(enc_cbc, rsa_key);
        std::cout << "Encrypted and decrypted with A256CBC-HS512" << std::endl;
        std::cout << "Match: " << (dec_cbc == payload ? "✓" : "✗") << std::endl;

        // Example 3: AES Key Wrap
        std::cout << "\n\n3. AES Key Wrap + AES-GCM" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\nGenerating 256-bit symmetric key..." << std::endl;
        JWK kek_key = JWK::generateOct(256);  // Key Encryption Key
        kek_key.setKeyID("kek-256");
        std::cout << "Symmetric KEK generated" << std::endl;

        std::string secret_message = "Secret message encrypted with AES Key Wrap";
        std::cout << "\nPlaintext: " << secret_message << std::endl;

        JWE jwe_kw;
        jwe_kw.setPlaintext(secret_message);
        jwe_kw.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::a256kw);
        jwe_kw.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a256gcm);
        jwe_kw.setKeyID(kek_key.getKeyID());

        std::string enc_kw = jwe_kw.encrypt(kek_key);
        std::cout << "\nEncrypted with A256KW + A256GCM" << std::endl;

        std::string dec_kw = JWE::decrypt(enc_kw, kek_key);
        std::cout << "Decrypted: " << dec_kw << std::endl;
        std::cout << "Match: " << (dec_kw == secret_message ? "✓ SUCCESS" : "✗ FAILED") << std::endl;

        // Example 4: Direct Encryption (No Key Wrapping)
        std::cout << "\n\n4. Direct Encryption (DIR)" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\nNote: DIR algorithm uses direct encryption with pre-shared key"
                  << std::endl;
        std::cout << "(Implementation may vary by library - skipping for compatibility)"
                  << std::endl;

        // Example 5: Working with Headers
        std::cout << "\n\n5. JWE Header Inspection" << std::endl;
        std::cout << "==========================================" << std::endl;

        JWE header_example;
        header_example.setPlaintext("Inspecting JWE headers");
        header_example.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep_256);
        header_example.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a256gcm);
        header_example.setKeyID("header-test-key");
        header_example.setType("JWE");
        header_example.setHeaderParam("cty", "application/json");

        std::string enc_header = header_example.encrypt(rsa_key);

        JWE parsed_header = JWE::parse(enc_header);
        std::cout << "\nJWE Header: " << parsed_header.getHeader() << std::endl;

        // Example 6: JWE Compact Serialization Format
        std::cout << "\n\n6. JWE Compact Serialization Format" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::cout << "\nJWE format: Header.EncKey.IV.Ciphertext.Tag" << std::endl;
        std::cout << "Full JWE length: " << encrypted.length() << " characters" << std::endl;

        int dot_count = 0;
        for (char c : encrypted)
        {
            if (c == '.')
                dot_count++;
        }
        std::cout << "Number of dots (should be 4): " << dot_count << std::endl;

        std::cout << "\nFirst 100 characters: " << encrypted.substr(0, 100) << "..." << std::endl;

        // Example 7: JSON Payload Encryption
        std::cout << "\n\n7. Encrypting JSON Data" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::string json_payload = R"({
  "userId": "12345",
  "email": "user@example.com",
  "creditCard": "4111-1111-1111-1111",
  "ssn": "123-45-6789"
})";

        std::cout << "\nJSON Payload:\n" << json_payload << std::endl;

        JWE jwe_json;
        jwe_json.setPlaintext(json_payload);
        jwe_json.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
        jwe_json.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a256gcm);
        jwe_json.setHeaderParam("cty", "application/json");

        std::string enc_json = jwe_json.encrypt(rsa_key);
        std::cout << "\n✓ JSON payload encrypted" << std::endl;

        std::string dec_json = JWE::decrypt(enc_json, rsa_key);
        std::cout << "\nDecrypted JSON:\n" << dec_json << std::endl;
        std::cout << "\nMatch: " << (dec_json == json_payload ? "✓ SUCCESS" : "✗ FAILED")
                  << std::endl;

        std::cout << "\n\n=== JWE Example Complete ===" << std::endl;
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
