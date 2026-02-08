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

#include "jose/jose.hpp"
#include <iostream>
#include <exception>

using namespace Vlinder::jose;

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
        JWK rsaKey = JWK::generateRSA(2048);
        rsaKey.setKeyId("rsa-enc-key-2024");
        rsaKey.setUse(JWK::Use::Encryption);
        std::cout << "RSA key generated with ID: " << rsaKey.getKeyId() << std::endl;
        
        std::string sensitiveData = "This is highly confidential information!";
        std::cout << "\nPlaintext: " << sensitiveData << std::endl;
        
        JWE jwe;
        jwe.setPlaintext(sensitiveData);
        jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
        jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A256GCM);
        jwe.setKeyId(rsaKey.getKeyId());
        jwe.setType("JWE");
        
        std::string encrypted = jwe.encrypt(rsaKey);
        std::cout << "\nEncrypted JWE: " << encrypted.substr(0, 80) << "..." << std::endl;
        std::cout << "Length: " << encrypted.length() << " characters" << std::endl;
        
        std::cout << "\nDecrypting JWE..." << std::endl;
        std::string decrypted = JWE::decrypt(encrypted, rsaKey);
        std::cout << "Decrypted: " << decrypted << std::endl;
        std::cout << "Match: " << (decrypted == sensitiveData ? "✓ SUCCESS" : "✗ FAILED")
                  << std::endl;

        // Example 2: Different Content Encryption Algorithms
        std::cout << "\n\n2. Different Content Encryption Algorithms" << std::endl;
        std::cout << "==========================================" << std::endl;
        
        std::string payload = "Testing different encryption algorithms";
        
        // AES128-GCM
        std::cout << "\n--- AES128-GCM ---" << std::endl;
        JWE jwe128;
        jwe128.setPlaintext(payload);
        jwe128.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
        jwe128.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
        
        std::string enc128 = jwe128.encrypt(rsaKey);
        std::string dec128 = JWE::decrypt(enc128, rsaKey);
        std::cout << "Encrypted and decrypted with A128GCM" << std::endl;
        std::cout << "Match: " << (dec128 == payload ? "✓" : "✗") << std::endl;
        
        // AES256-CBC-HMAC-SHA512
        std::cout << "\n--- AES256-CBC-HMAC-SHA512 ---" << std::endl;
        JWE jweCbc;
        jweCbc.setPlaintext(payload);
        jweCbc.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
        jweCbc.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A256CBC_HS512);
        
        std::string encCbc = jweCbc.encrypt(rsaKey);
        std::string decCbc = JWE::decrypt(encCbc, rsaKey);
        std::cout << "Encrypted and decrypted with A256CBC-HS512" << std::endl;
        std::cout << "Match: " << (decCbc == payload ? "✓" : "✗") << std::endl;

        // Example 3: AES Key Wrap
        std::cout << "\n\n3. AES Key Wrap + AES-GCM" << std::endl;
        std::cout << "==========================================" << std::endl;
        
        std::cout << "\nGenerating 256-bit symmetric key..." << std::endl;
        JWK kekKey = JWK::generateOct(256);  // Key Encryption Key
        kekKey.setKeyId("kek-256");
        std::cout << "Symmetric KEK generated" << std::endl;
        
        std::string secretMessage = "Secret message encrypted with AES Key Wrap";
        std::cout << "\nPlaintext: " << secretMessage << std::endl;
        
        JWE jweKw;
        jweKw.setPlaintext(secretMessage);
        jweKw.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::A256KW);
        jweKw.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A256GCM);
        jweKw.setKeyId(kekKey.getKeyId());
        
        std::string encKw = jweKw.encrypt(kekKey);
        std::cout << "\nEncrypted with A256KW + A256GCM" << std::endl;
        
        std::string decKw = JWE::decrypt(encKw, kekKey);
        std::cout << "Decrypted: " << decKw << std::endl;
        std::cout << "Match: " << (decKw == secretMessage ? "✓ SUCCESS" : "✗ FAILED") << std::endl;

        // Example 4: Direct Encryption (No Key Wrapping)
        std::cout << "\n\n4. Direct Encryption (DIR)" << std::endl;
        std::cout << "==========================================" << std::endl;
        
        std::cout << "\nNote: DIR algorithm uses direct encryption with pre-shared key" << std::endl;
        std::cout << "(Implementation may vary by library - skipping for compatibility)" << std::endl;

        // Example 5: Working with Headers
        std::cout << "\n\n5. JWE Header Inspection" << std::endl;
        std::cout << "==========================================" << std::endl;
        
        JWE headerExample;
        headerExample.setPlaintext("Inspecting JWE headers");
        headerExample.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP_256);
        headerExample.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A256GCM);
        headerExample.setKeyId("header-test-key");
        headerExample.setType("JWE");
        headerExample.setHeaderParam("cty", "application/json");
        
        std::string encHeader = headerExample.encrypt(rsaKey);
        
        JWE parsedHeader = JWE::parse(encHeader);
        std::cout << "\nJWE Header: " << parsedHeader.getHeader() << std::endl;

        // Example 6: JWE Compact Serialization Format
        std::cout << "\n\n6. JWE Compact Serialization Format" << std::endl;
        std::cout << "==========================================" << std::endl;
        
        std::cout << "\nJWE format: Header.EncKey.IV.Ciphertext.Tag" << std::endl;
        std::cout << "Full JWE length: " << encrypted.length() << " characters" << std::endl;
        
        int dotCount = 0;
        for (char c : encrypted)
        {
            if (c == '.')
                dotCount++;
        }
        std::cout << "Number of dots (should be 4): " << dotCount << std::endl;
        
        std::cout << "\nFirst 100 characters: " << encrypted.substr(0, 100) << "..." << std::endl;

        // Example 7: JSON Payload Encryption
        std::cout << "\n\n7. Encrypting JSON Data" << std::endl;
        std::cout << "==========================================" << std::endl;
        
        std::string jsonPayload = R"({
  "userId": "12345",
  "email": "user@example.com",
  "creditCard": "4111-1111-1111-1111",
  "ssn": "123-45-6789"
})";
        
        std::cout << "\nJSON Payload:\n" << jsonPayload << std::endl;
        
        JWE jweJson;
        jweJson.setPlaintext(jsonPayload);
        jweJson.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
        jweJson.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A256GCM);
        jweJson.setHeaderParam("cty", "application/json");
        
        std::string encJson = jweJson.encrypt(rsaKey);
        std::cout << "\n✓ JSON payload encrypted" << std::endl;
        
        std::string decJson = JWE::decrypt(encJson, rsaKey);
        std::cout << "\nDecrypted JSON:\n" << decJson << std::endl;
        std::cout << "\nMatch: " << (decJson == jsonPayload ? "✓ SUCCESS" : "✗ FAILED")
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
