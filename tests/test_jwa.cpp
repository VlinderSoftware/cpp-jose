#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

#include "jose/jose.hpp"

using namespace Vlinder::JOSE;

// Algorithm string conversion tests
TEST_CASE("SignatureAlgorithmToString", "[jwa][signaturealgorithmtostring]")
{
    REQUIRE("HS256" == JWA::toString(JWA::SignatureAlgorithm::HS256));
    REQUIRE("HS384" == JWA::toString(JWA::SignatureAlgorithm::HS384));
    REQUIRE("HS512" == JWA::toString(JWA::SignatureAlgorithm::HS512));
    REQUIRE("RS256" == JWA::toString(JWA::SignatureAlgorithm::RS256));
    REQUIRE("RS384" == JWA::toString(JWA::SignatureAlgorithm::RS384));
    REQUIRE("RS512" == JWA::toString(JWA::SignatureAlgorithm::RS512));
    REQUIRE("ES256" == JWA::toString(JWA::SignatureAlgorithm::ES256));
    REQUIRE("ES384" == JWA::toString(JWA::SignatureAlgorithm::ES384));
    REQUIRE("ES512" == JWA::toString(JWA::SignatureAlgorithm::ES512));
    REQUIRE("PS256" == JWA::toString(JWA::SignatureAlgorithm::PS256));
    REQUIRE("PS384" == JWA::toString(JWA::SignatureAlgorithm::PS384));
    REQUIRE("PS512" == JWA::toString(JWA::SignatureAlgorithm::PS512));
    REQUIRE("none" == JWA::toString(JWA::SignatureAlgorithm::None));
}

TEST_CASE("KeyEncryptionAlgorithmToString", "[jwa][keyencryptionalgorithmtostring]")
{
    REQUIRE("RSA1_5" == JWA::toString(JWA::KeyEncryptionAlgorithm::RSA1_5));
    REQUIRE("RSA-OAEP" == JWA::toString(JWA::KeyEncryptionAlgorithm::RSA_OAEP));
    REQUIRE("RSA-OAEP-256" == JWA::toString(JWA::KeyEncryptionAlgorithm::RSA_OAEP_256));
    REQUIRE("A128KW" == JWA::toString(JWA::KeyEncryptionAlgorithm::A128KW));
    REQUIRE("A192KW" == JWA::toString(JWA::KeyEncryptionAlgorithm::A192KW));
    REQUIRE("A256KW" == JWA::toString(JWA::KeyEncryptionAlgorithm::A256KW));
    REQUIRE("dir" == JWA::toString(JWA::KeyEncryptionAlgorithm::DIR));
    REQUIRE("ECDH-ES" == JWA::toString(JWA::KeyEncryptionAlgorithm::ECDH_ES));
    REQUIRE("A128GCMKW" == JWA::toString(JWA::KeyEncryptionAlgorithm::A128GCMKW));
    REQUIRE("A192GCMKW" == JWA::toString(JWA::KeyEncryptionAlgorithm::A192GCMKW));
    REQUIRE("A256GCMKW" == JWA::toString(JWA::KeyEncryptionAlgorithm::A256GCMKW));
}

TEST_CASE("ContentEncryptionAlgorithmToString", "[jwa][contentencryptionalgorithmtostring]")
{
    REQUIRE("A128CBC-HS256" == JWA::toString(JWA::ContentEncryptionAlgorithm::A128CBC_HS256));
    REQUIRE("A192CBC-HS384" == JWA::toString(JWA::ContentEncryptionAlgorithm::A192CBC_HS384));
    REQUIRE("A256CBC-HS512" == JWA::toString(JWA::ContentEncryptionAlgorithm::A256CBC_HS512));
    REQUIRE("A128GCM" == JWA::toString(JWA::ContentEncryptionAlgorithm::A128GCM));
    REQUIRE("A192GCM" == JWA::toString(JWA::ContentEncryptionAlgorithm::A192GCM));
    REQUIRE("A256GCM" == JWA::toString(JWA::ContentEncryptionAlgorithm::A256GCM));
}

TEST_CASE("SignatureAlgorithmFromString", "[jwa][signaturealgorithmfromstring]")
{
    REQUIRE(JWA::SignatureAlgorithm::HS256 == JWA::signatureAlgorithmFromString("HS256"));
    REQUIRE(JWA::SignatureAlgorithm::HS384 == JWA::signatureAlgorithmFromString("HS384"));
    REQUIRE(JWA::SignatureAlgorithm::HS512 == JWA::signatureAlgorithmFromString("HS512"));
    REQUIRE(JWA::SignatureAlgorithm::RS256 == JWA::signatureAlgorithmFromString("RS256"));
    REQUIRE(JWA::SignatureAlgorithm::RS384 == JWA::signatureAlgorithmFromString("RS384"));
    REQUIRE(JWA::SignatureAlgorithm::RS512 == JWA::signatureAlgorithmFromString("RS512"));
    REQUIRE(JWA::SignatureAlgorithm::ES256 == JWA::signatureAlgorithmFromString("ES256"));
    REQUIRE(JWA::SignatureAlgorithm::ES384 == JWA::signatureAlgorithmFromString("ES384"));
    REQUIRE(JWA::SignatureAlgorithm::ES512 == JWA::signatureAlgorithmFromString("ES512"));
    REQUIRE(JWA::SignatureAlgorithm::PS256 == JWA::signatureAlgorithmFromString("PS256"));
    REQUIRE(JWA::SignatureAlgorithm::PS384 == JWA::signatureAlgorithmFromString("PS384"));
    REQUIRE(JWA::SignatureAlgorithm::PS512 == JWA::signatureAlgorithmFromString("PS512"));
    REQUIRE(JWA::SignatureAlgorithm::None == JWA::signatureAlgorithmFromString("none"));
}

// HMAC signature tests (HS256, HS384, HS512)
TEST_CASE("HS256SignAndVerify", "[jwa][hs256signandverify]")
{
    JWK key = JWK::generateOct(256);
    std::string data = "test message";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::HS256, key, dataVec);

    REQUIRE_FALSE(signature.empty());

    bool verified = JWA::verify(JWA::SignatureAlgorithm::HS256, key, dataVec, signature);

    REQUIRE(verified);
}

TEST_CASE("HS384SignAndVerify", "[jwa][hs384signandverify]")
{
    JWK key = JWK::generateOct(384);
    std::string data = "test message for HS384";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::HS384, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::HS384, key, dataVec, signature));
}

TEST_CASE("HS512SignAndVerify", "[jwa][hs512signandverify]")
{
    JWK key = JWK::generateOct(512);
    std::string data = "test message for HS512";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::HS512, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::HS512, key, dataVec, signature));
}

TEST_CASE("HMACWrongKeyFails", "[jwa][hmacwrongkeyfails]")
{
    JWK key1 = JWK::generateOct(256);
    JWK key2 = JWK::generateOct(256);
    std::string data = "test message";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::HS256, key1, dataVec);

    bool verified = JWA::verify(JWA::SignatureAlgorithm::HS256, key2, dataVec, signature);

    REQUIRE_FALSE(verified);
}

// RSA signature tests (RS256, RS384, RS512)
TEST_CASE("RS256SignAndVerify", "[jwa][rs256signandverify]")
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "test message for RSA";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::RS256, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::RS256, key, dataVec, signature));
}

TEST_CASE("RS384SignAndVerify", "[jwa][rs384signandverify]")
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "test message for RS384";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::RS384, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::RS384, key, dataVec, signature));
}

TEST_CASE("RS512SignAndVerify", "[jwa][rs512signandverify]")
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "test message for RS512";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::RS512, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::RS512, key, dataVec, signature));
}

TEST_CASE("RSAPublicKeyVerification", "[jwa][rsapublickeyverification]")
{
    JWK privateKey = JWK::generateRSA(2048);
    std::string data = "test message";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature =
        JWA::sign(JWA::SignatureAlgorithm::RS256, privateKey, dataVec);

    // Export public key only
    std::string publicKeyJson = privateKey.toJson(false);
    JWK publicKey = JWK::fromJson(publicKeyJson);

    // Verify with public key
    bool verified = JWA::verify(JWA::SignatureAlgorithm::RS256, publicKey, dataVec, signature);

    REQUIRE(verified);
}

// ECDSA signature tests (ES256, ES384, ES512)
TEST_CASE("ES256SignAndVerify", "[jwa][es256signandverify]")
{
    JWK key = JWK::generateEC("P-256");
    std::string data = "test message for ECDSA";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::ES256, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::ES256, key, dataVec, signature));
}

TEST_CASE("ES384SignAndVerify", "[jwa][es384signandverify]")
{
    JWK key = JWK::generateEC("P-384");
    std::string data = "test message for ES384";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::ES384, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::ES384, key, dataVec, signature));
}

TEST_CASE("ES512SignAndVerify", "[jwa][es512signandverify]")
{
    JWK key = JWK::generateEC("P-521");
    std::string data = "test message for ES512";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::ES512, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::ES512, key, dataVec, signature));
}

// RSA-PSS signature tests (PS256, PS384, PS512)
TEST_CASE("PS256SignAndVerify", "[jwa][ps256signandverify]")
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "test message for PSS";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::PS256, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::PS256, key, dataVec, signature));
}

TEST_CASE("PS384SignAndVerify", "[jwa][ps384signandverify]")
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "test message for PS384";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::PS384, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::PS384, key, dataVec, signature));
}

TEST_CASE("PS512SignAndVerify", "[jwa][ps512signandverify]")
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "test message for PS512";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::PS512, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::PS512, key, dataVec, signature));
}

// Signature tampering detection
TEST_CASE("TamperedSignatureFails", "[jwa][tamperedsignaturefails]")
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "original message";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::RS256, key, dataVec);

    // Tamper with signature
    if (!signature.empty())
    {
        signature[0] ^= 0xFF;
    }

    bool verified = JWA::verify(JWA::SignatureAlgorithm::RS256, key, dataVec, signature);

    REQUIRE_FALSE(verified);
}

TEST_CASE("TamperedDataFails", "[jwa][tampereddatafails]")
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "original message";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::RS256, key, dataVec);

    // Tamper with data
    std::string tamperedData = "tampered message";
    std::vector<unsigned char> tamperedVec(tamperedData.begin(), tamperedData.end());

    bool verified = JWA::verify(JWA::SignatureAlgorithm::RS256, key, tamperedVec, signature);

    REQUIRE_FALSE(verified);
}

// Key encryption tests
TEST_CASE("RSA_OAEP_EncryptDecrypt", "[jwa][rsa-oaep-encryptdecrypt]")
{
    JWK key = JWK::generateRSA(2048);
    std::vector<unsigned char> cek(32, 0x42);  // 256-bit CEK

    std::vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::RSA_OAEP, key, cek);

    REQUIRE_FALSE(encrypted.empty());
    REQUIRE(cek != encrypted);

    std::vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::RSA_OAEP, key, encrypted);

    REQUIRE(cek == decrypted);
}

TEST_CASE("RSA_OAEP_256_EncryptDecrypt", "[jwa][rsa-oaep-256-encryptdecrypt]")
{
    JWK key = JWK::generateRSA(2048);
    std::vector<unsigned char> cek(32, 0x33);

    std::vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::RSA_OAEP_256, key, cek);

    REQUIRE_FALSE(encrypted.empty());

    std::vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::RSA_OAEP_256, key, encrypted);

    REQUIRE(cek == decrypted);
}

TEST_CASE("A128KW_EncryptDecrypt", "[jwa][a128kw-encryptdecrypt]")
{
    JWK kek = JWK::generateOct(128);
    std::vector<unsigned char> cek(16, 0x55);

    std::vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::A128KW, kek, cek);

    REQUIRE_FALSE(encrypted.empty());

    std::vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::A128KW, kek, encrypted);

    REQUIRE(cek == decrypted);
}

TEST_CASE("A256KW_EncryptDecrypt", "[jwa][a256kw-encryptdecrypt]")
{
    JWK kek = JWK::generateOct(256);
    std::vector<unsigned char> cek(32, 0x66);

    std::vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::A256KW, kek, cek);

    REQUIRE_FALSE(encrypted.empty());

    std::vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::A256KW, kek, encrypted);

    REQUIRE(cek == decrypted);
}

// Content encryption tests
TEST_CASE("A128GCM_EncryptDecrypt", "[jwa][a128gcm-encryptdecrypt]")
{
    std::vector<unsigned char> cek(16, 0x42);                               // 128-bit key
    std::vector<unsigned char> iv(12, 0x01);                                // 96-bit IV for GCM
    std::vector<unsigned char> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};  // "Hello"
    std::vector<unsigned char> aad = {0x41, 0x41, 0x44};                    // AAD

    auto [ciphertext, tag] =
        JWA::encryptContent(JWA::ContentEncryptionAlgorithm::A128GCM, cek, iv, plaintext, aad);

    REQUIRE_FALSE(ciphertext.empty());
    REQUIRE_FALSE(tag.empty());
    REQUIRE(plaintext != ciphertext);

    std::vector<unsigned char> decrypted = JWA::decryptContent(
        JWA::ContentEncryptionAlgorithm::A128GCM, cek, iv, ciphertext, aad, tag);

    REQUIRE(plaintext == decrypted);
}

TEST_CASE("A256GCM_EncryptDecrypt", "[jwa][a256gcm-encryptdecrypt]")
{
    std::vector<unsigned char> cek(32, 0x42);  // 256-bit key
    std::vector<unsigned char> iv(12, 0x01);
    std::vector<unsigned char> plaintext = {0x54, 0x65, 0x73, 0x74};  // "Test"
    std::vector<unsigned char> aad;

    auto [ciphertext, tag] =
        JWA::encryptContent(JWA::ContentEncryptionAlgorithm::A256GCM, cek, iv, plaintext, aad);

    REQUIRE_FALSE(ciphertext.empty());
    REQUIRE_FALSE(tag.empty());

    std::vector<unsigned char> decrypted = JWA::decryptContent(
        JWA::ContentEncryptionAlgorithm::A256GCM, cek, iv, ciphertext, aad, tag);

    REQUIRE(plaintext == decrypted);
}

TEST_CASE("A128CBC_HS256_EncryptDecrypt", "[jwa][a128cbc-hs256-encryptdecrypt]")
{
    std::vector<unsigned char> cek(32, 0x42);  // 256-bit key (128 for AES + 128 for HMAC)
    std::vector<unsigned char> iv(16, 0x01);   // 128-bit IV for CBC
    std::vector<unsigned char> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21};
    std::vector<unsigned char> aad = {0x41, 0x41, 0x44};

    auto [ciphertext, tag] = JWA::encryptContent(JWA::ContentEncryptionAlgorithm::A128CBC_HS256,
                                                 cek, iv, plaintext, aad);

    REQUIRE_FALSE(ciphertext.empty());
    REQUIRE_FALSE(tag.empty());

    std::vector<unsigned char> decrypted = JWA::decryptContent(
        JWA::ContentEncryptionAlgorithm::A128CBC_HS256, cek, iv, ciphertext, aad, tag);

    REQUIRE(plaintext == decrypted);
}

// Edge cases
TEST_CASE("EmptyDataSignature", "[jwa][emptydatasignature]")
{
    JWK key = JWK::generateRSA(2048);
    std::vector<unsigned char> emptyData;

    std::vector<unsigned char> signature =
        JWA::sign(JWA::SignatureAlgorithm::RS256, key, emptyData);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::RS256, key, emptyData, signature));
}

TEST_CASE("LargeDataSignature", "[jwa][largedatasignature]")
{
    JWK key = JWK::generateRSA(2048);
    std::vector<unsigned char> largeData(10000, 0x42);

    std::vector<unsigned char> signature =
        JWA::sign(JWA::SignatureAlgorithm::RS256, key, largeData);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::RS256, key, largeData, signature));
}

TEST_CASE("EmptyPlaintextEncryption", "[jwa][emptyplaintextencryption]")
{
    std::vector<unsigned char> cek(16, 0x42);
    std::vector<unsigned char> iv(12, 0x01);
    std::vector<unsigned char> plaintext;
    std::vector<unsigned char> aad;

    auto [ciphertext, tag] =
        JWA::encryptContent(JWA::ContentEncryptionAlgorithm::A128GCM, cek, iv, plaintext, aad);

    std::vector<unsigned char> decrypted = JWA::decryptContent(
        JWA::ContentEncryptionAlgorithm::A128GCM, cek, iv, ciphertext, aad, tag);

    REQUIRE(plaintext == decrypted);
}
