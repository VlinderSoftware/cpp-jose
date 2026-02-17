#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

#include "jose/jose.hpp"

using namespace Vlinder::JOSE;

// Algorithm string conversion tests
TEST_CASE("SignatureAlgorithmToString", "[jwa][signaturealgorithmtostring]")
{
    REQUIRE("HS256" == JWA::toString(JWA::SignatureAlgorithm::hs256));
    REQUIRE("HS384" == JWA::toString(JWA::SignatureAlgorithm::hs384));
    REQUIRE("HS512" == JWA::toString(JWA::SignatureAlgorithm::hs512));
    REQUIRE("RS256" == JWA::toString(JWA::SignatureAlgorithm::rs256));
    REQUIRE("RS384" == JWA::toString(JWA::SignatureAlgorithm::rs384));
    REQUIRE("RS512" == JWA::toString(JWA::SignatureAlgorithm::rs512));
    REQUIRE("ES256" == JWA::toString(JWA::SignatureAlgorithm::es256));
    REQUIRE("ES384" == JWA::toString(JWA::SignatureAlgorithm::es384));
    REQUIRE("ES512" == JWA::toString(JWA::SignatureAlgorithm::es512));
    REQUIRE("PS256" == JWA::toString(JWA::SignatureAlgorithm::ps256));
    REQUIRE("PS384" == JWA::toString(JWA::SignatureAlgorithm::ps384));
    REQUIRE("PS512" == JWA::toString(JWA::SignatureAlgorithm::ps512));
    REQUIRE("none" == JWA::toString(JWA::SignatureAlgorithm::none));
}

TEST_CASE("KeyEncryptionAlgorithmToString", "[jwa][keyencryptionalgorithmtostring]")
{
    REQUIRE("RSA1_5" == JWA::toString(JWA::KeyEncryptionAlgorithm::rsa1_5));
    REQUIRE("RSA-OAEP" == JWA::toString(JWA::KeyEncryptionAlgorithm::rsa_oaep));
    REQUIRE("RSA-OAEP-256" == JWA::toString(JWA::KeyEncryptionAlgorithm::rsa_oaep_256));
    REQUIRE("A128KW" == JWA::toString(JWA::KeyEncryptionAlgorithm::a128kw));
    REQUIRE("A192KW" == JWA::toString(JWA::KeyEncryptionAlgorithm::a192kw));
    REQUIRE("A256KW" == JWA::toString(JWA::KeyEncryptionAlgorithm::a256kw));
    REQUIRE("dir" == JWA::toString(JWA::KeyEncryptionAlgorithm::dir));
    REQUIRE("ECDH-ES" == JWA::toString(JWA::KeyEncryptionAlgorithm::ecdh_es));
    REQUIRE("A128GCMKW" == JWA::toString(JWA::KeyEncryptionAlgorithm::a128gcmkw));
    REQUIRE("A192GCMKW" == JWA::toString(JWA::KeyEncryptionAlgorithm::a192gcmkw));
    REQUIRE("A256GCMKW" == JWA::toString(JWA::KeyEncryptionAlgorithm::a256gcmkw));
}

TEST_CASE("ContentEncryptionAlgorithmToString", "[jwa][contentencryptionalgorithmtostring]")
{
    REQUIRE("A128CBC-HS256" == JWA::toString(JWA::ContentEncryptionAlgorithm::a128cbc_hs256));
    REQUIRE("A192CBC-HS384" == JWA::toString(JWA::ContentEncryptionAlgorithm::a192cbc_hs384));
    REQUIRE("A256CBC-HS512" == JWA::toString(JWA::ContentEncryptionAlgorithm::a256cbc_hs512));
    REQUIRE("A128GCM" == JWA::toString(JWA::ContentEncryptionAlgorithm::a128gcm));
    REQUIRE("A192GCM" == JWA::toString(JWA::ContentEncryptionAlgorithm::a192gcm));
    REQUIRE("A256GCM" == JWA::toString(JWA::ContentEncryptionAlgorithm::a256gcm));
}

TEST_CASE("SignatureAlgorithmFromString", "[jwa][signaturealgorithmfromstring]")
{
    REQUIRE(JWA::SignatureAlgorithm::hs256 == JWA::signatureAlgorithmFromString("HS256"));
    REQUIRE(JWA::SignatureAlgorithm::hs384 == JWA::signatureAlgorithmFromString("HS384"));
    REQUIRE(JWA::SignatureAlgorithm::hs512 == JWA::signatureAlgorithmFromString("HS512"));
    REQUIRE(JWA::SignatureAlgorithm::rs256 == JWA::signatureAlgorithmFromString("RS256"));
    REQUIRE(JWA::SignatureAlgorithm::rs384 == JWA::signatureAlgorithmFromString("RS384"));
    REQUIRE(JWA::SignatureAlgorithm::rs512 == JWA::signatureAlgorithmFromString("RS512"));
    REQUIRE(JWA::SignatureAlgorithm::es256 == JWA::signatureAlgorithmFromString("ES256"));
    REQUIRE(JWA::SignatureAlgorithm::es384 == JWA::signatureAlgorithmFromString("ES384"));
    REQUIRE(JWA::SignatureAlgorithm::es512 == JWA::signatureAlgorithmFromString("ES512"));
    REQUIRE(JWA::SignatureAlgorithm::ps256 == JWA::signatureAlgorithmFromString("PS256"));
    REQUIRE(JWA::SignatureAlgorithm::ps384 == JWA::signatureAlgorithmFromString("PS384"));
    REQUIRE(JWA::SignatureAlgorithm::ps512 == JWA::signatureAlgorithmFromString("PS512"));
    REQUIRE(JWA::SignatureAlgorithm::none == JWA::signatureAlgorithmFromString("none"));
}

// HMAC signature tests (HS256, HS384, HS512)
TEST_CASE("HS256SignAndVerify", "[jwa][hs256signandverify]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    std::string data = "test message";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::hs256, key, dataVec);

    REQUIRE_FALSE(signature.empty());

    bool verified = JWA::verify(JWA::SignatureAlgorithm::hs256, key, dataVec, signature);

    REQUIRE(verified);
}

TEST_CASE("HS384SignAndVerify", "[jwa][hs384signandverify]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 384);
    std::string data = "test message for HS384";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::hs384, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::hs384, key, dataVec, signature));
}

TEST_CASE("HS512SignAndVerify", "[jwa][hs512signandverify]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 512);
    std::string data = "test message for HS512";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::hs512, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::hs512, key, dataVec, signature));
}

TEST_CASE("HMACWrongKeyFails", "[jwa][hmacwrongkeyfails]")
{
    JWK key1 = JWK::generateOct(JWK::Use::signature, 256);
    JWK key2 = JWK::generateOct(JWK::Use::signature, 256);
    std::string data = "test message";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::hs256, key1, dataVec);

    bool verified = JWA::verify(JWA::SignatureAlgorithm::hs256, key2, dataVec, signature);

    REQUIRE_FALSE(verified);
}

// RSA signature tests (RS256, RS384, RS512)
TEST_CASE("RS256SignAndVerify", "[jwa][rs256signandverify]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    std::string data = "test message for RSA";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::rs256, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::rs256, key, dataVec, signature));
}

TEST_CASE("RS384SignAndVerify", "[jwa][rs384signandverify]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    std::string data = "test message for RS384";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::rs384, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::rs384, key, dataVec, signature));
}

TEST_CASE("RS512SignAndVerify", "[jwa][rs512signandverify]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    std::string data = "test message for RS512";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::rs512, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::rs512, key, dataVec, signature));
}

TEST_CASE("RSAPublicKeyVerification", "[jwa][rsapublickeyverification]")
{
    JWK privateKey = JWK::generateRSA(JWK::Use::signature, 2048);
    std::string data = "test message";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature =
        JWA::sign(JWA::SignatureAlgorithm::rs256, privateKey, dataVec);

    // Export public key only
    std::string publicKeyJson = privateKey.toJSON(false);
    JWK publicKey = JWK::fromJSON(publicKeyJson);

    // Verify with public key
    bool verified = JWA::verify(JWA::SignatureAlgorithm::rs256, publicKey, dataVec, signature);

    REQUIRE(verified);
}

// ECDSA signature tests (ES256, ES384, ES512)
TEST_CASE("ES256SignAndVerify", "[jwa][es256signandverify]")
{
    JWK key = JWK::generateEC(JWK::Use::signature, "P-256");
    std::string data = "test message for ECDSA";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::es256, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::es256, key, dataVec, signature));
}

TEST_CASE("ES384SignAndVerify", "[jwa][es384signandverify]")
{
    JWK key = JWK::generateEC(JWK::Use::signature, "P-384");
    std::string data = "test message for ES384";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::es384, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::es384, key, dataVec, signature));
}

TEST_CASE("ES512SignAndVerify", "[jwa][es512signandverify]")
{
    JWK key = JWK::generateEC(JWK::Use::signature, "P-521");
    std::string data = "test message for ES512";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::es512, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::es512, key, dataVec, signature));
}

// RSA-PSS signature tests (PS256, PS384, PS512)
TEST_CASE("PS256SignAndVerify", "[jwa][ps256signandverify]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    std::string data = "test message for PSS";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::ps256, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::ps256, key, dataVec, signature));
}

TEST_CASE("PS384SignAndVerify", "[jwa][ps384signandverify]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    std::string data = "test message for PS384";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::ps384, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::ps384, key, dataVec, signature));
}

TEST_CASE("PS512SignAndVerify", "[jwa][ps512signandverify]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    std::string data = "test message for PS512";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::ps512, key, dataVec);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::ps512, key, dataVec, signature));
}

// Signature tampering detection
TEST_CASE("TamperedSignatureFails", "[jwa][tamperedsignaturefails]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    std::string data = "original message";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::rs256, key, dataVec);

    // Tamper with signature
    if (!signature.empty())
    {
        signature[0] ^= 0xFF;
    }

    bool verified = JWA::verify(JWA::SignatureAlgorithm::rs256, key, dataVec, signature);

    REQUIRE_FALSE(verified);
}

TEST_CASE("TamperedDataFails", "[jwa][tampereddatafails]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    std::string data = "original message";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::rs256, key, dataVec);

    // Tamper with data
    std::string tamperedData = "tampered message";
    std::vector<unsigned char> tamperedVec(tamperedData.begin(), tamperedData.end());

    bool verified = JWA::verify(JWA::SignatureAlgorithm::rs256, key, tamperedVec, signature);

    REQUIRE_FALSE(verified);
}

// Key encryption tests
TEST_CASE("RSA_OAEP_EncryptDecrypt", "[jwa][rsa-oaep-encryptdecrypt]")
{
    JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
    std::vector<unsigned char> cek(32, 0x42);  // 256-bit CEK

    std::vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::rsa_oaep, key, cek);

    REQUIRE_FALSE(encrypted.empty());
    REQUIRE(cek != encrypted);

    std::vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::rsa_oaep, key, encrypted);

    REQUIRE(cek == decrypted);
}

TEST_CASE("RSA_OAEP_256_EncryptDecrypt", "[jwa][rsa-oaep-256-encryptdecrypt]")
{
    JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
    std::vector<unsigned char> cek(32, 0x33);

    std::vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::rsa_oaep_256, key, cek);

    REQUIRE_FALSE(encrypted.empty());

    std::vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::rsa_oaep_256, key, encrypted);

    REQUIRE(cek == decrypted);
}

TEST_CASE("A128KW_EncryptDecrypt", "[jwa][a128kw-encryptdecrypt]")
{
    JWK kek = JWK::generateOct(JWK::Use::encryption, 128);
    std::vector<unsigned char> cek(16, 0x55);

    std::vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::a128kw, kek, cek);

    REQUIRE_FALSE(encrypted.empty());

    std::vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::a128kw, kek, encrypted);

    REQUIRE(cek == decrypted);
}

TEST_CASE("A256KW_EncryptDecrypt", "[jwa][a256kw-encryptdecrypt]")
{
    JWK kek = JWK::generateOct(JWK::Use::encryption, 256);
    std::vector<unsigned char> cek(32, 0x66);

    std::vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::a256kw, kek, cek);

    REQUIRE_FALSE(encrypted.empty());

    std::vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::a256kw, kek, encrypted);

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
        JWA::encryptContent(JWA::ContentEncryptionAlgorithm::a128gcm, cek, iv, plaintext, aad);

    REQUIRE_FALSE(ciphertext.empty());
    REQUIRE_FALSE(tag.empty());
    REQUIRE(plaintext != ciphertext);

    std::vector<unsigned char> decrypted = JWA::decryptContent(
        JWA::ContentEncryptionAlgorithm::a128gcm, cek, iv, ciphertext, aad, tag);

    REQUIRE(plaintext == decrypted);
}

TEST_CASE("A256GCM_EncryptDecrypt", "[jwa][a256gcm-encryptdecrypt]")
{
    std::vector<unsigned char> cek(32, 0x42);  // 256-bit key
    std::vector<unsigned char> iv(12, 0x01);
    std::vector<unsigned char> plaintext = {0x54, 0x65, 0x73, 0x74};  // "Test"
    std::vector<unsigned char> aad;

    auto [ciphertext, tag] =
        JWA::encryptContent(JWA::ContentEncryptionAlgorithm::a256gcm, cek, iv, plaintext, aad);

    REQUIRE_FALSE(ciphertext.empty());
    REQUIRE_FALSE(tag.empty());

    std::vector<unsigned char> decrypted = JWA::decryptContent(
        JWA::ContentEncryptionAlgorithm::a256gcm, cek, iv, ciphertext, aad, tag);

    REQUIRE(plaintext == decrypted);
}

TEST_CASE("A128CBC_HS256_EncryptDecrypt", "[jwa][a128cbc-hs256-encryptdecrypt]")
{
    std::vector<unsigned char> cek(32, 0x42);  // 256-bit key (128 for AES + 128 for HMAC)
    std::vector<unsigned char> iv(16, 0x01);   // 128-bit IV for CBC
    std::vector<unsigned char> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21};
    std::vector<unsigned char> aad = {0x41, 0x41, 0x44};

    auto [ciphertext, tag] = JWA::encryptContent(JWA::ContentEncryptionAlgorithm::a128cbc_hs256,
                                                 cek, iv, plaintext, aad);

    REQUIRE_FALSE(ciphertext.empty());
    REQUIRE_FALSE(tag.empty());

    std::vector<unsigned char> decrypted = JWA::decryptContent(
        JWA::ContentEncryptionAlgorithm::a128cbc_hs256, cek, iv, ciphertext, aad, tag);

    REQUIRE(plaintext == decrypted);
}

// Edge cases
TEST_CASE("EmptyDataSignature", "[jwa][emptydatasignature]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    std::vector<unsigned char> emptyData;

    std::vector<unsigned char> signature =
        JWA::sign(JWA::SignatureAlgorithm::rs256, key, emptyData);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::rs256, key, emptyData, signature));
}

TEST_CASE("LargeDataSignature", "[jwa][largedatasignature]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    std::vector<unsigned char> largeData(10000, 0x42);

    std::vector<unsigned char> signature =
        JWA::sign(JWA::SignatureAlgorithm::rs256, key, largeData);

    REQUIRE_FALSE(signature.empty());
    REQUIRE(JWA::verify(JWA::SignatureAlgorithm::rs256, key, largeData, signature));
}

TEST_CASE("EmptyPlaintextEncryption", "[jwa][emptyplaintextencryption]")
{
    std::vector<unsigned char> cek(16, 0x42);
    std::vector<unsigned char> iv(12, 0x01);
    std::vector<unsigned char> plaintext;
    std::vector<unsigned char> aad;

    auto [ciphertext, tag] =
        JWA::encryptContent(JWA::ContentEncryptionAlgorithm::a128gcm, cek, iv, plaintext, aad);

    std::vector<unsigned char> decrypted = JWA::decryptContent(
        JWA::ContentEncryptionAlgorithm::a128gcm, cek, iv, ciphertext, aad, tag);

    REQUIRE(plaintext == decrypted);
}
