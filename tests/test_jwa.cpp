#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "jose/jose.hpp"

using namespace Vlinder::jose;

class JWATest : public ::testing::Test
{
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

// Algorithm string conversion tests
TEST_F(JWATest, SignatureAlgorithmToString)
{
    EXPECT_EQ("HS256", JWA::toString(JWA::SignatureAlgorithm::HS256));
    EXPECT_EQ("HS384", JWA::toString(JWA::SignatureAlgorithm::HS384));
    EXPECT_EQ("HS512", JWA::toString(JWA::SignatureAlgorithm::HS512));
    EXPECT_EQ("RS256", JWA::toString(JWA::SignatureAlgorithm::RS256));
    EXPECT_EQ("RS384", JWA::toString(JWA::SignatureAlgorithm::RS384));
    EXPECT_EQ("RS512", JWA::toString(JWA::SignatureAlgorithm::RS512));
    EXPECT_EQ("ES256", JWA::toString(JWA::SignatureAlgorithm::ES256));
    EXPECT_EQ("ES384", JWA::toString(JWA::SignatureAlgorithm::ES384));
    EXPECT_EQ("ES512", JWA::toString(JWA::SignatureAlgorithm::ES512));
    EXPECT_EQ("PS256", JWA::toString(JWA::SignatureAlgorithm::PS256));
    EXPECT_EQ("PS384", JWA::toString(JWA::SignatureAlgorithm::PS384));
    EXPECT_EQ("PS512", JWA::toString(JWA::SignatureAlgorithm::PS512));
    EXPECT_EQ("none", JWA::toString(JWA::SignatureAlgorithm::None));
}

TEST_F(JWATest, KeyEncryptionAlgorithmToString)
{
    EXPECT_EQ("RSA1_5", JWA::toString(JWA::KeyEncryptionAlgorithm::RSA1_5));
    EXPECT_EQ("RSA-OAEP", JWA::toString(JWA::KeyEncryptionAlgorithm::RSA_OAEP));
    EXPECT_EQ("RSA-OAEP-256", JWA::toString(JWA::KeyEncryptionAlgorithm::RSA_OAEP_256));
    EXPECT_EQ("A128KW", JWA::toString(JWA::KeyEncryptionAlgorithm::A128KW));
    EXPECT_EQ("A192KW", JWA::toString(JWA::KeyEncryptionAlgorithm::A192KW));
    EXPECT_EQ("A256KW", JWA::toString(JWA::KeyEncryptionAlgorithm::A256KW));
    EXPECT_EQ("dir", JWA::toString(JWA::KeyEncryptionAlgorithm::DIR));
    EXPECT_EQ("ECDH-ES", JWA::toString(JWA::KeyEncryptionAlgorithm::ECDH_ES));
    EXPECT_EQ("A128GCMKW", JWA::toString(JWA::KeyEncryptionAlgorithm::A128GCMKW));
    EXPECT_EQ("A192GCMKW", JWA::toString(JWA::KeyEncryptionAlgorithm::A192GCMKW));
    EXPECT_EQ("A256GCMKW", JWA::toString(JWA::KeyEncryptionAlgorithm::A256GCMKW));
}

TEST_F(JWATest, ContentEncryptionAlgorithmToString)
{
    EXPECT_EQ("A128CBC-HS256", JWA::toString(JWA::ContentEncryptionAlgorithm::A128CBC_HS256));
    EXPECT_EQ("A192CBC-HS384", JWA::toString(JWA::ContentEncryptionAlgorithm::A192CBC_HS384));
    EXPECT_EQ("A256CBC-HS512", JWA::toString(JWA::ContentEncryptionAlgorithm::A256CBC_HS512));
    EXPECT_EQ("A128GCM", JWA::toString(JWA::ContentEncryptionAlgorithm::A128GCM));
    EXPECT_EQ("A192GCM", JWA::toString(JWA::ContentEncryptionAlgorithm::A192GCM));
    EXPECT_EQ("A256GCM", JWA::toString(JWA::ContentEncryptionAlgorithm::A256GCM));
}

TEST_F(JWATest, SignatureAlgorithmFromString)
{
    EXPECT_EQ(JWA::SignatureAlgorithm::HS256, JWA::signatureAlgorithmFromString("HS256"));
    EXPECT_EQ(JWA::SignatureAlgorithm::HS384, JWA::signatureAlgorithmFromString("HS384"));
    EXPECT_EQ(JWA::SignatureAlgorithm::HS512, JWA::signatureAlgorithmFromString("HS512"));
    EXPECT_EQ(JWA::SignatureAlgorithm::RS256, JWA::signatureAlgorithmFromString("RS256"));
    EXPECT_EQ(JWA::SignatureAlgorithm::RS384, JWA::signatureAlgorithmFromString("RS384"));
    EXPECT_EQ(JWA::SignatureAlgorithm::RS512, JWA::signatureAlgorithmFromString("RS512"));
    EXPECT_EQ(JWA::SignatureAlgorithm::ES256, JWA::signatureAlgorithmFromString("ES256"));
    EXPECT_EQ(JWA::SignatureAlgorithm::ES384, JWA::signatureAlgorithmFromString("ES384"));
    EXPECT_EQ(JWA::SignatureAlgorithm::ES512, JWA::signatureAlgorithmFromString("ES512"));
    EXPECT_EQ(JWA::SignatureAlgorithm::PS256, JWA::signatureAlgorithmFromString("PS256"));
    EXPECT_EQ(JWA::SignatureAlgorithm::PS384, JWA::signatureAlgorithmFromString("PS384"));
    EXPECT_EQ(JWA::SignatureAlgorithm::PS512, JWA::signatureAlgorithmFromString("PS512"));
    EXPECT_EQ(JWA::SignatureAlgorithm::None, JWA::signatureAlgorithmFromString("none"));
}

// HMAC signature tests (HS256, HS384, HS512)
TEST_F(JWATest, HS256SignAndVerify)
{
    JWK key = JWK::generateOct(256);
    std::string data = "test message";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::HS256, key, dataVec);

    EXPECT_FALSE(signature.empty());

    bool verified = JWA::verify(JWA::SignatureAlgorithm::HS256, key, dataVec, signature);

    EXPECT_TRUE(verified);
}

TEST_F(JWATest, HS384SignAndVerify)
{
    JWK key = JWK::generateOct(384);
    std::string data = "test message for HS384";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::HS384, key, dataVec);

    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(JWA::verify(JWA::SignatureAlgorithm::HS384, key, dataVec, signature));
}

TEST_F(JWATest, HS512SignAndVerify)
{
    JWK key = JWK::generateOct(512);
    std::string data = "test message for HS512";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::HS512, key, dataVec);

    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(JWA::verify(JWA::SignatureAlgorithm::HS512, key, dataVec, signature));
}

TEST_F(JWATest, HMACWrongKeyFails)
{
    JWK key1 = JWK::generateOct(256);
    JWK key2 = JWK::generateOct(256);
    std::string data = "test message";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::HS256, key1, dataVec);

    bool verified = JWA::verify(JWA::SignatureAlgorithm::HS256, key2, dataVec, signature);

    EXPECT_FALSE(verified);
}

// RSA signature tests (RS256, RS384, RS512)
TEST_F(JWATest, RS256SignAndVerify)
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "test message for RSA";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::RS256, key, dataVec);

    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(JWA::verify(JWA::SignatureAlgorithm::RS256, key, dataVec, signature));
}

TEST_F(JWATest, RS384SignAndVerify)
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "test message for RS384";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::RS384, key, dataVec);

    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(JWA::verify(JWA::SignatureAlgorithm::RS384, key, dataVec, signature));
}

TEST_F(JWATest, RS512SignAndVerify)
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "test message for RS512";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::RS512, key, dataVec);

    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(JWA::verify(JWA::SignatureAlgorithm::RS512, key, dataVec, signature));
}

TEST_F(JWATest, RSAPublicKeyVerification)
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

    EXPECT_TRUE(verified);
}

// ECDSA signature tests (ES256, ES384, ES512)
TEST_F(JWATest, ES256SignAndVerify)
{
    JWK key = JWK::generateEC("P-256");
    std::string data = "test message for ECDSA";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::ES256, key, dataVec);

    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(JWA::verify(JWA::SignatureAlgorithm::ES256, key, dataVec, signature));
}

TEST_F(JWATest, ES384SignAndVerify)
{
    JWK key = JWK::generateEC("P-384");
    std::string data = "test message for ES384";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::ES384, key, dataVec);

    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(JWA::verify(JWA::SignatureAlgorithm::ES384, key, dataVec, signature));
}

TEST_F(JWATest, ES512SignAndVerify)
{
    JWK key = JWK::generateEC("P-521");
    std::string data = "test message for ES512";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::ES512, key, dataVec);

    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(JWA::verify(JWA::SignatureAlgorithm::ES512, key, dataVec, signature));
}

// RSA-PSS signature tests (PS256, PS384, PS512)
TEST_F(JWATest, PS256SignAndVerify)
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "test message for PSS";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::PS256, key, dataVec);

    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(JWA::verify(JWA::SignatureAlgorithm::PS256, key, dataVec, signature));
}

TEST_F(JWATest, PS384SignAndVerify)
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "test message for PS384";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::PS384, key, dataVec);

    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(JWA::verify(JWA::SignatureAlgorithm::PS384, key, dataVec, signature));
}

TEST_F(JWATest, PS512SignAndVerify)
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "test message for PS512";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::PS512, key, dataVec);

    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(JWA::verify(JWA::SignatureAlgorithm::PS512, key, dataVec, signature));
}

// Signature tampering detection
TEST_F(JWATest, TamperedSignatureFails)
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

    EXPECT_FALSE(verified);
}

TEST_F(JWATest, TamperedDataFails)
{
    JWK key = JWK::generateRSA(2048);
    std::string data = "original message";
    std::vector<unsigned char> dataVec(data.begin(), data.end());

    std::vector<unsigned char> signature = JWA::sign(JWA::SignatureAlgorithm::RS256, key, dataVec);

    // Tamper with data
    std::string tamperedData = "tampered message";
    std::vector<unsigned char> tamperedVec(tamperedData.begin(), tamperedData.end());

    bool verified = JWA::verify(JWA::SignatureAlgorithm::RS256, key, tamperedVec, signature);

    EXPECT_FALSE(verified);
}

// Key encryption tests
TEST_F(JWATest, RSA_OAEP_EncryptDecrypt)
{
    JWK key = JWK::generateRSA(2048);
    std::vector<unsigned char> cek(32, 0x42);  // 256-bit CEK

    std::vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::RSA_OAEP, key, cek);

    EXPECT_FALSE(encrypted.empty());
    EXPECT_NE(cek, encrypted);

    std::vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::RSA_OAEP, key, encrypted);

    EXPECT_EQ(cek, decrypted);
}

TEST_F(JWATest, RSA_OAEP_256_EncryptDecrypt)
{
    JWK key = JWK::generateRSA(2048);
    std::vector<unsigned char> cek(32, 0x33);

    std::vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::RSA_OAEP_256, key, cek);

    EXPECT_FALSE(encrypted.empty());

    std::vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::RSA_OAEP_256, key, encrypted);

    EXPECT_EQ(cek, decrypted);
}

TEST_F(JWATest, A128KW_EncryptDecrypt)
{
    JWK kek = JWK::generateOct(128);
    std::vector<unsigned char> cek(16, 0x55);

    std::vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::A128KW, kek, cek);

    EXPECT_FALSE(encrypted.empty());

    std::vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::A128KW, kek, encrypted);

    EXPECT_EQ(cek, decrypted);
}

TEST_F(JWATest, A256KW_EncryptDecrypt)
{
    JWK kek = JWK::generateOct(256);
    std::vector<unsigned char> cek(32, 0x66);

    std::vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::A256KW, kek, cek);

    EXPECT_FALSE(encrypted.empty());

    std::vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::A256KW, kek, encrypted);

    EXPECT_EQ(cek, decrypted);
}

// Content encryption tests
TEST_F(JWATest, A128GCM_EncryptDecrypt)
{
    std::vector<unsigned char> cek(16, 0x42);                               // 128-bit key
    std::vector<unsigned char> iv(12, 0x01);                                // 96-bit IV for GCM
    std::vector<unsigned char> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};  // "Hello"
    std::vector<unsigned char> aad = {0x41, 0x41, 0x44};                    // AAD

    auto [ciphertext, tag] =
        JWA::encryptContent(JWA::ContentEncryptionAlgorithm::A128GCM, cek, iv, plaintext, aad);

    EXPECT_FALSE(ciphertext.empty());
    EXPECT_FALSE(tag.empty());
    EXPECT_NE(plaintext, ciphertext);

    std::vector<unsigned char> decrypted = JWA::decryptContent(
        JWA::ContentEncryptionAlgorithm::A128GCM, cek, iv, ciphertext, aad, tag);

    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(JWATest, A256GCM_EncryptDecrypt)
{
    std::vector<unsigned char> cek(32, 0x42);  // 256-bit key
    std::vector<unsigned char> iv(12, 0x01);
    std::vector<unsigned char> plaintext = {0x54, 0x65, 0x73, 0x74};  // "Test"
    std::vector<unsigned char> aad;

    auto [ciphertext, tag] =
        JWA::encryptContent(JWA::ContentEncryptionAlgorithm::A256GCM, cek, iv, plaintext, aad);

    EXPECT_FALSE(ciphertext.empty());
    EXPECT_FALSE(tag.empty());

    std::vector<unsigned char> decrypted = JWA::decryptContent(
        JWA::ContentEncryptionAlgorithm::A256GCM, cek, iv, ciphertext, aad, tag);

    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(JWATest, A128CBC_HS256_EncryptDecrypt)
{
    std::vector<unsigned char> cek(32, 0x42);  // 256-bit key (128 for AES + 128 for HMAC)
    std::vector<unsigned char> iv(16, 0x01);   // 128-bit IV for CBC
    std::vector<unsigned char> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21};
    std::vector<unsigned char> aad = {0x41, 0x41, 0x44};

    auto [ciphertext, tag] = JWA::encryptContent(JWA::ContentEncryptionAlgorithm::A128CBC_HS256,
                                                 cek, iv, plaintext, aad);

    EXPECT_FALSE(ciphertext.empty());
    EXPECT_FALSE(tag.empty());

    std::vector<unsigned char> decrypted = JWA::decryptContent(
        JWA::ContentEncryptionAlgorithm::A128CBC_HS256, cek, iv, ciphertext, aad, tag);

    EXPECT_EQ(plaintext, decrypted);
}

// Edge cases
TEST_F(JWATest, EmptyDataSignature)
{
    JWK key = JWK::generateRSA(2048);
    std::vector<unsigned char> emptyData;

    std::vector<unsigned char> signature =
        JWA::sign(JWA::SignatureAlgorithm::RS256, key, emptyData);

    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(JWA::verify(JWA::SignatureAlgorithm::RS256, key, emptyData, signature));
}

TEST_F(JWATest, LargeDataSignature)
{
    JWK key = JWK::generateRSA(2048);
    std::vector<unsigned char> largeData(10000, 0x42);

    std::vector<unsigned char> signature =
        JWA::sign(JWA::SignatureAlgorithm::RS256, key, largeData);

    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(JWA::verify(JWA::SignatureAlgorithm::RS256, key, largeData, signature));
}

TEST_F(JWATest, EmptyPlaintextEncryption)
{
    std::vector<unsigned char> cek(16, 0x42);
    std::vector<unsigned char> iv(12, 0x01);
    std::vector<unsigned char> plaintext;
    std::vector<unsigned char> aad;

    auto [ciphertext, tag] =
        JWA::encryptContent(JWA::ContentEncryptionAlgorithm::A128GCM, cek, iv, plaintext, aad);

    std::vector<unsigned char> decrypted = JWA::decryptContent(
        JWA::ContentEncryptionAlgorithm::A128GCM, cek, iv, ciphertext, aad, tag);

    EXPECT_EQ(plaintext, decrypted);
}
