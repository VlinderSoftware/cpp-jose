#include <gtest/gtest.h>
#include "jose/jose.hpp"
#include <string>

using namespace Vlinder::jose;

class JWETest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// Basic JWE creation tests
TEST_F(JWETest, CreateSimpleJWE) {
    JWK key = JWK::generateRSA(2048);
    
    JWE jwe;
    jwe.setPlaintext("test plaintext");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    std::string token = jwe.encrypt(key);
    EXPECT_FALSE(token.empty());
    
    // Should have 5 parts separated by dots
    int dotCount = 0;
    for (char c : token) {
        if (c == '.') dotCount++;
    }
    EXPECT_EQ(4, dotCount);  // 5 parts = 4 dots
}

TEST_F(JWETest, EncryptDecryptRSA_OAEP_A128GCM) {
    JWK key = JWK::generateRSA(2048);
    
    JWE jwe;
    std::string plaintext = "This is a secret message";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    std::string token = jwe.encrypt(key);
    
    std::string decrypted = JWE::decrypt(token, key);
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(JWETest, EncryptDecryptRSA_OAEP_A256GCM) {
    JWK key = JWK::generateRSA(2048);
    
    JWE jwe;
    std::string plaintext = "Secret data with A256GCM";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A256GCM);
    
    std::string token = jwe.encrypt(key);
    
    std::string decrypted = JWE::decrypt(token, key);
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(JWETest, EncryptDecryptRSA_OAEP_256_A128GCM) {
    JWK key = JWK::generateRSA(2048);
    
    JWE jwe;
    std::string plaintext = "Testing RSA-OAEP-256";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP_256);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    std::string token = jwe.encrypt(key);
    
    std::string decrypted = JWE::decrypt(token, key);
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(JWETest, EncryptDecryptA128KW_A128GCM) {
    JWK key = JWK::generateOct(128);
    
    JWE jwe;
    std::string plaintext = "AES Key Wrap test";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::A128KW);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    std::string token = jwe.encrypt(key);
    
    std::string decrypted = JWE::decrypt(token, key);
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(JWETest, EncryptDecryptA256KW_A256GCM) {
    JWK key = JWK::generateOct(256);
    
    JWE jwe;
    std::string plaintext = "A256KW with A256GCM";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::A256KW);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A256GCM);
    
    std::string token = jwe.encrypt(key);
    
    std::string decrypted = JWE::decrypt(token, key);
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(JWETest, EncryptDecryptDIR_A128GCM) {
    JWK key = JWK::generateOct(128);
    
    JWE jwe;
    std::string plaintext = "Direct encryption test";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::DIR);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    std::string token = jwe.encrypt(key);
    
    std::string decrypted = JWE::decrypt(token, key);
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(JWETest, EncryptDecryptA128CBC_HS256) {
    JWK key = JWK::generateRSA(2048);
    
    JWE jwe;
    std::string plaintext = "Testing CBC mode";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128CBC_HS256);
    
    std::string token = jwe.encrypt(key);
    
    std::string decrypted = JWE::decrypt(token, key);
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(JWETest, EncryptDecryptA256CBC_HS512) {
    JWK key = JWK::generateRSA(2048);
    
    JWE jwe;
    std::string plaintext = "Testing A256CBC-HS512";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A256CBC_HS512);
    
    std::string token = jwe.encrypt(key);
    
    std::string decrypted = JWE::decrypt(token, key);
    EXPECT_EQ(plaintext, decrypted);
}

// Header and metadata tests
TEST_F(JWETest, SetKeyId) {
    JWK key = JWK::generateRSA(2048);
    
    JWE jwe;
    jwe.setPlaintext("test");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    jwe.setKeyId("my-key-id");
    
    std::string token = jwe.encrypt(key);
    
    JWE parsed = JWE::parse(token);
    std::string header = parsed.getHeader();
    
    EXPECT_NE(std::string::npos, header.find("my-key-id"));
}

TEST_F(JWETest, SetType) {
    JWK key = JWK::generateRSA(2048);
    
    JWE jwe;
    jwe.setPlaintext("test");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    jwe.setType("JWT");
    
    std::string token = jwe.encrypt(key);
    
    JWE parsed = JWE::parse(token);
    std::string header = parsed.getHeader();
    
    EXPECT_NE(std::string::npos, header.find("JWT"));
}

TEST_F(JWETest, SetCustomHeaderParam) {
    JWK key = JWK::generateRSA(2048);
    
    JWE jwe;
    jwe.setPlaintext("test");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    jwe.setHeaderParam("custom", "value");
    
    std::string token = jwe.encrypt(key);
    
    JWE parsed = JWE::parse(token);
    std::string header = parsed.getHeader();
    
    EXPECT_NE(std::string::npos, header.find("custom"));
    EXPECT_NE(std::string::npos, header.find("value"));
}

TEST_F(JWETest, GetHeader) {
    JWK key = JWK::generateRSA(2048);
    
    JWE jwe;
    jwe.setPlaintext("test");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    std::string token = jwe.encrypt(key);
    
    JWE parsed = JWE::parse(token);
    std::string header = parsed.getHeader();
    
    EXPECT_FALSE(header.empty());
    EXPECT_NE(std::string::npos, header.find("alg"));
    EXPECT_NE(std::string::npos, header.find("enc"));
}

// Parsing tests
TEST_F(JWETest, ParseJWE) {
    JWK key = JWK::generateRSA(2048);
    
    JWE original;
    original.setPlaintext("test plaintext");
    original.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    original.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    original.setKeyId("key-123");
    
    std::string token = original.encrypt(key);
    
    JWE parsed = JWE::parse(token);
    std::string header = parsed.getHeader();
    
    EXPECT_NE(std::string::npos, header.find("key-123"));
}

// Wrong key tests
TEST_F(JWETest, DecryptWithWrongKeyFails) {
    JWK key1 = JWK::generateRSA(2048);
    JWK key2 = JWK::generateRSA(2048);
    
    JWE jwe;
    jwe.setPlaintext("secret");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    std::string token = jwe.encrypt(key1);
    
    EXPECT_THROW({
        JWE::decrypt(token, key2);
    }, std::exception);
}

TEST_F(JWETest, SymmetricWrongKeyFails) {
    JWK key1 = JWK::generateOct(256);
    JWK key2 = JWK::generateOct(256);
    
    JWE jwe;
    jwe.setPlaintext("secret");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::A256KW);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A256GCM);
    
    std::string token = jwe.encrypt(key1);
    
    EXPECT_THROW({
        JWE::decrypt(token, key2);
    }, std::exception);
}

// Tampering tests
TEST_F(JWETest, TamperedCiphertextFails) {
    JWK key = JWK::generateRSA(2048);
    
    JWE jwe;
    jwe.setPlaintext("original");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    std::string token = jwe.encrypt(key);
    
    // Tamper with ciphertext part (4th component)
    size_t dot1 = token.find('.');
    size_t dot2 = token.find('.', dot1 + 1);
    size_t dot3 = token.find('.', dot2 + 1);
    size_t dot4 = token.find('.', dot3 + 1);
    
    if (dot3 != std::string::npos && dot4 != std::string::npos && dot3 + 1 < dot4) {
        token[dot3 + 1] = (token[dot3 + 1] == 'A') ? 'B' : 'A';
    }
    
    EXPECT_THROW({
        JWE::decrypt(token, key);
    }, std::exception);
}

// Copy and move semantics
TEST_F(JWETest, CopyConstructor) {
    JWE original;
    original.setPlaintext("test");
    original.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    original.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    JWE copy(original);
    EXPECT_EQ(original.getPlaintext(), copy.getPlaintext());
}

TEST_F(JWETest, CopyAssignment) {
    JWE original;
    original.setPlaintext("test");
    original.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    original.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    JWE copy = original;
    EXPECT_EQ(original.getPlaintext(), copy.getPlaintext());
}

TEST_F(JWETest, MoveConstructor) {
    JWE original;
    original.setPlaintext("test plaintext");
    original.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    original.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    JWE moved(std::move(original));
    EXPECT_EQ("test plaintext", moved.getPlaintext());
}

TEST_F(JWETest, MoveAssignment) {
    JWE original;
    original.setPlaintext("test plaintext");
    original.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    original.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    JWE moved = std::move(original);
    EXPECT_EQ("test plaintext", moved.getPlaintext());
}

// Edge cases
TEST_F(JWETest, EmptyPlaintext) {
    JWK key = JWK::generateRSA(2048);
    
    JWE jwe;
    jwe.setPlaintext("");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    std::string token = jwe.encrypt(key);
    EXPECT_FALSE(token.empty());
    
    std::string decrypted = JWE::decrypt(token, key);
    EXPECT_EQ("", decrypted);
}

TEST_F(JWETest, LargePlaintext) {
    JWK key = JWK::generateRSA(2048);
    
    std::string largePlaintext(10000, 'X');
    
    JWE jwe;
    jwe.setPlaintext(largePlaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    std::string token = jwe.encrypt(key);
    
    std::string decrypted = JWE::decrypt(token, key);
    EXPECT_EQ(largePlaintext, decrypted);
}

TEST_F(JWETest, PlaintextWithSpecialCharacters) {
    JWK key = JWK::generateRSA(2048);
    
    std::string plaintext = "Special: \n\t\r\"'{}[]<>!@#$%^&*()";
    
    JWE jwe;
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    std::string token = jwe.encrypt(key);
    
    std::string decrypted = JWE::decrypt(token, key);
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(JWETest, BinaryPlaintext) {
    JWK key = JWK::generateRSA(2048);
    
    std::string plaintext;
    for (int i = 0; i < 256; i++) {
        plaintext += static_cast<char>(i);
    }
    
    JWE jwe;
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    std::string token = jwe.encrypt(key);
    
    std::string decrypted = JWE::decrypt(token, key);
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(JWETest, JSONPlaintext) {
    JWK key = JWK::generateRSA(2048);
    
    std::string jsonPlaintext = R"({
        "user": "john",
        "role": "admin",
        "permissions": ["read", "write", "delete"]
    })";
    
    JWE jwe;
    jwe.setPlaintext(jsonPlaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    std::string token = jwe.encrypt(key);
    
    std::string decrypted = JWE::decrypt(token, key);
    EXPECT_EQ(jsonPlaintext, decrypted);
}

TEST_F(JWETest, MultipleEncryptionsSamePlaintext) {
    JWK key = JWK::generateRSA(2048);
    std::string plaintext = "same plaintext";
    
    JWE jwe1;
    jwe1.setPlaintext(plaintext);
    jwe1.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe1.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    JWE jwe2;
    jwe2.setPlaintext(plaintext);
    jwe2.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::RSA_OAEP);
    jwe2.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::A128GCM);
    
    std::string token1 = jwe1.encrypt(key);
    std::string token2 = jwe2.encrypt(key);
    
    // Tokens should be different due to random IV/CEK
    EXPECT_NE(token1, token2);
    
    // But both should decrypt to same plaintext
    EXPECT_EQ(plaintext, JWE::decrypt(token1, key));
    EXPECT_EQ(plaintext, JWE::decrypt(token2, key));
}

