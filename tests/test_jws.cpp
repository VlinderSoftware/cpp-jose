#include <gtest/gtest.h>
#include "jose/jose.hpp"
#include <string>

using namespace Vlinder::jose;

class JWSTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// Basic JWS creation tests
TEST_F(JWSTest, CreateSimpleJWS) {
    JWK key = JWK::generateOct(256);
    
    JWS jws;
    jws.setPayload("test payload");
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    
    std::string token = jws.sign(key);
    EXPECT_FALSE(token.empty());
    
    // Should have 3 parts separated by dots
    size_t firstDot = token.find('.');
    size_t secondDot = token.find('.', firstDot + 1);
    EXPECT_NE(std::string::npos, firstDot);
    EXPECT_NE(std::string::npos, secondDot);
}

TEST_F(JWSTest, CreateJWSWithAllAlgorithms) {
    std::vector<std::pair<JWA::SignatureAlgorithm, JWK>> testCases = {
        {JWA::SignatureAlgorithm::HS256, JWK::generateOct(256)},
        {JWA::SignatureAlgorithm::HS384, JWK::generateOct(384)},
        {JWA::SignatureAlgorithm::HS512, JWK::generateOct(512)},
        {JWA::SignatureAlgorithm::RS256, JWK::generateRSA(2048)},
        {JWA::SignatureAlgorithm::RS384, JWK::generateRSA(2048)},
        {JWA::SignatureAlgorithm::RS512, JWK::generateRSA(2048)},
        {JWA::SignatureAlgorithm::ES256, JWK::generateEC("P-256")},
        {JWA::SignatureAlgorithm::ES384, JWK::generateEC("P-384")},
        {JWA::SignatureAlgorithm::ES512, JWK::generateEC("P-521")},
        {JWA::SignatureAlgorithm::PS256, JWK::generateRSA(2048)},
        {JWA::SignatureAlgorithm::PS384, JWK::generateRSA(2048)},
        {JWA::SignatureAlgorithm::PS512, JWK::generateRSA(2048)}
    };
    
    for (const auto& [alg, key] : testCases) {
        JWS jws;
        jws.setPayload("test");
        jws.setAlgorithm(alg);
        
        std::string token = jws.sign(key);
        EXPECT_FALSE(token.empty()) << "Failed for algorithm: " << JWA::toString(alg);
    }
}

TEST_F(JWSTest, SetPayload) {
    JWS jws;
    jws.setPayload("Hello, World!");
    
    JWK key = JWK::generateOct(256);
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    
    std::string token = jws.sign(key);
    JWS parsed = JWS::parse(token);
    
    EXPECT_EQ("Hello, World!", parsed.getPayload());
}

TEST_F(JWSTest, SetKeyId) {
    JWS jws;
    jws.setPayload("test");
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    jws.setKeyId("my-key-123");
    
    JWK key = JWK::generateOct(256);
    std::string token = jws.sign(key);
    
    JWS parsed = JWS::parse(token);
    std::string header = parsed.getHeader();
    
    EXPECT_NE(std::string::npos, header.find("my-key-123"));
}

TEST_F(JWSTest, SetType) {
    JWS jws;
    jws.setPayload("test");
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    jws.setType("JWT");
    
    JWK key = JWK::generateOct(256);
    std::string token = jws.sign(key);
    
    JWS parsed = JWS::parse(token);
    std::string header = parsed.getHeader();
    
    EXPECT_NE(std::string::npos, header.find("JWT"));
}

TEST_F(JWSTest, SetCustomHeaderParam) {
    JWS jws;
    jws.setPayload("test");
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    jws.setHeaderParam("custom", "value");
    
    JWK key = JWK::generateOct(256);
    std::string token = jws.sign(key);
    
    JWS parsed = JWS::parse(token);
    std::string header = parsed.getHeader();
    
    EXPECT_NE(std::string::npos, header.find("custom"));
    EXPECT_NE(std::string::npos, header.find("value"));
}

TEST_F(JWSTest, GetHeader) {
    JWS jws;
    jws.setPayload("test");
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    jws.setKeyId("key-1");
    jws.setType("JWT");
    
    JWK key = JWK::generateOct(256);
    std::string token = jws.sign(key);
    
    JWS parsed = JWS::parse(token);
    std::string header = parsed.getHeader();
    
    EXPECT_FALSE(header.empty());
    EXPECT_NE(std::string::npos, header.find("alg"));
    EXPECT_NE(std::string::npos, header.find("HS256"));
}

TEST_F(JWSTest, GetAlgorithm) {
    JWS jws;
    jws.setPayload("test");
    jws.setAlgorithm(JWA::SignatureAlgorithm::RS256);
    
    JWK key = JWK::generateRSA(2048);
    std::string token = jws.sign(key);
    
    JWS parsed = JWS::parse(token);
    EXPECT_EQ(JWA::SignatureAlgorithm::RS256, parsed.getAlgorithm());
}

// Verification tests
TEST_F(JWSTest, VerifyValidHS256) {
    JWK key = JWK::generateOct(256);
    
    JWS jws;
    jws.setPayload("secure message");
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    
    std::string token = jws.sign(key);
    
    bool verified = JWS::verify(token, key);
    EXPECT_TRUE(verified);
}

TEST_F(JWSTest, VerifyValidRS256) {
    JWK key = JWK::generateRSA(2048);
    
    JWS jws;
    jws.setPayload("rsa signed message");
    jws.setAlgorithm(JWA::SignatureAlgorithm::RS256);
    
    std::string token = jws.sign(key);
    
    bool verified = JWS::verify(token, key);
    EXPECT_TRUE(verified);
}

TEST_F(JWSTest, VerifyValidES256) {
    JWK key = JWK::generateEC("P-256");
    
    JWS jws;
    jws.setPayload("ecdsa signed message");
    jws.setAlgorithm(JWA::SignatureAlgorithm::ES256);
    
    std::string token = jws.sign(key);
    
    bool verified = JWS::verify(token, key);
    EXPECT_TRUE(verified);
}

TEST_F(JWSTest, VerifyWithWrongKeyFails) {
    JWK key1 = JWK::generateOct(256);
    JWK key2 = JWK::generateOct(256);
    
    JWS jws;
    jws.setPayload("message");
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    
    std::string token = jws.sign(key1);
    
    bool verified = JWS::verify(token, key2);
    EXPECT_FALSE(verified);
}

TEST_F(JWSTest, VerifyTamperedPayloadFails) {
    JWK key = JWK::generateOct(256);
    
    JWS jws;
    jws.setPayload("original payload");
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    
    std::string token = jws.sign(key);
    
    // Tamper with token by modifying the payload part
    size_t firstDot = token.find('.');
    size_t secondDot = token.find('.', firstDot + 1);
    if (firstDot != std::string::npos && secondDot != std::string::npos) {
        token[firstDot + 1] = (token[firstDot + 1] == 'A') ? 'B' : 'A';
    }
    
    bool verified = JWS::verify(token, key);
    EXPECT_FALSE(verified);
}

TEST_F(JWSTest, VerifyTamperedSignatureFails) {
    JWK key = JWK::generateOct(256);
    
    JWS jws;
    jws.setPayload("payload");
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    
    std::string token = jws.sign(key);
    
    // Tamper with signature
    size_t lastDot = token.rfind('.');
    if (lastDot != std::string::npos && lastDot + 1 < token.length()) {
        token[lastDot + 1] = (token[lastDot + 1] == 'A') ? 'B' : 'A';
    }
    
    bool verified = JWS::verify(token, key);
    EXPECT_FALSE(verified);
}

// Parsing tests
TEST_F(JWSTest, ParseJWS) {
    JWK key = JWK::generateOct(256);
    
    JWS original;
    original.setPayload("test payload");
    original.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    original.setKeyId("key-123");
    
    std::string token = original.sign(key);
    
    JWS parsed = JWS::parse(token);
    EXPECT_EQ("test payload", parsed.getPayload());
    EXPECT_EQ(JWA::SignatureAlgorithm::HS256, parsed.getAlgorithm());
}

TEST_F(JWSTest, ParseAndGetPayload) {
    JWK key = JWK::generateRSA(2048);
    
    JWS jws;
    jws.setPayload("This is the payload content");
    jws.setAlgorithm(JWA::SignatureAlgorithm::RS256);
    
    std::string token = jws.sign(key);
    
    JWS parsed = JWS::parse(token);
    EXPECT_EQ("This is the payload content", parsed.getPayload());
}

// Copy and move semantics
TEST_F(JWSTest, CopyConstructor) {
    JWS original;
    original.setPayload("test");
    original.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    
    JWS copy(original);
    EXPECT_EQ(original.getPayload(), copy.getPayload());
    EXPECT_EQ(original.getAlgorithm(), copy.getAlgorithm());
}

TEST_F(JWSTest, CopyAssignment) {
    JWS original;
    original.setPayload("test");
    original.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    
    JWS copy = original;
    EXPECT_EQ(original.getPayload(), copy.getPayload());
}

TEST_F(JWSTest, MoveConstructor) {
    JWS original;
    original.setPayload("test payload");
    original.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    
    JWS moved(std::move(original));
    EXPECT_EQ("test payload", moved.getPayload());
}

TEST_F(JWSTest, MoveAssignment) {
    JWS original;
    original.setPayload("test payload");
    original.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    
    JWS moved = std::move(original);
    EXPECT_EQ("test payload", moved.getPayload());
}

// Edge cases
TEST_F(JWSTest, EmptyPayload) {
    JWK key = JWK::generateOct(256);
    
    JWS jws;
    jws.setPayload("");
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    
    std::string token = jws.sign(key);
    EXPECT_FALSE(token.empty());
    
    bool verified = JWS::verify(token, key);
    EXPECT_TRUE(verified);
}

TEST_F(JWSTest, LargePayload) {
    JWK key = JWK::generateOct(256);
    
    std::string largePayload(10000, 'X');
    
    JWS jws;
    jws.setPayload(largePayload);
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    
    std::string token = jws.sign(key);
    EXPECT_FALSE(token.empty());
    
    JWS parsed = JWS::parse(token);
    EXPECT_EQ(largePayload, parsed.getPayload());
}

TEST_F(JWSTest, PayloadWithSpecialCharacters) {
    JWK key = JWK::generateOct(256);
    
    std::string payload = "Special chars: \n\t\r\"'{}[]";
    
    JWS jws;
    jws.setPayload(payload);
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    
    std::string token = jws.sign(key);
    
    JWS parsed = JWS::parse(token);
    EXPECT_EQ(payload, parsed.getPayload());
}

TEST_F(JWSTest, JSONPayload) {
    JWK key = JWK::generateOct(256);
    
    std::string jsonPayload = R"({"name":"John","age":30,"city":"New York"})";
    
    JWS jws;
    jws.setPayload(jsonPayload);
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    
    std::string token = jws.sign(key);
    
    JWS parsed = JWS::parse(token);
    EXPECT_EQ(jsonPayload, parsed.getPayload());
}

TEST_F(JWSTest, MultipleHeaderParams) {
    JWK key = JWK::generateOct(256);
    
    JWS jws;
    jws.setPayload("test");
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    jws.setKeyId("key-1");
    jws.setType("JWT");
    jws.setHeaderParam("custom1", "value1");
    jws.setHeaderParam("custom2", "value2");
    
    std::string token = jws.sign(key);
    
    JWS parsed = JWS::parse(token);
    std::string header = parsed.getHeader();
    
    EXPECT_NE(std::string::npos, header.find("custom1"));
    EXPECT_NE(std::string::npos, header.find("custom2"));
}

// Public key verification
TEST_F(JWSTest, RSAPublicKeyVerification) {
    JWK privateKey = JWK::generateRSA(2048);
    
    JWS jws;
    jws.setPayload("message for public verification");
    jws.setAlgorithm(JWA::SignatureAlgorithm::RS256);
    
    std::string token = jws.sign(privateKey);
    
    // Extract public key
    std::string publicKeyJson = privateKey.toJson(false);
    JWK publicKey = JWK::fromJson(publicKeyJson);
    
    bool verified = JWS::verify(token, publicKey);
    EXPECT_TRUE(verified);
}

TEST_F(JWSTest, ECPublicKeyVerification) {
    JWK privateKey = JWK::generateEC("P-256");
    
    JWS jws;
    jws.setPayload("ec message");
    jws.setAlgorithm(JWA::SignatureAlgorithm::ES256);
    
    std::string token = jws.sign(privateKey);
    
    // Extract public key
    std::string publicKeyJson = privateKey.toJson(false);
    JWK publicKey = JWK::fromJson(publicKeyJson);
    
    bool verified = JWS::verify(token, publicKey);
    EXPECT_TRUE(verified);
}

// Interoperability test
TEST_F(JWSTest, CreateWithJWSVerifyWithJWT) {
    JWK key = JWK::generateOct(256);
    
    JWS jws;
    std::string payload = R"({"sub":"1234567890","name":"John Doe","iat":1516239022})";
    jws.setPayload(payload);
    jws.setAlgorithm(JWA::SignatureAlgorithm::HS256);
    jws.setType("JWT");
    
    std::string token = jws.sign(key);
    
    // Should be verifiable as JWT
    bool verified = JWS::verify(token, key);
    EXPECT_TRUE(verified);
}

