#include "jose/jose.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <thread>

using namespace Vlinder::jose;

class JWTTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

// Basic JWT creation tests
TEST_F(JWTTest, CreateSimpleJWT)
{
    JWT jwt;
    jwt.setIssuer("test-issuer");
    jwt.setSubject("user123");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key, "HS256");

    EXPECT_FALSE(token.empty());

    // JWT should have 3 parts
    size_t firstDot = token.find('.');
    size_t secondDot = token.find('.', firstDot + 1);
    EXPECT_NE(std::string::npos, firstDot);
    EXPECT_NE(std::string::npos, secondDot);
}

TEST_F(JWTTest, SetAndGetIssuer)
{
    JWT jwt;
    jwt.setIssuer("https://example.com");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    EXPECT_EQ("https://example.com", verified.getIssuer());
}

TEST_F(JWTTest, SetAndGetSubject)
{
    JWT jwt;
    jwt.setSubject("user@example.com");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    EXPECT_EQ("user@example.com", verified.getSubject());
}

TEST_F(JWTTest, SetAndGetAudienceSingle)
{
    JWT jwt;
    jwt.setAudience("https://api.example.com");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    std::vector<std::string> audience = verified.getAudience();
    EXPECT_EQ(1, audience.size());
    EXPECT_EQ("https://api.example.com", audience[0]);
}

TEST_F(JWTTest, SetAndGetAudienceMultiple)
{
    JWT jwt;
    std::vector<std::string> audiences = {"audience1", "audience2", "audience3"};
    jwt.setAudience(audiences);

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    std::vector<std::string> retrievedAudiences = verified.getAudience();
    EXPECT_EQ(3, retrievedAudiences.size());
    EXPECT_EQ("audience1", retrievedAudiences[0]);
    EXPECT_EQ("audience2", retrievedAudiences[1]);
    EXPECT_EQ("audience3", retrievedAudiences[2]);
}

TEST_F(JWTTest, SetAndGetExpiration)
{
    JWT jwt;
    auto now = std::chrono::system_clock::now();
    auto expiration = now + std::chrono::hours(1);
    jwt.setExpiration(expiration);

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    auto retrievedExp = verified.getExpiration();

    // Allow 1 second tolerance
    auto diff = std::chrono::abs(expiration - retrievedExp);
    EXPECT_LE(diff, std::chrono::seconds(1));
}

TEST_F(JWTTest, SetAndGetNotBefore)
{
    JWT jwt;
    auto now = std::chrono::system_clock::now();
    jwt.setNotBefore(now);

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    auto retrievedNbf = verified.getNotBefore();

    auto diff = std::chrono::abs(now - retrievedNbf);
    EXPECT_LE(diff, std::chrono::seconds(1));
}

TEST_F(JWTTest, SetAndGetIssuedAt)
{
    JWT jwt;
    auto now = std::chrono::system_clock::now();
    jwt.setIssuedAt(now);

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    auto retrievedIat = verified.getIssuedAt();

    auto diff = std::chrono::abs(now - retrievedIat);
    EXPECT_LE(diff, std::chrono::seconds(1));
}

TEST_F(JWTTest, SetAndGetJwtId)
{
    JWT jwt;
    jwt.setJwtId("unique-jwt-id-12345");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    EXPECT_EQ("unique-jwt-id-12345", verified.getJwtId());
}

TEST_F(JWTTest, SetAndGetCustomClaim)
{
    JWT jwt;
    jwt.setClaim("custom_claim", "custom_value");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    EXPECT_TRUE(verified.hasClaim("custom_claim"));
    EXPECT_EQ("custom_value", verified.getClaim("custom_claim"));
}

TEST_F(JWTTest, MultipleCustomClaims)
{
    JWT jwt;
    jwt.setClaim("claim1", "value1");
    jwt.setClaim("claim2", "value2");
    jwt.setClaim("claim3", "value3");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    EXPECT_TRUE(verified.hasClaim("claim1"));
    EXPECT_TRUE(verified.hasClaim("claim2"));
    EXPECT_TRUE(verified.hasClaim("claim3"));
    EXPECT_EQ("value1", verified.getClaim("claim1"));
    EXPECT_EQ("value2", verified.getClaim("claim2"));
    EXPECT_EQ("value3", verified.getClaim("claim3"));
}

TEST_F(JWTTest, HasClaimReturnsFalseForNonexistent)
{
    JWT jwt;
    jwt.setClaim("existing_claim", "value");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    EXPECT_TRUE(verified.hasClaim("existing_claim"));
    EXPECT_FALSE(verified.hasClaim("nonexistent_claim"));
}

// Algorithm tests
TEST_F(JWTTest, SignWithHS256)
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key, "HS256");

    JWT verified = JWT::verify(token, key);
    EXPECT_EQ("test", verified.getSubject());
}

TEST_F(JWTTest, SignWithHS512)
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateOct(512);
    std::string token = jwt.sign(key, "HS512");

    JWT verified = JWT::verify(token, key);
    EXPECT_EQ("test", verified.getSubject());
}

TEST_F(JWTTest, SignWithRS256)
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateRSA(2048);
    std::string token = jwt.sign(key, "RS256");

    JWT verified = JWT::verify(token, key);
    EXPECT_EQ("test", verified.getSubject());
}

TEST_F(JWTTest, SignWithRS512)
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateRSA(2048);
    std::string token = jwt.sign(key, "RS512");

    JWT verified = JWT::verify(token, key);
    EXPECT_EQ("test", verified.getSubject());
}

TEST_F(JWTTest, SignWithES256)
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateEC("P-256");
    std::string token = jwt.sign(key, "ES256");

    JWT verified = JWT::verify(token, key);
    EXPECT_EQ("test", verified.getSubject());
}

TEST_F(JWTTest, SignWithES384)
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateEC("P-384");
    std::string token = jwt.sign(key, "ES384");

    JWT verified = JWT::verify(token, key);
    EXPECT_EQ("test", verified.getSubject());
}

TEST_F(JWTTest, SignWithPS256)
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateRSA(2048);
    std::string token = jwt.sign(key, "PS256");

    JWT verified = JWT::verify(token, key);
    EXPECT_EQ("test", verified.getSubject());
}

TEST_F(JWTTest, DefaultAlgorithmIsRS256)
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateRSA(2048);
    std::string token = jwt.sign(key);  // No algorithm specified

    JWT verified = JWT::verify(token, key);
    EXPECT_EQ("test", verified.getSubject());
}

// Verification tests
TEST_F(JWTTest, VerifyValidToken)
{
    JWT jwt;
    jwt.setIssuer("issuer");
    jwt.setSubject("subject");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    EXPECT_EQ("issuer", verified.getIssuer());
    EXPECT_EQ("subject", verified.getSubject());
}

TEST_F(JWTTest, VerifyWithWrongKeyFails)
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key1 = JWK::generateOct(256);
    JWK key2 = JWK::generateOct(256);

    std::string token = jwt.sign(key1);

    EXPECT_THROW({ JWT::verify(token, key2); }, std::exception);
}

TEST_F(JWTTest, VerifyTamperedTokenFails)
{
    JWT jwt;
    jwt.setSubject("original");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    // Tamper with payload
    size_t firstDot = token.find('.');
    if (firstDot != std::string::npos && firstDot + 1 < token.length())
    {
        token[firstDot + 1] = (token[firstDot + 1] == 'A') ? 'B' : 'A';
    }

    EXPECT_THROW({ JWT::verify(token, key); }, std::exception);
}

TEST_F(JWTTest, ParseWithoutVerification)
{
    JWT jwt;
    jwt.setIssuer("issuer");
    jwt.setSubject("subject");
    jwt.setClaim("custom", "value");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    // Parse without verification
    JWT parsed = JWT::parse(token);
    EXPECT_EQ("issuer", parsed.getIssuer());
    EXPECT_EQ("subject", parsed.getSubject());
    EXPECT_EQ("value", parsed.getClaim("custom"));
}

// Validation tests
TEST_F(JWTTest, ValidateWithCorrectIssuer)
{
    JWT jwt;
    jwt.setIssuer("https://auth.example.com");
    jwt.setSubject("user123");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    bool valid = verified.validate("https://auth.example.com");
    EXPECT_TRUE(valid);
}

TEST_F(JWTTest, ValidateWithWrongIssuerFails)
{
    JWT jwt;
    jwt.setIssuer("https://auth.example.com");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    bool valid = verified.validate("https://wrong-issuer.com");
    EXPECT_FALSE(valid);
}

TEST_F(JWTTest, ValidateWithCorrectAudience)
{
    JWT jwt;
    jwt.setAudience("https://api.example.com");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    bool valid = verified.validate("", "https://api.example.com");
    EXPECT_TRUE(valid);
}

TEST_F(JWTTest, ValidateWithWrongAudienceFails)
{
    JWT jwt;
    jwt.setAudience("https://api.example.com");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    bool valid = verified.validate("", "https://wrong-api.com");
    EXPECT_FALSE(valid);
}

TEST_F(JWTTest, ValidateExpiredTokenFails)
{
    JWT jwt;
    auto pastTime = std::chrono::system_clock::now() - std::chrono::hours(1);
    jwt.setExpiration(pastTime);

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    bool valid = verified.validate();
    EXPECT_FALSE(valid);
}

TEST_F(JWTTest, ValidateNotYetValidTokenFails)
{
    JWT jwt;
    auto futureTime = std::chrono::system_clock::now() + std::chrono::hours(1);
    jwt.setNotBefore(futureTime);

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    bool valid = verified.validate();
    EXPECT_FALSE(valid);
}

TEST_F(JWTTest, ValidateWithLeeway)
{
    JWT jwt;
    // Token expired 30 seconds ago
    auto expiration = std::chrono::system_clock::now() - std::chrono::seconds(30);
    jwt.setExpiration(expiration);

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);

    // Should fail without leeway
    bool validWithoutLeeway = verified.validate("", "", 0);
    EXPECT_FALSE(validWithoutLeeway);

    // Should pass with 60 second leeway
    bool validWithLeeway = verified.validate("", "", 60);
    EXPECT_TRUE(validWithLeeway);
}

TEST_F(JWTTest, ValidateAllClaims)
{
    JWT jwt;
    jwt.setIssuer("https://auth.example.com");
    jwt.setAudience("https://api.example.com");
    auto now = std::chrono::system_clock::now();
    jwt.setExpiration(now + std::chrono::hours(1));
    jwt.setNotBefore(now - std::chrono::seconds(10));
    jwt.setIssuedAt(now);

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    bool valid = verified.validate("https://auth.example.com", "https://api.example.com", 10);
    EXPECT_TRUE(valid);
}

// Copy and move semantics
TEST_F(JWTTest, CopyConstructor)
{
    JWT original;
    original.setIssuer("issuer");
    original.setSubject("subject");

    JWT copy(original);
    EXPECT_EQ(original.getIssuer(), copy.getIssuer());
    EXPECT_EQ(original.getSubject(), copy.getSubject());
}

TEST_F(JWTTest, CopyAssignment)
{
    JWT original;
    original.setIssuer("issuer");
    original.setSubject("subject");

    JWT copy = original;
    EXPECT_EQ(original.getIssuer(), copy.getIssuer());
}

TEST_F(JWTTest, MoveConstructor)
{
    JWT original;
    original.setIssuer("issuer");
    original.setSubject("subject");
    std::string expectedIssuer = original.getIssuer();

    JWT moved(std::move(original));
    EXPECT_EQ(expectedIssuer, moved.getIssuer());
}

TEST_F(JWTTest, MoveAssignment)
{
    JWT original;
    original.setIssuer("issuer");
    std::string expectedIssuer = original.getIssuer();

    JWT moved = std::move(original);
    EXPECT_EQ(expectedIssuer, moved.getIssuer());
}

// Edge cases
TEST_F(JWTTest, EmptyClaimsJWT)
{
    JWT jwt;

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    EXPECT_FALSE(token.empty());

    JWT verified = JWT::verify(token, key);
    EXPECT_TRUE(verified.getIssuer().empty());
    EXPECT_TRUE(verified.getSubject().empty());
}

TEST_F(JWTTest, AllStandardClaims)
{
    JWT jwt;
    jwt.setIssuer("issuer");
    jwt.setSubject("subject");
    jwt.setAudience("audience");
    auto now = std::chrono::system_clock::now();
    jwt.setExpiration(now + std::chrono::hours(1));
    jwt.setNotBefore(now);
    jwt.setIssuedAt(now);
    jwt.setJwtId("jwt-id-123");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    EXPECT_EQ("issuer", verified.getIssuer());
    EXPECT_EQ("subject", verified.getSubject());
    EXPECT_EQ(1, verified.getAudience().size());
    EXPECT_EQ("jwt-id-123", verified.getJwtId());
}

TEST_F(JWTTest, ComplexCustomClaims)
{
    JWT jwt;
    jwt.setClaim("role", "admin");
    jwt.setClaim("permissions", "read,write,delete");
    jwt.setClaim("department", "engineering");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    EXPECT_EQ("admin", verified.getClaim("role"));
    EXPECT_EQ("read,write,delete", verified.getClaim("permissions"));
    EXPECT_EQ("engineering", verified.getClaim("department"));
}

TEST_F(JWTTest, RSAPublicKeyVerification)
{
    JWT jwt;
    jwt.setIssuer("issuer");
    jwt.setSubject("subject");

    JWK privateKey = JWK::generateRSA(2048);
    std::string token = jwt.sign(privateKey, "RS256");

    // Extract public key
    std::string publicKeyJson = privateKey.toJson(false);
    JWK publicKey = JWK::fromJson(publicKeyJson);

    JWT verified = JWT::verify(token, publicKey);
    EXPECT_EQ("issuer", verified.getIssuer());
    EXPECT_EQ("subject", verified.getSubject());
}

TEST_F(JWTTest, ECPublicKeyVerification)
{
    JWT jwt;
    jwt.setSubject("ec-subject");

    JWK privateKey = JWK::generateEC("P-256");
    std::string token = jwt.sign(privateKey, "ES256");

    std::string publicKeyJson = privateKey.toJson(false);
    JWK publicKey = JWK::fromJson(publicKeyJson);

    JWT verified = JWT::verify(token, publicKey);
    EXPECT_EQ("ec-subject", verified.getSubject());
}
