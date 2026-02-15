#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <thread>

#include "jose/jose.hpp"

using namespace Vlinder::JOSE;


// Basic JWT creation tests
TEST_CASE("JWT_CreateSimpleJWT", "[jwt][createsimplejwt]")
{
    JWT jwt;
    jwt.setIssuer("test-issuer");
    jwt.setSubject("user123");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key, "HS256");

    REQUIRE_FALSE(token.empty());

    // JWT should have 3 parts
    size_t firstDot = token.find('.');
    size_t secondDot = token.find('.', firstDot + 1);
    REQUIRE(std::string::npos != firstDot);
    REQUIRE(std::string::npos != secondDot);
}

TEST_CASE("JWT_SetAndGetIssuer", "[jwt][setandgetissuer]")
{
    JWT jwt;
    jwt.setIssuer("https://example.com");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    REQUIRE("https://example.com" == verified.getIssuer());
}

TEST_CASE("JWT_SetAndGetSubject", "[jwt][setandgetsubject]")
{
    JWT jwt;
    jwt.setSubject("user@example.com");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    REQUIRE("user@example.com" == verified.getSubject());
}

TEST_CASE("JWT_SetAndGetAudienceSingle", "[jwt][setandgetaudiencesingle]")
{
    JWT jwt;
    jwt.setAudience("https://api.example.com");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    std::vector<std::string> audience = verified.getAudience();
    REQUIRE(1 == audience.size());
    REQUIRE("https://api.example.com" == audience[0]);
}

TEST_CASE("JWT_SetAndGetAudienceMultiple", "[jwt][setandgetaudiencemultiple]")
{
    JWT jwt;
    std::vector<std::string> audiences = {"audience1", "audience2", "audience3"};
    jwt.setAudience(audiences);

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    std::vector<std::string> retrievedAudiences = verified.getAudience();
    REQUIRE(3 == retrievedAudiences.size());
    REQUIRE("audience1" == retrievedAudiences[0]);
    REQUIRE("audience2" == retrievedAudiences[1]);
    REQUIRE("audience3" == retrievedAudiences[2]);
}

TEST_CASE("JWT_SetAndGetExpiration", "[jwt][setandgetexpiration]")
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
    REQUIRE(diff <= std::chrono::seconds(1));
}

TEST_CASE("JWT_SetAndGetNotBefore", "[jwt][setandgetnotbefore]")
{
    JWT jwt;
    auto now = std::chrono::system_clock::now();
    jwt.setNotBefore(now);

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    auto retrievedNbf = verified.getNotBefore();

    auto diff = std::chrono::abs(now - retrievedNbf);
    REQUIRE(diff <= std::chrono::seconds(1));
}

TEST_CASE("JWT_SetAndGetIssuedAt", "[jwt][setandgetissuedat]")
{
    JWT jwt;
    auto now = std::chrono::system_clock::now();
    jwt.setIssuedAt(now);

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    auto retrievedIat = verified.getIssuedAt();

    auto diff = std::chrono::abs(now - retrievedIat);
    REQUIRE(diff <= std::chrono::seconds(1));
}

TEST_CASE("JWT_SetAndGetJwtId", "[jwt][setandgetjwtid]")
{
    JWT jwt;
    jwt.setJWTID("unique-jwt-id-12345");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    REQUIRE("unique-jwt-id-12345" == verified.getJWTID());
}

TEST_CASE("JWT_SetAndGetCustomClaim", "[jwt][setandgetcustomclaim]")
{
    JWT jwt;
    jwt.setClaim("custom_claim", "custom_value");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    REQUIRE(verified.hasClaim("custom_claim"));
    REQUIRE("custom_value" == verified.getClaim("custom_claim"));
}

TEST_CASE("JWT_MultipleCustomClaims", "[jwt][multiplecustomclaims]")
{
    JWT jwt;
    jwt.setClaim("claim1", "value1");
    jwt.setClaim("claim2", "value2");
    jwt.setClaim("claim3", "value3");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    REQUIRE(verified.hasClaim("claim1"));
    REQUIRE(verified.hasClaim("claim2"));
    REQUIRE(verified.hasClaim("claim3"));
    REQUIRE("value1" == verified.getClaim("claim1"));
    REQUIRE("value2" == verified.getClaim("claim2"));
    REQUIRE("value3" == verified.getClaim("claim3"));
}

TEST_CASE("JWT_HasClaimReturnsFalseForNonexistent", "[jwt][hasclaimreturnsfalsefornonexistent]")
{
    JWT jwt;
    jwt.setClaim("existing_claim", "value");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    REQUIRE(verified.hasClaim("existing_claim"));
    REQUIRE_FALSE(verified.hasClaim("nonexistent_claim"));
}

// Algorithm tests
TEST_CASE("JWT_SignWithHS256", "[jwt][signwithhs256]")
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key, "HS256");

    JWT verified = JWT::verify(token, key);
    REQUIRE("test" == verified.getSubject());
}

TEST_CASE("JWT_SignWithHS512", "[jwt][signwithhs512]")
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateOct(512);
    std::string token = jwt.sign(key, "HS512");

    JWT verified = JWT::verify(token, key);
    REQUIRE("test" == verified.getSubject());
}

TEST_CASE("JWT_SignWithRS256", "[jwt][signwithrs256]")
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateRSA(2048);
    std::string token = jwt.sign(key, "RS256");

    JWT verified = JWT::verify(token, key);
    REQUIRE("test" == verified.getSubject());
}

TEST_CASE("JWT_SignWithRS512", "[jwt][signwithrs512]")
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateRSA(2048);
    std::string token = jwt.sign(key, "RS512");

    JWT verified = JWT::verify(token, key);
    REQUIRE("test" == verified.getSubject());
}

TEST_CASE("JWT_SignWithES256", "[jwt][signwithes256]")
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateEC("P-256");
    std::string token = jwt.sign(key, "ES256");

    JWT verified = JWT::verify(token, key);
    REQUIRE("test" == verified.getSubject());
}

TEST_CASE("JWT_SignWithES384", "[jwt][signwithes384]")
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateEC("P-384");
    std::string token = jwt.sign(key, "ES384");

    JWT verified = JWT::verify(token, key);
    REQUIRE("test" == verified.getSubject());
}

TEST_CASE("JWT_SignWithPS256", "[jwt][signwithps256]")
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateRSA(2048);
    std::string token = jwt.sign(key, "PS256");

    JWT verified = JWT::verify(token, key);
    REQUIRE("test" == verified.getSubject());
}

TEST_CASE("JWT_DefaultAlgorithmIsRS256", "[jwt][defaultalgorithmisrs256]")
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key = JWK::generateRSA(2048);
    std::string token = jwt.sign(key);  // No algorithm specified

    JWT verified = JWT::verify(token, key);
    REQUIRE("test" == verified.getSubject());
}

// Verification tests
TEST_CASE("JWT_VerifyValidToken", "[jwt][verifyvalidtoken]")
{
    JWT jwt;
    jwt.setIssuer("issuer");
    jwt.setSubject("subject");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    REQUIRE("issuer" == verified.getIssuer());
    REQUIRE("subject" == verified.getSubject());
}

TEST_CASE("JWT_VerifyWithWrongKeyFails", "[jwt][verifywithwrongkeyfails]")
{
    JWT jwt;
    jwt.setSubject("test");

    JWK key1 = JWK::generateOct(256);
    JWK key2 = JWK::generateOct(256);

    std::string token = jwt.sign(key1);

    REQUIRE_THROWS_AS(JWT::verify(token, key2), std::exception);
}

TEST_CASE("JWT_VerifyTamperedTokenFails", "[jwt][verifytamperedtokenfails]")
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

    REQUIRE_THROWS_AS(JWT::verify(token, key), std::exception);
}

TEST_CASE("JWT_ParseWithoutVerification", "[jwt][parsewithoutverification]")
{
    JWT jwt;
    jwt.setIssuer("issuer");
    jwt.setSubject("subject");
    jwt.setClaim("custom", "value");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    // Parse without verification
    JWT parsed = JWT::parse(token);
    REQUIRE("issuer" == parsed.getIssuer());
    REQUIRE("subject" == parsed.getSubject());
    REQUIRE("value" == parsed.getClaim("custom"));
}

// Validation tests
TEST_CASE("JWT_ValidateWithCorrectIssuer", "[jwt][validatewithcorrectissuer]")
{
    JWT jwt;
    jwt.setIssuer("https://auth.example.com");
    jwt.setSubject("user123");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    bool valid = verified.validate("https://auth.example.com");
    REQUIRE(valid);
}

TEST_CASE("JWT_ValidateWithWrongIssuerFails", "[jwt][validatewithwrongissuerfails]")
{
    JWT jwt;
    jwt.setIssuer("https://auth.example.com");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    bool valid = verified.validate("https://wrong-issuer.com");
    REQUIRE_FALSE(valid);
}

TEST_CASE("JWT_ValidateWithCorrectAudience", "[jwt][validatewithcorrectaudience]")
{
    JWT jwt;
    jwt.setAudience("https://api.example.com");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    bool valid = verified.validate("", "https://api.example.com");
    REQUIRE(valid);
}

TEST_CASE("JWT_ValidateWithWrongAudienceFails", "[jwt][validatewithwrongaudiencefails]")
{
    JWT jwt;
    jwt.setAudience("https://api.example.com");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    bool valid = verified.validate("", "https://wrong-api.com");
    REQUIRE_FALSE(valid);
}

TEST_CASE("JWT_ValidateExpiredTokenFails", "[jwt][validateexpiredtokenfails]")
{
    JWT jwt;
    auto pastTime = std::chrono::system_clock::now() - std::chrono::hours(1);
    jwt.setExpiration(pastTime);

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    bool valid = verified.validate();
    REQUIRE_FALSE(valid);
}

TEST_CASE("JWT_ValidateNotYetValidTokenFails", "[jwt][validatenotyetvalidtokenfails]")
{
    JWT jwt;
    auto futureTime = std::chrono::system_clock::now() + std::chrono::hours(1);
    jwt.setNotBefore(futureTime);

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    bool valid = verified.validate();
    REQUIRE_FALSE(valid);
}

TEST_CASE("JWT_ValidateWithLeeway", "[jwt][validatewithleeway]")
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
    REQUIRE_FALSE(validWithoutLeeway);

    // Should pass with 60 second leeway
    bool validWithLeeway = verified.validate("", "", 60);
    REQUIRE(validWithLeeway);
}

TEST_CASE("JWT_ValidateAllClaims", "[jwt][validateallclaims]")
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
    REQUIRE(valid);
}

// Copy and move semantics
TEST_CASE("JWT_CopyConstructor", "[jwt][copyconstructor]")
{
    JWT original;
    original.setIssuer("issuer");
    original.setSubject("subject");

    JWT copy(original);
    REQUIRE(original.getIssuer() == copy.getIssuer());
    REQUIRE(original.getSubject() == copy.getSubject());
}

TEST_CASE("JWT_CopyAssignment", "[jwt][copyassignment]")
{
    JWT original;
    original.setIssuer("issuer");
    original.setSubject("subject");

    JWT copy = original;
    REQUIRE(original.getIssuer() == copy.getIssuer());
}

TEST_CASE("JWT_MoveConstructor", "[jwt][moveconstructor]")
{
    JWT original;
    original.setIssuer("issuer");
    original.setSubject("subject");
    std::string expectedIssuer = original.getIssuer();

    JWT moved(std::move(original));
    REQUIRE(expectedIssuer == moved.getIssuer());
}

TEST_CASE("JWT_MoveAssignment", "[jwt][moveassignment]")
{
    JWT original;
    original.setIssuer("issuer");
    std::string expectedIssuer = original.getIssuer();

    JWT moved = std::move(original);
    REQUIRE(expectedIssuer == moved.getIssuer());
}

// Edge cases
TEST_CASE("JWT_EmptyClaimsJWT", "[jwt][emptyclaimsjwt]")
{
    JWT jwt;

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    REQUIRE_FALSE(token.empty());

    JWT verified = JWT::verify(token, key);
    REQUIRE(verified.getIssuer().empty());
    REQUIRE(verified.getSubject().empty());
}

TEST_CASE("JWT_AllStandardClaims", "[jwt][allstandardclaims]")
{
    JWT jwt;
    jwt.setIssuer("issuer");
    jwt.setSubject("subject");
    jwt.setAudience("audience");
    auto now = std::chrono::system_clock::now();
    jwt.setExpiration(now + std::chrono::hours(1));
    jwt.setNotBefore(now);
    jwt.setIssuedAt(now);
    jwt.setJWTID("jwt-id-123");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    REQUIRE("issuer" == verified.getIssuer());
    REQUIRE("subject" == verified.getSubject());
    REQUIRE(1 == verified.getAudience().size());
    REQUIRE("jwt-id-123" == verified.getJWTID());
}

TEST_CASE("JWT_ComplexCustomClaims", "[jwt][complexcustomclaims]")
{
    JWT jwt;
    jwt.setClaim("role", "admin");
    jwt.setClaim("permissions", "read,write,delete");
    jwt.setClaim("department", "engineering");

    JWK key = JWK::generateOct(256);
    std::string token = jwt.sign(key);

    JWT verified = JWT::verify(token, key);
    REQUIRE("admin" == verified.getClaim("role"));
    REQUIRE(verified.getClaim("permissions") == "read,write,delete");
    REQUIRE("engineering" == verified.getClaim("department"));
}

TEST_CASE("JWT_RSAPublicKeyVerification", "[jwt][rsapublickeyverification]")
{
    JWT jwt;
    jwt.setIssuer("issuer");
    jwt.setSubject("subject");

    JWK privateKey = JWK::generateRSA(2048);
    std::string token = jwt.sign(privateKey, "RS256");

    // Extract public key
    std::string publicKeyJson = privateKey.toJSON(false);
    JWK publicKey = JWK::fromJSON(publicKeyJson);

    JWT verified = JWT::verify(token, publicKey);
    REQUIRE("issuer" == verified.getIssuer());
    REQUIRE("subject" == verified.getSubject());
}

TEST_CASE("JWT_ECPublicKeyVerification", "[jwt][ecpublickeyverification]")
{
    JWT jwt;
    jwt.setSubject("ec-subject");

    JWK privateKey = JWK::generateEC("P-256");
    std::string token = jwt.sign(privateKey, "ES256");

    std::string publicKeyJson = privateKey.toJSON(false);
    JWK publicKey = JWK::fromJSON(publicKeyJson);

    JWT verified = JWT::verify(token, publicKey);
    REQUIRE("ec-subject" == verified.getSubject());
}
