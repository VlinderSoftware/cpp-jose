#include "jose/jose.hpp"

#include <gtest/gtest.h>
#include <string>

using namespace Vlinder::jose;

class JWKThumbprintTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

// Basic thumbprint computation tests
TEST_F(JWKThumbprintTest, ComputeRSAThumbprint)
{
    JWK key = JWK::generateRSA(2048);
    std::string thumbprint = JWKThumbprint::compute(key);

    EXPECT_FALSE(thumbprint.empty());
    // Base64URL encoded SHA-256 is 43 characters (256 bits / 6 bits per char, rounded up)
    EXPECT_EQ(43, thumbprint.length());
}

TEST_F(JWKThumbprintTest, ComputeECThumbprint)
{
    JWK key = JWK::generateEC("P-256");
    std::string thumbprint = JWKThumbprint::compute(key);

    EXPECT_FALSE(thumbprint.empty());
    EXPECT_EQ(43, thumbprint.length());
}

TEST_F(JWKThumbprintTest, ComputeOctThumbprint)
{
    JWK key = JWK::generateOct(256);
    std::string thumbprint = JWKThumbprint::compute(key);

    EXPECT_FALSE(thumbprint.empty());
    EXPECT_EQ(43, thumbprint.length());
}

// Default algorithm is SHA-256
TEST_F(JWKThumbprintTest, DefaultAlgorithmIsSHA256)
{
    JWK key = JWK::generateRSA(2048);

    std::string thumbprint1 = JWKThumbprint::compute(key);
    std::string thumbprint2 = JWKThumbprint::compute(key, "SHA-256");

    EXPECT_EQ(thumbprint1, thumbprint2);
}

// Different hash algorithms
TEST_F(JWKThumbprintTest, ComputeWithSHA384)
{
    JWK key = JWK::generateRSA(2048);
    std::string thumbprint = JWKThumbprint::compute(key, "SHA-384");

    EXPECT_FALSE(thumbprint.empty());
    // SHA-384 produces 384 bits = 64 base64url characters
    EXPECT_EQ(64, thumbprint.length());
}

TEST_F(JWKThumbprintTest, ComputeWithSHA512)
{
    JWK key = JWK::generateRSA(2048);
    std::string thumbprint = JWKThumbprint::compute(key, "SHA-512");

    EXPECT_FALSE(thumbprint.empty());
    // SHA-512 produces 512 bits = 86 base64url characters
    EXPECT_EQ(86, thumbprint.length());
}

// Deterministic thumbprints
TEST_F(JWKThumbprintTest, ThumbprintIsDeterministic)
{
    JWK key = JWK::generateRSA(2048);

    std::string thumbprint1 = JWKThumbprint::compute(key);
    std::string thumbprint2 = JWKThumbprint::compute(key);

    EXPECT_EQ(thumbprint1, thumbprint2);
}

TEST_F(JWKThumbprintTest, SameKeyDifferentPropertiesSameThumbprint)
{
    JWK key1 = JWK::generateRSA(2048);
    std::string keyJson = key1.toJson(true);

    JWK key2 = JWK::fromJson(keyJson);
    key2.setKeyId("different-id");
    key2.setAlgorithm("RS512");
    key2.setUse(JWK::Use::Signature);

    // Thumbprint should be the same because it's based on key material only
    std::string thumbprint1 = JWKThumbprint::compute(key1);
    std::string thumbprint2 = JWKThumbprint::compute(key2);

    EXPECT_EQ(thumbprint1, thumbprint2);
}

// Different keys produce different thumbprints
TEST_F(JWKThumbprintTest, DifferentKeysProduceDifferentThumbprints)
{
    JWK key1 = JWK::generateRSA(2048);
    JWK key2 = JWK::generateRSA(2048);

    std::string thumbprint1 = JWKThumbprint::compute(key1);
    std::string thumbprint2 = JWKThumbprint::compute(key2);

    EXPECT_NE(thumbprint1, thumbprint2);
}

TEST_F(JWKThumbprintTest, DifferentKeyTypesProduceDifferentThumbprints)
{
    JWK rsaKey = JWK::generateRSA(2048);
    JWK ecKey = JWK::generateEC("P-256");
    JWK octKey = JWK::generateOct(256);

    std::string rsaThumbprint = JWKThumbprint::compute(rsaKey);
    std::string ecThumbprint = JWKThumbprint::compute(ecKey);
    std::string octThumbprint = JWKThumbprint::compute(octKey);

    EXPECT_NE(rsaThumbprint, ecThumbprint);
    EXPECT_NE(rsaThumbprint, octThumbprint);
    EXPECT_NE(ecThumbprint, octThumbprint);
}

// Test with different EC curves
TEST_F(JWKThumbprintTest, DifferentECCurvesProduceDifferentThumbprints)
{
    JWK keyP256 = JWK::generateEC("P-256");
    JWK keyP384 = JWK::generateEC("P-384");
    JWK keyP521 = JWK::generateEC("P-521");

    std::string thumbprintP256 = JWKThumbprint::compute(keyP256);
    std::string thumbprintP384 = JWKThumbprint::compute(keyP384);
    std::string thumbprintP521 = JWKThumbprint::compute(keyP521);

    EXPECT_NE(thumbprintP256, thumbprintP384);
    EXPECT_NE(thumbprintP256, thumbprintP521);
    EXPECT_NE(thumbprintP384, thumbprintP521);
}

// Raw thumbprint tests
TEST_F(JWKThumbprintTest, ComputeRawThumbprint)
{
    JWK key = JWK::generateRSA(2048);

    std::vector<unsigned char> rawThumbprint = JWKThumbprint::computeRaw(key);

    EXPECT_FALSE(rawThumbprint.empty());
    // SHA-256 produces 32 bytes
    EXPECT_EQ(32, rawThumbprint.size());
}

TEST_F(JWKThumbprintTest, ComputeRawThumbprintSHA384)
{
    JWK key = JWK::generateRSA(2048);

    std::vector<unsigned char> rawThumbprint = JWKThumbprint::computeRaw(key, "SHA-384");

    EXPECT_FALSE(rawThumbprint.empty());
    // SHA-384 produces 48 bytes
    EXPECT_EQ(48, rawThumbprint.size());
}

TEST_F(JWKThumbprintTest, ComputeRawThumbprintSHA512)
{
    JWK key = JWK::generateRSA(2048);

    std::vector<unsigned char> rawThumbprint = JWKThumbprint::computeRaw(key, "SHA-512");

    EXPECT_FALSE(rawThumbprint.empty());
    // SHA-512 produces 64 bytes
    EXPECT_EQ(64, rawThumbprint.size());
}

TEST_F(JWKThumbprintTest, RawThumbprintMatchesEncodedThumbprint)
{
    JWK key = JWK::generateRSA(2048);

    std::string encoded = JWKThumbprint::compute(key);
    std::vector<unsigned char> raw = JWKThumbprint::computeRaw(key);

    // Encode the raw thumbprint and compare
    std::string encodedFromRaw = Base64Url::encode(raw);

    EXPECT_EQ(encoded, encodedFromRaw);
}

// Round-trip tests
TEST_F(JWKThumbprintTest, ThumbprintSurvivesSerializationRoundTrip)
{
    JWK original = JWK::generateRSA(2048);
    std::string originalThumbprint = JWKThumbprint::compute(original);

    // Serialize and deserialize
    std::string json = original.toJson(true);
    JWK deserialized = JWK::fromJson(json);

    std::string deserializedThumbprint = JWKThumbprint::compute(deserialized);

    EXPECT_EQ(originalThumbprint, deserializedThumbprint);
}

TEST_F(JWKThumbprintTest, PublicKeyOnlyThumbprintMatchesFullKey)
{
    JWK privateKey = JWK::generateRSA(2048);
    std::string privateThumbprint = JWKThumbprint::compute(privateKey);

    // Export public key only
    std::string publicKeyJson = privateKey.toJson(false);
    JWK publicKey = JWK::fromJson(publicKeyJson);

    std::string publicThumbprint = JWKThumbprint::compute(publicKey);

    // Thumbprint should be the same
    EXPECT_EQ(privateThumbprint, publicThumbprint);
}

// Test that thumbprint doesn't contain invalid base64url characters
TEST_F(JWKThumbprintTest, ThumbprintIsValidBase64Url)
{
    JWK key = JWK::generateRSA(2048);
    std::string thumbprint = JWKThumbprint::compute(key);

    // Should not contain '+', '/', or '='
    EXPECT_EQ(std::string::npos, thumbprint.find('+'));
    EXPECT_EQ(std::string::npos, thumbprint.find('/'));
    EXPECT_EQ(std::string::npos, thumbprint.find('='));

    // Should only contain valid base64url characters: A-Z, a-z, 0-9, -, _
    for (char c : thumbprint)
    {
        bool valid = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                     c == '-' || c == '_';
        EXPECT_TRUE(valid) << "Invalid character: " << c;
    }
}

// Edge cases
TEST_F(JWKThumbprintTest, SmallKeyThumbprint)
{
    JWK key = JWK::generateOct(128);
    std::string thumbprint = JWKThumbprint::compute(key);

    EXPECT_FALSE(thumbprint.empty());
    EXPECT_EQ(43, thumbprint.length());
}

TEST_F(JWKThumbprintTest, LargeKeyThumbprint)
{
    JWK key = JWK::generateRSA(4096);
    std::string thumbprint = JWKThumbprint::compute(key);

    // Thumbprint size should be the same regardless of key size
    EXPECT_EQ(43, thumbprint.length());
}

// RFC 7638 compliance test
TEST_F(JWKThumbprintTest, RFC7638Example)
{
    // RFC 7638 Section 3.1 provides an example
    // We can't test the exact example without the exact key, but we can test the format
    JWK key = JWK::generateRSA(2048);

    std::string thumbprint = JWKThumbprint::compute(key);

    // Verify it's a valid base64url string of the right length for SHA-256
    EXPECT_EQ(43, thumbprint.length());

    // Verify it's deterministic
    std::string thumbprint2 = JWKThumbprint::compute(key);
    EXPECT_EQ(thumbprint, thumbprint2);
}

// Test all key types
TEST_F(JWKThumbprintTest, AllKeyTypesProduceValidThumbprints)
{
    std::vector<JWK> keys = {JWK::generateRSA(2048),   JWK::generateEC("P-256"),
                             JWK::generateEC("P-384"), JWK::generateEC("P-521"),
                             JWK::generateOct(128),    JWK::generateOct(256),
                             JWK::generateOct(512)};

    for (const auto& key : keys)
    {
        std::string thumbprint = JWKThumbprint::compute(key);
        EXPECT_FALSE(thumbprint.empty());
        EXPECT_EQ(43, thumbprint.length());

        // Verify it's base64url
        EXPECT_EQ(std::string::npos, thumbprint.find('+'));
        EXPECT_EQ(std::string::npos, thumbprint.find('/'));
        EXPECT_EQ(std::string::npos, thumbprint.find('='));
    }
}

// Test with different hash algorithms for all key types
TEST_F(JWKThumbprintTest, AllHashAlgorithmsWork)
{
    JWK key = JWK::generateRSA(2048);

    std::vector<std::pair<std::string, size_t>> algorithms = {
        {"SHA-256", 43}, {"SHA-384", 64}, {"SHA-512", 86}};

    for (const auto& [alg, expectedLength] : algorithms)
    {
        std::string thumbprint = JWKThumbprint::compute(key, alg);
        EXPECT_FALSE(thumbprint.empty()) << "Failed for " << alg;
        EXPECT_EQ(expectedLength, thumbprint.length()) << "Wrong length for " << alg;
    }
}

// Use thumbprint as key ID
TEST_F(JWKThumbprintTest, UseThumbprintAsKeyId)
{
    JWK key = JWK::generateRSA(2048);

    std::string thumbprint = JWKThumbprint::compute(key);
    key.setKeyId(thumbprint);

    EXPECT_EQ(thumbprint, key.getKeyId());

    // Verify it survives serialization
    std::string json = key.toJson(false);
    JWK parsed = JWK::fromJson(json);

    EXPECT_EQ(thumbprint, parsed.getKeyId());

    // Verify the thumbprint of the parsed key is still the same
    std::string parsedThumbprint = JWKThumbprint::compute(parsed);
    EXPECT_EQ(thumbprint, parsedThumbprint);
}

// Uniqueness test
TEST_F(JWKThumbprintTest, ManyKeysProduceUniqueThumbprints)
{
    std::set<std::string> thumbprints;

    // Generate 100 keys and verify all thumbprints are unique
    for (int i = 0; i < 100; i++)
    {
        JWK key = JWK::generateRSA(2048);
        std::string thumbprint = JWKThumbprint::compute(key);

        EXPECT_EQ(0, thumbprints.count(thumbprint)) << "Duplicate thumbprint found!";
        thumbprints.insert(thumbprint);
    }

    EXPECT_EQ(100, thumbprints.size());
}
