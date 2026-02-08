#include <gtest/gtest.h>

#include <string>

#include "jose/jose.hpp"

using namespace Vlinder::jose;

class JWKTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

// RSA key generation tests
TEST_F(JWKTest, GenerateRSA2048)
{
    JWK key = JWK::generateRSA(2048);
    EXPECT_EQ(JWK::KeyType::RSA, key.getKeyType());
    EXPECT_TRUE(key.hasPrivateKey());
}

TEST_F(JWKTest, GenerateRSA3072)
{
    JWK key = JWK::generateRSA(3072);
    EXPECT_EQ(JWK::KeyType::RSA, key.getKeyType());
    EXPECT_TRUE(key.hasPrivateKey());
}

TEST_F(JWKTest, GenerateRSA4096)
{
    JWK key = JWK::generateRSA(4096);
    EXPECT_EQ(JWK::KeyType::RSA, key.getKeyType());
    EXPECT_TRUE(key.hasPrivateKey());
}

TEST_F(JWKTest, GenerateRSADefault)
{
    JWK key = JWK::generateRSA();
    EXPECT_EQ(JWK::KeyType::RSA, key.getKeyType());
    EXPECT_TRUE(key.hasPrivateKey());
}

// EC key generation tests
TEST_F(JWKTest, GenerateECP256)
{
    JWK key = JWK::generateEC("P-256");
    EXPECT_EQ(JWK::KeyType::EC, key.getKeyType());
    EXPECT_TRUE(key.hasPrivateKey());
}

TEST_F(JWKTest, GenerateECP384)
{
    JWK key = JWK::generateEC("P-384");
    EXPECT_EQ(JWK::KeyType::EC, key.getKeyType());
    EXPECT_TRUE(key.hasPrivateKey());
}

TEST_F(JWKTest, GenerateECP521)
{
    JWK key = JWK::generateEC("P-521");
    EXPECT_EQ(JWK::KeyType::EC, key.getKeyType());
    EXPECT_TRUE(key.hasPrivateKey());
}

TEST_F(JWKTest, GenerateECDefault)
{
    JWK key = JWK::generateEC();
    EXPECT_EQ(JWK::KeyType::EC, key.getKeyType());
    EXPECT_TRUE(key.hasPrivateKey());
}

// Symmetric key generation tests
TEST_F(JWKTest, GenerateOct128)
{
    JWK key = JWK::generateOct(128);
    EXPECT_EQ(JWK::KeyType::oct, key.getKeyType());
    EXPECT_TRUE(key.hasPrivateKey());
}

TEST_F(JWKTest, GenerateOct192)
{
    JWK key = JWK::generateOct(192);
    EXPECT_EQ(JWK::KeyType::oct, key.getKeyType());
    EXPECT_TRUE(key.hasPrivateKey());
}

TEST_F(JWKTest, GenerateOct256)
{
    JWK key = JWK::generateOct(256);
    EXPECT_EQ(JWK::KeyType::oct, key.getKeyType());
    EXPECT_TRUE(key.hasPrivateKey());
}

TEST_F(JWKTest, GenerateOctDefault)
{
    JWK key = JWK::generateOct();
    EXPECT_EQ(JWK::KeyType::oct, key.getKeyType());
    EXPECT_TRUE(key.hasPrivateKey());
}

// Key properties tests
TEST_F(JWKTest, SetAndGetKeyId)
{
    JWK key = JWK::generateRSA(2048);
    key.setKeyId("my-key-id");
    EXPECT_EQ("my-key-id", key.getKeyId());
}

TEST_F(JWKTest, SetKeyIdWithSpecialChars)
{
    JWK key = JWK::generateEC("P-256");
    key.setKeyId("key-2024-01-01-v1.0");
    EXPECT_EQ("key-2024-01-01-v1.0", key.getKeyId());
}

TEST_F(JWKTest, SetUseSignature)
{
    JWK key = JWK::generateRSA(2048);
    key.setUse(JWK::Use::Signature);
    // No getter for use, but should not throw
}

TEST_F(JWKTest, SetUseEncryption)
{
    JWK key = JWK::generateRSA(2048);
    key.setUse(JWK::Use::Encryption);
    // No getter for use, but should not throw
}

TEST_F(JWKTest, SetAndGetAlgorithm)
{
    JWK key = JWK::generateRSA(2048);
    key.setAlgorithm("RS256");
    EXPECT_EQ("RS256", key.getAlgorithm());
}

TEST_F(JWKTest, SetMultipleAlgorithms)
{
    JWK rsaKey = JWK::generateRSA(2048);
    rsaKey.setAlgorithm("RS512");
    EXPECT_EQ("RS512", rsaKey.getAlgorithm());

    JWK ecKey = JWK::generateEC("P-256");
    ecKey.setAlgorithm("ES256");
    EXPECT_EQ("ES256", ecKey.getAlgorithm());

    JWK octKey = JWK::generateOct(256);
    octKey.setAlgorithm("HS256");
    EXPECT_EQ("HS256", octKey.getAlgorithm());
}

// Serialization tests
TEST_F(JWKTest, RSASerializeWithPrivate)
{
    JWK key = JWK::generateRSA(2048);
    key.setKeyId("rsa-key-1");
    key.setAlgorithm("RS256");

    std::string json = key.toJson(true);
    EXPECT_NE(std::string::npos, json.find("\"kty\""));
    EXPECT_NE(std::string::npos, json.find("\"RSA\""));
    EXPECT_NE(std::string::npos, json.find("\"kid\""));
    EXPECT_NE(std::string::npos, json.find("\"rsa-key-1\""));
    EXPECT_NE(std::string::npos, json.find("\"alg\""));
    EXPECT_NE(std::string::npos, json.find("\"RS256\""));
}

TEST_F(JWKTest, RSASerializeWithoutPrivate)
{
    JWK key = JWK::generateRSA(2048);
    key.setKeyId("rsa-public-key");

    std::string json = key.toJson(false);
    EXPECT_NE(std::string::npos, json.find("\"kty\""));
    EXPECT_NE(std::string::npos, json.find("\"RSA\""));
    EXPECT_NE(std::string::npos, json.find("\"kid\""));
    // Should not contain private key components
}

TEST_F(JWKTest, ECSerializeWithPrivate)
{
    JWK key = JWK::generateEC("P-256");
    key.setKeyId("ec-key-1");
    key.setAlgorithm("ES256");

    std::string json = key.toJson(true);
    EXPECT_NE(std::string::npos, json.find("\"kty\""));
    EXPECT_NE(std::string::npos, json.find("\"EC\""));
    EXPECT_NE(std::string::npos, json.find("\"crv\""));
    EXPECT_NE(std::string::npos, json.find("\"P-256\""));
}

TEST_F(JWKTest, OctSerialize)
{
    JWK key = JWK::generateOct(256);
    key.setKeyId("symmetric-key");
    key.setAlgorithm("HS256");

    std::string json = key.toJson(true);
    EXPECT_NE(std::string::npos, json.find("\"kty\""));
    EXPECT_NE(std::string::npos, json.find("\"oct\""));
    EXPECT_NE(std::string::npos, json.find("\"k\""));
}

// Parsing tests
TEST_F(JWKTest, ParseRSAKey)
{
    JWK original = JWK::generateRSA(2048);
    original.setKeyId("test-rsa");

    std::string json = original.toJson(true);
    JWK parsed = JWK::fromJson(json);

    EXPECT_EQ(JWK::KeyType::RSA, parsed.getKeyType());
    EXPECT_EQ("test-rsa", parsed.getKeyId());
    EXPECT_TRUE(parsed.hasPrivateKey());
}

TEST_F(JWKTest, ParseECKey)
{
    JWK original = JWK::generateEC("P-384");
    original.setKeyId("test-ec");
    original.setAlgorithm("ES384");

    std::string json = original.toJson(true);
    JWK parsed = JWK::fromJson(json);

    EXPECT_EQ(JWK::KeyType::EC, parsed.getKeyType());
    EXPECT_EQ("test-ec", parsed.getKeyId());
    EXPECT_EQ("ES384", parsed.getAlgorithm());
}

TEST_F(JWKTest, ParseOctKey)
{
    JWK original = JWK::generateOct(256);
    original.setKeyId("test-oct");

    std::string json = original.toJson(true);
    JWK parsed = JWK::fromJson(json);

    EXPECT_EQ(JWK::KeyType::oct, parsed.getKeyType());
    EXPECT_EQ("test-oct", parsed.getKeyId());
}

TEST_F(JWKTest, ParsePublicKeyOnly)
{
    JWK original = JWK::generateRSA(2048);
    original.setKeyId("public-only");

    std::string publicJson = original.toJson(false);
    JWK parsed = JWK::fromJson(publicJson);

    EXPECT_EQ(JWK::KeyType::RSA, parsed.getKeyType());
    EXPECT_EQ("public-only", parsed.getKeyId());
    EXPECT_FALSE(parsed.hasPrivateKey());
}

// Round-trip tests
TEST_F(JWKTest, RoundTripRSA)
{
    JWK original = JWK::generateRSA(2048);
    original.setKeyId("rsa-round-trip");
    original.setAlgorithm("RS256");
    original.setUse(JWK::Use::Signature);

    std::string json = original.toJson(true);
    JWK parsed = JWK::fromJson(json);

    EXPECT_EQ(original.getKeyType(), parsed.getKeyType());
    EXPECT_EQ(original.getKeyId(), parsed.getKeyId());
    EXPECT_EQ(original.getAlgorithm(), parsed.getAlgorithm());
    EXPECT_EQ(original.hasPrivateKey(), parsed.hasPrivateKey());
}

TEST_F(JWKTest, RoundTripEC)
{
    JWK original = JWK::generateEC("P-521");
    original.setKeyId("ec-round-trip");
    original.setAlgorithm("ES512");

    std::string json = original.toJson(true);
    JWK parsed = JWK::fromJson(json);

    EXPECT_EQ(original.getKeyType(), parsed.getKeyType());
    EXPECT_EQ(original.getKeyId(), parsed.getKeyId());
    EXPECT_EQ(original.getAlgorithm(), parsed.getAlgorithm());
}

TEST_F(JWKTest, RoundTripOct)
{
    JWK original = JWK::generateOct(256);
    original.setKeyId("oct-round-trip");
    original.setAlgorithm("HS256");

    std::string json = original.toJson(true);
    JWK parsed = JWK::fromJson(json);

    EXPECT_EQ(original.getKeyType(), parsed.getKeyType());
    EXPECT_EQ(original.getKeyId(), parsed.getKeyId());
    EXPECT_EQ(original.getAlgorithm(), parsed.getAlgorithm());
}

// Copy and move semantics
TEST_F(JWKTest, CopyConstructor)
{
    JWK original = JWK::generateRSA(2048);
    original.setKeyId("original");

    JWK copy(original);
    EXPECT_EQ(original.getKeyId(), copy.getKeyId());
    EXPECT_EQ(original.getKeyType(), copy.getKeyType());
}

TEST_F(JWKTest, CopyAssignment)
{
    JWK original = JWK::generateRSA(2048);
    original.setKeyId("original");

    JWK copy = original;
    EXPECT_EQ(original.getKeyId(), copy.getKeyId());
    EXPECT_EQ(original.getKeyType(), copy.getKeyType());
}

TEST_F(JWKTest, MoveConstructor)
{
    JWK original = JWK::generateRSA(2048);
    original.setKeyId("original");
    std::string expectedId = original.getKeyId();

    JWK moved(std::move(original));
    EXPECT_EQ(expectedId, moved.getKeyId());
}

TEST_F(JWKTest, MoveAssignment)
{
    JWK original = JWK::generateRSA(2048);
    original.setKeyId("original");
    std::string expectedId = original.getKeyId();

    JWK moved = std::move(original);
    EXPECT_EQ(expectedId, moved.getKeyId());
}

// JWKSet tests
TEST_F(JWKTest, JWKSetEmpty)
{
    JWKSet jwkSet;
    std::string json = jwkSet.toJson();
    EXPECT_NE(std::string::npos, json.find("\"keys\""));
}

TEST_F(JWKTest, JWKSetAddKey)
{
    JWKSet jwkSet;

    JWK key1 = JWK::generateRSA(2048);
    key1.setKeyId("key1");
    jwkSet.addKey(key1);

    JWK key2 = JWK::generateEC("P-256");
    key2.setKeyId("key2");
    jwkSet.addKey(key2);

    std::string json = jwkSet.toJson();
    EXPECT_NE(std::string::npos, json.find("\"key1\""));
    EXPECT_NE(std::string::npos, json.find("\"key2\""));
}

TEST_F(JWKTest, JWKSetGetKey)
{
    JWKSet jwkSet;

    JWK key1 = JWK::generateRSA(2048);
    key1.setKeyId("rsa-key");
    jwkSet.addKey(key1);

    JWK key2 = JWK::generateEC("P-256");
    key2.setKeyId("ec-key");
    jwkSet.addKey(key2);

    JWK retrieved = jwkSet.getKey("rsa-key");
    EXPECT_EQ("rsa-key", retrieved.getKeyId());
    EXPECT_EQ(JWK::KeyType::RSA, retrieved.getKeyType());

    JWK retrieved2 = jwkSet.getKey("ec-key");
    EXPECT_EQ("ec-key", retrieved2.getKeyId());
    EXPECT_EQ(JWK::KeyType::EC, retrieved2.getKeyType());
}

TEST_F(JWKTest, JWKSetGetKeys)
{
    JWKSet jwkSet;

    jwkSet.addKey(JWK::generateRSA(2048));
    jwkSet.addKey(JWK::generateEC("P-256"));
    jwkSet.addKey(JWK::generateOct(256));

    std::vector<JWK> keys = jwkSet.getKeys();
    EXPECT_EQ(3, keys.size());
}

TEST_F(JWKTest, JWKSetRoundTrip)
{
    JWKSet original;

    JWK key1 = JWK::generateRSA(2048);
    key1.setKeyId("key1");
    key1.setAlgorithm("RS256");
    original.addKey(key1);

    JWK key2 = JWK::generateEC("P-256");
    key2.setKeyId("key2");
    key2.setAlgorithm("ES256");
    original.addKey(key2);

    std::string json = original.toJson();
    JWKSet parsed = JWKSet::fromJson(json);

    JWK retrievedKey1 = parsed.getKey("key1");
    EXPECT_EQ("key1", retrievedKey1.getKeyId());
    EXPECT_EQ("RS256", retrievedKey1.getAlgorithm());

    JWK retrievedKey2 = parsed.getKey("key2");
    EXPECT_EQ("key2", retrievedKey2.getKeyId());
    EXPECT_EQ("ES256", retrievedKey2.getAlgorithm());
}

TEST_F(JWKTest, JWKSetMultipleKeysOfSameType)
{
    JWKSet jwkSet;

    for (int i = 0; i < 5; i++)
    {
        JWK key = JWK::generateRSA(2048);
        key.setKeyId("rsa-key-" + std::to_string(i));
        jwkSet.addKey(key);
    }

    std::vector<JWK> keys = jwkSet.getKeys();
    EXPECT_EQ(5, keys.size());

    JWK retrieved = jwkSet.getKey("rsa-key-3");
    EXPECT_EQ("rsa-key-3", retrieved.getKeyId());
}

// Edge cases
TEST_F(JWKTest, EmptyKeyId)
{
    JWK key = JWK::generateRSA(2048);
    key.setKeyId("");
    EXPECT_EQ("", key.getKeyId());
}

TEST_F(JWKTest, LongKeyId)
{
    JWK key = JWK::generateEC("P-256");
    std::string longId(1000, 'a');
    key.setKeyId(longId);
    EXPECT_EQ(longId, key.getKeyId());
}

TEST_F(JWKTest, SpecialCharsInKeyId)
{
    JWK key = JWK::generateOct(256);
    key.setKeyId("key-with-dashes_and_underscores.and.dots");
    EXPECT_EQ("key-with-dashes_and_underscores.and.dots", key.getKeyId());
}

TEST_F(JWKTest, MultiplePropertiesSet)
{
    JWK key = JWK::generateRSA(2048);
    key.setKeyId("multi-prop-key");
    key.setAlgorithm("RS384");
    key.setUse(JWK::Use::Signature);

    EXPECT_EQ("multi-prop-key", key.getKeyId());
    EXPECT_EQ("RS384", key.getAlgorithm());

    std::string json = key.toJson(true);
    EXPECT_NE(std::string::npos, json.find("\"multi-prop-key\""));
    EXPECT_NE(std::string::npos, json.find("\"RS384\""));
}
