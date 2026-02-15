#include <catch2/catch_test_macros.hpp>

#include <string>

#include "jose/jose.hpp"

using namespace Vlinder::JOSE;

// BDD-style tests for RSA key generation
SCENARIO("RSA keys can be generated with different bit sizes", "[jwk][rsa][generation][bdd]")
{
    GIVEN("no specific requirements")
    {
        WHEN("generating a default RSA key")
        {
            JWK key = JWK::generateRSA();
            
            THEN("it should be an RSA key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::rsa);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
    
    GIVEN("a requirement for 2048-bit RSA")
    {
        WHEN("generating a 2048-bit RSA key")
        {
            JWK key = JWK::generateRSA(2048);
            
            THEN("it should be an RSA key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::rsa);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
    
    GIVEN("a requirement for 3072-bit RSA")
    {
        WHEN("generating a 3072-bit RSA key")
        {
            JWK key = JWK::generateRSA(3072);
            
            THEN("it should be an RSA key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::rsa);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
    
    GIVEN("a requirement for 4096-bit RSA")
    {
        WHEN("generating a 4096-bit RSA key")
        {
            JWK key = JWK::generateRSA(4096);
            
            THEN("it should be an RSA key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::rsa);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
}

// BDD-style tests for EC key generation
SCENARIO("Elliptic curve keys can be generated with different curves", "[jwk][ec][generation][bdd]")
{
    GIVEN("no specific curve requirement")
    {
        WHEN("generating a default EC key")
        {
            JWK key = JWK::generateEC();
            
            THEN("it should be an EC key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::ec);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
    
    GIVEN("a requirement for P-256 curve")
    {
        WHEN("generating a P-256 EC key")
        {
            JWK key = JWK::generateEC("P-256");
            
            THEN("it should be an EC key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::ec);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
    
    GIVEN("a requirement for P-384 curve")
    {
        WHEN("generating a P-384 EC key")
        {
            JWK key = JWK::generateEC("P-384");
            
            THEN("it should be an EC key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::ec);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
    
    GIVEN("a requirement for P-521 curve")
    {
        WHEN("generating a P-521 EC key")
        {
            JWK key = JWK::generateEC("P-521");
            
            THEN("it should be an EC key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::ec);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
}

// BDD-style tests for symmetric key generation
SCENARIO("Symmetric keys can be generated with different bit sizes", "[jwk][oct][generation][bdd]")
{
    GIVEN("no specific requirements")
    {
        WHEN("generating a default symmetric key")
        {
            JWK key = JWK::generateOct();
            
            THEN("it should be an octet key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::oct);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
    
    GIVEN("a requirement for 128-bit key")
    {
        WHEN("generating a 128-bit symmetric key")
        {
            JWK key = JWK::generateOct(128);
            
            THEN("it should be an octet key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::oct);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
    
    GIVEN("a requirement for 192-bit key")
    {
        WHEN("generating a 192-bit symmetric key")
        {
            JWK key = JWK::generateOct(192);
            
            THEN("it should be an octet key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::oct);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
    
    GIVEN("a requirement for 256-bit key")
    {
        WHEN("generating a 256-bit symmetric key")
        {
            JWK key = JWK::generateOct(256);
            
            THEN("it should be an octet key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::oct);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
}

// BDD-style tests for key properties
SCENARIO("JWK properties can be set and retrieved", "[jwk][properties][bdd]")
{
    GIVEN("a generated RSA key")
    {
        JWK key = JWK::generateRSA(2048);
        
        WHEN("setting a key ID")
        {
            key.setKeyID("my-key-id");
            
            THEN("the key ID can be retrieved")
            {
                REQUIRE(key.getKeyID() == "my-key-id");
            }
        }
        
        WHEN("setting a key ID with special characters")
        {
            key.setKeyID("key-2024-01-01-v1.0");
            
            THEN("the special characters are preserved")
            {
                REQUIRE(key.getKeyID() == "key-2024-01-01-v1.0");
            }
        }
        
        WHEN("setting an algorithm")
        {
            key.setAlgorithm("RS256");
            
            THEN("the algorithm can be retrieved")
            {
                REQUIRE(key.getAlgorithm() == "RS256");
            }
        }
        
        WHEN("setting the use to signature")
        {
            THEN("it should not throw")
            {
                REQUIRE_NOTHROW(key.setUse(JWK::Use::signature));
            }
        }
        
        WHEN("setting the use to encryption")
        {
            THEN("it should not throw")
            {
                REQUIRE_NOTHROW(key.setUse(JWK::Use::encryption));
            }
        }
    }
}

TEST_CASE("Different key types support different algorithms", "[jwk][properties]")
{
    JWK rsaKey = JWK::generateRSA(2048);
    rsaKey.setAlgorithm("RS512");
    REQUIRE(rsaKey.getAlgorithm() == "RS512");

    JWK ecKey = JWK::generateEC("P-256");
    ecKey.setAlgorithm("ES256");
    REQUIRE(ecKey.getAlgorithm() == "ES256");

    JWK octKey = JWK::generateOct(256);
    octKey.setAlgorithm("HS256");
    REQUIRE(octKey.getAlgorithm() == "HS256");
}

// BDD-style serialization tests
SCENARIO("JWKs can be serialized to JSON", "[jwk][serialization][bdd]")
{
    GIVEN("an RSA key with metadata")
    {
        JWK key = JWK::generateRSA(2048);
        key.setKeyID("rsa-key-1");
        key.setAlgorithm("RS256");
        
        WHEN("serializing with private key")
        {
            std::string json = key.toJSON(true);
            
            THEN("the JSON should contain all key components")
            {
                REQUIRE(json.find("\"kty\"") != std::string::npos);
                REQUIRE(json.find("\"RSA\"") != std::string::npos);
                REQUIRE(json.find("\"kid\"") != std::string::npos);
                REQUIRE(json.find("\"rsa-key-1\"") != std::string::npos);
                REQUIRE(json.find("\"alg\"") != std::string::npos);
                REQUIRE(json.find("\"RS256\"") != std::string::npos);
            }
        }
        
        WHEN("serializing without private key")
        {
            key.setKeyID("rsa-public-key");
            std::string json = key.toJSON(false);
            
            THEN("the JSON should contain only public components")
            {
                REQUIRE(json.find("\"kty\"") != std::string::npos);
                REQUIRE(json.find("\"RSA\"") != std::string::npos);
                REQUIRE(json.find("\"kid\"") != std::string::npos);
            }
        }
    }
    
    GIVEN("an EC key with metadata")
    {
        JWK key = JWK::generateEC("P-256");
        key.setKeyID("ec-key-1");
        key.setAlgorithm("ES256");
        
        WHEN("serializing with private key")
        {
            std::string json = key.toJSON(true);
            
            THEN("the JSON should contain curve information")
            {
                REQUIRE(json.find("\"kty\"") != std::string::npos);
                REQUIRE(json.find("\"EC\"") != std::string::npos);
                REQUIRE(json.find("\"crv\"") != std::string::npos);
                REQUIRE(json.find("\"P-256\"") != std::string::npos);
            }
        }
    }
    
    GIVEN("a symmetric key")
    {
        JWK key = JWK::generateOct(256);
        key.setKeyID("symmetric-key");
        key.setAlgorithm("HS256");
        
        WHEN("serializing the key")
        {
            std::string json = key.toJSON(true);
            
            THEN("the JSON should contain the key material")
            {
                REQUIRE(json.find("\"kty\"") != std::string::npos);
                REQUIRE(json.find("\"oct\"") != std::string::npos);
                REQUIRE(json.find("\"k\"") != std::string::npos);
            }
        }
    }
}

// BDD-style parsing tests
SCENARIO("JWKs can be parsed from JSON", "[jwk][parsing][bdd]")
{
    GIVEN("a serialized RSA key")
    {
        JWK original = JWK::generateRSA(2048);
        original.setKeyID("test-rsa");
        std::string json = original.toJSON(true);
        
        WHEN("parsing the JSON")
        {
            JWK parsed = JWK::fromJSON(json);
            
            THEN("the key should be reconstructed correctly")
            {
                REQUIRE(parsed.getKeyType() == JWK::KeyType::rsa);
                REQUIRE(parsed.getKeyID() == "test-rsa");
                REQUIRE(parsed.hasPrivateKey());
            }
        }
    }
    
    GIVEN("a serialized EC key")
    {
        JWK original = JWK::generateEC("P-384");
        original.setKeyID("test-ec");
        original.setAlgorithm("ES384");
        std::string json = original.toJSON(true);
        
        WHEN("parsing the JSON")
        {
            JWK parsed = JWK::fromJSON(json);
            
            THEN("the key should be reconstructed with all metadata")
            {
                REQUIRE(parsed.getKeyType() == JWK::KeyType::ec);
                REQUIRE(parsed.getKeyID() == "test-ec");
                REQUIRE(parsed.getAlgorithm() == "ES384");
            }
        }
    }
    
    GIVEN("a serialized symmetric key")
    {
        JWK original = JWK::generateOct(256);
        original.setKeyID("test-oct");
        std::string json = original.toJSON(true);
        
        WHEN("parsing the JSON")
        {
            JWK parsed = JWK::fromJSON(json);
            
            THEN("the key should be reconstructed")
            {
                REQUIRE(parsed.getKeyType() == JWK::KeyType::oct);
                REQUIRE(parsed.getKeyID() == "test-oct");
            }
        }
    }
    
    GIVEN("a public key only JSON")
    {
        JWK original = JWK::generateRSA(2048);
        original.setKeyID("public-only");
        std::string publicJson = original.toJSON(false);
        
        WHEN("parsing the public key JSON")
        {
            JWK parsed = JWK::fromJSON(publicJson);
            
            THEN("the key should not have a private component")
            {
                REQUIRE(parsed.getKeyType() == JWK::KeyType::rsa);
                REQUIRE(parsed.getKeyID() == "public-only");
                REQUIRE_FALSE(parsed.hasPrivateKey());
            }
        }
    }
}

// Round-trip tests
TEST_CASE("JWK RSA round-trip preserves all properties", "[jwk][round-trip]")
{
    JWK original = JWK::generateRSA(2048);
    original.setKeyID("rsa-round-trip");
    original.setAlgorithm("RS256");
    original.setUse(JWK::Use::signature);

    std::string json = original.toJSON(true);
    JWK parsed = JWK::fromJSON(json);

    REQUIRE(original.getKeyType() == parsed.getKeyType());
    REQUIRE(original.getKeyID() == parsed.getKeyID());
    REQUIRE(original.getAlgorithm() == parsed.getAlgorithm());
    REQUIRE(original.hasPrivateKey() == parsed.hasPrivateKey());
}

TEST_CASE("JWK EC round-trip preserves all properties", "[jwk][round-trip]")
{
    JWK original = JWK::generateEC("P-521");
    original.setKeyID("ec-round-trip");
    original.setAlgorithm("ES512");

    std::string json = original.toJSON(true);
    JWK parsed = JWK::fromJSON(json);

    REQUIRE(original.getKeyType() == parsed.getKeyType());
    REQUIRE(original.getKeyID() == parsed.getKeyID());
    REQUIRE(original.getAlgorithm() == parsed.getAlgorithm());
}

TEST_CASE("JWK Oct round-trip preserves all properties", "[jwk][round-trip]")
{
    JWK original = JWK::generateOct(256);
    original.setKeyID("oct-round-trip");
    original.setAlgorithm("HS256");

    std::string json = original.toJSON(true);
    JWK parsed = JWK::fromJSON(json);

    REQUIRE(original.getKeyType() == parsed.getKeyType());
    REQUIRE(original.getKeyID() == parsed.getKeyID());
    REQUIRE(original.getAlgorithm() == parsed.getAlgorithm());
}

// Copy and move semantics
TEST_CASE("JWK copy constructor works correctly", "[jwk][copy]")
{
    JWK original = JWK::generateRSA(2048);
    original.setKeyID("original");

    JWK copy(original);
    REQUIRE(original.getKeyID() == copy.getKeyID());
    REQUIRE(original.getKeyType() == copy.getKeyType());
}

TEST_CASE("JWK copy assignment works correctly", "[jwk][copy]")
{
    JWK original = JWK::generateRSA(2048);
    original.setKeyID("original");

    JWK copy = original;
    REQUIRE(original.getKeyID() == copy.getKeyID());
    REQUIRE(original.getKeyType() == copy.getKeyType());
}

TEST_CASE("JWK move constructor works correctly", "[jwk][move]")
{
    JWK original = JWK::generateRSA(2048);
    original.setKeyID("original");
    std::string expectedId = original.getKeyID();

    JWK moved(std::move(original));
    REQUIRE(expectedId == moved.getKeyID());
}

TEST_CASE("JWK move assignment works correctly", "[jwk][move]")
{
    JWK original = JWK::generateRSA(2048);
    original.setKeyID("original");
    std::string expectedId = original.getKeyID();

    JWK moved = std::move(original);
    REQUIRE(expectedId == moved.getKeyID());
}

// BDD-style JWKSet tests
SCENARIO("JWKSet can manage multiple keys", "[jwk][jwkset][bdd]")
{
    GIVEN("an empty JWKSet")
    {
        JWKSet jwkSet;
        
        WHEN("serializing the empty set")
        {
            std::string json = jwkSet.toJSON();
            
            THEN("it should contain a keys array")
            {
                REQUIRE(json.find("\"keys\"") != std::string::npos);
            }
        }
        
        WHEN("adding multiple keys")
        {
            JWK key1 = JWK::generateRSA(2048);
            key1.setKeyID("key1");
            jwkSet.addKey(key1);

            JWK key2 = JWK::generateEC("P-256");
            key2.setKeyID("key2");
            jwkSet.addKey(key2);
            
            THEN("both keys should be in the serialized JSON")
            {
                std::string json = jwkSet.toJSON();
                REQUIRE(json.find("\"key1\"") != std::string::npos);
                REQUIRE(json.find("\"key2\"") != std::string::npos);
            }
            
            AND_THEN("keys can be retrieved by ID")
            {
                JWK retrieved = jwkSet.getKey("key1");
                REQUIRE(retrieved.getKeyID() == "key1");
                REQUIRE(retrieved.getKeyType() == JWK::KeyType::rsa);

                JWK retrieved2 = jwkSet.getKey("key2");
                REQUIRE(retrieved2.getKeyID() == "key2");
                REQUIRE(retrieved2.getKeyType() == JWK::KeyType::ec);
            }
            
            AND_THEN("all keys can be retrieved as a vector")
            {
                std::vector<JWK> keys = jwkSet.getKeys();
                REQUIRE(keys.size() == 2);
            }
        }
    }
    
    GIVEN("a JWKSet with multiple keys of the same type")
    {
        JWKSet jwkSet;
        
        WHEN("adding five RSA keys")
        {
            for (int i = 0; i < 5; i++)
            {
                JWK key = JWK::generateRSA(2048);
                key.setKeyID("rsa-key-" + std::to_string(i));
                jwkSet.addKey(key);
            }
            
            THEN("all keys should be stored")
            {
                std::vector<JWK> keys = jwkSet.getKeys();
                REQUIRE(keys.size() == 5);
            }
            
            AND_THEN("a specific key can be retrieved")
            {
                JWK retrieved = jwkSet.getKey("rsa-key-3");
                REQUIRE(retrieved.getKeyID() == "rsa-key-3");
            }
        }
    }
}

TEST_CASE("JWKSet round-trip preserves all keys", "[jwk][jwkset][round-trip]")
{
    JWKSet original;

    JWK key1 = JWK::generateRSA(2048);
    key1.setKeyID("key1");
    key1.setAlgorithm("RS256");
    original.addKey(key1);

    JWK key2 = JWK::generateEC("P-256");
    key2.setKeyID("key2");
    key2.setAlgorithm("ES256");
    original.addKey(key2);

    std::string json = original.toJSON();
    JWKSet parsed = JWKSet::fromJSON(json);

    JWK retrievedKey1 = parsed.getKey("key1");
    REQUIRE(retrievedKey1.getKeyID() == "key1");
    REQUIRE(retrievedKey1.getAlgorithm() == "RS256");

    JWK retrievedKey2 = parsed.getKey("key2");
    REQUIRE(retrievedKey2.getKeyID() == "key2");
    REQUIRE(retrievedKey2.getAlgorithm() == "ES256");
}

TEST_CASE("JWKSet can contain three keys", "[jwk][jwkset]")
{
    JWKSet jwkSet;

    jwkSet.addKey(JWK::generateRSA(2048));
    jwkSet.addKey(JWK::generateEC("P-256"));
    jwkSet.addKey(JWK::generateOct(256));

    std::vector<JWK> keys = jwkSet.getKeys();
    REQUIRE(keys.size() == 3);
}

// Edge cases
TEST_CASE("JWK handles empty key ID", "[jwk][edge-cases]")
{
    JWK key = JWK::generateRSA(2048);
    key.setKeyID("");
    REQUIRE(key.getKeyID() == "");
}

TEST_CASE("JWK handles very long key ID", "[jwk][edge-cases]")
{
    JWK key = JWK::generateEC("P-256");
    std::string longId(1000, 'a');
    key.setKeyID(longId);
    REQUIRE(key.getKeyID() == longId);
}

TEST_CASE("JWK handles special characters in key ID", "[jwk][edge-cases]")
{
    JWK key = JWK::generateOct(256);
    key.setKeyID("key-with-dashes_and_underscores.and.dots");
    REQUIRE(key.getKeyID() == "key-with-dashes_and_underscores.and.dots");
}

TEST_CASE("JWK handles multiple properties set together", "[jwk][edge-cases]")
{
    JWK key = JWK::generateRSA(2048);
    key.setKeyID("multi-prop-key");
    key.setAlgorithm("RS384");
    key.setUse(JWK::Use::signature);

    REQUIRE(key.getKeyID() == "multi-prop-key");
    REQUIRE(key.getAlgorithm() == "RS384");

    std::string json = key.toJSON(true);
    REQUIRE(json.find("\"multi-prop-key\"") != std::string::npos);
    REQUIRE(json.find("\"RS384\"") != std::string::npos);
}

