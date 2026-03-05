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
            JWK key = JWK::generateRSA(JWK::Use::signature);
            
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
            JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
            
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
            JWK key = JWK::generateRSA(JWK::Use::signature, 3072);
            
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
            JWK key = JWK::generateRSA(JWK::Use::signature, 4096);
            
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
            JWK key = JWK::generateEC(JWK::Use::signature);
            
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
            JWK key = JWK::generateEC(JWK::Use::signature, "P-256");
            
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
            JWK key = JWK::generateEC(JWK::Use::signature, "P-384");
            
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
            JWK key = JWK::generateEC(JWK::Use::signature, "P-521");
            
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
            JWK key = JWK::generateOct(JWK::Use::signature);
            
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
            JWK key = JWK::generateOct(JWK::Use::signature, 128);
            
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
            JWK key = JWK::generateOct(JWK::Use::signature, 192);
            
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
            JWK key = JWK::generateOct(JWK::Use::signature, 256);
            
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
        JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
        
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
    JWK rsaKey = JWK::generateRSA(JWK::Use::signature, 2048);
    rsaKey.setAlgorithm("RS512");
    REQUIRE(rsaKey.getAlgorithm() == "RS512");

    JWK ecKey = JWK::generateEC(JWK::Use::signature, "P-256");
    ecKey.setAlgorithm("ES256");
    REQUIRE(ecKey.getAlgorithm() == "ES256");

    JWK octKey = JWK::generateOct(JWK::Use::signature, 256);
    octKey.setAlgorithm("HS256");
    REQUIRE(octKey.getAlgorithm() == "HS256");
}

// BDD-style serialization tests
SCENARIO("JWKs can be serialized to JSON", "[jwk][serialization][bdd]")
{
    GIVEN("an RSA key with metadata")
    {
        JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
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
        JWK key = JWK::generateEC(JWK::Use::signature, "P-256");
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
        JWK key = JWK::generateOct(JWK::Use::signature, 256);
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
        JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
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
        JWK original = JWK::generateEC(JWK::Use::signature, "P-384");
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
        JWK original = JWK::generateOct(JWK::Use::signature, 256);
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
        JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
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
    JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
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
    JWK original = JWK::generateEC(JWK::Use::signature, "P-521");
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
    JWK original = JWK::generateOct(JWK::Use::signature, 256);
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
    JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
    original.setKeyID("original");

    JWK copy(original);
    REQUIRE(original.getKeyID() == copy.getKeyID());
    REQUIRE(original.getKeyType() == copy.getKeyType());
}

TEST_CASE("JWK copy assignment works correctly", "[jwk][copy]")
{
    JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
    original.setKeyID("original");

    JWK copy = original;
    REQUIRE(original.getKeyID() == copy.getKeyID());
    REQUIRE(original.getKeyType() == copy.getKeyType());
}

TEST_CASE("JWK move constructor works correctly", "[jwk][move]")
{
    JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
    original.setKeyID("original");
    std::string expectedId = original.getKeyID();

    JWK moved(std::move(original));
    REQUIRE(expectedId == moved.getKeyID());
}

TEST_CASE("JWK move assignment works correctly", "[jwk][move]")
{
    JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
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
            JWK key1 = JWK::generateRSA(JWK::Use::signature, 2048);
            key1.setKeyID("key1");
            jwkSet.addKey(key1);

            JWK key2 = JWK::generateEC(JWK::Use::signature, "P-256");
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
                JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
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

    JWK key1 = JWK::generateRSA(JWK::Use::signature, 2048);
    key1.setKeyID("key1");
    key1.setAlgorithm("RS256");
    original.addKey(key1);

    JWK key2 = JWK::generateEC(JWK::Use::signature, "P-256");
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

    jwkSet.addKey(JWK::generateRSA(JWK::Use::signature, 2048));
    jwkSet.addKey(JWK::generateEC(JWK::Use::signature, "P-256"));
    jwkSet.addKey(JWK::generateOct(JWK::Use::signature, 256));

    std::vector<JWK> keys = jwkSet.getKeys();
    REQUIRE(keys.size() == 3);
}

// ---------------------------------------------------------------------------
// EC key import (fromJSON) -- these tests verify behaviour that the current
// stub (case KeyType::ec: break;) does NOT implement, so they are expected to
// FAIL until the EC import branch is filled in.
// ---------------------------------------------------------------------------

// Known-good P-256 public key from RFC 7517 Appendix A.2
static std::string const k_p256_public_json =
    R"({"kty":"EC","crv":"P-256",)"
    R"("x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",)"
    R"("y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",)"
    R"("use":"enc","alg":"ECDH-ES","kid":"p256-pub"})";

// Known-good P-256 private key (public + d)
static std::string const k_p256_private_json =
    R"({"kty":"EC","crv":"P-256",)"
    R"("x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",)"
    R"("y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",)"
    R"("d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",)"
    R"("use":"sig","alg":"ES256","kid":"p256-priv"})";

SCENARIO("EC public keys can be imported from JSON", "[jwk][ec][import]")
{
    GIVEN("a P-256 public key JSON")
    {
        WHEN("parsing the JSON")
        {
            JWK key = JWK::fromJSON(k_p256_public_json);

            THEN("the key type is EC")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::ec);
            }
            THEN("it has no private component")
            {
                REQUIRE_FALSE(key.hasPrivateKey());
            }
            THEN("the key ID is preserved")
            {
                REQUIRE(key.getKeyID() == "p256-pub");
            }
            THEN("the algorithm is preserved")
            {
                REQUIRE(key.getAlgorithm() == "ECDH-ES");
            }
            THEN("toJSON round-trips the public coordinates")
            {
                std::string json = key.toJSON(false);
                REQUIRE(json.find("\"x\"") != std::string::npos);
                REQUIRE(json.find("\"y\"") != std::string::npos);
                REQUIRE(json.find("\"P-256\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("EC private keys can be imported from JSON", "[jwk][ec][import]")
{
    GIVEN("a P-256 private key JSON")
    {
        WHEN("parsing the JSON")
        {
            JWK key = JWK::fromJSON(k_p256_private_json);

            THEN("the key type is EC")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::ec);
            }
            THEN("it has a private component")
            {
                REQUIRE(key.hasPrivateKey());
            }
            THEN("the key ID is preserved")
            {
                REQUIRE(key.getKeyID() == "p256-priv");
            }
            THEN("toJSON with private includes d")
            {
                std::string json = key.toJSON(true);
                REQUIRE(json.find("\"d\"") != std::string::npos);
            }
            THEN("toJSON without private omits d")
            {
                std::string json = key.toJSON(false);
                REQUIRE(json.find("\"d\"") == std::string::npos);
            }
        }
    }
}

SCENARIO("EC keys round-trip through JSON for all standard curves",
         "[jwk][ec][import][round-trip]")
{
    auto test_curve = [](std::string const& curve, std::string const& alg)
    {
        JWK original = JWK::generateEC(JWK::Use::signature, curve);
        original.setKeyID("rt-" + curve);
        original.setAlgorithm(alg);

        std::string json = original.toJSON(true);
        JWK parsed = JWK::fromJSON(json);

        REQUIRE(parsed.getKeyType() == JWK::KeyType::ec);
        REQUIRE(parsed.getKeyID()   == "rt-" + curve);
        REQUIRE(parsed.getAlgorithm() == alg);
        // The imported key must carry private material.
        REQUIRE(parsed.hasPrivateKey());
        // A second round-trip must produce identical JSON.
        REQUIRE(parsed.toJSON(true) == json);
    };

    GIVEN("a generated P-256 key")
    {
        WHEN("round-tripping through JSON")
        {
            THEN("all properties are preserved") { test_curve("P-256", "ES256"); }
        }
    }
    GIVEN("a generated P-384 key")
    {
        WHEN("round-tripping through JSON")
        {
            THEN("all properties are preserved") { test_curve("P-384", "ES384"); }
        }
    }
    GIVEN("a generated P-521 key")
    {
        WHEN("round-tripping through JSON")
        {
            THEN("all properties are preserved") { test_curve("P-521", "ES512"); }
        }
    }
}

SCENARIO("EC encryption keys can be imported from JSON",
         "[jwk][ec][import][enc]")
{
    GIVEN("a P-256 public key intended for ECDH-ES")
    {
        WHEN("parsing the JSON")
        {
            JWK key = JWK::fromJSON(k_p256_public_json);

            THEN("the key type and algorithm are correct")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::ec);
                REQUIRE(key.getAlgorithm() == "ECDH-ES");
            }
            THEN("it has no private component")
            {
                REQUIRE_FALSE(key.hasPrivateKey());
            }
        }
    }
}

// Edge cases
TEST_CASE("JWK handles empty key ID", "[jwk][edge-cases]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    key.setKeyID("");
    REQUIRE(key.getKeyID() == "");
}

TEST_CASE("JWK handles very long key ID", "[jwk][edge-cases]")
{
    JWK key = JWK::generateEC(JWK::Use::signature, "P-256");
    std::string longId(1000, 'a');
    key.setKeyID(longId);
    REQUIRE(key.getKeyID() == longId);
}

TEST_CASE("JWK handles special characters in key ID", "[jwk][edge-cases]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    key.setKeyID("key-with-dashes_and_underscores.and.dots");
    REQUIRE(key.getKeyID() == "key-with-dashes_and_underscores.and.dots");
}

TEST_CASE("JWK handles multiple properties set together", "[jwk][edge-cases]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    key.setKeyID("multi-prop-key");
    key.setAlgorithm("RS384");
    key.setUse(JWK::Use::signature);

    REQUIRE(key.getKeyID() == "multi-prop-key");
    REQUIRE(key.getAlgorithm() == "RS384");

    std::string json = key.toJSON(true);
    REQUIRE(json.find("\"multi-prop-key\"") != std::string::npos);
    REQUIRE(json.find("\"RS384\"") != std::string::npos);
}

// Algorithm validation tests
TEST_CASE("JWK validates RSA signature algorithms", "[jwk][validation]")
{
    // Valid RSA signature algorithms
    REQUIRE_NOTHROW(JWK::generateRSA(JWK::Use::signature, 2048, "RS256"));
    REQUIRE_NOTHROW(JWK::generateRSA(JWK::Use::signature, 2048, "RS384"));
    REQUIRE_NOTHROW(JWK::generateRSA(JWK::Use::signature, 2048, "RS512"));
    REQUIRE_NOTHROW(JWK::generateRSA(JWK::Use::signature, 2048, "PS256"));
    REQUIRE_NOTHROW(JWK::generateRSA(JWK::Use::signature, 2048, "PS384"));
    REQUIRE_NOTHROW(JWK::generateRSA(JWK::Use::signature, 2048, "PS512"));

    // Invalid: encryption algorithms for signature use
    REQUIRE_THROWS(JWK::generateRSA(JWK::Use::signature, 2048, "RSA-OAEP"));
    REQUIRE_THROWS(JWK::generateRSA(JWK::Use::signature, 2048, "RSA-OAEP-256"));
    REQUIRE_THROWS(JWK::generateRSA(JWK::Use::signature, 2048, "RSA1_5"));

    // Invalid: HMAC algorithms for RSA
    REQUIRE_THROWS(JWK::generateRSA(JWK::Use::signature, 2048, "HS256"));
    REQUIRE_THROWS(JWK::generateRSA(JWK::Use::signature, 2048, "HS512"));

    // Invalid: EC algorithms for RSA
    REQUIRE_THROWS(JWK::generateRSA(JWK::Use::signature, 2048, "ES256"));
}

TEST_CASE("JWK validates RSA encryption algorithms", "[jwk][validation]")
{
    // Valid RSA encryption algorithms
    REQUIRE_NOTHROW(JWK::generateRSA(JWK::Use::encryption, 2048, "RSA-OAEP"));
    REQUIRE_NOTHROW(JWK::generateRSA(JWK::Use::encryption, 2048, "RSA-OAEP-256"));
    REQUIRE_NOTHROW(JWK::generateRSA(JWK::Use::encryption, 2048, "RSA1_5"));

    // Invalid: signature algorithms for encryption use
    REQUIRE_THROWS(JWK::generateRSA(JWK::Use::encryption, 2048, "RS256"));
    REQUIRE_THROWS(JWK::generateRSA(JWK::Use::encryption, 2048, "PS256"));

    // Invalid: other key type algorithms
    REQUIRE_THROWS(JWK::generateRSA(JWK::Use::encryption, 2048, "A256KW"));
    REQUIRE_THROWS(JWK::generateRSA(JWK::Use::encryption, 2048, "HS256"));
}

TEST_CASE("JWK validates EC signature algorithms", "[jwk][validation]")
{
    // Valid EC signature algorithms
    REQUIRE_NOTHROW(JWK::generateEC(JWK::Use::signature, "P-256", "ES256"));
    REQUIRE_NOTHROW(JWK::generateEC(JWK::Use::signature, "P-384", "ES384"));
    REQUIRE_NOTHROW(JWK::generateEC(JWK::Use::signature, "P-521", "ES512"));

    // Invalid: RSA algorithms for EC
    REQUIRE_THROWS(JWK::generateEC(JWK::Use::signature, "P-256", "RS256"));
    REQUIRE_THROWS(JWK::generateEC(JWK::Use::signature, "P-256", "PS256"));

    // Invalid: HMAC algorithms for EC
    REQUIRE_THROWS(JWK::generateEC(JWK::Use::signature, "P-256", "HS256"));

    // Invalid: encryption algorithms for signature use
    REQUIRE_THROWS(JWK::generateEC(JWK::Use::signature, "P-256", "ECDH-ES"));
}

TEST_CASE("JWK validates EC encryption algorithms", "[jwk][validation]")
{
    // Valid EC encryption algorithms
    REQUIRE_NOTHROW(JWK::generateEC(JWK::Use::encryption, "P-256", "ECDH-ES"));
    REQUIRE_NOTHROW(JWK::generateEC(JWK::Use::encryption, "P-256", "ECDH-ES+A128KW"));
    REQUIRE_NOTHROW(JWK::generateEC(JWK::Use::encryption, "P-256", "ECDH-ES+A256KW"));

    // Invalid: signature algorithms for encryption use
    REQUIRE_THROWS(JWK::generateEC(JWK::Use::encryption, "P-256", "ES256"));
    REQUIRE_THROWS(JWK::generateEC(JWK::Use::encryption, "P-384", "ES384"));
}

TEST_CASE("JWK validates symmetric signature algorithms", "[jwk][validation]")
{
    // Valid HMAC signature algorithms
    REQUIRE_NOTHROW(JWK::generateOct(JWK::Use::signature, 256, "HS256"));
    REQUIRE_NOTHROW(JWK::generateOct(JWK::Use::signature, 384, "HS384"));
    REQUIRE_NOTHROW(JWK::generateOct(JWK::Use::signature, 512, "HS512"));

    // Invalid: RSA algorithms for symmetric keys
    REQUIRE_THROWS(JWK::generateOct(JWK::Use::signature, 256, "RS256"));

    // Invalid: EC algorithms for symmetric keys
    REQUIRE_THROWS(JWK::generateOct(JWK::Use::signature, 256, "ES256"));

    // Invalid: AES key wrap for signature use
    REQUIRE_THROWS(JWK::generateOct(JWK::Use::signature, 256, "A256KW"));
}

TEST_CASE("JWK validates symmetric encryption algorithms", "[jwk][validation]")
{
    // Valid AES key wrap algorithms
    REQUIRE_NOTHROW(JWK::generateOct(JWK::Use::encryption, 128, "A128KW"));
    REQUIRE_NOTHROW(JWK::generateOct(JWK::Use::encryption, 256, "A256KW"));
    REQUIRE_NOTHROW(JWK::generateOct(JWK::Use::encryption, 128, "A128GCMKW"));
    REQUIRE_NOTHROW(JWK::generateOct(JWK::Use::encryption, 256, "A256GCMKW"));

    // Invalid: HMAC for encryption use
    REQUIRE_THROWS(JWK::generateOct(JWK::Use::encryption, 256, "HS256"));

    // Invalid: RSA algorithms for symmetric keys
    REQUIRE_THROWS(JWK::generateOct(JWK::Use::encryption, 256, "RSA-OAEP"));
}

TEST_CASE("JWK selects correct default algorithms", "[jwk][validation][defaults]")
{
    // RSA defaults
    {
        JWK sig_key = JWK::generateRSA(JWK::Use::signature);
        REQUIRE(sig_key.getAlgorithm() == "RS256");
        
        JWK enc_key = JWK::generateRSA(JWK::Use::encryption);
        REQUIRE(enc_key.getAlgorithm() == "RSA-OAEP-256");
    }

    // EC defaults
    {
        JWK sig_key_256 = JWK::generateEC(JWK::Use::signature, "P-256");
        REQUIRE(sig_key_256.getAlgorithm() == "ES256");
        
        JWK sig_key_384 = JWK::generateEC(JWK::Use::signature, "P-384");
        REQUIRE(sig_key_384.getAlgorithm() == "ES384");
        
        JWK sig_key_521 = JWK::generateEC(JWK::Use::signature, "P-521");
        REQUIRE(sig_key_521.getAlgorithm() == "ES512");
        
        JWK enc_key = JWK::generateEC(JWK::Use::encryption, "P-256");
        REQUIRE(enc_key.getAlgorithm() == "ECDH-ES");
    }

    // Symmetric defaults
    {
        JWK sig_key = JWK::generateOct(JWK::Use::signature);
        REQUIRE(sig_key.getAlgorithm() == "HS256");
        
        JWK enc_key = JWK::generateOct(JWK::Use::encryption);
        REQUIRE(enc_key.getAlgorithm() == "A256KW");
    }
}

TEST_CASE("JWK default algorithms are valid for their use", "[jwk][validation][defaults]")
{
    // All default algorithms should pass validation
    REQUIRE_NOTHROW(JWK::generateRSA(JWK::Use::signature));
    REQUIRE_NOTHROW(JWK::generateRSA(JWK::Use::encryption));
    REQUIRE_NOTHROW(JWK::generateEC(JWK::Use::signature, "P-256"));
    REQUIRE_NOTHROW(JWK::generateEC(JWK::Use::signature, "P-384"));
    REQUIRE_NOTHROW(JWK::generateEC(JWK::Use::signature, "P-521"));
    REQUIRE_NOTHROW(JWK::generateEC(JWK::Use::encryption, "P-256"));
    REQUIRE_NOTHROW(JWK::generateOct(JWK::Use::signature));
    REQUIRE_NOTHROW(JWK::generateOct(JWK::Use::encryption));
}

// ---------------------------------------------------------------------------
// Symmetric key (oct) import (fromJSON)
// The oct case in fromJSON currently stubs out (case KeyType::oct: break;),
// so impl.key_ is never set. These tests drive the implementation:
//   - hasPrivateKey() must return true (currently returns false)
//   - toJSON(true) must include "k"   (currently omits it)
//   - round-trip JSON must be stable  (currently loses key material)
// ---------------------------------------------------------------------------

// RFC 7515 §A.1.1 — 512-bit HMAC key used in the JWS HMAC-SHA2 example
static std::string const k_oct_512_json =
    R"({"kty":"oct",)"
    R"("k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",)"
    R"("use":"sig","alg":"HS512","kid":"oct-512"})";

// RFC 7517 §C.3 — 128-bit AES key-wrap key
static std::string const k_oct_128_json =
    R"({"kty":"oct",)"
    R"("k":"GawgguFyGrWKav7AX4VKUg",)"
    R"("use":"enc","alg":"A128KW","kid":"81b20965-8332-43d9-a468-82160ad91ac8"})";

SCENARIO("Symmetric keys can be imported from a known JSON vector",
         "[jwk][oct][import]")
{
    GIVEN("the RFC 7515 §A.1.1 512-bit HMAC key")
    {
        WHEN("parsing the JSON")
        {
            JWK key = JWK::fromJSON(k_oct_512_json);

            THEN("the key type is oct")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::oct);
            }
            THEN("it has a private (symmetric) component")
            {
                REQUIRE(key.hasPrivateKey());
            }
            THEN("the key ID is preserved")
            {
                REQUIRE(key.getKeyID() == "oct-512");
            }
            THEN("the algorithm is preserved")
            {
                REQUIRE(key.getAlgorithm() == "HS512");
            }
            THEN("toJSON includes the k parameter")
            {
                std::string json = key.toJSON(true);
                REQUIRE(json.find("\"k\"") != std::string::npos);
            }
        }
    }

    GIVEN("the RFC 7517 §C.3 128-bit AES key-wrap key")
    {
        WHEN("parsing the JSON")
        {
            JWK key = JWK::fromJSON(k_oct_128_json);

            THEN("the key type is oct")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::oct);
            }
            THEN("it has a private (symmetric) component")
            {
                REQUIRE(key.hasPrivateKey());
            }
            THEN("the algorithm is preserved")
            {
                REQUIRE(key.getAlgorithm() == "A128KW");
            }
        }
    }
}

SCENARIO("Symmetric key JSON must contain the k parameter", "[jwk][oct][import]")
{
    GIVEN("a JSON object with kty=oct but no k field")
    {
        std::string const bad_json =
            R"({"kty":"oct","use":"sig","alg":"HS256","kid":"missing-k"})";

        WHEN("parsing the JSON")
        {
            THEN("it should throw")
            {
                REQUIRE_THROWS(JWK::fromJSON(bad_json));
            }
        }
    }
}

SCENARIO("Symmetric keys round-trip through JSON for all standard sizes",
         "[jwk][oct][import][round-trip]")
{
    auto test_size = [](int bits, std::string const& alg, JWK::Use use)
    {
        JWK original = JWK::generateOct(use, bits, alg);
        original.setKeyID("rt-" + std::to_string(bits));

        std::string json = original.toJSON(true);
        JWK parsed = JWK::fromJSON(json);

        REQUIRE(parsed.getKeyType()   == JWK::KeyType::oct);
        REQUIRE(parsed.getKeyID()     == "rt-" + std::to_string(bits));
        REQUIRE(parsed.getAlgorithm() == alg);
        // Symmetric keys always carry private (key) material.
        REQUIRE(parsed.hasPrivateKey());
        // A second round-trip must produce identical JSON.
        REQUIRE(parsed.toJSON(true) == json);
    };

    GIVEN("a generated 128-bit HS256 key")
    {
        WHEN("round-tripping through JSON")
        {
            THEN("all properties are preserved")
            {
                test_size(128, "HS256", JWK::Use::signature);
            }
        }
    }
    GIVEN("a generated 192-bit HS384 key")
    {
        WHEN("round-tripping through JSON")
        {
            THEN("all properties are preserved")
            {
                test_size(192, "HS384", JWK::Use::signature);
            }
        }
    }
    GIVEN("a generated 256-bit HS512 key")
    {
        WHEN("round-tripping through JSON")
        {
            THEN("all properties are preserved")
            {
                test_size(256, "HS512", JWK::Use::signature);
            }
        }
    }
    GIVEN("a generated 128-bit A128KW key")
    {
        WHEN("round-tripping through JSON")
        {
            THEN("all properties are preserved")
            {
                test_size(128, "A128KW", JWK::Use::encryption);
            }
        }
    }
    GIVEN("a generated 256-bit A256KW key")
    {
        WHEN("round-tripping through JSON")
        {
            THEN("all properties are preserved")
            {
                test_size(256, "A256KW", JWK::Use::encryption);
            }
        }
    }
}

SCENARIO("Symmetric key toJSON omits k when include_private is false",
         "[jwk][oct][import]")
{
    GIVEN("an imported symmetric key")
    {
        JWK key = JWK::fromJSON(k_oct_512_json);

        WHEN("serialising without private material")
        {
            std::string json = key.toJSON(false);

            THEN("the k parameter is absent")
            {
                REQUIRE(json.find("\"k\"") == std::string::npos);
            }
            THEN("kty and kid are still present")
            {
                REQUIRE(json.find("\"oct\"") != std::string::npos);
                REQUIRE(json.find("\"oct-512\"") != std::string::npos);
            }
        }
    }
}
