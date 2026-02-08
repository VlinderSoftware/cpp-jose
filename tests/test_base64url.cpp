#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

#include "jose/jose.hpp"

using namespace Vlinder::jose;

// BDD-style tests for encoding
SCENARIO("Base64Url encoding handles various inputs", "[base64url][encoding][bdd]")
{
    GIVEN("an empty string")
    {
        std::string input = "";
        
        WHEN("encoding the empty string")
        {
            std::string encoded = Base64Url::encode(input);
            
            THEN("the result should be empty")
            {
                REQUIRE(encoded == "");
            }
        }
    }
    
    GIVEN("an empty vector")
    {
        std::vector<unsigned char> input;
        
        WHEN("encoding the empty vector")
        {
            std::string encoded = Base64Url::encode(input);
            
            THEN("the result should be empty")
            {
                REQUIRE(encoded == "");
            }
        }
    }
    
    GIVEN("a simple string")
    {
        std::string input = "hello";
        
        WHEN("encoding the string")
        {
            std::string encoded = Base64Url::encode(input);
            
            THEN("it should be properly base64url encoded")
            {
                REQUIRE(encoded == "aGVsbG8");
            }
        }
    }
}

SCENARIO("Base64Url encoding removes padding", "[base64url][encoding][padding][bdd]")
{
    GIVEN("strings that would normally require padding")
    {
        WHEN("encoding 'Man' (no padding needed)")
        {
            std::string input = "Man";
            std::string encoded = Base64Url::encode(input);
            
            THEN("the result should be 'TWFu'")
            {
                REQUIRE(encoded == "TWFu");
            }
        }
        
        WHEN("encoding 'Ma' (would be TWE= in base64)")
        {
            std::string input = "Ma";
            std::string encoded = Base64Url::encode(input);
            
            THEN("padding should be removed")
            {
                REQUIRE(encoded == "TWE");
            }
        }
        
        WHEN("encoding 'M' (would be TQ== in base64)")
        {
            std::string input = "M";
            std::string encoded = Base64Url::encode(input);
            
            THEN("all padding should be removed")
            {
                REQUIRE(encoded == "TQ");
            }
        }
    }
}

SCENARIO("Base64Url uses URL-safe characters", "[base64url][encoding][special-chars][bdd]")
{
    GIVEN("binary data that would produce + or / in standard base64")
    {
        std::vector<unsigned char> input = {0xfb, 0xff, 0xff};
        
        WHEN("encoding the data")
        {
            std::string encoded = Base64Url::encode(input);
            
            THEN("it should use '-' and '_' instead of '+' and '/'")
            {
                REQUIRE(encoded == "-___");
            }
        }
    }
}

// Regular test cases for encoding
TEST_CASE("Base64Url encodes binary data correctly", "[base64url][encoding]")
{
    std::vector<unsigned char> input = {0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd};
    std::string encoded = Base64Url::encode(input);
    std::vector<unsigned char> decoded = Base64Url::decode(encoded);
    REQUIRE(input == decoded);
}

TEST_CASE("Base64Url encodes RFC7515 example", "[base64url][encoding][rfc7515]")
{
    // From RFC 7515 Appendix A.1
    std::string input = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
    std::string encoded = Base64Url::encode(input);
    REQUIRE(encoded == "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");
}

// BDD-style tests for decoding
SCENARIO("Base64Url decoding handles various inputs", "[base64url][decoding][bdd]")
{
    GIVEN("an empty string")
    {
        std::string input = "";
        
        WHEN("decoding to vector")
        {
            std::vector<unsigned char> decoded = Base64Url::decode(input);
            
            THEN("the result should be empty")
            {
                REQUIRE(decoded.empty());
            }
        }
        
        WHEN("decoding to string")
        {
            std::string decoded = Base64Url::decodeToString(input);
            
            THEN("the result should be empty")
            {
                REQUIRE(decoded == "");
            }
        }
    }
    
    GIVEN("a simple encoded string")
    {
        std::string encoded = "aGVsbG8";
        
        WHEN("decoding to string")
        {
            std::string decoded = Base64Url::decodeToString(encoded);
            
            THEN("it should produce the original text")
            {
                REQUIRE(decoded == "hello");
            }
        }
    }
}

SCENARIO("Base64Url decoding handles missing padding", "[base64url][decoding][padding][bdd]")
{
    GIVEN("encoded strings with missing padding")
    {
        WHEN("decoding 'TWE' (Ma with padding removed)")
        {
            std::string encoded = "TWE";
            std::string decoded = Base64Url::decodeToString(encoded);
            
            THEN("it should correctly decode without padding")
            {
                REQUIRE(decoded == "Ma");
            }
        }
        
        WHEN("decoding 'TQ' (M with padding removed)")
        {
            std::string encoded = "TQ";
            std::string decoded = Base64Url::decodeToString(encoded);
            
            THEN("it should correctly decode without padding")
            {
                REQUIRE(decoded == "M");
            }
        }
    }
}

SCENARIO("Base64Url decodes URL-safe characters", "[base64url][decoding][special-chars][bdd]")
{
    GIVEN("encoded string with URL-safe characters")
    {
        std::string encoded = "-___";
        
        WHEN("decoding the string")
        {
            std::vector<unsigned char> decoded = Base64Url::decode(encoded);
            
            THEN("it should correctly interpret '-' and '_'")
            {
                std::vector<unsigned char> expected = {0xfb, 0xff, 0xff};
                REQUIRE(decoded == expected);
            }
        }
    }
}

TEST_CASE("Base64Url decodes binary data correctly", "[base64url][decoding]")
{
    std::vector<unsigned char> original = {0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b};
    std::string encoded = Base64Url::encode(original);
    std::vector<unsigned char> decoded = Base64Url::decode(encoded);
    REQUIRE(original == decoded);
}

// BDD-style round-trip tests
SCENARIO("Base64Url encoding and decoding are reversible", "[base64url][round-trip][bdd]")
{
    GIVEN("various types of data")
    {
        WHEN("encoding and decoding a text string")
        {
            std::string original = "The quick brown fox jumps over the lazy dog";
            std::string encoded = Base64Url::encode(original);
            std::string decoded = Base64Url::decodeToString(encoded);
            
            THEN("the decoded string should match the original")
            {
                REQUIRE(decoded == original);
            }
        }
        
        WHEN("encoding and decoding a byte vector")
        {
            std::vector<unsigned char> original = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21};
            std::string encoded = Base64Url::encode(original);
            std::vector<unsigned char> decoded = Base64Url::decode(encoded);
            
            THEN("the decoded vector should match the original")
            {
                REQUIRE(decoded == original);
            }
        }
        
        WHEN("encoding and decoding all byte values")
        {
            std::vector<unsigned char> original;
            for (int i = 0; i < 256; i++)
            {
                original.push_back(static_cast<unsigned char>(i));
            }
            std::string encoded = Base64Url::encode(original);
            std::vector<unsigned char> decoded = Base64Url::decode(encoded);
            
            THEN("all bytes should be preserved")
            {
                REQUIRE(decoded == original);
            }
        }
        
        WHEN("encoding and decoding UTF-8 text")
        {
            std::string original = "Hello 世界 🌍";
            std::string encoded = Base64Url::encode(original);
            std::string decoded = Base64Url::decodeToString(encoded);
            
            THEN("the UTF-8 characters should be preserved")
            {
                REQUIRE(decoded == original);
            }
        }
    }
}

// Edge cases
TEST_CASE("Base64Url handles long strings", "[base64url][edge-cases]")
{
    std::string original(10000, 'A');
    std::string encoded = Base64Url::encode(original);
    std::string decoded = Base64Url::decodeToString(encoded);
    REQUIRE(original == decoded);
}

TEST_CASE("Base64Url handles single byte", "[base64url][edge-cases]")
{
    std::vector<unsigned char> original = {0x42};
    std::string encoded = Base64Url::encode(original);
    std::vector<unsigned char> decoded = Base64Url::decode(encoded);
    REQUIRE(original == decoded);
}

TEST_CASE("Base64Url handles two bytes", "[base64url][edge-cases]")
{
    std::vector<unsigned char> original = {0x42, 0x43};
    std::string encoded = Base64Url::encode(original);
    std::vector<unsigned char> decoded = Base64Url::decode(encoded);
    REQUIRE(original == decoded);
}

TEST_CASE("Base64Url handles three bytes", "[base64url][edge-cases]")
{
    std::vector<unsigned char> original = {0x42, 0x43, 0x44};
    std::string encoded = Base64Url::encode(original);
    std::vector<unsigned char> decoded = Base64Url::decode(encoded);
    REQUIRE(original == decoded);
}

TEST_CASE("Base64Url never contains + or /", "[base64url][invariants]")
{
    std::vector<unsigned char> input;
    for (int i = 0; i < 256; i++)
    {
        input.push_back(static_cast<unsigned char>(i));
    }
    std::string encoded = Base64Url::encode(input);
    REQUIRE(encoded.find('+') == std::string::npos);
    REQUIRE(encoded.find('/') == std::string::npos);
}

TEST_CASE("Base64Url never contains padding", "[base64url][invariants]")
{
    std::vector<unsigned char> input1 = {0x42};
    std::string encoded1 = Base64Url::encode(input1);
    REQUIRE(encoded1.find('=') == std::string::npos);

    std::vector<unsigned char> input2 = {0x42, 0x43};
    std::string encoded2 = Base64Url::encode(input2);
    REQUIRE(encoded2.find('=') == std::string::npos);
}

// RFC 7515 test vectors
TEST_CASE("Base64Url RFC7515 Appendix C example", "[base64url][rfc7515]")
{
    std::string payload =
        "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
    std::string encoded = Base64Url::encode(payload);
    std::string expected = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmN"
                           "vbS9pc19yb290Ijp0cnVlfQ";
    REQUIRE(encoded == expected);

    std::string decoded = Base64Url::decodeToString(encoded);
    REQUIRE(decoded == payload);
}
