#include <catch2/catch_test_macros.hpp>
#include <string>
#include <vector>

#include "jose/jose.hpp"

using namespace std;

using namespace Vlinder::JOSE;

// BDD-style tests for encoding
SCENARIO("Base64Url encoding handles various inputs", "[base64url][encoding][bdd]")
{
    GIVEN("an empty string")
    {
        string input = "";

        WHEN("encoding the empty string")
        {
            string encoded = Base64Url::encode(input);

            THEN("the result should be empty")
            {
                REQUIRE(encoded == "");
            }
        }
    }

    GIVEN("an empty vector")
    {
        vector<unsigned char> input;

        WHEN("encoding the empty vector")
        {
            string encoded = Base64Url::encode(input);

            THEN("the result should be empty")
            {
                REQUIRE(encoded == "");
            }
        }
    }

    GIVEN("a simple string")
    {
        string input = "hello";

        WHEN("encoding the string")
        {
            string encoded = Base64Url::encode(input);

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
            string input = "Man";
            string encoded = Base64Url::encode(input);

            THEN("the result should be 'TWFu'")
            {
                REQUIRE(encoded == "TWFu");
            }
        }

        WHEN("encoding 'Ma' (would be TWE= in base64)")
        {
            string input = "Ma";
            string encoded = Base64Url::encode(input);

            THEN("padding should be removed")
            {
                REQUIRE(encoded == "TWE");
            }
        }

        WHEN("encoding 'M' (would be TQ== in base64)")
        {
            string input = "M";
            string encoded = Base64Url::encode(input);

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
        vector<unsigned char> input = {0xfb, 0xff, 0xff};

        WHEN("encoding the data")
        {
            string encoded = Base64Url::encode(input);

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
    vector<unsigned char> input = {0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd};
    string encoded = Base64Url::encode(input);
    vector<unsigned char> decoded = Base64Url::decode(encoded);
    REQUIRE(input == decoded);
}

TEST_CASE("Base64Url encodes RFC7515 example", "[base64url][encoding][rfc7515]")
{
    // From RFC 7515 Appendix A.1
    string input = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
    string encoded = Base64Url::encode(input);
    REQUIRE(encoded == "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");
}

// BDD-style tests for decoding
SCENARIO("Base64Url decoding handles various inputs", "[base64url][decoding][bdd]")
{
    GIVEN("an empty string")
    {
        string input = "";

        WHEN("decoding to vector")
        {
            vector<unsigned char> decoded = Base64Url::decode(input);

            THEN("the result should be empty")
            {
                REQUIRE(decoded.empty());
            }
        }

        WHEN("decoding to string")
        {
            string decoded = Base64Url::decodeToString(input);

            THEN("the result should be empty")
            {
                REQUIRE(decoded == "");
            }
        }
    }

    GIVEN("a simple encoded string")
    {
        string encoded = "aGVsbG8";

        WHEN("decoding to string")
        {
            string decoded = Base64Url::decodeToString(encoded);

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
            string encoded = "TWE";
            string decoded = Base64Url::decodeToString(encoded);

            THEN("it should correctly decode without padding")
            {
                REQUIRE(decoded == "Ma");
            }
        }

        WHEN("decoding 'TQ' (M with padding removed)")
        {
            string encoded = "TQ";
            string decoded = Base64Url::decodeToString(encoded);

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
        string encoded = "-___";

        WHEN("decoding the string")
        {
            vector<unsigned char> decoded = Base64Url::decode(encoded);

            THEN("it should correctly interpret '-' and '_'")
            {
                vector<unsigned char> expected = {0xfb, 0xff, 0xff};
                REQUIRE(decoded == expected);
            }
        }
    }
}

TEST_CASE("Base64Url decodes binary data correctly", "[base64url][decoding]")
{
    vector<unsigned char> original = {0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b};
    string encoded = Base64Url::encode(original);
    vector<unsigned char> decoded = Base64Url::decode(encoded);
    REQUIRE(original == decoded);
}

// BDD-style round-trip tests
SCENARIO("Base64Url encoding and decoding are reversible", "[base64url][round-trip][bdd]")
{
    GIVEN("various types of data")
    {
        WHEN("encoding and decoding a text string")
        {
            string original = "The quick brown fox jumps over the lazy dog";
            string encoded = Base64Url::encode(original);
            string decoded = Base64Url::decodeToString(encoded);

            THEN("the decoded string should match the original")
            {
                REQUIRE(decoded == original);
            }
        }

        WHEN("encoding and decoding a byte vector")
        {
            vector<unsigned char> original = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21};
            string encoded = Base64Url::encode(original);
            vector<unsigned char> decoded = Base64Url::decode(encoded);

            THEN("the decoded vector should match the original")
            {
                REQUIRE(decoded == original);
            }
        }

        WHEN("encoding and decoding all byte values")
        {
            vector<unsigned char> original;
            for (int i = 0; i < 256; i++)
            {
                original.push_back(static_cast<unsigned char>(i));
            }
            string encoded = Base64Url::encode(original);
            vector<unsigned char> decoded = Base64Url::decode(encoded);

            THEN("all bytes should be preserved")
            {
                REQUIRE(decoded == original);
            }
        }

        WHEN("encoding and decoding UTF-8 text")
        {
            string original = "Hello 世界 🌍";
            string encoded = Base64Url::encode(original);
            string decoded = Base64Url::decodeToString(encoded);

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
    string original(10000, 'A');
    string encoded = Base64Url::encode(original);
    string decoded = Base64Url::decodeToString(encoded);
    REQUIRE(original == decoded);
}

TEST_CASE("Base64Url handles single byte", "[base64url][edge-cases]")
{
    vector<unsigned char> original = {0x42};
    string encoded = Base64Url::encode(original);
    vector<unsigned char> decoded = Base64Url::decode(encoded);
    REQUIRE(original == decoded);
}

TEST_CASE("Base64Url handles two bytes", "[base64url][edge-cases]")
{
    vector<unsigned char> original = {0x42, 0x43};
    string encoded = Base64Url::encode(original);
    vector<unsigned char> decoded = Base64Url::decode(encoded);
    REQUIRE(original == decoded);
}

TEST_CASE("Base64Url handles three bytes", "[base64url][edge-cases]")
{
    vector<unsigned char> original = {0x42, 0x43, 0x44};
    string encoded = Base64Url::encode(original);
    vector<unsigned char> decoded = Base64Url::decode(encoded);
    REQUIRE(original == decoded);
}

TEST_CASE("Base64Url never contains + or /", "[base64url][invariants]")
{
    vector<unsigned char> input;
    for (int i = 0; i < 256; i++)
    {
        input.push_back(static_cast<unsigned char>(i));
    }
    string encoded = Base64Url::encode(input);
    REQUIRE(encoded.find('+') == string::npos);
    REQUIRE(encoded.find('/') == string::npos);
}

TEST_CASE("Base64Url never contains padding", "[base64url][invariants]")
{
    vector<unsigned char> input1 = {0x42};
    string encoded1 = Base64Url::encode(input1);
    REQUIRE(encoded1.find('=') == string::npos);

    vector<unsigned char> input2 = {0x42, 0x43};
    string encoded2 = Base64Url::encode(input2);
    REQUIRE(encoded2.find('=') == string::npos);
}

// RFC 7515 test vectors
TEST_CASE("Base64Url RFC7515 Appendix C example", "[base64url][rfc7515]")
{
    string payload =
        "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
    string encoded = Base64Url::encode(payload);
    string expected = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmN"
                      "vbS9pc19yb290Ijp0cnVlfQ";
    REQUIRE(encoded == expected);

    string decoded = Base64Url::decodeToString(encoded);
    REQUIRE(decoded == payload);
}
