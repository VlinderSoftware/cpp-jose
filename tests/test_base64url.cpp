#include "jose/jose.hpp"

#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace Vlinder::jose;

class Base64UrlTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

// Basic encoding tests
TEST_F(Base64UrlTest, EncodeEmptyString)
{
    std::string input = "";
    std::string encoded = Base64Url::encode(input);
    EXPECT_EQ("", encoded);
}

TEST_F(Base64UrlTest, EncodeEmptyVector)
{
    std::vector<unsigned char> input;
    std::string encoded = Base64Url::encode(input);
    EXPECT_EQ("", encoded);
}

TEST_F(Base64UrlTest, EncodeSimpleString)
{
    std::string input = "hello";
    std::string encoded = Base64Url::encode(input);
    EXPECT_EQ("aGVsbG8", encoded);
}

TEST_F(Base64UrlTest, EncodeWithPaddingRemoved)
{
    // "Man" in base64 is "TWFu" (no padding needed)
    std::string input = "Man";
    std::string encoded = Base64Url::encode(input);
    EXPECT_EQ("TWFu", encoded);

    // "Ma" in base64 would be "TWE=" but base64url removes padding
    input = "Ma";
    encoded = Base64Url::encode(input);
    EXPECT_EQ("TWE", encoded);

    // "M" in base64 would be "TQ==" but base64url removes padding
    input = "M";
    encoded = Base64Url::encode(input);
    EXPECT_EQ("TQ", encoded);
}

TEST_F(Base64UrlTest, EncodeSpecialCharacters)
{
    // Base64url uses '-' instead of '+' and '_' instead of '/'
    std::vector<unsigned char> input = {0xfb, 0xff, 0xff};
    std::string encoded = Base64Url::encode(input);
    // Standard base64: "+///", base64url: "-___"
    EXPECT_EQ("-___", encoded);
}

TEST_F(Base64UrlTest, EncodeBinaryData)
{
    std::vector<unsigned char> input = {0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd};
    std::string encoded = Base64Url::encode(input);
    std::vector<unsigned char> decoded = Base64Url::decode(encoded);
    EXPECT_EQ(input, decoded);
}

TEST_F(Base64UrlTest, EncodeRFC7515Example)
{
    // From RFC 7515 Appendix A.1
    std::string input = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
    std::string encoded = Base64Url::encode(input);
    EXPECT_EQ("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9", encoded);
}

// Basic decoding tests
TEST_F(Base64UrlTest, DecodeEmptyString)
{
    std::string input = "";
    std::vector<unsigned char> decoded = Base64Url::decode(input);
    EXPECT_TRUE(decoded.empty());
}

TEST_F(Base64UrlTest, DecodeToStringEmpty)
{
    std::string input = "";
    std::string decoded = Base64Url::decodeToString(input);
    EXPECT_EQ("", decoded);
}

TEST_F(Base64UrlTest, DecodeSimpleString)
{
    std::string encoded = "aGVsbG8";
    std::string decoded = Base64Url::decodeToString(encoded);
    EXPECT_EQ("hello", decoded);
}

TEST_F(Base64UrlTest, DecodeWithMissingPadding)
{
    // Base64url should handle missing padding
    std::string encoded1 = "TWE";  // "Ma" with padding removed
    std::string decoded1 = Base64Url::decodeToString(encoded1);
    EXPECT_EQ("Ma", decoded1);

    std::string encoded2 = "TQ";  // "M" with padding removed
    std::string decoded2 = Base64Url::decodeToString(encoded2);
    EXPECT_EQ("M", decoded2);
}

TEST_F(Base64UrlTest, DecodeSpecialCharacters)
{
    std::string encoded = "-___";
    std::vector<unsigned char> decoded = Base64Url::decode(encoded);
    std::vector<unsigned char> expected = {0xfb, 0xff, 0xff};
    EXPECT_EQ(expected, decoded);
}

TEST_F(Base64UrlTest, DecodeBinaryData)
{
    std::vector<unsigned char> original = {0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b};
    std::string encoded = Base64Url::encode(original);
    std::vector<unsigned char> decoded = Base64Url::decode(encoded);
    EXPECT_EQ(original, decoded);
}

// Round-trip tests
TEST_F(Base64UrlTest, RoundTripString)
{
    std::string original = "The quick brown fox jumps over the lazy dog";
    std::string encoded = Base64Url::encode(original);
    std::string decoded = Base64Url::decodeToString(encoded);
    EXPECT_EQ(original, decoded);
}

TEST_F(Base64UrlTest, RoundTripVector)
{
    std::vector<unsigned char> original = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21};
    std::string encoded = Base64Url::encode(original);
    std::vector<unsigned char> decoded = Base64Url::decode(encoded);
    EXPECT_EQ(original, decoded);
}

TEST_F(Base64UrlTest, RoundTripAllByteValues)
{
    std::vector<unsigned char> original;
    for (int i = 0; i < 256; i++)
    {
        original.push_back(static_cast<unsigned char>(i));
    }
    std::string encoded = Base64Url::encode(original);
    std::vector<unsigned char> decoded = Base64Url::decode(encoded);
    EXPECT_EQ(original, decoded);
}

TEST_F(Base64UrlTest, RoundTripUTF8)
{
    std::string original = "Hello 世界 🌍";
    std::string encoded = Base64Url::encode(original);
    std::string decoded = Base64Url::decodeToString(encoded);
    EXPECT_EQ(original, decoded);
}

// Edge cases
TEST_F(Base64UrlTest, LongString)
{
    std::string original(10000, 'A');
    std::string encoded = Base64Url::encode(original);
    std::string decoded = Base64Url::decodeToString(encoded);
    EXPECT_EQ(original, decoded);
}

TEST_F(Base64UrlTest, SingleByte)
{
    std::vector<unsigned char> original = {0x42};
    std::string encoded = Base64Url::encode(original);
    std::vector<unsigned char> decoded = Base64Url::decode(encoded);
    EXPECT_EQ(original, decoded);
}

TEST_F(Base64UrlTest, TwoBytes)
{
    std::vector<unsigned char> original = {0x42, 0x43};
    std::string encoded = Base64Url::encode(original);
    std::vector<unsigned char> decoded = Base64Url::decode(encoded);
    EXPECT_EQ(original, decoded);
}

TEST_F(Base64UrlTest, ThreeBytes)
{
    std::vector<unsigned char> original = {0x42, 0x43, 0x44};
    std::string encoded = Base64Url::encode(original);
    std::vector<unsigned char> decoded = Base64Url::decode(encoded);
    EXPECT_EQ(original, decoded);
}

TEST_F(Base64UrlTest, NoPlusOrSlash)
{
    // Verify that encoded strings never contain '+' or '/'
    std::vector<unsigned char> input;
    for (int i = 0; i < 256; i++)
    {
        input.push_back(static_cast<unsigned char>(i));
    }
    std::string encoded = Base64Url::encode(input);
    EXPECT_EQ(std::string::npos, encoded.find('+'));
    EXPECT_EQ(std::string::npos, encoded.find('/'));
}

TEST_F(Base64UrlTest, NoPadding)
{
    // Verify that encoded strings never contain '='
    std::vector<unsigned char> input1 = {0x42};
    std::string encoded1 = Base64Url::encode(input1);
    EXPECT_EQ(std::string::npos, encoded1.find('='));

    std::vector<unsigned char> input2 = {0x42, 0x43};
    std::string encoded2 = Base64Url::encode(input2);
    EXPECT_EQ(std::string::npos, encoded2.find('='));
}

// RFC 7515 test vectors
TEST_F(Base64UrlTest, RFC7515AppendixC)
{
    // Example from RFC 7515 Appendix C
    std::string payload =
        "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
    std::string encoded = Base64Url::encode(payload);
    std::string expected = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmN"
                           "vbS9pc19yb290Ijp0cnVlfQ";
    EXPECT_EQ(expected, encoded);

    std::string decoded = Base64Url::decodeToString(encoded);
    EXPECT_EQ(payload, decoded);
}
