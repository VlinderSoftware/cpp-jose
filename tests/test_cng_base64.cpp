#include "../src/private/cng_back_end.hpp"
#include <catch2/catch_test_macros.hpp>

using namespace Vlinder::JOSE::Private;

TEST_CASE("CNGBackEnd base64 encode/decode")
{
    CNGBackEnd backend;
    std::vector<unsigned char> const data = { 'h', 'e', 'l', 'l', 'o' };
    std::string enc = backend.base64Encode(data);
    REQUIRE(enc == "aGVsbG8=");

    auto dec = backend.base64Decode(enc);
    REQUIRE(dec == data);
}

TEST_CASE("CNGBackEnd base64 decode ignores newlines")
{
    CNGBackEnd backend;
    std::string enc = "aGVs\r\nbG8="; // contains CRLF
    auto dec = backend.base64Decode(enc);
    std::vector<unsigned char> expected = { 'h', 'e', 'l', 'l', 'o' };
    REQUIRE(dec == expected);
}

TEST_CASE("CNGBackEnd base64 empty inputs")
{
    CNGBackEnd backend;
    std::vector<unsigned char> const empty_data{};
    std::string enc = backend.base64Encode(empty_data);
    REQUIRE(enc.empty());

    auto dec = backend.base64Decode(std::string());
    REQUIRE(dec.empty());
}
