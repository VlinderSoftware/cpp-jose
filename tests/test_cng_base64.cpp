#include <catch2/catch_test_macros.hpp>

#include "../src/private/cng_back_end.hpp"

using namespace std;

using namespace Vlinder::JOSE::Private;

TEST_CASE("CNGBackEnd base64 encode/decode")
{
    CNGBackEnd backend;
    vector<unsigned char> const data = {'h', 'e', 'l', 'l', 'o'};
    string enc = backend.base64Encode(data);
    REQUIRE(enc == "aGVsbG8=");

    auto dec = backend.base64Decode(enc);
    REQUIRE(dec == data);
}

TEST_CASE("CNGBackEnd base64 decode ignores newlines")
{
    CNGBackEnd backend;
    string enc = "aGVs\r\nbG8=";  // contains CRLF
    auto dec = backend.base64Decode(enc);
    vector<unsigned char> expected = {'h', 'e', 'l', 'l', 'o'};
    REQUIRE(dec == expected);
}

TEST_CASE("CNGBackEnd base64 empty inputs")
{
    CNGBackEnd backend;
    vector<unsigned char> const empty_data{};
    string enc = backend.base64Encode(empty_data);
    REQUIRE(enc.empty());

    auto dec = backend.base64Decode(string());
    REQUIRE(dec.empty());
}
