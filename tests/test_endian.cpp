#include <catch2/catch_test_macros.hpp>

#include "../src/private/endian.hpp"

using namespace std;

using namespace Vlinder::JOSE::Private;

TEST_CASE("byteSwap32 inverts byte order")
{
    uint32_t v = 0x11223344u;
    REQUIRE(byteSwap32(v) == 0x44332211u);
    REQUIRE(byteSwap32(byteSwap32(v)) == v);
}

TEST_CASE("toNetworkEndian and toHostEndian are round-trip")
{
    uint32_t v = 0x01020304u;
    uint32_t net = toNetworkEndian(v);
    uint32_t host = toHostEndian(net);
    REQUIRE(host == v);
}

TEST_CASE("toNetworkEndian produces big-endian representation")
{
    uint32_t v = 0x0A0B0C0Du;
    union
    {
        uint32_t value;
        unsigned char bytes[4];
    } net;
    net.value = toNetworkEndian(v);
    REQUIRE(net.bytes[0] == 0x0A);
    REQUIRE(net.bytes[1] == 0x0B);
    REQUIRE(net.bytes[2] == 0x0C);
    REQUIRE(net.bytes[3] == 0x0D);
}
