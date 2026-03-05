#pragma once

#include <bit>
#include <cstdint>

namespace Vlinder {
namespace JOSE {
namespace Private {

// Endian-agnostic helpers for 32-bit values. Functions are inline so they
// can live in the header without violating the ODR.

// Prefer a constexpr detection when the platform exposes byte-order macros
inline constexpr bool hostIsLittleEndian()
{
    if constexpr (std::endian::native == std::endian::little)
    {
        return true;
    }
    if constexpr (std::endian::native == std::endian::big)
    {
        return false;
    }

    // Mixed-endian targets are outside supported scope for this library.
    return false;
}

inline uint32_t byteSwap32(uint32_t v)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(v);
#else
    return ((v & 0x000000FFU) << 24) | ((v & 0x0000FF00U) << 8) |
           ((v & 0x00FF0000U) >> 8) | ((v & 0xFF000000U) >> 24);
#endif
}

// Convert host-order to network-order (big-endian)
inline uint32_t toNetworkEndian(uint32_t value)
{
    return hostIsLittleEndian() ? byteSwap32(value) : value;
}

inline uint32_t toBigEndian(uint32_t value)
{
    return toNetworkEndian(value);
}

// Convert network-order (big-endian) to host-order
inline uint32_t toHostEndian(uint32_t value)
{
    return hostIsLittleEndian() ? byteSwap32(value) : value;
}

}  // namespace Private
}  // namespace JOSE
}  // namespace Vlinder
