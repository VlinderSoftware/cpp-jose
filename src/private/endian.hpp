#pragma once

#include <cstdint>

namespace Vlinder {
namespace JOSE {
namespace Private {

// Endian-agnostic helpers for 32-bit values. Functions are inline so they
// can live in the header without violating the ODR.

// Prefer a constexpr detection when the platform exposes byte-order macros
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
    (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
inline constexpr bool hostIsLittleEndian() { return true; }
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
inline constexpr bool hostIsLittleEndian() { return false; }
#elif defined(_WIN32)
// Windows on supported architectures is little-endian
inline constexpr bool hostIsLittleEndian() { return true; }
#else
// Fallback runtime check when compile-time macros are not available.
inline bool hostIsLittleEndian()
{
    uint32_t x = 1;
    return *reinterpret_cast<unsigned char const *>(&x) == 1;
}
#endif

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
