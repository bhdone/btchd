#include <compat/byteswap.h>

#ifndef HAVE_BYTESWAP_H

uint16_t __bswap_16(uint16_t x) { return (x >> 8) | (x << 8); }

uint32_t __bswap_32(uint32_t x)
{
    return (
        ((x & 0xff000000U) >> 24) | ((x & 0x00ff0000U) >> 8) | ((x & 0x0000ff00U) << 8) | ((x & 0x000000ffU) << 24));
}

uint64_t __bswap_64(uint64_t x)
{
    return (((x & 0xff00000000000000ull) >> 56) | ((x & 0x00ff000000000000ull) >> 40) |
            ((x & 0x0000ff0000000000ull) >> 24) | ((x & 0x000000ff00000000ull) >> 8) |
            ((x & 0x00000000ff000000ull) << 8) | ((x & 0x0000000000ff0000ull) << 24) |
            ((x & 0x000000000000ff00ull) << 40) | ((x & 0x00000000000000ffull) << 56));
}

#endif
