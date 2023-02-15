// Copyright (c) 2014-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPAT_BYTESWAP2_H
#define BITCOIN_COMPAT_BYTESWAP2_H

#include <stdint.h>

// Note: The byteorder functions are replaced by using the byte order functions from library `chiapos`
// the following 3 functions are just a backup

uint16_t __bswap_16(uint16_t x);

uint32_t __bswap_32(uint32_t x);

uint64_t __bswap_64(uint64_t x);

#endif // BITCOIN_COMPAT_BYTESWAP_H
