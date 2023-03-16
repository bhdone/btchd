#ifndef BTCHD_CHIAPOS_KERNEL_CALC_DIFF_H
#define BTCHD_CHIAPOS_KERNEL_CALC_DIFF_H

#include <arith_uint256.h>
#include <chiapos/block_fields.h>
#include <uint256.h>

#include <cstdint>

namespace chiapos {

// K between 25 and 50
int const MIN_K_TEST_NET = 25;
int const MIN_K = 25;
int const MAX_K = 50;

int const NUMBER_OF_ZEROS_BITS_FOR_FILTER = 9;
int const NUMBER_OF_ZEROS_BITS_FOR_FILTER_TESTNET = 0;

int const DIFFICULTY_CONSTANT_FACTOR_BITS = 67;

arith_uint256 Pow2(int bits);

uint64_t AdjustDifficulty(uint64_t prev_block_difficulty, uint64_t curr_block_duration, uint64_t target_duration);

uint256 GenerateMixedQualityString(CPosProof const& posProof);

uint64_t CalculateIterationsQuality(uint256 const& mixed_quality_string, uint64_t difficulty, int difficulty_constant_factor_bits, uint8_t k);

arith_uint256 CalculateNetworkSpace(uint64_t difficulty, uint64_t iters, int difficulty_constant_factor_bits, int bits_of_filter);

}  // namespace chiapos

#endif
