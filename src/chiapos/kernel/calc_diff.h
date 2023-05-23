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
int const NUMBER_OF_ZEROS_BITS_FOR_FILTER_TESTNET = 3;

constexpr double DIFFICULTY_CHANGE_MAX_FACTOR = 3;
constexpr double UI_ACTUAL_SPACE_CONSTANT_FACTOR = 0.762;

int const DIFFICULTY_CONSTANT_FACTOR_BITS = 35;

arith_uint256 Pow2(int bits);

template <typename Int>
Int expected_plot_size(uint8_t k) {
    Int a = 2;
    a = a * k + 1;
    Int b = (Int)1 << (k - 1);
    return a * b;
}

uint64_t AdjustDifficulty(uint64_t prev_block_difficulty, uint64_t curr_block_duration, uint64_t target_duration,
                          double max_factor, uint64_t min_difficulty);

uint256 GenerateMixedQualityString(CPosProof const& posProof);

uint64_t CalculateIterationsQuality(uint256 const& mixed_quality_string, uint64_t difficulty, int bits_filter,
                                    int difficulty_constant_factor_bits, uint8_t k, uint64_t base_iters,
                                    double* quality_in_plot = nullptr, arith_uint256* quality = nullptr);

arith_uint256 CalculateNetworkSpace(uint64_t difficulty, uint64_t iters, int difficulty_constant_factor_bits,
                                    int bits_filter);

}  // namespace chiapos

#endif
