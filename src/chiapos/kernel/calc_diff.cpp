#include "calc_diff.h"

#include <arith_uint256.h>
#include <crypto/sha256.h>

#include <cmath>
#include <cstdint>
#include <limits>

#include "pos.h"
#include "utils.h"

namespace chiapos {

namespace {

template <typename Int>
Int expected_plot_size(uint8_t k) {
    Int a = 2;
    a = a * k + 1;
    Int b = (Int)1 << (k - 1);
    return a * b;
}

arith_uint256 lower_bits(uint256 const& quality_string, int bits) {
    return UintToArith256(quality_string) & (Pow2(bits) - 1);
}

}  // namespace

using QualityBaseType = uint32_t;
constexpr int QualityBaseBits = sizeof(QualityBaseType) * 8;

constexpr double DIFFICULTY_CHANGE_MAX_FACTOR = 1.5;
constexpr double UI_ACTUAL_SPACE_CONSTANT_FACTOR = 0.762;

arith_uint256 Pow2(int bits) { return arith_uint256(1) << bits; }

uint64_t AdjustDifficulty(uint64_t prev_block_difficulty, uint64_t curr_block_duration, uint64_t target_duration) {
    assert(curr_block_duration > 0);
    uint64_t new_difficulty = prev_block_difficulty / curr_block_duration * target_duration;
    if (new_difficulty > prev_block_difficulty) {
        uint64_t max_difficulty = prev_block_difficulty * DIFFICULTY_CHANGE_MAX_FACTOR;
        new_difficulty = std::min(new_difficulty, max_difficulty);
    } else {
        uint64_t min_difficulty = prev_block_difficulty / DIFFICULTY_CHANGE_MAX_FACTOR;
        new_difficulty = std::max(new_difficulty, min_difficulty);
    }
    return std::max<uint64_t>(new_difficulty, 1);
}

uint256 GenerateMixedQualityString(CPosProof const& posProof) {
    PubKeyOrHash poolPkOrHash =
            MakePubKeyOrHash(static_cast<PlotPubKeyType>(posProof.nPlotType), posProof.vchPoolPkOrHash);
    return chiapos::MakeMixedQualityString(MakeArray<PK_LEN>(posProof.vchLocalPk),
                                           MakeArray<PK_LEN>(posProof.vchFarmerPk), poolPkOrHash, posProof.nPlotK,
                                           posProof.challenge, posProof.vchProof);
}

uint64_t CalculateIterationsQuality(uint256 const& mixed_quality_string, uint64_t difficulty,
                                    int difficulty_constant_factor_bits, uint8_t k, uint64_t base_iters,
                                    double* quality_in_plot, arith_uint256* quality) {
    assert(difficulty > 0);
    auto l = lower_bits(mixed_quality_string, QualityBaseBits);
    auto h = Pow2(QualityBaseBits);
    auto size = expected_plot_size<arith_uint256>(k);
    auto iters = difficulty * Pow2(difficulty_constant_factor_bits) * l / (size * h) + base_iters;
    if (quality_in_plot) {
        *quality_in_plot = static_cast<double>(l.GetLow64()) / static_cast<double>(h.GetLow64());
    }
    if (quality) {
        *quality = size * h / l;
    }
    if (iters > Pow2(64)) {
        return std::numeric_limits<uint64_t>::max();
    }
    return std::max<uint64_t>(iters.GetLow64(), 1);
}

arith_uint256 CalculateNetworkSpace(uint64_t difficulty, uint64_t iters, int difficulty_constant_factor_bits,
                                    int bits_of_filter) {
    arith_uint256 diff_iters = static_cast<double>(difficulty) / iters * UI_ACTUAL_SPACE_CONSTANT_FACTOR;
    arith_uint256 additional_difficulty_constant = Pow2(difficulty_constant_factor_bits);
    arith_uint256 eligible_plots_filter_multiplier = Pow2(bits_of_filter);
    return diff_iters * additional_difficulty_constant * eligible_plots_filter_multiplier;
}

}  // namespace chiapos
