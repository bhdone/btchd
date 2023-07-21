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

arith_uint256 lower_bits(uint256 const& quality_string, int bits) {
    return UintToArith256(quality_string) & (Pow2(bits) - 1);
}

}  // namespace

using QualityBaseType = uint32_t;
constexpr int QUALITY_BASE_BITS = sizeof(QualityBaseType) * 8;

arith_uint256 Pow2(int bits) { return arith_uint256(1) << bits; }

uint64_t AdjustDifficulty(uint64_t prev_block_difficulty, uint64_t curr_block_duration, uint64_t target_duration,
                          int duration_fix, double max_factor, uint64_t network_min_difficulty) {
    assert(curr_block_duration > 0);
    uint64_t n = std::max<uint64_t>(prev_block_difficulty / curr_block_duration, 1);
    uint64_t new_difficulty = std::max(n * (target_duration + duration_fix), network_min_difficulty);
    if (new_difficulty > prev_block_difficulty) {
        uint64_t max_difficulty = prev_block_difficulty * max_factor;
        new_difficulty = std::min(new_difficulty, max_difficulty);
    } else {
        uint64_t min_difficulty = prev_block_difficulty / max_factor;
        new_difficulty = std::max(new_difficulty, min_difficulty);
    }
    return std::max<uint64_t>(new_difficulty, 1);
}

int QueryDurationFix(int curr_height, std::map<int, int> const& fixes) {
    int height { 0 };
    int duration_fix { 0 };
    for (auto const& fix : fixes) {
        if (fix.first < curr_height && fix.first > height) {
            height = fix.first;
            duration_fix = fix.second;
        }
    }
    return duration_fix;
}

uint256 GenerateMixedQualityString(CPosProof const& posProof) {
    PubKeyOrHash poolPkOrHash =
            MakePubKeyOrHash(static_cast<PlotPubKeyType>(posProof.nPlotType), posProof.vchPoolPkOrHash);
    return chiapos::MakeMixedQualityString(MakeArray<PK_LEN>(posProof.vchLocalPk),
                                           MakeArray<PK_LEN>(posProof.vchFarmerPk), poolPkOrHash, posProof.nPlotK,
                                           posProof.challenge, posProof.vchProof);
}

double CalculateQuality(uint256 const& mixed_quality_string) {
    auto l = lower_bits(mixed_quality_string, QUALITY_BASE_BITS);
    auto h = Pow2(QUALITY_BASE_BITS);
    return static_cast<double>(l.GetLow64()) / static_cast<double>(h.GetLow64());
}

uint64_t CalculateIterationsQuality(uint256 const& mixed_quality_string, uint64_t difficulty, int bits_filter,
                                    int difficulty_constant_factor_bits, uint8_t k, uint64_t base_iters,
                                    double* quality_in_plot, arith_uint256* quality) {
    assert(difficulty > 0);
    auto l = lower_bits(mixed_quality_string, QUALITY_BASE_BITS);
    auto h = Pow2(QUALITY_BASE_BITS);
    auto size = expected_plot_size<arith_uint256>(k);
    auto iters = difficulty * Pow2(difficulty_constant_factor_bits) * l / Pow2(bits_filter) / (size * h) + base_iters;
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

arith_uint256 CalculateNetworkSpace(uint64_t difficulty, uint64_t iters, int difficulty_constant_factor_bits) {
    arith_uint256 additional_difficulty_constant = Pow2(difficulty_constant_factor_bits);
    return arith_uint256(difficulty) / iters * additional_difficulty_constant * UI_ACTUAL_SPACE_CONSTANT_FACTOR /
           UI_ACTUAL_SPACE_CONSTANT_FACTOR_BASE;
}

}  // namespace chiapos
