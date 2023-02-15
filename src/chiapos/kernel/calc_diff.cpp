#include "calc_diff.h"

#include <arith_uint256.h>
#include <crypto/sha256.h>

#include <cmath>
#include <cstdint>
#include <limits>

#include "pos.h"
#include "utils.h"

namespace chiapos {

int const QUALITY_BASE_BITS = 32;

arith_uint256 Pow2(int bits) { return arith_uint256(1) << bits; }

uint64_t AdjustDifficulty(uint64_t prev_block_difficulty, uint64_t curr_block_duration, uint64_t target_duration) {
    assert(curr_block_duration > 0);
    uint64_t new_difficulty = prev_block_difficulty / curr_block_duration * target_duration;
    return std::max<uint64_t>(new_difficulty, 1);
}

arith_uint256 LimitQualityStringBits(uint256 const& quality_string, int bits) {
    return UintToArith256(quality_string) & (Pow2(bits) - 1);
}

uint64_t CalculateIterationsQuality(uint256 const& mixed_quality_string, uint8_t k, uint64_t difficulty,
                                    int difficulty_constant_factor_bits) {
    assert(difficulty > 0);
    uint64_t quality = CalculateQuality(mixed_quality_string, k);
    auto iters = arith_uint256(difficulty) * Pow2(difficulty_constant_factor_bits) / quality;
    assert(iters <= std::numeric_limits<uint64_t>::max());
    return std::max<uint64_t>(iters.GetLow64(), 1);
}

arith_uint256 CalculateNetworkSpace(uint64_t difficulty, uint64_t iters, int difficulty_constant_factor_bits,
                                    int bits_of_filter) {
    arith_uint256 additional_difficulty_constant = Pow2(difficulty_constant_factor_bits + 3);
    arith_uint256 eligible_plots_filter_multiplier = Pow2(bits_of_filter);
    return difficulty * additional_difficulty_constant * eligible_plots_filter_multiplier / iters;
}

uint64_t CalculateQuality(uint256 const& mixed_quality_string, uint8_t k) {
    arith_uint256 quality = LimitQualityStringBits(mixed_quality_string, QUALITY_BASE_BITS) *
                            calc::expected_plot_size<arith_uint256>(k) / Pow2(QUALITY_BASE_BITS);
    assert(quality <= std::numeric_limits<uint64_t>::max());
    return std::max<uint64_t>(quality.GetLow64(), 1);
}

uint64_t CalculateQuality(CPosProof const& posProof) {
    PubKeyOrHash poolPkOrHash =
            MakePubKeyOrHash(static_cast<PlotPubKeyType>(posProof.nPlotType), posProof.vchPoolPkOrHash);
    uint256 mixed_quality_string = chiapos::MakeMixedQualityString(
            MakeArray<PK_LEN>(posProof.vchLocalPk), MakeArray<PK_LEN>(posProof.vchFarmerPk), poolPkOrHash,
            posProof.nPlotK, posProof.challenge, posProof.vchProof);
    return CalculateQuality(mixed_quality_string, posProof.nPlotK);
}

}  // namespace chiapos
