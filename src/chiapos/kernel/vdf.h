#ifndef BTCHD_CHIAPOS_VDF_H
#define BTCHD_CHIAPOS_VDF_H

#include <chiapos/block_fields.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <functional>
#include <tuple>

#include "chiapos_types.h"

namespace chiapos {

constexpr int VDF_FORM_SIZE = 100;

using VdfForm = std::array<uint8_t, VDF_FORM_SIZE>;

VdfForm MakeZeroForm();

VdfForm MakeVDFForm(Bytes const& vchData);

uint256 MakeChallenge(uint256 const& hashBlock, Bytes const& proof);

std::tuple<uint64_t, uint64_t> CountVDFItersAndDuration(CBlockFields const& fields);

uint64_t CalculateVDFItersPerSecond(CBlockFields const& fields, uint64_t nDefaultIters);

uint64_t CalculateVDFItersPerSecond(uint64_t nIters, uint64_t nDuration, uint64_t nDefaultIters);

bool VerifyItersWithDuration(uint64_t nIters, uint64_t nDuration, uint64_t nItersPerSec);

bool VerifyVdf(uint256 const& challenge, VdfForm const& x, uint64_t nIters, VdfForm const& y, Bytes const& proof,
               uint8_t nWitnessType);

}  // namespace chiapos

#endif
