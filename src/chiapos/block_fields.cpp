#include "block_fields.h"

#include <chiapos/kernel/pos.h>
#include <chiapos/kernel/utils.h>
#include <chiapos/post.h>

namespace chiapos {

void CPosProof::SetNull() {
    challenge.SetNull();
    vchPoolPkOrHash.clear();
    vchLocalPk.clear();
    vchFarmerPk.clear();
    nPlotType = 0;
    nPlotK = 0;
    vchProof.clear();
}

bool CPosProof::IsNull() const {
    return challenge.IsNull() && vchPoolPkOrHash.empty() && vchLocalPk.empty() && vchFarmerPk.empty() && nPlotType == 0 && nPlotK == 0 && vchProof.empty();
}

void CVdfProof::SetNull() {
    challenge.SetNull();
    vchY.clear();
    vchProof.clear();
    nWitnessType = 0;
    nVdfIters = 0;
    nVdfDuration = 0;
}

bool CVdfProof::IsNull() const {
    return challenge.IsNull() && vchY.empty() && vchProof.empty() && nWitnessType == 0 && nVdfIters == 0 && nVdfDuration == 0;
}

void CBlockFields::SetNull() {
    nDifficulty = 0;
    posProof.SetNull();
    vdfProof.SetNull();
    vchFarmerSignature.clear();
}

bool CBlockFields::IsNull() const {
    return nDifficulty == 0 && posProof.IsNull() && vdfProof.IsNull() && vchFarmerSignature.empty();
}

}  // namespace chiapos
