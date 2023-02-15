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

void CVdfProof::SetNull() {
    challenge.SetNull();
    vchY.clear();
    vchProof.clear();
    nWitnessType = 0;
    nVdfIters = 0;
    nVdfDuration = 0;
}

void CBlockFields::SetNull() {
    nDifficulty = 0;
    posProof.SetNull();
    vdfProof.SetNull();
    vVoidBlockVdf.clear();
    vchFarmerSignature.clear();
}

bool CBlockFields::IsNull() const {
    return vchFarmerSignature.empty() && posProof.vchProof.empty() && posProof.nPlotK == 0 &&
           posProof.challenge.IsNull() && vdfProof.challenge.IsNull() && vdfProof.vchProof.empty();
}

}  // namespace chiapos
