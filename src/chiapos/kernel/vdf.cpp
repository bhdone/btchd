#include "vdf.h"

#include <logging.h>
#include <util/system.h>
#include <vdf_computer.h>

#include <atomic>
#include <chrono>
#include <map>
#include <thread>

#include "utils.h"

namespace chiapos {

VdfForm MakeZeroForm() {
    VdfForm form;
    memset(form.data(), 0, form.size());
    form[0] = 0x08;
    return form;
}

VdfForm MakeVDFForm(Bytes const& vchData) { return MakeArray<VDF_FORM_SIZE>(vchData); }

uint256 MakeChallenge(uint256 const& challenge, Bytes const& proof) {
    CSHA256 sha;
    sha.Write(challenge.begin(), challenge.size());
    sha.Write(proof.data(), proof.size());

    uint256 res;
    sha.Finalize(res.begin());
    return res;
}

std::tuple<uint64_t, uint64_t> CountVDFItersAndDuration(CBlockFields const& fields) {
    uint64_t nIters = fields.vdfProof.nVdfIters, nDuration = fields.vdfProof.nVdfDuration;
    for (CVdfProof const& vdf : fields.vVoidBlockVdf) {
        nIters += vdf.nVdfIters;
        nDuration += vdf.nVdfDuration;
    }
    return std::make_tuple(nIters, nDuration);
}

uint64_t CalculateVDFItersPerSecond(CBlockFields const& fields, uint64_t nDefaultIters) {
    uint64_t nIters, nDuration;
    std::tie(nIters, nDuration) = CountVDFItersAndDuration(fields);
    return CalculateVDFItersPerSecond(nIters, nDuration, nDefaultIters);
}

uint64_t CalculateVDFItersPerSecond(uint64_t nIters, uint64_t nDuration, uint64_t nDefaultIters) {
    if (nDuration == 0) {
        // Avoid division by zero, just simply return the iters
        return nIters;
    }
    uint64_t nIters2 = nIters / nDuration;
    if (nIters2 == 0) {
        return nDefaultIters;
    }
    return nIters2;
}

bool VerifyItersWithDuration(uint64_t nIters, uint64_t nDuration, uint64_t nItersPerSec) {
    assert(nItersPerSec > 0);
    return nIters / nItersPerSec == nDuration;
}

bool VerifyVdf(uint256 const& challenge, VdfForm const& x, uint64_t nIters, VdfForm const& y, Bytes const& proof,
               uint8_t nWitnessType) {
    Bytes vchVerifyProof = BytesConnector::Connect(y, proof);
    auto D = vdf::utils::CreateDiscriminant(MakeBytes(challenge));
    return vdf::utils::VerifyProof(D, vchVerifyProof, nIters, nWitnessType, MakeBytes(x));
}

}  // namespace chiapos
