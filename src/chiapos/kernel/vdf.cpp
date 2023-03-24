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

bool VerifyVdf(uint256 const& challenge, VdfForm const& x, uint64_t nIters, VdfForm const& y, Bytes const& proof,
               uint8_t nWitnessType) {
    Bytes vchVerifyProof = BytesConnector::Connect(y, proof);
    auto D = vdf::utils::CreateDiscriminant(MakeBytes(challenge));
    return vdf::utils::VerifyProof(D, vchVerifyProof, nIters, nWitnessType, MakeBytes(x));
}

}  // namespace chiapos
