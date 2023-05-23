#ifndef BTCHD_CHIAPOS_BLOCK_FIELDS_H
#define BTCHD_CHIAPOS_BLOCK_FIELDS_H

#include <chiapos/kernel/bls_key.h>
#include <chiapos/kernel/chiapos_types.h>
#include <serialize.h>
#include <uint256.h>

#include <functional>
#include <vector>

namespace chiapos {

const uint64_t CHIAHEADER_VERSION = 0x107;

class CPosProof {
public:
    uint256 challenge;  // The challenge for PoS

    // The following fields will be used to make PlotID
    Bytes vchPoolPkOrHash;  // Pool public-key (48-byte) or pool contract puzzle hash (32-byte)
    Bytes vchLocalPk;
    Bytes vchFarmerPk;
    uint8_t nPlotType;  // 0 - OGPlot; 1 - PooledPlots

    uint8_t nPlotK;  // The size of the plot
    Bytes vchProof;  // The final proof for the space

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(challenge);

        READWRITE(vchPoolPkOrHash);
        READWRITE(LIMITED_VECTOR(vchLocalPk, PK_LEN));
        READWRITE(LIMITED_VECTOR(vchFarmerPk, PK_LEN));
        READWRITE(nPlotType);

        READWRITE(nPlotK);
        READWRITE(vchProof);
    }

    CPosProof() { SetNull(); }

    void SetNull();
};

class CVdfProof {
public:
    uint256 challenge;
    Bytes vchY;
    Bytes vchProof;
    uint8_t nWitnessType{0};
    uint64_t nVdfIters{0};
    uint64_t nVdfDuration{0};

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(challenge);
        READWRITE(vchY);
        READWRITE(vchProof);
        READWRITE(nWitnessType);
        READWRITE(nVdfIters);
        READWRITE(nVdfDuration);
    }

    CVdfProof() { SetNull(); }

    void SetNull();
};

class CBlockFields {
public:
    uint64_t nVersion{CHIAHEADER_VERSION};
    uint64_t nDifficulty;

    CPosProof posProof;
    CVdfProof vdfProof;

    Bytes vchFarmerSignature;  // A signature by farmer, it should be able to verified by farmer-pubkey

    CBlockFields() { SetNull(); }

    void SetNull();

    bool IsNull() const;

    uint64_t GetTotalIters() const {
        return vdfProof.nVdfIters;
    }

    uint64_t GetTotalDuration() const {
        return vdfProof.nVdfDuration;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(nDifficulty);
        READWRITE(posProof);
        READWRITE(vdfProof);
        if (!(GetSerializeType(s) & SER_UNSIGNATURED)) {
            READWRITE(LIMITED_VECTOR(vchFarmerSignature, SIG_LEN));
        }
    }
};

}  // namespace chiapos

#endif
