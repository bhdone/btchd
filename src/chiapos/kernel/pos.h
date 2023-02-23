#ifndef BTCHD_CHIAPOS_POS_H
#define BTCHD_CHIAPOS_POS_H

#include <chiapos/kernel/chiapos_types.h>
#include <uint256.h>

#include <boost/variant.hpp>
#include <string>
#include <vector>

#include "bls_key.h"

namespace chiapos {

struct LargeBitsImpl;

class LargeBitsDummy {
public:
    LargeBitsDummy() = default;

    Bytes ToBytes() const;

    void FromBytes(Bytes const& data, int size_bits);

private:
    std::shared_ptr<LargeBitsImpl> m_pimpl;
};

enum class PlotPubKeyType : uint32_t { OGPlots, PooledPlots };

struct PlotMemo {
    Bytes plot_id;
    PlotPubKeyType plot_id_type;
    Bytes pool_pk_or_puzzle_hash;
    Bytes farmer_pk;
    Bytes local_master_sk;
};

struct QualityStringPack {
    std::string plot_path;
    chiapos::LargeBitsDummy quality_str;
    uint8_t k;
    int index;
};

struct PlotFileImpl;

using PubKeyOrHash = boost::variant<PubKey, uint256>;
using PlotId = uint256;

class CPlotFile {
public:
    explicit CPlotFile(std::string filePath);

    bool IsReady() const { return m_impl != nullptr; }

    PlotId GetPlotId() const;

    bool ReadMemo(PlotMemo& outMemo);

    bool GetQualityString(uint256 const& challenge, std::vector<QualityStringPack>& out) const;

    bool GetFullProof(uint256 const& challenge, int index, Bytes& out) const;

    std::string GetPath() const { return m_path; }

private:
    std::string m_path;
    mutable uint256 m_cached_plotid;
    std::shared_ptr<PlotFileImpl> m_impl;
};

Bytes ToBytes(PubKeyOrHash const& val);

PlotPubKeyType GetType(PubKeyOrHash const& val);

PubKeyOrHash MakePubKeyOrHash(PlotPubKeyType type, Bytes const& vchData);

PlotId MakePlotId(PubKey const& localPk, PubKey const& farmerPk, PubKeyOrHash const& poolPkOrHash);

uint256 MakeMixedQualityString(PlotId const& plotId, uint8_t k, uint256 const& challenge, Bytes const& vchProof);

uint256 MakeMixedQualityString(PubKey const& localPk, PubKey const& farmerPk, PubKeyOrHash const& poolPkOrHash,
                               uint8_t k, uint256 const& challenge, Bytes const& proof);

bool PassesFilter(PlotId const& plotId, uint256 const& challenge, int bits);

/**
 * @brief Mix quality string
 *
 * @param quality_string The original quality string data from disk prover
 * @param challenge The challenge
 *
 * @return The mixed quality string
 */
uint256 GetMixedQualityString(Bytes const& quality_string, uint256 const& challenge);

bool VerifyPos(uint256 const& challenge, PubKey const& localPk, PubKey const& farmerPk,
               PubKeyOrHash const& poolPkOrHash, uint8_t k, Bytes const& vchProof, uint256* out_mixed_quality_string,
               int bits_of_filter);

}  // namespace chiapos

#endif
