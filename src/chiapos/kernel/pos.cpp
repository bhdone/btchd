#include <arith_uint256.h>
#include <chiapos/kernel/calc_diff.h>
#include <chiapos/kernel/pos.h>
#include <crypto/sha256.h>
#include <logging.h>

#include <chiapos/lib/include/picosha2.hpp>
#include <chiapos/src/prover_disk.hpp>
#include <chiapos/src/verifier.hpp>

#include "utils.h"

namespace chiapos {

Bytes ToBytes(LargeBits const& src) {
    int num_bits = src.GetSize();
    if (num_bits == 0) {
        return {};
    }
    int num_bytes;
    if (num_bits % 8 > 0) {
        num_bytes = num_bits / 8 + 1;
    } else {
        num_bytes = num_bits / 8;
    }
    Bytes res(num_bytes, '\0');
    src.ToBytes(res.data());
    return res;
}

struct LargeBitsImpl {
    LargeBits bits;
};

void LargeBitsDummy::FromBytes(Bytes const& data, int size_bits) {
    m_pimpl.reset(new LargeBitsImpl{LargeBits(data.data(), data.size(), size_bits)});
}

Bytes LargeBitsDummy::ToBytes() const { return chiapos::ToBytes(m_pimpl->bits); }

struct MakePubKeyOrHashBytes : public boost::static_visitor<Bytes> {
    Bytes operator()(PubKey const& pk) const { return MakeBytes(pk); }

    Bytes operator()(uint256 const& val) const { return MakeBytes(val); }
};

struct GetPubKeyOrHashType : public boost::static_visitor<PlotPubKeyType> {
    PlotPubKeyType operator()(PubKey const&) const { return PlotPubKeyType::OGPlots; }
    PlotPubKeyType operator()(uint256 const&) const { return PlotPubKeyType::PooledPlots; }
};

struct PlotFileImpl {
    std::shared_ptr<DiskProver> diskProver;
};

CPlotFile::CPlotFile(std::string filePath) : m_path(std::move(filePath)) {
    try {
        m_impl.reset(new PlotFileImpl{std::make_shared<DiskProver>(m_path)});
    } catch (std::exception const& e) {
        m_impl.reset();
    }
}

PlotId CPlotFile::GetPlotId() const {
    if (m_impl == nullptr) {
        return {};
    }
    if (m_cached_plotid.IsNull()) {
        m_cached_plotid = MakeUint256(m_impl->diskProver->GetId());
    }
    return m_cached_plotid;
}

bool CPlotFile::ReadMemo(PlotMemo& outMemo) {
    if (m_impl == nullptr) {
        return false;
    }
    try {
        Bytes memo = m_impl->diskProver->GetMemo();
        PlotMemo plot_memo;
        plot_memo.plot_id = m_impl->diskProver->GetId();
        if (memo.size() == 48 + 48 + 32) {
            plot_memo.plot_id_type = PlotPubKeyType::OGPlots;
            plot_memo.pool_pk_or_puzzle_hash = SubBytes(memo, 0, 48);
            plot_memo.farmer_pk = SubBytes(memo, 48, 48);
            plot_memo.local_master_sk = SubBytes(memo, 48 + 48);
        } else if (memo.size() == 32 + 48 + 32) {
            plot_memo.plot_id_type = PlotPubKeyType::PooledPlots;
            plot_memo.pool_pk_or_puzzle_hash = SubBytes(memo, 0, 32);
            plot_memo.farmer_pk = SubBytes(memo, 32, 48);
            plot_memo.local_master_sk = SubBytes(memo, 32 + 48);
        }
        outMemo = plot_memo;
        return true;
    } catch (std::exception const& e) {
        std::cerr << __func__ << ": " << e.what();
    }
    return false;
}

bool CPlotFile::GetQualityString(uint256 const& challenge, std::vector<QualityStringPack>& out) const {
    if (m_impl == nullptr) {
        return false;
    }
    try {
        std::vector<LargeBits> qualities = m_impl->diskProver->GetQualitiesForChallenge(challenge.begin());
        std::vector<QualityStringPack> qs_pack_vec;
        int index{0};
        for (auto const& quality : qualities) {
            QualityStringPack qs_pack;
            qs_pack.plot_path = m_path;
            Bytes quality_bytes = ToBytes(quality);
            qs_pack.quality_str.FromBytes(quality_bytes, quality.GetSize());
            qs_pack.k = m_impl->diskProver->GetSize();
            qs_pack.index = index++;
            qs_pack_vec.push_back(std::move(qs_pack));
        }
        out = qs_pack_vec;
        return true;
    } catch (std::exception const& e) {
        LogPrintf("%s: cannot get quality string from plot=%s\n", __func__, m_path);
    }
    return false;
}

bool CPlotFile::GetFullProof(uint256 const& challenge, int index, Bytes& out) const {
    if (m_impl == nullptr) {
        return false;
    }
    try {
        int proof_bytes = (int)m_impl->diskProver->GetSize() * 8;
        LargeBits proof = m_impl->diskProver->GetFullProof(challenge.begin(), index);
        Bytes proof_data(proof_bytes);
        proof.ToBytes(proof_data.data());
        out = proof_data;
        return true;
    } catch (std::exception const& e) {
        LogPrintf("%s: cannot read full proof from plot=%s\n", __func__, m_path);
    }
    return false;
}

Bytes ToBytes(PubKeyOrHash const& val) { return boost::apply_visitor(MakePubKeyOrHashBytes(), val); }

PlotPubKeyType GetType(PubKeyOrHash const& val) { return boost::apply_visitor(GetPubKeyOrHashType(), val); }

CKey GenerateTapRootSk(PubKey const& localPk, PubKey const& farmerPk) {
    PubKey aggPk = AggregatePubkeys({localPk, farmerPk});
    Bytes vchSeed = MakeSHA256(BytesConnector::Connect(MakeBytes(aggPk), MakeBytes(localPk), MakeBytes(farmerPk)));
    return CKey::Generate(vchSeed);
}

PubKey MakePlotPubkey(PubKey const& localPk, PubKey const& farmerPk, PlotPubKeyType type) {
    if (type == PlotPubKeyType::OGPlots) {
        // Aggregate two public-keys 2-2 into one then get the plot-id public-key
        return AggregatePubkeys({localPk, farmerPk});
    } else if (type == PlotPubKeyType::PooledPlots) {
        // Make taproot_sk by generating a new private key
        CKey tapRootSk = GenerateTapRootSk(localPk, farmerPk);
        PubKey tapRootPk = tapRootSk.GetPubkey();
        return AggregatePubkeys({localPk, farmerPk, tapRootPk});
    }
    throw std::runtime_error("unknown type detected during the procedure of making a plot public-key");
}

PubKeyOrHash MakePubKeyOrHash(PlotPubKeyType type, Bytes const& vchData) {
    if (type == PlotPubKeyType::OGPlots) {
        if (vchData.size() != PK_LEN) {
            throw std::runtime_error("cannot convert public-key, the length of data must be 48 bytes");
        }
        return MakeArray<PK_LEN>(vchData);
    } else if (type == PlotPubKeyType::PooledPlots) {
        if (vchData.size() != ADDR_LEN) {
            throw std::runtime_error("cannot convert hash value, the length of data must be 32 bytes");
        }
        return MakeUint256(vchData);
    }
    throw std::runtime_error("unknown type");
}

PlotId MakePlotId(Bytes const& poolPk, PubKey const& plotPk) {
    return MakeUint256(MakeSHA256(BytesConnector::Connect(poolPk, plotPk)));
}

PlotId MakePlotId(PubKey const& localPk, PubKey const& farmerPk, PubKeyOrHash const& poolPkOrHash) {
    PubKey plotPk = MakePlotPubkey(localPk, farmerPk, GetType(poolPkOrHash));
    return MakePlotId(ToBytes(poolPkOrHash), plotPk);
}

uint256 MakeMixedQualityString(PlotId const& plotId, uint8_t k, uint256 const& challenge, Bytes const& vchProof) {
    Verifier verifier;
    Bytes plot_id_bytes = MakeBytes(plotId);
    LargeBits quality_string_bits =
            verifier.ValidateProof(plot_id_bytes.data(), k, challenge.begin(), vchProof.data(), vchProof.size());
    Bytes quality_string = ToBytes(quality_string_bits);
    if (quality_string.empty()) {
        return uint256();
    }
    return GetMixedQualityString(quality_string, challenge);
}

uint256 MakeMixedQualityString(PubKey const& localPk, PubKey const& farmerPk, PubKeyOrHash const& poolPkOrHash,
                               uint8_t k, uint256 const& challenge, Bytes const& proof) {
    PlotId plotId = MakePlotId(localPk, farmerPk, poolPkOrHash);
    return MakeMixedQualityString(plotId, k, challenge, proof);
}

bool PassesFilter(PlotId const& plotId, uint256 const& challenge, int bits) {
    int const BYTES_uint256 = 32;
    Bytes data(BYTES_uint256 * 2);
    memcpy(data.data(), plotId.begin(), BYTES_uint256);
    memcpy(data.data() + BYTES_uint256, challenge.begin(), BYTES_uint256);
    Bytes data_hashed = MakeSHA256(data);
    auto res = MakeUint256(data_hashed);
    auto res_filter = UintToArith256(res) >> (256 - bits);
    return res_filter == 0;
}

uint256 GetMixedQualityString(Bytes const& quality_string, uint256 const& challenge) {
    return MakeUint256(MakeSHA256(quality_string, challenge));
}

bool VerifyPos(uint256 const& challenge, PubKey const& localPk, PubKey const& farmerPk,
               PubKeyOrHash const& poolPkOrHash, uint8_t k, Bytes const& vchProof, uint256* out_mixed_quality_string,
               int bits_of_filter) {
    if (k * 8 != vchProof.size()) {
        // invalid size of the proof
        return false;
    }
    PlotId plotId = MakePlotId(localPk, farmerPk, poolPkOrHash);
    if (!PassesFilter(plotId, challenge, bits_of_filter)) {
        // The challenge with plot-id doesn't pass the filter
        return false;
    }
    uint256 mixed_quality_string = MakeMixedQualityString(plotId, k, challenge, vchProof);
    if (out_mixed_quality_string != nullptr) {
        *out_mixed_quality_string = mixed_quality_string;
    }
    return !mixed_quality_string.IsNull();
}

}  // namespace chiapos
