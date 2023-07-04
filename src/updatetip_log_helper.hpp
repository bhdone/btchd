#ifndef UPDATETIP_LOG_HELPER
#define UPDATETIP_LOG_HELPER

#include <util/time.h>

#include <univalue.h>
#include <chiapos/post.h>

#include <chainparams.h>
#include <interfaces/chain.h>

double GuessVerificationProgress(const ChainTxData& data, const CBlockIndex *pindex);

class UpdateTipLogHelper {
public:
    UpdateTipLogHelper(CBlockIndex const* pindex, CChainParams const& chainParams) : m_pindex(pindex), m_chainParams(chainParams) {
        ApplyLogFromCurrIndex();
    }

    CBlockIndex const* GetBlockIndex() const {
        return m_pindex;
    }

    bool MoveToPrevIndex() {
        if (m_pindex->pprev == nullptr) {
            return false;
        }
        m_pindex = m_pindex->pprev;
        ApplyLogFromCurrIndex();
        return true;
    }

    void PrintLog(std::string const& strFuncName) const {
        LogPrintf("%s:%s\n", strFuncName, GetLogStr());
    }

    UniValue PrintJson() const {
        return GetJson();
    }

    void AddLogEntry(std::string const& name, std::string const& value) {
        m_logVec.push_back(tinyformat::format("%s=%s", name, value));
    }

    void AddLogEntry(std::string const& name, uint64_t value) {
        AddLogEntry(name, chiapos::MakeNumberStr(value));
    }

    void AddLogEntry(std::string strEntry) {
        m_logVec.push_back(std::move(strEntry));
    }

private:
    uint64_t CalculateReqIters(Consensus::Params const& params) const {
        // calculate required vdf iterations
        chiapos::PubKeyOrHash poolPkOrHash = chiapos::MakePubKeyOrHash(static_cast<chiapos::PlotPubKeyType>(m_pindex->chiaposFields.posProof.nPlotType), m_pindex->chiaposFields.posProof.vchPoolPkOrHash);
        uint256 mixed_quality_string = chiapos::MakeMixedQualityString(
                chiapos::MakeArray<chiapos::PK_LEN>(m_pindex->chiaposFields.posProof.vchLocalPk), chiapos::MakeArray<chiapos::PK_LEN>(m_pindex->chiaposFields.posProof.vchFarmerPk), poolPkOrHash,
                m_pindex->chiaposFields.posProof.nPlotK, m_pindex->chiaposFields.posProof.challenge, m_pindex->chiaposFields.posProof.vchProof);
        int nTargetHeight = m_pindex->nHeight;
        int nBitsFilter = nTargetHeight < params.BHDIP009PlotIdBitsOfFilterEnableOnHeight ? 0 : params.BHDIP009PlotIdBitsOfFilter;
        uint64_t nBaseIters = chiapos::GetBaseIters(nTargetHeight, params);
        return chiapos::CalculateIterationsQuality(mixed_quality_string, chiapos::GetDifficultyForNextIterations(m_pindex->pprev, params), nBitsFilter, params.BHDIP009DifficultyConstantFactorBits, m_pindex->chiaposFields.posProof.nPlotK, nBaseIters);
    }

    void ApplyLogFromCurrIndex() {
        AddLogEntry("new best", m_pindex->GetBlockHash().GetHex());
        AddLogEntry("height", m_pindex->nHeight);
        AddLogEntry(tinyformat::format("version=0x%08x", m_pindex->nVersion));
        AddLogEntry("tx", m_pindex->nTx);
        AddLogEntry("tx-chain", m_pindex->nChainTx);
        AddLogEntry("date", FormatISO8601DateTime(m_pindex->GetBlockTime()));
        AddLogEntry(tinyformat::format("progress=%1.2f", GuessVerificationProgress(m_chainParams.TxData(), m_pindex)));
        auto const& params = m_chainParams.GetConsensus();
        AddLogEntry("work", GetBlockWork(*m_pindex).GetLow64());
        AddLogEntry("type", m_pindex->nHeight >= params.BHDIP009Height ? "chia" : "burst");
        // For BHDIP009?
        if (m_pindex->nHeight >= params.BHDIP009Height) {
            int nBlockDuration = m_pindex->GetBlockTime() - m_pindex->pprev->GetBlockTime();
            AddLogEntry("block-time", chiapos::FormatTime(nBlockDuration));
            // vdf related
            AddLogEntry("vdf-iters", m_pindex->chiaposFields.vdfProof.nVdfIters);
            AddLogEntry("vdf-time", chiapos::FormatTime(m_pindex->chiaposFields.vdfProof.nVdfDuration));
            AddLogEntry("vdf-iters-req", CalculateReqIters(params));
            std::string strVdfSpeed = chiapos::FormatNumberStr(std::to_string(m_pindex->chiaposFields.GetTotalIters() / m_pindex->chiaposFields.GetTotalDuration()));
            AddLogEntry(tinyformat::format("vdf=%s(%s ips)", chiapos::MakeNumberStr(m_pindex->chiaposFields.GetTotalIters()), strVdfSpeed));
            // filter bits
            AddLogEntry("filter-bit", m_pindex->nHeight < params.BHDIP009PlotIdBitsOfFilterEnableOnHeight ? 0 : params.BHDIP009PlotIdBitsOfFilter);
            // challenge
            uint256 challenge = chiapos::MakeChallenge(m_pindex, params);
            AddLogEntry("challenge", challenge.GetHex());
            AddLogEntry("challenge-diff", chiapos::GetDifficultyForNextIterations(m_pindex, params));
            // difficulty
            AddLogEntry("block-difficulty", chiapos::GetChiaBlockDifficulty(m_pindex, params));
            AddLogEntry("min-difficulty", chiapos::MakeNumberStr(params.BHDIP009StartDifficulty));
            AddLogEntry("k", m_pindex->chiaposFields.posProof.nPlotK);
            AddLogEntry("farmer-pk", chiapos::BytesToHex(m_pindex->chiaposFields.posProof.vchFarmerPk));
            // netspace
            auto netspace = chiapos::CalculateNetworkSpace(chiapos::GetDifficultyForNextIterations(m_pindex->pprev, params), m_pindex->chiaposFields.GetTotalIters(), params.BHDIP009DifficultyConstantFactorBits);
            AddLogEntry("netspace", netspace.GetLow64());
        }
    }

    std::string GetLogStr() const {
        std::stringstream ss;
        for (auto const& str : m_logVec) {
            ss << " " << str;
        }
        return ss.str();
    }

    UniValue GetJson() const {
        UniValue res(UniValue::VOBJ);
        for (auto const& val : m_logVec) {
            auto p = val.find_first_of('=');
            if (p != std::string::npos) {
                res.pushKV(val.substr(0, p), val.substr(p + 1));
            }
        }
        return res;
    }

    CBlockIndex const* m_pindex;
    CChainParams const& m_chainParams;
    std::vector<std::string> m_logVec;
};

#endif
