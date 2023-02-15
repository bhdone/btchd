#ifndef BTCHD_MINER_TEST1_H
#define BTCHD_MINER_TEST1_H

#include <chiapos/kernel/bls_key.h>
#include <chiapos/kernel/calc_diff.h>
#include <chiapos/kernel/utils.h>
#include <chiapos/kernel/vdf.h>
#include <chiapos/miner/keyman.h>
#include <gtest/gtest.h>
#include <uint256.h>
#include <vdf_computer.h>

#include <memory>

#include "arith_uint256.h"
#include "chiapos/miner/chiapos_miner.h"
#include "prover.h"
#include "rpc_client.h"
#include "tools.h"

class ChallengeBase {
    char const* SZ_CHALLENGE = "abd2fdbd2e6eece6171f3adcb4560acff92578ad33af3ebe2ad407b2101610ae";

protected:
    uint256 MakeChallenge() const { return uint256S(SZ_CHALLENGE); }

    uint256 MakeChallenge(uint8_t b) const {
        uint256 res;
        memset(res.begin(), b, res.size());
        return res;
    }
};

class DifficultyBase {
    uint64_t const difficulty_start = 30;

protected:
    uint64_t GetDifficultyStart() const { return difficulty_start; }
};

class RPCBase {
    char const* SZ_URL = "http://127.0.0.1:18732";

protected:
    std::unique_ptr<miner::RPCClient> CreateRPCClient() const {
        return std::unique_ptr<miner::RPCClient>(
                new miner::RPCClient(SZ_URL, tools::GetDefaultDataDir(true, ".cookie")));
    }
};

class PosBase {
    char const* SZ_PLOT_PATH = "/home/matthew/data/plotfiles2";
    char const* SZ_MNEMONIC =
            "bird convince trend skin lumber escape crater describe public blame pen twin muscle rebuild satisfy vague "
            "artist banana worry please museum unable tail useful";
    char const* SZ_REWARD_ADDRESS = "3N2TZmoKY1KsAvZDzq6FXjNAja8u4vtxht";

protected:
    std::string GetPlotPath() const { return SZ_PLOT_PATH; }

    std::string GetRewardAddress() const { return SZ_REWARD_ADDRESS; }

    keyman::Mnemonic GetMnemonic() const { return keyman::Mnemonic(SZ_MNEMONIC); }

    chiapos::SecreKey GetFarmerSk() const {
        keyman::Key key(GetMnemonic(), "");
        auto farmer_sk = keyman::Wallet::GetFarmerKey(key, 0);
        return farmer_sk.GetPrivateKey();
    }

    chiapos::PubKey GetFarmerPk() const {
        keyman::Key key(GetMnemonic(), "");
        auto farmer_sk = keyman::Wallet::GetFarmerKey(key, 0);
        return farmer_sk.GetPublicKey();
    }

    std::unique_ptr<miner::Prover> CreateProver() const {
        return std::unique_ptr<miner::Prover>(new miner::Prover({GetPlotPath()}));
    }
};

class MinerTest : public ::testing::Test, public ChallengeBase, public RPCBase, public PosBase {
protected:
    std::unique_ptr<miner::RPCClient> m_pclient;
    std::unique_ptr<miner::Prover> m_pprover;

    void SetUp() override {
        m_pclient = CreateRPCClient();
        m_pprover = CreateProver();
    }

    void TearDown() override {}
};

class DifficultyTest : public ::testing::Test, public ChallengeBase, public DifficultyBase, public PosBase {
protected:
    std::unique_ptr<miner::Prover> m_prover;

    void SetUp() override { m_prover = CreateProver(); }

    void TearDown() override {}
};

int HandleCommand_Test(int argc, char** argv);

#endif
