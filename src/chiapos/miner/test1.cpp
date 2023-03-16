#include "test1.h"

#include <chiapos/kernel/calc_diff.h>
#include <chiapos/kernel/vdf.h>
#include <chiapos/post.h>
#include <gtest/gtest.h>
#include <vdf_computer.h>

#include <chrono>
#include <stdexcept>

#include "chiapos/kernel/bls_key.h"
#include "chiapos/kernel/chiapos_types.h"
#include "chiapos/kernel/pos.h"
#include "chiapos/kernel/utils.h"
#include "chiapos/miner/keyman.h"
#include "chiapos/miner/prover.h"
#include "chiapos_miner.h"
#include "plog/Log.h"
#include "rpc_client.h"
#include "uint256.h"

TEST_F(MinerTest, QualityCalculating) {
    EXPECT_TRUE(m_pclient->CheckChiapos());
    miner::RPCClient::Challenge queried_challenge = m_pclient->QueryChallenge();
    // Find PoS
    auto pos = miner::pos::QueryBestPosProof(*m_pprover, queried_challenge.challenge, 10000,
                                             chiapos::DIFFICULTY_CONSTANT_FACTOR_BITS,
                                             chiapos::NUMBER_OF_ZEROS_BITS_FOR_FILTER);
    EXPECT_TRUE(pos.has_value());
    if (!pos.has_value()) {
        return;
    }
    // EXPECT_GT(pos->quality, 0);
}

TEST_F(MinerTest, CheckChiapos) {
    EXPECT_NO_THROW({
        bool is_chia = m_pclient->CheckChiapos();
        EXPECT_TRUE(is_chia);
    });
}

TEST_F(MinerTest, QueryChallenge) {
    EXPECT_NO_THROW({
        miner::RPCClient::Challenge ch = m_pclient->QueryChallenge();
        EXPECT_TRUE(!ch.challenge.IsNull());
        EXPECT_TRUE(ch.difficulty > 0);
        EXPECT_TRUE(!ch.prev_block_hash.IsNull());
        EXPECT_TRUE(ch.prev_block_height > 0);
        EXPECT_EQ(ch.target_height, ch.prev_block_height + 1);
        EXPECT_TRUE(ch.target_duration > 0);
    });
}

TEST_F(MinerTest, QueryVdf) {
    EXPECT_NO_THROW({
        uint256 challenge = MakeChallenge();
        miner::RPCClient::VdfProof vdf = m_pclient->QueryVdf(challenge, 0);
        EXPECT_EQ(vdf.challenge, challenge);
        EXPECT_TRUE(vdf.iters > 0);
        bool verified = chiapos::VerifyVdf(vdf.challenge, chiapos::MakeZeroForm(), vdf.iters, vdf.y, vdf.proof,
                                           vdf.witness_type);
        EXPECT_TRUE(verified);
    });
}
int HandleCommand_Test(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
