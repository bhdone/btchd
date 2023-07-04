// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <poc/poc.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>
#include <arith_uint256.h>

#include <limits>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include <chiapos/post.h>
#include <chiapos/kernel/calc_diff.h>

const uint32_t SECONDS_OF_A_DAY = 60 * 60 * 24;
const int AVERAGE_VDF_SPEED = 200 * 1000; // 200k ips we assume

static CBlock CreateGenesisBlock(char const* pszTimestamp, CScript const& genesisOutputScript, uint32_t nTime,
                                 uint64_t nNonce, uint64_t nBaseTarget, int32_t nVersion,
                                 CAmount const& genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(2);
    txNew.vin[0].scriptSig =
            CScript() << static_cast<unsigned int>(0) << CScriptNum(static_cast<int64_t>(nNonce))
                      << CScriptNum(static_cast<int64_t>(0))
                      << std::vector<unsigned char>((unsigned char const*)pszTimestamp,
                                                    (unsigned char const*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;
    txNew.vout[1].nValue = 0;
    txNew.vout[1].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime       = nTime;
    genesis.nBaseTarget = nBaseTarget;
    genesis.nNonce      = nNonce;
    genesis.nVersion    = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=8cec494f7f02ad, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=6b80acabaf0fef, nTime=1531292789, nBaseTarget=18325193796, nNonce=0, vtx=1)
 *   CTransaction(hash=6b80acabaf0fef, ver=1, vin.size=1, vout.size=2, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=25.00000000, scriptPubKey=0x2102CD2103A86877937A05)
 *     CTxOut(nValue=00.00000000, scriptPubKey=0x2102CD2103A86877937A05)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint64_t nNonce, uint64_t nBaseTarget, int32_t nVersion,
                                 CAmount const& genesisReward) {
    char const* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("02cd2103a86877937a05eff85cf487424b52796542149f2888f9a17fbe6d66ce9d") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBaseTarget, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;

        consensus.BHDFundAddress = "32B86ghqRTJkh2jvyhRWFugX7YWoqHPqVE";
        // See https://bhd.one/wiki/fund-address-pool
        consensus.BHDFundAddressPool = {
            "3F26JRhiGjc8z8pRKJvLXBEkdE6nLDAA3y", //!< 0x20000000, Deprecated!. Last use on v1.1.0.1-30849da
            "32B86ghqRTJkh2jvyhRWFugX7YWoqHPqVE", //!< 0x20000004, 0x20000000
            "39Vb1GNSurGoHcQ4aTKrTYC1oNmPppGea3",
            "3Maw3PdwSvtXgBKJ9QPGwRSQW8AgQrGK3W",
            "3Hy3V3sPVpuQaG6ttihfQNh4vcDXumLQq9",
            "3MxgS9jRcGLihAtb9goAyD1QC8AfRNFE1F",
            "3A4uNFxQf6Jo8b6QpBVnNcjDRqDchgpGbR",
        };
        assert(consensus.BHDFundAddressPool.find(consensus.BHDFundAddress) != consensus.BHDFundAddressPool.end());

        consensus.nPowTargetSpacing = 180; // Reset by BHDIP008
        consensus.fPowNoRetargeting = false;
        consensus.nCapacityEvalWindow = 2016; // About 1 week
        consensus.nSubsidyHalvingInterval = 210000; // About 4 years. 210000*600/(365*24*3600) = 3.99543379
        consensus.fAllowMinDifficultyBlocks = false; // For test
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // About 1 week

        consensus.BHDIP001PreMiningEndHeight = 84001; // 21M * 10% = 2.1M, 2.1M/25=84000 (+1 for deprecated public test data)
        consensus.BHDIP001FundZeroLastHeight = 92641; // End 1 month after 30 * 24 * 60 / 5 = 8640
        consensus.BHDIP001TargetSpacing = 300; // 5 minutes. Subsidy halving interval 420000 blocks
        consensus.BHDIP001FundRoyaltyForFullMortgage = 50; // 50‰ to fund
        consensus.BHDIP001FundRoyaltyForLowMortgage = 700; // 700‰ to fund
        consensus.BHDIP001MiningRatio = 3 * COIN;

        // It's fuck mind BitcoinHD1 Improvement Proposals
        consensus.BHDIP004Height = 96264; // BitcoinHD1 new consensus upgrade bug. 96264 is first invalid block
        consensus.BHDIP004AbandonHeight = 99000;

        consensus.BHDIP006Height = 129100; // Actived on Wed, 02 Jan 2019 02:17:19 GMT
        consensus.BHDIP006BindPlotterActiveHeight = 131116; // Bind plotter actived on Tue, 08 Jan 2019 23:14:57 GMT
        consensus.BHDIP006CheckRelayHeight = 133000; // Bind and unbind plotter limit. Active on Tue, 15 Jan 2019 11:00:00 GMT
        consensus.BHDIP006LimitBindPlotterHeight = 134650; // Bind plotter limit. Active on Tue, 21 Jan 2019 9:00:00 GMT

        consensus.BHDIP007Height = 168300; // Begin BHDIP007 consensus
        consensus.BHDIP007SmoothEndHeight  = 172332; // 240 -> 300, About 2 weeks
        consensus.BHDIP007MiningRatioStage = 1250 * 1024; // 1250 PB

        consensus.BHDIP008Height = 197568; // Begin BHDIP008 consensus. About active on Tue, 27 Aug 2019 04:47:46 GMT
        consensus.BHDIP008TargetSpacing = 180; // 3 minutes. Subsidy halving interval 700000 blocks
        consensus.BHDIP008FundRoyaltyForLowMortgage = 270; // 270‰ to fund
        consensus.BHDIP008FundRoyaltyDecreaseForLowMortgage = 20; // 20‰ decrease
        consensus.BHDIP008FundRoyaltyDecreasePeriodForLowMortgage = 33600; // 10 weeks. About 110 weeks decrease to 50‰
        assert(consensus.BHDIP008Height % consensus.nMinerConfirmationWindow == 0);
        assert(consensus.BHDIP008FundRoyaltyForLowMortgage < consensus.BHDIP001FundRoyaltyForLowMortgage);
        assert(consensus.BHDIP008FundRoyaltyForLowMortgage > consensus.BHDIP001FundRoyaltyForFullMortgage);

        int nHeightsOfADay = SECONDS_OF_A_DAY / consensus.BHDIP008TargetSpacing;
        consensus.BHDIP009SkipTestChainChecks = false; // Do not check validation for blocks of burst consensus
        consensus.BHDIP009Height = 860130; // 2023/6/19 13:00 - 17:00
        consensus.BHDIP009StartVerifyingVdfDurationHeight = consensus.BHDIP009Height + nHeightsOfADay * 7;
        consensus.BHDIP009OldPledgesDisableOnHeight = consensus.BHDIP009Height + nHeightsOfADay * 14;
        // The reward address should be filled
        consensus.BHDIP009FundAddresses = { "34QSZXwx354rXUZ7W3mJnwfCiomJpHQApp" };
        consensus.BHDIP009FundRoyaltyForLowMortgage = 150;
        consensus.BHDIP009StartBlockIters = AVERAGE_VDF_SPEED * consensus.BHDIP008TargetSpacing;
        consensus.BHDIP009DifficultyConstantFactorBits = chiapos::DIFFICULTY_CONSTANT_FACTOR_BITS;
        consensus.BHDIP009DifficultyEvalWindow = 20 * 3; // 3 hours
        consensus.BHDIP009PlotIdBitsOfFilter = chiapos::NUMBER_OF_ZEROS_BITS_FOR_FILTER;
        consensus.BHDIP009PlotIdBitsOfFilterEnableOnHeight = consensus.BHDIP009Height + 200;
        consensus.BHDIP009PlotSizeMin = chiapos::MIN_K;
        consensus.BHDIP009PlotSizeMax = chiapos::MAX_K;
        consensus.BHDIP009BaseIters = AVERAGE_VDF_SPEED * 60;
        consensus.BHDIP009StartDifficulty = (arith_uint256(consensus.BHDIP009StartBlockIters) * chiapos::expected_plot_size<arith_uint256>(chiapos::MIN_K) / chiapos::Pow2(consensus.BHDIP009DifficultyConstantFactorBits)).GetLow64();

        consensus.BHDIP009PledgeTerms[0] = {nHeightsOfADay * 5, 8};
        consensus.BHDIP009PledgeTerms[1] = {nHeightsOfADay * 365, 20};
        consensus.BHDIP009PledgeTerms[2] = {nHeightsOfADay * 365 * 2, 50};
        consensus.BHDIP009PledgeTerms[3] = {nHeightsOfADay * 365 * 3, 100};

        consensus.BHDIP009TotalAmountUpgradeMultiply = 3; // 21,000,000 * 3 = 63,000,000
        consensus.BHDIP009CalculateDistributedAmountEveryHeights = nHeightsOfADay * 30; // every 30 days the distributed amount will be changed
        consensus.BHDIP009PledgeRetargetMinHeights = (SECONDS_OF_A_DAY / consensus.BHDIP008TargetSpacing) * 7; // minimal number to retarget a pledge is 7 days
        consensus.BHDIP009DifficultyChangeMaxFactor = chiapos::DIFFICULTY_CHANGE_MAX_FACTOR;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000003eee4fa76b462cc633c");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x915e3ef622459f8b1b04dc274e1097b31111b0c6e0a9e9cd2da60c9d692f2c93");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xe5;
        pchMessageStart[1] = 0xba;
        pchMessageStart[2] = 0xb0;
        pchMessageStart[3] = 0xd5;
        nDefaultPort = 8733;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 3;
        m_assumed_chain_state_size = 1;


        genesis = CreateGenesisBlock(1531292789, 0, poc::GetBaseTarget(240), 2, 50 * COIN * consensus.BHDIP001TargetSpacing / 600);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x8cec494f7f02ad25b3abf418f7d5647885000e010c34e16c039711e4061497b0"));
        assert(genesis.hashMerkleRoot == uint256S("0x6b80acabaf0fef45e2cad0b8b63d07cff1b35640e81f3ab3d83120dd8bc48164"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.push_back("seed0-chain.bhd.one");
        vSeeds.push_back("seed1-chain.bhd.one");
        vSeeds.push_back("seed2-chain.bhd.one");
        vSeeds.push_back("seed3-chain.bhd.one");
        vSeeds.push_back("seed-bhd.hpool.com");
        vSeeds.push_back("seed-bhd.hdpool.com");
        vSeeds.push_back("seed-bhd.awpool.com");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;

        checkpointData = {
            {
                {      0, uint256S("0x8cec494f7f02ad25b3abf418f7d5647885000e010c34e16c039711e4061497b0") },
                {   2000, uint256S("0x3e0ea5fc8f09808fc4ea0c7f2bd90bedd2de2ce6852882c82593c7aedc4ff5a4") },
                {   4000, uint256S("0xa9406ac6837fcb59d1549c8a9e9623530c82c9a69b426a8ce5e8b61bb1ae349e") },
                {   8000, uint256S("0xec2455cb8fede24bb2de7993de20d79a25a4e5936d773b72efff711890538b6c") },
                {  10000, uint256S("0x5345016cec4d0d9458990ca12384371e0ae61e140aa85e1e995db7d51b57c42a") },
                {  16000, uint256S("0x378156abc134017c11ae94f5758854b629c05050030f42834813d6d7530ade2f") },
                {  22000, uint256S("0x2f6e0be78a4f6d13917c6d3811faff36dab7578e4c38c5d56ef0054e54c05316") },
                {  30000, uint256S("0x484b7cb499004f1ca0ef8e2fccb4c4fcd3535196a7ac45b2e82adbfebd3dda78") },
                {  40000, uint256S("0x00fb659ebbf0e396d3c28cdcea2dc86c0464c8240b4527cd71d64b975bf09995") },
                {  50000, uint256S("0xcc3008bac1014bd11bf0e5ee15c5e3221af9ab396bf546b873dac13de5f2184e") },
                {  60000, uint256S("0xb01923d8ea4c6c8d1830bdd922841246dc994b64867c8b0113ff8f17e46918e4") },
                {  70000, uint256S("0x464a90f3e349e9066847dfb377e11b994b412407ba8ca00c34e330278db8383e") },
                {  80000, uint256S("0x4a6f5a5c944105a70aaba7e64c5a7c8f4fc4f3759ac8af423c824db8c89f7482") },
                {  84001, uint256S("0xa474cb4eeca85ada0f4600b1d6fe656bb09c88328e00c3fcccc0136f2c360e94") },
                // Offset +2000. Sync batch by 2000, accelerate block verify
                {  85000, uint256S("0xaaeb335da849331f43e7808611f38e630ffbb2726ba131181ba72ac8d58a2da3") },
                {  86000, uint256S("0xe4fabbdcef187186ae1f1cc32ef8ec2fa22025c0f38a8a4cb0a89118ba34f75b") },
                {  88000, uint256S("0x24928cd2154d1546930e5a6ac4f7828dc40fca3dadfc31ce8fa8caea6cfb5401") },
                {  90000, uint256S("0x7acd0596d0a5b97c036fa705e08ea636b07e5dc004d8171d2a02955fae12ddde") },
                {  92000, uint256S("0xfe0f3540c630cde2afc5e5081a4aec25ea43a57e1bf603e403054e218a3dc9cf") },
                {  94000, uint256S("0x7dd832ac7da06f01cf8db0e6e9917dab12e37d009f7369cff00c0484cdd42a22") },
                {  96000, uint256S("0x18ada0a6fbd634489a4b05318731035fa048bdbb381084b10071107b3790dd3b") },
                {  98000, uint256S("0x3f1068eb2eb9a6b1a2e3a93ef74a34c59fefe0d0e48b6d1f458bc562a8c83a05") },
                { 100000, uint256S("0x5ef9b2dae9a7aceac25c5229225a64e49a493435ed0ecbe6baf92a6496515931") },
                { 102000, uint256S("0x90a77896d7c1ac9c52504c5779f4b070530cd4de8047babe443de4c71feef0e4") },
                { 104000, uint256S("0xf89deb06a14ebde24cfaf1ff4fb0f545f59a7940e660d498f6c306c6c9b66cde") },
                { 106000, uint256S("0xf7dfa89a61703f561fbd30782328c03ea2721c2c2cda04046b872303468512ed") },
                { 108000, uint256S("0xd7c1c6d6d019ebe460d4bef7f3dc2fd2a4375462eff574560343d47bf314161d") },
                { 110000, uint256S("0xc3fa82d07a4ed51b347f3694ff144d654dbccc950092988df9f58aeb2b907dc8") },
                { 112000, uint256S("0xfd78fbf7e6e6274919f12c384e46ea7f5e3ffc2c7a3828a35664622d06885667") },
                { 114000, uint256S("0xfe881b2ea8b7481e5233c80fc2d8394d7a5c29484275dd93bce8d0d375f458cf") },
                { 116000, uint256S("0x5ea5ea3fe879a01ec7f2625cf68b1b703d2d7fcc7dbc9206b34b651ad6533f16") },
                { 118000, uint256S("0xf640f20483939c0ca4bfea2c42bd11fb6c071e40dd415ed9895ea220c2a19e1c") },
                { 120000, uint256S("0x0b1ae104b516bbc4f19f4850c6bb499154387b391334ed7f0e93671e11530bbc") },
                { 122000, uint256S("0x5f60e469b8742068e56147d4e463723952e0395e196e255ad8941835459ad37e") },
                { 124000, uint256S("0x3387babe46e9d70cb6fec1d8104b741070b86c7d96362b512026ccefe7546774") },
                { 126000, uint256S("0xb4a81eb95d4ea3028b489bd77b045c4278058a6889558967949b4694967302c6") },
                { 128000, uint256S("0x94ebf25c1db0e170e5d3c6529f2e453ce2edac11984ac9b94c1c61eda76d7d42") },
                { 129100, uint256S("0xebbc8573080109747838beec06c2014f11327b7b7dc35eab8332a53efecf7f25") }, // BHDIP006
                { 130000, uint256S("0xfea47141ac2ab697b33ceb3ee71cbca42c8aa93115f301ca69fd21d7ab2f65f5") },
                { 132000, uint256S("0x35feb21020d8dc2674a811c5c23e8d85bd2d13339022c273c202986746c18636") },
                { 133000, uint256S("0xcdea9a2bfc267e7cc9d7e6d8c5606a5b7685c39eec4afba6e8a07bbafd776bac") }, // BHDIP006 unbind limit
                { 134000, uint256S("0x68dedaf2c309f2008ec63d19328547b598ec51989ab3be4106b3c1df4e2c1b77") },
                { 134650, uint256S("0x2c1d20602c660e0fc5bfae6d1bd6bf4a6fa9e2970e625b88275a3ef30b09b418") }, // BHDIP006 bind limit
                { 136000, uint256S("0xda9cdfbb86b88444abe8f4273f476c51c63b1eed61d819bbd98af3aa23241325") },
                { 138000, uint256S("0x256edfe36cf331eafa31e6396038d15b5f2596b36bd62c7d58a5264479b6a634") },
                { 140000, uint256S("0x4dcf1556b92576914bcbd6b79345892a46be3cac4014da8877dbedf0e868bcf5") },
                { 142000, uint256S("0x5b28060a28c9b374711d03298178c8a72ae2219bb7448ff6744a871afd913bc5") },
                { 144000, uint256S("0x410a176bd881b5b10c138e5a1cc19323cba95354a56ed3bca13b9c7617b59525") },
                { 146000, uint256S("0x3175a4b96764360c7a833a42b0109e35effd467f0570fe6652b6bf7037ba6688") },
                { 148000, uint256S("0x3ea544f4c427f30826a3461c1289629fbb5acffda8bb780b52cc97548392b8f3") },
                { 150000, uint256S("0xb1a59ed57b8d63b8f22c0778639ed83675e927338d9248023c9e18d512dfbdc8") },
                { 152000, uint256S("0x09f2593a4b69c9e8c96961989caf7056ff7ecfb68bd6bc7b094ece2afb0e21c6") },
                { 154000, uint256S("0x28810c52d94b874222992567e0941c47a3463d01e0d1435e2f5b15699bc891ee") },
                { 156000, uint256S("0x73ef83a58d52c335282d0e1211758d11b312e21ca17c96b5d4e54039846f3223") },
                { 158000, uint256S("0x218ec95bc448bf33332cf10d58c88fb1599989002abe9879fd752eaff0e56a45") },
                { 160000, uint256S("0x5e359da309f92e13112d6dcdf653a4d7bc67734c8aee09baf70a239bb653984c") },
                { 162000, uint256S("0x4e7c05d21667baae77f1a0aeb41bf7cbedbd6c8fc32c73fffd338ef57b86adfb") },
                { 164000, uint256S("0x4e7ac62f3e8d095f40fb02432f06ba80d61a6291407ff9e52ffdc65b92611ef0") },
                { 166000, uint256S("0x446840af87879836fa00ea01cfe8d7dbca9fcd434f2ba0f789a9b8504d9eb874") },
                { 168000, uint256S("0xd82cd123af6e4ba46bb330d7d1ae6991a60bedba78a8aa43618e35d6c3231e73") },
                { 168300, uint256S("0x19ea608cd637f2339c6739df555ff1b0a27fd392593311dd4ceba5a8803097ab") }, // BHDIP007 signatrue
                { 170000, uint256S("0x28db5d41d36d51f8767ceb63a7322f0f9b7f64d5737e48100197f8219f50fe85") },
                { 172000, uint256S("0x2386f19892240901ef94df758fce5f1c90540f67bb0e3ad1cf6010fcf115029d") },
                { 174000, uint256S("0xc872da8ce684e812f63fbe3cb3e9317162b8f85696f34413989afa5c4c0d116f") },
                { 176000, uint256S("0x4234612b4d046d2d40ab559e614deecf48b18d68e9b4c4e1ecaad861f340419d") },
                { 178000, uint256S("0x9bbf3dbfb163b73c8f7a89d31ce37f00e48e87f3084b86a93a22458159762bd2") },
                { 180000, uint256S("0x640d412ce4513e84ff107eb1930136de0bf24447791090c8cc204c83f37ba8bd") },
                { 182000, uint256S("0xcf2bd7de53ab26c1e8d6fb046d8a8b93cb94ddae6aa96426a99b24f40a043ec0") },
                { 184000, uint256S("0xeaf18bc6f33792f441a91a56bcb21c059af5985ba948a671a0386ccb69b50b69") },
                { 186000, uint256S("0x5e0067e96034f34e4d5f4006ca8db9ae35d799b8e6b7ccf43a1a1d139795f200") },
                { 188000, uint256S("0xbd6955e707034b0858cae13ecf76897a9de744df8ac42c432c98b1ac661e6bc3") },
                { 190000, uint256S("0x89977ef0f2d4c4c73ca503acb60105998f456cde963b628fcec61bff937d1c1f") },
                { 192000, uint256S("0x3a5207e5288f59936dfc771b38b7ac1d67195348c46714dce07d01215e8f991a") },
                { 194000, uint256S("0x562a6d0221251ceacd21b7d75a8d1f83e1ce6978295a29188515f7b65a597ab2") },
                { 196000, uint256S("0x6d843d19eb31c3f5279687e56746a9af2df61d559a7af9c7cb96ddd18096dd8d") },
                { 197568, uint256S("0xf12007a3bd180a75c3db6b5264e509e86331d7947831c51758449c03b6edad82") }, // BHDIP008
                { 198000, uint256S("0x6625f6c687d4f58572f1207ebed1953f5f20c63c5fdc3d59cc14222de1a05a1f") },
                { 200000, uint256S("0xbfb68663c994c3e76c33b4b93b92093a7308ff9f7fa25bd84d59a3c092eba262") },
                { 202000, uint256S("0xc5d824a10eab3d2c8ed366cc5c544a920b1d7edbf747757df084ef72657ed0a3") },
                { 204000, uint256S("0xe0f0686f23b4b93f8539f524a8a222ff0c387e91aaa0685e046f2c88b7fddaad") },
                { 206000, uint256S("0xfd19341a4ab9bb8ec1ddfe1ab4b619b154af70a809c8bc7fddf4c1fd9efe407a") },
                { 208000, uint256S("0x5e2fe184b40cfe90e370dc59927f7e07fb909e919ea82f46e68cda70e9a84079") },
                { 210000, uint256S("0xfc9753fae68a19897b03a1288e67683d64b469f723302f67d7c6b89b0def0c6a") },
                { 212000, uint256S("0x6dc9268d6000a219669ddcafe18a5cd7ef05893bb5db0b31d413fd166e4e89c5") },
                { 214000, uint256S("0xe1449b1ba76823f8586d3f8416f54b25897d80af5a831c30143f9f311520b1eb") },
                { 216000, uint256S("0xb273c8376475b84f3656032ce44b068bc1f7c94a9c32c7c4695b9dfc8074bfb4") },
                { 218000, uint256S("0xc8dc730a71982f9965d9cb46e59a074947e7a5bc6098d55b6c005a6f84c4975b") },
                { 220000, uint256S("0xc68c4bdc49b73591d4ea8ceb5af3ef3677413809fbbe67875213390fdb08d145") },
                { 222000, uint256S("0xb081e10c89ec32a454cadae9c0ef355d2fd60dbae9d5f99ac26f221b42e7bc61") },
                { 224000, uint256S("0x17905215f82523b1c494ea15908f213b0d392945a2c2799e1aa346f3e2348d8a") },
                { 226000, uint256S("0x82cde8d6d772569e988ae77be492c81172a1b85898552e231bde88dd57616f56") },
                { 228000, uint256S("0x7860484f4eb684b76ccb661d33d00e8b0c09989f4849a5472fbc1a1a0731cda4") },
                { 230000, uint256S("0x122dc43efbe575f8f9d87625d4737a1b3b8dbaecb9c8b837c9496a4c7142e9b5") },
                { 232000, uint256S("0xe39d30cd45414978ebfb8468cca494dfa56ffa38d2a292948be601b222787b19") },
                { 234000, uint256S("0x08847ab819f62aeb7f19490c32253a0631a1e9e8e27559763eb195f79e399929") },
                { 236000, uint256S("0x0e1885952ce107c635d76c32c0b077c2bc9cceb3c61d0e4bba52df502ea207fc") },
                { 238000, uint256S("0x94eecff7a84a332ce9315b471854a112ee3d6d790a6dc57a0d201abb47ab6767") },
                { 240000, uint256S("0x5592ab2db0f58dd56e699dfaec340655f7fc6dc855751e58159d2ae7cd49e76e") },
                { 242000, uint256S("0x6f89864cca13a74cc9a83f9cb079f704d9c9171bdd3f233ef939eb69b21bd173") },
                { 244000, uint256S("0xaae98ccf0aaa0880a74b9b8a92c784b587be75872f43a5836018d7fc8021c67f") },
                { 246000, uint256S("0x1423dc5bbb20cec861d35dfa0bd3cc0a4add2a260d1f9066a28ae838fdbf7f64") },
                { 248000, uint256S("0x2a9569cd4691a9b375cdfe6c05f526eb610b9dc0766ac25b435cc26adde8a8f9") },
                { 250000, uint256S("0xaa735cb177a98642ed2cabe26455a93bb48ec07e39738a3992495c13533d5433") },
                { 252000, uint256S("0x4d3b5c0410589fbd46849488a881875b4a66aa58a65fc0ada1823a502874c614") },
                { 254000, uint256S("0x8b6af6ba4d53aa8bd20a13eb945390577809fe2630a05265fb899173837754a1") },
                { 256000, uint256S("0x08a155a0d30e19a50cb6f5f824b190c327c50006eb4b76731178f58227eb91b5") },
                { 258000, uint256S("0x9f9f5993505790b18e8b46803576c318a4a8222ea82b6c46c09fa2fe549692a1") },
                { 260000, uint256S("0xceb815103aa0d34a8b0927141ec8b07c61ee2b44deecd77578478f2ccb853adf") },
                { 262000, uint256S("0xfb56aec8bd0f0f7e8ffa2bc5814d0b8ee3f40a79da0f7479e11fbc94d93daeff") },
                { 264000, uint256S("0x51670fd4a6956b74c25bf8988d703f0797ccb809199a6655077abbf3f137d874") },
                { 266000, uint256S("0xf82e70e634616d15ec9b72c4d5cd8be71f0b69a00ccb10e95d879f53657df0ba") },
                { 268000, uint256S("0x6ae025211bf012bf470e450528b8c45e79bb0433a5921f7e0d43ff62f77f3239") },
                { 270000, uint256S("0xf390e170142a857547b35bb93e5bb7d42e371a82f0890abff999674b3c7f0f54") },
                { 272000, uint256S("0xa77ced6c07e82c8057a8005578568efd1c092b2899c0dcd8786eb45812d50dd8") },
                { 274000, uint256S("0x91b11d77ee689dd885238bd54f7760618da46edc5905f31172dc4aa12a4a29eb") },
                { 276000, uint256S("0x05d3fba4c49ff15d7d75ad611134c0d50277299f32e47ded3c34f565cd1088f9") },
                { 278000, uint256S("0xb6937f59a4473f344894711f4d10a4d54aac35ad2c38e7f66ea8a1dc94135c54") },
                { 280000, uint256S("0x0b8b0524957f581abe8baccf8e539654551445f9a50ecf37e84659c08c5051d0") },
                { 282000, uint256S("0x5513dd36f7f57904e29cca36c7f14050d5dc18e8a1dc3934c73f1bf7b018045f") },
                { 284000, uint256S("0xf7d942f66d50b6629e1c97a9a4044e46c2d060b0a78debce69592df388c4071c") },
                { 286000, uint256S("0xf0ab544892f2adddcd48029fb94a49e1214c8a76547d0b0834cb1f2d19a6b0d7") },
                { 288000, uint256S("0x27e8dc318aad0eb2a3e43bdb1fb4bd4ef8205fe0c7bd336f850d88354e3b3afb") },
                { 290000, uint256S("0xb5df358b346f46ae46972a47a6839779afbae060b9f2089f6e29d1d711c7b868") },
                { 292000, uint256S("0x72aa3525ffde5cf320690c98dbebc1f1e0901da5aa360f18690a65edcd678a12") },
                { 294000, uint256S("0x5c9a58a85a4ceeebb9e5f986bfe4437984850a498000bd66ea70640d95f95d59") },
                { 296000, uint256S("0xa55321cfa7f0001706f45a5baaf35ddc731c261dad6fba764a4b223d0f14dffc") },
                { 298000, uint256S("0xf9c3cea6626dd9998a048f71d4f0db5edfb404cab16cc0ad677b18eaafefcb07") },
                { 300000, uint256S("0x1af1fd881ab45dee3dc0f2cf4c0dd74eb97039d083311b389b481fad215a57b8") },
                { 302000, uint256S("0x33523e7ce24aadb2cdef0921996b784b3dbc5c2013ff94dd37b79d983e073fca") },
                { 304000, uint256S("0x3fbddf910059013054902252cf84abd4734067a712f6e830dc0548002ff703ab") },
                { 306000, uint256S("0xca1d0de7c9deb3df5d10e223eb0111ccd1f3bc2c6908076327421f06ab4796bf") },
                { 308000, uint256S("0x59ac3a9d75cd401e2a68fc121c8093e52154ffb83d87246d565212460e241d46") },
                { 310000, uint256S("0x915e3ef622459f8b1b04dc274e1097b31111b0c6e0a9e9cd2da60c9d692f2c93") },
                { 312000, uint256S("0x73df31896fd8a918b803a1456f03a901acd9ca6111814d04d5dfb185502b88c9") },
                { 314000, uint256S("0x8255df7800b680a1b84d2f50e70eb4feb0ec18234380debb621bd09cf2d7ea6a") },
                { 316000, uint256S("0x3b9bd616ff47790c46e3658c71236f42f8fa1e34b444e2a2ae999a2e8cc77fcc") },
                { 318000, uint256S("0x09c4cfaad2fd555ac406d5a68b776347519bd6f53615bc44dd11578c815becfa") },
                { 320000, uint256S("0x625966af67ccccb3d52232d32666f60cf62326e20d52b7ff6ec24d5a14ffd4c2") },
                { 322000, uint256S("0x83ca175806b6f3ccb2f091cbe7c02054358827e5106912c517d11e42101dab91") },
                { 324000, uint256S("0x6576e76c299865b6943736706295c4d740a8ceead4bdbc096fef463250192a55") },
                { 326000, uint256S("0x6744688612429c0ff85b8ac49683c20837ffeb4098670da2aef2212c3eb93d58") },
                { 328000, uint256S("0x06cd46491a14a2698725c1de6743a596a4f111e4871cf9687b04122200f6ab51") },
                { 330000, uint256S("0xaf1ffa1b09bd9fbcb9ecf914620958928f669b8594ffc397d87e4371a16ee3d1") },
                { 332000, uint256S("0xfff4753e0338ff2f20459990db471b4c8f78f0f244084989556a069390e59d0c") },
                { 334000, uint256S("0xa9fadc6816a081dc10c80b0f9dff6714b8c98508ecb016d4622906ad184ab5d1") },
                { 336000, uint256S("0x95cce405c220756cae0c57faccba6306650304ec79853300d37001eb127075df") },
                { 338000, uint256S("0x8c09f21363c3809eee8df6804484f6101d2a34ce57c8d8746ae8364496efe2a9") },
                { 340000, uint256S("0xba310a041a34b7332d9f88fe64522e6b49d9812ca4dd297f42ad29168338ab78") },
                { 342000, uint256S("0x8fbd6edaeb1d2b91992b3b93c4b263e73b794e1044722186b2329bd58d963f14") },
                { 344000, uint256S("0x539dd0a0310ce2d4b981151ebcad79d3a88601b5efd5b018bc13d5e9daab0729") },
                { 346000, uint256S("0xd24d59dbc0f1e340469b0ce64a41b5a958579e12bb6469034c0314c9879eda60") },
                { 348000, uint256S("0x4718609020861ac10c818487233f7934b5adac512adc7750ab9b8b761f17e007") },
                { 350000, uint256S("0x0c6f71d9f5358f7ee2409a497749eb558d35a1d0492a384aa52cb3a4529ab279") },
                { 352000, uint256S("0x5adab458c6a5f83cb275f9058b6ba338f4cd738699f9a51101e72be0c0c5b317") },
                { 354000, uint256S("0x95663065cef808e490014507239595f23d72e95e15619c8ffcc88d7fb523f957") },
                { 356000, uint256S("0x9f8cc993df3af1fe2a2a2bfe8f5f088b5faf434603b1faa39d5d79a87e17a429") },
                { 358000, uint256S("0xbb5e0e0ecf5a0655f048bae7968a1d657f8ef4a9954b27c4b39bbd1daa33c894") },
                { 360000, uint256S("0x298412e14d9a9f1e25dba65d0a102295997746852213df6e2937a61cd5a271ff") },
                { 362000, uint256S("0x346a581334c1c8edf20b274aaa50b3a303cbaf75bae0c798d6753103f3b18f7e") },
                { 364000, uint256S("0x34adb49807e92dda15d4c2ff63d7ee7bac8c27d6a1643fb4ee8c7024c0b691d6") },
                { 366000, uint256S("0xed4faf5be95a07aa3efa8e770ecdb1866e48b70e528535d8079dc9beaf597b11") },
                { 368000, uint256S("0x587775982a376c8cbdc45b90cd893947768bc101286c63c4f7cb9ba76315b719") },
                { 370000, uint256S("0xd94df8899f764dd316a64b42e39fe3994a6d54de192fab9e6b52b1641e372bbd") },
                { 372000, uint256S("0xcab7f5aa8852d995070b9729397fcaacbbca5a3c5428dfe2de0fce0d57cc2d0b") },
                { 374000, uint256S("0x596f448f21dead2d8abc2816a5ee2dabb9546a4e0220494213f3d926aa526400") },
                { 376000, uint256S("0xbe7891e838c25b2c187b1969e965d42468a8da9e01df80320a6c40a68741721f") },
                { 378000, uint256S("0xb5cb33767fd2450008100555c93281014ee6abaef51c3664fc1ddeee20e5661b") },
                { 380000, uint256S("0xea7069fda792e577df6da21b8fa9cc25572664e96db0c887556e52043e32e36d") },
                { 382000, uint256S("0xbde18f8049acc66463152624fca505b20a0886cc371a2745756168470d8e710a") },
                { 384000, uint256S("0x41a7bf7c408022549e8b5558cd5a2898d2dd578c989ed2ef4dea9f8e23b49a23") },
                { 386000, uint256S("0x82ea3b45112bb8bf8bac3906cb7ab1e1538a3feb547d652a4f651c6ed921d670") },
                { 388000, uint256S("0x71fb0975d7d02b851e6cccc7f04c482b8b54a6ceb1ddf14b1ebd77b2e657c4af") },
                { 390000, uint256S("0x1c7dd10519b0f072297e01360aaad9f8ec97d4654f67bb5f3ef1504a4aca4f8b") },
                { 392000, uint256S("0x85df844e65b4df5019b86ed72078562920fdc820d8bae1bcdf412d6eac7a7d97") },
                { 394000, uint256S("0x35574f9d265c60574703fa59b61e5d84a4814f350ca2560949a0340937ef377c") },
                { 396000, uint256S("0xbc3b1cf0f7dfeec82054ea6d0284b1997ba0873ba248346b5c1e3adfdad3a5a0") },
                { 398000, uint256S("0x1b582d3c0866a6a996437b9ea2f4e2c340016ee6b08707e1bd469cd78e4e3ea5") },
                { 400000, uint256S("0xdea22e91e44e4187b363fdd014e39e0ce78b631787fef389789ac26ac9824a1b") },
                { 402000, uint256S("0xc2770980fd5af1736b01ff3291cc353d9eed0133d75ef9bec3f60e79cd6d20fe") },
                { 404000, uint256S("0x2d873043f2baa92297dadfd127f43e2f1116f26bd0ee1947b97852e6fe7ee6ff") },
                { 406000, uint256S("0x0239ce5c579bd8c6b7b1d106348c1274b433cfb1a6ca606d5604498b5dc49abd") },
                { 408000, uint256S("0x9a5f796c28bf8738d91affcd422d961fe474f720fa028f588a740dc91d95674e") },
                { 410000, uint256S("0x60e5fc08e1ae96bc0b68865c75008069b0034824a1945e55ae7a0d16b658cfe0") },
                { 412000, uint256S("0x3cc1e250cb4993a04585f66c1c33591130b77c964316f5cfa21483d788604aeb") },
                { 414000, uint256S("0xd168634bb00bed81b26548d12cb88c5da4508423febb7046126af1f94929f0d9") },
                { 416000, uint256S("0x15c1acd058d88956b292825f68e0201eab7edcbbd7f16b90a8b864afccda8af9") },
                { 418000, uint256S("0xefc1cb3340dd38316dabbd27ec5608099b2d00abaf7b609141dadab53875a51f") },
                { 420000, uint256S("0x355eab7a5e734e0d3456ff8137fc80d10c06e202cd3ea7148414908e4f6579c7") },
                { 422000, uint256S("0x72a86110229e60af3ce9552bb160e750edbd604dc53a78517d2892b06dec0d7f") },
                { 424000, uint256S("0xa689d2365f03efbb0643585b47bf98a62327c1fe6beaac3fc7b3466112f4ea62") },
                { 426000, uint256S("0x0845170f1db9e3a330f69a66e9e64f0fddfc09ff61d06c5bb45aa18d12f36318") },
                { 428000, uint256S("0x2b4697413db48f40170bb68cbc3ffae57767ae3ee571c1eebb296ca54e65e2f5") },
                { 430000, uint256S("0xa31167bbdd18361684de4ec7185e9ab2d015bd5ceef46ef9a9e420bc1aa2df15") },
                { 432000, uint256S("0x30fec41c0317c857a6298bb34da9a71e1c18f49a18b54f19a37dade1bc3a01f1") },
                { 434000, uint256S("0x5f57873f1284d1618c4282414614ec915c666089abccd83769c6d9d8078f57f5") },
                { 436000, uint256S("0xedfb682366ec875dbc43318d2cb24b1c717ec396b9ec21d5412f5cfc1cdf1394") },
                { 438000, uint256S("0xb1d65e71c523eaebfacaa5ceb6124d402172039f7470f7bd0f50ae9e3cf6c592") },
                { 440000, uint256S("0xc8d26f76edda69f3df8d5ba8601628feb33f631210653f788cad58373772a2e3") },
                { 442000, uint256S("0xde916cc3a040111e3c8b80bcb0856acf7838d3ba9876a738287daab703bef37f") },
                { 444000, uint256S("0x6472d858add7d0058b886d3bdc63d559c54dd85e248f9806c2de34e42fbfcba4") },
                { 446000, uint256S("0x7573d00f47f15697ee1995b288d9d10daa3bd7895d6f8e81c2dae47e3b0f2e62") },
                { 448000, uint256S("0x7b0f8748d6169fe264ef700b077e051df3c4de266bff5f38bae7caf92ded801d") },
                { 450000, uint256S("0xc876d12ea413cab35b3a54b870a93ad756b584dd034c4d137d513da378e151d7") },
                { 452000, uint256S("0xb938ce8d4d04173b2c04e35808207945bcc773d32c67ac769bd7cdb75fbee921") },
                { 454000, uint256S("0xc7b9efde2298989fd1d64afa3cc4fafe1ac411e06703312392261c5c6e933806") },
                { 456000, uint256S("0xc55518ba7cd3a55d1ffdfaf9cc9bfd75e5fa17ced0aefeec1a157f35401fab8d") },
                { 458000, uint256S("0xb4c2e67e5173bccd379f1b8a8a3afee78e916f5d7f79765561a0e143ec46a132") },
                { 460000, uint256S("0x6ea0ee40b41776c32ebc113fcd5dc11a17af1c8174dd9095cca71975e1f99ba1") },
                { 462000, uint256S("0xfc9c7b1246ccf12f2b995124d9dded6933869b2a2dd78439cda4cd1fa449ce7c") },
                { 464000, uint256S("0x6c3f7bab22a58ec79bc4b7ed72bd341392e302afe92c2b794efa68130613e2ba") },
                { 466000, uint256S("0xd1967af24be195d5c26099a38e0ba7999dc553803cb6fbfbce23b45a6cb27ce2") },
                { 468000, uint256S("0x15d851a0fb936069aa35a81f567081177071473d6be4b9a4ad4b2cdc060c49ed") },
                { 470000, uint256S("0x5c17ed84481f52380345dde166851621710b9edbf2c07c1788dd6dbea8406607") },
                { 472000, uint256S("0x3376e2f0ff9153e27db057d46f6a394bdc7dfbbe2805530ef9a0b11f4f9380f0") },
                { 474000, uint256S("0xc50a63e636dd9d12c5cb34553013fe0abebacc135815c85bad93587275b1203a") },
                { 476000, uint256S("0xb9adba4fe5f3cfa77380b75ab8bd517fff5f2d8d5c46274ac1bc3aff057d12de") },
                { 478000, uint256S("0x913da355be316c8639291351f93b977ec07399157d29a83c46b498d5c4fe2afd") },
                { 480000, uint256S("0xf274998de59ee8496a0194e8bebfdc9dcf85cbada6089f9b71961485ea01dd44") },
                { 482000, uint256S("0xcf0c16876102b7293bb3114fa88a54bf33ef4a081f98b8b95034ddcc4b95bb49") },
                { 484000, uint256S("0x396a5b2cff0aa6f075acaba3f27142fa124c017b600cb628a39f14079f485219") },
                { 486000, uint256S("0x3df5a78359cfbb88e9446d172391cdf747937acf543be0a3b68990e2f2fb9425") },
                { 488000, uint256S("0x178b0a6a4aab726e2fa4ea2cf797d32ddb14d3d960c2767c6956f1a494741af4") },
                { 490000, uint256S("0x9f11d47689242c5711b60235a8d56a041e7f91ba3fc38e862240b59bc7ddb0a7") },
                { 492000, uint256S("0x86afd50ba8045691bdf68b8c3d1cff307ccf560a6a9c456b279751590d62cc46") },
                { 494000, uint256S("0x1085dbe435ad931848bfb23e8d7d5feb3b82a98fd0d121afc9233dc031634c00") },
                { 496000, uint256S("0xfffed7f5479987db76beb5a7247e496021cd73d82ff9903adf71b781d5fe7013") },
                { 498000, uint256S("0xd868af8dcbb1fbbb026d9b69a74e31e6a56cb5403e3cadce768c5987782eaba8") },
                { 500000, uint256S("0x027e43a41c4d2736378a0db39017d1aed20a4e68239889561f3c2194de40d276") },
                { 502000, uint256S("0x2c109201f14fd6d714cc2c525cb539d171fc2cec83664c67263a13478a170543") },
                { 504000, uint256S("0x6bbc7166ce650377465c0725e7927bca84aef7995e34bfa624c20c7e4e1cb162") },
                { 506000, uint256S("0x638b3c38e8e606149875d0c88faaeb7fec439182acad21556867bc097fcb49a0") },
                { 508000, uint256S("0xc55e30dec7d6dc35d0d2806b8b572abf94f3dafb88f305872e86e18337a01652") },
                { 510000, uint256S("0x536e191820cd9754e0f62c9cdc523e3e1076087699977892dc2d0f2f02422701") },
                { 512000, uint256S("0x21e79f8a8e942a0175be80616345ff011db3a748b09d1bf0c5e3d21f91d67600") },
                { 514000, uint256S("0x6cffd8723b963207c08ff9a56759c8e69c8132e5ffa7bd750813a57282d8ee3c") },
                { 516000, uint256S("0xa8453611cc26f35cd76f1b67bfd2834046864e94e1683b6820f268b895213fdb") },
                { 518000, uint256S("0x814d025b4f8a632fd6185e531296faec30d2cec50ea4113867c3e029bc988092") },
                { 520000, uint256S("0x4fd9f5991a9fdd7d9d9546d368697c0c615f42d34d8a65903c78a51815e1d743") },
                { 522000, uint256S("0x29679f62ddd122e96c97ef345b9532dd88f8d766df10f96df605c311416cc915") },
                { 524000, uint256S("0xf56454e5c3c986d0520a6c3b77dff1d76e3edb935678b2de84fe28127aad02d4") },
                { 526000, uint256S("0xfcf2221b52f8dc7aa99516cbd88a4f83b18e39ac6309a89c37ad149459b0410f") },
                { 528000, uint256S("0x09177f8d30ad828a3022c9c2fe7ca24681cf8969fe71e941497362fb6dcc46b3") },
                { 530000, uint256S("0xd57db6f2b8808139836eef75584a70d6e61d1735d7dc7e072ea3d033f64867d5") },
                { 532000, uint256S("0x6ba442bcbef8d0b3e312d22dff40bc3f9d250adf026cd0083c07d85a182cd761") },
                { 534000, uint256S("0xb9f9f283ed9f97488818ed895bfdd49599564a0a6402983d32fed8f0508b0648") },
                { 536000, uint256S("0x34b28ab9cdf35ceeb8688aecfd9b43beedd4e36389d64fb04426428aa0112b4c") },
                { 538000, uint256S("0x15f729b63a587baf70d683cc3b7901a650f392938314ac97d2a6d1495fcdecfa") },
                { 540000, uint256S("0xcf1d4d8c95705daeb1cfdc986420192ed28c2e2a59cc47b5267f07c90aa3a036") },
                { 542000, uint256S("0x1fbf84a655b906f29d284e7b059abdd091cbcd700dfd27c4117e368868ae727c") },
                { 544000, uint256S("0xaf0e68439335372f8d027588062c62e351cc23162916ad464dc1262cc4d584d7") },
                { 546000, uint256S("0xbd95954b1f49bf9a11109bf3c68a641d040e6e77e2cdbb291b9c0a87cc75a292") },
                { 548000, uint256S("0x5627f77d593c8b0721f775314cb7a1872b68a6591d2e64d2bdbb344eb9a091be") },
                { 550000, uint256S("0xb55012c5d8e3959bad190db378db02519470d882fe4f23dfdc2da321eefc5a72") },
                { 552000, uint256S("0x0e9b89eb9d414e6e282d66bf6ddbe6874a611163bfe1d8137117fc8661294af5") },
                { 554000, uint256S("0x822236f5e5a7fe83a2d066426385786268f94f1f82d012171c3f0d274f48356b") },
                { 556000, uint256S("0x0fc034efeb79e4e063eece8811f662b6157f91c6ef6aaf8faaaff3312112464c") },
                { 558000, uint256S("0xba47abb1fdf7ecdcc654e5d7e158f03b104ab838bc8e5dee24141d28f6ec2677") },
                { 560000, uint256S("0xc7e40e6bece7cb7ab36433d3161d9144ebbadc84ea3447f0918f5f7626fb309d") },
                { 562000, uint256S("0xcea913ebfc7e96fdeebc0ca591169d1043696dab718b5b01dbb9cfdfb112d043") },
                { 564000, uint256S("0x275610d09c2159fa56d10f61fffe75a6d3ae29dc2c95eadc9497059fd8920240") },
                { 566000, uint256S("0xb0ab75d12ede530691ab4d322b5c5c460d9fa8df47a7410150bc32738194abf2") },
                { 568000, uint256S("0x5644d8e05d272415e27b9d03c06b508752e5f364127ecd68b6e892be12388fb4") },
                { 570000, uint256S("0xf5b2c9bceacf00da3815ad5bb310eec0f78449e12121f58e37e31573d2631513") },
                { 572000, uint256S("0xd676235890253daf99b8366e811d404762f618e97493c00f70a2c9a2ce876a9b") },
                { 574000, uint256S("0xd13f9b9a3b49992dd2e11678f2cb132970d6630430d5ab4eedc6be56d4826e44") },
                { 576000, uint256S("0x9664f53c2dccbedf2d4fb8e3854754f3b6183458f1966b2330c9704f1fc72f73") },
                { 578000, uint256S("0x880c0fc8f4deff78d27b7e17ffa768ab89962403f0ff5abd5f313237582a62e0") },
                { 580000, uint256S("0xf5691f0db36518e3d3a376fe97d4f118982fcabdea1c773b33c83707b24464cc") },
                { 582000, uint256S("0xd61146529ba132c52808a7dc5d8fcd6ef0c24bef3750ab529d3539917efbb1e4") },
                { 584000, uint256S("0xf1c8c517d4a05abcc825092c90b81210e3c12e9dbd3159c0aa167efae81daff9") },
                { 586000, uint256S("0xdcea0d7b145a05b8d70cb9a77020f24baf02ef65daa547674dfe5f82f9915832") },
                { 588000, uint256S("0x1c4c3d38813b617c704ba2808611f80c675b0755cb3530fd290d70cc1ce16e43") },
                { 590000, uint256S("0x41c84d5e8d17a65d2adf3e3239b82337ffc081282c159a528865e6c48c84b366") },
                { 592000, uint256S("0x09fdb87d0cb31c81139f91ac0e29c51e5a39e5b0b548957071e9838fb8dfb3b8") },
                { 594000, uint256S("0x5e5d43209b90b671176a2ce70ce8cbc0730bf9c4e0a8d4b814345d28e3702095") },
                { 596000, uint256S("0x901e791134b3d26ea5dc35bd09fda512828635a0ee1aad095d72b8521d722db2") },
                { 598000, uint256S("0x043ed703f864e9638bc6a86aea363f97a4db4afa293e72ef34efd983179cd079") },
                { 600000, uint256S("0x04cc1f50c27aa45a1df936f1be8e9b523071c9c7ac72c6b4f5a086cf1dafd14a") },
                { 602000, uint256S("0x30d2a593149a7502c386105908402a99e2af1e405533c6c66b2e6a7f5e80ca0d") },
                { 604000, uint256S("0xb562403b6372ad5fc08bf261840e3fd575aa4185eca2be0717ed8e008b961034") },
                { 606000, uint256S("0xc798408c206c2f40d214004f22cd0f436c3f242296d47dbf8fda83cbf490d71e") },
                { 608000, uint256S("0x73feb836b5d724ae2ca62b5089c861980225eadff43ca28cebc38556b895e1c6") },
                { 610000, uint256S("0x907ecc18583c874492721c12512a827df691c584c40f4687ba5a382a1236d4c2") },
                { 612000, uint256S("0xcee7db6fa18e3a425086b0f9982e291fdd41711bc20e0cbba717c41c8c65db56") },
                { 614000, uint256S("0x7bca9abaf1b28563198d66ab8b413358d88efb57640b4d84ce15008c2cc77175") },
                { 616000, uint256S("0x4d72f2b2e070a94fc66bd409c1a1485452d79f4bc0605913b654eefc04c90786") },
                { 618000, uint256S("0x134324796295244fac24728a17a3155a48f13b8d9b17d87eb01cefedff3036cb") },
                { 620000, uint256S("0xd265d9d3095c5e5c80bfa5050f6fdf8ecda2aa26c70f1a29037b5f23cdd0dbcb") },
                { 622000, uint256S("0xc8dcb1364858313fa3e1986f94771b9e65be9a91f885bb637002c3c05ef8bb3e") },
                { 624000, uint256S("0x1d4166d0c4b0b0e483b0c499ad812f23bce3775c1d5898d4dd8e625552068b6e") },
                { 626000, uint256S("0xda427e7dac63cdd4a40a02b31f335151f8d356ff305067218b578be559f453ec") },
                { 628000, uint256S("0xecbaf5bddb4600564c1ae8da447027310e292c3ffefd097730c7fd598d079514") },
                { 630000, uint256S("0xc3e559664331b1ddeb38fa3e57c8270c378954281e5f287eb427350b3bdea1e0") },
                { 632000, uint256S("0x6efc8ef58d5f9ff34a451bbf5c2e5f6f0a0bf72f845d59ac8085d43ef2ce49d9") },
                { 634000, uint256S("0x75c9acf55ac903479ae79ef10dd3e85d45260fdf2905cb8d599390ae889be63c") },
                { 636000, uint256S("0x57b262ca514422b3222d5db66039b8b209155f1b44a14900a705b88758cc9ff8") },
                { 638000, uint256S("0x1f6a1e92d8bdda4357257a0680888b412195620fd321d6c5d37f98b3b38f38fc") },
                { 640000, uint256S("0x1c491cbd59be95c2422124d173b44490bd376813eef581a91a9699d4f8341810") },
                { 642000, uint256S("0x9e1ee9ac8b5f540b18a452688f8c7e78a38272681508b073b568114593f154e7") },
                { 644000, uint256S("0xf6a19748fb0ddaa51a0ac5aba12d1ad4f310c3ecc4a9fd7ee4703b1b8040f976") },
                { 646000, uint256S("0xd89d0c78d7686c1ffe0306bd336dfb852c42a954cafdfe2deb0ca1daa6ceb432") },
                { 648000, uint256S("0xb4787692cf096682695b81ca971788a67083a292b84411a1816fc8cc488fc34e") },
                { 650000, uint256S("0x85b0fdc40017d867f22d028a8baa34e2212866bba7cd81c0c02c44f993995fe6") },
                { 652000, uint256S("0x179f6e945b48417512769dde06a4ae28ccb41114dd29393fdef253150a5ba9c5") },
                { 654000, uint256S("0x53966535efef5a6fd3e32a8edfabae0956699a230ae6eb589c69adf5140a4d7f") },
                { 656000, uint256S("0x0c8b79c142e0eb7723b73e48f342503ebc5088b31ccbfbe6043f0c248e4f3721") },
                { 658000, uint256S("0xc3d64fe709d162bbd2eb071a23ef7d04eb9c6a58626ccf927e9fbba1917ac490") },
                { 660000, uint256S("0x8909565e1e0a56113f34cd33640ca6ea93c6a507b3bb3730885e4fd2a91087af") },
                { 662000, uint256S("0x98c953426ce51558491c63d840be5e281f0dfc6be91e403dbc71e8e0eaddd63c") },
                { 664000, uint256S("0x0067d03b24c321bd7b8a0861121f25fb601858cf28a71f966c4a0151eb071798") },
                { 666000, uint256S("0xde3b617987829ceeeff87d49df4b4f7f994d16693e9205568ad20fc569a88c5c") },
                { 668000, uint256S("0xf0c95093c76cf4a151eb905decfc59a6c91ee716a0fde343e026ca57430567cc") },
                { 670000, uint256S("0x1fb04b17a6fd81def256a7d2f5e742117090f5f5454027e2ef9c065b6475ef70") },
                { 672000, uint256S("0x6acafb4db33dc67410f2277218bf9dcf2a9e52031a93e7422ae55d7306ac6b64") },
                { 674000, uint256S("0xd6f538907b0a354bd2d62f8edf000f5ac4334485420e70a45ad0c20e8491b9ef") },
                { 676000, uint256S("0x1430437f12478f4cbee8b96f889bd5a8959a5d1fed42a677cf5bc6b26cdc3e92") },
                { 678000, uint256S("0xa1b490eeac4b3c5d5cc0d1f3aaaa0d94b117769cb797beba9f49467c0cdba39d") },
                { 680000, uint256S("0x26e7279cb35da11b8cec66302aae09f6ed0331d71f99aab20075e519ccb71fc9") },
                { 682000, uint256S("0x63748712afef12a6659fc1e9ef36b8c2c803d8f5d7c9c945cfaab8276c2a6325") },
                { 684000, uint256S("0x8280caf670c14f494dfe351b073fa0fda80aeefe289a2f7cd74450a5b8fef2d7") },
                { 686000, uint256S("0xc3fddfec93938428e41da4d92de3384034d577f948a3292ce176cef786dbcb97") },
                { 688000, uint256S("0xfe918beb5e58b2ec13f92bc8d30c6eb8dd7ac0b1ca93dce2c228d47bc42334e9") },
                { 690000, uint256S("0xba83adf4484500e37d1eb1943e5152fc5af621e7d927c5d1bfc8149967efcc24") },
                { 692000, uint256S("0x35cf4e1f7da8326a5e24d5521e304753ec523dcf653ddd991eddb75938335d9a") },
                { 694000, uint256S("0xc2a5a86e5f00c82caf464c8d10b41139154b6a847dad7c939e2f65cf25b24f74") },
                { 696000, uint256S("0xae38bba0b78f8ecf1d6a5fa6715706bf935de4a6de0d9a4057a8db31f981049d") },
                { 698000, uint256S("0x61c14c2eba363a3214954a8e323b363796bac7661faba6245aff52f8b582e637") },
                { 700000, uint256S("0x69a8dead10d8c869fbc5c7c25cff9379cd690d23de9490b74fa51692209b5b65") },
                { 702000, uint256S("0x58d84bfdd6902aa51662d7729721de225f4c3ef8fcb5fccdb70584f0716ac4ba") },
                { 704000, uint256S("0x303da3afbe977b08b07618cc89bef68edbae65638a9517c504e6936ed7bf323f") },
                { 706000, uint256S("0x35ab100312e8833b5893d8858ba3cf0df67247a8165765c335b97f65b539eac0") },
                { 708000, uint256S("0x0051b4b0de891b737d20d11901dc77ae39029b5dfabc13071062bd84fe930489") },
                { 710000, uint256S("0x04c708f4d175d1e61e606556a889a822960954c791a81fd827080e6d617bd85f") },
                { 712000, uint256S("0x2c238f69c36afa5fb849b9adfb2bc6a7a846d3bd9841b6d534999e23d4ab7846") },
                { 714000, uint256S("0x31f1526524a91f848eb2976f623a72f3dacb13975fc6c833079260c48fee3e2b") },
                { 716000, uint256S("0xd6a4819d39f301992337674838b199dbba2b2139ac66403090acc401306b8976") },
                { 718000, uint256S("0xe684057cdaae70809015beed068ffab7df85bdd15165ff47ca5afb1ea2c24aa6") },
                { 720000, uint256S("0x00498fe513143bea3a947c339ca8d91fd564340621e540d11cc30bc166e9362f") },
                { 722000, uint256S("0xb6f80d42d5ff6158cc8d80dbb4ff0e892f054b5e9ccbf856396af8a83b3b3542") },
                { 724000, uint256S("0x8edd3728e26b6da225a0bdab94fae37353a97b4cc961f02f27483cf40e6473b3") },
                { 726000, uint256S("0x3f4e975a250f6792db4e8f06d2cc5bbea122e83280811983b15ed2fa88630f47") },
                { 728000, uint256S("0xb254f83cb14cbc87f4427c9af462a62ba45589c19bf2effc47587b52afce124c") },
                { 730000, uint256S("0x85799f6376f2f91ad79ba27e05a90434b69c82a881db659c3be8b67b50cc88c4") },
                { 732000, uint256S("0x3030493d8fa1892f0f25ee6d17a0edb41eb1eb22ac507d098eea15651a72726b") },
                { 734000, uint256S("0x6a306ae083d65c73210cd660af4b16b3a9269dc407fc0eb289bdc34d5ffe219f") },
                { 736000, uint256S("0x199ae06110936181395a98b627b5b7dd3b803bb77fcdd12cc0aaac07d272cff9") },
                { 738000, uint256S("0x473506c8b3a45308eeb032be4b75ea48455f201360fd2ec09941d0ad72219ac9") },
                { 740000, uint256S("0x6a3d338085497d8340cdb8b1a07ffc9e2dd42a1821336139c1bd0b39187fc15e") },
                { 742000, uint256S("0xe9d0cfaee6e937a0e43d4e0a32943b71a513214012b95c3b107e657c64942e04") },
                { 744000, uint256S("0xc62d3e4a142611d8e907ae37df15d0e82bac1e3087922c6052396a28240efe0a") },
                { 746000, uint256S("0x987cc2bb7e17688f1d86c07a4a21fd89f0c5665dde8e003612e4863bc049b276") },
                { 748000, uint256S("0xfd82388985adaecd7777d760c8b7b7b426009fd2beefd770e1a954dfb17fd14f") },
                { 750000, uint256S("0x36515b77b1f6e0897f9c95ccb55ef98d18476d64e5e1e4b32a90664c9f1aa281") },
                { 752000, uint256S("0x45980c2607b976284d5713dcf835900a4f4538a8536e6266e6e44f163b40ea7a") },
                { 754000, uint256S("0x0de1ef672c0192423ccdf8128bb5af1f0287b990f3021cd74c7a78e8adba2ed1") },
                { 756000, uint256S("0xe829aea9ab98aa4445200ab5665ae206aa92851e37898d7a2a35abd1403e080e") },
                { 758000, uint256S("0x72de6de4556c954551eb9e9afd09ea6b71a0571470a89154b0f436a0fbb7d5df") },
                { 760000, uint256S("0xcbfb471e8140e3f007f889f5f7637c2beaec66303530387136706e66340c0b46") },
                { 762000, uint256S("0x002e1fc05cc4365671db44c6c3b081cf65407a250b1189d5c89328a58498e2e8") },
                { 764000, uint256S("0x9a247b006177ebe3f2645299759cb877b3a5e54f9c53955ac98da5abb9eb0672") },
                { 766000, uint256S("0xe06f27511c0c2f1868568ada792bd495cfddd54640d239fb488e0e910dd23c08") },
                { 768000, uint256S("0x603a71d377f65a35b8d4285c56010fccee872705ee95271f4173de5cbeb73d64") },
                { 770000, uint256S("0x15b59bf8c4d442c6d2c115e0bcf00f10a6a23eea68b3b39a8a5e032cad99c752") },
                { 772000, uint256S("0x89ea2edf55ce2b18a99179f8a47514268cc9090f9c58ba4c04aa54fcf6109767") },
                { 774000, uint256S("0xc7caf4dccce665c005073727c2640fc35ab786e4d04a8b9d625f498eb2539a89") },
                { 776000, uint256S("0xeac41667f0cd4a280bbae61203d57b7a33cf19f29b63b03e28cd60e00a20d49b") },
                { 778000, uint256S("0x2df4547422f1c8e6c07427ed27ee2f9aa8291cb5df03b4ea1d45e2b7f5587509") },
                { 780000, uint256S("0xc9151ee5664505b1de7a60cdaa9cfe4e094d55edb569103da859a8a9fd329dfe") },
                { 782000, uint256S("0xaf160259c87759d707492f3d65f40b457f1a483dacdc8831dcd89f49c75f09da") },
                { 784000, uint256S("0x7799df4f4693bc44ca8c176aeff560674ed0769c85ece23019c8347e5124ed91") },
                { 786000, uint256S("0xb894de345089706d1e8987b1546130a09c04ad4ab0339a03a979b0f6eefce41a") },
                { 788000, uint256S("0x0405bd4f858c6d5ebf2695b7101cd96a6f8b22755f7d7b31a17a59e2f7b37cba") },
                { 790000, uint256S("0x6d8009afacb5a38e96bb567570f918a42cab7a30576f952fe4eef6ecc170e150") },
                { 792000, uint256S("0xb9d173178b6f6b9edbf475b63826bff9b98fc266cd8adb98c3711df60b62c493") },
                { 794000, uint256S("0xe2dd90181d8e79c08c4091e29c40653653b2cee9b2eb423d3dd677fdbcf4c35a") },
                { 796000, uint256S("0x0708420ee03155569a7ff97f08b1cb897374332f5048f1efe252e2ce842aab22") },
                { 798000, uint256S("0x51adddd7a5571fe5685d0d2c4905973d7e13a7cc4108fc91cafa05708abfdf7e") },
                { 800000, uint256S("0xad91a0f5c7add35f87f13da778489fc636817131851111a0fa85be13801f50e7") },
                { 802000, uint256S("0x2de963f7912ca940f2199e57dd1e6304e43ad85b4aedd2eea62ad6670188ed17") },
                { 804000, uint256S("0x43c5101cf7708a23210ff59bff5cfdc2a033748fb8fb6fb11b2d652782b70405") },
                { 806000, uint256S("0x4f80981768614ddcf92ea2a60384c1527290e791ba8133644eaa255060377526") },
                { 808000, uint256S("0x6cdbd094a38dbbb39c321bc247ede6d96d221b717316fc62e2349b490e587696") },
                { 810000, uint256S("0xabb1f1e2939b4e1d0ba43662d8313b1da9ec382e4d7ad8982731ded82006828a") },
                { 812000, uint256S("0x67938ce47d211150647d90d6ceed7d81218c42808474e72dc45121ca678657e7") },
                { 814000, uint256S("0x53d715baa001419de2259a1ceade75287c2271514cc4d841586cceb74f398946") },
                { 816000, uint256S("0x9cc95eefef56d63e40066eb051d5faa93e0bce1b900b02e33d000f1649f61e59") },
                { 818000, uint256S("0xcf8492b328d6a70b5da4adfcbd22fc22bc285cc9d14fb727fb4bd14eff7393b9") },
                { 820000, uint256S("0x91fd2a79194de9cb4d1dae01a6816d6799d99a24a0bbe194d463a6e1eb2d88bb") },
                { 822000, uint256S("0x131ecf9c33236bc99671b73f7ef9b8730e8d8887f121ff9dca61e38dca6c8ebf") },
                { 824000, uint256S("0xeb4f9f0f86f212d75310cce4680b41a856e5415366628dff6b8d9c70ca789513") },
                { 826000, uint256S("0xab43d5b22f5d7d27a723ffb79cfb0f104b2b353603dbdd380c66dae6099a9192") },
                { 828000, uint256S("0x5c7b3b70b83e8a3e30ea8d66c521e3ef23f7fdbc54640f4b72ede014cdceae73") },
                { 830000, uint256S("0x9ef2479ef5255c2ed17306c20e860bb026ef502e023ded93485e6613fc846cde") },
                { 832000, uint256S("0x6b9d052b8f47a88b1454d1aefc35837f5bb3d6482ef1adac9836c1ed39fd5622") },
                { 834000, uint256S("0xa279df529ff799b2d6d101af8c331ccc960f8b25dcd722da79ff848c34b31b10") },
                { 836000, uint256S("0xcb9580d6f60fe782ce93b596edcd7891dd2f57f9951ec24403ad9eec647a9ca9") },
                { 838000, uint256S("0x9fd758d995200670e2f887638ad6b3e81342aa8f5beef67119da55fd5b7ac1dd") },
                { 840000, uint256S("0xc2d51cce900392ccea3acfb39c3d38b447d329002a47d3e3ba5cd044f5ffc619") },
                { 842000, uint256S("0x9caafa2f3ff1fe096ec46ccb741a00660961faf9a91cb503b4d1259691167d64") },
                { 844000, uint256S("0xd3a79173ce32993ef03f589d1add30d406cb316aabc3d059ca567f7645106fed") },
                { 846000, uint256S("0xbe2a7302e517bc13e6aad67433661020d42b667e99d5feee45e1c39a66e290e2") },
                { 848000, uint256S("0x1514f5412516ad71c66cd5b1d211e1e5d46fd05f3f2365a859dad566b6cd6c8e") },
                { 850000, uint256S("0xf3c10e82d85f205398229802b22466eb2965cdc9989292e5785d7117adc8e9c5") },
                { 852000, uint256S("0x3ca9762f753daf2c886c5b7af7955ecdb76ecff69e42736100e00b00043b71e1") },
                { 854000, uint256S("0xc4bff3c99e080b9ecde656263cdd3f8b6c1baf1e46c5900108bcebe6f8e82226") },
                { 856000, uint256S("0x5cfa6f7a657ceaef08a919934510646ee3c63d91d07165a5ef01a886611c896f") },
                { 858000, uint256S("0xd374ce447a9225f6b6790093b2b1eeec9247751ccab28e1beca4f986f8a8457d") },
                { 860000, uint256S("0x1de6b21b331472c49758e77d178cffa4af05100be19263ff65cf09d961a6853b") },
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 915e3ef622459f8b1b04dc274e1097b31111b0c6e0a9e9cd2da60c9d692f2c93
            /* nTime    */ 1587324676,
            /* nTxCount */ 496881,
            /* dTxRate  */ 0.01319561041786995,
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;

        consensus.BHDFundAddress = "2N5aE4GqA1AYQWmDWaHHRTg38cBBXQr3Q58";
        consensus.BHDFundAddressPool = { "2N5aE4GqA1AYQWmDWaHHRTg38cBBXQr3Q58" };

        assert(consensus.BHDFundAddressPool.find(consensus.BHDFundAddress) != consensus.BHDFundAddressPool.end());

        consensus.nPowTargetSpacing = 180; // Reset by BHDIP008
        consensus.fPowNoRetargeting = false;
        consensus.nCapacityEvalWindow = 2016;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.fAllowMinDifficultyBlocks = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016;

        consensus.BHDIP001PreMiningEndHeight = 84001; // 21M * 1% = 0.21M, 0.21M/25=8400
        consensus.BHDIP001FundZeroLastHeight = 92641;
        consensus.BHDIP001TargetSpacing = 300;
        consensus.BHDIP001FundRoyaltyForFullMortgage = 50; // 50‰
        consensus.BHDIP001FundRoyaltyForLowMortgage = 700; // 700‰
        consensus.BHDIP001MiningRatio = 3 * COIN;

        consensus.BHDIP004Height = 96264; // BHDIP004. BitcoinHD1 new consensus upgrade bug.
        consensus.BHDIP004AbandonHeight = 99000;

        consensus.BHDIP006Height = 129100;
        consensus.BHDIP006BindPlotterActiveHeight = 131116;
        consensus.BHDIP006CheckRelayHeight = 133000;
        consensus.BHDIP006LimitBindPlotterHeight  = 134650;

        consensus.BHDIP007Height = 168300;
        consensus.BHDIP007SmoothEndHeight = 172332; // 240 -> 300, About 2 weeks
        consensus.BHDIP007MiningRatioStage = 1250 * 1024; // 1250 PB

        consensus.BHDIP008Height = 197568; // About active on Fri, 09 Aug 2019 10:01:58 GMT
        consensus.BHDIP008TargetSpacing = 180;
        consensus.BHDIP008FundRoyaltyForLowMortgage = 270;  // 270‰ to fund
        consensus.BHDIP008FundRoyaltyDecreaseForLowMortgage = 20; // 20‰ decrease
        consensus.BHDIP008FundRoyaltyDecreasePeriodForLowMortgage = 33600; // About half week
        assert(consensus.BHDIP008Height % consensus.nMinerConfirmationWindow == 0);
        assert(consensus.BHDIP008FundRoyaltyForLowMortgage < consensus.BHDIP001FundRoyaltyForLowMortgage);
        assert(consensus.BHDIP008FundRoyaltyForLowMortgage > consensus.BHDIP001FundRoyaltyForFullMortgage);

        int nHeightsOfADay = SECONDS_OF_A_DAY / consensus.BHDIP008TargetSpacing;
        consensus.BHDIP009SkipTestChainChecks = true; // Do not check on test-chain construction
        consensus.BHDIP009Height = 200000; // When reach the height the consensus will change to chiapos
        consensus.BHDIP009StartVerifyingVdfDurationHeight = consensus.BHDIP009Height + nHeightsOfADay * 7;
        consensus.BHDIP009OldPledgesDisableOnHeight = consensus.BHDIP009Height + nHeightsOfADay * 14;
        consensus.BHDIP009FundAddresses = {"2N7mAbSHzAeCiY2WJzREPJYKTEJbKo7tYke"};
        consensus.BHDIP009FundRoyaltyForLowMortgage = 150;
        consensus.BHDIP009StartBlockIters = AVERAGE_VDF_SPEED * consensus.BHDIP008TargetSpacing;
        consensus.BHDIP009DifficultyConstantFactorBits = chiapos::DIFFICULTY_CONSTANT_FACTOR_BITS;
        consensus.BHDIP009DifficultyEvalWindow = 100;
        consensus.BHDIP009PlotIdBitsOfFilter = 0;
        consensus.BHDIP009PlotIdBitsOfFilterEnableOnHeight = consensus.BHDIP009Height + 0;
        consensus.BHDIP009PlotSizeMin = chiapos::MIN_K_TEST_NET;
        consensus.BHDIP009PlotSizeMax = chiapos::MAX_K;
        consensus.BHDIP009BaseIters = AVERAGE_VDF_SPEED * 60 * 2;
        consensus.BHDIP009BaseItersVec.push_back(std::make_pair(200210, AVERAGE_VDF_SPEED * 60 * 2));
        consensus.BHDIP009BaseItersVec.push_back(std::make_pair(200240, AVERAGE_VDF_SPEED * 60 * 1.5));
        consensus.BHDIP009StartDifficulty = (arith_uint256(consensus.BHDIP009StartBlockIters) * chiapos::expected_plot_size<arith_uint256>(32) / chiapos::Pow2(consensus.BHDIP009DifficultyConstantFactorBits)).GetLow64();
        consensus.BHDIP009PledgeTerms[0] = {nHeightsOfADay * 1, 8};
        consensus.BHDIP009PledgeTerms[1] = {nHeightsOfADay * 2, 20};
        consensus.BHDIP009PledgeTerms[2] = {nHeightsOfADay * 3, 50};
        consensus.BHDIP009PledgeTerms[3] = {nHeightsOfADay * 4, 100};
        consensus.BHDIP009TotalAmountUpgradeMultiply = 3; // 21,000,000 * 3 = 63,000,000
        consensus.BHDIP009CalculateDistributedAmountEveryHeights = 20; // every 1 hour the distributed amount will be changed
        consensus.BHDIP009PledgeRetargetMinHeights = 10; // minimal number to retarget a pledge is 10 blocks in testnet3
        consensus.BHDIP009DifficultyChangeMaxFactor = chiapos::DIFFICULTY_CHANGE_MAX_FACTOR;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x915e3ef622459f8b1b04dc274e1097b31111b0c6e0a9e9cd2da60c9d692f2c93");

        pchMessageStart[0] = 0x1e;
        pchMessageStart[1] = 0x12;
        pchMessageStart[2] = 0xa0;
        pchMessageStart[3] = 0x08;
        nDefaultPort = 18733;
        nPruneAfterHeight = 0;
        m_assumed_blockchain_size = 3;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(1531292789, 0, poc::GetBaseTarget(240), 2, 50 * COIN * consensus.BHDIP001TargetSpacing / 600);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x8cec494f7f02ad25b3abf418f7d5647885000e010c34e16c039711e4061497b0"));
        assert(genesis.hashMerkleRoot == uint256S("0x6b80acabaf0fef45e2cad0b8b63d07cff1b35640e81f3ab3d83120dd8bc48164"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back("testnet-seed0-chain.bhd.one");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;

        checkpointData = {
            {
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 915e3ef622459f8b1b04dc274e1097b31111b0c6e0a9e9cd2da60c9d692f2c93
            /* nTime    */ 1587324676,
            /* nTxCount */ 496881,
            /* dTxRate  */ 0.01319561041786995,
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(ArgsManager const& args) {
        strNetworkID = "regtest";
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;

        consensus.BHDFundAddress = "2NDHUkujmJ3SBL5JmFZrycxGbAumhr2ycgy"; // pubkey 03eab29d59f6d14053c6e98f6d3d7e7db9cc17c619a513b9c00aa416fbdada73f1
        consensus.BHDFundAddressPool = { "2NDHUkujmJ3SBL5JmFZrycxGbAumhr2ycgy" };
        assert(consensus.BHDFundAddressPool.find(consensus.BHDFundAddress) != consensus.BHDFundAddressPool.end());

        consensus.nPowTargetSpacing = 180; // Reset by BHDIP008
        consensus.fPowNoRetargeting = true;
        consensus.nCapacityEvalWindow = 144;
        consensus.nSubsidyHalvingInterval = 300;
        consensus.fAllowMinDifficultyBlocks = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144;

        consensus.BHDIP001PreMiningEndHeight = 84; // 21M * 0.01% = 0.0021M, 0.0021M/25=84
        consensus.BHDIP001FundZeroLastHeight = 94;
        consensus.BHDIP001TargetSpacing = 300;
        consensus.BHDIP001FundRoyaltyForFullMortgage = 50; // 50‰
        consensus.BHDIP001FundRoyaltyForLowMortgage = 700; // 700‰
        consensus.BHDIP001MiningRatio = 3 * COIN;

        // Disable BHDIP004
        consensus.BHDIP004Height = 0;
        consensus.BHDIP004AbandonHeight = 0;

        consensus.BHDIP006Height = 294;
        consensus.BHDIP006BindPlotterActiveHeight = 344;
        consensus.BHDIP006CheckRelayHeight = 488;
        consensus.BHDIP006LimitBindPlotterHeight  = 493;

        consensus.BHDIP007Height = 550;
        consensus.BHDIP007SmoothEndHeight = 586;
        consensus.BHDIP007MiningRatioStage = 10 * 1024; // 10 PB

        consensus.BHDIP008Height = 720;
        consensus.BHDIP008TargetSpacing = 180;
        consensus.BHDIP008FundRoyaltyForLowMortgage = 270;
        consensus.BHDIP008FundRoyaltyDecreaseForLowMortgage = 20;
        consensus.BHDIP008FundRoyaltyDecreasePeriodForLowMortgage = 36;
        assert(consensus.BHDIP008Height % consensus.nMinerConfirmationWindow == 0);
        assert(consensus.BHDIP008FundRoyaltyForLowMortgage < consensus.BHDIP001FundRoyaltyForLowMortgage);
        assert(consensus.BHDIP008FundRoyaltyForLowMortgage > consensus.BHDIP001FundRoyaltyForFullMortgage);

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xe6;
        pchMessageStart[1] = 0xbb;
        pchMessageStart[2] = 0xb1;
        pchMessageStart[3] = 0xd6;
        nDefaultPort = 18744;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        genesis = CreateGenesisBlock(1531292789, 2, poc::GetBaseTarget(240), 2, 50 * COIN * consensus.BHDIP001TargetSpacing / 600);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x8414542ce030252cd4958545e6043b8c4e48182756fe39325851af58922b7df6"));
        assert(genesis.hashMerkleRoot == uint256S("0xb17eff00d4b76e03a07e98f256850a13cd42c3246dc6927be56db838b171d79b"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;

        checkpointData = {
            {
                {0, uint256S("0x8414542ce030252cd4958545e6043b8c4e48182756fe39325851af58922b7df6")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateActivationParametersFromArgs(ArgsManager const& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(ArgsManager const& args) {
    if (gArgs.IsArgSet("-segwitheight")) {
        int64_t height = gArgs.GetArg("-segwitheight", consensus.SegwitHeight);
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for segwit is out of valid range. Use -1 to disable segwit.", height));
        } else if (height == -1) {
            LogPrintf("Segwit disabled for testing\n");
            height = std::numeric_limits<int>::max();
        }
        consensus.SegwitHeight = static_cast<int>(height);
    }

    if (!args.IsArgSet("-vbparams")) return;

    for (std::string const& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

CChainParams const& Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(std::string const& chain) {
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(std::string const& network) {
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
