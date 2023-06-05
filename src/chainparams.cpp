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
const int AVERAGE_VDF_SPEED = 200 * 1000; // 100k ips we assume

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

        consensus.BHDIP009SkipTestChainChecks = false; // Do not check validation for blocks of burst consensus
        consensus.BHDIP009Height = 860130; // 2023/6/19 13:00 - 17:00
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

        int nHeightsOfADay = SECONDS_OF_A_DAY / consensus.BHDIP008TargetSpacing;
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

        consensus.BHDIP009SkipTestChainChecks = true; // Do not check on test-chain construction
        consensus.BHDIP009Height = 200000; // When reach the height the consensus will change to chiapos
        consensus.BHDIP009FundAddresses = {"2N7mAbSHzAeCiY2WJzREPJYKTEJbKo7tYke"};
        consensus.BHDIP009FundRoyaltyForLowMortgage = 150;
        consensus.BHDIP009StartBlockIters = AVERAGE_VDF_SPEED * consensus.BHDIP008TargetSpacing;
        consensus.BHDIP009DifficultyConstantFactorBits = chiapos::DIFFICULTY_CONSTANT_FACTOR_BITS;
        consensus.BHDIP009DifficultyEvalWindow = 100;
        consensus.BHDIP009PlotIdBitsOfFilter = chiapos::NUMBER_OF_ZEROS_BITS_FOR_FILTER_TESTNET;
        consensus.BHDIP009PlotIdBitsOfFilterEnableOnHeight = consensus.BHDIP009Height + 200;
        consensus.BHDIP009PlotSizeMin = chiapos::MIN_K_TEST_NET;
        consensus.BHDIP009PlotSizeMax = chiapos::MAX_K;
        consensus.BHDIP009BaseIters = AVERAGE_VDF_SPEED * 60;
        consensus.BHDIP009StartDifficulty = (arith_uint256(consensus.BHDIP009StartBlockIters) * chiapos::expected_plot_size<arith_uint256>(32) / chiapos::Pow2(consensus.BHDIP009DifficultyConstantFactorBits)).GetLow64();
        int nHeightsOfADay = SECONDS_OF_A_DAY / consensus.BHDIP008TargetSpacing;
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
