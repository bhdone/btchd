#include <chainparams.h>

#include <chiapos/post.h>
#include <chiapos/kernel/calc_diff.h>
#include <chiapos/kernel/utils.h>

#include <key_io.h>
#include <logging.h>
#include <rpc/util.h>
#include <uint256.h>
#include <univalue.h>
#include <arith_uint256.h>

#include <chiabls/bls.hpp>
#include <chiabls/elements.hpp>

#include <cstdint>

#include <gtest/gtest.h>

namespace chiapos {
static char const* SZ_POOL_PK =
        "92f7dbd5de62bfe6c752c957d7d17af1114500670819dfb149a055edaafcc77bd376b450d43eb1c3208a424b00abe950";
static char const* SZ_LOCAL_PK =
        "87f6303b49d3c7cd71017d18ecee805f6f1380c259075f9a6165e0d0282e7bdcb1d23c521ae1bc4c7defc343c15dd992";
static char const* SZ_FARMER_PK =
        "8b17c85e49be1a2303588b6fe9a0206dc0722c83db2281bb1aee695ae7e97c098672e1609a50b86786126cca3c9c8639";
static char const* SZ_PLOT_ID = "7f88b755ddb5ee59c9a74b0c90a46b652ee8a3d9621f5b4500c5fb0a35ddbdd0";
// static char const* SZ_PROOF =
//         "cfc6e9bf214fd7ca3d45fed95d5b2d33e08027510c59d0c6089ba19d48ee5305ebadfbf1780e9e217fa179bb6a45671affaf0f37edcc2a"
//         "ee43480f9bd6b86555c82924bfae14c53fae2d26f97f199699d99c5e323e85f650c8be84e531ff510d561e5ab55cbbfc77350ca986eba7"
//         "2e25d555229ce4def80c6e5f06a1a8ecbd7a909f006addcfdb484a34dc7014b53b93ffc02cb4f15dfc83901335862a1c0d55ef87834378"
//         "133120ed1d832dac071af1fecd3aebbdde306cd2729dbc30ed4aab1a591610d62364bd";
static char const* SZ_CHALLENGE = "abd2fdbd2e6eece6171f3adcb4560acff92578ad33af3ebe2ad407b2101610ae";
static const uint8_t K = 25;

// clang-format off
const char *SZ_PROOFS_FOR_CHIAPOS_GENESIS =
    "{"
    "        \"farmerPk\" : \"8b17c85e49be1a2303588b6fe9a0206dc0722c83db2281bb1aee695ae7e97c098672e1609a50b86786126cca3c9c8639\","
    "        \"farmerSk\" : \"5b6b702a857450298ae02d9f09136e52fe285b6707f787e68aa900b1db4dd29e\","
    "        \"initialChallenge\" : \"abd2fdbd2e6eece6171f3adcb4560acff92578ad33af3ebe2ad407b2101610ae\","
    "        \"iters\" : 100000,"
    "        \"k\" : 25,"
    "        \"localPk\" : \"87f6303b49d3c7cd71017d18ecee805f6f1380c259075f9a6165e0d0282e7bdcb1d23c521ae1bc4c7defc343c15dd992\","
    "        \"plotId\" : \"7f88b755ddb5ee59c9a74b0c90a46b652ee8a3d9621f5b4500c5fb0a35ddbdd0\","
    "        \"poolPk\" : \"92f7dbd5de62bfe6c752c957d7d17af1114500670819dfb149a055edaafcc77bd376b450d43eb1c3208a424b00abe950\","
    "        \"posProof\" : \"cfc6e9bf214fd7ca3d45fed95d5b2d33e08027510c59d0c6089ba19d48ee5305ebadfbf1780e9e217fa179bb6a45671affaf0f37edcc2aee43480f9bd6b86555c82924bfae14c53fae2d26f97f199699d99c5e323e85f650c8be84e531ff510d561e5ab55cbbfc77350ca986eba72e25d555229ce4def80c6e5f06a1a8ecbd7a909f006addcfdb484a34dc7014b53b93ffc02cb4f15dfc83901335862a1c0d55ef87834378133120ed1d832dac071af1fecd3aebbdde306cd2729dbc30ed4aab1a591610d62364bd\","
    "        \"qualityString\" : \"f4c6fa88890a80cfc96a87b3a0818bb760ad7da5c38daba3da8c544cc332fda0\","
    "        \"rewardDest\" : \"3JohQvZpZZwvxJxx8yUviWSg2hJCW6RmSc\","
    "        \"vdfProofs\" :"
    "        ["
    "                {"
    "                        \"proof\" : \"0100844fb261103a17de629abd0776cd00805fbef71f2004f754430ecfc71a8fbfef512d4de71c33c6accbe9a40293e7bbce198738e94fe5badc3ba978bbcc5ce10de5b8ed73a4cd24e34a40e019c12902d5d5d65e3ce0995c71c877f2446ed37b090301\","
    "                        \"witnessType\" : 0,"
    "                        \"y\" : \"02001ec87764bfa3ddbfeed9236b7f45e13476d660c93881f07102fbd1069b324cf3c9b4f290b1241dc21b5d1fa9b9a891caf613663cd7fc9e365a7218e9fad3cc38374c2e91296654eef95e7a106e3ec51fe4a452bb4fceeef02514df7f20bf39260100\""
    "                }"
    "        ]"
    "}";
// clang-format on

static char const* SZ_PREVIOUSE_BLOCK_HASH = "8138553ff6aacccda3d29bf20ad941f9ca7966ea336eea64182c947b7a938394";

TEST(Base, BytesAndHex) {
    Bytes vchData = BytesFromHex(SZ_POOL_PK);
    std::string strHex = BytesToHex(vchData);

    EXPECT_EQ(strHex, SZ_POOL_PK);
}

TEST(Base, G1Element) {
    Bytes vchPoolPk = BytesFromHex(SZ_POOL_PK);
    auto g1 = bls::G1Element::FromByteVector(vchPoolPk);
    Bytes vchPoolPk2 = g1.Serialize();

    EXPECT_EQ(vchPoolPk, vchPoolPk2);
}

TEST(Base, CPubKey) {
    PubKey pk(MakeArray<PK_LEN>(BytesFromHex(SZ_POOL_PK)));
    EXPECT_EQ(MakeBytes(pk), BytesFromHex(SZ_POOL_PK));
}

TEST(Base, MakeUint256) {
    uint256 challenge = uint256S(SZ_CHALLENGE);
    uint256 challenge2 = MakeUint256(BytesFromHex(SZ_CHALLENGE));
    EXPECT_EQ(challenge, challenge2);
}

TEST(Base, Test_MakeUint256_R) {
    uint256 val = MakeUint256(BytesFromHex(SZ_PREVIOUSE_BLOCK_HASH));
    EXPECT_EQ(val.ToString(), BytesToHex(BytesFromHex(val.ToString())));
}

TEST(Base, Test_MakeBytes) {
    Bytes challenge = BytesFromHex(SZ_CHALLENGE);

    uint256 u256 = MakeUint256(challenge);
    EXPECT_EQ(MakeBytes(u256), challenge);
}

static char const* SZ_FUND_ADDRESS = "32B86ghqRTJkh2jvyhRWFugX7YWoqHPqVE";

TEST(Base, Test_FundAddress) {
    CTxDestination dest = DecodeDestination(SZ_FUND_ADDRESS);
    EXPECT_TRUE(IsValidDestination(dest));
}

TEST(Chiapos, Test_MakePlotId) {
    PubKey localPk = MakeArray<PK_LEN>(BytesFromHex(SZ_LOCAL_PK));
    PubKey farmerPk = MakeArray<PK_LEN>(BytesFromHex(SZ_FARMER_PK));
    PubKeyOrHash poolPkOrHash = MakePubKeyOrHash(PlotPubKeyType::OGPlots, BytesFromHex(SZ_POOL_PK));

    PlotId plotId = MakePlotId(localPk, farmerPk, poolPkOrHash);
    uint256 plotId2 = uint256S(SZ_PLOT_ID);

    EXPECT_EQ(plotId, plotId2);
}

TEST(Chiapos, Test_VerifyChiaposProof) {
    uint256 challenge = uint256S("cc5ac4c68e9228f2487aa3d4a0ca067e150ad19f85934f5d97f4355c8c83fdbd");
    Bytes vchProof = BytesFromHex("407f849c3b8fa9265751f34a72b57192cca83a5d7d7d2ce935cfde94e91ffa7567dadbe0cdd36e9da11c5ffd6b790b4acbe64a91d6e4c2f87b4e0b3f7d130222a3196fe705bbebf47817062f3deea06ea3c71dec4198ceaaa1f7fdad81e616c465bf4e8506a088ccd3ace16f1c0bdf9a9c73edcddc1cf0dcfacd8ef574809c442c9f8ffbd92defb3f520b27de1ae949201d63f618514af50994014f5a522bd5b67f6430fa927bda70c39b751c0a9a4a0a864889ed8202aecb283a708378002c5a6cf5f19fe05b31c");
    PubKeyOrHash poolPkOrHash = MakePubKeyOrHash(PlotPubKeyType::OGPlots, BytesFromHex("92f7dbd5de62bfe6c752c957d7d17af1114500670819dfb149a055edaafcc77bd376b450d43eb1c3208a424b00abe950"));
    PubKey localPk = MakeArray<PK_LEN>(BytesFromHex("b1578afd24055235e1a946108b84bab4c27b42f47e0a1f9562e251462b2f7564bd12991abcb9c23df5b62e77ed1f1ce7"));
    PubKey farmerPk = MakeArray<PK_LEN>(BytesFromHex("8b17c85e49be1a2303588b6fe9a0206dc0722c83db2281bb1aee695ae7e97c098672e1609a50b86786126cca3c9c8639"));
    EXPECT_TRUE(VerifyPos(challenge, localPk, farmerPk, poolPkOrHash, K, vchProof, nullptr, 0));
}

TEST(utils, ParseHosts)
{
	static char const* SZ_HOSTS = "127.0.0.1:1991,sample.com:1676,none:1939,okthen:1919,noport.com";
	auto entries = chiapos::ParseHostsStr(SZ_HOSTS, 19191);
	EXPECT_EQ(entries.size(), 5);
	EXPECT_EQ(entries[0].first, "127.0.0.1");
	EXPECT_EQ(entries[0].second, 1991);
	EXPECT_EQ(entries[1].first, "sample.com");
	EXPECT_EQ(entries[1].second, 1676);
	EXPECT_EQ(entries[2].first, "none");
	EXPECT_EQ(entries[2].second, 1939);
	EXPECT_EQ(entries[3].first, "okthen");
	EXPECT_EQ(entries[3].second, 1919);
	EXPECT_EQ(entries[4].first, "noport.com");
	EXPECT_EQ(entries[4].second, 19191);
}

// Vdf proof verification
// static char const* SZ_VDF_CHALLENGE = "9159bc7838880dcf826ba5fd7f5b693f203c01e29070ffa4eb1a73b727e09d84";
// static const uint64_t VDF_ITERS = 100000;
// static char const* SZ_VDF_Y =
//         "0000e16a31edf6070934cacf78d3c3139e6986b7cebd0a45b996720fc916a163803a9c73d43b05c0835e8f2e4c52b2e10ae5623f7c1d5b"
//         "98db"
//         "2fc13b140b4c6035080f1b12cfe429abcee3912844319f2f81858d7ed4f7a6a108cf14f4a71090a1130201";
// static char const* SZ_VDF_PROOF =
//         "0200f845362c6a25e82034591c60797922723c20f7fc4fd2f955c43baefaa96ec4b3014174ff36ce05070f119a875b7b2df2ced3fe4963"
//         "bc34"
//         "fe7091e61623da6408117c6c31aef6d9b40f1e5c3c6fa7295196733d3448139a85bb8e6e5e0bc6dd020d07";
//
// TEST(Chiapos, Test_VerifyVdfProof) {
//     CVdfProof proof;
//     proof.challenge = uint256S(SZ_VDF_CHALLENGE);
//     proof.vchY = BytesFromHex(SZ_VDF_Y);
//     proof.vchProof = BytesFromHex(SZ_VDF_PROOF);
//     proof.nWitnessType = 0;
//     proof.nVdfIters = VDF_ITERS;
//     proof.nVdfDuration = 0;
//     CValidationState state;
//     EXPECT_TRUE(CheckVdfProof(proof, state));
// }

// TEST(Difficulty, ExpectSize) {
//     EXPECT_EQ(chiapos::calc::expected_plot_size<int64_t>(25), 855638016);
//     EXPECT_EQ(chiapos::calc::expected_plot_size<arith_uint256>(25), 855638016);
//     EXPECT_EQ(chiapos::calc::expected_plot_size<int64_t>(32), 139586437120);
//     EXPECT_EQ(chiapos::calc::expected_plot_size<arith_uint256>(32), 139586437120);
// }

TEST(Utils, FormatNumberStr) {
    EXPECT_EQ(chiapos::FormatNumberStr("2022"), "2,022");
    EXPECT_EQ(chiapos::FormatNumberStr("202203"), "202,203");
    EXPECT_EQ(chiapos::FormatNumberStr("20220310"), "20,220,310");
    EXPECT_EQ(chiapos::FormatNumberStr("2022031010"), "2,022,031,010");
}

int RunAllTests() {
    ::testing::InitGoogleTest();
    return RUN_ALL_TESTS();
}

}  // namespace chiapos
