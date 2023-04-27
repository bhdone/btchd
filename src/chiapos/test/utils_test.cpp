#include <cstdint>

#include <gtest/gtest.h>

#include <chiapos/kernel/utils.h>
#include <chiapos/kernel/chiapos_types.h>
#include <chiapos/kernel/bls_key.h>
#include <chiapos/kernel/pos.h>

static char const* SZ_POOL_PK =
        "92f7dbd5de62bfe6c752c957d7d17af1114500670819dfb149a055edaafcc77bd376b450d43eb1c3208a424b00abe950";
static char const* SZ_LOCAL_PK =
        "87f6303b49d3c7cd71017d18ecee805f6f1380c259075f9a6165e0d0282e7bdcb1d23c521ae1bc4c7defc343c15dd992";
static char const* SZ_FARMER_PK =
        "8b17c85e49be1a2303588b6fe9a0206dc0722c83db2281bb1aee695ae7e97c098672e1609a50b86786126cca3c9c8639";
static char const* SZ_PLOT_ID = "7f88b755ddb5ee59c9a74b0c90a46b652ee8a3d9621f5b4500c5fb0a35ddbdd0";
static char const* SZ_CHALLENGE = "abd2fdbd2e6eece6171f3adcb4560acff92578ad33af3ebe2ad407b2101610ae";
static const uint8_t K = 25;

static char const* SZ_PREVIOUSE_BLOCK_HASH = "8138553ff6aacccda3d29bf20ad941f9ca7966ea336eea64182c947b7a938394";

TEST(UTILS, BytesAndHex) {
    chiapos::Bytes vchData = chiapos::BytesFromHex(SZ_POOL_PK);
    std::string strHex = chiapos::BytesToHex(vchData);

    EXPECT_EQ(strHex, SZ_POOL_PK);
}

TEST(UTILS, CPubKey) {
    chiapos::PubKey pk(chiapos::MakeArray<chiapos::PK_LEN>(chiapos::BytesFromHex(SZ_POOL_PK)));
    EXPECT_EQ(chiapos::MakeBytes(pk), chiapos::BytesFromHex(SZ_POOL_PK));
}

TEST(UTILS, MakeUint256) {
    uint256 challenge = uint256S(SZ_CHALLENGE);
    uint256 challenge2 = chiapos::MakeUint256(chiapos::BytesFromHex(SZ_CHALLENGE));
    EXPECT_EQ(challenge, challenge2);
}

TEST(UTILS, MakeUint256AndReverse) {
    uint256 val = chiapos::MakeUint256(chiapos::BytesFromHex(SZ_PREVIOUSE_BLOCK_HASH));
    EXPECT_EQ(val.ToString(), chiapos::BytesToHex(chiapos::BytesFromHex(val.ToString())));
}

TEST(UTILS, MakeBytesToUint256) {
    chiapos::Bytes challenge = chiapos::BytesFromHex(SZ_CHALLENGE);

    uint256 u256 = chiapos::MakeUint256(challenge);
    EXPECT_EQ(chiapos::MakeBytes(u256), challenge);
}

TEST(UTILS, BytesConnection) {
    char const* SZ_A = "aa";
    char const* SZ_B = "bb";
    auto bytes_a = chiapos::BytesFromHex(SZ_A);
    auto bytes_b = chiapos::BytesFromHex(SZ_B);
    auto bytes_c = chiapos::BytesConnector::Connect(bytes_a, bytes_b);
    EXPECT_EQ(bytes_c, chiapos::BytesFromHex("aabb"));
}

TEST(UTILS, BytesConnection2) {
    auto bytes_a = chiapos::BytesFromHex(SZ_LOCAL_PK);
    auto bytes_b = chiapos::BytesFromHex(SZ_POOL_PK);
    auto bytes = chiapos::BytesConnector::Connect(bytes_a, bytes_b);
    EXPECT_EQ(chiapos::BytesToHex(bytes), std::string(SZ_LOCAL_PK) + std::string(SZ_POOL_PK));
}

TEST(UTILS, SubBytes) {
    auto bytes = chiapos::BytesFromHex("aabb");
    auto bytes_a = chiapos::SubBytes(bytes, 0, 1);
    auto bytes_b = chiapos::SubBytes(bytes, 1, 1);
    EXPECT_EQ(bytes_a, chiapos::BytesFromHex("aa"));
    EXPECT_EQ(bytes_b, chiapos::BytesFromHex("bb"));
}

TEST(UTILS, ParseHosts) {
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

TEST(UTILS, FormatNumberStr) {
    EXPECT_EQ(chiapos::FormatNumberStr("2022"), "2,022");
    EXPECT_EQ(chiapos::FormatNumberStr("202203"), "202,203");
    EXPECT_EQ(chiapos::FormatNumberStr("20220310"), "20,220,310");
    EXPECT_EQ(chiapos::FormatNumberStr("2022031010"), "2,022,031,010");
}

TEST(UTILS, MakePlotId) {
    chiapos::PubKey localPk = chiapos::MakeArray<chiapos::PK_LEN>(chiapos::BytesFromHex(SZ_LOCAL_PK));
    chiapos::PubKey farmerPk = chiapos::MakeArray<chiapos::PK_LEN>(chiapos::BytesFromHex(SZ_FARMER_PK));
    chiapos::PubKeyOrHash poolPkOrHash =
            MakePubKeyOrHash(chiapos::PlotPubKeyType::OGPlots, chiapos::BytesFromHex(SZ_POOL_PK));

    chiapos::PlotId plotId = chiapos::MakePlotId(localPk, farmerPk, poolPkOrHash);
    uint256 plotId2 = uint256S(SZ_PLOT_ID);

    EXPECT_EQ(plotId, plotId2);
}

TEST(UTILS, VerifyChiaposProof) {
    uint256 challenge = uint256S("cc5ac4c68e9228f2487aa3d4a0ca067e150ad19f85934f5d97f4355c8c83fdbd");
    chiapos::Bytes vchProof = chiapos::BytesFromHex(
            "407f849c3b8fa9265751f34a72b57192cca83a5d7d7d2ce935cfde94e91ffa7567dadbe0cdd36e9da11c5ffd6b790b4acbe64a91d6"
            "e4c2f87b4e0b3f7d130222a3196fe705bbebf47817062f3deea06ea3c71dec4198ceaaa1f7fdad81e616c465bf4e8506a088ccd3ac"
            "e16f1c0bdf9a9c73edcddc1cf0dcfacd8ef574809c442c9f8ffbd92defb3f520b27de1ae949201d63f618514af50994014f5a522bd"
            "5b67f6430fa927bda70c39b751c0a9a4a0a864889ed8202aecb283a708378002c5a6cf5f19fe05b31c");
    chiapos::PubKeyOrHash poolPkOrHash =
            MakePubKeyOrHash(chiapos::PlotPubKeyType::OGPlots,
                             chiapos::BytesFromHex("92f7dbd5de62bfe6c752c957d7d17af1114500670819dfb149a"
                                                   "055edaafcc77bd376b450d43eb1c3208a424b00abe950"));
    chiapos::PubKey localPk = chiapos::MakeArray<chiapos::PK_LEN>(chiapos::BytesFromHex(
            "b1578afd24055235e1a946108b84bab4c27b42f47e0a1f9562e251462b2f7564bd12991abcb9c23df5b62e77ed1f1ce7"));
    chiapos::PubKey farmerPk = chiapos::MakeArray<chiapos::PK_LEN>(chiapos::BytesFromHex(
            "8b17c85e49be1a2303588b6fe9a0206dc0722c83db2281bb1aee695ae7e97c098672e1609a50b86786126cca3c9c8639"));
    EXPECT_TRUE(chiapos::VerifyPos(challenge, localPk, farmerPk, poolPkOrHash, K, vchProof, nullptr, 0));
}
