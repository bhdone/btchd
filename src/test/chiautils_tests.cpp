// Copyright (c) 2012-2023 The DePINC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

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

BOOST_FIXTURE_TEST_SUITE(chiautils_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(chiautils_byteshex)
{
    chiapos::Bytes vchData = chiapos::BytesFromHex(SZ_POOL_PK);
    std::string strHex = chiapos::BytesToHex(vchData);

    BOOST_CHECK(strHex == SZ_POOL_PK);
}

BOOST_AUTO_TEST_CASE(chiautils_pubkey)
{
    chiapos::PubKey pk(chiapos::MakeArray<chiapos::PK_LEN>(chiapos::BytesFromHex(SZ_POOL_PK)));
    BOOST_CHECK(chiapos::MakeBytes(pk) == chiapos::BytesFromHex(SZ_POOL_PK));
}

BOOST_AUTO_TEST_CASE(chiautils_makeuint256)
{
    uint256 challenge = uint256S(SZ_CHALLENGE);
    uint256 challenge2 = chiapos::MakeUint256(chiapos::BytesFromHex(SZ_CHALLENGE));
    BOOST_CHECK(challenge == challenge2);
}

BOOST_AUTO_TEST_CASE(chiautils_makeuint256_reverse)
{
    uint256 val = chiapos::MakeUint256(chiapos::BytesFromHex(SZ_PREVIOUSE_BLOCK_HASH));
    BOOST_CHECK(val.ToString() == chiapos::BytesToHex(chiapos::BytesFromHex(val.ToString())));
}

BOOST_AUTO_TEST_CASE(chiautils_bytes_uint256)
{
    chiapos::Bytes challenge = chiapos::BytesFromHex(SZ_CHALLENGE);
    uint256 u256 = chiapos::MakeUint256(challenge);
    BOOST_CHECK(chiapos::MakeBytes(u256) == challenge);
}

BOOST_AUTO_TEST_CASE(chiautils_bytesconnection)
{
    char const* SZ_A = "aa";
    char const* SZ_B = "bb";
    auto bytes_a = chiapos::BytesFromHex(SZ_A);
    auto bytes_b = chiapos::BytesFromHex(SZ_B);
    auto bytes_c = chiapos::BytesConnector::Connect(bytes_a = bytes_b);
    BOOST_CHECK(bytes_c == chiapos::BytesFromHex("aabb"));

    bytes_a = chiapos::BytesFromHex(SZ_LOCAL_PK);
    bytes_b = chiapos::BytesFromHex(SZ_POOL_PK);
    auto bytes = chiapos::BytesConnector::Connect(bytes_a, bytes_b);
    BOOST_CHECK(chiapos::BytesToHex(bytes) == std::string(SZ_LOCAL_PK) + std::string(SZ_POOL_PK));
}

BOOST_AUTO_TEST_CASE(chiautils_subbytes)
{
    auto bytes = chiapos::BytesFromHex("aabb");
    auto bytes_a = chiapos::SubBytes(bytes, 0, 1);
    auto bytes_b = chiapos::SubBytes(bytes, 1, 1);
    BOOST_CHECK(bytes_a == chiapos::BytesFromHex("aa"));
    BOOST_CHECK(bytes_b == chiapos::BytesFromHex("bb"));
}

BOOST_AUTO_TEST_CASE(chiautils_parsehosts)
{
    auto entries_empty = chiapos::ParseHostsStr("", 19191);
    BOOST_CHECK(entries_empty.empty());

    static char const* SZ_HOSTS = "127.0.0.1:1991,sample.com:1676,none:1939,okthen:1919,noport.com";
    auto entries = chiapos::ParseHostsStr(SZ_HOSTS, 19191);
    BOOST_CHECK(entries.size() == 5);
    BOOST_CHECK(entries[0].first == "127.0.0.1");
    BOOST_CHECK(entries[0].second == 1991);
    BOOST_CHECK(entries[1].first == "sample.com");
    BOOST_CHECK(entries[1].second == 1676);
    BOOST_CHECK(entries[2].first == "none");
    BOOST_CHECK(entries[2].second == 1939);
    BOOST_CHECK(entries[3].first == "okthen");
    BOOST_CHECK(entries[3].second == 1919);
    BOOST_CHECK(entries[4].first == "noport.com");
    BOOST_CHECK(entries[4].second == 19191);
}

BOOST_AUTO_TEST_CASE(chiautils_formatnumstring)
{
    BOOST_CHECK(chiapos::FormatNumberStr("2022") == "2,022");
    BOOST_CHECK(chiapos::FormatNumberStr("202203") == "202,203");
    BOOST_CHECK(chiapos::FormatNumberStr("20220310") == "20,220,310");
    BOOST_CHECK(chiapos::FormatNumberStr("2022031010") == "2,022,031,010");
}

BOOST_AUTO_TEST_CASE(chiapos_makeplots)
{
    chiapos::PubKey localPk = chiapos::MakeArray<chiapos::PK_LEN>(chiapos::BytesFromHex(SZ_LOCAL_PK));
    chiapos::PubKey farmerPk = chiapos::MakeArray<chiapos::PK_LEN>(chiapos::BytesFromHex(SZ_FARMER_PK));
    chiapos::PubKeyOrHash poolPkOrHash =
            MakePubKeyOrHash(chiapos::PlotPubKeyType::OGPlots, chiapos::BytesFromHex(SZ_POOL_PK));

    chiapos::PlotId plotId = chiapos::MakePlotId(localPk, farmerPk, poolPkOrHash);
    uint256 plotId2 = uint256S(SZ_PLOT_ID);

    BOOST_CHECK(plotId == plotId2);
}

BOOST_AUTO_TEST_CASE(chiapos_verifyproof)
{
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
    BOOST_CHECK(chiapos::VerifyPos(challenge, localPk, farmerPk, poolPkOrHash, K, vchProof, nullptr, 0));
}

BOOST_AUTO_TEST_SUITE_END()
