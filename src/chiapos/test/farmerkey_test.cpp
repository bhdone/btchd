#include <gtest/gtest.h>

#include <chiapos/kernel/chiapos_types.h>
#include <chiapos/kernel/bls_key.h>
#include <chiapos/kernel/utils.h>

char const* SZ_PASSPHRASE =
        "focus clutch crawl female stomach toss ice pepper silly already there identify plug invite road public cart "
        "victory fine ready nation orange air wink";
char const* SZ_SK = "2d9b342abe20578835804df43ac06bf7d2489741c53642e3aec2413242305dfc";
char const* SZ_PK = "8ec1bd0cac36d4c035ff623ea387bdb0453c9524061c5a797b374446b67d44d7b84782ea7c4e35756bd12f302296592d";
char const* SZ_FARMER_PK =
        "a7ecb9581e69e4ce968e5465764f29f519901d9bc892da89e3048b87ba820c8b04e17d726bfbb236e3f0e33f8a83851e";
char const* SZ_POOL_PK =
        "97e034b18cdd88c5a9193ab731c12a6804ebe189583d44196a4072a8545bf21e8421e727a7ccad442ed39026bd56ad85";

TEST(FARMERPK, Decode) {
    chiapos::CKey sk = chiapos::CKey::CreateKeyWithMnemonicWords(SZ_PASSPHRASE, "");
    EXPECT_EQ(chiapos::BytesToHex(chiapos::MakeBytes(sk.GetSecreKey())), SZ_SK);
    EXPECT_EQ(chiapos::BytesToHex(chiapos::MakeBytes(sk.GetPubKey())), SZ_PK);
    chiapos::CWallet wallet(std::move(sk));
    EXPECT_EQ(chiapos::BytesToHex(chiapos::MakeBytes(wallet.GetFarmerKey(0).GetPubKey())), SZ_FARMER_PK);
    EXPECT_EQ(chiapos::BytesToHex(chiapos::MakeBytes(wallet.GetPoolKey(0).GetPubKey())), SZ_POOL_PK);
}
