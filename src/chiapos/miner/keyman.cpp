#include "keyman.h"

#include <bip3x/Bip39Mnemonic.h>
#include <bip3x/utils.h>
#include <openssl/evp.h>

#ifdef __APPLE__
#include <gmp.h>
#endif

#include <chiabls/elements.hpp>
#include <chiabls/schemes.hpp>
#include <sstream>

#define UTF8PROC_STATIC 1
#include <chiapos/kernel/utils.h>
#include <utf8proc.h>

namespace keyman {

namespace utils {

Bytes CopyMnemonicResultToBytes(bip3x::Bip39Mnemonic::MnemonicResult const& res) {
    Bytes bytes(res.len);
    memcpy(bytes.data(), res.raw.data(), res.len);
    return bytes;
}

bip3x::Bip39Mnemonic::MnemonicResult WordsToMnemonicResult(Mnemonic::Words const& words, std::string lang) {
    std::string str = Mnemonic::WordsToString(words);
    bip3x::bytes_data bytes = bip3x::Bip39Mnemonic::decodeMnemonic(str.data(), lang.data());
    return bip3x::Bip39Mnemonic::encodeBytes(bytes.data(), lang.data());
}

std::string NormalizeString(std::string const& str) {
    uint8_t* chars = utf8proc_NFKD(reinterpret_cast<uint8_t const*>(str.data()));
    std::string res(reinterpret_cast<char const*>(chars));
    free(chars);
    return res;
}

}  // namespace utils

Mnemonic Mnemonic::GenerateNew(std::string lang) {
    bip3x::Bip39Mnemonic::MnemonicResult res = bip3x::Bip39Mnemonic::generate(lang.data());
    return Mnemonic(res.words, lang);
}

std::string Mnemonic::WordsToString(Mnemonic::Words const& words) {
    std::stringstream ss;
    for (std::string const& word : words) {
        ss << " " << word;
    }
    return ss.str().substr(1);
}

Mnemonic::Words Mnemonic::StringToWords(std::string str) {
    uint32_t i{0}, last{0};
    Mnemonic::Words res;
    while (i < str.size()) {
        if (str[i] == ' ') {
            if (i - last > 0) {
                res.push_back(std::string(str.substr(last, i - last)));
            }
            last = i + 1;
        }
        ++i;
    }
    if (i - last - 1 > 0) {
        res.push_back(str.substr(last, i - last).data());
    }
    return res;
}

Mnemonic::Mnemonic(Words words, std::string lang) : words_(std::move(words)) {
    bip3x::Bip39Mnemonic::MnemonicResult res = utils::WordsToMnemonicResult(words_, lang);
    bytes_ = utils::CopyMnemonicResultToBytes(res);
}

Mnemonic::Mnemonic(std::string words, std::string lang) : Mnemonic(StringToWords(words), lang) {}

std::string Mnemonic::ToString() const { return WordsToString(words_); }

Mnemonic::Words Mnemonic::GetWords() const { return words_; }

/**
 * Generating seed method is copied from chia-network:
 *
 * def mnemonic_to_seed(mnemonic: str, passphrase: str) -> bytes:
 *   """
 *   Uses BIP39 standard to derive a seed from entropy bytes.
 *   """
 *   salt_str: str = "mnemonic" + passphrase
 *   salt = unicodedata.normalize("NFKD", salt_str).encode("utf-8")
 *   mnemonic_normalized = unicodedata.normalize("NFKD",
 *       mnemonic).encode("utf-8")
 *   seed = pbkdf2_hmac("sha512", mnemonic_normalized, salt, 2048)
 *
 *   assert len(seed) == 64
 *   return seed
 */
Bytes64 Mnemonic::GetSeed(std::string passphrase) const {
    std::string salt = utils::NormalizeString(std::string("mnemonic") + passphrase.data());
    std::string mnemonic = utils::NormalizeString(WordsToString(words_));
    Bytes64 digest;
    digest.fill('\0');
    int len = PKCS5_PBKDF2_HMAC(mnemonic.data(), mnemonic.size(), reinterpret_cast<uint8_t const*>(salt.data()),
                                salt.size(), 2048, EVP_sha512(), 64, digest.data());
    assert(len == 1);
    return digest;
}

bool Mnemonic::IsEmpty() const { return words_.empty(); }

bool Key::VerifySig(PublicKey const& pub_key, Bytes const& msg, Signature const& sig) {
    return bls::AugSchemeMPL().Verify(chiapos::MakeBytes(pub_key), msg, chiapos::MakeBytes(sig));
}

PubKey::PubKey() { pubkey_ = chiapos::MakeArray<Key::PUB_KEY_LEN>(bls::G1Element().Serialize()); }

PubKey::PubKey(PublicKey pubkey) : pubkey_(std::move(pubkey)) {}

PubKey PubKey::operator+(PubKey const& rhs) const {
    auto lhs_g1 = bls::G1Element::FromBytes(bls::Bytes(pubkey_.data(), pubkey_.size()));
    auto rhs_g1 = bls::G1Element::FromBytes(bls::Bytes(rhs.pubkey_.data(), rhs.pubkey_.size()));
    auto res = bls::AugSchemeMPL().Aggregate({lhs_g1, rhs_g1});
    return PubKey(chiapos::MakeArray<Key::PUB_KEY_LEN>(res.Serialize()));
}

PubKey& PubKey::operator+=(PubKey const& rhs) {
    *this = *this + rhs;
    return *this;
}

PublicKey const& PubKey::GetPublicKey() const { return pubkey_; }

PublicKey Key::CreatePublicKey() { return chiapos::MakeArray<PUB_KEY_LEN>(bls::G1Element().Serialize()); }

PublicKey Key::AddTwoPubkey(PublicKey const& lhs, PublicKey const& rhs) {
    bls::G1Element g1lhs = bls::G1Element::FromBytes(bls::Bytes(lhs.data(), lhs.size()));
    bls::G1Element g1rhs = bls::G1Element::FromBytes(bls::Bytes(rhs.data(), rhs.size()));
    auto res = g1lhs + g1rhs;
    return chiapos::MakeArray<PUB_KEY_LEN>(res.Serialize());
}

Key::Key() {}

Key::Key(PrivateKey priv_key) : priv_key_(std::move(priv_key)) {}

Key::Key(Mnemonic const& mnemonic, std::string passphrase) {
    Bytes64 seed = mnemonic.GetSeed(passphrase);
    priv_key_ = chiapos::MakeArray<PRIV_KEY_LEN>(bls::AugSchemeMPL().KeyGen(chiapos::MakeBytes(seed)).Serialize());
}

bool Key::IsEmpty() const { return priv_key_.empty(); }

void Key::GenerateNew(Bytes const& seed) {
    bls::PrivateKey bls_priv_key = bls::AugSchemeMPL().KeyGen(seed);
    Bytes priv_key_bytes = bls_priv_key.Serialize();
    priv_key_ = chiapos::MakeArray<PRIV_KEY_LEN>(priv_key_bytes);
}

PrivateKey Key::GetPrivateKey() const { return priv_key_; }

PublicKey Key::GetPublicKey() const {
    bls::PrivateKey bls_priv_key = bls::PrivateKey::FromBytes(bls::Bytes(chiapos::MakeBytes(priv_key_)));
    return chiapos::MakeArray<PUB_KEY_LEN>(bls_priv_key.GetG1Element().Serialize());
}

Signature Key::Sign(Bytes const& msg) {
    bls::PrivateKey bls_priv_key = bls::PrivateKey::FromBytes(bls::Bytes(chiapos::MakeBytes(priv_key_)));
    Bytes sig_bytes = bls::AugSchemeMPL().Sign(bls_priv_key, msg).Serialize();
    return chiapos::MakeArray<SIG_LEN>(sig_bytes);
}

Key Key::DerivePath(std::vector<uint32_t> const& paths) const {
    bls::PrivateKey bls_priv_key = bls::PrivateKey::FromBytes(bls::Bytes(chiapos::MakeBytes(priv_key_)));
    auto sk{bls_priv_key};
    for (uint32_t path : paths) {
        sk = bls::AugSchemeMPL().DeriveChildSk(sk, path);
    }
    return Key(chiapos::MakeArray<PRIV_KEY_LEN>(sk.Serialize()));
}

Key Wallet::GetKey(Key const& master_sk, uint32_t index) { return master_sk.DerivePath({12381, 8444, 2, index}); }

Key Wallet::GetFarmerKey(Key const& master_sk, uint32_t index) { return master_sk.DerivePath({12381, 8444, 0, index}); }

Key Wallet::GetPoolKey(Key const& master_sk, uint32_t index) { return master_sk.DerivePath({12381, 8444, 1, index}); }

Key Wallet::GetLocalKey(Key const& master_sk, uint32_t index) { return master_sk.DerivePath({12381, 8444, 3, index}); }

Key Wallet::GetBackupKey(Key const& master_sk, uint32_t index) { return master_sk.DerivePath({12381, 8444, 4, index}); }

Wallet::Wallet(std::string passphrase) : mnemonic_(Mnemonic::GenerateNew()), passphrase_(passphrase) {}

Wallet::Wallet(Mnemonic mnemonic, std::string passphrase) : mnemonic_(std::move(mnemonic)), passphrase_(passphrase) {}

Wallet::Wallet(std::string words, std::string passphrase) : mnemonic_(words), passphrase_(passphrase) {}

Key Wallet::GetKey(uint32_t index) const {
    Key key(mnemonic_, passphrase_);
    return GetKey(key, index);
}

Key Wallet::GetFarmerKey(uint32_t index) const {
    Key key(mnemonic_, passphrase_);
    return GetFarmerKey(key, index);
}

Key Wallet::GetPoolKey(uint32_t index) const {
    Key key(mnemonic_, passphrase_);
    return GetPoolKey(key, index);
}

Key Wallet::GetLocalKey(uint32_t index) const {
    Key key(mnemonic_, passphrase_);
    return GetLocalKey(key, index);
}

Key Wallet::GetBackupKey(uint32_t index) const {
    Key key(mnemonic_, passphrase_);
    return GetBackupKey(key, index);
}

Key Wallet::GetMainKey() const { return Key(mnemonic_, passphrase_); }

}  // namespace keyman
