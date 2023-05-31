#include "bls_key.h"

#ifdef __APPLE__
#include <gmp.h>
#endif

#include <openssl/evp.h>

#include <chiabls/elements.hpp>
#include <chiabls/schemes.hpp>
#include <stdexcept>

#define UTF8PROC_STATIC 1
#include <utf8proc.h>

#include <chiapos/kernel/utils.h>

namespace chiapos {

namespace utils {

std::string NormalizeString(std::string const& str) {
    uint8_t* chars = utf8proc_NFKD(reinterpret_cast<uint8_t const*>(str.data()));
    std::string res(reinterpret_cast<char const*>(chars));
    free(chars);
    return res;
}

}  // namespace utils

struct CKey::KeyImpl {
    bls::PrivateKey privKey;
    KeyImpl(bls::PrivateKey k) : privKey(std::move(k)) {}
};

CKey::CKey() {}

CKey CKey::CreateKeyWithRandomSeed(Bytes const& vchSeed) {
    bls::PrivateKey privKey = bls::AugSchemeMPL().KeyGen(vchSeed);
    CKey sk;
    sk.m_impl.reset(new KeyImpl(std::move(privKey)));
    return sk;
}

CKey CKey::CreateKeyWithMnemonicWords(std::string const& words, std::string const& passphrase) {
    std::string salt = utils::NormalizeString(std::string("mnemonic") + passphrase.data());
    std::string mnemonic = utils::NormalizeString(words);
    Bytes64 digest;
    digest.fill('\0');
    int len = PKCS5_PBKDF2_HMAC(mnemonic.data(), mnemonic.size(), reinterpret_cast<uint8_t const*>(salt.data()),
                                salt.size(), 2048, EVP_sha512(), 64, digest.data());
    assert(len == 1);
    Bytes seed = MakeBytes(digest);
    return CreateKeyWithRandomSeed(seed);
}

CKey::CKey(SecreKey const& sk) {
    if (sk.size() != SK_LEN) {
        throw std::runtime_error(
                "cannot create a bls private-key object because the length of incoming data is invalid");
    }
    bls::PrivateKey privKey = bls::PrivateKey::FromByteVector(MakeBytes<SK_LEN>(sk));
    m_impl.reset(new KeyImpl(privKey));
}

CKey::CKey(CKey&&) = default;

CKey& CKey::operator=(CKey&&) = default;

CKey::~CKey() = default;

SecreKey CKey::GetSecreKey() const {
    if (m_impl == nullptr) {
        // No key available
        return {};
    }
    return MakeArray<SK_LEN>(m_impl->privKey.Serialize());
}

PubKey CKey::GetPubKey() const {
    if (m_impl == nullptr) {
        throw std::runtime_error("cannot retrieve public-key from an empty CKey");
    }
    return MakeArray<PK_LEN>(m_impl->privKey.GetG1Element().Serialize());
}

Signature CKey::Sign(Bytes const& vchMessage) const {
    if (m_impl == nullptr) {
        throw std::runtime_error("trying to make a signature from an empty CKey");
    }
    bls::G2Element signature = bls::AugSchemeMPL().Sign(m_impl->privKey, bls::Bytes(vchMessage));
    return MakeArray<SIG_LEN>(signature.Serialize());
}

CKey CKey::DerivePath(std::vector<uint32_t> const& paths) const {
    bls::PrivateKey privKey = bls::PrivateKey::FromBytes(bls::Bytes(m_impl->privKey.Serialize()));
    auto sk{privKey};
    for (uint32_t path : paths) {
        sk = bls::AugSchemeMPL().DeriveChildSk(sk, path);
    }
    return CKey(MakeArray<SK_LEN>(sk.Serialize()));
}

bool VerifySignature(PubKey const& pk, Signature const& signature, Bytes const& vchMessage) {
    auto g1 = bls::G1Element::FromByteVector(MakeBytes(pk));
    auto s = bls::G2Element::FromByteVector(MakeBytes(signature));
    return bls::AugSchemeMPL().Verify(g1, vchMessage, s);
}

PubKey AggregatePubkeys(std::vector<PubKey> const& pks) {
    std::vector<bls::G1Element> elements;
    for (auto const& pk : pks) {
        auto g1 = bls::G1Element::FromByteVector(MakeBytes(pk));
        elements.push_back(std::move(g1));
    }
    auto g1 = bls::AugSchemeMPL().Aggregate(elements);
    return MakeArray<PK_LEN>(g1.Serialize());
}

CWallet::CWallet(CKey masterKey) : m_masterKey(std::move(masterKey)) {}

CKey const& CWallet::GetMasterKey() const { return m_masterKey; }

CKey CWallet::GetKey(uint32_t index) const { return m_masterKey.DerivePath({12381, 8444, 2, index}); }

CKey CWallet::GetFarmerKey(uint32_t index) const { return m_masterKey.DerivePath({12381, 8444, 0, index}); }

CKey CWallet::GetPoolKey(uint32_t index) const { return m_masterKey.DerivePath({12381, 8444, 1, index}); }

CKey CWallet::GetLocalKey(uint32_t index) const { return m_masterKey.DerivePath({12381, 8444, 3, index}); }

CKey CWallet::GetBackupKey(uint32_t index) const { return m_masterKey.DerivePath({12381, 8444, 4, index}); }

}  // namespace chiapos
