#include "bls_key.h"

#ifdef __APPLE__
#include <gmp.h>
#endif

#include <chiabls/elements.hpp>
#include <chiabls/schemes.hpp>
#include <stdexcept>

#include "utils.h"

namespace chiapos {

struct CKey::KeyImpl {
    bls::PrivateKey privKey;
    KeyImpl(bls::PrivateKey k) : privKey(std::move(k)) {}
};

CKey::CKey() {}

CKey CKey::Generate(Bytes const& vchSeed) {
    bls::PrivateKey privKey = bls::AugSchemeMPL().KeyGen(vchSeed);
    CKey sk;
    sk.m_impl.reset(new KeyImpl(std::move(privKey)));
    return sk;
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

SecreKey CKey::ToRaw() const {
    if (m_impl == nullptr) {
        // No key available
        return {};
    }
    return MakeArray<SK_LEN>(m_impl->privKey.Serialize());
}

PubKey CKey::GetPubkey() const {
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

}  // namespace chiapos
