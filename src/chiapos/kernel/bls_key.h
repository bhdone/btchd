#ifndef BTCHD_CHIAPOS_BLS_KEY_H
#define BTCHD_CHIAPOS_BLS_KEY_H

#include <array>
#include <memory>

#include "chiapos_types.h"

namespace chiapos {

int const PK_LEN = 48;
int const ADDR_LEN = 32;
int const SK_LEN = 32;
int const SIG_LEN = 96;

using PubKey = std::array<uint8_t, PK_LEN>;
using SecreKey = std::array<uint8_t, SK_LEN>;
using Signature = std::array<uint8_t, SIG_LEN>;

class CKey {
public:
    static CKey Generate(Bytes const& vchData);

    CKey();

    CKey(CKey const&) = delete;

    CKey& operator=(CKey const&) = delete;

    CKey(CKey&&);

    CKey& operator=(CKey&&);

    ~CKey();

    explicit CKey(SecreKey const& sk);

    SecreKey ToRaw() const;

    PubKey GetPubkey() const;

    Signature Sign(Bytes const& vchMessage) const;

private:
    struct KeyImpl;
    std::unique_ptr<KeyImpl> m_impl;
};

bool VerifySignature(PubKey const& pubkey, Signature const& signature, Bytes const& vchMessage);

PubKey AggregatePubkeys(std::vector<PubKey> const& pks);

}  // namespace chiapos

#endif
