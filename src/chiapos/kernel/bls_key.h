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
using Bytes64 = std::array<uint8_t, 64>;

class CKey {
public:
    static CKey CreateKeyWithRandomSeed(Bytes const& vchData);

    static CKey CreateKeyWithMnemonicWords(std::string const& words, std::string const& passphrase);

    CKey();

    CKey(CKey const&) = delete;

    CKey& operator=(CKey const&) = delete;

    CKey(CKey&&);

    CKey& operator=(CKey&&);

    ~CKey();

    explicit CKey(SecreKey const& sk);

    SecreKey GetSecreKey() const;

    PubKey GetPubKey() const;

    Signature Sign(Bytes const& vchMessage) const;

    CKey DerivePath(std::vector<uint32_t> const& paths) const;

private:
    struct KeyImpl;
    std::unique_ptr<KeyImpl> m_impl;
};

bool VerifySignature(PubKey const& pubkey, Signature const& signature, Bytes const& vchMessage);

PubKey AggregatePubkeys(std::vector<PubKey> const& pks);

class CWallet {
public:
    explicit CWallet(CKey masterKey);

    CKey const& GetMasterKey() const;

    CKey GetKey(uint32_t index) const;

    CKey GetFarmerKey(uint32_t index) const;

    CKey GetPoolKey(uint32_t index) const;

    CKey GetLocalKey(uint32_t index) const;

    CKey GetBackupKey(uint32_t index) const;

private:
    CKey m_masterKey;
};

}  // namespace chiapos

#endif
