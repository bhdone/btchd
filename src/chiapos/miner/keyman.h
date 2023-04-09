#ifndef BTCHD_KEYMAN_H
#define BTCHD_KEYMAN_H

#include <string>
#include <vector>

#include <chiapos/bhd_types.h>

namespace keyman {

class Mnemonic {
public:
    using Words = std::vector<std::string>;

    /// Generate a new mnemonic
    static Mnemonic GenerateNew(std::string lang = "en");

    /// Convert words into separated words string
    static std::string WordsToString(Mnemonic::Words const& words);

    /// Parse words from a string
    static Mnemonic::Words StringToWords(std::string str);

    /// Create a mnemonic object by importing words
    explicit Mnemonic(Words words, std::string lang = "en");

    /// Create a new mnemonic object by importing words in string
    explicit Mnemonic(std::string words, std::string lang = "en");

    /// Convert mnemonic to string
    std::string ToString() const;

    /// Get words of the mnemonic, it'll return an empty vector if the mnemonic is
    /// empty
    Words GetWords() const;

    /// Get the seed, fill with zeros if the mnemonic is empty
    Bytes64 GetSeed(std::string passphrase = "") const;

    /// Return `true` if current mnemonic is empty
    bool IsEmpty() const;

private:
    Words words_;
    Bytes bytes_;
};

class PubKey {
public:
    PubKey();

    explicit PubKey(PublicKey pubkey);

    PubKey operator+(PubKey const& rhs) const;

    PubKey& operator+=(PubKey const& rhs);

    PublicKey const& GetPublicKey() const;

private:
    PublicKey pubkey_;
};

class Key {
public:
    static int const PRIV_KEY_LEN = 32;
    static int const PUB_KEY_LEN = 48;
    static int const SIG_LEN = 96;

    static bool VerifySig(PublicKey const& pub_key, Bytes const& msg, Signature const& sig);

    static PublicKey CreatePublicKey();

    static PublicKey AddTwoPubkey(PublicKey const& lhs, PublicKey const& rhs);

    /// Create an empty key object without key creation
    Key();

    /// Create a object by importing the private key
    explicit Key(PrivateKey priv_key);

    /// Create a new key will be generated from the mnemonic
    Key(Mnemonic const& mnemonic, std::string passphrase);

    /// Return `true` when the key is empty
    bool IsEmpty() const;

    /// Generate a new private key
    void GenerateNew(Bytes const& seed);

    /// Get the private key value
    PrivateKey GetPrivateKey() const;

    /// Get public key
    PublicKey GetPublicKey() const;

    /// Make a signature
    Signature Sign(Bytes const& msg);

    /// Derive key
    Key DerivePath(std::vector<uint32_t> const& paths) const;

private:
    PrivateKey priv_key_;
};

class Wallet {
public:
    static Key GetKey(Key const& master_sk, uint32_t index);

    static Key GetFarmerKey(Key const& master_sk, uint32_t index);

    static Key GetPoolKey(Key const& master_sk, uint32_t index);

    static Key GetLocalKey(Key const& master_sk, uint32_t index);

    static Key GetBackupKey(Key const& master_sk, uint32_t index);

    /// Create a wallet object by importing a mnemonic
    Wallet(Mnemonic mnemonic, std::string passphrase);

    /// Create a wallet object from a passphrase words
    Wallet(std::string words, std::string passphrase);

    /// Get mnemonic object
    Mnemonic const& GetMnemonic() const { return mnemonic_; }

    /// Get `Key` object that is according the index
    Key GetKey(uint32_t index) const;

    Key GetFarmerKey(uint32_t index) const;

    Key GetPoolKey(uint32_t index) const;

    Key GetLocalKey(uint32_t index) const;

    Key GetBackupKey(uint32_t index) const;

    /// Get main-key which is generated directly from mnemonic
    Key GetMainKey() const;

private:
    Mnemonic mnemonic_;
    std::string passphrase_;
};

}  // namespace keyman

#endif
