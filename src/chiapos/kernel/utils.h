#ifndef BTCHD_CHIAPOS_UTILS_H
#define BTCHD_CHIAPOS_UTILS_H

#include <memory>

#include <crypto/sha256.h>
#include <uint256.h>

#include "chiapos_types.h"

namespace chiapos {

Bytes MakeBytes(uint256 const& val);

template <typename T, typename... Args>
std::unique_ptr<T> MakeUnique(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

template <size_t N>
Bytes MakeBytes(std::array<uint8_t, N> const& val) {
    Bytes res(N);
    memcpy(res.data(), val.data(), N);
    return res;
}

template <size_t N>
std::array<uint8_t, N> MakeArray(Bytes const& val) {
    assert(val.size() == N);
    std::array<uint8_t, N> res;
    memcpy(res.data(), val.data(), N);
    return res;
}

uint256 MakeUint256(Bytes const& vchBytes);

std::string BytesToHex(Bytes const& bytes);

Bytes BytesFromHex(std::string hex);

class BytesConnector {
    static void ConnectBytesList(BytesConnector& connector) {}

    template <typename T, typename... Ts>
    static void ConnectBytesList(BytesConnector& connector, T const& data, Ts&&... rest) {
        connector.Connect(data);
        ConnectBytesList(connector, std::forward<Ts>(rest)...);
    }

public:
    BytesConnector& Connect(Bytes const& data);

    template <size_t N>
    BytesConnector& Connect(std::array<uint8_t, N> const& data) {
        size_t nOffset = m_vchData.size();
        m_vchData.resize(nOffset + data.size());
        memcpy(m_vchData.data() + nOffset, data.data(), data.size());
        return *this;
    }

    template <typename T>
    BytesConnector& Connect(T const& val) {
        static_assert(std::is_integral<T>::value, "Connect with only buffer/number types");
        std::array<uint8_t, sizeof(T)> data;
        // TODO matthew: maybe we need to consider the byte order here
        memcpy(data.data(), &val, sizeof(T));
        return Connect(data);
    }

    Bytes const& GetData() const;

    template <typename... T>
    static Bytes Connect(T&&... dataList) {
        BytesConnector connector;
        ConnectBytesList(connector, std::forward<T>(dataList)...);
        return connector.GetData();
    }

private:
    Bytes m_vchData;
};

/**
 * Get part of a bytes
 *
 * @param bytes The source of those bytes
 * @param start From where the part is
 * @param count How many bytes you want to crypto_utils
 *
 * @return The bytes you want
 */
Bytes SubBytes(Bytes const& bytes, int start, int count = 0);

inline void MakeSHA256Impl(CSHA256& sha256) {}

inline void MakeSHA256_WriteData(CSHA256& sha256, Bytes const& data) { sha256.Write(data.data(), data.size()); }

inline void MakeSHA256_WriteData(CSHA256& sha256, uint256 const& data) { sha256.Write(data.begin(), data.size()); }

template <typename T, typename... TS>
void MakeSHA256Impl(CSHA256& sha256, T&& data, TS&&... params) {
    MakeSHA256_WriteData(sha256, std::forward<T>(data));
    MakeSHA256Impl(sha256, std::forward<TS>(params)...);
}

template <typename... T>
Bytes MakeSHA256(T&&... params) {
    CSHA256 sha256;
    MakeSHA256Impl(sha256, std::forward<T>(params)...);
    Bytes res(CSHA256::OUTPUT_SIZE);
    sha256.Finalize(res.data());
    return res;
}

std::string FormatNumberStr(std::string const& num_str);

uint64_t MakeNumberTB(uint64_t value);

std::string MakeNumberStr(uint64_t value);

using HostEntry = std::pair<std::string, uint16_t>;
std::vector<HostEntry> ParseHostsStr(std::string const& hosts, uint16_t default_port);

std::string FormatTime(int duration);

}  // namespace chiapos

#endif
