#include "utils.h"

#include <sstream>

namespace chiapos {

Bytes MakeBytes(uint256 const& val) { return BytesFromHex(val.ToString()); }

uint256 MakeUint256(Bytes const& vchBytes) { return uint256S(BytesToHex(vchBytes)); }

Bytes StrToBytes(std::string str) {
    Bytes b;
    b.resize(str.size());
    memcpy(b.data(), str.data(), str.size());
    return b;
}

char const hex_chars[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

char Byte4bToHexChar(uint8_t hex) { return hex_chars[hex]; }

uint8_t HexCharToByte4b(char ch) {
    if (ch >= 'A' && ch <= 'F') {
        ch = std::tolower(ch);
    }
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    // Not found, the character is invalid
    std::stringstream err_ss;
    err_ss << "invalid hex character (" << static_cast<int>(ch) << ") in order to convert into number";
    throw std::runtime_error(err_ss.str());
}

std::string ByteToHex(uint8_t byte) {
    std::string hex(2, '0');
    uint8_t hi = (byte & 0xf0) >> 4;
    uint8_t lo = byte & 0x0f;
    hex[0] = Byte4bToHexChar(hi);
    hex[1] = Byte4bToHexChar(lo);
    return hex;
}

uint8_t ByteFromHex(std::string const& hex, int* consumed) {
    int actual_len = strlen(hex.c_str());
    if (actual_len == 0) {
        if (consumed) {
            *consumed = 0;
        }
        return 0;
    }
    if (actual_len == 1) {
        if (consumed) {
            *consumed = 1;
        }
        return HexCharToByte4b(hex[0]);
    }
    uint8_t byte = (static_cast<int>(HexCharToByte4b(hex[0])) << 4) + HexCharToByte4b(hex[1]);
    if (consumed) {
        *consumed = 2;
    }
    return byte;
}

std::string BytesToHex(Bytes const& bytes) {
    std::stringstream ss;
    for (uint8_t byte : bytes) {
        ss << ByteToHex(byte);
    }
    return ss.str();
}

Bytes BytesFromHex(std::string hex) {
    Bytes res;
    int consumed;
    uint8_t byte = ByteFromHex(hex, &consumed);
    while (consumed > 0) {
        res.push_back(byte);
        hex = hex.substr(consumed);
        // Next byte
        byte = ByteFromHex(hex, &consumed);
    }
    return res;
}

BytesConnector& BytesConnector::Connect(Bytes const& vchData) {
    size_t nOffset = m_vchData.size();
    m_vchData.resize(nOffset + vchData.size());
    memcpy(m_vchData.data() + nOffset, vchData.data(), vchData.size());
    return *this;
}

Bytes const& BytesConnector::GetData() const { return m_vchData; }

Bytes SubBytes(Bytes const& bytes, int start, int count) {
    int n;
    if (count == 0) {
        n = bytes.size() - start;
    } else {
        n = count;
    }
    Bytes res(n);
    memcpy(res.data(), bytes.data() + start, n);
    return res;
}

std::string FormatNumberStr(std::string const& num_str) {
    std::string res;
    int c{0};
    for (auto i = num_str.rbegin(); i != num_str.rend(); ++i) {
        if (c == 3) {
            c = 1;
            res.insert(res.begin(), 1, ',');
        } else {
            ++c;
        }
        res.insert(res.begin(), 1, *i);
    }
    return res;
}

std::string MakeNumberStr(uint64_t value) { return FormatNumberStr(std::to_string(value)); }

std::tuple<HostEntry, bool> ParseHostEntryStr(std::string const& entry_str, uint16_t default_port) {
    if (entry_str.empty()) {
        return std::make_tuple(std::make_pair("", default_port), false);
    }
    auto c_pos = entry_str.find_first_of(':');
    if (c_pos != std::string::npos) {
        std::string host = entry_str.substr(0, c_pos);
        std::string port_str = entry_str.substr(c_pos + 1);
        int port = std::atoi(port_str.c_str());
        if (port != 0) {
            return std::make_tuple(std::make_pair(host, port), true);
        }
    }
    return std::make_tuple(std::make_pair(entry_str, default_port), true);
}

std::vector<HostEntry> ParseHostsStr(std::string const& hosts, uint16_t default_port) {
    std::vector<HostEntry> res;
    HostEntry entry;
    bool succ;

    auto pos = 0;
    auto last_pos = hosts.find_first_of(',');
    while (last_pos != std::string::npos) {
        std::string entry_str = hosts.substr(pos, last_pos - pos);
        // analyze entry_str with ':' separated
        auto c_pos = entry_str.find_first_of(':');
        if (c_pos != std::string::npos) {
            std::tie(entry, succ) = ParseHostEntryStr(entry_str, default_port);
            if (succ) {
                res.push_back(std::move(entry));
            }
        }
        pos = last_pos + 1;
        last_pos = hosts.find_first_of(',', pos);
    }
    std::tie(entry, succ) = ParseHostEntryStr(hosts.substr(pos), default_port);
    if (succ) {
        res.push_back(std::move(entry));
    }
    return res;
}

std::string FormatTime(int duration) {
    int sec = duration % 60;
    int min = duration / 60 % 60;
    int hour = duration / 3600;
    return std::to_string(hour) + ":" + std::to_string(min) + ":" + std::to_string(sec);
}

}  // namespace chiapos
