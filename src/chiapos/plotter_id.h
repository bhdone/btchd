#ifndef BTCHD_CHIAPOS_PLOTTER_ID_H
#define BTCHD_CHIAPOS_PLOTTER_ID_H

#include <streams.h>

#include <array>
#include <boost/variant.hpp>
#include <cstdint>
#include <string>

#include "kernel/bls_key.h"

class CChiaFarmerPk {
public:
    CChiaFarmerPk() : m_vchData(chiapos::PK_LEN, 0) {}

    explicit CChiaFarmerPk(chiapos::Bytes vchData);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(LIMITED_VECTOR(m_vchData, chiapos::PK_LEN));
    }

    std::string ToString() const;

    chiapos::Bytes const& ToBytes() const;

    bool operator==(CChiaFarmerPk const& rhs) const;

    bool operator<(CChiaFarmerPk const& rhs) const;

    bool IsZero() const;

private:
    chiapos::Bytes m_vchData;
};

class CPlotterBindData {
public:
    enum class Type { UNKNOWN, BURST, CHIA };

    static std::string TypeToString(Type type);

    CPlotterBindData() {}

    explicit CPlotterBindData(uint64_t nPlotterId) : m_type(Type::BURST), m_data(nPlotterId) {}

    explicit CPlotterBindData(CChiaFarmerPk farmerPk) : m_type(Type::CHIA), m_data(std::move(farmerPk)) {}

    CPlotterBindData(CPlotterBindData const& rhs) : m_type(rhs.m_type), m_data(rhs.m_data) {}

    CPlotterBindData(CPlotterBindData&& rhs) : m_type(rhs.m_type), m_data(std::move(rhs.m_data)) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        if (GetType() == Type::BURST) {
            READWRITE(VARINT(boost::get<uint64_t>(m_data)));
        } else if (GetType() == Type::CHIA) {
            READWRITE(boost::get<CChiaFarmerPk>(m_data));
        } else {
            throw std::runtime_error(
                    "cannot execute serialization operator, because of the invalid type of plotter-id");
        }
    }

    Type GetType() const;

    uint64_t GetBurstPlotterId() const;

    CChiaFarmerPk GetChiaFarmerPk() const;

    void SetZero();

    bool IsZero() const;

    CPlotterBindData& operator=(uint64_t rhs);

    CPlotterBindData& operator=(CChiaFarmerPk rhs);

    CPlotterBindData& operator=(CPlotterBindData const& rhs);

    CPlotterBindData& operator=(CPlotterBindData&& rhs);

    bool operator==(uint64_t rhs) const;

    bool operator==(CChiaFarmerPk const& rhs) const;

    bool operator==(CPlotterBindData const& rhs) const;

    bool operator<(uint64_t rhs) const;

    bool operator<(CChiaFarmerPk const& rhs) const;

    bool operator<(CPlotterBindData const& rhs) const;

    std::string ToString() const;

private:
    Type m_type{Type::UNKNOWN};
    boost::variant<uint64_t, CChiaFarmerPk> m_data;
};

#endif
