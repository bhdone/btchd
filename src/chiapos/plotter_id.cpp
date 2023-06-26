#include "plotter_id.h"

#include "kernel/utils.h"

CChiaFarmerPk::CChiaFarmerPk(chiapos::Bytes vchData) : m_vchData(std::move(vchData)) {
    if (m_vchData.size() != chiapos::PK_LEN) {
        throw std::runtime_error("invalid size of farmer public-key's data");
    }
}

std::string CChiaFarmerPk::ToString() const { return chiapos::BytesToHex(m_vchData); }

chiapos::Bytes const& CChiaFarmerPk::ToBytes() const { return m_vchData; }

bool CChiaFarmerPk::operator==(CChiaFarmerPk const& rhs) const { return m_vchData == rhs.m_vchData; }

bool CChiaFarmerPk::operator<(CChiaFarmerPk const& rhs) const { return m_vchData < rhs.m_vchData; }

bool CChiaFarmerPk::IsZero() const {
    for (uint8_t b : m_vchData) {
        if (b != 0) {
            return false;
        }
    }
    return true;
}

std::string CPlotterBindData::TypeToString(Type type) {
    switch (type) {
        case Type::UNKNOWN:
            return "unknown";
        case Type::BURST:
            return "burst";
        case Type::CHIA:
            return "chia";
    }
    assert(false);
}

CPlotterBindData::Type CPlotterBindData::GetType() const { return m_type; }

uint64_t CPlotterBindData::GetBurstPlotterId() const {
    if (GetType() != Type::BURST) {
        throw std::runtime_error("cannot retrieve burst plotter-id, the plotter-id type is not burst");
    }
    return boost::get<uint64_t>(m_data);
}

CChiaFarmerPk CPlotterBindData::GetChiaFarmerPk() const {
    if (GetType() != Type::CHIA) {
        throw std::runtime_error("cannot retrieve chia plotter-id, the plotter-id type is invalid");
    }
    return boost::get<CChiaFarmerPk>(m_data);
}

void CPlotterBindData::SetZero() {
    if (GetType() == Type::UNKNOWN) {
        // Do nothing when the type is unknown
        return;
    }
    if (GetType() == Type::BURST) {
        m_data = 0;
    } else if (GetType() == Type::CHIA) {
        m_data = CChiaFarmerPk();
    }
}

bool CPlotterBindData::IsZero() const {
    if (GetType() == Type::UNKNOWN) {
        return true;
    }
    if (GetType() == Type::BURST) {
        return GetBurstPlotterId() == 0;
    } else if (GetType() == Type::CHIA) {
        return GetChiaFarmerPk().IsZero();
    }
    return false;
}

CPlotterBindData& CPlotterBindData::operator=(uint64_t rhs) {
    if (GetType() == Type::CHIA) {
        throw std::runtime_error("cannot assign a plotter-id to CPlotterBindData(CHIA)");
    }
    m_data = rhs;
    m_type = Type::BURST;  // override if the original type is UNKNOWN
    return *this;
}

CPlotterBindData& CPlotterBindData::operator=(CChiaFarmerPk rhs) {
    if (GetType() == Type::BURST) {
        throw std::runtime_error("cannot assign farmer public-key to CPlotterBindData(BURST)");
    }
    m_data = std::move(rhs);
    m_type = Type::CHIA;  // override if the original type is UNKNOWN
    return *this;
}

CPlotterBindData& CPlotterBindData::operator=(CPlotterBindData const& rhs) {
    if (this != &rhs) {
        m_type = rhs.m_type;
        m_data = rhs.m_data;
    }
    return *this;
}

CPlotterBindData& CPlotterBindData::operator=(CPlotterBindData&& rhs) {
    if (this != &rhs) {
        m_type = rhs.m_type;
        m_data = std::move(rhs.m_data);
    }
    return *this;
}

bool CPlotterBindData::operator==(uint64_t rhs) const {
    if (GetType() == Type::UNKNOWN) {
        return false;
    }
    if (GetType() != Type::BURST) {
        return false;
    }
    return boost::get<uint64_t>(m_data) == rhs;
}

bool CPlotterBindData::operator==(CChiaFarmerPk const& rhs) const {
    if (GetType() == Type::UNKNOWN) {
        return false;
    }
    if (GetType() != Type::CHIA) {
        return false;
    }
    return boost::get<CChiaFarmerPk>(m_data) == rhs;
}

bool CPlotterBindData::operator==(CPlotterBindData const& rhs) const {
    if (GetType() == Type::UNKNOWN && rhs.GetType() == Type::UNKNOWN) {
        return true;
    } else if (GetType() == Type::UNKNOWN || rhs.GetType() == Type::UNKNOWN) {
        return false;
    } else if ((IsZero() && !rhs.IsZero()) || (!IsZero() && rhs.IsZero())) {
        return false;
    } else if (GetType() != rhs.GetType()) {
        return false;
    }
    return m_data == rhs.m_data;
}

bool CPlotterBindData::operator<(uint64_t rhs) const {
    if (GetType() != Type::BURST) {
        throw std::runtime_error("cannot compare Burst plotter-id because of the type is Chia");
    }
    return boost::get<uint64_t>(m_data) < rhs;
}

bool CPlotterBindData::operator<(CChiaFarmerPk const& rhs) const {
    if (GetType() != Type::CHIA) {
        throw std::runtime_error("cannot compare Chia plotter-id because of the type is Burst");
    }
    return boost::get<CChiaFarmerPk>(m_data) < rhs;
}

bool CPlotterBindData::operator<(CPlotterBindData const& rhs) const {
    if (GetType() != rhs.GetType()) {
        return GetType() < rhs.GetType();
    }
    if (GetType() == Type::BURST) {
        return *this < rhs.GetBurstPlotterId();
    } else if (GetType() == Type::CHIA) {
        return *this < rhs.GetChiaFarmerPk();
    }
    throw std::runtime_error("cannot compare two plotter-id because of the type of plotter-id is unknown");
}

std::string CPlotterBindData::ToString() const {
    if (GetType() == Type::BURST) {
        return std::to_string(boost::get<uint64_t>(m_data));
    } else if (GetType() == Type::CHIA) {
        return boost::get<CChiaFarmerPk>(m_data).ToString();
    }
    throw std::runtime_error("cannot convert plotter-id to string because of the type is unknown");
}
