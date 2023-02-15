#ifndef BTCHD_CHIAPOS_COMMON_TYPES_H
#define BTCHD_CHIAPOS_COMMON_TYPES_H

#include <boost/optional.hpp>
#include <cstdint>
#include <vector>

namespace chiapos {

using Bytes = std::vector<uint8_t>;

template <typename T>
using optional = boost::optional<T>;

}  // namespace chiapos

#endif
