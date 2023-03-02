#ifndef TL_MSG_IDS_H
#define TL_MSG_IDS_H

#include <string>

// messages send from FrontEnd
enum class TimelordMsgs : int {
    PONG = 1000,
    PROOF = 1010,
    READY = 1020,
    SPEED = 1030,
    CALC_REPLY = 1040,
};

inline std::string TimelordMsgIdToString(TimelordMsgs msg_id) {
    switch (msg_id) {
        case TimelordMsgs::PROOF:
            return "PROOF";
        case TimelordMsgs::READY:
            return "READY";
        case TimelordMsgs::SPEED:
            return "SPEED";
        default:
            return "OTHERS";
    }
}

// messages send from Bhd
enum class TimelordClientMsgs : int {
    PING = 2000,
    CALC = 2010,
    QUERY_SPEED = 2020,
};

#endif
