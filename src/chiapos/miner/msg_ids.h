#ifndef TL_MSG_IDS_H
#define TL_MSG_IDS_H

// messages send from FrontEnd
enum class TimelordMsgs : int {
    PONG = 1000,
    PROOF = 1010,
    READY = 1020,
    SPEED = 1030,
};

// messages send from Bhd
enum class TimelordClientMsgs : int {
    PING = 2000,
    CALC = 2010,
    QUERY_SPEED = 2020,
};

#endif
