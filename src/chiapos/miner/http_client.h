#ifndef CHIAPOS_MINER_HTTP_CLIENT_H
#define CHIAPOS_MINER_HTTP_CLIENT_H

#include <chiapos/kernel/chiapos_types.h>
#include <curl/curl.h>

#include <string>
#include <tuple>

namespace miner {

class HTTPClient {
public:
    HTTPClient(std::string url, std::string user, std::string passwd, bool no_proxy);

    ~HTTPClient();

    std::tuple<bool, int, std::string> Send(std::string const& buff);

    chiapos::Bytes GetReceivedData() const;

private:
    void AppendRecvData(char const* ptr, size_t total);

    static size_t RecvCallback(char* ptr, size_t size, size_t nmemb, void* userdata);

    static size_t SendCallback(char* buffer, size_t size, size_t nitems, void* userdata);

private:
    CURL* m_curl;
    std::string m_url;
    std::string m_user;
    std::string m_passwd;
    bool m_no_proxy;
    chiapos::Bytes m_send_data;
    size_t m_send_data_offset{0};
    chiapos::Bytes m_recv_data;
};

}  // namespace miner

#endif
