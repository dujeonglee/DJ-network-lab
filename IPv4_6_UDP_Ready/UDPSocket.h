#include <netinet/in.h>
#include <stdint.h>

#include <string>

enum NetworkType : uint8_t
{
    IPV4Network = 0,
    IPV6Network = 1,
    IPNetworks = 2
};

class UDPSocket
{
private:
    int m_TxSockets[IPNetworks];
    int m_RxSockets[IPNetworks];
    std::function<void(void* const, const uint32_t, sockaddr_in*  const)> m_IPv4RxCallback;
    std::function<void(void* const, const uint32_t, sockaddr_in6* const)> m_IPv6RxCallback;
public:
    UDPSocket();
    ~UDPSocket();
    bool Start(const std::string listenport, bool broadcastflag = false);
    bool Stop();
    void RegisterIPv4RxCallback(std::function<void(void* const, const uint32_t, sockaddr_in*  const)> cb);
    void RegisterIPv6RxCallback(std::function<void(void* const, const uint32_t, sockaddr_in6* const)> cb);
    void Send(const std::string address, const std::string port, const std::string interface, const void* payload, int payloadsize);
    void Recv();
    static const std::string GetIPv4Address(const std::string);
    static const std::string GetIPv6Address(const std::string);
    static const std::string GetIPv4Netmask(const std::string);
    static const std::string GetIPv6Netmask(const std::string);
};
