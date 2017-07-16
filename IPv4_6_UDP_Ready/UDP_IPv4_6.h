#include <thread>
#include <vector>
#include <string>
#include <utility> 
#include "SingleShotTimer.h"

enum NetworkType
{
    IPV4Network = 0,
    IPV6Network
};

class UDPSocket
{
private:
    int m_Sockets[2];
    SingleShotTimer<2,1> m_TaskQueue;
    void AwatingPackets(std::function<void(const NetworkType type, const void* payload, int payloadsize, void* const addr, const int addrlen)> cb);
public:
    ~UDPSocket();
    void Send(const std::string address, const std::string port, const void* payload, int payloadsize);
    bool Listen(const std::string port, std::function<void(const NetworkType type, const void* payload, int payloadsize, void* const addr, const int addrlen)> cb);
    void Halt();
};
