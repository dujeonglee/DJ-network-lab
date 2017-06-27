#include <thread>
#include <vector>
#include <string>
#include <utility> 

enum NetworkType
{
    IPV4Network = 0,
    IPV6Network
};

class UDPSocket
{
private:
    int m_Sockets[2];
    std::thread m_RxThread;
    bool m_RxRunning;
public:
    UDPSocket(const std::string port);
    ~UDPSocket();
    int Send(const std::string address, const std::string port, const void* payload, int payloadsize);    
};
