#include <thread>
#include <vector>
#include <string>
#include <utility> 

enum NetworkType
{
    IPV4Network,
    IPV6Network
};

class UDPSocket
{
private:
    std::vector< std::pair<int, NetworkType> > m_Sockets;
    std::thread m_RxThread;
    bool m_RxRunning;
public:
    UDPSocket(const std::string port);
    ~UDPSocket();
    int Send(const std::string address, const std::string port, const void* payload, int payloadsize);    
};