#include <unistd.h>
#include "UDP_IPv4_6.h"


void RxCallback(const NetworkType type, const void* payload, int payloadsize, void* const addr, const int addrlen)
{
    std::cout<<"RECV"<<+type<<":"<<payloadsize<<":"<<(char*)payload<<std::endl;
}

int main(int argc, char **argv) 
{ 
    UDPSocket socket;
    if(false == socket.Listen(std::string(argv[1]), RxCallback))
    {
        return 0;
    }
    while(1)
    {
        if(argc == 4)
            socket.Send(std::string(argv[2]), std::string(argv[3]), "HiHi", 5);
        sleep(1);
    }
    return 1; 
} 
