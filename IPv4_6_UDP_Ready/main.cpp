#include <unistd.h>
#include <iostream>
#include "SingleShotTimer.h"
#include "UDPSocket.h"


UDPSocket Socket;
SingleShotTimer<2,1> Queue;

void Recv()
{
    std::cout<<__FUNCTION__<<std::endl;
    Socket.Recv();
    Queue.ImmediateTask([](){
        Recv();
    });
}



int main(int argc, char **argv) 
{ 
    if(false == Socket.Start(std::string(argv[1]), false))
    {
        return 0;
    }
    Socket.RegisterIPv4RxCallback([](void* const buffer, const uint32_t length, sockaddr_in*  const addr){
        // IPv4
        std::cout<<"IPv4:"<<(char*)buffer<<std::endl;
    });
    Socket.RegisterIPv6RxCallback([](void* const buffer, const uint32_t length, sockaddr_in6* const addr){
        // IPv6
        std::cout<<"IPv6:"<<(char*)buffer<<std::endl;
    });
    Recv();
    while(1)
    {
        if(argc == 4)
        {
            Socket.Send(std::string(argv[2]), std::string(argv[3]), "", "HiHi", 5);
        }
        sleep(1);
    }
    return 1; 
} 
