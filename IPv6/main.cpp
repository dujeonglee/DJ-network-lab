#include <unistd.h>
#include "UDPIPv6.h"

int main(int argc, char **argv) 
{ 
    UDPSocket* socket = new UDPSocket(std::string(argv[1]));
    while(1)
    {
        if(argc == 4)
            socket->Send(std::string(argv[2]), std::string(argv[3]), "HiHi", 5);
        sleep(1);
    }
    return 1; 
} 
