#include <unistd.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include <cstring>
#include <iostream>

#include "UDPIPv6.h"

UDPSocket::UDPSocket(const std::string port)
{
	// 1 Open Socket
    addrinfo hints;
    addrinfo *ret;

    m_Sockets[IPV4Network] = -1;
    m_Sockets[IPV6Network] = -1;
    
    memset(&hints, 0x00, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;    // Accept IPv4 and IPv6 
    hints.ai_socktype = SOCK_DGRAM; // UDP
    if(0 != getaddrinfo(nullptr, port.c_str(), &hints, &ret)) 
    { 
        exit(-1); 
    }
    
    for(addrinfo *iter = ret; iter != nullptr; iter = iter->ai_next) 
    { 
        sockaddr_in *sin; 
        sockaddr_in6 *sin6;
        char Addr[80] = {0};
        // IPv4
        if(iter->ai_family == AF_INET) 
        { 
            sin = (sockaddr_in *)iter->ai_addr; 
            inet_ntop(iter->ai_family, &sin->sin_addr, Addr, sizeof(Addr)); 
            std::cout<<"Bind: "<<iter->ai_protocol<<"/"<<iter->ai_socktype<<"/"<<Addr<<std::endl; 
            m_Sockets[IPV4Network] = socket(iter->ai_family, iter->ai_socktype, iter->ai_protocol);
            if(m_Sockets[IPV4Network] < 0)
            {
                exit(-1);
            }
            if(bind(m_Sockets[IPV4Network], iter->ai_addr, iter->ai_addrlen) != 0) 
            {
                exit(-1);                
            }
        } 
        // IPv6
        else if(iter->ai_family == AF_INET6) 
        { 
            int opt = 1; 
            sin6 = (sockaddr_in6*)iter->ai_addr; 
            inet_ntop(iter->ai_family, &sin6->sin6_addr, Addr, sizeof(Addr)); 
            std::cout<<"Bind: "<<iter->ai_protocol<<"/"<<iter->ai_socktype<<"/"<<Addr<<std::endl; 
            m_Sockets[IPV6Network] = socket(iter->ai_family, iter->ai_socktype, iter->ai_protocol);
            if(m_Sockets[IPV6Network] < 0)
            {
                exit(-1);
            }
            setsockopt(m_Sockets[IPV6Network], IPPROTO_IPV6, IPV6_V6ONLY, (char *)&opt, sizeof(opt)); 
            if(bind(m_Sockets[IPV6Network], iter->ai_addr, iter->ai_addrlen) != 0) 
            {
                exit(-1);                
            }
        }
    }
    freeaddrinfo(ret);
    if(m_Sockets[IPV4Network] == -1 || m_Sockets[IPV6Network] == -1)
    {
        exit(-1);
    }

	// 2 Receive
    const UDPSocket* self = this;
    m_RxRunning = true;
    m_RxThread = std::thread([self](){
        char buffer[1024];
        timeval rx_to = {1, 0};
        int MaxFD = -1;
        fd_set ReadFD;
        FD_ZERO(&ReadFD);
        FD_SET(self->m_Sockets[IPV4Network], &ReadFD);
        FD_SET(self->m_Sockets[IPV6Network], &ReadFD);
        MaxFD = (self->m_Sockets[IPV4Network] > self->m_Sockets[IPV6Network] ? self->m_Sockets[IPV4Network] : self->m_Sockets[IPV6Network]);

        while(self->m_RxRunning)
        {
            fd_set AllFD = ReadFD;
            const int state = select(MaxFD + 1 , &AllFD, NULL, NULL, &rx_to);
            
            if(state <= 0)
            {
                continue;
            }
            if(FD_ISSET(self->m_Sockets[IPV4Network], &AllFD))
            {
                sockaddr_in sender;
                socklen_t sender_length = sizeof(sender);
                recvfrom(self->m_Sockets[IPV4Network], buffer, sizeof(buffer), 0, (sockaddr*)&sender, &sender_length);
                std::cout<<"Rx IPv4"<<buffer<<std::endl;
            }
            if(FD_ISSET(self->m_Sockets[IPV6Network], &AllFD))
            {
                sockaddr_in6 sender;
                socklen_t sender_length = sizeof(sender);
                recvfrom(self->m_Sockets[IPV6Network], buffer, sizeof(buffer), 0, (sockaddr*)&sender, &sender_length);
                std::cout<<"Rx IPv6"<<buffer<<std::endl;
            }
        }
    });
}

UDPSocket::~UDPSocket()
{
    m_RxRunning = false;
    m_RxThread.join();
    close(m_Sockets[IPV4Network]);
    close(m_Sockets[IPV6Network]);
}


int UDPSocket::Send(const std::string address, const std::string port, const void* payload, int payloadsize)
{
    addrinfo hints;
    addrinfo* ret = nullptr;
    addrinfo* iter = nullptr;

    memset(&hints, 0x00, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;    // Accept IPv4 and IPv6 
    hints.ai_socktype = SOCK_DGRAM; // UDP

    if(0 != getaddrinfo(address.c_str(), port.c_str(), &hints, &ret))
    {
        if(nullptr)
        {
            freeaddrinfo(ret);
        }
        return -1;
    }
    for(iter = ret; iter != nullptr; iter=iter->ai_next)
    {
        if(iter->ai_family == AF_INET)
        {
            std::cout<<"Send IPv4"<<std::endl;
            sendto(m_Sockets[IPV4Network], payload, (size_t)payloadsize, 0, (sockaddr*)iter->ai_addr, iter->ai_addrlen);
        }
        else if(iter->ai_family == AF_INET6)
        {
            std::cout<<"Send IPv6"<<std::endl;
            sendto(m_Sockets[IPV6Network], payload, (size_t)payloadsize, 0, (sockaddr*)iter->ai_addr, iter->ai_addrlen);
        }
    }
    freeaddrinfo(ret);
    return payloadsize;
}
