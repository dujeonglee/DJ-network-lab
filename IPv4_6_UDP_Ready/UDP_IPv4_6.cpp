#include <unistd.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include <cstring>
#include <iostream>

#include "UDP_IPv4_6.h"

void UDPSocket::AwatingPackets(std::function<void(const NetworkType type, const void* payload, int payloadsize, void* const addr, const int addrlen)> cb)
{
    char buffer[1024*10];
    timeval rx_to = {0, 100000};
    int MaxFD = -1;
    fd_set ReadFD;

    FD_ZERO(&ReadFD);
    FD_SET(m_Sockets[IPV4Network], &ReadFD);
    FD_SET(m_Sockets[IPV6Network], &ReadFD);
    MaxFD = (m_Sockets[IPV4Network] > m_Sockets[IPV6Network] ? m_Sockets[IPV4Network] : m_Sockets[IPV6Network]);

    const int state = select(MaxFD + 1 , &ReadFD, NULL, NULL, &rx_to);
    
    if(state <= 0)
    {
        // 2 Receive
        goto ScheduleNextPolling;
        return;
    }
    if(FD_ISSET(m_Sockets[IPV4Network], &ReadFD))
    {
        sockaddr_in sender;
        socklen_t sender_length = sizeof(sender);
        const int ret = recvfrom(m_Sockets[IPV4Network], buffer, sizeof(buffer), 0, (sockaddr*)&sender, &sender_length);
        if(ret > 0)
        {
            cb(IPV4Network, buffer, ret, &sender, sender_length);
        }
    }
    if(FD_ISSET(m_Sockets[IPV6Network], &ReadFD))
    {
        sockaddr_in6 sender;
        socklen_t sender_length = sizeof(sender);
        const int ret = recvfrom(m_Sockets[IPV6Network], buffer, sizeof(buffer), 0, (sockaddr*)&sender, &sender_length);
        if(ret > 0)
        {
            cb(IPV6Network, buffer, ret, &sender, sender_length);
        }
    }
ScheduleNextPolling:
    UDPSocket* const self = this;
    m_TaskQueue.ImmediateTask([self, cb](){
        self->AwatingPackets(cb);
    }, 1);
}

UDPSocket::~UDPSocket()
{
    Halt();
    close(m_Sockets[IPV4Network]);
    close(m_Sockets[IPV6Network]);
}


void UDPSocket::Send(const std::string address, const std::string port, const void* payload, int payloadsize)
{
    uint8_t* buffer = nullptr;
    try
    {
        buffer = new uint8_t[payloadsize];
        memcpy(buffer, payload, payloadsize);
    }
    catch (const std::bad_alloc& ex)
    {
        return;
    }

    UDPSocket* const self = this;
    if(IMMEDIATE_TIMER_ID != m_TaskQueue.ImmediateTask([self, address, port, buffer, payloadsize](){
        addrinfo hints;
        addrinfo* ret = nullptr;
        addrinfo* iter = nullptr;

        memset(&hints, 0x00, sizeof(hints));
        hints.ai_flags = AI_PASSIVE;
        hints.ai_family = AF_UNSPEC;    // Accept IPv4 and IPv6 
        hints.ai_socktype = SOCK_DGRAM; // UDP

        if(0 != getaddrinfo(address.c_str(), port.c_str(), &hints, &ret))
        {
            if(ret != nullptr)
            {
                freeaddrinfo(ret);
            }
            return;
        }
        for(iter = ret; iter != nullptr; iter=iter->ai_next)
        {
            if(iter->ai_family == AF_INET)
            {
                std::cout<<"Send IPv4"<<std::endl;
                sendto(self->m_Sockets[IPV4Network], buffer, (size_t)payloadsize, 0, (sockaddr*)iter->ai_addr, iter->ai_addrlen);
            }
            else if(iter->ai_family == AF_INET6)
            {
                std::cout<<"Send IPv6"<<std::endl;
                sendto(self->m_Sockets[IPV6Network], buffer, (size_t)payloadsize, 0, (sockaddr*)iter->ai_addr, iter->ai_addrlen);
            }
        }
        freeaddrinfo(ret);
        delete [] buffer;
    }, 0))
    {
        delete [] buffer;
        return;
    }
}

bool UDPSocket::Listen(const std::string port, std::function<void(const NetworkType type, const void* payload, int payloadsize, void* const addr, const int addrlen)> cb)
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
        return false; 
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
                if(m_Sockets[IPV4Network] != -1)
                {
                    close(m_Sockets[IPV4Network]);
                    m_Sockets[IPV4Network] = -1;
                }
                if(m_Sockets[IPV6Network] != -1)
                {
                    close(m_Sockets[IPV4Network]);
                    m_Sockets[IPV4Network] = -1;
                }
                return false;
            }
            if(bind(m_Sockets[IPV4Network], iter->ai_addr, iter->ai_addrlen) != 0) 
            {
                if(m_Sockets[IPV4Network] != -1)
                {
                    close(m_Sockets[IPV4Network]);
                    m_Sockets[IPV4Network] = -1;
                }
                if(m_Sockets[IPV6Network] != -1)
                {
                    close(m_Sockets[IPV4Network]);
                    m_Sockets[IPV4Network] = -1;
                }
                return false;
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
                if(m_Sockets[IPV4Network] != -1)
                {
                    close(m_Sockets[IPV4Network]);
                    m_Sockets[IPV4Network] = -1;
                }
                if(m_Sockets[IPV6Network] != -1)
                {
                    close(m_Sockets[IPV4Network]);
                    m_Sockets[IPV4Network] = -1;
                }
                return false;
            }
            setsockopt(m_Sockets[IPV6Network], IPPROTO_IPV6, IPV6_V6ONLY, (char *)&opt, sizeof(opt)); 
            if(bind(m_Sockets[IPV6Network], iter->ai_addr, iter->ai_addrlen) != 0) 
            {
                if(m_Sockets[IPV4Network] != -1)
                {
                    close(m_Sockets[IPV4Network]);
                    m_Sockets[IPV4Network] = -1;
                }
                if(m_Sockets[IPV6Network] != -1)
                {
                    close(m_Sockets[IPV4Network]);
                    m_Sockets[IPV4Network] = -1;
                }
                return false;
            }
        }
    }
    freeaddrinfo(ret);
    if(m_Sockets[IPV4Network] == -1 || m_Sockets[IPV6Network] == -1)
    {
        if(m_Sockets[IPV4Network] != -1)
        {
            close(m_Sockets[IPV4Network]);
            m_Sockets[IPV4Network] = -1;
        }
        if(m_Sockets[IPV6Network] != -1)
        {
            close(m_Sockets[IPV4Network]);
            m_Sockets[IPV4Network] = -1;
        }
        return false;
    }

	// 2 Receive
    UDPSocket* const self = this;
    while(IMMEDIATE_TIMER_ID != m_TaskQueue.ImmediateTask([self, cb](){
        self->AwatingPackets(cb);
    }));
    return true;
}

void UDPSocket::Halt()
{
    m_TaskQueue.Stop();
}
