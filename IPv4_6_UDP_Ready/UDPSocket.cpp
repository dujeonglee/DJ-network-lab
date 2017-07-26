#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <functional>
#include <iostream>
#include "UDPSocket.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
//#include <sys/types.h> 
//#include <sys/socket.h>

UDPSocket::UDPSocket()
{
    m_TxSockets[IPV4Network] = -1;
    m_TxSockets[IPV6Network] = -1;
    m_RxSockets[IPV4Network] = -1;
    m_RxSockets[IPV6Network] = -1;
}

UDPSocket::~UDPSocket()
{
    if(m_TxSockets[IPV4Network] != -1)
    {
        close(m_TxSockets[IPV4Network]);
        m_TxSockets[IPV4Network] = -1;
    }
    if(m_TxSockets[IPV6Network] != -1)
    {
        close(m_TxSockets[IPV6Network]);
        m_TxSockets[IPV6Network] = -1;
    }
    if(m_RxSockets[IPV4Network] != -1)
    {
        close(m_RxSockets[IPV4Network]);
        m_RxSockets[IPV4Network] = -1;
    }
    if(m_RxSockets[IPV6Network] != -1)
    {
        close(m_RxSockets[IPV6Network]);
        m_RxSockets[IPV6Network] = -1;
    }
}

bool UDPSocket::Start(const std::string listenport, bool broadcastflag)
{
    addrinfo hints;
    addrinfo *ret = nullptr;

    // If sockets are already opened, close all sockets.
    if(m_TxSockets[IPV4Network] != -1)
    {
        close(m_TxSockets[IPV4Network]);
        m_TxSockets[IPV4Network] = -1;
    }
    if(m_TxSockets[IPV6Network] != -1)
    {
        close(m_TxSockets[IPV6Network]);
        m_TxSockets[IPV6Network] = -1;
    }
    if(m_RxSockets[IPV4Network] != -1)
    {
        close(m_RxSockets[IPV4Network]);
        m_RxSockets[IPV4Network] = -1;
    }
    if(m_RxSockets[IPV6Network] != -1)
    {
        close(m_RxSockets[IPV6Network]);
        m_RxSockets[IPV6Network] = -1;
    }

    memset(&hints, 0x00, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;    // Accept IPv4 and IPv6 
    hints.ai_socktype = SOCK_DGRAM; // UDP
    if(getaddrinfo(nullptr, listenport.c_str(), &hints, &ret) != 0) 
    { 
        if(ret)
        {
            freeaddrinfo(ret);
        }
        return false; 
    }
    
    for(addrinfo *iter = ret; iter != nullptr; iter = iter->ai_next) 
    { 
        // IPv4
        if(iter->ai_family == AF_INET) 
        { 
            m_RxSockets[IPV4Network] = socket(iter->ai_family, iter->ai_socktype, iter->ai_protocol);
            if(m_RxSockets[IPV4Network] == -1)
            {
                Stop();
                freeaddrinfo(ret);
                return false;
            }
            int opt = 1;
            if(setsockopt(m_RxSockets[IPV4Network], SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(option)) == -1)
            {
                Stop();
                freeaddrinfo(ret);
                return false;
            }
            if(bind(m_RxSockets[IPV4Network], iter->ai_addr, iter->ai_addrlen) != 0) 
            {
                Stop();
                freeaddrinfo(ret);
                return false;
            }
        } 
        // IPv6
        else if(iter->ai_family == AF_INET6) 
        { 
            int opt = 1; 
            m_RxSockets[IPV6Network] = socket(iter->ai_family, iter->ai_socktype, iter->ai_protocol);
            if(m_RxSockets[IPV6Network] == -1)
            {
                Stop();
                freeaddrinfo(ret);
                return false;
            }
            opt = 1;
            if(setsockopt(m_RxSockets[IPV6Network], SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(option)) == -1)
            {
                Stop();
                freeaddrinfo(ret);
                return false;
            }
            opt = 1;
            if(setsockopt(m_RxSockets[IPV6Network], IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) == -1)
            {
                Stop();
                freeaddrinfo(ret);
                return false;
            }
            if(bind(m_RxSockets[IPV6Network], iter->ai_addr, iter->ai_addrlen) != 0) 
            {
                Stop();
                freeaddrinfo(ret);
                return false;
            }
        }
    }
    freeaddrinfo(ret);
    if(m_RxSockets[IPV4Network] == -1 && m_RxSockets[IPV6Network] == -1)
    {
        Stop();
        return false;
    }
    if(m_RxSockets[IPV4Network])
    {
        int option;
        m_TxSockets[IPV4Network] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(m_TxSockets[IPV4Network] == -1)
        {
            Stop();
            return false;
        }

        option = 1;
        if(setsockopt(m_TxSockets[IPV4Network], SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) == -1)
        {
            Stop();
            return false;
        }

        if(broadcastflag)
        {
            option = 1;
            if(setsockopt(m_TxSockets[IPV4Network], SOL_SOCKET, SO_BROADCAST, &option, sizeof(option)) == -1)
            {
                Stop();
                return false;
            }
        }
    }
    if(m_RxSockets[IPV6Network])
    {
        int option;
        m_TxSockets[IPV6Network] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if(m_TxSockets[IPV6Network] == -1)
        {
            Stop();
            return false;
        }

        option = 1;
        if(setsockopt(m_TxSockets[IPV6Network], SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) == -1)
        {
            Stop();
            return false;
        }

        if(broadcastflag)
        {
            option = 1;
            if(setsockopt(m_TxSockets[IPV6Network], SOL_SOCKET, SO_BROADCAST, &option, sizeof(option)) == -1)
            {
                Stop();
                return false;
            }
        }
    }
    return true;
}

bool UDPSocket::Stop()
{
    if(m_TxSockets[IPV4Network] != -1)
    {
        close(m_TxSockets[IPV4Network]);
        m_TxSockets[IPV4Network] = -1;
    }
    if(m_TxSockets[IPV6Network] != -1)
    {
        close(m_TxSockets[IPV6Network]);
        m_TxSockets[IPV6Network] = -1;
    }
    if(m_RxSockets[IPV4Network] != -1)
    {
        close(m_RxSockets[IPV4Network]);
        m_RxSockets[IPV4Network] = -1;
    }
    if(m_RxSockets[IPV6Network] != -1)
    {
        close(m_RxSockets[IPV6Network]);
        m_RxSockets[IPV6Network] = -1;
    }
    return true;
}

void UDPSocket::RegisterIPv4RxCallback(std::function<void(void* const, const uint32_t, sockaddr_in*  const)> cb)
{
    m_IPv4RxCallback = cb;
}

void UDPSocket::RegisterIPv6RxCallback(std::function<void(void* const, const uint32_t, sockaddr_in6* const)> cb)
{
    m_IPv6RxCallback = cb;
}

void UDPSocket::Send(const std::string address, const std::string port, const std::string interface, const void* payload, int payloadsize)
{
    addrinfo hints;
    addrinfo* ret = nullptr;
    addrinfo* iter = nullptr;

    memset(&hints, 0x00, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;    // Accept IPv4 and IPv6 
    hints.ai_socktype = SOCK_DGRAM; // UDP

    if(getaddrinfo(address.c_str(), port.c_str(), &hints, &ret) != 0)
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
            if(interface.compare(""))
            {
                /*if(setsockopt(m_TxSockets[IPV4Network], SOL_SOCKET, SO_BINDTODEVICE, interface.c_str(), strlen(interface.c_str())) == -1)
                {
                    freeaddrinfo(ret);
                    return;
                }*/
            }
            std::cout<<"Send IPv4"<<std::endl;
            sendto(m_TxSockets[IPV4Network], payload, (size_t)payloadsize, 0, (sockaddr*)iter->ai_addr, iter->ai_addrlen);
        }
        else if(iter->ai_family == AF_INET6)
        {
            if(interface.compare(""))
            {
                /*if(setsockopt(m_TxSockets[IPV6Network], SOL_SOCKET, SO_BINDTODEVICE, interface.c_str(), strlen(interface.c_str())) == -1)
                {
                    freeaddrinfo(ret);
                    return;
                }*/
            }
            std::cout<<"Send IPv6"<<std::endl;
            sendto(m_RxSockets[IPV6Network], payload, (size_t)payloadsize, 0, (sockaddr*)iter->ai_addr, iter->ai_addrlen);
        }
    }
    freeaddrinfo(ret);
}

void UDPSocket::Recv()
{
    char buffer[1024*10];
    timeval rx_to = {0, 10000};
    int MaxFD = -1;
    fd_set ReadFD;

    FD_ZERO(&ReadFD);
    FD_SET(m_RxSockets[IPV4Network], &ReadFD);
    FD_SET(m_RxSockets[IPV6Network], &ReadFD);
    MaxFD = (m_RxSockets[IPV4Network] > m_RxSockets[IPV6Network] ? m_RxSockets[IPV4Network] : m_RxSockets[IPV6Network]);

    const int state = select(MaxFD + 1 , &ReadFD, NULL, NULL, &rx_to);
    
    if(state <= 0)
    {
        return;
    }
    if(FD_ISSET(m_RxSockets[IPV4Network], &ReadFD))
    {
        sockaddr_in sender;
        socklen_t sender_length = sizeof(sender);
        const int ret = recvfrom(m_RxSockets[IPV4Network], buffer, sizeof(buffer), 0, (sockaddr*)&sender, &sender_length);
        if(ret > 0 && m_IPv4RxCallback)
        {
            m_IPv4RxCallback(buffer, ret, &sender);
        }
    }
    if(FD_ISSET(m_RxSockets[IPV6Network], &ReadFD))
    {
        sockaddr_in6 sender;
        socklen_t sender_length = sizeof(sender);
        const int ret = recvfrom(m_RxSockets[IPV6Network], buffer, sizeof(buffer), 0, (sockaddr*)&sender, &sender_length);
        if(ret > 0 && m_IPv6RxCallback)
        {
            m_IPv6RxCallback(buffer, ret, &sender);
        }
    }
}

const std::string UDPSocket::GetIPv4Address(const std::string interface)
{
    ifaddrs* ifa = nullptr;
    ifaddrs* iter = nullptr;
    char str[INET_ADDRSTRLEN] = {0};

    const int rc = getifaddrs(&ifa);
    if (rc==0) {
        for(iter = ifa ; iter != nullptr ; iter = iter->ifa_next) {
            if(iter->ifa_addr && 
                iter->ifa_addr->sa_family == AF_INET && 
                std::string(iter->ifa_name).compare(interface) == 0)
            {
                 break;
            }
        }
    }
    if(iter)
    {
        inet_ntop(iter->ifa_addr->sa_family, &((sockaddr_in*)iter->ifa_addr)->sin_addr, str, sizeof(str));
    }
    freeifaddrs(ifa);
    return std::string(str);
}

const std::string UDPSocket::GetIPv6Address(const std::string interface)
{
    ifaddrs* ifa = nullptr;
    ifaddrs* iter = nullptr;
    char str[INET6_ADDRSTRLEN] = {0};

    const int rc = getifaddrs(&ifa);
    if (rc==0) {
        for(iter = ifa ; iter != nullptr ; iter = iter->ifa_next) {
            if(iter->ifa_addr && 
                iter->ifa_addr->sa_family == AF_INET6 && 
                std::string(iter->ifa_name).compare(interface) == 0)
            {
                 break;
            }
        }
    }
    if(iter)
    {
        inet_ntop(iter->ifa_addr->sa_family, &((sockaddr_in6*)iter->ifa_addr)->sin6_addr, str, sizeof(str));
    }
    freeifaddrs(ifa);
    return std::string(str);
}

const std::string UDPSocket::GetIPv4Netmask(const std::string interface)
{
    ifaddrs* ifa = nullptr;
    ifaddrs* iter = nullptr;
    char str[INET_ADDRSTRLEN] = {0};
    const int rc = getifaddrs(&ifa);
    if (rc==0) {
        for(iter = ifa ; iter != nullptr ; iter = iter->ifa_next) {
            if(iter->ifa_netmask && 
                iter->ifa_netmask->sa_family == AF_INET && 
                std::string(iter->ifa_name).compare(interface) == 0)
            {
                break;
            }
        }
    }
    if(iter)
    {
        inet_ntop(iter->ifa_netmask->sa_family, &((sockaddr_in*)iter->ifa_netmask)->sin_addr, str, sizeof(str));
    }
    freeifaddrs(ifa);
    return std::string(str);
}

const std::string UDPSocket::GetIPv6Netmask(const std::string interface)
{
    ifaddrs* ifa = nullptr;
    ifaddrs* iter = nullptr;
    char str[INET6_ADDRSTRLEN] = {0};

    const int rc = getifaddrs(&ifa);
    if (rc==0) {
        for(iter = ifa ; iter != nullptr ; iter = iter->ifa_next) {
            if(iter->ifa_netmask && 
                iter->ifa_netmask->sa_family == AF_INET6 && 
                std::string(iter->ifa_name).compare(interface) == 0)
            {
                 break;
            }
        }
    }
    if(iter)
    {
        inet_ntop(iter->ifa_netmask->sa_family, &((sockaddr_in6*)iter->ifa_netmask)->sin6_addr, str, sizeof(str));
    }
    freeifaddrs(ifa);
    return std::string(str);
}
