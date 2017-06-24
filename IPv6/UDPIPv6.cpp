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
    addrinfo hints;
    addrinfo *ret;
    
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
        int sock;
        // IPv4
        if(iter->ai_family == AF_INET) 
        { 
            sin = (sockaddr_in *)iter->ai_addr; 
            inet_ntop(iter->ai_family, &sin->sin_addr, Addr, sizeof(Addr)); 
            std::cout<<"Bind: "<<iter->ai_protocol<<"/"<<iter->ai_socktype<<"/"<<Addr<<std::endl; 
            sock = socket(iter->ai_family, iter->ai_socktype, iter->ai_protocol);
            if(sock < 0)
            {
                exit(-1);
            }
            m_Sockets.push_back(std::pair<int, NetworkType>(sock, IPV4Network));
        } 
        // IPv6
        else if(iter->ai_family == AF_INET6) 
        { 
            int opt = 1; 
            sin6 = (sockaddr_in6*)iter->ai_addr; 
            inet_ntop(iter->ai_family, &sin6->sin6_addr, Addr, sizeof(Addr)); 
            std::cout<<"Bind: "<<iter->ai_protocol<<"/"<<iter->ai_socktype<<"/"<<Addr<<std::endl; 
            sock = socket(iter->ai_family, iter->ai_socktype, iter->ai_protocol);
            if(sock < 0)
            {
                exit(-1);
            }
            m_Sockets.push_back(std::pair<int, NetworkType>(sock, IPV6Network));
            setsockopt(m_Sockets.back().first, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&opt, sizeof(opt)); 
        }
        if(bind(m_Sockets.back().first, iter->ai_addr, iter->ai_addrlen) != 0) 
        {
            exit(-1);                
        }
    }
    freeaddrinfo(ret);
    const UDPSocket* self = this;
    m_RxRunning = true;
    m_RxThread = std::thread([self](){
        char buffer[1024];
        timeval rx_to = {1, 0};
        int MaxFD = -1;
        fd_set ReadFD;
        FD_ZERO(&ReadFD);
        for(unsigned int i = 0 ; i < self->m_Sockets.size() ; i++)
        {
            FD_SET(self->m_Sockets[i].first, &ReadFD);
            if(self->m_Sockets[i].first > MaxFD)
            {
                MaxFD = self->m_Sockets[i].first;
            }
        }
        while(self->m_RxRunning)
        {
            fd_set AllFD = ReadFD;
            const int state = select(MaxFD + 1 , &AllFD, NULL, NULL, &rx_to);
            
            if(state <= 0)
            {
                continue;
            }
            for(unsigned int i = 0 ; i < self->m_Sockets.size() ; i++)
            {
                if(FD_ISSET(self->m_Sockets[i].first, &AllFD))
                {
                    switch(self->m_Sockets[i].second)
                    {
                        case IPV4Network:
                        {
                            sockaddr_in sender;
                            size_t sender_length = sizeof(sender);
                            recvfrom(self->m_Sockets[i].first, buffer, sizeof(buffer), 0, (sockaddr*)&sender, &sender_length);
                            std::cout<<"Rx IPv4"<<buffer<<std::endl;
                        }
                            break;
                        case IPV6Network:
                        {
                            sockaddr_in6 sender;
                            size_t sender_length = sizeof(sender);
                            recvfrom(self->m_Sockets[i].first, buffer, sizeof(buffer), 0, (sockaddr*)&sender, &sender_length);
                            std::cout<<"Rx IPv6"<<buffer<<std::endl;
                        }
                            break;
                    }
                }
            }
        }
    });
}

UDPSocket::~UDPSocket()
{
    m_RxRunning = false;
    m_RxThread.join();
    for(uint32_t i = 0 ; i < m_Sockets.size() ; i++)
    {
        close(m_Sockets[i].first);
    }
    m_Sockets.clear();
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
            for(unsigned int i = 0 ; i < m_Sockets.size() ; i++)
            {
                if(m_Sockets[i].second == IPV6Network)
                {
                    continue;
                }
                std::cout<<"Send IPv4"<<std::endl;
                sendto(m_Sockets[i].first, payload, (size_t)payloadsize, 0, (sockaddr*)iter->ai_addr, iter->ai_addrlen);
            }
        }
        else if(iter->ai_family == AF_INET6)
        {
            for(unsigned int i = 0 ; i < m_Sockets.size() ; i++)
            {
                if(m_Sockets[i].second == IPV4Network)
                {
                    continue;
                }
                std::cout<<"Send IPv6"<<std::endl;
                sendto(m_Sockets[i].first, payload, (size_t)payloadsize, 0, (sockaddr*)iter->ai_addr, iter->ai_addrlen);
            }
        }
    }
    freeaddrinfo(ret);
    return payloadsize;
}

/*
int main(int argc, char* argv[])
{
   int sock;
   int status;
   struct addrinfo sainfo, *psinfo;
   struct sockaddr_in6 sin6;
   int sin6len;
   char buffer[MAXBUF];

   sin6len = sizeof(struct sockaddr_in6);

   if(argc < 2)
     printf("Specify a port number\n"), exit(1);

   sock = socket(PF_INET6, SOCK_DGRAM,0);

   memset(&sin6, 0, sizeof(struct sockaddr_in6));
   sin6.sin6_port = htons(0);
   sin6.sin6_family = AF_INET6;
   sin6.sin6_addr = in6addr_any;

   status = bind(sock, (struct sockaddr *)&sin6, sin6len);

   if(-1 == status)
     perror("bind"), exit(1);

   memset(&sainfo, 0, sizeof(struct addrinfo));
   memset(&sin6, 0, sin6len);

   sainfo.ai_flags = 0;
   sainfo.ai_family = PF_INET6;
   sainfo.ai_socktype = SOCK_DGRAM;
   sainfo.ai_protocol = IPPROTO_UDP;
   status = getaddrinfo("ip6-localhost", argv[1], &sainfo, &psinfo);

   switch (status) 
     {
      case EAI_FAMILY: printf("family\n");
        break;
      case EAI_SOCKTYPE: printf("stype\n");
        break;
      case EAI_BADFLAGS: printf("flag\n");
        break;
      case EAI_NONAME: printf("noname\n");
        break;
      case EAI_SERVICE: printf("service\n");
        break;
     }
   sprintf(buffer,"Ciao");

   status = sendto(sock, buffer, strlen(buffer), 0,
                     (struct sockaddr *)psinfo->ai_addr, sin6len);
   printf("buffer : %s \t%d\n", buffer, status);

   // free memory
   freeaddrinfo(psinfo);
   psinfo = NULL;

   shutdown(sock, 2);
   close(sock);
   return 0;
}
*/