#include <unistd.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include <cstring>
#include <iostream>
#include <iomanip>

#include "BroadcastForward.h"

BroadcastForward* BroadcastForward::g_Instance = new BroadcastForward();

BroadcastForward* BroadcastForward::Instance()
{
    return g_Instance;
}

bool BroadcastForward::HWAddress(const char* const ifname, uint8_t* const hw_address)
{
    FILE *file;
    char hw[18]={0};
    char filename[128]={0};
    sprintf(filename, "/sys/class/net/%s/address", ifname);
    file = fopen(filename, "r");
    if(file == NULL)
    {
        return false;
    }
    if(nullptr == fgets(hw, sizeof(hw), file))
    {
        return false;
    }
    fclose(file);
    if(sscanf(hw, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_address[0], &hw_address[1], &hw_address[2], &hw_address[3], &hw_address[4], &hw_address[5]) != ETHER_ADDR_LEN)
    {
        return false;
    }
    return true;
}

MD5 BroadcastForward::MessageDigest(const void* const data, const uint32_t length)
{
    MD5 ret;
    md5_state_t state;

    md5_init(&state);
    md5_append(&state, (const md5_byte_t *)data, length);
    md5_finish(&state, ret.stream);
    return ret; 
}

std::string BroadcastForward::MessageDigestStr(const void* const data, const uint32_t length)
{
    md5_state_t state;
    md5_byte_t digest[16];
    char hex_output[sizeof(digest)*2 + 1];

    md5_init(&state);
    md5_append(&state, (const md5_byte_t *)data, length);
    md5_finish(&state, digest);
    for(uint8_t di = 0; di < 16; ++di)
        sprintf(hex_output + di * 2, "%02x", digest[di]);
    return hex_output; 
}

void BroadcastForward::Forward(const std::string ifname)
{
    BroadcastForward* const self = this;
    if(m_IfName.compare("") == 0)
    {
       m_IfName = std::string(ifname);
    }

    while(HWAddress(m_IfName.c_str(), HWAddr) == false);
    while(setsockopt(m_RxSocket, SOL_SOCKET, SO_BINDTODEVICE, m_IfName.c_str(), strlen(m_IfName.c_str())) != 0);
    
    timeval rx_to = {1, 0};
    fd_set ReadFD;
    FD_ZERO(&ReadFD);
    FD_SET(m_RxSocket, &ReadFD);
    const int MaxFD = (m_RxSocket);

    fd_set AllFD = ReadFD;
    const int state = select(MaxFD + 1 , &AllFD, NULL, NULL, &rx_to);
    if(state <= 0)
    {
        goto FORWARD_END;
    }
    if(FD_ISSET(m_RxSocket, &AllFD))
    {
        ether_header* const RxEthHdr = (ether_header*)m_RxBuffer;
        int received_bytes = -1;
        sockaddr_ll RxAddr;
        socklen_t RxAddrLen = sizeof(RxAddr);

        memset(m_RxBuffer, 0x00, sizeof(m_RxBuffer));// Initialize the rx buffer.
        received_bytes = recvfrom(m_RxSocket, m_RxBuffer, sizeof(m_RxBuffer), 0, (sockaddr*)&RxAddr, &RxAddrLen);// Receive a packet.
        if(received_bytes <= 0)
        {
            goto FORWARD_END;
        }
        if(RxAddr.sll_pkttype == PACKET_OUTGOING)
        {
            goto FORWARD_END;
        }
        if(RxAddr.sll_pkttype != PACKET_BROADCAST && RxAddr.sll_pkttype != PACKET_MULTICAST)
        {
            goto FORWARD_END;
        }
        if(ntohs(RxEthHdr->ether_type) != ETH_P_IP && ntohs(RxEthHdr->ether_type) != ETH_P_IPV6)
        {
            goto FORWARD_END;
        }
        if(ntohs(RxEthHdr->ether_type) == ETH_P_IP)
        {
            if(RxAddr.sll_pkttype == PACKET_BROADCAST)
            {
                std::cout<<"IPv4 B"<<std::endl;
            }
            else
            {
                std::cout<<"IPv4 M"<<std::endl;
            }
        }
        if(ntohs(RxEthHdr->ether_type) == ETH_P_IPV6)
        {
            if(RxAddr.sll_pkttype == PACKET_BROADCAST)
            {
                std::cout<<"IPv6 B"<<std::endl;
            }
            else
            {
                std::cout<<"IPv6 M"<<std::endl;
            }
        }
        const MD5 ret = MessageDigest((uint8_t*)RxEthHdr + sizeof(ether_header), received_bytes-sizeof(ether_header));
        if(m_MD5.GetPtr(ret))
        {
            goto FORWARD_END;
        }
        m_MD5.Insert(ret, 0);
        m_Timer.ScheduleTask(3000, [self, ret](){
            self->m_ThreadPool.Enqueue([self, ret](){
                self->m_MD5.Remove(ret);
            }, 0);
        }, 0);
        sockaddr_ll ifaddr;
        memset(&ifaddr, 0, sizeof(ifaddr));
        ifaddr.sll_ifindex = if_nametoindex(m_IfName.c_str()); //Interface number
        ifaddr.sll_family = AF_PACKET;
        memcpy(ifaddr.sll_addr, HWAddr, ETHER_ADDR_LEN); //Physical layer address
        ifaddr.sll_halen = htons(ETHER_ADDR_LEN); //Length of address
        if(received_bytes!=sendto(m_TxSocket, m_RxBuffer, received_bytes, 0, (struct sockaddr *)&ifaddr, sizeof(ifaddr)))
        {
            std::cout<<"Cannot Send"<<std::endl;
        }
    }
FORWARD_END:
    m_Timer.ScheduleTask(0, [self](){
        self->m_ThreadPool.Enqueue([self](){
            self->Forward("");
        }, 1);
    }, 1);
}

BroadcastForward::BroadcastForward()
{
    m_IfName = "";
    while((m_RxSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0);
    while((m_TxSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0);
}

BroadcastForward::~BroadcastForward()
{
	m_Timer.Stop();
    close(m_RxSocket);
    close(m_TxSocket);
}
