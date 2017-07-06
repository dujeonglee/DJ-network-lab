#include <unistd.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include <cstring>
#include <iostream>
#include <iomanip>

#include "BroadMulticastForward.h"

struct DHCPv4
{
    uint8_t op;									/* 0: Message opcode/type */
    uint8_t htype;								/* 1: Hardware addr type (net/if_types.h) */
    uint8_t hlen;								/* 2: Hardware addr length */
    uint8_t hops;								/* 3: Number of relay agent hops from client */
    uint32_t xid;								/* 4: Transaction ID */
    uint16_t secs;								/* 8: Seconds since client started looking */
    uint16_t flags;								/* 10: Flag bits */
    uint32_t ciaddr;							/* 12: Client IP address (if already in use) */
    uint32_t yiaddr;							/* 16: Client IP address */
    uint32_t siaddr;							/* 18: IP address of next server to talk to */
    uint32_t giaddr;							/* 20: DHCP relay agent IP address */
    uint8_t chaddr[16];						/* 24: Client hardware address */
    char sname[64];			/* 40: Server name */
    char file[128];				/* 104: Boot filename */
    char options[1236];	/* 212: Optional parameters */
};

struct DHCPv6
{
    uint8_t Message;
    uint8_t Data[1];
}__attribute__((packed));

BroadMulticastForward* BroadMulticastForward::g_Instance = new BroadMulticastForward();

BroadMulticastForward* BroadMulticastForward::Instance()
{
    return g_Instance;
}

bool BroadMulticastForward::HWAddress(const char* const ifname, uint8_t* const hw_address)
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

MD5 BroadMulticastForward::MessageDigest(const void* const data, const uint32_t length)
{
    MD5 ret;
    md5_state_t state;

    md5_init(&state);
    md5_append(&state, (const md5_byte_t *)data, length);
    md5_finish(&state, ret.stream);
    return ret; 
}

std::string BroadMulticastForward::MessageDigestStr(const void* const data, const uint32_t length)
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

void BroadMulticastForward::Forward()
{
    BroadMulticastForward* const self = this;
    timeval rx_to = {1, 0};
    fd_set ReadFD;

    FD_ZERO(&ReadFD);
    if(m_InterfaceNames[WIRELESS].compare(""))
    {
        FD_SET(m_Sockets[WIRELESS], &ReadFD);
    }
    if(m_InterfaceNames[WIRED].compare(""))
    {
        FD_SET(m_Sockets[WIRED], &ReadFD);
    }
    const int MaxFD = (m_Sockets[WIRELESS] > m_Sockets[WIRED]?m_Sockets[WIRELESS]:m_Sockets[WIRED]);
    const int state = select(MaxFD + 1 , &ReadFD, NULL, NULL, &rx_to);
    if(state > 0)
    {
        for(uint8_t rxinterface = 0 ; rxinterface < MAX_NETWORK_INTERFACES ; rxinterface++)
        {
            if(m_Sockets[rxinterface] != -1 && FD_ISSET(m_Sockets[rxinterface], &ReadFD))
            {
                int received_bytes = -1;
                sockaddr_ll RxAddr;
                socklen_t RxAddrLen = sizeof(RxAddr);

                memset(m_RxBuffer, 0x00, sizeof(m_RxBuffer));// Initialize the rx buffer.
                received_bytes = recvfrom(m_Sockets[rxinterface], m_RxBuffer, sizeof(m_RxBuffer), 0, (sockaddr*)&RxAddr, &RxAddrLen);// Receive a packet.
                if(received_bytes <= 0)
                {
                    continue;
                }
                if(RxAddr.sll_pkttype != PACKET_BROADCAST && RxAddr.sll_pkttype != PACKET_MULTICAST)
                {
                    continue;
                }
                ether_header* const RxEthHdr = (ether_header*)m_RxBuffer;
                if(ntohs(RxEthHdr->ether_type) != ETH_P_IP && ntohs(RxEthHdr->ether_type) != ETH_P_IPV6)
                {
                    continue;
                }
                iphdr* const RxIP4Hdr  = (ntohs(RxEthHdr->ether_type) == ETH_P_IP ? 
                    (iphdr*)(m_RxBuffer+sizeof(ether_header)) :
                    nullptr);

                ip6_hdr* const RxIP6Hdr = ( ntohs(RxEthHdr->ether_type) == ETH_P_IPV6 ?
                    (ip6_hdr*)(m_RxBuffer+sizeof(ether_header)) :
                    nullptr);

                udphdr* const RxUDPHdr = ( ntohs(RxEthHdr->ether_type) == ETH_P_IP  ? 
                    ( RxIP4Hdr->protocol == 0x11? (udphdr*)(m_RxBuffer+sizeof(ether_header)+RxIP4Hdr->ihl*4) : nullptr ):
                    ( RxIP6Hdr->ip6_nxt  == 0x11? (udphdr*)(m_RxBuffer+sizeof(ether_header)+sizeof(ip6_hdr)) : nullptr ) );
                if(RxUDPHdr && ntohs(RxUDPHdr->dest) == 20000)
                {
                    continue;
                }
                DHCPv4* const RxDHCPv4Hdr = (RxIP4Hdr && RxUDPHdr && (RxUDPHdr->dest == htons(67) || RxUDPHdr->dest == htons(68)) ?
                    (DHCPv4*)((uint8_t*)RxUDPHdr + sizeof(udphdr)) :
                    nullptr);
                if(RxDHCPv4Hdr)
                {
                    if(RxDHCPv4Hdr->op == 1)
                    {
                        RxDHCPv4Hdr->flags = 0x80;
                        RxUDPHdr->check = 0;
                    }
                    else // RxDHCPv4Hdr->op == 2
                    {
                        uint8_t* p_option = (uint8_t*)RxDHCPv4Hdr->options+4;
                        bool ack = false;
                        uint8_t* router_address = nullptr;
                        while(p_option < (uint8_t*)RxUDPHdr + ntohs(RxUDPHdr->len))
                        {
                            if(p_option[0] == 53)
                            {
                                // Ack
                                ack = true;
                            }
                            if(p_option[0] == 3)
                            {
                                // Router option;
                                router_address = p_option+2;
                            }
                            if(ack && router_address)
                            {
                                break;
                            }
                            else
                            {
                                p_option = p_option + sizeof(uint8_t) + sizeof(uint8_t) + p_option[1];
                            }
                        }
                        if(ack && router_address)
                        {
                            printf("DHCPv4 ACK [Router:%hhu.%hhu.%hhu.%hhu]\n", router_address[0], router_address[1], router_address[2], router_address[3]);
                            sockaddr_in addr;
                            socklen_t len = sizeof(addr);
                            memset(&addr, 0, sizeof(addr));
                            if(getsockname(m_Sockets[rxinterface], (sockaddr*)&addr, &len) != 0)
                            {
                                continue;
                            }
                            router_address[0] = ((uint8_t*)&addr)[0];
                            router_address[1] = ((uint8_t*)&addr)[1];
                            router_address[2] = ((uint8_t*)&addr)[2];
                            router_address[3] = ((uint8_t*)&addr)[3];
                            RxUDPHdr->check = 0;
                        }

                    }
                }
                DHCPv6* const RxDHCPv6Hdr = (RxIP6Hdr && RxUDPHdr && (RxUDPHdr->dest == htons(546) || RxUDPHdr->dest == htons(547)) ?
                    (DHCPv6*)((uint8_t*)RxUDPHdr + sizeof(udphdr)) :
                    nullptr);
                std::cout<<(RxIP4Hdr?"[IPv4]":"")<<(RxIP6Hdr?"[IPv6]":"")<<(RxUDPHdr?"[UDP]":"")<<(RxDHCPv4Hdr?"[DHCPv4]("+std::to_string(RxDHCPv4Hdr->op)+")":"")<<(RxDHCPv6Hdr?"[DHCPv6]("+std::to_string(RxDHCPv6Hdr->Message)+")":"")<<std::endl;
                
                if(RxAddr.sll_pkttype == PACKET_OUTGOING)
                {
                    const MD5 ret = MessageDigest((uint8_t*)RxEthHdr + sizeof(ether_header), received_bytes-sizeof(ether_header));
                    if(m_MD5.GetPtr(ret) == nullptr)
                    {
                        m_MD5.Insert(ret, 0);
                        while(m_Running == true && m_Timer.ScheduleTask(1000, [self,ret](){
                            while(self->m_Running == true && self->m_ThreadPool.Enqueue([self,ret](){
                                self->m_MD5.Remove(ret);
                            }, 0) == false);
                        }, 0) == false);
                    }
                    continue;
                }
                const MD5 ret = MessageDigest((uint8_t*)RxEthHdr + sizeof(ether_header), received_bytes-sizeof(ether_header));
                if(m_MD5.GetPtr(ret) == nullptr)
                {
                    m_MD5.Insert(ret, 0);
                    while(m_Running == true && m_Timer.ScheduleTask(1000, [self,ret](){
                        while(self->m_Running == true && self->m_ThreadPool.Enqueue([self,ret](){
                            self->m_MD5.Remove(ret);
                        }, 0) == false);
                    }, 0) == false);
                    #if 0
                    if(m_Sockets[WIRELESS] != -1)
                    {
                        sockaddr_ll ifaddr;
                        memset(&ifaddr, 0, sizeof(ifaddr));
                        ifaddr.sll_ifindex = if_nametoindex(m_InterfaceNames[WIRELESS].c_str()); //Interface number
                        ifaddr.sll_family = AF_PACKET;
                        memcpy(ifaddr.sll_addr, m_InterfaceHWAddresses[WIRELESS].address, ETHER_ADDR_LEN); //Physical layer address
                        ifaddr.sll_halen = htons(ETHER_ADDR_LEN); //Length of address
                        if(received_bytes!=sendto(m_Sockets[WIRELESS], m_RxBuffer, received_bytes, 0, (sockaddr *)&ifaddr, sizeof(ifaddr)))
                        {
                            std::cout<<"Cannot Send"<<std::endl;
                        }
                    }
                    if(rxinterface == WIRELESS)
                    {
                        if(m_Sockets[WIRED] != -1)
                        {
                            sockaddr_ll ifaddr;
                            memset(&ifaddr, 0, sizeof(ifaddr));
                            ifaddr.sll_ifindex = if_nametoindex(m_InterfaceNames[WIRED].c_str()); //Interface number
                            ifaddr.sll_family = AF_PACKET;
                            memcpy(ifaddr.sll_addr, m_InterfaceHWAddresses[WIRED].address, ETHER_ADDR_LEN); //Physical layer address
                            ifaddr.sll_halen = htons(ETHER_ADDR_LEN); //Length of address
                            if(received_bytes!=sendto(m_Sockets[WIRED], m_RxBuffer, received_bytes, 0, (sockaddr *)&ifaddr, sizeof(ifaddr)))
                            {
                                std::cout<<"Cannot Send"<<std::endl;
                            }
                        }
                    }
                    #endif
                }
            }
        }
    }

    while(m_Running == true && m_Timer.ScheduleTask(0, [self](){
        while(self->m_Running == true && self->m_ThreadPool.Enqueue([self](){
            self->Forward();
        }, 1) == false);
    }, 1) == false);
}

void BroadMulticastForward::SetNetworkInterface(const NetworkInterfaceType type, const std::string iface)
{
    if(HWAddress(iface.c_str(), m_InterfaceHWAddresses[type].address))
    {
        m_InterfaceNames[type] = iface;
    }
    else
    {
        m_InterfaceNames[type] = "";
        memset(m_InterfaceHWAddresses[type].address, 0, sizeof(m_InterfaceHWAddresses[type].address));
    }
}

BroadMulticastForward::BroadMulticastForward()
{
    m_Running = false;
    m_Sockets[WIRELESS] = -1;
    m_Sockets[WIRED] = -1;

    m_MD5.Clear();
    m_ThreadPool.Stop();
    m_Timer.Stop();

    m_ThreadPool.Start();
    m_Timer.Start();
}

BroadMulticastForward::~BroadMulticastForward()
{
	Stop();
}

bool BroadMulticastForward::Start()
{
    if(m_InterfaceNames[WIRELESS].compare("") == 0 && m_InterfaceNames[WIRED].compare("") == 0)
    {
        return false;
    }
    if(m_InterfaceNames[WIRELESS].compare(""))
    {
        sockaddr_ll sll;
        if((m_Sockets[WIRELESS] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
        {
            return false;
        }
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET; 
        sll.sll_ifindex = if_nametoindex(m_InterfaceNames[WIRELESS].c_str()); 
        sll.sll_protocol = htons(ETH_P_ALL);
        if((bind(m_Sockets[WIRELESS], (sockaddr*)&sll , sizeof(sll))) ==-1)
        {
            close(m_Sockets[WIRELESS]);
            return false;
        }
    }
    if(m_InterfaceNames[WIRED].compare(""))
    {
        sockaddr_ll sll;
        if((m_Sockets[WIRED] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
        {
            close(m_Sockets[WIRELESS]);
            return false;
        }
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET; 
        sll.sll_ifindex = if_nametoindex(m_InterfaceNames[WIRED].c_str()); 
        sll.sll_protocol = htons(ETH_P_ALL);
        if((bind(m_Sockets[WIRED], (sockaddr*)&sll , sizeof(sll))) ==-1)
        {
            close(m_Sockets[WIRELESS]);
            close(m_Sockets[WIRED]);
            return false;
        }
    }
    m_ThreadPool.Start();
    m_Timer.Start();
    m_Running = true;
    Forward();
    return true;
}

void BroadMulticastForward::Stop()
{
    m_Running = false;
    m_MD5.Clear();
    m_ThreadPool.Stop();
    m_Timer.Stop();
    if(m_Sockets[WIRELESS] > 0)
    {
        close(m_Sockets[WIRELESS]);
    }
    if(m_Sockets[WIRED] > 0)
    {
        close(m_Sockets[WIRED]);
    }
}
