#include <unistd.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/ioctl.h>

#include <cstring>
#include <iostream>
#include <iomanip>

#include "BroadMulticastForward.h"

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
    {
        sprintf(hex_output + di * 2, "%02x", digest[di]);
    }
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
                DHCPv4* const RxDHCPv4Hdr = (RxIP4Hdr && RxUDPHdr && (RxUDPHdr->dest == htons(67) || RxUDPHdr->dest == htons(68)) ?
                    (DHCPv4*)((uint8_t*)RxUDPHdr + sizeof(udphdr)) :
                    nullptr);
                DHCPv6* const RxDHCPv6Hdr = (RxIP6Hdr && RxUDPHdr && (RxUDPHdr->dest == htons(546) || RxUDPHdr->dest == htons(547)) ?
                    (DHCPv6*)((uint8_t*)RxUDPHdr + sizeof(udphdr)) :
                    nullptr);
                if(RxUDPHdr == nullptr)
                {
                    continue;
                }
                if(ntohs(RxUDPHdr->dest) == 20000)
                {
                    continue;
                }
                if(RxAddr.sll_pkttype == PACKET_OUTGOING)
                {
                    const MD5 ret = MessageDigest((uint8_t*)RxEthHdr + sizeof(ether_header), received_bytes-sizeof(ether_header));
                    if(m_MD5.GetPtr(ret) == nullptr)
                    {
                        m_MD5.Insert(ret, 0);
                        while(m_Running == true && m_Timer.ScheduleTask(3000, [self,ret](){
                            while(self->m_Running == true && self->m_ThreadPool.Enqueue([self,ret](){
                                self->m_MD5.Remove(ret);
                            }, 0) == false);
                        }, 0) == false);
                    }
                    continue;
                }

                std::cout<<(RxIP4Hdr?"[IPv4]":"")<<(RxIP6Hdr?"[IPv6]":"")<<(RxUDPHdr?"[UDP]":"")<<(RxDHCPv4Hdr?"[DHCPv4]("+std::to_string(RxDHCPv4Hdr->op)+")":"")<<(RxDHCPv6Hdr?"[DHCPv6]("+std::to_string(RxDHCPv6Hdr->Message)+")":"")<<std::endl;

                const MD5 ret = MessageDigest((uint8_t*)RxEthHdr + sizeof(ether_header), received_bytes-sizeof(ether_header));
                if(m_MD5.GetPtr(ret) == nullptr)
                {
                    m_MD5.Insert(ret, 0);
                    while(m_Running == true && m_Timer.ScheduleTask(3000, [self,ret](){
                        while(self->m_Running == true && self->m_ThreadPool.Enqueue([self,ret](){
                            self->m_MD5.Remove(ret);
                        }, 0) == false);
                    }, 0) == false);
                    if(RxDHCPv4Hdr == nullptr && RxDHCPv6Hdr == nullptr) // Ordinary broadcast and multicast packets.
                    {
                        HandleNormalPackets(m_RxBuffer, received_bytes, (NetworkInterfaceType)rxinterface);
                    }
                    else if(RxDHCPv4Hdr)
                    {
                        HandleDHCPv4Packets(m_RxBuffer, RxUDPHdr, RxDHCPv4Hdr, received_bytes, (NetworkInterfaceType)rxinterface);
                    }
                    else if(RxDHCPv6Hdr)
                    {
                        HandleDHCPv6Packets(m_RxBuffer, RxUDPHdr, RxDHCPv6Hdr, received_bytes, (NetworkInterfaceType)rxinterface);
                    }
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

void BroadMulticastForward::HandleNormalPackets(void* const pkt, const uint32_t pktlen, const NetworkInterfaceType iftype)
{
    std::cout<<__FUNCTION__<<std::endl;
    if(iftype == WIRELESS)
    {
        Send(WIRELESS, pkt, pktlen);
        Send(WIRED, pkt, pktlen);
    }
    else if(iftype == WIRED)
    {
        Send(WIRELESS, pkt, pktlen);
    }
}

void BroadMulticastForward::HandleDHCPv4Packets(void* const pkt, udphdr* const udp, DHCPv4* const dhcp, const uint32_t pktlen, const NetworkInterfaceType iftype)
{
    std::cout<<__FUNCTION__<<std::endl;
    if(dhcp->op == 1) // from client to server
    {
        dhcp->flags = 0x80;
        if(iftype == WIRELESS)
        {
            udp->check = 0;
            Send(WIRELESS, pkt, pktlen);
            Send(WIRED, pkt, pktlen);
        }
        else if(iftype == WIRED)
        {
            return;
        }
    }
    else // RxDHCPv4Hdr->op == 2 // from server to client
    {
        uint8_t* p_option = (uint8_t*)dhcp->options+4;
        bool ack = false;
        uint8_t* router_address = nullptr;
        while(p_option < (uint8_t*)pkt + pktlen)
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
            printf("DHCPv4 ACK [Router:%hhu.%hhu.%hhu.%hhu] -> ", router_address[0], router_address[1], router_address[2], router_address[3]);
            int fd;
            ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            if((fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
            {
                return;
            }
            ifr.ifr_addr.sa_family = PF_INET;
            strcpy(ifr.ifr_name, m_InterfaceNames[iftype].c_str());
            if(ioctl(fd, SIOCGIFADDR, &ifr) != 0)
            {
                close(fd);
                return;
            }
            close(fd);
            router_address[0] = ((uint8_t*)&((sockaddr_in*)&ifr.ifr_addr)->sin_addr)[0];
            router_address[1] = ((uint8_t*)&((sockaddr_in*)&ifr.ifr_addr)->sin_addr)[1];
            router_address[2] = ((uint8_t*)&((sockaddr_in*)&ifr.ifr_addr)->sin_addr)[2];
            router_address[3] = ((uint8_t*)&((sockaddr_in*)&ifr.ifr_addr)->sin_addr)[3];
            printf("[Router:%hhu.%hhu.%hhu.%hhu]\n", router_address[0], router_address[1], router_address[2], router_address[3]);
        }
        if(iftype == WIRELESS)
        {
            udp->check = 0;
            Send(WIRELESS, pkt, pktlen);
        }
        else if(iftype == WIRED)
        {
            udp->check = 0;
            Send(WIRELESS, pkt, pktlen);
        }
    }
}

void BroadMulticastForward::HandleDHCPv6Packets(void* const pkt, udphdr* const udp, DHCPv6* const dhcp, const uint32_t pktlen, const NetworkInterfaceType iftype)
{
    std::cout<<__FUNCTION__<<std::endl;
}

int BroadMulticastForward::Send(const NetworkInterfaceType iftype, void* const pkt, const uint32_t pktlen)
{
#if 0
    if(iftype >= MAX_NETWORK_INTERFACES)
    {
        return -1;
    }
    if(m_Sockets[iftype] == -1)
    {
        return -1;
    }
    sockaddr_ll ifaddr;
    memset(&ifaddr, 0, sizeof(ifaddr));
    ifaddr.sll_ifindex = if_nametoindex(m_InterfaceNames[iftype].c_str()); //Interface number
    ifaddr.sll_family = AF_PACKET;
    memcpy(ifaddr.sll_addr, m_InterfaceHWAddresses[iftype].address, ETHER_ADDR_LEN); //Physical layer address
    ifaddr.sll_halen = htons(ETHER_ADDR_LEN); //Length of address
    return sendto(m_Sockets[iftype], pkt, pktlen, 0, (sockaddr *)&ifaddr, sizeof(ifaddr));
#else
    return -1;
#endif
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
