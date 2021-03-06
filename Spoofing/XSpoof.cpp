#include <unistd.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/ioctl.h>

#include <cstring>
#include <iostream>

#include "XSpoof.h"

#define MAC_ADDR_BUFFER_SIZE    18
#define FILE_NAME_SIZE          128

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif /*ETHER_ADDR_LEN*/

#ifndef IP_ADDR_LEN
#define IP_ADDR_LEN 4
#endif /*IP_ADDR_LEN*/

#ifndef ARP_LEN
#define ARP_LEN                  (sizeof(struct ether_header) + sizeof(struct ether_arp))
#endif /*ARP_LEN*/

enum ICMPOptions : uint8_t
{
    Source_Link_Layer_Address = 1,
    Target_Link_Layer_Address
};

struct ICMPOptionTLV
{
    ICMPOptions Type;
    uint8_t     Length;
    uint8_t     Value[6];
}__attribute__((packed));

struct ICMPOptionLinkLayerAddress
{
    ICMPOptions Type;
    uint8_t     Length;
    uint8_t     Address[6];
}__attribute__((packed));

XSpoof* XSpoof::g_Instance = new XSpoof();

XSpoof* XSpoof::Instance()
{
    return g_Instance;
}

bool XSpoof::HWAddress(const char* const ifname, uint8_t* const hw_address)
{
    FILE *file = nullptr;
    char hw[MAC_ADDR_BUFFER_SIZE]={0};
    char filename[FILE_NAME_SIZE]={0};
    sprintf(filename, "/sys/class/net/%s/address", ifname);
    file = fopen(filename, "r");
    if(file == nullptr)
    {
        return false;
    }
    if(nullptr == fgets(hw, MAC_ADDR_BUFFER_SIZE, file))
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


void XSpoof::DoXSpoof()
{
    timeval rx_to = {1, 0};
    fd_set ReadFD;
    FD_ZERO(&ReadFD);
    FD_SET(m_RxSockets[IPV4], &ReadFD);
    FD_SET(m_RxSockets[IPV6], &ReadFD);
    const int MaxFD = (m_RxSockets[IPV4] > m_RxSockets[IPV6] ? m_RxSockets[IPV4] : m_RxSockets[IPV6]);

    const int state = select(MaxFD + 1 , &ReadFD, NULL, NULL, &rx_to);
    if(state <= 0)
    {
        return;
    }
    if(FD_ISSET(m_RxSockets[IPV4], &ReadFD))
    {
        sockaddr_ll remote;
        memset(&remote, 0, sizeof(remote));
        uint32_t addrLength = sizeof(remote);
        ether_header* const RxEthHdr = (ether_header*)m_RxBuffer;
        ether_arp* const RxARPHdr= (ether_arp*)(m_RxBuffer+sizeof(ether_header));
        ether_header* const TxEthHdr = (ether_header *)m_TxBuffer;
        ether_arp* const TxARPHdr = (ether_arp *)(m_TxBuffer + sizeof(ether_header));
        int received_bytes = -1;
        sockaddr_ll ifaddr;

        memset(m_RxBuffer, 0x00, ARP_LEN);// Initialize the rx buffer.
        received_bytes = recvfrom(m_RxSockets[IPV4], m_RxBuffer, ARP_LEN, 0, (sockaddr*)&remote, &addrLength);// Receive a packet.
        if(received_bytes > 0)
        {
            char ifname[128];
            if_indextoname(remote.sll_ifindex, ifname);
            char targetip[128];
            inet_ntop(AF_INET, RxARPHdr->arp_tpa, targetip, INET_ADDRSTRLEN);
            std::cout<<"ARP Req for "<<targetip<<" ["<<ifname<<"]"<<std::endl;
            // make reply packet;
            // ethernet header
            memcpy(TxEthHdr->ether_dhost, RxEthHdr->ether_shost, ETHER_ADDR_LEN);// set destination mac address of reply packet with the source mac address of the request packet.
            memcpy(TxEthHdr->ether_shost, m_HWAddr, ETHER_ADDR_LEN);
            TxEthHdr->ether_type = htons(ETH_P_ARP);
            // arp header
            TxARPHdr->ea_hdr.ar_hrd = htons(ARPHRD_ETHER); //Format of hardware address
            TxARPHdr->ea_hdr.ar_pro = htons(ETH_P_IP);  //Format of protocol address.
            TxARPHdr->ea_hdr.ar_hln = ETHER_ADDR_LEN; //Length of hardware address.
            TxARPHdr->ea_hdr.ar_pln = IP_ADDR_LEN; //Length of protocol address.
            TxARPHdr->ea_hdr.ar_op = htons(ARPOP_REPLY); //ARP operation : REPLY
            memcpy(TxARPHdr->arp_sha, m_HWAddr, ETHER_ADDR_LEN);// set source mac address of the reply packet with mac address of this machine.
            memcpy(TxARPHdr->arp_spa, RxARPHdr->arp_tpa, IP_ADDR_LEN);// set source IP address of the reply packet with the target IP address of the request packet.
            memcpy(TxARPHdr->arp_tha, RxEthHdr->ether_shost, ETHER_ADDR_LEN);// set target mac address with the source mac address of the request packet.
            memcpy(TxARPHdr->arp_tpa, RxARPHdr->arp_spa, IP_ADDR_LEN);// set target IP address of the reply packet with the source IP address of the request packet.
            // sockaddr_ll
            memset(&ifaddr, 0, sizeof(ifaddr));
            ifaddr.sll_ifindex = if_nametoindex(m_IfName.c_str()); //Interface number
            ifaddr.sll_family = AF_PACKET;
            memcpy(ifaddr.sll_addr, m_HWAddr, ETHER_ADDR_LEN); //Physical layer address
            ifaddr.sll_halen = htons(ETHER_ADDR_LEN); //Length of address
            #if 0 /*Caution. This can screw up the network.*/
            if(ARP_LEN != sendto(m_TxSocket, m_TxBuffer, ARP_LEN, 0, (struct sockaddr *) &ifaddr, sizeof(ifaddr)))
            {
                std::cout<<"Cannot send arp spoofing message"<<std::endl;
            }
            #endif
        }
    }

    if(FD_ISSET(m_RxSockets[IPV6], &ReadFD))
    {
        sockaddr_ll remote;
        uint32_t addrLength = sizeof(remote);
        ether_header* const RxEthHdr = (ether_header*)m_RxBuffer;
        ip6_hdr* const IPv6Hdr = (ip6_hdr*)(m_RxBuffer+sizeof(ether_header));
        icmp6_hdr* const ICMPv6Hdr = (icmp6_hdr*)(m_RxBuffer+sizeof(ether_header)+sizeof(ip6_hdr));
        int received_bytes/*, sent_bytes*/;

        memset(m_RxBuffer, 0x00, ARP_LEN);// Initialize the rx buffer.
        received_bytes = recvfrom(m_RxSockets[IPV6], m_RxBuffer, sizeof(m_RxBuffer), 0, (sockaddr*)&remote, &addrLength);// Receive a packet.
        if(received_bytes > 0 && IPv6Hdr->ip6_nxt == 0x3A && ICMPv6Hdr->icmp6_type == ND_NEIGHBOR_SOLICIT)
        {
            std::cout<<"IPv6"<<":"<<__LINE__<<std::endl;
            if(ICMPChecksum(IPv6Hdr))
            {
                std::cout<<"Checksum error"<<std::endl;
                return;
            }
            nd_neighbor_solicit* NeighborSolicit = (nd_neighbor_solicit*)ICMPv6Hdr;

            uint8_t* parsingposition = (uint8_t*)NeighborSolicit+sizeof(nd_neighbor_solicit);
            while(parsingposition < ((uint8_t*)m_RxBuffer + received_bytes))
            {
                ICMPOptionTLV* tlv = (ICMPOptionTLV*)(parsingposition);
                if(tlv->Type == Source_Link_Layer_Address)
                {
                    // SOURCE LINK LAYER ADDRESS
                    // printf("--SourceLinkLayerAddress: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", 
                    //    tlv->Value[0], tlv->Value[1], tlv->Value[2], tlv->Value[3], tlv->Value[4], tlv->Value[5]);
                }
                if(tlv->Type == Target_Link_Layer_Address)
                {
                    // TARGET LINK LAYER ADDRESS
                    // printf("--TargetLinkLayerAddress: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", 
                    //    tlv->Value[0], tlv->Value[1], tlv->Value[2], tlv->Value[3], tlv->Value[4], tlv->Value[5]);
                }
                parsingposition += tlv->Length*8;
            }
            char target_ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, NeighborSolicit->nd_ns_target.s6_addr , target_ip_str, INET6_ADDRSTRLEN);
            std::cout<<"Neighbor Req for "<<target_ip_str<<std::endl;
            {
                ether_header* const TxEthHdr       = (ether_header*)      (m_TxBuffer);
                ip6_hdr* const TxIPv6Hdr           = (ip6_hdr*)           (m_TxBuffer+sizeof(ether_header));
                nd_neighbor_advert* const TxNeighborAdvert = (nd_neighbor_advert*)(m_TxBuffer+sizeof(ether_header)+sizeof(ip6_hdr));
                ICMPOptionLinkLayerAddress* const TxLinkLayerAddress = (ICMPOptionLinkLayerAddress*)(m_TxBuffer+sizeof(ether_header)+sizeof(ip6_hdr)+sizeof(nd_neighbor_advert));
                sockaddr_ll ifaddr;

                memcpy(TxEthHdr->ether_dhost, RxEthHdr->ether_shost, ETHER_ADDR_LEN);// set destination mac address of reply packet with the source mac address of the request packet.
                memcpy(TxEthHdr->ether_shost, m_HWAddr, ETHER_ADDR_LEN);
                TxEthHdr->ether_type = htons(ETH_P_IPV6);

                TxIPv6Hdr->ip6_vfc  = (0x60 & 0xf0);
                TxIPv6Hdr->ip6_plen = htons(sizeof(nd_neighbor_advert)+sizeof(ICMPOptionLinkLayerAddress));
                TxIPv6Hdr->ip6_nxt  = 58;
                TxIPv6Hdr->ip6_hops = 255;
                memcpy(&TxIPv6Hdr->ip6_src, NeighborSolicit->nd_ns_target.s6_addr , 16);
                memcpy(&TxIPv6Hdr->ip6_dst, IPv6Hdr->ip6_src.s6_addr, 16);

                TxNeighborAdvert->nd_na_type = ND_NEIGHBOR_ADVERT;
                TxNeighborAdvert->nd_na_code = 0;
                TxNeighborAdvert->nd_na_cksum = 0;
                TxNeighborAdvert->nd_na_flags_reserved = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;
                TxNeighborAdvert->nd_na_target = NeighborSolicit->nd_ns_target;
                TxLinkLayerAddress->Type = Target_Link_Layer_Address;
                TxLinkLayerAddress->Length = 1;
                memcpy(TxLinkLayerAddress->Address, m_HWAddr, 6);
                // Calcuate Checksum
                TxNeighborAdvert->nd_na_cksum = ICMPChecksum(TxIPv6Hdr);
                
                memset(&ifaddr, 0, sizeof(ifaddr));
                ifaddr.sll_ifindex = if_nametoindex(m_IfName.c_str()); //Interface number
                ifaddr.sll_family = AF_PACKET;
                memcpy(ifaddr.sll_addr, m_HWAddr, ETHER_ADDR_LEN); //Physical layer address
                ifaddr.sll_halen = htons(ETHER_ADDR_LEN); //Length of address

            #if 0/*Caution. This can screw up the network.*/
                if((int)(sizeof(ether_header)+sizeof(ip6_hdr)+ntohs(TxIPv6Hdr->ip6_plen)) != 
                    sendto(m_TxSocket, m_TxBuffer, sizeof(ether_header)+sizeof(ip6_hdr)+ntohs(TxIPv6Hdr->ip6_plen), 0, (struct sockaddr *)&ifaddr, sizeof(ifaddr)))
                {
                    std::cout<<"Cannot send NDP spoofing message"<<std::endl;
                }
                else
                {
                    std::cout<<"Send NDP spoofing message"<<std::endl;
                }
            #endif
            }
        }
    }
}

uint16_t XSpoof::ICMPChecksum(void* IP6Hdr)
{
    // Calculation must be done in the host byte order.
    // Then, the result must be converted into the network byte order.
    ip6_hdr* const IP = (ip6_hdr*)IP6Hdr;
    const uint32_t payloadlength = ntohs(IP->ip6_plen);
    const uint32_t nextheader = IP->ip6_nxt;
    uint32_t sum = 0;

    // Psuedo header for checksum calculation
    for(uint8_t i = 0 ; i < 16 ; i+=2)
    {
        sum += ntohs(*(uint16_t*)(IP->ip6_src.s6_addr+i));
        sum += ntohs(*(uint16_t*)(IP->ip6_dst.s6_addr+i));
    }
    sum += ((payloadlength&0xffff) + (payloadlength>>16));
    sum += ((nextheader&0xffff) + (nextheader>>16));

    // Sum up 2-byte values until none or only one byte left.
    uint32_t len = ntohs(IP->ip6_plen);
    uint16_t* buffer = (uint16_t*)((uint8_t*)IP + sizeof(ip6_hdr));
    while(len > 1)
    {
        sum += ntohs(*(buffer++));
        len -= 2;
    }
    if (len > 0)
    {
        sum += *(uint8_t*)buffer;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    return htons((~sum));
}

void XSpoof::SendNeighborAdvertisement(const uint8_t* TargetIPAddress, const uint8_t* TargetMACAddress, const std::string interface)
{
    const unsigned char BroadcastHWAddr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const unsigned char AllNodeMulticastIPAddress[] =   {0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    ether_header* const TxEthHdr       = (ether_header*)      (m_TxBuffer);
    ip6_hdr* const TxIPv6Hdr           = (ip6_hdr*)           (m_TxBuffer+sizeof(ether_header));
    nd_neighbor_advert* const TxNeighborAdvert = (nd_neighbor_advert*)(m_TxBuffer+sizeof(ether_header)+sizeof(ip6_hdr));
    ICMPOptionLinkLayerAddress* const TxLinkLayerAddress = (ICMPOptionLinkLayerAddress*)(m_TxBuffer+sizeof(ether_header)+sizeof(ip6_hdr)+sizeof(nd_neighbor_advert));
    sockaddr_ll ifaddr;

    memset(m_TxBuffer, 0, sizeof(m_TxBuffer));

    memcpy(TxEthHdr->ether_dhost, BroadcastHWAddr, ETHER_ADDR_LEN);// set destination mac address of reply packet with the source mac address of the request packet.
    if(TargetMACAddress)
    {
        memcpy(TxEthHdr->ether_shost, TargetMACAddress, ETHER_ADDR_LEN);
    }
    else
    {
        memcpy(TxEthHdr->ether_shost, m_HWAddr, ETHER_ADDR_LEN);
    }
    TxEthHdr->ether_type = htons(ETH_P_IPV6);

    TxIPv6Hdr->ip6_vfc  |= (0x60 & 0xf0);
    TxIPv6Hdr->ip6_plen |= htons(sizeof(nd_neighbor_advert)+sizeof(ICMPOptionLinkLayerAddress));
    TxIPv6Hdr->ip6_nxt  |= 58;
    TxIPv6Hdr->ip6_hops |= 255;
    memcpy(&TxIPv6Hdr->ip6_src, TargetIPAddress, 16);
    memcpy(&TxIPv6Hdr->ip6_dst, AllNodeMulticastIPAddress, 16);

    TxNeighborAdvert->nd_na_type = ND_NEIGHBOR_ADVERT;
    TxNeighborAdvert->nd_na_code = 0;
    TxNeighborAdvert->nd_na_cksum = 0;
    TxNeighborAdvert->nd_na_flags_reserved = ND_NA_FLAG_OVERRIDE;
    memcpy(&TxNeighborAdvert->nd_na_target, TargetIPAddress, 16);
    TxLinkLayerAddress->Type = Target_Link_Layer_Address;
    TxLinkLayerAddress->Length = 1;
    if(TargetMACAddress)
    {
        memcpy(TxLinkLayerAddress->Address, TargetMACAddress, 6);
    }
    else
    {
        memcpy(TxLinkLayerAddress->Address, m_HWAddr, 6);
    }
    // Calcuate Checksum
    TxNeighborAdvert->nd_na_cksum = ICMPChecksum(TxIPv6Hdr);

    memset(&ifaddr, 0, sizeof(ifaddr));
    ifaddr.sll_ifindex = if_nametoindex(m_IfName.c_str()); //Interface number
    ifaddr.sll_family = AF_PACKET;
    if(TargetMACAddress)
    {
        memcpy(ifaddr.sll_addr, TargetMACAddress, ETHER_ADDR_LEN); //Physical layer address
    }
    else
    {
        memcpy(ifaddr.sll_addr, m_HWAddr, ETHER_ADDR_LEN); //Physical layer address
    }
    ifaddr.sll_halen = htons(ETHER_ADDR_LEN); //Length of address

    if((int)(sizeof(ether_header)+sizeof(ip6_hdr)+ntohs(TxIPv6Hdr->ip6_plen)) != 
        sendto(m_TxSocket, m_TxBuffer, sizeof(ether_header)+sizeof(ip6_hdr)+ntohs(TxIPv6Hdr->ip6_plen), 0, (struct sockaddr *)&ifaddr, sizeof(ifaddr)))
    {
        std::cout<<"Cannot send NDP spoofing message"<<std::endl;
    }

    std::cout<<"SendNeighborAdvertisement"<<std::endl;
}

bool XSpoof::Start(const std::string interface)
{
    if(m_Running == true)
    {
        return true;
    }

    m_IfName = interface;

    if(HWAddress(m_IfName.c_str(), m_HWAddr) == false)
    {
        Stop();
        return false;
    }

    if((m_RxSockets[IPV4] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
    {
        Stop();
        return false;
    }
    sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET; 
    sll.sll_ifindex = if_nametoindex(m_IfName.c_str());
    sll.sll_protocol = htons(ETH_P_ARP);
    if(bind(m_RxSockets[IPV4], (sockaddr*)&sll , sizeof(sll)) == -1)
    {
        Stop();
        return false;
    }

    if((m_RxSockets[IPV6] = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_IPV6))) < 0)
    {
        Stop();
        return false;
    }
    ifreq ifr;
    memset (&ifr, 0, sizeof (struct ifreq));
    strcpy (ifr.ifr_name, m_IfName.c_str());
    if(ioctl (m_RxSockets[IPV6], SIOCGIFFLAGS, &ifr) == -1)
    {
        Stop();
        return false;
    }
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl (m_RxSockets[IPV6], SIOCSIFFLAGS, &ifr) == -1)
    {
        Stop();
        return false;
    }

    if((m_TxSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        Stop();
        return false;
    }
    m_Running = true;
    XSpoof* self = this;
    m_Queue.PeriodicTask(0, [self](){
        self->DoXSpoof();
        return true;
    });
    return true;
}

void XSpoof::Stop()
{
    if(m_Running == false)
    {
        return;
    }
    memset(m_HWAddr, 0, sizeof(m_HWAddr));
    if(m_RxSockets[IPV6] != -1)
    {
        close(m_RxSockets[IPV6]);
        m_RxSockets[IPV6] = -1;
    }
    if(m_RxSockets[IPV4] != -1)
    {
        close(m_RxSockets[IPV4]);
        m_RxSockets[IPV4] = -1;
    }
    if(m_TxSocket != -1)
    {
        close(m_TxSocket);
        m_TxSocket = -1;
    }
    m_Running = false;
}

XSpoof::XSpoof()
{
    m_RxSockets[IPV4] = -1;
    m_RxSockets[IPV6] = -1;
    m_TxSocket = -1;
    m_Running = false;
}

XSpoof::~XSpoof()
{
    Stop();
}
