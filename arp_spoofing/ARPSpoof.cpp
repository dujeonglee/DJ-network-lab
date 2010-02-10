#define DJLEE

#include <unistd.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <linux/ipv6.h>
#include <cstring>
#include <cstdio>

#include "ARPSpoof.h"

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

struct icmpv6hdr
{
    unsigned char icmpv6_type;
    unsigned char icmpv6_code;
    unsigned short int icmpv6_cksum;
    union
    {
        unsigned int data_32[1];
        unsigned short int data_16[2];
        unsigned char data_8[4];
    }
    icmpv6_dataun;
}__attribute__((packed));

struct RouterAdvertisement
{
    unsigned char HopLimit;
    unsigned char Flag;
    unsigned short Lifetime;
    unsigned int ReachableTime;
    unsigned int RetransmissionTime;
}__attribute__((packed));

struct TLV
{
    unsigned char Type;
    unsigned char Length;
    unsigned char Value[1];
}__attribute__((packed));

enum ICMPOptions
{
    Source_Link_Layer_Address = 1,
    Target_Link_Layer_Address,
    Prefix_Information,
    Redirected_Header,
    MTU
}__attribute__((packed));

struct ICMPOptionLinkLayerAddress
{
    unsigned char Type;
    unsigned char Length;
    unsigned char Address[6];
}__attribute__((packed));

struct ICMPOptionPrefixInformation
{
    unsigned char Type;
    unsigned char Length;
    unsigned char PrefixLength;
    unsigned char Flag;
    unsigned int ValidLifetime;
    unsigned int PreferredLifetime;
    unsigned int Reserved;
    unsigned char Prefix[16];
}__attribute__((packed));


ARPSpoof* ARPSpoof::g_Instance = new ARPSpoof();

ARPSpoof* ARPSpoof::Instance()
{
    return g_Instance;
}

bool ARPSpoof::HWAddress(const char* const ifname, unsigned char* const hw_address)
{
    FILE *file;
    char hw[MAC_ADDR_BUFFER_SIZE]={0};
    char filename[FILE_NAME_SIZE]={0};
    sprintf(filename, "/sys/class/net/%s/address", ifname);
    file = fopen(filename, "r");
    if(file == NULL)
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


void ARPSpoof::DoARPSpoof(const char *ifname, const char *filename)
{
    unsigned char HWAddr[ETHER_ADDR_LEN] = {0};
    ether_header* const RxEthHdr = (ether_header*)m_RxBuffer;
    ether_arp* const RxARPHdr= (ether_arp*)(m_RxBuffer+sizeof(ether_header));
    ipv6hdr* const IPv6Hdr = (ipv6hdr*)(m_RxBuffer+sizeof(ether_header));
    icmpv6hdr* const ICMPv6Hdr = (icmpv6hdr*)(m_RxBuffer+sizeof(ether_header)+sizeof(ipv6hdr));
    ether_header* const TxEthHdr = (ether_header *)m_TxBuffer;
    ether_arp* const TxARPHdr = (ether_arp *)(m_TxBuffer + sizeof(ether_header));

    if(ifname == nullptr)
    {
        return;
    }

    while(HWAddress(ifname, HWAddr) == false);
    while(setsockopt(m_RxSockets[IPV4], SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) != 0);
    while(setsockopt(m_RxSockets[IPV6], SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) != 0);
    
    timeval rx_to = {1, 0};
    int MaxFD = -1;
    fd_set ReadFD;
    FD_ZERO(&ReadFD);
    for(unsigned int i = 0 ; i < m_RxSockets.size() ; i++)
    {
        FD_SET(m_RxSockets[i], &ReadFD);
        if(m_RxSockets[i] > MaxFD)
        {
            MaxFD = m_RxSockets[i];
        }
    }
    while(1)
    {
        fd_set AllFD = ReadFD;
        const int state = select(MaxFD + 1 , &AllFD, NULL, NULL, &rx_to);
        if(state <= 0)
        {
            continue;
        }
        for(unsigned int i = 0 ; i < m_RxSockets.size() ; i++)
        {
            if(FD_ISSET(m_RxSockets[IPV4], &AllFD))
            {
                int received_bytes;
                int sent_bytes;
                sockaddr_ll ifaddr;
                memset(m_RxBuffer, 0x00, ARP_LEN);// Initialize the rx buffer.
                received_bytes = read(m_RxSockets[0], m_RxBuffer, ARP_LEN);// Receive a packet.
                if(received_bytes <= 0)
                {
                    continue;
                }
                continue;
                // make reply packet;
                // ethernet header
                memcpy(TxEthHdr->ether_dhost, RxEthHdr->ether_shost, ETHER_ADDR_LEN);// set destination mac address of reply packet with the source mac address of the request packet.
                memcpy(TxEthHdr->ether_shost, HWAddr, ETHER_ADDR_LEN);
                TxEthHdr->ether_type = htons(ETH_P_ARP);
                // arp header
                TxARPHdr->ea_hdr.ar_hrd = htons(ARPHRD_ETHER); //Format of hardware address
                TxARPHdr->ea_hdr.ar_pro = htons(ETH_P_IP);  //Format of protocol address.
                TxARPHdr->ea_hdr.ar_hln = ETHER_ADDR_LEN; //Length of hardware address.
                TxARPHdr->ea_hdr.ar_pln = IP_ADDR_LEN; //Length of protocol address.
                TxARPHdr->ea_hdr.ar_op = htons(ARPOP_REPLY); //ARP operation : REPLY
                memcpy(TxARPHdr->arp_sha, HWAddr, ETHER_ADDR_LEN);// set source mac address of the reply packet with mac address of this machine.
                memcpy(TxARPHdr->arp_spa, RxARPHdr->arp_tpa, IP_ADDR_LEN);// set source IP address of the reply packet with the target IP address of the request packet.
                memcpy(TxARPHdr->arp_tha, RxEthHdr->ether_shost, ETHER_ADDR_LEN);// set target mac address with the source mac address of the request packet.
                memcpy(TxARPHdr->arp_tpa, RxARPHdr->arp_spa, IP_ADDR_LEN);// set target IP address of the reply packet with the source IP address of the request packet.
                // sockaddr_ll
                memset(&ifaddr, 0, sizeof(ifaddr));
                ifaddr.sll_ifindex = if_nametoindex(ifname); //Interface number
                ifaddr.sll_family = AF_PACKET;
                memcpy(ifaddr.sll_addr, HWAddr, ETHER_ADDR_LEN); //Physical layer address
                ifaddr.sll_halen = htons(ETHER_ADDR_LEN); //Length of address
                #if 0
                sent_bytes = sendto(m_TxSocket, m_TxBuffer, ARP_LEN, 0, (struct sockaddr *) &ifaddr, sizeof(ifaddr));
                #else
                printf("Not send\n");
                sent_bytes = ARP_LEN;
                #endif
                if(sent_bytes == ARP_LEN)
                {
                    printf("%u Sent ARP reply for %hhu.%hhu.%hhu.%hhu to %hhu.%hhu.%hhu.%hhu\n", 
                        sent_bytes,
                        RxARPHdr->arp_tpa[0], 
                        RxARPHdr->arp_tpa[1], 
                        RxARPHdr->arp_tpa[2], 
                        RxARPHdr->arp_tpa[3],
                        RxARPHdr->arp_spa[0], 
                        RxARPHdr->arp_spa[1], 
                        RxARPHdr->arp_spa[2], 
                        RxARPHdr->arp_spa[3]);
                }
            }
            if(FD_ISSET(m_RxSockets[IPV6], &AllFD))
            {
                int received_bytes/*, sent_bytes*/;
                //sockaddr_ll ifaddr;
                memset(m_RxBuffer, 0x00, ARP_LEN);// Initialize the rx buffer.
                received_bytes = read(m_RxSockets[1], m_RxBuffer, sizeof(m_RxBuffer));// Receive a packet.
                if(received_bytes <= 0)
                {
                    continue;
                }
                if(IPv6Hdr->nexthdr != 0x3A)
                {
                    continue;
                }
                if(ICMPv6Hdr->icmpv6_type == 133)
                {
                    printf("Router Solicitation\n");
                }
                else if(ICMPv6Hdr->icmpv6_type == 134)
                {
                    int parsingposition = 0;
                    printf("Router Advertisement\n");
                    printf("ICMP Type %hhu\n", ICMPv6Hdr->icmpv6_type);
                    printf("ICMP Code %hhu\n", ICMPv6Hdr->icmpv6_code);
                    printf("ICMP CKSUM %hu\n", ICMPv6Hdr->icmpv6_cksum);
                    RouterAdvertisement* payload = (RouterAdvertisement*)ICMPv6Hdr->icmpv6_dataun.data_8;
                    printf("Hoplimit %hhu\n", payload->HopLimit);
                    printf("Flag %hhx\n", payload->Flag);
                    printf("Lifetime %hu s\n", ntohs(payload->Lifetime));
                    printf("ReachableTime %u ms\n", ntohl(payload->ReachableTime));
                    printf("RetransmissionTime %u ms\n", ntohl(payload->RetransmissionTime));
                    parsingposition += 16;
                    while(((unsigned char*)ICMPv6Hdr + parsingposition) < ((unsigned char*)m_RxBuffer + received_bytes))
                    {
                        TLV* tlv = (TLV*)((unsigned char*)ICMPv6Hdr + parsingposition);
                        printf("Type: %hhu\n", tlv->Type);
                        parsingposition += tlv->Length*8;
                    }
                }
                else if(ICMPv6Hdr->icmpv6_type == 135)
                {
                    printf("Neighbor Solicitation\n");
                }
                else if(ICMPv6Hdr->icmpv6_type == 136)
                {
                    printf("Neighbor Advertisement\n");
                }
            }
        }
    }
}

ARPSpoof::ARPSpoof()
{
    int sock;
    while((sock = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP))) < 0);
    m_RxSockets.push_back(sock);
    while((sock = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_IPV6))) < 0);
    m_RxSockets.push_back(sock);
    while((m_TxSocket = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ALL))) < 0);
}

ARPSpoof::~ARPSpoof()
{
    for(unsigned int i = 0 ; i < m_RxSockets.size() ; i++)
    {
        close(m_RxSockets[i]);
    }
    close(m_TxSocket);
}
