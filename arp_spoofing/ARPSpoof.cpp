#define DJLEE

#include <unistd.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include <cstring>
#include <cstdio>
#include <cstdint>

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

////////////////////////////// Header Formats
// IPv6 Header
struct IPv6Header {
	uint32_t            Version4_Priority8_Flowlabel20;
	uint16_t            PayloadLenth;
	uint8_t             NextHeader;
	uint8_t             HopLimit;
	uint8_t             SourceAddress[16];
	uint8_t             DestinationAddress[16];
}__attribute__((packed));
// ICMPv6 Header
struct ICMPv6Header
{
    uint8_t         Type;
    uint8_t         Code;
    uint16_t        Checksum;
    union
    {
        uint32_t    Data32[1];
        uint16_t    Data16[2];
        uint8_t     Data8[4];
    }
    Payload;
}__attribute__((packed));
// ICMPv6 uint32_t
//
struct RouterSolicitation
{
    uint32_t Reserved;
}__attribute__((packed));

struct RouterAdvertisement
{
    uint8_t HopLimit;
    uint8_t M1_O1_Reserved6;
    uint16_t RouterLifetime;
    uint32_t ReachableTime;
    uint32_t RetransmissionTime;
}__attribute__((packed));

struct NeighborSolicitation
{
    uint32_t Reserved;
    uint8_t TargetAddress[16];
}__attribute__((packed));

struct NeighborAdvertisement
{
    uint32_t R1_S1_O1_Reserved29;
    uint8_t TargetAddress[16];
}__attribute__((packed));

enum ICMPOptions : uint8_t
{
    Source_Link_Layer_Address = 1,
    Target_Link_Layer_Address,
    Prefix_Information,
    Redirected_Header,
    MTU
};

struct ICMPOptionTLV
{
    ICMPOptions Type;
    uint8_t     Length;
    uint8_t     Value[1];
}__attribute__((packed));

struct ICMPOptionLinkLayerAddress
{
    ICMPOptions Type;
    uint8_t     Length;
    uint8_t     Address[6];
}__attribute__((packed));

struct ICMPOptionPrefixInformation
{
    ICMPOptions Type;
    uint8_t     Length;
    uint8_t     PrefixLength;
    uint8_t     M1_O1_Reserved6;
    uint32_t    ValidLifetime;
    uint32_t    PreferredLifetime;
    uint32_t    Reserved;
    uint8_t     Prefix[16];
}__attribute__((packed));

struct ICMPOptionRedirectedHeader
{
    ICMPOptions Type;
    uint8_t     Length;
    uint16_t    Reserved_1;
    uint32_t    Reserved_2;
    IPv6Header  IPv6HeaderPayload;
}__attribute__((packed));

struct ICMPOptionMTU
{
    ICMPOptions Type;
    uint8_t     Length;
    uint16_t    Reserved;
    uint32_t    MTU;
}__attribute__((packed));

ARPSpoof* ARPSpoof::g_Instance = new ARPSpoof();

ARPSpoof* ARPSpoof::Instance()
{
    return g_Instance;
}

bool ARPSpoof::HWAddress(const char* const ifname, uint8_t* const hw_address)
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
    uint8_t HWAddr[ETHER_ADDR_LEN] = {0};
    ether_header* const RxEthHdr = (ether_header*)m_RxBuffer;
    ether_arp* const RxARPHdr= (ether_arp*)(m_RxBuffer+sizeof(ether_header));
    IPv6Header* const IPv6Hdr = (IPv6Header*)(m_RxBuffer+sizeof(ether_header));
    ICMPv6Header* const ICMPv6Hdr = (ICMPv6Header*)(m_RxBuffer+sizeof(ether_header)+sizeof(IPv6Header));
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
    for(uint32_t i = 0 ; i < m_RxSockets.size() ; i++)
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
        for(uint32_t i = 0 ; i < m_RxSockets.size() ; i++)
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
                if(IPv6Hdr->NextHeader != 0x3A)
                {
                    continue;
                }
                if(ICMPv6Hdr->Type == 133)
                {
                    int parsingposition = 0;
                    printf("============================\n");
                    printf("IP SRC: ");
                    for(uint32_t i = 0 ; i < 16 ; i++)
                    {
                        printf("%02hhx", IPv6Hdr->SourceAddress[i]);
                        if(i%2 == 1 && i != 15)
                        {
                            printf(":");
                        }
                    }
                    printf("\n");
                    printf("IP DST: ");
                    for(uint32_t i = 0 ; i < 16 ; i++)
                    {
                        printf("%02hhx", IPv6Hdr->DestinationAddress[i]);
                        if(i%2 == 1 && i != 15)
                        {
                            printf(":");
                        }
                    }
                    printf("\n");
                    printf("Router Solicitation\n");
                    printf("ICMP Type %hhu\n", ICMPv6Hdr->Type);
                    printf("ICMP Code %hhu\n", ICMPv6Hdr->Code);
                    printf("ICMP CKSUM %hu\n", ICMPv6Hdr->Checksum);
                    RouterSolicitation* payload = (RouterSolicitation*)ICMPv6Hdr->Payload.Data8;
                    printf("-Reserved %x\n", ntohl(payload->Reserved));
                    parsingposition += 8;
                    while(((uint8_t*)ICMPv6Hdr + parsingposition) < ((uint8_t*)m_RxBuffer + received_bytes))
                    {
                        ICMPOptionTLV* tlv = (ICMPOptionTLV*)((uint8_t*)ICMPv6Hdr + parsingposition);
                        if(tlv->Type == Source_Link_Layer_Address)
                        {
                            ICMPOptionLinkLayerAddress* const option = (ICMPOptionLinkLayerAddress*)tlv;
                            printf("--SourceLinkLayerAddress: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", 
                                option->Address[0],
                                option->Address[1],
                                option->Address[2],
                                option->Address[3],
                                option->Address[4],
                                option->Address[5]);
                        }
                        else if(tlv->Type == Target_Link_Layer_Address)
                        {
                            ICMPOptionLinkLayerAddress* const option = (ICMPOptionLinkLayerAddress*)tlv;
                            printf("--TargetLinkLayerAddress: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", 
                                option->Address[0],
                                option->Address[1],
                                option->Address[2],
                                option->Address[3],
                                option->Address[4],
                                option->Address[5]);
                        }
                        else if(tlv->Type == Prefix_Information)
                        {
                            ICMPOptionPrefixInformation* const option = (ICMPOptionPrefixInformation*)tlv;
                            printf("--PrefixInformation\n");
                            printf("----PrefixLength %hhu\n", option->PrefixLength);
                            printf("----MOReserved %hhx\n", option->M1_O1_Reserved6);
                            printf("----ValidLifetime %u\n", ntohl(option->ValidLifetime));
                            printf("----PreferredLifetime %u\n", ntohl(option->PreferredLifetime));
                            printf("----Reserved %u\n", ntohl(option->Reserved));
                            printf("----Prefix ");
                            for(uint8_t i = 0 ; i < 16 ; i++)
                            {
                                printf("%02hhx", option->Prefix[i]);
                                if(i%2 == 1 && i != 15)
                                {
                                    printf(":");
                                }
                            }
                            printf("\n");
                        }
                        else if(tlv->Type == Redirected_Header)
                        {
                            printf("--RedirectedHeader\n");
                        }
                        else if(tlv->Type == MTU)
                        {
                            ICMPOptionMTU* const option = (ICMPOptionMTU*)tlv;
                            printf("--MTU : %u\n", ntohl(option->MTU));
                        }
                        parsingposition += tlv->Length*8;
                    }
                }
                else if(ICMPv6Hdr->Type == 134)
                {
                    int parsingposition = 0;
                    printf("============================\n");
                    printf("IP SRC: ");
                    for(uint32_t i = 0 ; i < 16 ; i++)
                    {
                        printf("%02hhx", IPv6Hdr->SourceAddress[i]);
                        if(i%2 == 1 && i != 15)
                        {
                            printf(":");
                        }
                    }
                    printf("\n");
                    printf("IP DST: ");
                    for(uint32_t i = 0 ; i < 16 ; i++)
                    {
                        printf("%02hhx", IPv6Hdr->DestinationAddress[i]);
                        if(i%2 == 1 && i != 15)
                        {
                            printf(":");
                        }
                    }
                    printf("\n");
                    printf("Router Advertisement\n");
                    printf("ICMP Type %hhu\n", ICMPv6Hdr->Type);
                    printf("ICMP Code %hhu\n", ICMPv6Hdr->Code);
                    printf("ICMP CKSUM %hu\n", ICMPv6Hdr->Checksum);
                    RouterAdvertisement* payload = (RouterAdvertisement*)ICMPv6Hdr->Payload.Data8;
                    printf("-Hoplimit %hhu\n", payload->HopLimit);
                    printf("-MOReserved %hhx\n", payload->M1_O1_Reserved6);
                    printf("-Lifetime %hu s\n", ntohs(payload->RouterLifetime));
                    printf("-ReachableTime %u ms\n", ntohl(payload->ReachableTime));
                    printf("-RetransmissionTime %u ms\n", ntohl(payload->RetransmissionTime));
                    parsingposition += 16;
                    while(((uint8_t*)ICMPv6Hdr + parsingposition) < ((uint8_t*)m_RxBuffer + received_bytes))
                    {
                        ICMPOptionTLV* tlv = (ICMPOptionTLV*)((uint8_t*)ICMPv6Hdr + parsingposition);
                        if(tlv->Type == Source_Link_Layer_Address)
                        {
                            ICMPOptionLinkLayerAddress* const option = (ICMPOptionLinkLayerAddress*)tlv;
                            printf("--SourceLinkLayerAddress: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", 
                                option->Address[0],
                                option->Address[1],
                                option->Address[2],
                                option->Address[3],
                                option->Address[4],
                                option->Address[5]);
                        }
                        else if(tlv->Type == Target_Link_Layer_Address)
                        {
                            ICMPOptionLinkLayerAddress* const option = (ICMPOptionLinkLayerAddress*)tlv;
                            printf("--TargetLinkLayerAddress: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", 
                                option->Address[0],
                                option->Address[1],
                                option->Address[2],
                                option->Address[3],
                                option->Address[4],
                                option->Address[5]);
                        }
                        else if(tlv->Type == Prefix_Information)
                        {
                            ICMPOptionPrefixInformation* const option = (ICMPOptionPrefixInformation*)tlv;
                            printf("--PrefixInformation\n");
                            printf("----PrefixLength %hhu\n", option->PrefixLength);
                            printf("----MOReserved %hhx\n", option->M1_O1_Reserved6);
                            printf("----ValidLifetime %u\n", ntohl(option->ValidLifetime));
                            printf("----PreferredLifetime %u\n", ntohl(option->PreferredLifetime));
                            printf("----Reserved %u\n", ntohl(option->Reserved));
                            printf("----Prefix ");
                            for(uint8_t i = 0 ; i < 16 ; i++)
                            {
                                printf("%02hhx", option->Prefix[i]);
                                if(i%2 == 1 && i != 15)
                                {
                                    printf(":");
                                }
                            }
                            printf("\n");
                        }
                        else if(tlv->Type == Redirected_Header)
                        {
                            printf("--RedirectedHeader\n");
                        }
                        else if(tlv->Type == MTU)
                        {
                            ICMPOptionMTU* const option = (ICMPOptionMTU*)tlv;
                            printf("--MTU : %u\n", ntohl(option->MTU));
                        }
                        parsingposition += tlv->Length*8;
                    }
                }
                else if(ICMPv6Hdr->Type == 135)
                {
                    int parsingposition = 0;
                    printf("============================\n");
                    printf("IP SRC: ");
                    for(uint32_t i = 0 ; i < 16 ; i++)
                    {
                        printf("%02hhx", IPv6Hdr->SourceAddress[i]);
                        if(i%2 == 1 && i != 15)
                        {
                            printf(":");
                        }
                    }
                    printf("\n");
                    printf("IP DST: ");
                    for(uint32_t i = 0 ; i < 16 ; i++)
                    {
                        printf("%02hhx", IPv6Hdr->DestinationAddress[i]);
                        if(i%2 == 1 && i != 15)
                        {
                            printf(":");
                        }
                    }
                    printf("\n");
                    printf("Neighbor Solicitation\n");
                    printf("ICMP Type %hhu\n", ICMPv6Hdr->Type);
                    printf("ICMP Code %hhu\n", ICMPv6Hdr->Code);
                    printf("ICMP CKSUM %hu\n", ICMPv6Hdr->Checksum);
                    NeighborSolicitation* payload = (NeighborSolicitation*)ICMPv6Hdr->Payload.Data8;
                    printf("-Reserved %x\n", ntohl(payload->Reserved));
                    printf("-TargetAddress ");
                    for(uint32_t i = 0 ; i < 16 ; i++)
                    {
                        printf("%02hhx", payload->TargetAddress[i]);
                        if(i%2 == 1 && i != 15)
                        {
                            printf(":");
                        }
                    }
                    printf("\n");
                    parsingposition += 24;
                    while(((uint8_t*)ICMPv6Hdr + parsingposition) < ((uint8_t*)m_RxBuffer + received_bytes))
                    {
                        ICMPOptionTLV* tlv = (ICMPOptionTLV*)((uint8_t*)ICMPv6Hdr + parsingposition);
                        if(tlv->Type == Source_Link_Layer_Address)
                        {
                            ICMPOptionLinkLayerAddress* const option = (ICMPOptionLinkLayerAddress*)tlv;
                            printf("--SourceLinkLayerAddress: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", 
                                option->Address[0],
                                option->Address[1],
                                option->Address[2],
                                option->Address[3],
                                option->Address[4],
                                option->Address[5]);
                        }
                        else if(tlv->Type == Target_Link_Layer_Address)
                        {
                            ICMPOptionLinkLayerAddress* const option = (ICMPOptionLinkLayerAddress*)tlv;
                            printf("--TargetLinkLayerAddress: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", 
                                option->Address[0],
                                option->Address[1],
                                option->Address[2],
                                option->Address[3],
                                option->Address[4],
                                option->Address[5]);
                        }
                        else if(tlv->Type == Prefix_Information)
                        {
                            ICMPOptionPrefixInformation* const option = (ICMPOptionPrefixInformation*)tlv;
                            printf("--PrefixInformation\n");
                            printf("----PrefixLength %hhu\n", option->PrefixLength);
                            printf("----MOReserved %hhx\n", option->M1_O1_Reserved6);
                            printf("----ValidLifetime %u\n", ntohl(option->ValidLifetime));
                            printf("----PreferredLifetime %u\n", ntohl(option->PreferredLifetime));
                            printf("----Reserved %u\n", ntohl(option->Reserved));
                            printf("----Prefix ");
                            for(uint8_t i = 0 ; i < 16 ; i++)
                            {
                                printf("%02hhx", option->Prefix[i]);
                                if(i%2 == 1 && i != 15)
                                {
                                    printf(":");
                                }
                            }
                            printf("\n");
                        }
                        else if(tlv->Type == Redirected_Header)
                        {
                            printf("--RedirectedHeader\n");
                        }
                        else if(tlv->Type == MTU)
                        {
                            ICMPOptionMTU* const option = (ICMPOptionMTU*)tlv;
                            printf("--MTU : %u\n", ntohl(option->MTU));
                        }
                        parsingposition += tlv->Length*8;
                    }
                }
                else if(ICMPv6Hdr->Type == 136)
                {
                    int parsingposition = 0;
                    printf("============================\n");
                    printf("IP SRC: ");
                    for(uint32_t i = 0 ; i < 16 ; i++)
                    {
                        printf("%02hhx", IPv6Hdr->SourceAddress[i]);
                        if(i%2 == 1 && i != 15)
                        {
                            printf(":");
                        }
                    }
                    printf("\n");
                    printf("IP DST: ");
                    for(uint32_t i = 0 ; i < 16 ; i++)
                    {
                        printf("%02hhx", IPv6Hdr->DestinationAddress[i]);
                        if(i%2 == 1 && i != 15)
                        {
                            printf(":");
                        }
                    }
                    printf("\n");
                    printf("Neighbor Advertisement\n");
                    printf("ICMP Type %hhu\n", ICMPv6Hdr->Type);
                    printf("ICMP Code %hhu\n", ICMPv6Hdr->Code);
                    printf("ICMP CKSUM %hu\n", ICMPv6Hdr->Checksum);
                    NeighborAdvertisement* payload = (NeighborAdvertisement*)ICMPv6Hdr->Payload.Data8;
                    printf("-Reserved %x\n", ntohl(payload->R1_S1_O1_Reserved29));
                    printf("-TargetAddress ");
                    for(uint32_t i = 0 ; i < 16 ; i++)
                    {
                        printf("%02hhx", payload->TargetAddress[i]);
                        if(i%2 == 1 && i != 15)
                        {
                            printf(":");
                        }
                    }
                    printf("\n");
                    parsingposition += 24;
                    while(((uint8_t*)ICMPv6Hdr + parsingposition) < ((uint8_t*)m_RxBuffer + received_bytes))
                    {
                        ICMPOptionTLV* tlv = (ICMPOptionTLV*)((uint8_t*)ICMPv6Hdr + parsingposition);
                        if(tlv->Type == Source_Link_Layer_Address)
                        {
                            ICMPOptionLinkLayerAddress* const option = (ICMPOptionLinkLayerAddress*)tlv;
                            printf("--SourceLinkLayerAddress: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", 
                                option->Address[0],
                                option->Address[1],
                                option->Address[2],
                                option->Address[3],
                                option->Address[4],
                                option->Address[5]);
                        }
                        else if(tlv->Type == Target_Link_Layer_Address)
                        {
                            ICMPOptionLinkLayerAddress* const option = (ICMPOptionLinkLayerAddress*)tlv;
                            printf("--TargetLinkLayerAddress: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", 
                                option->Address[0],
                                option->Address[1],
                                option->Address[2],
                                option->Address[3],
                                option->Address[4],
                                option->Address[5]);
                        }
                        else if(tlv->Type == Prefix_Information)
                        {
                            ICMPOptionPrefixInformation* const option = (ICMPOptionPrefixInformation*)tlv;
                            printf("--PrefixInformation\n");
                            printf("----PrefixLength %hhu\n", option->PrefixLength);
                            printf("----MOReserved %hhx\n", option->M1_O1_Reserved6);
                            printf("----ValidLifetime %u\n", ntohl(option->ValidLifetime));
                            printf("----PreferredLifetime %u\n", ntohl(option->PreferredLifetime));
                            printf("----Reserved %u\n", ntohl(option->Reserved));
                            printf("----Prefix ");
                            for(uint8_t i = 0 ; i < 16 ; i++)
                            {
                                printf("%02hhx", option->Prefix[i]);
                                if(i%2 == 1 && i != 15)
                                {
                                    printf(":");
                                }
                            }
                            printf("\n");
                        }
                        else if(tlv->Type == Redirected_Header)
                        {
                            printf("--RedirectedHeader\n");
                        }
                        else if(tlv->Type == MTU)
                        {
                            ICMPOptionMTU* const option = (ICMPOptionMTU*)tlv;
                            printf("--MTU : %u\n", ntohl(option->MTU));
                        }
                        parsingposition += tlv->Length*8;
                    }
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
    for(uint32_t i = 0 ; i < m_RxSockets.size() ; i++)
    {
        close(m_RxSockets[i]);
    }
    close(m_TxSocket);
}
