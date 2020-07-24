#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>

#include "arp.h"

arp*	arp::_instance = 0;

arp* arp::instance(){
    if(_instance){
        return _instance;
    }
    _instance = new arp;
    if(_instance == 0){
        exit(-1);
    }
    return _instance;
}

bool arp::hw_address(const char* const ifname, unsigned char* const hw_address){
    FILE *fp;
    char hw[MAC_ADDR_BUFFER_SIZE]={0};
    char filename[FILE_NAME_SIZE]={0};

    sprintf(filename, "/sys/class/net/%s/address", ifname);
    fp = fopen(filename, "r");
    if(fp == NULL){
        printf("Cannot read mac address from %s\n", filename);
        return false;
    }
    fgets(hw, MAC_ADDR_BUFFER_SIZE, fp);
    fclose(fp);
    if(sscanf(hw, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_address[0], &hw_address[1], &hw_address[2], &hw_address[3], &hw_address[4], &hw_address[5]) != ETHER_ADDR_LEN){
        printf("Cannot read mac address from %s\n", filename);
        return false;
    }
    return true;
}

void arp::print_arp(const char* const buffer) {
    const ether_header* const eth_header = (struct ether_header *)buffer;
    const ether_arp* const arp_header = (struct ether_arp *)(buffer + sizeof(struct ether_header));
    printf("ETH [DST: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx|SRC: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx|TYPE: %04hx]\n", 
            eth_header->ether_dhost[0],
            eth_header->ether_dhost[1],
            eth_header->ether_dhost[2],
            eth_header->ether_dhost[3],
            eth_header->ether_dhost[4],
            eth_header->ether_dhost[5],
            eth_header->ether_shost[0],
            eth_header->ether_shost[1],
            eth_header->ether_shost[2],
            eth_header->ether_shost[3],
            eth_header->ether_shost[4],
            eth_header->ether_shost[5],
            ntohs(eth_header->ether_type));
    printf("ARP [HDR: %04hx|PRO: %04hx|HLN: %02hhx|PLN: %02hhx|OP: %04hx]\n"
            "    [SHA: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx|SPA: %hhu.%hhu.%hhu.%hhu]\n"
            "    [THA: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx|TPA: %hhu.%hhu.%hhu.%hhu]\n",
            ntohs(arp_header->ea_hdr.ar_hrd),
            ntohs(arp_header->ea_hdr.ar_pro),
            arp_header->ea_hdr.ar_hln,
            arp_header->ea_hdr.ar_pln,
            ntohs(arp_header->ea_hdr.ar_op),
            arp_header->arp_sha[0],
            arp_header->arp_sha[1],
            arp_header->arp_sha[2],
            arp_header->arp_sha[3],
            arp_header->arp_sha[4],
            arp_header->arp_sha[5],
            arp_header->arp_spa[0],
            arp_header->arp_spa[1],
            arp_header->arp_spa[2],
            arp_header->arp_spa[3],
            arp_header->arp_tha[0],
            arp_header->arp_tha[1],
            arp_header->arp_tha[2],
            arp_header->arp_tha[3],
            arp_header->arp_tha[4],
            arp_header->arp_tha[5],
            arp_header->arp_tpa[0],
            arp_header->arp_tpa[1],
            arp_header->arp_tpa[2],
            arp_header->arp_tpa[3]);
}

int arp::garp_send(const unsigned int ip, const char* const ifname){
    const unsigned char BCAST_MAC[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const unsigned char ZERO_MAC[ETHER_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char mac[ETHER_ADDR_LEN];

    if(hw_address(ifname, mac) == false){ // Set my mac address for source
        return -1;
    }
    return raw_arp_send(BCAST_MAC, mac, ARPHRD_ETHER, ETH_P_IP, ETHER_ADDR_LEN, IP_ADDR_LEN, ARPOP_REQUEST, mac, ip, ZERO_MAC, ip, ifname);
}

int arp::raw_arp_send(const unsigned char* const eth_dst, 
                    const unsigned char* const eth_src,
                    const unsigned short ar_hrd,
                    const unsigned short ar_pro,
                    const unsigned char ar_hln,
                    const unsigned char ar_pln,
                    const unsigned short ar_op,
                    const unsigned char* const arp_sha,
                    const unsigned int arp_spa,
                    const unsigned char* const arp_tha,
                    const unsigned int arp_tpa,
                    const char* const ifname){
    char packet_buffer[ARP_LEN];
    ether_header* const eth_header = (struct ether_header *)packet_buffer;
    ether_arp* const arp_header = (struct ether_arp *)(packet_buffer + sizeof(struct ether_header));
    sockaddr_ll arp_device;
    int ret = -1;

    memcpy(eth_header->ether_dhost, eth_dst, ETHER_ADDR_LEN);   // Set destination mac.
    memcpy(eth_header->ether_shost, eth_src, ETHER_ADDR_LEN);   // Set source mac.
    eth_header->ether_type = htons(ETH_P_ARP);                  // Set ETHER_TYPE by ETH_P_ARP.

    arp_header->ea_hdr.ar_hrd = htons(ar_hrd);	                //Format of hardware address
    arp_header->ea_hdr.ar_pro = htons(ar_pro);	                //Format of protocol address.
    arp_header->ea_hdr.ar_hln = ar_hln;			                //Length of hardware address.
    arp_header->ea_hdr.ar_pln = ar_pln;			                //Length of protocol address.
    arp_header->ea_hdr.ar_op = htons(ar_op);	                //ARP operation : REQUEST

    memcpy(arp_header->arp_sha, arp_sha, ar_hln);
    memcpy(arp_header->arp_spa, &arp_spa, ar_pln);
    memcpy(arp_header->arp_tha, arp_tha, ar_hln);
    memcpy(arp_header->arp_tpa, &arp_tpa, ar_pln);

    memset(&arp_device, 0, sizeof(arp_device));
    arp_device.sll_ifindex = if_nametoindex(ifname); //Interface number
    arp_device.sll_family = AF_PACKET;
    memcpy(arp_device.sll_addr, eth_header->ether_shost, ETHER_ADDR_LEN); //Physical layer address
    arp_device.sll_halen = htons(ETHER_ADDR_LEN); //Length of address

    ret = sendto(_send_socket, (char *) packet_buffer, ARP_LEN, 0, (struct sockaddr *) &arp_device, sizeof(packet_buffer));
    if(ret == sizeof(packet_buffer)){
        print_arp(packet_buffer);
    }
    return ret;
}

arp::arp(){
    _send_socket = -1;
    _send_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(_send_socket == -1){
        exit(-1);
    }
}

arp::~arp(){
    if(_send_socket){
        close(_send_socket);
    }
}
