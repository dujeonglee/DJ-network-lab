#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>

#include "garp.h"

garp*	garp::_instance = 0;

garp* garp::instance(){
    if(_instance){
        return _instance;
    }
    _instance = new garp;
    if(_instance == 0){
        exit(-1);
    }
    return _instance;
}

bool garp::hw_address(const char* const ifname, unsigned char* const hw_address){
    FILE *fp;
    char hw[MAC_ADDR_BUFFER_SIZE]={0};
    char filename[FILE_NAME_SIZE]={0};

    sprintf(filename, "/sys/class/net/%s/address", ifname);
    fp = fopen(filename, "r");
    if(fp == NULL){
        return false;
    }
    fgets(hw, MAC_ADDR_BUFFER_SIZE, fp);
    fclose(fp);
    if(sscanf(hw, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_address[0], &hw_address[1], &hw_address[2], &hw_address[3], &hw_address[4], &hw_address[5]) != ETHER_ADDR_LEN){
        return false;
    }
    return true;
}

int garp::send(const unsigned int ip, const char* const ifname, const unsigned char type){
    char _gratuitous_packet[ARP_LEN];
    ether_header* const _gratuitous_eth = (struct ether_header *)_gratuitous_packet;
    ether_arp* const _gratuitous_arp = (struct ether_arp *)(_gratuitous_packet + sizeof(struct ether_header));
    sockaddr_ll _gratuitous_device;

    if(type != GARP_REQ_TYPE && type != GARP_REP_TYPE){
        return -1;
    }

    memset(_gratuitous_eth->ether_dhost, 0xff, ETHER_ADDR_LEN);// Set broadcast mac address for destination
    if(hw_address(ifname, _gratuitous_eth->ether_shost) == false){ // Set my mac address for source
        return -1;
    }
    _gratuitous_eth->ether_type = htons(ETH_P_ARP); // Set ethernet type
    memcpy(_gratuitous_arp->arp_sha, _gratuitous_eth->ether_shost, ETHER_ADDR_LEN); //set source host address with my mac address
    memcpy(_gratuitous_arp->arp_spa, &ip, IP_ADDR_LEN);// set source IP address with IP.
    if(type == GARP_REQ_TYPE){
        memset(_gratuitous_arp->arp_tha, 0x00, ETHER_ADDR_LEN);
        memcpy(_gratuitous_arp->arp_tpa, &ip, IP_ADDR_LEN);
    }else if(type == GARP_REP_TYPE){
        memset(_gratuitous_arp->arp_tha, 0xff, ETHER_ADDR_LEN);
        memset(_gratuitous_arp->arp_tpa, 0xff, IP_ADDR_LEN);
    }

    _gratuitous_arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);	//Format of hardware address
    _gratuitous_arp->ea_hdr.ar_pro = htons(ETH_P_IP);		//Format of protocol address.
    _gratuitous_arp->ea_hdr.ar_hln = ETHER_ADDR_LEN;		//Length of hardware address.
    _gratuitous_arp->ea_hdr.ar_pln = IP_ADDR_LEN;		//Length of protocol address.
    if(type == GARP_REQ_TYPE){
        _gratuitous_arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);		//ARP operation : REQUEST
    }else if(type == GARP_REP_TYPE){
        _gratuitous_arp->ea_hdr.ar_op = htons(ARPOP_REPLY);		//ARP operation : REQUEST
    }

    memset(&_gratuitous_device, 0, sizeof(_gratuitous_device));
    _gratuitous_device.sll_ifindex = if_nametoindex(ifname); //Interface number
    _gratuitous_device.sll_family = AF_PACKET;
    memcpy(_gratuitous_device.sll_addr, _gratuitous_eth->ether_shost, ETHER_ADDR_LEN); //Physical layer address
    _gratuitous_device.sll_halen = htons(ETHER_ADDR_LEN); //Length of address

    return sendto(_send_socket, (char *) _gratuitous_eth, ARP_LEN, 0, (struct sockaddr *) &_gratuitous_device, sizeof(_gratuitous_device));
}

int garp::send(const unsigned int ip, const char* const ifname, const unsigned char* const mac, const unsigned char type){
    char _gratuitous_packet[ARP_LEN];
    ether_header* const _gratuitous_eth = (struct ether_header *)_gratuitous_packet;
    ether_arp* const _gratuitous_arp = (struct ether_arp *)(_gratuitous_packet + sizeof(struct ether_header));
    sockaddr_ll _gratuitous_device;

    if(type != GARP_REQ_TYPE && type != GARP_REP_TYPE){
        return -1;
    }

    memset(_gratuitous_eth->ether_dhost, 0xff, ETHER_ADDR_LEN);// Set broadcast mac address for destination.
    memcpy(_gratuitous_eth->ether_shost, mac, ETHER_ADDR_LEN);// Set source mac address with the given mac address.

    _gratuitous_eth->ether_type = htons(ETH_P_ARP);

    memcpy(_gratuitous_arp->arp_sha, _gratuitous_eth->ether_shost, ETHER_ADDR_LEN);
    memcpy(_gratuitous_arp->arp_spa, &ip, IP_ADDR_LEN);
    if(type == GARP_REQ_TYPE){
        memset(_gratuitous_arp->arp_tha, 0x00, ETHER_ADDR_LEN);
        memcpy(_gratuitous_arp->arp_tpa, &ip, IP_ADDR_LEN);
    }else if(type == GARP_REP_TYPE){
        memset(_gratuitous_arp->arp_tha, 0xff, ETHER_ADDR_LEN);
        memset(_gratuitous_arp->arp_tpa, 0xff, IP_ADDR_LEN);
    }

    _gratuitous_arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);	//Format of hardware address
    _gratuitous_arp->ea_hdr.ar_pro = htons(ETH_P_IP);		//Format of protocol address.
    _gratuitous_arp->ea_hdr.ar_hln = ETHER_ADDR_LEN;				//Length of hardware address.
    _gratuitous_arp->ea_hdr.ar_pln = IP_ADDR_LEN;						//Length of protocol address.
    if(type == GARP_REQ_TYPE){
        _gratuitous_arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);		//ARP operation : REQUEST
    }else if(type == GARP_REP_TYPE){
        _gratuitous_arp->ea_hdr.ar_op = htons(ARPOP_REPLY);		//ARP operation : REQUEST
    }

    memset(&_gratuitous_device, 0, sizeof(_gratuitous_device));
    _gratuitous_device.sll_ifindex = if_nametoindex(ifname); //Interface number
    _gratuitous_device.sll_family = AF_PACKET;
    memcpy(_gratuitous_device.sll_addr, _gratuitous_eth->ether_shost, ETHER_ADDR_LEN); //Physical layer address
    _gratuitous_device.sll_halen = htons(ETHER_ADDR_LEN); //Length of address

    return sendto(_send_socket, (char *) _gratuitous_eth, ARP_LEN, 0, (struct sockaddr *) &_gratuitous_device, sizeof(_gratuitous_device));
}

garp::garp(){
    _send_socket = -1;
    _send_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(_send_socket == -1){
        exit(-1);
    }
}

garp::~garp(){
    if(_send_socket){
        close(_send_socket);
    }
}
