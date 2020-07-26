#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread>         // std::this_thread::sleep_for
#include <chrono>
#include "arp.h"

unsigned char eth_dst[ETHER_ADDR_LEN]; 
unsigned char eth_src[ETHER_ADDR_LEN];

unsigned short ar_hrd;
unsigned short ar_pro;
unsigned char ar_hln;
unsigned char ar_pln;
unsigned short ar_op;
unsigned char arp_sha[ETHER_ADDR_LEN];
unsigned int arp_spa;
unsigned char arp_tha[ETHER_ADDR_LEN];
unsigned int arp_tpa;

char ifname[16] = {0};

int main(int argc, char* argv[]){
    if(argc == 3){
        sscanf(argv[1], "%hhu.%hhu.%hhu.%hhu", ((unsigned char*)&arp_tpa), ((unsigned char*)&arp_tpa)+1, ((unsigned char*)&arp_tpa)+2, ((unsigned char*)&arp_tpa)+3);
        strcpy(ifname, argv[2]);

        arp::instance()->start_rcv(ifname);
        while(1) {
            arp::instance()->garp_send(arp_tpa, ifname);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }else if(argc == 13){
        sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", eth_dst, eth_dst+1, eth_dst+2, eth_dst+3, eth_dst+4, eth_dst+5);
        sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", eth_src, eth_src+1, eth_src+2, eth_src+3, eth_src+4, eth_src+5);

        sscanf(argv[3], "%hx", &ar_hrd);
        sscanf(argv[4], "%hx", &ar_pro);
        sscanf(argv[5], "%hhx", &ar_hln);
        sscanf(argv[6], "%hhx", &ar_pln);
        sscanf(argv[7], "%hx", &ar_op);
        sscanf(argv[8], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", arp_sha, arp_sha+1, arp_sha+2, arp_sha+3, arp_sha+4, arp_sha+5);
        sscanf(argv[9], "%hhu.%hhu.%hhu.%hhu", ((unsigned char*)&arp_spa), ((unsigned char*)&arp_spa)+1, ((unsigned char*)&arp_spa)+2, ((unsigned char*)&arp_spa)+3);
        sscanf(argv[10], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", arp_tha, arp_tha+1, arp_tha+2, arp_tha+3, arp_tha+4, arp_tha+5);
        sscanf(argv[11], "%hhu.%hhu.%hhu.%hhu", ((unsigned char*)&arp_tpa), ((unsigned char*)&arp_tpa)+1, ((unsigned char*)&arp_tpa)+2, ((unsigned char*)&arp_tpa)+3);

        strcpy(ifname, argv[12]);

        arp::instance()->start_rcv(ifname);
        while(1) {
            arp::instance()->raw_arp_send(eth_dst, eth_src, ar_hrd, ar_pro, ar_hln, ar_pln, ar_op, arp_sha, arp_spa, arp_tha, arp_tpa, ifname);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }else{
        printf("Usage : %s IP IF\n", argv[0]);
    }
    return 0;
}
