#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "garp.h"

int main(int argc, char* argv[]){
    unsigned int ip = 0;
    char ifname[16] = {0};
    unsigned char mac[ETHER_ADDR_LEN] = {0};

    if(argc == 3){
        sscanf(argv[1], "%hhu.%hhu.%hhu.%hhu", ((unsigned char*)&ip), ((unsigned char*)&ip)+1, ((unsigned char*)&ip)+2, ((unsigned char*)&ip)+3);
        strcpy(ifname, argv[2]);
        garp::instance()->send(ip, ifname, GARP_REQ_TYPE);
        garp::instance()->send(ip, ifname, GARP_REP_TYPE);
    }else if(argc == 4){
        sscanf(argv[1], "%hhu.%hhu.%hhu.%hhu", ((unsigned char*)&ip), ((unsigned char*)&ip)+1, ((unsigned char*)&ip)+2, ((unsigned char*)&ip)+3);
        strcpy(ifname, argv[2]);
        sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", mac, mac+1, mac+2, mac+3, mac+4, mac+5);
        garp::instance()->send(ip, ifname, mac, GARP_REQ_TYPE);
        garp::instance()->send(ip, ifname, mac, GARP_REP_TYPE);
    }else{
        printf("Usage : %s IP IF [MAC]\n", argv[0]);
    }
    return 0;
}
