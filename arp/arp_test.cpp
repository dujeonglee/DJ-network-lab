#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "arp.h"

int main(int argc, char* argv[]){
    unsigned int ip = 0;
    char ifname[16] = {0};

    if(argc == 3){
        sscanf(argv[1], "%hhu.%hhu.%hhu.%hhu", ((unsigned char*)&ip), ((unsigned char*)&ip)+1, ((unsigned char*)&ip)+2, ((unsigned char*)&ip)+3);
        strcpy(ifname, argv[2]);
        arp::instance()->garp_send(ip, ifname);
    }else{
        printf("Usage : %s IP IF\n", argv[0]);
    }
    return 0;
}
