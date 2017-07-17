#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "BroadMulticastForward.h"

int main(int argc, char* argv[]){
    BroadMulticastForward::Instance()->SetNetworkInterface(WIRELESS, argv[1]);
    if(argc == 3)
        BroadMulticastForward::Instance()->SetNetworkInterface(WIRED, argv[2]);
    BroadMulticastForward::Instance()->Start();
    while(1)
    {
        sleep(1);
    }
    return 0;
}
