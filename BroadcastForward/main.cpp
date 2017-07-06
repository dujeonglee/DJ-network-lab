#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "BroadMulticastForward.h"

int main(int argc, char* argv[]){
    BroadMulticastForward::Instance()->SetNetworkInterface(WIRELESS, "enp0s31f6");
    BroadMulticastForward::Instance()->SetNetworkInterface(WIRED, "docker0");
    BroadMulticastForward::Instance()->Start();
    while(1)
    {
        sleep(1);
    }
    return 0;
}
