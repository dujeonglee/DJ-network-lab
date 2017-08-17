#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "RouteMonitor.h"

int main(int argc, char* argv[]){
    while(1){
        RouteMonitor::Instance()->MonitorRoutingUpdate();
    }

    return 0;
}
