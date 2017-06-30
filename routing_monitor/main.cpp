#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "RouteMonitor.h"

int main(int argc, char* argv[]){
    while(1){
        route_monitor::instance()->waiting_for_routing_change();
    }

    return 0;
}
