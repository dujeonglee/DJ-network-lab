#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "route_monitor.h"

int main(int argc, char* argv[]){
    while(1){
        route_monitor::instance()->waiting_for_routing_change();
    }

    return 0;
}
