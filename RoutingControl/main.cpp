#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "RouteMonitor.h"
#include "SingleShotTimer.h"

SingleShotTimer<1,1> Queue;

int main(int argc, char* argv[]){
    Queue.PeriodicTask(0, []()->bool{
        RouteMonitor::Instance()->MonitorRoutingUpdate();
        return true;
    });
    while(1);
    return 0;
}
