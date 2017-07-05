#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "BroadcastForward.h"

int main(int argc, char* argv[]){
    BroadcastForward::Instance()->Forward((argc > 1?std::string(argv[1]):std::string("")));
    while(1);
    return 0;
}
