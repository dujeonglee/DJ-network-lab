#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "arp_spoof.h"

int main(int argc, char* argv[]){
    arp_spoof::instance()->do_arp_spoof((argc > 1?argv[1]:NULL), (argc > 2?argv[2]:NULL));
    return 0;
}
