#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ARPSpoof.h"

int main(int argc, char* argv[]){
    ARPSpoof::Instance()->DoARPSpoof((argc > 1?argv[1]:NULL), (argc > 2?argv[2]:NULL));
    return 0;
}
