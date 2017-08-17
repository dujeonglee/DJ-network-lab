#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "XSpoof.h"

int main(int argc, char* argv[]){
    if(argc != 2)
    {
        printf("sudo %s interface\n", argv[0]);
        return 0;
    }
    XSpoof::Instance()->Start(std::string(argv[1]));
    while(1);
    return 0;
}
