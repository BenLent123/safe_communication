#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "server.h"
#include "client.h"


int main(int argc, char *argv[]) {
    char cmd;
    char ipAddress[10];
        printf("input your IP (ex = 12.0.2.1)\n");
        scanf(" %s",&ipAddress);
    do {
        printf("host or join? type \"h\" to host and \"j\" to join or \"q\" to quit\n");
        scanf(" %c", &cmd); // The space before %c skips whitespace (including newlines)
        switch(cmd){
            case 'h':
                printf("You chose to host.\n");
                ServerMainFunc();
                break;
            case 'j':
                printf("You chose to join.\n");
                ClientMainFunc(ipAddress);
                break;
            case 'q':
                printf("Quitting...\n");
                break;
            default:
                printf("Invalid input.\n");
                break;
        }
    } while(cmd != 'q'); 

    return 0;
}