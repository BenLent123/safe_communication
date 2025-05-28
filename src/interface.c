#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "server.h"
#include "client.h"
#include "common.h"


int main(int argc, char *argv[]) {
    char cmd;
    char serverIpAddress[16];
    int serverPort;
        
    do {
        printf("host or join? type \"h\" to host and \"j\" to join or \"q\" to quit\n");
        scanf(" %c", &cmd); // The space before %c skips whitespace (including newlines)
        switch(cmd){
            case 'h':
                printf("You chose to host.\n");
                printf("input a port to use (ex = 8080). \n");
                scanf(" %d",&serverPort);
                ServerMainFunc(serverPort);
                break;
            case 'j':
                printf("You chose to join.\n");
                printf("input your server IP (ex = 127.0.0.1), leave empty for localhost.\n");
                scanf(" %s",&serverIpAddress);
                printf("input your server port (ex = 8080).\n");
                scanf(" %d",&serverPort);
                ClientMainFunc(serverIpAddress, serverPort);
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