#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "sockethandler.h"

int main(int argc, char *argv[]){   
    
    if (argc < 2 ) {

        printf("not enough arguments, type help for layout and valid arguments.\n");

        return -1;
    }
    if(strcmp(argv[1], "help") == 0){

        printf("Usage: %s [\"h\" for hosting)|\"j\" for joining|\"help\" for all commands] [port] [serverIP (IPV4) (only for joining) (\"l\" for localhost)]\n", argv[0]);
        
        return -1;
    }

    if (strcmp(argv[1], "h") == 0) {
        
        if (argc < 4) {
        printf("missing arguments to host, Usage: %s [h] [port] [displayName (16 chars)] \n", argv[0]);
        return -1;
        }

        int port = atoi(argv[2]);
        char *userName = argv[3];

        if (port <= 0) {
            printf("Invalid port number.\n");
            return -1;
        }

        printf("hosting....\n");

        ServerHandler(port, userName);

    } else if (strcmp(argv[1], "j") == 0) {

        if (argc < 5) {
        printf("not enough arguments for joining, Usage: %s [j] [port server is hosting on] [serverIP (IPV4) or \"l\" for localhost] [displayName (16 chars)]\n", argv[0]);
        return -1;
        
    }
        int port = atoi(argv[2]);
        const char *serverIp = argv[3];
        char *userName = argv[4];

        if (port <= 0) {
            printf("Invalid port number.\n");
            return -1;
        }

        if (serverIp == NULL || strlen(serverIp) == 0) {
            printf("Invalid server IP address.\n");
            return -1;
        }

        if(strcmp(serverIp, "l") == 0){
            serverIp = "127.0.0.1";
        }

        // Call the client handler function here
        printf("joining....\n");

        ClientHandler(port, serverIp, userName);
        
    } else {
        printf("Invalid argument, type help for layout and valid arguments.\n");
        return -1;
    }

    return 0;
}