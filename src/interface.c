#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/aes.h>
#include "server.h"
#include "client.h"
#include "common.h"


int main(int argc, char *argv[]) {
    AES_KEY encrpytionKey, decryptionKey;
    char cmd;
    char key[17]; // 16 chars + null terminator
    char serverIpAddress[16]; // 15 chars + null
    int serverPort;
        
    do {
        do {
            printf("enter the encryption key, both parties need the same key (16 characters long, only first 16 are taken ).\n");
            scanf("%16s", key);
            if(strlen(key) != 16){
                printf("key was not correct in length - too short\n");
            }
        } while(strlen(key) != 16);
        SetEncryptionKeys((unsigned char*)key, &encrpytionKey, &decryptionKey);
        printf("host or join? type \"h\" to host and \"j\" to join or \"q\" to quit\n");
        scanf(" %c", &cmd); // The space before %c skips whitespace (including newlines)
        switch(cmd){
            case 'h':
                printf("You chose to host.\n");
                printf("input a port to use (ex = 8080). \n");
                scanf(" %d", &serverPort);
                ServerMainFunc(serverPort, &encrpytionKey, &decryptionKey);
                break;
            case 'j':
                printf("You chose to join.\n");
                printf("input your server IP (ex = 127.0.0.1 -> localhost), leave empty for localhost.\n");
                scanf(" %s", serverIpAddress);
                printf("input your server port (ex = 8080).\n");
                scanf(" %d", &serverPort);
                ClientMainFunc(serverIpAddress, serverPort, &encrpytionKey, &decryptionKey);
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