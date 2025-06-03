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
            printf("enter the encryption key, both parties need the same key (16 characters long).\n");
            scanf("%16s", key);
            if(strlen(key) != 16){
                printf("key was not long enough\n");
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
                do {
                    printf("input your server IP (ex = 127.0.0.1 -> localhost), leave empty for localhost.\n");
                    fgets(serverIpAddress, sizeof(serverIpAddress), stdin);
                    // Remove newline if present
                    size_t ipLen = strlen(serverIpAddress);
                    if (ipLen > 0 && serverIpAddress[ipLen-1] == '\n') {
                        serverIpAddress[ipLen-1] = '\0';
                        ipLen--;
                    }
                    if (ipLen == 0) {
                        strcpy(serverIpAddress, "127.0.0.1");
                        ipLen = strlen(serverIpAddress);
                    }
                    if (ipLen < 7 || ipLen > 15) {
                        printf("Invalid IP length. Please enter a valid IPv4 address.\n");
                    }
                } while (strlen(serverIpAddress) < 7 || strlen(serverIpAddress) > 15);
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