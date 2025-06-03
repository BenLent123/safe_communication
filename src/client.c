#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <arpa/inet.h>
#include "common.h"
#define MAX_LENGTH 64

int setup(int *socketfd, struct sockaddr_in *server_addr, char ipAddress[16], int port){
    
    *socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*socketfd < 0) {
        perror("socket creation failed");
        return -1;
    }

    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(port); // Replace with your port

    const char *ip = (ipAddress && strlen(ipAddress)>0) ? ipAddress : "127.0.0.1";

    if (inet_pton(AF_INET, ip, &server_addr->sin_addr) <= 0 ){ // Replace with your server IP or if locally run its fine to have localhost
        perror("invalid ip address");
        close(*socketfd);
        return -1;
    } 

    if (connect(*socketfd, (struct sockaddr*)server_addr, sizeof(*server_addr)) < 0) {
        perror("connect failed");
        close(*socketfd);
        return -1;
    }

    return 0;
}

int ClientMainFunc (char ipAdress[16], int port, AES_KEY *encrpytionKey,AES_KEY *decryptionKey) {
    int socketfd;
    int pollResult;
    struct sockaddr_in server_addr;
    char readTextBuffer[MAX_LENGTH];
    char sendTextBuffer[MAX_LENGTH];

    if(setup(&socketfd, &server_addr, ipAdress, port) != 0){
        fprintf(stderr,"error in setup\n");
        return -1;
    }

    while(1){
        pollResult = CommunicationPoll(5000, socketfd); // 5 seconds timeout
        if (pollResult == -1) {
            break;
        }
        Communicate(socketfd, readTextBuffer, sendTextBuffer, pollResult, encrpytionKey, decryptionKey);
        if(strcmp(sendTextBuffer, "goodbye") == 0){
            break;
        }
    }
    close(socketfd);
    return 0;
}