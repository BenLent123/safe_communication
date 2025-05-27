#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <arpa/inet.h>
#define MAX_LENGTH 64

int ClientCommunicationPoll(int timeout, int socketfd){
    struct pollfd pfd;
    pfd.fd = socketfd;
    pfd.events = POLLIN | POLLOUT;
    int ret = poll(&pfd, 1, timeout);
    if(ret == -1){
        perror("poll failed\n");
        return -1;
    } else if(ret == 0){
        printf("timeout\n");
    } else {
        if(pfd.revents & POLLIN){
            printf("socket read is available\n");
            return 1;
        }
        if(pfd.revents & POLLOUT){
            printf("socket write is available\n");
            return 2;
        }
    }
    return 0;
}

// decides based on poll if you can write or read
void ClientCommunicate(int socketfd, char readTextBuffer[MAX_LENGTH], char sendTextBuffer[MAX_LENGTH], int pollResult){
    if(pollResult == 1){
        ssize_t bytesReceived = recv(socketfd, readTextBuffer, MAX_LENGTH - 1, 0);
        if (bytesReceived > 0) {
            readTextBuffer[bytesReceived] = '\0'; // Null-terminate for safe printing
            printf("Received: %s\n", readTextBuffer);
        } else if (bytesReceived == 0) {
            printf("Client disconnected.\n");
            // Optionally set a flag or handle cleanup here
            strcpy(sendTextBuffer, "goodbye"); // To break the main loop
        } else {
            perror("recv failed");
        }
    }
    else if(pollResult == 2){
        printf("Enter message to send: ");
        if (fgets(sendTextBuffer, MAX_LENGTH, stdin) != NULL) {
            // Remove newline if present
            size_t len = strlen(sendTextBuffer);
            if (len > 0 && sendTextBuffer[len-1] == '\n') {
                sendTextBuffer[len-1] = '\0';
            }
            send(socketfd, sendTextBuffer, strlen(sendTextBuffer) + 1, 0);
        }
    }
}


int setup(int *socketfd, struct sockaddr_in *server_addr){

    *socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*socketfd < 0) {
        perror("socket creation failed");
        return -1;
    }

    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(12345); // Replace with your port
    inet_pton(AF_INET, "127.0.0.1", &server_addr->sin_addr); // Replace with your server IP

    if (connect(*socketfd, (struct sockaddr*)server_addr, sizeof(*server_addr)) < 0) {
        perror("connect failed");
        close(*socketfd);
        return -1;
    }

    return 0;
}

int ClientMainFunc (char ipAdress[10]) {
    int socketfd;
    int pollResult;
    struct sockaddr_in server_addr;
    char readTextBuffer[MAX_LENGTH];
    char sendTextBuffer[MAX_LENGTH];

    if(setup(&socketfd, &server_addr) != 0){
        fprintf(stderr,"error in setup\n");
        return -1;
    }

    while(1){
        pollResult = ClientCommunicationPoll(5000, socketfd); // 5 seconds timeout
        if (pollResult == -1) {
            break;
        }
        ClientCommunicate(socketfd, readTextBuffer, sendTextBuffer, pollResult);
        if(strcmp(sendTextBuffer, "goodbye") == 0){
            break;
        }
    }
    close(socketfd);
    return 0;
}