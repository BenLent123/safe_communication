#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "encryption.h"
#include "chathandler.h"

#define MAX_USERNAME_LENGTH 17

int ServerHandler(int port, char *userName){
    int serverfd, clientfd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    char *hello = "Hello from server";
    int maxQueuedClients = 3;
    char peerName[MAX_USERNAME_LENGTH];

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    RSA *rsaServer = NULL;
    BIGNUM *bnServer = NULL;
    RSA *rsaOutServer = NULL;
    char *pubKeyServer = NULL;
    size_t pubKeyLenServer = 0;

    // Create socket file descriptor
    if ((serverfd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to the port
    if (bind(serverfd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(serverfd, maxQueuedClients) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", port);

    // Accept a connection
    if ((clientfd = accept(serverfd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    printf("connection established on %d!(type \"q\" to quit)\n",clientfd);
    
    // generate RSA pub and priv keys
    if (GenerateKey(&rsaServer, &bnServer, &pubKeyServer, &pubKeyLenServer)<0){
        fprintf(stderr, "Key generation failed\n");
        return -1;
    }

    if(ExtractPublicKey(clientfd, &rsaOutServer)<0){
        fprintf(stderr, "Extracting client public key failed\n");
        return -1;
    }
    
    if(SendPublicKey(clientfd, pubKeyLenServer, pubKeyServer) <0){
        fprintf(stderr, "Sending public key failed\n");
        return -1;
    }
    
    if(recv(clientfd, peerName, MAX_USERNAME_LENGTH, 0)<0){
        return -1;
    }
    size_t len = strlen(peerName);
    if (len > 0 && peerName[len-1] == '\n') {
        peerName[len-1] = '\0';
     }
    printf("peer username recieved...\n");

    if(send(clientfd, userName, strlen(userName) + 1, 0)<0){ // +1 to include null terminator
        return -1; 
    } 
    printf("username sent to peer...\n");
    

    ChatLoop(clientfd,rsaOutServer,rsaServer,peerName,userName);


    close(clientfd);
    close(serverfd);
    return 0;
}


int ClientHandler(int serverPort, const char *serverIp, char *userName) {
    int clientSocket = 0;
    struct sockaddr_in serv_addr;
    char *hello = "Hello from client";
    char buffer[1024] = {0};
    char peerName[MAX_USERNAME_LENGTH];

    RSA *rsaClient = NULL;
    BIGNUM *bnClient = NULL;
    RSA *rsaOutClient = NULL;
    char *pubKeyClient = NULL;
    size_t pubKeyLenClient = 0;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(serverPort);

    // generate RSA pub and priv keys
    if (GenerateKey(&rsaClient, &bnClient, &pubKeyClient, &pubKeyLenClient)<0){
        fprintf(stderr, "Key generation failed\n");
        return -1;
    }

    // Create socket
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, serverIp, &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    // Connect to server
    if (connect(clientSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    printf("connection established on %d!(type \"q\" to quit)\n",clientSocket);


    if(SendPublicKey(clientSocket, pubKeyLenClient, pubKeyClient) <0){
        fprintf(stderr, "Sending public key failed\n");
        return -1;
    }
    
    
    if(ExtractPublicKey(clientSocket, &rsaOutClient)<0){
        fprintf(stderr, "Extracting server public key failed\n");
        return -1;
    }
    
    if(send(clientSocket, userName, strlen(userName) + 1, 0)<0){ // +1 to include null terminator
        return -1; 
    } 

    printf("username sent to peer...\n");

    if(recv(clientSocket, peerName, MAX_USERNAME_LENGTH, 0)<0){
        return -1;
    }
    size_t len = strlen(peerName);
    if (len > 0 && peerName[len-1] == '\n') {
        peerName[len-1] = '\0';
    }
    printf("peer username recieved...\n");
    
    ChatLoop(clientSocket,rsaOutClient,rsaClient,peerName,userName);

    close(clientSocket);
    return 0;
}


