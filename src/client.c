#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "encryption.h"
#include "common.h"

#define MAX_LENGTH 64 // length used for max everything (arbitrary)

// setup of sockets and ports and checking for errors
int ClientSetup(int *socketfd, struct sockaddr_in *server_addr, char *ip, int port){
    
    *socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*socketfd < 0) {
        perror("socket creation failed");
        return -1;
    }

    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(port); // Replace with your port


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
    printf("connection established! (type \"q\" to quit)\n");
    return 0;
}

// self explanatory
void ClientCloseEncryption(RSA *rsa, BIGNUM *bn, RSA *rsaOut, char *pubKeyClient) {
    if (pubKeyClient) free(pubKeyClient);
    if (rsa) RSA_free(rsa);
    if (bn) BN_free(bn);
    if (rsaOut) RSA_free(rsaOut);
}

// encryption split in two parts part 1 here so that client has key ready before server and 
// send and recieve happen in the same order with client first then server!
int ClientEncryptionSetupPart1(RSA **rsa, BIGNUM **bn, RSA **rsaOut,char **pubKeyClient,
     size_t *pubKeyClientLen, int clientfd) {
    if (GenerateKeyPair(rsa, bn) < 0) {
        return -1;
    }
    if (ExportPublicKey(*rsa, pubKeyClient, pubKeyClientLen) < 0) {
        return -1;
    }
    return 0;
}
// second part of encryption 
int ClientEncryptionSetupPart2(RSA **rsa, BIGNUM **bn, RSA **rsaOut,char **pubKeyClient,
     size_t *pubKeyClientLen, int clientfd){
    if (SendPublicKey(clientfd, *pubKeyClientLen, *pubKeyClient) < 0) {
        return -1;
    }
    if (ExtractPublicKey(clientfd, rsaOut) < 0) {
        return -1;
    }
    return 0;
}
// function handles passing client username to server aswell as handling \n in username entered in interface.c
int ClientUsernameHandler(char *userName, char *peerName, int socketfd){
    if(send(socketfd, userName, strlen(userName) + 1, 0)<0){ // +1 to include null terminator
        return -1; 
    } //send entered username from interface
    printf("username sent to peer...\n");
    if(recv(socketfd, peerName, MAX_LENGTH, 0)<0){
        return -1;
    } // recieve entered username by server
    size_t len = strlen(peerName);
    if (len > 0 && peerName[len-1] == '\n') {
        peerName[len-1] = '\0';
    } // make sure it has no \n so it does not print wrong
    printf("peer username recieved...\n");
    return 0;
}
// main function
int ClientMainFunc(char *ipAdress, int serverPort, char *userName){
    int socketfd;
    char peerName[MAX_LENGTH];
    struct sockaddr_in server_addr;
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;
    RSA *rsaOut = NULL;
    char *pubKeyClient = NULL;
    size_t pubKeyClientLen = 0;

    if (ClientEncryptionSetupPart1(&rsa, &bn, &rsaOut, &pubKeyClient, &pubKeyClientLen, socketfd) < 0) {
    return -1;
    }

    if(ClientSetup(&socketfd, &server_addr, ipAdress, serverPort) != 0){
        fprintf(stderr,"error in setup\n");
        return -1;
    }

    if (ClientEncryptionSetupPart2(&rsa, &bn, &rsaOut, &pubKeyClient, &pubKeyClientLen, socketfd) < 0) {
        return -1;
    }
    
    if(ClientUsernameHandler(userName,peerName,socketfd)<0){
        return -1;
    };

    ChatLoop(socketfd, rsaOut, rsa, peerName);
        
    close(socketfd);

    ClientCloseEncryption(rsa, bn, rsaOut, pubKeyClient);

    return 0;
}