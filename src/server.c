#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "encryption.h"
#include "chathandler.h"

#define MAX_LENGTH 64

// structure to describe internet socketaddress
typedef struct {
    unsigned long socketAddress; // Internet address
}InetAddressInfo;

// structure to describe internet socket information
typedef struct{
    short inetSocketFamily; // Address family -> short as only 16bit number needed
    unsigned short inetSocketPort; // Port number -> same here but port will always be positive
    InetAddressInfo InetSocketAddress; // Internet address link to the other struct
}InetSocketInfo;


int InitSocket(int *socketfd) {
    // Create a socket via premade sys/socket fuction socket();
    *socketfd = socket(AF_INET, SOCK_STREAM, 0);
    // check of socket created successfully
    if (*socketfd < 0) {
        perror("socket creation failed");
        return -1; // if an error occurs, return -1 and exit the function
    }
    return 0;
}


int ConnectSocket(int socketfd, InetSocketInfo *socketInfo) {

    struct sockaddr_in addr; // creates a structure expected by <netinet/in.h>
    memset(&addr, 0, sizeof(addr)); // setting correct values of socketInfo
    addr.sin_family = socketInfo->inetSocketFamily;
    addr.sin_port = htons(socketInfo->inetSocketPort);
    addr.sin_addr.s_addr = htonl(socketInfo->InetSocketAddress.socketAddress);
    // bind to a socket
    if (bind(socketfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("binding of socket has failed");
        return -1; // return -1 if binding has failed and exit function
    }

    return 0;
}


int ListenForConnection(int socketfd){
// listen for any incoming connection via listen()
    int connectionSuccess = listen(socketfd,SOMAXCONN);
    // check if connection successful or not and return errors accordingly
    if (connectionSuccess<0){
        perror("could not connect to others");
        return -1;
    }

    return 0;
}


int AcceptConnection(int socketfd){
    struct sockaddr_in client_addr; // creates a structure expected by <netinet/in.h>
    socklen_t client_len = sizeof(client_addr); // again

    int clientfd = accept(socketfd, (struct sockaddr*)&client_addr,&client_len);

    if(clientfd <0){
        perror("accepting connection has failed"); // check for error
        return -1;
    }
    return clientfd;
}

// closes all communication
void ServerCloseCommunication(int socketfd, int clientfd){
    close(clientfd);
    close(socketfd);
    return;
}

int ServerSetup(int *socketfd, InetSocketInfo *socketInfo){
     if (InitSocket(socketfd) != 0) {
        // Handle error, exit or return
        fprintf(stderr, "Failed to initialize socket\n");
        return -1;
    }
    if (ConnectSocket(*socketfd,socketInfo) != 0) {
        // Handle error, exit or return
        fprintf(stderr, "Failed to connect socket\n");
        return -1;
    }
    if (ListenForConnection(*socketfd) != 0) {
        // Handle error, exit or return
        fprintf(stderr, "Failed to listen for connection\n");
        return -1;
    }
    printf("waiting for client to connect\n");
    int clientfd = AcceptConnection(*socketfd);
    if (clientfd< 0) {
        // Handle error, exit or return
        fprintf(stderr, "Failed to Accept connection to socket\n");
        return -1;
    }
    printf("connection established! (type \"q\" to quit)\n");
    return clientfd;
}
// closes all the encryption variables if they exsist
void ServerCloseEncryption(RSA *rsa, BIGNUM *bn, RSA *rsaOut, char *pubKeyClient) {
    if (pubKeyClient) free(pubKeyClient);
    if (rsa) RSA_free(rsa);
    if (bn) BN_free(bn);
    if (rsaOut) RSA_free(rsaOut);
}

// setups of the public and private key encryption, all in one go to have it ready to send 
// recieves key from client first before sending
// functions are more explained in encryption
int ServerEncryptionSetup(RSA **rsa, BIGNUM **bn, RSA **rsaOut,char **pubKeyClient,
     size_t *pubKeyClientLen, int clientfd) {
    if (GenerateKeyPair(rsa, bn) < 0) {
        return -1; 
    }
    if (ExportPublicKey(*rsa, pubKeyClient, pubKeyClientLen) < 0) {
        return -1;
    }
    if (SendPublicKey(clientfd, *pubKeyClientLen, *pubKeyClient) < 0) {
        return -1;
    }
    if (ExtractPublicKey(clientfd, rsaOut) < 0) {
        return -1;
    }
    return 0;
}
// handles username entry from interface and communication of it to client 
// also reads the clients username to use for printing
int ServerUsernameHandler(char *userName, char *peerName, int clientfd){
    if(send(clientfd, userName, strlen(userName) + 1, 0)<0){ // +1 to include null terminator
        return -1; 
    } 
    printf("username sent to peer...\n");
    if(recv(clientfd, peerName, MAX_LENGTH, 0)<0){
        return -1;
    }
    size_t len = strlen(peerName);
    if (len > 0 && peerName[len-1] == '\n') {
        peerName[len-1] = '\0';
    }
    printf("peer username recieved...\n");
    return 0;
}
// main function
int ServerMainFunc (int serverPort, char *serverUserName) {
    int socketfd;
    int clientfd;
    char peerName[MAX_LENGTH];
    InetSocketInfo socketInfo;
    socketInfo.inetSocketFamily = AF_INET;
    socketInfo.inetSocketPort = serverPort; // Example port // serverport set here
    socketInfo.InetSocketAddress.socketAddress = INADDR_ANY; // Listen on all interfaces
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;
    RSA *rsaOut = NULL;
    char *pubKeyClient = NULL;
    size_t pubKeyClientLen = 0;

    clientfd = ServerSetup(&socketfd,&socketInfo);
    if(clientfd < 0){
        fprintf(stderr, "failed setup\n");
        return -1;
    }
    
    if (ServerEncryptionSetup(&rsa, &bn, &rsaOut, &pubKeyClient, &pubKeyClientLen, clientfd) < 0) {
        return -1;
    }

    if(ServerUsernameHandler(serverUserName,peerName,clientfd)<0){
        return -1;
    }

    ChatLoop(clientfd, rsaOut, rsa, peerName, serverUserName); // main chat loop

    ServerCloseCommunication(socketfd, clientfd);

    ServerCloseEncryption(rsa, bn, rsaOut, pubKeyClient);

    return 0;
}