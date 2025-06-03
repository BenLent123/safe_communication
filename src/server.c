#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include "common.h"
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
void CloseCommunication(int socketfd, int clientfd){
    close(clientfd);
    close(socketfd);
    return;
}

int Setup(int *socketfd, InetSocketInfo *socketInfo){
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
    int clientfd = AcceptConnection(*socketfd);
    if (clientfd< 0) {
        // Handle error, exit or return
        fprintf(stderr, "Failed to Accept connection to socket\n");
        return -1;
    }
    return clientfd;
}

int ServerMainFunc (int serverPort, AES_KEY *encrpytionKey, AES_KEY *decryptionKey) {
    int socketfd;
    int clientfd;
    int pollResult;
    char readTextBuffer[MAX_LENGTH];
    char sendTextBuffer[MAX_LENGTH];
    InetSocketInfo socketInfo;
    //InetAddressInfo addrInfo;
    socketInfo.inetSocketFamily = AF_INET;
    socketInfo.inetSocketPort = 8080; // Example port // serverport set here
    socketInfo.InetSocketAddress.socketAddress = INADDR_ANY; // Listen on all interfaces

    clientfd = Setup(&socketfd,&socketInfo);
    if(clientfd < 0){
        fprintf(stderr, "failed setup\n");
        return -1;
    }

    while(1){
        // pollResult = ServerCommunicationPoll(5000,clientfd);
        // ServerCommunicate(clientfd, readTextBuffer,sendTextBuffer,pollResult);
        // if(strcmp(sendTextBuffer, "goodbye") == 0){
        // break;
        // }
        pollResult = CommunicationPoll(5000,clientfd);
        Communicate(clientfd, readTextBuffer,sendTextBuffer,pollResult, encrpytionKey, decryptionKey);
        if(strcmp(sendTextBuffer, "goodbye") == 0){
        break;
        }
    }

    CloseCommunication(socketfd, clientfd);

    return 0;
}