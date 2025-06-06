#ifndef SERVER_H
#define SERVER_H

#include <netinet/in.h>

#define MAX_LENGTH 64

typedef struct {
    unsigned long socketAddress;
} InetAddressInfo;

typedef struct {
    short inetSocketFamily;
    unsigned short inetSocketPort;
    InetAddressInfo InetSocketAddress;
} InetSocketInfo;

int InitSocket(int *socketfd);
int ConnectSocket(int socketfd, InetSocketInfo *socketInfo);
int ListenForConnection(int socketfd);
int AcceptConnection(int socketfd, InetSocketInfo *socketInfo);
//int ServerCommunicationPoll(int timeout, int socketfd);
//void ServerCommunicate(int clientfd, char readTextBuffer[MAX_LENGTH], char sendTextBuffer[MAX_LENGTH], int pollResult);
void CloseCommunication(int socketfd, int clientfd);
int Setup(int *socketfd, InetSocketInfo *socketInfo);
int ServerMainFunc(int serverPort, AES_KEY *encrpytionKey, AES_KEY *decryptionKey);
#endif // SERVER_H