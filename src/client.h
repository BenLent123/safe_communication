#ifndef CLIENT_H
#define CLIENT_H

#include <netinet/in.h>

#define MAX_LENGTH 64

//int ClientCommunicationPoll(int timeout, int socketfd);
//void ClientCommunicate(int socketfd, char readTextBuffer[MAX_LENGTH], char sendTextBuffer[MAX_LENGTH], int pollResult);
int setup(int *socketfd, struct sockaddr_in *server_addr, char ipAddress[16], int port);
int ClientMainFunc(char ipAddress[16], int port, AES_KEY *encrpytionKey, AES_KEY *decryptionKey);

#endif // CLIENT_H