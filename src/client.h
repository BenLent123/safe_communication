#ifndef CLIENT_H
#define CLIENT_H

#include <netinet/in.h>

#define MAX_LENGTH 64

int CommunicationPoll(int timeout, int socketfd);
void Communicate(int socketfd, char readTextBuffer[MAX_LENGTH], char sendTextBuffer[MAX_LENGTH], int pollResult);
int setup(int *socketfd, struct sockaddr_in *server_addr);
int ClientMainFunc(int argc, char *argv[]);

#endif // CLIENT_H