#ifndef SERVER_H
#define SERVER_H

#define MAX_LENGTH 64

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <netinet/in.h>

// Structure to describe internet socket address
typedef struct {
    unsigned long socketAddress;
} InetAddressInfo;

// Structure to describe internet socket information
typedef struct {
    short inetSocketFamily;
    unsigned short inetSocketPort;
    InetAddressInfo InetSocketAddress;
} InetSocketInfo;

int InitSocket(int *socketfd);
int ConnectSocket(int socketfd, InetSocketInfo *socketInfo);
int ListenForConnection(int socketfd);
int AcceptConnection(int socketfd);

void ServerCloseCommunication(int socketfd, int clientfd);
void ServerCloseEncryption(RSA *rsa, BIGNUM *bn, RSA *rsaOut, char *pubKeyClient);
int ServerUsernameHandler(char *userName, char *peerName, int clientfd);

int ServerEncryptionSetup(RSA **rsa, BIGNUM **bn, RSA **rsaOut,char **pubKeyClient,size_t *pubKeyClientLen, int clientfd);
int ServerSetup(int *socketfd, InetSocketInfo *socketInfo);

int ServerMainFunc(int serverPort, char *serverUserName);

#endif // SERVER_H