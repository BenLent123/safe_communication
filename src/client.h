#ifndef CLIENT_H
#define CLIENT_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <netinet/in.h>

#define MAX_LENGTH 64

int ClientUsernameHandler(char *userName, char *peerName, int socketfd);

void ClientCloseEncryption(RSA *rsa, BIGNUM *bn, RSA *rsaOut, char *pubKeyClient);

int ClientEncryptionSetupPart1(RSA **rsa, BIGNUM **bn, RSA **rsaOut,char **pubKeyClient,size_t *pubKeyClientLen, int clientfd);
int ClientEncryptionSetupPart2(RSA **rsa, BIGNUM **bn, RSA **rsaOut,char **pubKeyClient,size_t *pubKeyClientLen, int clientfd);

int ClientSetup(int *socketfd, struct sockaddr_in *server_addr, char *ip, int port);

int ClientMainFunc(char *ipAdress, int serverPort, char *userName);

#endif // CLIENT_H