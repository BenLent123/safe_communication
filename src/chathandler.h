#ifndef COMMON_H
#define COMMON_H

#define MAX_LENGTH 64
#include <openssl/rsa.h>
void ChatLoop(int socketfd, RSA *rsaOut, RSA *rsa, char *peerUserName, char *yourUserName);

#endif // COMMON_H