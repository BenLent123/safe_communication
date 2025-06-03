#ifndef COMMON_H
#define COMMON_H

#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#define MAX_LENGTH 64
#define AES_BLOCK_SIZE 16

int CommunicationPoll(int timeout, int socketfd);
void Communicate(int socketfd, char readTextBuffer[MAX_LENGTH], char sendTextBuffer[MAX_LENGTH], int pollResult,AES_KEY *encryptionKey, AES_KEY *decryptionKey);
void SetEncryptionKeys(unsigned const char key[16], AES_KEY *encrpytionKey, AES_KEY *decryptionKey);
void Encrypt(const AES_KEY *encryptionKey, const unsigned char *in, unsigned char *out);
void Decrypt(const AES_KEY *decryptionKey, const unsigned char *in, unsigned char *out);

#endif