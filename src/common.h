#ifndef COMMON_H
#define COMMON_H

#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#define MAX_LENGTH 64

int CommunicationPoll(int timeout, int socketfd);
void Communicate(int socketfd, char readTextBuffer[MAX_LENGTH], char sendTextBuffer[MAX_LENGTH], int pollResult);
void SetEncryptionKeys(unsigned const char key[16], AES_KEY *encrpytionKey, AES_KEY *decryptionKey);
char Encrypt(AES_KEY encryptionKey, char inputMessage[MAX_LENGTH]);
char Decrypt(AES_KEY decryptionKey, char inputMessage[MAX_LENGTH]);

#endif