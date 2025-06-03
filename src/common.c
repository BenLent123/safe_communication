#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#define MAX_LENGTH 64
#define AES_BLOCK_SIZE 16

int CommunicationPoll(int timeout, int socketfd){
    struct pollfd pfd;
    pfd.fd = socketfd;
    pfd.events = POLLIN | POLLOUT;
    int ret = poll(&pfd, 1, timeout);
    if(ret == -1){
        perror("poll failed\n");
        return -1;
    } else if(ret == 0){
        printf("timeout\n");
    } else {
        if(pfd.revents & POLLIN){
            printf("socket read is available\n");
            return 1;
        }
        if(pfd.revents & POLLOUT){
            printf("socket write is available\n");
            return 2;
        }
    }
    return 0;
}

// decides based on poll if you can write or read
void Communicate(int socketfd, char readTextBuffer[MAX_LENGTH], char sendTextBuffer[MAX_LENGTH], int pollResult, AES_KEY *encryptionKey, AES_KEY *decryptionKey) {
    if (pollResult == 1) {
        ssize_t bytesReceived = recv(socketfd, readTextBuffer, MAX_LENGTH - 1, 0);
        if (bytesReceived > 0) {
            readTextBuffer[bytesReceived] = '\0';
            // Decrypt in 16-byte blocks
            for (int i = 0; i < bytesReceived; i += AES_BLOCK_SIZE) {
                Decrypt(decryptionKey, (unsigned char*)&readTextBuffer[i], (unsigned char*)&readTextBuffer[i]);
            }
            printf("Received: %s\n", readTextBuffer);
        } else if (bytesReceived == 0) {
            printf("Client disconnected.\n");
            strcpy(sendTextBuffer, "goodbye");
        } else {
            perror("recv failed");
        }
    } else if (pollResult == 2) {
        printf("Enter message to send: ");
        if (fgets(sendTextBuffer, MAX_LENGTH, stdin) != NULL) {
            size_t len = strlen(sendTextBuffer);
            if (len > 0 && sendTextBuffer[len-1] == '\n') {
                sendTextBuffer[len-1] = '\0';
                len--;
            }
            // Pad to multiple of 16 bytes
            size_t paddedLen = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
            memset(sendTextBuffer + len, 0, paddedLen - len);
            for (int i = 0; i < paddedLen; i += AES_BLOCK_SIZE) {
                Encrypt(encryptionKey, (unsigned char*)&sendTextBuffer[i], (unsigned char*)&sendTextBuffer[i]);
            }
            send(socketfd, sendTextBuffer, paddedLen, 0);
        }
    }
}

void SetEncryptionKeys(unsigned const char key[16], AES_KEY *encrpytionKey, AES_KEY *decryptionKey){

    AES_set_encrypt_key(key,128,encrpytionKey);

    AES_set_decrypt_key(key,128,decryptionKey);

}

void Encrypt(const AES_KEY *encryptionKey, const unsigned char *in, unsigned char *out) {
   
    AES_encrypt(in, out, encryptionKey);

}

void Decrypt(const AES_KEY *decryptionKey, const unsigned char *in, unsigned char *out) {
   
    AES_decrypt(in, out, decryptionKey);

}

