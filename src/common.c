#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <openssl/rsa.h>
#include <arpa/inet.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "encryption.h"

#define MAX_LENGTH 64
// two way chat using poll.h and encryption via public and private keys
void ChatLoop(int socketfd, RSA *rsaOut, RSA *rsa, char *userName) {
    //poll events and values such as write and read ready buffers etc
    struct pollfd pfds[2]; 
    pfds[0].fd = socketfd;
    pfds[0].events = POLLIN;
    pfds[1].fd = STDIN_FILENO;
    pfds[1].events = POLLIN;

    char sendBuffer[MAX_LENGTH];  //buffer used to send messages
    unsigned char encrypted[256]; // buffer used to encrypt messages
    unsigned char decrypted[256]; // buffer used to decrypt messages
    printf("----CHAT BEGINS HERE-----.\n");
    while (1) {
        int ret = poll(pfds, 2, -1);
        if (ret == -1) {
            perror("poll");
            break;
        }

        // Incoming encrypted message
        if (pfds[0].revents & POLLIN) {
            uint32_t net_len;
            ssize_t r = recv(socketfd, &net_len, sizeof(net_len), MSG_WAITALL);
            if (r != sizeof(net_len)) {
                perror("recv encrypted length failed");
                break;
            }
            int encryptedLen = ntohl(net_len);
            if (encryptedLen <= 0 || encryptedLen > 256) {
                fprintf(stderr, "Invalid encrypted length: %d\n", encryptedLen);
                break;
            }
            r = recv(socketfd, encrypted, encryptedLen, MSG_WAITALL);
            if (r != encryptedLen) {
                perror("recv encrypted data failed");
                break;
            }
            int decryptedLen = DecryptWithPrivateKey(encrypted, encryptedLen, decrypted, rsa);
            if (decryptedLen > 0) {
                printf("%s: %s\n",userName, decrypted);
            }
        }

        // Outgoing message
        if (pfds[1].revents & POLLIN) {
            if (fgets(sendBuffer, MAX_LENGTH, stdin) != NULL) {
                size_t len = strlen(sendBuffer);
                if (len > 0 && sendBuffer[len-1] == '\n') {
                    sendBuffer[len-1] = '\0';
                    len--;
                }
                
                if (len > 0) {
                    int encryptedLen = EncryptedWithPublicKey((unsigned char*)sendBuffer, encrypted, rsaOut);
                    if (encryptedLen > 0) {
                        uint32_t net_len = htonl(encryptedLen);
                        send(socketfd, &net_len, sizeof(net_len), 0);
                        send(socketfd, encrypted, encryptedLen, 0);
                    }
                }

                if(strcmp(sendBuffer,"q") == 0){
                    printf("your quitting the chat...\n");
                    char quitMsg[MAX_LENGTH];
                    snprintf(quitMsg, MAX_LENGTH, "---THE CHAT HAS ENDED---.\n");
                    int encryptedLen = EncryptedWithPublicKey((unsigned char*)quitMsg, encrypted, rsaOut);
                    if (encryptedLen > 0) {
                        uint32_t net_len = htonl(encryptedLen);
                        send(socketfd, &net_len, sizeof(net_len), 0);
                        send(socketfd, encrypted, encryptedLen, 0);
                    }
                    break;
                }
            }
        }
    }
}

