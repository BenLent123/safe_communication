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
void Communicate(int socketfd, char readTextBuffer[MAX_LENGTH], char sendTextBuffer[MAX_LENGTH], int pollResult){
    if(pollResult == 1){
        ssize_t bytesReceived = recv(socketfd, readTextBuffer, MAX_LENGTH - 1, 0);
        if (bytesReceived > 0) {
            readTextBuffer[bytesReceived] = '\0'; // Null-terminate for safe printing
            printf("Received: %s\n", readTextBuffer);
        } else if (bytesReceived == 0) {
            printf("Client disconnected.\n");
            // Optionally set a flag or handle cleanup here
            strcpy(sendTextBuffer, "goodbye"); // To break the main loop
        } else {
            perror("recv failed");
        }
    }
    else if(pollResult == 2){
        printf("Enter message to send: ");
        if (fgets(sendTextBuffer, MAX_LENGTH, stdin) != NULL) {
            // Remove newline if present
            size_t len = strlen(sendTextBuffer);
            if (len > 0 && sendTextBuffer[len-1] == '\n') {
                sendTextBuffer[len-1] = '\0';
            }
            send(socketfd, sendTextBuffer, strlen(sendTextBuffer) + 1, 0);
        }
    }
}

void SetEncryptionKeys(unsigned const char key[16], AES_KEY *encrpytionKey, AES_KEY *decryptionKey){

    AES_set_encrypt_key(key,128,&encrpytionKey);

    AES_set_decrypt_key(key,128,&decryptionKey);

}

char Encrypt(AES_KEY encryptionKey, char inputMessage[MAX_LENGTH]){
    
    char out[MAX_LENGTH];

    AES_encrypt(inputMessage, out, &encryptionKey);  

    return out;
   
}

void Decrypt(AES_KEY decryptionKey, char inputMessage[MAX_LENGTH]){

    char decoded[MAX_LENGTH];
   
    AES_decrypt(inputMessage, decoded, &decryptionKey);
    
}

