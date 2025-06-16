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
#include <readline/readline.h>
#include <readline/history.h>
#include "encryption.h"

#define MAX_LENGTH 64

static int user_input_ready = 0;
static char *user_input_line = NULL;

void handle_user_input(char *line) {
    user_input_line = line;
    user_input_ready = 1;
}

void ChatLoop(int socketfd, RSA *rsaOut, RSA *rsa, char *peerUserName, char *yourUserName) {
    struct pollfd pfds[2];
    pfds[0].fd = socketfd;
    pfds[0].events = POLLIN;
    pfds[1].fd = STDIN_FILENO;
    pfds[1].events = POLLIN;

    unsigned char encrypted[256];
    unsigned char decrypted[256];

    printf("----CHAT BEGINS HERE-----.\n");

    rl_callback_handler_install("me: ", handle_user_input); // Only ONCE

    while (1) {
        int ret = poll(pfds, 2, -1);
        if (ret == -1) {
            perror("poll");
            break;
        }

        // Handle incoming message
        if (pfds[0].revents & POLLIN) {
            uint32_t net_len;
            ssize_t r = recv(socketfd, &net_len, sizeof(net_len), MSG_WAITALL);
            if (r != sizeof(net_len)) break;
            int encryptedLen = ntohl(net_len);
            if (encryptedLen <= 0 || encryptedLen > 256) break;
            r = recv(socketfd, encrypted, encryptedLen, MSG_WAITALL);
            if (r != encryptedLen) break;
            int decryptedLen = DecryptWithPrivateKey(encrypted, encryptedLen, decrypted, rsa);
            if (decryptedLen > 0) {
                decrypted[decryptedLen] = '\0';

                char *sep = strchr((char*)decrypted, ':');
                if (sep) {
                    *sep = '\0';
                    char *sender = (char*)decrypted;
                    char *msg = sep + 1;
                    if (strcmp(sender, yourUserName) != 0) {
                        char *saved_line = rl_copy_text(0, rl_end);
                        int saved_point = rl_point;
                        rl_set_prompt("");
                        rl_replace_line("", 0);
                        rl_redisplay();
                        printf("\r%s: %s\n", sender, msg);
                        rl_set_prompt("me: ");
                        rl_replace_line(saved_line, 0);
                        rl_point = saved_point;
                        rl_redisplay();
                        free(saved_line);
                    }
                } else {
                    char *saved_line = rl_copy_text(0, rl_end);
                    int saved_point = rl_point;
                    rl_set_prompt("");
                    rl_replace_line("", 0);
                    rl_redisplay();
                    printf("\r%s: %s\n", peerUserName, decrypted);
                    rl_set_prompt("me: ");
                    rl_replace_line(saved_line, 0);
                    rl_point = saved_point;
                    rl_redisplay();
                    free(saved_line);
                }
            }
        }

        // Handle user input (non-blocking)
        if (pfds[1].revents & POLLIN) {
            rl_callback_read_char();
        }

        // If user input is ready, process it
        if (user_input_ready && user_input_line) {
            if (*user_input_line) {
                add_history(user_input_line);

                // Send as "yourUserName:message" 
                char sendBuffer[MAX_LENGTH * 2];
                snprintf(sendBuffer, sizeof(sendBuffer), "%s:%s", yourUserName, user_input_line);

                int encryptedLen = EncryptedWithPublicKey((unsigned char*)sendBuffer, encrypted, rsaOut);
                if (encryptedLen > 0) {
                    uint32_t net_len = htonl(encryptedLen);
                    send(socketfd, &net_len, sizeof(net_len), 0);
                    send(socketfd, encrypted, encryptedLen, 0);
                }

                if (strcmp(user_input_line, "q") == 0) {
                    printf("your quitting the chat...\n");
                    char quitMsg[MAX_LENGTH];
                    snprintf(quitMsg, MAX_LENGTH, "---THE CHAT HAS ENDED---.\n");
                    int encryptedLen = EncryptedWithPublicKey((unsigned char*)quitMsg, encrypted, rsaOut);
                    if (encryptedLen > 0) {
                        uint32_t net_len = htonl(encryptedLen);
                        send(socketfd, &net_len, sizeof(net_len), 0);
                        send(socketfd, encrypted, encryptedLen, 0);
                    }
                    free(user_input_line);
                    break;
                }
            }
            free(user_input_line);
            user_input_line = NULL;
            user_input_ready = 0;
            // DO NOT reinstall the prompt here!
            // Just let readline handle it.
            rl_set_prompt("me: ");
            rl_replace_line("", 0);
            rl_redisplay();
        }
    }
    rl_callback_handler_remove();
}

