#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "client.h"
#include "chathandler.h"

#define MAX_BUFF_LEN 16


// this function handles reating out of buffer and putting it into the required variables for user inputs
// valueselector chooses what to return such as trying to read a char,int or string
// this function overwrites the buffer 
int BufferHandleFunc(int valueSelector, char *buffer, int *outInt, char *outChar){
    if (fgets(buffer, MAX_BUFF_LEN, stdin) == NULL){
        return -1; // fgets failed to read
    }
    if (valueSelector == 0){ // read integer
        return sscanf(buffer, "%d", outInt) == 1 ? 0 : -1;
    } else if (valueSelector == 1) { // read character
        return sscanf(buffer, "%c", outChar) == 1 ? 0 : -1;
    } else { // read all (copy buffer to outChar)
        buffer[strcspn(buffer, "\n")] = '\0'; // Remove newline if present
        strcpy(outChar, buffer);
        return 0;
    }
}


int main(int argc, char *argv[]) {
    
    char cmd; // switch variable for do-while
    char serverIpAddress[MAX_BUFF_LEN]; // 15 chars + null
    int serverPort; // port used by server 
    char buffer[MAX_BUFF_LEN]; //buffer used to read for all
    struct in_addr addr; // struct to check ipv4 address validity
    char userName[MAX_BUFF_LEN];

do {
    printf("host or join? type \"h\" to host and \"j\" to join or \"q\" to quit\n");

    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        printf("Input error.\n");       // check for error
        continue;
    }
    cmd = buffer[0]; // assigment of cmd via buffer and fgets() to allow switch

    switch(cmd) {
        //case for hosting h
        case 'h':
            printf("You chose to host.\n");
        // loop for entering pc port the server uses, only checks if port is 5 digits
            do {
                printf("input a port host on (ex = 8080, max 5 numbers).\n");
                int result = BufferHandleFunc(0, buffer, &serverPort, NULL);
                if (result != 0 || serverPort < 0 || serverPort > 99999) {
                    printf("invalid port entered, please retry.\n");
                }
            }while (serverPort < 0 || serverPort > 99999);
        // loop for entering the servers username which is max 16 characters
            do{
                printf("enter username: (enter nothing for anonymous, max 16 characters)\n");
                BufferHandleFunc(2,buffer,NULL,userName);
                if(strlen(userName) == 0){
                    strcpy(userName,"Anonymous");
                }
            }while((strlen(userName ) >= MAX_BUFF_LEN));
            
            ServerMainFunc(serverPort, userName);

            break;

            // case for joining so switching to client side of this program
        case 'j':
            printf("You chose to join.\n");
            // loop for inputing an IPV4 address, does check for validity of a address
            do{
                printf("input the server IPv4 address (ex = 127.0.0.1), leave empty for localhost.\n");
                BufferHandleFunc(2, buffer, NULL, serverIpAddress);
                if (serverIpAddress[0] == '\n' || serverIpAddress[0] == '\0') {
                    strcpy(serverIpAddress, "127.0.0.1");
                    break;
                }
                if (inet_pton(AF_INET, serverIpAddress, &addr) != 1) {
                    printf("Invalid IPv4 address, please try again.\n");
                }
            }while((inet_pton(AF_INET,serverIpAddress, &addr) !=1));
        // loop for entering the port which the server is using    
            do {
                printf("input the server port (ex = 8080, max 5 numbers).\n");
                int result = BufferHandleFunc(0, buffer, &serverPort, NULL);
                if (result != 0 || serverPort < 0 || serverPort > 99999) {
                    printf("invalid port entered, please retry.\n");
                }
            }while (serverPort < 0 || serverPort > 99999);
        // loop for entering username of client
            do{
            printf("enter username: (enter nothing for anonymous, max 16 characters)\n");
            BufferHandleFunc(2,buffer,NULL,userName);
            if(strlen(userName) == 0){
                strcpy(userName,"Anonymous");
            }
            }while((strlen(userName ) >= MAX_BUFF_LEN));

            ClientMainFunc(serverIpAddress, serverPort, userName);

            break;
        // case for quiting
        case 'q':
            printf("Quitting...\n");
            break;


        default:
            printf("Invalid input.\n");
            break;
    }
} while(cmd != 'q'); 

    return 0;
}
