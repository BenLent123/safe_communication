#ifndef SOCKETHANDLER_H
#define SOCKETHANDLER_H

int ServerHandler(int port, char *userName);
int ClientHandler(int port, const char *serverIp, char *userName);

#endif