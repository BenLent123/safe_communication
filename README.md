# safe communication via basic socket
this project revolves around trying to make "secure" unhackable communication in c using ports, ips and sockets

***WRITTEN IN LINUX, currently not for windows!***

the idea is to enable simple two-way communication between two pcs, furthermore the main goal is to have this
communication occur at a very basic but extremly secure method via hashing the messages where ip,ports and hashkeys have to be exchange 
differently (like in person or idk). therefore stuff becomes "unhackable".

- using these libs:
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <poll.h>

