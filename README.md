# Safe communication in C via OPENSSL and Sockets

## Description

This project is an exploration into the communication capabilities of C, by any means this project is not done nor.... fully memmory safe (memmory safety? whats that, just write that shiii out of bounds :3). This project uses sockets and encryption via openSSL to allow safe communication between a client and server (who is also another client), there is no inbetween connections one person is the "server" the other the "client". That is about it ! ^_^ enjoy

THIS IS ALL CURRENTLY ONLY FOR LINUX AND NOT FULLY SAFE !!!
---

## Features

- Public Private Key encryption via OPENSSL (deprecated RN ill check if i can change that)
- direct IP&PC Port communication between a server and client
- username personalization (crazy IK)
- dynamic two-way chat experience using poll abd select (only 1 thread)
- written all in c so consider insanity of doing this a feature
- recieving during write does not interrupt writing via readline
- quiting chat is possible

---

## Installation

```sh
git clone https://github.com/benlent123/safe_communication.git
cd safe_communication
make
```

---

## Troubleshooting

 - you need to use pc ports that are not in use 
 - you might need to temporarily disable firewall as you are recieving connections as server (unsafe)

---

## Usage

```sh
./safecom [h|j] [port] [ipv4 IP] [username]
```

---

## Contributing

I guess i dont really expect anyone to contribute, but feel free to use it or idk. Anything else drop a message lol (dont use this to do so *skull emoji*)

---

## License
Free to use and code is "As is", I do not have any liability what happens with this code or if 
this is used
