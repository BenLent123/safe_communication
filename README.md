# Safe communication in C via OPENSSL and Sockets

## Description

This project is an exploration into openssl and the communication capabilities of C, by any means this project is not done nor.... fully memmory safe (memmory safety? whats that, just write that shiii out of bounds :3). This project uses sockets and encryption via openSSL to allow safe communication between a client and server (who is also another client), there is no inbetween connections one person is the "server" the other the "client". That is about it ! ^_^ enjoy

---

## Features

- Public Private Key encryption via OPENSSL
- direct IP&PC Port communication between a server and client
- username personalization
- dynamic two-way chat experience using poll.h
- written all in c so consider insanity of doing this a feature

---

## Installation

```sh
git clone https://github.com/benlent123/safe_communication.git
cd safe_communication
make
```

---

## Usage

```sh
./communication
```

---

## Contributing

I guess i dont really expect anyone to contribute but if you do or wanna use it feel free, anything else drop a message lol (dont use this to do so *skull emoji*)

---

## License

[MIT](LICENSE)