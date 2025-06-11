CC=gcc
CFLAGS=-Wall -Wextra -g
LDFLAGS=-lssl -lcrypto
SRC=src/server.c src/client.c src/interface.c src/common.c src/encryption.c
TARGET=communication

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) $(CFLAGS) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)