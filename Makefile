CC=gcc
CFLAGS=-Wall -Wextra -g
LDFLAGS=-lssl -lcrypto -lreadline
SRC=src/server.c src/client.c src/interface.c src/chathandler.c src/encryption.c
TARGET=safecomm

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) $(CFLAGS) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)