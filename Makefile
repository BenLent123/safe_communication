CC = gcc
CFLAGS=-Wall -Wextra -g
LDFLAGS=-lssl -lcrypto -lreadline
SRC = src/main.c src/sockethandler.c src/encryption.c src/chathandler.c
OUT = safecom

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(SRC) $(CFLAGS) $(LDFLAGS) -o $(OUT)

clean:
	rm -f $(OUT)
