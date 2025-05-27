CC=gcc
CFLAGS=-Wall -Wextra -g
SRC=src/server.c src/client.c src/communication.c
OBJ=$(SRC:.c=.o)
TARGET=communication

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) $(CFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)