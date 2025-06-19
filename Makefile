CC = gcc
CFLAGS = -Iinclude
SRC = src/main.c src/sniffer.c src/parser.c
OBJ = $(SRC:.c=.o)
TARGET = packet-sniffer

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
