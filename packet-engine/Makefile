CC=gcc
CFLAGS=-Wall
LIBS=-lpcap

SRC=src/main.c src/capture.c src/parser.c src/emitter.c
OUT=sniffer

all:
	$(CC) $(SRC) -o $(OUT) $(LIBS)

clean:
	rm -f $(OUT)