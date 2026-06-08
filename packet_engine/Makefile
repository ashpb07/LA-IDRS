CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -I./include
LIBS    = -lpcap
TARGET  = build/packet_engine
SRCS    = src/main.c src/capture.c src/parser.c src/emitter.c
OBJS    = $(SRCS:src/%.c=build/%.o)

all: build_dir $(TARGET)

build_dir:
	mkdir -p build

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

build/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf build/*.o $(TARGET)

.PHONY: all clean build_dir