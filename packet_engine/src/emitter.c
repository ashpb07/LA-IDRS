#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "emitter.h"

static int sock;
static struct sockaddr_in server;

void init_emitter(const char *ip, int port) {
    sock = socket(AF_INET, SOCK_STREAM, 0);

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server.sin_addr);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("Emitter connection failed");
    } else {
        printf("[+] Connected to Python server\n");
    }
}

void send_packet_data(const char *data) {
    send(sock, data, strlen(data), 0);
}