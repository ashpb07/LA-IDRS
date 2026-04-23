#include <stdio.h>
#include "capture.h"
#include "emitter.h"

int main() {
    const char *interface = "enp0s3";     // change if needed
    const char *server_ip = "127.0.0.1";
    int port = 9999;

    printf("[+] Starting NetSentinel Packet Engine\n");

    init_emitter(server_ip, port);
    start_capture(interface);

    return 0;
}