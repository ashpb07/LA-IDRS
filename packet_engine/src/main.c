#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include "../include/capture.h"
#include "../include/parser.h"
#include "../include/emitter.h"

static capture_ctx_t g_cap;
static emitter_ctx_t g_emit;
static volatile int  g_running = 1;

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
    capture_stop(&g_cap);
}

static void packet_callback(u_char *user, const struct pcap_pkthdr *header,
                             const u_char *data) {
    (void)user;
    packet_meta_t meta;
    memset(&meta, 0, sizeof(meta));

    if (parse_packet(data, header->caplen,
                     (uint32_t)header->ts.tv_sec,
                     (uint32_t)header->ts.tv_usec,
                     &meta) != 0) {
        return; /* skip non-IP or malformed */
    }

    if (emitter_send(&g_emit, &meta) != 0) {
        fprintf(stderr, "[main] Failed to send packet to detection engine\n");
    }
}

int main(int argc, char *argv[]) {
    const char *iface = (argc > 1) ? argv[1] : "eth0";

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    fprintf(stdout, "[netsentinel] Packet Engine starting on interface: %s\n", iface);

    if (emitter_init(&g_emit) != 0) {
        fprintf(stderr, "[main] Emitter init failed — is detection engine running?\n");
        return EXIT_FAILURE;
    }

    if (capture_init(&g_cap, iface) != 0) {
        fprintf(stderr, "[main] Capture init failed — check interface name and permissions.\n");
        emitter_destroy(&g_emit);
        return EXIT_FAILURE;
    }

    capture_start(&g_cap, packet_callback, NULL);

    fprintf(stdout, "[netsentinel] Packet Engine stopped.\n");
    capture_destroy(&g_cap);
    emitter_destroy(&g_emit);
    return EXIT_SUCCESS;
}
