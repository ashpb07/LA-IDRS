#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/capture.h"

int capture_init(capture_ctx_t *ctx, const char *iface) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!ctx || !iface) return -1;

    strncpy(ctx->interface, iface, MAX_IFACE_LEN - 1);
    ctx->interface[MAX_IFACE_LEN - 1] = '\0';

    ctx->handle = pcap_open_live(iface, SNAP_LEN, PROMISC_MODE,
                                  READ_TIMEOUT_MS, errbuf);
    if (!ctx->handle) {
        fprintf(stderr, "[capture] pcap_open_live failed: %s\n", errbuf);
        return -1;
    }

    /* Only capture IP traffic */
    struct bpf_program fp;
    if (pcap_compile(ctx->handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "[capture] pcap_compile failed: %s\n",
                pcap_geterr(ctx->handle));
        return -1;
    }
    if (pcap_setfilter(ctx->handle, &fp) == -1) {
        fprintf(stderr, "[capture] pcap_setfilter failed: %s\n",
                pcap_geterr(ctx->handle));
        pcap_freecode(&fp);
        return -1;
    }
    pcap_freecode(&fp);

    fprintf(stdout, "[capture] Listening on interface: %s\n", iface);
    return 0;
}

void capture_start(capture_ctx_t *ctx, pcap_handler callback, u_char *user_data) {
    if (!ctx || !ctx->handle) return;
    /* -1 = loop forever until capture_stop calls pcap_breakloop */
    pcap_loop(ctx->handle, -1, callback, user_data);
}

void capture_stop(capture_ctx_t *ctx) {
    if (ctx && ctx->handle)
        pcap_breakloop(ctx->handle);
}

void capture_destroy(capture_ctx_t *ctx) {
    if (ctx && ctx->handle) {
        pcap_close(ctx->handle);
        ctx->handle = NULL;
    }
}
