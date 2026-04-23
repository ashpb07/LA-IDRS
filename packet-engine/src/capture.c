#include <pcap.h>
#include <stdio.h>
#include <sys/types.h>
#include "capture.h"
#include "parser.h"

#include <stdint.h>

void packet_handler(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet){
    parse_packet(packet);
}

void start_capture(const char *dev) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        printf("Error opening device %s: %s\n", dev, errbuf);
        return;
    }

    printf("[+] Capturing on %s...\n", dev);

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
}