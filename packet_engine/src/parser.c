#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include "parser.h"
#include "emitter.h"

void parse_packet(const u_char *packet) {
    struct ip *ip_header = (struct ip*)(packet + 14);

    if (ip_header->ip_p != IPPROTO_TCP)
        return;

    struct tcphdr *tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl * 4));

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    int src_port = ntohs(tcp_header->th_sport);
    int dst_port = ntohs(tcp_header->th_dport);

    int syn_flag = (tcp_header->th_flags & TH_SYN) ? 1 : 0;
    int ack_flag = (tcp_header->th_flags & TH_ACK) ? 1 : 0;

    char buffer[512];

    snprintf(buffer, sizeof(buffer),
        "{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%d,\"dst_port\":%d,\"syn\":%d,\"ack\":%d}\n",
        src_ip, dst_ip, src_port, dst_port, syn_flag, ack_flag
    );

    send_packet_data(buffer);
}