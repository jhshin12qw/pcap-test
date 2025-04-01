#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define LIBNET_LIL_ENDIAN
#elif __BYTE_ORDER == __BIG_ENDIAN
#define LIBNET_BIG_ENDIAN
#else
#error "Unknown endianness"
#endif

#ifndef LIBNET_HEADERS_H
#define LIBNET_HEADERS_H

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

struct libnet_ethernet_hdr {
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];
    u_int8_t  ether_shost[ETHER_ADDR_LEN];
    u_int16_t ether_type;
};

struct libnet_tcp_hdr {
    u_int16_t th_sport;
    u_int16_t th_dport;
    u_int32_t th_seq;
    u_int32_t th_ack;
#if defined(LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4, th_off:4;
#elif defined(LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4, th_x2:4;
#endif
    u_int8_t  th_flags;
    u_int16_t th_win;
    u_int16_t th_sum;
    u_int16_t th_urp;
};

struct libnet_ipv4_hdr {
#if defined(__LITTLE_ENDIAN)
    u_int8_t ip_hl:4, ip_v:4;
#elif defined(__BIG_ENDIAN)
    u_int8_t ip_v:4, ip_hl:4;
#else
#error "Please fix <endian.h>"
#endif
    u_int8_t  ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t  ip_ttl;
    u_int8_t  ip_p;
    u_int16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

#endif

#define MAX_PAYLOAD_PRINT 20

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d (%s)\n", res, pcap_geterr(pcap));
            break;
        }
        if (header->caplen < sizeof(struct libnet_ethernet_hdr))
            continue;
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        if (ntohs(eth_hdr->ether_type) != 0x0800)
            continue;
        if (header->caplen < sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr))
            continue;
        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        if (ip_hdr->ip_p != IPPROTO_TCP)
            continue;
        int ip_header_length = ip_hdr->ip_hl * 4;
        if (ip_header_length < 20)
            continue;
        if (header->caplen < sizeof(struct libnet_ethernet_hdr) + ip_header_length)
            continue;
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + ip_header_length);
        int tcp_header_length = tcp_hdr->th_off * 4;
        if (tcp_header_length < 20)
            continue;
        if (header->caplen < sizeof(struct libnet_ethernet_hdr) + ip_header_length + tcp_header_length)
            continue;
        int total_headers_length = sizeof(struct libnet_ethernet_hdr) + ip_header_length + tcp_header_length;
        int payload_length = header->caplen - total_headers_length;
        if (payload_length < 0)
            payload_length = 0;
        const u_char* payload = packet + total_headers_length;
        printf("Ethernet:\n");
        printf("  src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
               eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
        printf("  dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
               eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, sizeof(dst_ip));
        printf("IP:\n");
        printf("  src IP: %s\n", src_ip);
        printf("  dst IP: %s\n", dst_ip);
        printf("TCP:\n");
        printf("  src port: %d\n", ntohs(tcp_hdr->th_sport));
        printf("  dst port: %d\n", ntohs(tcp_hdr->th_dport));
        printf("Payload (hex, up to %d bytes):\n  ", MAX_PAYLOAD_PRINT);
        int print_length = (payload_length < MAX_PAYLOAD_PRINT) ? payload_length : MAX_PAYLOAD_PRINT;
        for (int i = 0; i < print_length; i++) {
            printf("%02x ", payload[i]);
        }
        printf("\n\n");
    }
    pcap_close(pcap);
    return 0;
}
   
