#include "sniffer.h"
#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>

int init_sniffer(const char *interface_name) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        perror("socket");
        exit(1);
    }

    unsigned int ifindex = if_nametoindex(interface_name);
    if (ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", interface_name);
        close(sock);
        exit(1);
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;

    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        exit(1);
    }

    return sock;
}

static void print_mac(const unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_packet(const unsigned char *buffer, size_t len) {
    if (len < 14) {
        printf("Packet too short\n");
        return;
    }

    struct ethhdr *eth = (struct ethhdr *)buffer;
    printf("Source MAC: ");
    print_mac(eth->h_source);
    printf("\nDestination MAC: ");
    print_mac(eth->h_dest);
    printf("\nEtherType: 0x%04x\n", ntohs(eth->h_proto));

    if (ntohs(eth->h_proto) == ETH_P_IP) {
        if (len < 14 + 20) {
            printf("IP packet too short\n");
            return;
        }
        struct iphdr *ip = (struct iphdr *)(buffer + 14);
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->saddr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip->daddr, dst_ip, INET_ADDRSTRLEN);
        printf("Source IP: %s\n", src_ip);
        printf("Destination IP: %s\n", dst_ip);
        printf("Protocol: %s (%u)\n", get_protocol_name(ip->protocol), ip->protocol);
    } else {
        printf("Non-IP packet\n");
    }
    printf("----------\n");
}

void capture_packet(int sock) {
    unsigned char buffer[65536];
    ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
    if (len == -1) {
        perror("recvfrom");
        exit(1);
    }
    printf("Packet captured, length: %zd\n", len);
    print_packet(buffer, len);
}
