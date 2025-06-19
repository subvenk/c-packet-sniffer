#include "sniffer.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(1);
    }

    const char *interface = argv[1];
    int sock = init_sniffer(interface);

    while (1) {
        capture_packet(sock);
    }

    return 0;
}
