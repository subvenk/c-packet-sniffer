#ifndef SNIFFER_H
#define SNIFFER_H

int init_sniffer(const char *interface_name);
void capture_packet(int sock);

#endif
