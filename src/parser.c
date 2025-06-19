#include "parser.h"
#include<stddef.h>
// Structure for protocol mapping
typedef struct {
    int number;
    const char *name;
} ProtocolMap;

// Array of known protocols
ProtocolMap protocols[] = {
    {1, "ICMP"},
    {6, "TCP"},
    {17, "UDP"},
    {2, "IGMP"},
    {41, "IPv6"},
    {50, "ESP"},
    {51, "AH"},
    {0, NULL}  // Sentinel value to mark the end
};

// Function to get protocol name from number
const char* get_protocol_name(int number) {
    for (int i = 0; protocols[i].name != NULL; i++) {
        if (protocols[i].number == number) {
            return protocols[i].name;
        }
    }
    return "Unknown";  // Default for unmapped protocols
}
