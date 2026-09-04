#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include <pcap.h>

// Structs for the headers
typedef struct Eth_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];    
    uint16_t ether_type;
} Eth_header;

typedef struct ARP_header {
    uint8_t metadata[6];            // We dont use
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} ARP_header;

typedef struct IPv4_header {
    uint8_t ver_hl;
    uint8_t tos;
    uint8_t len_id_fragOffset[6];   // We dont use
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dest_ip[4];
} IPv4_header;

typedef struct TCP_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t sequence_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;   // Data offset, reserved bits, and NS flag
    uint8_t flags;                  // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;        // We dont use
} TCP_header;

typedef struct ICMP_header {
    uint8_t type;
    uint8_t code;                   // We dont use
    uint16_t checksum;              // We dont print
    uint16_t identifier;            // We dont use
    uint16_t sequence_num;          // We dont use
} ICMP_header;

typedef struct UDP_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;                // We dont print
    uint16_t checksum;              // We dont print
} UDP_header;


void process_packets(
    uint64_t packet_num,
    struct pcap_pkthdr *header,
    const u_char *data
);

void parse_IP(
    const IPv4_header *ip_header,
    uint32_t caplen
);

void parse_ARP(const ARP_header *arp_header);

void parse_TCP(
    const TCP_header *tcp_header, 
    const IPv4_header *ip_header
);

void parse_UDP(const UDP_header *udp_header);

void print_port(uint16_t port);
