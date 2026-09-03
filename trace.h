void process_packets(
    uint64_t packet_num,
    struct pcap_pkthdr *header,
    const u_char *data
);

void parse_IP(
    const IPv4_header *ip_header,
    size_t captured_ip_len
);

void parse_ARP(const ARP_header *arp_header);

void parse_TCP(
    const IPv4_header *ip_header,
    const uint8_t *tcp_data,
    size_t tcp_segment_len
);

void parse_UDP(
    const uint8_t *udp_data,
    size_t udp_available_len
);

void print_port(uint16_t port);
