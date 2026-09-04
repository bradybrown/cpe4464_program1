#include "trace.h"
#include "checksum.h"

struct pcap_pkthdr;


int main(int argc, char *argv[])
{
    if (argc > 2) {
        fprintf(stderr, "Too many parameters.");
        return EXIT_FAILURE;
    }

    if (argc <= 1) {
        fprintf(stderr, "Too few parameters.");
        return EXIT_FAILURE;
    }

    const char *pcapFilename = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *pkt_data;
    struct pcap_pkthdr *pkt_header;

    int result;

    pcap_t *handle = pcap_open_offline(pcapFilename, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "%s", errbuf);
        return 1;
    }

    uint64_t packet_num = 1;

    while ((result = pcap_next_ex(handle, &pkt_header, &pkt_data)) >= 0)
    {
        if (result == 0) {continue;}  // Reading timeout
        if (result == PCAP_ERROR_BREAK) {
            // printf("There is nothing left to read from the file.");
            break;
        }

        printf("\n");
        process_packets(packet_num, pkt_header, pkt_data);
        printf("\n");
        packet_num++;
    }

    if (result == PCAP_ERROR) {
        // Error: Call pcap_geterr(p) to fetch the reason and exit/log.
        pcap_close(handle);
        return EXIT_FAILURE;
    }
    else if (result == PCAP_ERROR_BREAK) {
        // printf("Successfully reached the end of the file."); // TODO: Remove later
        pcap_close(handle);
        return EXIT_SUCCESS;
    }
    // printf("Hmmm, we made it to the end of main."); // TODO: Remove later
    pcap_close(handle);
    return EXIT_FAILURE;
}

void process_packets(uint64_t packet_num, struct pcap_pkthdr *header, const u_char *data)
{
    printf("Packet number: %llu  Packet Len: %u", (unsigned long long)packet_num, header->len);

    if (header->caplen < 14) {
        printf("\nUnknown PDU"); // TODO: Verify that this check works
        return;
    }

    // Ethernet header: 1st 14 bytes
    printf("\n\n\tEthernet Header");
    const Eth_header *eth_header = (Eth_header *)data;
    
    struct ether_addr dest_mac;
    struct ether_addr src_mac;
    memcpy(&dest_mac, eth_header->dest_mac, sizeof(eth_header->dest_mac));
    memcpy(&src_mac, eth_header->src_mac, sizeof(eth_header->src_mac));

    printf("\n\t\tDest MAC: %s", ether_ntoa(&dest_mac));
    printf("\n\t\tSource MAC: %s", ether_ntoa(&src_mac));

    uint16_t ethernet_type = ntohs(eth_header->ether_type); 
        // TODO: Assumes the header->caplen is >= 14
    switch (ethernet_type)
    {
        case 0x0800: {
            printf("\n\t\tType: IP");
            printf("\n");
            const IPv4_header *ip_header = (IPv4_header *)(data + sizeof(Eth_header));
            parse_IP(ip_header, header->caplen);
            break;
        }
            
        case 0x0806: {
            printf("\n\t\tType: ARP");
            printf("\n");
            const ARP_header *arp_header = (ARP_header *)(data + sizeof(Eth_header));
            parse_ARP(arp_header);
            break;
        }

        default: {
            printf("\n\t\tType: Unknown");  // TODO: Do i need Unknown PDU?
        }
    }
}


void parse_IP(const IPv4_header *ip_header, uint32_t caplen) {
    // IP Header: Next 20 to 60 Bytes
    int len = (ip_header->ver_hl & 0x0F) * 4;
    if (caplen < 20) {
        printf("Unknown PDU\n");
        return;
    }

    printf("\n\tIP Header");
    printf("\n\t\tTOS: 0x%x", ip_header->tos);
    printf("\n\t\tTTL: %u", ip_header->ttl);
    printf("\n\t\tProtocol: ");
    
    uint8_t protocol = 0;

    switch (ip_header->protocol) {
        case 1: {
            printf("ICMP");
            protocol = 1;
            break;
        }
        case 6: {
            printf("TCP");
            protocol = 6;
            break;
        }
        case 17: {
            printf("UDP");
            protocol = 17;
            break;
        }
        default: {
            printf("Unknown");
            protocol = 0;
        } 
        printf("\n");
    }


    uint16_t ck_sum = ntohs(ip_header->checksum);
    if (in_cksum((unsigned short *)ip_header, len) == 0) {
        printf("\n\t\tChecksum: Correct (0x%x)", (unsigned int)ck_sum);
    } 
    else {
        printf("\n\t\tChecksum: Incorrect (0x%x)", (unsigned int)ck_sum);
    }

    struct in_addr ip_src;
    struct in_addr ip_dest;
    memcpy(&ip_src, ip_header->src_ip, sizeof(ip_header->src_ip));
    memcpy(&ip_dest, ip_header->dest_ip, sizeof(ip_header->dest_ip));

    printf("\n\t\tSender IP: %s", inet_ntoa(ip_src));
    printf("\n\t\tDest IP: %s", inet_ntoa(ip_dest));
    printf("\n");

    uint8_t *next_header = (uint8_t *)ip_header;
    next_header += len;
    switch (protocol) {
        case 1: {
            printf("\n\tICMP Header\n\t\tType: ");
            switch (ntohs(*(uint16_t *)next_header)) {
                case 0: {
                    printf("Reply");
                    break;
                }
                case 8: {
                    printf("Request");
                    break;
                }
                default: printf("Unknown");
            }
            break;
        }
        case 6: {
            
            parse_TCP((const TCP_header *)(next_header), ip_header);
            break;
        }
        case 17: {
            parse_UDP((const UDP_header *)(next_header));
            break;
        }
        default: printf("Unknown");
    }    
}

void parse_ARP(const ARP_header *arp_header) {
    printf("\n\tARP Header");
    int opcode = ntohs(arp_header->opcode);
    if (opcode == 1) {
        printf("\n\t\tOpcode: Request");
    }
    else if (opcode == 2) {
        printf("\n\t\tOpcode: Reply");
    } 
    else {
        printf("\n\t\tOpcode: Unknown"); // SHOULD NEVER PRINT THIS
    } 

    struct ether_addr sender_mac;
    struct ether_addr target_mac;
    memcpy(&sender_mac, arp_header->sender_mac, sizeof(arp_header->sender_mac));
    memcpy(&target_mac, arp_header->target_mac, sizeof(arp_header->target_mac));

    struct in_addr ip_src;
    struct in_addr ip_dest;
    memcpy(&ip_src, arp_header->sender_ip, sizeof(arp_header->sender_ip));
    memcpy(&ip_dest, arp_header->target_ip, sizeof(arp_header->target_ip));

    printf("\n\t\tSender MAC: %s", ether_ntoa(&sender_mac));
    printf("\n\t\tSender IP: %s", inet_ntoa(ip_src));
    printf("\n\t\tTarget MAC: %s", ether_ntoa(&target_mac));
    printf("\n\t\tTarget IP: %s", inet_ntoa(ip_dest));
}

void parse_TCP(const TCP_header *tcp_header, const IPv4_header *ip_header) {
    // TCP Header: 20 to 60 Bytes
    printf("\n\tTCP Header");
    printf("\n\t\tSource Port:  ");
    print_port(ntohs(tcp_header->src_port));
    printf("\n\t\tDest Port:  ");
    print_port(ntohs(tcp_header->dest_port));
    printf("\n\t\tSequence Number: %u", ntohl(tcp_header->sequence_num));
    printf("\n\t\tACK Number: %u", ntohl(tcp_header->ack_num));
    
    if (tcp_header->flags & (1 << 1)) {printf("\n\t\tSYN Flag: Yes");}
    else {printf("\n\t\tSYN Flag: No");}
    if (tcp_header->flags & (1 << 2)) {printf("\n\t\tRST Flag: Yes");}
    else {printf("\n\t\tRST Flag: No");}
    if (tcp_header->flags & (1 << 0)) {printf("\n\t\tFIN Flag: Yes");}
    else {printf("\n\t\tFIN Flag: No");}

    printf("\n\t\tWindow Size: %u", (unsigned int)ntohs(tcp_header->window_size));
    
    // TODO: ck_sum var is good. Incorrect input to the un_cksum() function
    uint16_t tcp_segment_len = ntohs(ip_header->total_length); 
    tcp_segment_len -= (uint16_t)((ip_header->ver_hl & 0x0F) * 4);

    uint16_t pseudo_size = 12; // 12 Bytes for IPv4 part  
    pseudo_size += tcp_segment_len;
    pseudo_size += (pseudo_size % 2); // If odd number, pad w/ extra byte that is zero  
    uint8_t *pseudo_header = malloc((size_t)pseudo_size); 
    if (pseudo_header == NULL) {
        fprintf(stderr, "Unable to allocate checksum buffer\n");
        return;
    }
    
    // Set all memory to 0 before filling
    memset(pseudo_header, 0, pseudo_size);
    memcpy(pseudo_header, ip_header->src_ip, 4);
    memcpy(pseudo_header + 4, ip_header->dest_ip, 4);
    pseudo_header[8] = 0; // Reserved byte, set to 0
    pseudo_header[9] = 0x06;

    uint16_t network_tcp_len = htons((uint16_t)tcp_segment_len);
    memcpy(pseudo_header + 10, &network_tcp_len, 2);
    memcpy(pseudo_header + 12, tcp_header, tcp_segment_len);

    uint16_t ck_sum = ntohs(tcp_header->checksum);
    if (in_cksum((unsigned short *)pseudo_header, (int)pseudo_size) == 0) {
        printf("\n\t\tChecksum: Correct (0x%x)", (unsigned int)ck_sum);
    } 
    else {
        printf("\n\t\tChecksum: Incorrect (0x%x)", (unsigned int)ck_sum);
    }
    printf("\n");
    free(pseudo_header);
}

void parse_UDP(const UDP_header *udp_header) {
    printf("\n\tUDP Header");
    printf("\n\t\tSource Port:  ");
    print_port(ntohs(udp_header->src_port));
    printf("\n\t\tDest Port:  ");
    print_port(ntohs(udp_header->dest_port));
}

void print_port(uint16_t port) {
    switch (port) {
        case 80:
            printf("HTTP");
            break;
        case 23:
            printf("Telnet");
            break;
        case 21:
            printf("FTP");
            break;
        case 110:
            printf("POP3");
            break;
        case 25:
            printf("SMTP");
            break;
        default:
            printf("%u", (unsigned int)port);
            break;
    }
}
