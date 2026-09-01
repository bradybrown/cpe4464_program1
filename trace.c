#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap/pcap.h>

#include "trace.h"

struct pcap_pkthdr;

int main(int argc, char *argv[])
{
    if (argc > 2)
    {
        fprintf(stderr, "Too many parameters.");
        return 1;
    }

    if (argc <= 1)
    {
        fprintf(stderr, "Too few parameters.");
        return 1;
    }

    const char *pcapFilename = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    u_char *pkt_data;
    struct pcap_pkthdr *pkt_header;

    int result;

    // pcap_t *pcap_open_offline(const char *fname, char *errbuf);
    pcap_t *handle = pcap_open_offline(pcapFilename, errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "%s", errbuf);
        return 1;
    }

    u_int64 packet_num = 0; 
    
    while ((result = pcap_next_ex(p, &pkt_header, &pkt_data)) >= 0)
    {
        if (result == 0)
        {
            // Reading timeout
            continue;
        }
        if (result == PCAP_ERROR_BREAK) {
            // printf("There is nothing left to read from the file.");
            break;
        }
        
        printf("Packet %lld has been received! Length: ", packet_num, pkt_header->len);

        parse_ethernet()


    }

    // if (result < 0) {

    // }

    pcap_close(handle);
    return 0;
}

int parse_ethernet() {


    
    return 0;
}
