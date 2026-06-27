#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
    // Ethernet Header
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800) return;

    printf("[Ethernet Header]\n");
    printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    // IP Header
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    int ip_header_len = ip->iph_ihl * 4;
    
    printf("[IP Header]\n");
    printf("Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Dst IP: %s\n", inet_ntoa(ip->iph_destip));

    if (ip->iph_protocol != IPPROTO_TCP) return;

    // TCP Header
    struct tcpheader *tcp = (struct tcpheader *)(packet
                            + sizeof(struct ethheader)
                            + ip_header_len);

    int tcp_header_len = TH_OFF(tcp) * 4;
    
    printf("[TCP Header]\n");
    printf("Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("Dst Port: %d\n", ntohs(tcp->tcp_dport));

    // HTTP Payload
    int data_offset = sizeof(struct ethheader) + ip_header_len + tcp_header_len;

    int data_len = header->caplen - data_offset;

    if (data_len > 0) {
        const u_char *data = packet + data_offset;

        if (strncmp((char *)data, "GET ",  4) == 0 ||
            strncmp((char *)data, "POST",  4) == 0 ||
            strncmp((char *)data, "HTTP",  4) == 0 ||
            strncmp((char *)data, "PUT ",  4) == 0 ||
            strncmp((char *)data, "HEAD",  4) == 0) {

            printf("[HTTP Message]\n");
            for (int i = 0; i < data_len; i++) {
                printf("%c", data[i]);
            }
            
        }
    }
    printf("\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }


    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}