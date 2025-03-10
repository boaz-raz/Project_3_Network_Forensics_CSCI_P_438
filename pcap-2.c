#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

int counter = 0;

void total_number_packets(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
);
//void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);
static int add();

/* Finds the payload of a TCP/IP packet */
void total_ip_packets(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        // printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
    // printf("Total packet available: %d bytes\n", header->caplen);
    // printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */ 
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    // printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        // printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    tcp_header_length = tcp_header_length * 4;
    // printf("TCP header length in bytes: %d\n", tcp_header_length);

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    // printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    // printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    //printf("Memory address where payload begins: %p\n\n", payload);

    /* Print payload in ASCII */
    /*  
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
    */

    add();

    return;
}

// total TCP packets
void total_tcp_packets(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
  /* First, lets make sure we have an IP and next TCP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) !=  ETHERTYPE_IP) {
        printf("TCP packet...\n\n");
        return;
    }

     /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */ 
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    // printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol == IPPROTO_TCP) {
        // printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    add();
    return;
}   


// total UDP packets
void total_udp_packets(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
  /* First, lets make sure we have an IP and next TCP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) !=  ETHERTYPE_IP) {
        // printf("TCP packet...\n\n");
        return;
    }

     /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */ 
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    // printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol == IPPROTO_TCP) {
        // printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    add();
    return;
}  

int main(int argc, char **argv) {    
    char *device = "eth0";
    char error_buffer[PCAP_ERRBUF_SIZE];
    // char error_buffer[PCAP_ERRBUF_SIZE];
	  pcap_t *handle = pcap_open_offline("task1.test1.pcap", error_buffer);
    // pcap_t *handle;
    /* Snapshot length is how many bytes to capture from each packet. This includes*/
    int snapshot_length = 1024;
    /* End the loop after this many packets are captured */
    int total_packet_count = 200;
    u_char *my_arguments = NULL;
    

    struct bpf_program filter;
    char filter_exp[] = "port 80";
    bpf_u_int32 subnet_mask, ip;


    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    // total_packet_cout should be var to count the numbet of all pakets
    // handle = pcap_open_live(device, snapshot_length, 0, 10000, error_buffer);
    pcap_loop(handle, 0, total_ip_packets, NULL);
    // pcap_loop(handle, 0, total_number_packets, NULL);
    printf("Total numbet of packets is: %d\n", counter);



    // print_packet_info();

    return 0;

}
// Function to count the number off types of packets. Task 1.1
// int* counter = 0;

void total_number_packets(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)

{
    // print_packet_info(packet_body, *packet_header);
    // printf("IP header length (IHL) in bytes: %d\n", *counter);
    add();
    return;
    
}
// calculate the numbet of total packets
static int add(){
  counter++;
  return  counter;

}


// void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
//      //count++;
//     //printf("Packet capture length: %d\n", packet_header.caplen);
//     //printf("Packet total length %d\n", packet_header.len);
// }
