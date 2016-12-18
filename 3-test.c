// Boaz Raz

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
assemble_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
total_number_packets(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/*
* calculate the number of packets - task 1
*/
static int count = 0;                   /* packet counter */
static int count_ip = 0;
static int count_tcp = 0;
// static int count_icmp = 0;
static int count_udp = 0;

void
total_number_packets(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	int size_ip;
	int size_tcp;

	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		// printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;

	}
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			count_tcp++;
			// printf("   Protocol: TCP %d:\n", count);
			break;
		case IPPROTO_UDP:
			count_udp++;
			// printf("   Protocol: UDP %d:\n", count);
			return;
		case IPPROTO_ICMP:
			// count_icmp++;
			// printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			count_ip++;
			// printf("   Protocol: IP\n");
			return;
		default:
			// printf("   Protocol: unknown\n");
			return;
	}
	return;
}


void
assemble_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{	
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	// printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		// printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		// printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	printf("size_ip %d\n", size_ip);
	printf("%s", inet_ntoa(ip->ip_src));
	printf(" %d", ntohs(tcp->th_sport));
	printf(" %s", inet_ntoa(ip->ip_dst));
	printf(" %d\n", ntohs(tcp->th_dport));
	
return;
}

int main(int argc, char **argv)
{

	// char input
	char *file_name = argv[2];
	char *task_number = argv[1];

	char *dev = "en0";			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	// pcap_t *handle;				/* packet capture handle */
	pcap_t *handle = pcap_open_offline(file_name, errbuf);

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

	if (*task_number == '1'){
		pcap_loop(handle,0 ,total_number_packets, NULL);		
	 	printf("%d %d %d %d\n",count,count_ip, count_tcp, count_udp);
	} 
	else if (*task_number == '2'){
		pcap_loop(handle,0 ,assemble_packet, NULL);	
	} 

	/* now we can set our callback function */
	pcap_loop(handle,0 ,assemble_packet, NULL);

	/* cleanup */
	// printf("argv:  %s\n", argv[1]);
	pcap_freecode(&fp);
	pcap_close(handle);

return 0;
}