 #include <pcap.h>
	 #include <stdio.h>

	void my_packet_handler(
	    u_char *args,
	    const struct pcap_pkthdr *header,
	    const u_char *packet
	)
	{
	    /* Do something with the packet here. 
	       The print_packet_info() function shows in the
	       previous example could be used here. */
	    /* print_packet_info(packet, header); */
	    return;
	}
	 int main(int argc, char *argv[])
	 {
		// pcap_t *handle;			/* Session handle */
		char *dev = "eth0";			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "src port 53";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */


	 	pcap_t *handle = pcap_open_offline("task1.test1.pcap", errbuf);

		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
		// /* Open the session in promiscuous mode */
		// handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		// if (handle == NULL) {
		// 	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		// 	return(2);
		// }
		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}

		pcap_loop(handle, 0, my_packet_handler, &header);

		/* Grab a packet */
		// packet = pcap_next(handle, &header);
		/* Print its length */
		printf("Jacked a packet with length of [%d]\n", mask);
		/* And close the session */
		pcap_close(handle);
		return(0);
	 }
