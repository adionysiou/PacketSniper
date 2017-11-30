/*
This program is implemented for analyzing a trace of captured packets and extract
valuable information. All implemented using libpcap.

Author: Antreas Dionysiou

Compile using:
-------------- 
gcc -Wall -lpcap sniffer.c -o sniffer

Execute using: (show help with: ./sniffer )
--------------
./sniffer trace_filename 
or 
./sniffer trace_filenam -arg1 -arg2 -...

Ex. ./sniffer filename: shows the total number of packets of the trace file 'filename'.

Available arguments to issue:
-----------------------------
-p or -protocol: to create the file 'protocols_used.txt' that shows all protocols used for each packet.
-ip_add or -ip_src_dest_address: to create the file 'ipaddresess_used.txt' that shows src,dest ip addresses used for each packet.
-f or -tcp_flags: to create the file 'tcpflags_used.txt' that shows all raised tcp flags for each packet.
-dport or -destination_port: to create the file 'destports_used.txt' that shows destination port used, for each packet.
-sport or -source_port: to create the file 'srcports_used.txt' that shows source port used, for each packet.
-pl or -payload: to create the file 'payload_of_packets.txt' that shows the payload of all packets.

"NOTE THAT THE TRACE_FILENAME SHOULD BE THE FIRST ARGUMENT GIVEN!!!"
*/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6

/* Ethernet header */
    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };

    /* IP header */
    struct sniff_ip {
        u_char ip_vhl;      /* version << 4 | header length >> 2 */
        u_char ip_tos;      /* type of service */
        u_short ip_len;     /* total length */
        u_short ip_id;      /* identification */
        u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
        u_char ip_ttl;      /* time to live */
        u_char ip_p;        /* protocol */
        u_short ip_sum;     /* checksum */
        struct in_addr ip_src;
        struct in_addr ip_dst; /* source and dest address */
    };
    #define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)        (((ip)->ip_vhl) >> 4)

    /* TCP header */
    struct sniff_tcp {
        u_short th_sport;   /* source port */
        u_short th_dport;   /* destination port */
        u_int32_t th_seq;       /* sequence number */
        u_int32_t th_ack;       /* acknowledgement number */

        u_char th_offx2;    /* data offset, rsvd */
    #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;     /* window */
        u_short th_sum;     /* checksum */
        u_short th_urp;     /* urgent pointer */
};

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}

	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}


/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/* Show menu function */
void show_menu(){
	printf("Run the program as follow:\n");
	printf("----------------------------------------------------\n");
	printf("./sniffer trace_filename -argument1 -argument2 -....\n");
	printf("./sniffer filename: shows the total number of packets of the trace file 'filename'.\n");
	printf("----------------------------------------------------\n");
	printf("Available arguments to give are:\n");
	printf("--------------------------------\n");
	printf("-p or -protocol: to create the file 'protocols_used.txt' that shows all protocols used for each packet.\n");
	printf("-ip_add or -ip_src_dest_address: to create the file 'ipaddresess_used.txt' that shows src,dest ip addresses used for each packet.\n");
	printf("-f or -tcp_flags: to create the file 'tcpflags_used.txt' that shows all raised tcp flags for each packet.\n");
	printf("-dport or -destination_port: to create the file 'destports_used.txt' that shows destination port used, for each packet.\n");
	printf("-sport or -source_port: to create the file 'srcports_used.txt' that shows source port used, for each packet.\n");
	printf("-pl or -payload: to create the file 'payload_of_packets.txt' that shows the payload of all packets.\n");
	printf("-----------------------------------------------------\n");
	printf("NOTE THAT THE TRACE_FILENAME SHOULD BE THE FIRST ARGUMENT GIVEN!!!\n");
	exit(0);
}

/* Check if file exists  and arguments given number */
void check_file(int argc,char* argv[]){
	if (argc==1){
		show_menu();	
		exit(0);	
	}	
	if (argc>8){
		printf("WRONG NUMBER OF PARAMETERS GIVEN!\n");
		exit(1);
	}
	FILE * file;
	file = fopen(argv[1], "r");
	if (file){
   		//file exists and can be opened. 
   	fclose(file);
	}else{
   		//file doesn't exists or cannot be opened (es. you don't have access permission )
		printf("FILE GIVEN DOES NOT EXIST!!!\n");
		exit(1);
	}
}

/* Determine Protocol Used. */
void determine_protocol(u_char ip_p,FILE *fp,int num_of_packets){
	fprintf(fp,"PACKET %d: ",num_of_packets);
	switch(ip_p) {
		case IPPROTO_TCP:
			fprintf(fp,"Protocol: TCP\n");
			return;
		case IPPROTO_UDP:
			fprintf(fp,"Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			fprintf(fp,"Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			fprintf(fp,"Protocol: IP\n");
			return;
		default:
			fprintf(fp,"Protocol: unknown\n");
			return;
	}

}

/* Output source and destination IP addresses. */
void determine_ip_addr(char * src_IP_addr,char *dest_IP_addr,FILE *fp,int num_of_packets){
	fprintf(fp,"PAKCET %d:\n",num_of_packets);	
	fprintf(fp,"\n IP src: %s",src_IP_addr );
    	fprintf(fp,"\n IP dest: %s\n",dest_IP_addr);
	return;
}

/* Output destination port of a packet. */
void determine_dest_port(int dest_port,FILE * fp,int num_of_packets){
	fprintf(fp,"PACKET %d destination_port: %d \n",num_of_packets,dest_port);
	return;
}
 /* Output source port of a packet. */
void determine_src_port(int src_port,FILE * fp,int num_of_packets){
	fprintf(fp,"PACKET %d source_port: %d\n",num_of_packets,src_port);	
	return;
}

/* Output tcp flags of a packet. */
void determine_tcp_flags(int flags,int num_of_packets,FILE * fp){
	fprintf(fp,"Packet %d flags enabled: ",num_of_packets);
	if (flags & TH_FIN){
		fprintf(fp,"FIN|");
	}
	if (flags & TH_SYN){
		fprintf(fp,"SYN|");
	}
	if (flags & TH_RST){
		fprintf(fp,"RST|");
	}
	if (flags & TH_ACK){
		fprintf(fp,"ACK|");
	}
	fprintf(fp,"\n");
	return;
}

/* MAIN */
int main(int argc,char *argv[]){
	pcap_t * pcap;
	char errbuf[PCAP_ERRBUF_SIZE];
	check_file(argc,argv);
	pcap = pcap_open_offline(argv[1], errbuf);
	struct pcap_pkthdr header;
	const u_char * packet;
	int num_of_packets=0;
	int num_of_packs_no_content=0;
	//tcp info
    	//const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */
	int size_payload;
	u_int size_ip;
	u_int size_tcp;
	int prot_flag=0;
	int ipadd_flag=0;
	int tcpflags_flag=0;
	int destport_flag=0;
	int srcport_flag=0;
	int pld_flag=0;
	int argp=0;
	FILE *protocols=NULL;
	FILE *ip_addresses=NULL;
	FILE *tcp_flags=NULL;
	FILE *destports=NULL;
	FILE *srcports=NULL;

	//create appropriate files according to arguments given.
	for (argp=2;argp<argc;argp++){
		if ((strcmp(argv[argp],"-p")==0)||(strcmp(argv[argp],"-protocol")==0)){
			prot_flag=1;
			protocols = fopen ( "protocols_used.txt", "w" ) ;
			if (protocols == NULL) {
				printf ("Protocols File not created!!\n");
				exit(1);
		    	}
		}
		if ((strcmp(argv[argp],"-ip_add")==0)||(strcmp(argv[argp],"-ip_src_dest_address")==0)){
			ipadd_flag=1;
			ip_addresses = fopen ( "ipaddresess_used.txt", "w" ) ;
			if (ip_addresses == NULL) {
				printf ("IP addresses File not created!!\n");
				exit(1);
		    	}
		}
		if ((strcmp(argv[argp],"-f")==0)||(strcmp(argv[argp],"-tcp_flags")==0)){
			tcpflags_flag=1;
			tcp_flags = fopen ( "tcpflags_used.txt", "w" ) ;
			if (tcp_flags == NULL) {
				printf ("TCP flags File not created!!\n");
				exit(1);
		    	}
		}
		if ((strcmp(argv[argp],"-dport")==0)||(strcmp(argv[argp],"-destination_port")==0)){
			destport_flag=1;
			destports = fopen ( "destports_used.txt", "w" ) ;
			if (destports == NULL) {
				printf ("Destination Ports File not created!!\n");
				exit(1);
		    	}
		}
		if ((strcmp(argv[argp],"-sport")==0)||(strcmp(argv[argp],"-source_port")==0)){
			srcport_flag=1;
			srcports = fopen ( "srcports_used.txt", "w" ) ;
			if (srcports == NULL) {
				printf ("Source Ports File not created!!\n");
				exit(1);
		    	}
		}
		if ((strcmp(argv[argp],"-pl")==0)||(strcmp(argv[argp],"-payload")==0)){
			pld_flag=1;
		}
	}
	
	//analyze packets
	while ((packet = pcap_next(pcap,&header)) != NULL){
		//ethernet = (struct sniff_ethernet*)(packet);

		/* determine IP part of packet */
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		/* determine protocol used if -p or -protocol given as argument */
		if (prot_flag){
			determine_protocol(ip->ip_p,protocols,num_of_packets);
		}	

		/* determine ip source and destination addresses */	
		if (ipadd_flag){
			determine_ip_addr(inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst),ip_addresses,num_of_packets);
		}
			
		/* determine IP header length*/
		size_ip = IP_HL(ip)*4;
		/* check if IP header length is valid */
		if (size_ip < 20) {
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			exit(1);
		}
		/* determine tcp part of packet */
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		/* determine tcp flags */
		if (tcpflags_flag){
			determine_tcp_flags(tcp->th_flags,num_of_packets,tcp_flags);
		}
		
		/* determine source and destination ports*/
		if (destport_flag){
			determine_dest_port(ntohs(tcp->th_dport),destports,num_of_packets);
		}
		
		if (srcport_flag){
			determine_src_port(ntohs(tcp->th_sport),srcports,num_of_packets);
		}
		
		/* determine TCP header length*/
		size_tcp = TH_OFF(tcp)*4;
		/* check if TCP header length is valid */
		//if (size_tcp < 20) {
			//printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			//exit(1);
		//}

		/* determine PAYLOAD part of packet */
		payload = (const char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		/* compute tcp payload (segment) size */
		size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

		/*
		 * Print payload data; it might be binary.
		 */
		if (size_payload > 0){
			if (pld_flag){
				print_payload((const u_char *)payload, size_payload);
			}
			
		}
		else{
			//printf("NO PAYLOAD FOUND!!! (SIZE=0)\n");	
			num_of_packs_no_content+=1; 
		}
		num_of_packets+=1;
		
	}
	//close files.
	if (protocols!=NULL){
		fclose(protocols);
	}
	if (ip_addresses!=NULL){
		fclose(ip_addresses);
	}
	if (tcp_flags!=NULL){
		fclose(tcp_flags);
	}
	if (destports!=NULL){
		fclose(destports);
	}
	if (srcports!=NULL){
		fclose(srcports);
	}
	//show total packets of trace. 
	printf("TOTAL PACKETS FOR GIVEN TRACE: %d\n",num_of_packets);
	printf("TOTAL PACKETS WITH ZERO PAYLOAD: %d\n",num_of_packs_no_content);
	return 0;
}
