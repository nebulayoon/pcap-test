#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define ETHERNET_SIZE 14
#define DATA_LEN 10

typedef struct Ethernet{
    u_int8_t  des_addr[ETHER_ADDR_LEN];
    u_int8_t  src_addr[ETHER_ADDR_LEN];
    u_int16_t type;
}Ethernet;

typedef struct IPv4 {
	u_char ver_headerlen;		
	u_char tos;		
	u_short total_len;
	u_short id;		
	u_short frag_offset;
	u_char ttl;
	u_char protocol;
	u_short checksum;
	struct in_addr src,dst;
}IPv4;

typedef struct TCP {
  u_int16_t src_port;
  u_int16_t dst_port;
  u_int32_t seq;
  u_int32_t ack;
  u_int8_t  data_offset;  // 4 bits
  u_int8_t  flags;
  u_int16_t window_size;
  u_int16_t checksum;
  u_int16_t urgent_p;
}TCP;

typedef struct DATA_10{
    u_char data[DATA_LEN];
}DATA_10;

void print_ethernet_info(const u_char* packet){
    const Ethernet* ethernet = (Ethernet*)(packet);
    
    printf("[+]Ethernet Header\n");
    printf("src mac address: %02x %02x %02x %02x %02x %02x\n", ethernet->src_addr[0], ethernet->src_addr[1], ethernet->src_addr[2], ethernet->src_addr[3],ethernet->src_addr[4],ethernet->src_addr[5]);
    printf("dst mac address: %02x %02x %02x %02x %02x %02x\n", ethernet->des_addr[0], ethernet->des_addr[1], ethernet->des_addr[2], ethernet->des_addr[3],ethernet->des_addr[4],ethernet->des_addr[5]);
}

void print_ip_info(const u_char* packet){
    const IPv4* ip = (IPv4*)(packet);

    printf("[+]IPv4 Header\n");
    printf("src IP: %s\n", inet_ntoa(ip->src));
    printf("dst IP: %s\n", inet_ntoa(ip->dst));
}

void print_tcp_info(const u_char* packet){
    const TCP* tcp = (TCP*)(packet);
    
    printf("[+]TCP Header\n");
    printf("src PORT: %d\n", ntohs(tcp->src_port));
    printf("dst PORT: %d\n", ntohs(tcp->dst_port));
}

void print_packet_data(const u_char* packet){
    const DATA_10* p_data = (DATA_10*)(packet);
    int i;
    printf("[+]DATA\n");
    for(i = 0; i < 10; i++){
        printf("%x ",p_data->data[i]);
    }
    printf("\n");
}

u_int16_t ether_type(const u_char* packet){
    const Ethernet* ethernet = (Ethernet*)(packet);
    return ntohs(ethernet->type);
}

const u_int8_t ip_header_len(const u_char* packet){
    const IPv4* ip = (IPv4*)(packet);
    const u_int8_t header_len = ip->ver_headerlen & 0b00001111;
    
    return header_len;
}

u_char ip_header_protocol(const u_char* packet){
    const IPv4* ip = (IPv4*)(packet);
    return ip->protocol;
}

u_short ip_header_total_len(const u_char* packet){
    const IPv4* ip = (IPv4*)(packet);
    return ntohs(ip->total_len);
}

u_int8_t tcp_header_len(const u_char* packet){
    const TCP* tcp = (TCP*)(packet);
    return (tcp->data_offset & 0b11110000) >> 4;
}

void usage(){
    printf("./pcap_parse <interface>");
}

int main(int argc, char* argv[]){
    if(argc != 2){
        usage();
        exit(-1);
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev_name = argv[1];

    // pcap open
    pcap_t* pcap_handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
	if (pcap_handle == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev_name, errbuf);
		return -1;
	}
    if (pcap_datalink(pcap_handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev_name);
        return -1;
    }

    while(1){
        
        struct pcap_pkthdr* pkt_header;
        const u_char* packet;
        int res = pcap_next_ex(pcap_handle, &pkt_header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap_handle));
			break;
		}
        
        //filter
        const u_int16_t type = ether_type(packet);
        if(type != 0x0800){ //ipv4 check
            continue;
        }

        u_char protocol = ip_header_protocol(packet + ETHERNET_SIZE);
        if(protocol != 0x06){ //tcp check
            continue;
        }

        // lengths
        u_int8_t ipv4_header_len = ip_header_len(packet + ETHERNET_SIZE) * 4;
        u_short total_len = ip_header_total_len(packet + ETHERNET_SIZE);
        u_short data_start_ptr = total_len - ipv4_header_len;
        u_int8_t tcp_len = tcp_header_len(packet + ETHERNET_SIZE + ipv4_header_len) * 4;
        

        printf("\n\n\n\n\n\n");
        printf("[>]TCP packet\n");
        
        //Ethernet
        print_ethernet_info(packet);

        //IP
        print_ip_info(packet + ETHERNET_SIZE);

        //TCP
        print_tcp_info(packet + ETHERNET_SIZE + ipv4_header_len);
        
        //DATA
        u_int8_t etot_headers_total_len = ETHERNET_SIZE + ipv4_header_len + tcp_len;
        if(pkt_header->caplen > etot_headers_total_len){
            print_packet_data(packet + etot_headers_total_len);
        }else{
            printf("[+]DATA\n");
            printf("The data is not available.\n");
        }
    }

    return 0;
}

