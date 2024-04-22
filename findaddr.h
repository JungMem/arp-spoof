// Code from https://tttsss77.tistory.com/138


#include<net/if.h>
#include<net/if_arp.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<stdint.h>
#include<stdio.h>
#include<string.h>
#include<unistd.h>

#define MAC_ALEN 6

void GetMacAddr(const char *ifname, uint8_t* mac_addr){

	struct ifreq ifr;
	int sockfd, ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("Faile to get interface MAC address - socket() failed - %m\n");
		exit(1);
	}
	
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret <0){
		printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sockfd);
		exit(1);
	}
	
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
	close(sockfd);


}

void GetIpAddr(char* ifname, char* ip_addr){

	struct ifreq ifr;
	
	int sockfd, ret;
	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("Faile to get interface MAC address - socket() failed - %m\n");
		exit(1);
	}
	
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		
		close(sockfd);
		exit(1);
	}
	
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip_addr, sizeof(struct sockaddr));
	close(sockfd);

}
