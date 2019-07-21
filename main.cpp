#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
void print_ip(const uint8_t* ip);

void print_mac(const uint8_t* mac);

void print_port(const uint8_t* port);

void print_data(const uint8_t* port);

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }  

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\n", header->caplen);
    printf("\n---------------------------------------------\n\n");
    printf("Dmac ");
    print_mac(&packet[0]);
    printf("Smac ");
    print_mac(&packet[6]);
    printf("S-ip ");
    print_ip(&packet[14 + 12]);
    printf("D-ip ");
    print_ip(&packet[14 + 16]);
    printf("S_port ");
    print_port(&packet[14 + 20]);
    printf("D-port ");
    print_port(&packet[14 + 22]);
    printf("Data ");
    for(int i=0;i<=10;i++)
    {
        print_data(&packet[14 + 19 + 20 + i ]);
    }

    //TcpDATA = TOTALlength - IHL*4 - THL/4


  }

  pcap_close(handle);
  return 0;
}
void print_ip(const uint8_t* ip) {
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_mac(const uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_port(const uint8_t* port) {
    printf("%d\n", port[0] * 256 + port[1]);
}

void print_data(const uint8_t* port) {
    printf("%02x ", port[0] * 256 + port[1]);
}

