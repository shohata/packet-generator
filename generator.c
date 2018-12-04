#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

/* #define NDEBUG */

#ifdef NDEBUG
  #define DEBUG( fmt, ... ) ((void)0)
#else /* !NDEBUG */
  #define DEBUG( fmt, ... ) \
    fprintf(stderr, "[%s] %s:%03u # " fmt "\n", __DATE__, __FILE__, __LINE__, ##__VA_ARGS__)
#endif /* NDEBUG */

#define DATA_LEN 32


/* MAC Address */
const unsigned char nuc3macaddr [6] = {0xF4, 0x4D, 0x30, 0x67, 0xD5, 0xF5};
const unsigned char nuc4macaddr [6] = {0xF4, 0x4D, 0x30, 0x67, 0xCD, 0x68};
const unsigned char fpgamacaddr [6] = {0xDA, 0x02, 0x03, 0x04, 0x05, 0x06};

/* IP Address */
const unsigned char nuc3ipaddr [4] = {10, 24, 128, 213};
const unsigned char nuc4ipaddr [4] = {10, 24, 129, 175};
const unsigned char fpgaipaddr [4] = {10, 24, 129, 222};


int createSocket(char *interface, struct sockaddr_ll *sll);
int checkHeader(unsigned char *packet);
void generateHeader(unsigned char *packet);
void generateData(unsigned char *packet);
void generateRandData(unsigned char *packet);
void printHeader(unsigned char *packet);
void printData(unsigned char *packet);
void printByte(unsigned char *packet);


int main(int argc, char *argv[]){
  char c = '\0';
  unsigned char packet[1518];
  int sock;
  struct sockaddr_ll sll;

  if (argc > 1) {
    c = argv[1][0];
  }

  sock = createSocket("eth0", &sll);
  if (sock == -1) {
    return 1;
  }

  srand(time(NULL));

  while (1) {
    switch (c) {
      case 'r': /* receive packet */
        recv(sock, packet, sizeof(packet), 0);
        printHeader(packet);
        printData(packet);
        printByte(packet);
        break;
      case 'R': /* reseive target packet */
        recv(sock, packet, sizeof(packet), 0);
        if (checkHeader(packet)) {
          printHeader(packet);
          printData(packet);
        }
        break;
      case 's': /* send permutatin value packet */
        generateHeader(packet);
        generateData(packet);
        sendto(sock, packet, 42 + DATA_LEN*4, 0, (struct sockaddr *)&sll, sizeof(sll));
        printf("send packet!\n");
        break;
      case 'S': /* send randomized value packet */
        generateHeader(packet);
        generateRandData(packet);
        sendto(sock, packet, 42 + DATA_LEN*4, 0, (struct sockaddr *)&sll, sizeof(sll));
        printData(packet);
        break;
      default:
        DEBUG("option %c is not defined.", c);
        printf("usage: [r] [s] [R] [S]\n");
        printf("  r: Receive all packets\n");
        printf("  R: Receive target packets\n");
        printf("  s: Send permutation value packets\n");
        printf("  S: Send randomized value packets\n");
        return 0;
    }
    usleep(100000);   /* 100,000 us == 100 ms */
  }

  return 0;
}

/*
 * Create Raw-socket, which includes MAC header and payload
 */
int createSocket(char *interface, struct sockaddr_ll *sll) {
	int i;
	unsigned char buf[2048];
  int recvbuf = 0;
  int recvbuflen = sizeof(recvbuf);
  int sock;
  int ifindex;
  struct ifreq ifr;

  /* Get socket */
  sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
  if (sock == -1) {
    printf("Error: cannot get socket\n");
    return -1;
  }
  DEBUG("socket: %d", sock);

  /* Set interface name */
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, interface, IFNAMSIZ);
  DEBUG("interface name: %s", interface);

  /* Get interface index number */
  if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
    printf("Error: cannot get interface index number\n");
    return -1;
  }
  ifindex = ifr.ifr_ifindex;
  DEBUG("index number: %d", ifindex);

  /* bind uses only sll_protocol and sll_ifindex.*/
  memset(sll, 0, sizeof(*sll));
  sll->sll_family = AF_PACKET;	/* allways AF_PACKET */
  sll->sll_protocol = htons(ETH_P_IP);
  sll->sll_ifindex = ifindex;
  if (bind(sock, (struct sockaddr*)sll, sizeof(*sll)) == -1) {
    printf("Error: cannot bind\n");
    return -1;
  }
  DEBUG("success: binding");

  /* 
   * Flush all received packets. 
   *
   * Raw-socket receives packets from all interfaces,
   * while the socket is not binded to a interface.
   */

  /* Get receive buffer length */
  if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &recvbuf, &recvbuflen)) {
    printf("Error: get receive buffer length\n");
    return -1;
  }
  recvbuf /= 2;
  DEBUG("receive buffer legth: %d", recvbuf);

  /* Read all received packets */
	do {
    i = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
    if (i < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      break;
    }
    recvbuf -= i;
	} while (recvbuf > 0);
  DEBUG("success: flushing all");

  return sock;
}

/*
 * Generate MAC, IP, and UDP header
 */
void generateHeader(unsigned char *packet) {
  struct ethhdr eth;
  struct iphdr ip;
  struct udphdr udp;

  /* MAC header */
  memcpy(eth.h_dest, nuc3macaddr, 6);
  memcpy(eth.h_source, nuc4macaddr, 6);
  eth.h_proto = htons(0x800); /* IP */

  /* IP header */
  ip.ihl = 5;
  ip.version = 4; /* Ipv4 */
  ip.tos = 0x00;
  ip.tot_len = htons(28 + DATA_LEN*4);
  ip.id = htons(0);
  ip.frag_off = htons(0);
  ip.ttl = 0xFF;
  ip.protocol = 0x11; /* UDP */
  ip.check = htons(0);
  memcpy(&ip.saddr, nuc4ipaddr, 4);
  memcpy(&ip.daddr, nuc3ipaddr, 4);

  /* UDP header */
  udp.source = htons(0x4000); /* UDP source port = 0x4000 */
  udp.dest = htons(0x4000);
  udp.len = htons(8 + DATA_LEN*4);
  udp.check = htons(0);

  memcpy(packet, &eth, 14);
  memcpy(packet + 14, &ip, 20);
  memcpy(packet + 34, &udp, 8);
}

/*
 * Generate MAC, IP, and UDP header
 */
void printHeader(unsigned char *packet) {
  struct ethhdr *eth = (struct ethhdr *) packet;
  struct iphdr *ip = (struct iphdr *)(packet + 14);
  struct udphdr *udp = (struct udphdr *)(packet + 34);
  unsigned char *p;

  /* MAC header */
  printf("-------- MAC Header --------\n");
  p = eth->h_dest;
  printf("dst mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);
  p = eth->h_source;
  printf("src mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);
  printf("type: 0x%04x\n", ntohs(eth->h_proto));

  /* IP header */
  printf("-------- IP Header --------\n");
  printf("version: %d\n", ip->version);
  printf("ip header length: %d\n", ip->ihl);
  printf("time of service: 0x02%x\n", ip->tos);
  printf("total length: %d\n", ntohs(ip->tot_len));
  printf("id: %d\n", ntohs(ip->id));
  printf("frag offset: %d\n", ntohs(ip->frag_off));
  printf("time to live: %d\n", ip->ttl);
  printf("protocol: 0x%02x\n", ip->protocol);
  printf("checksum: 0x%04x\n", ntohs(ip->check));
  p = (char *)&ip->saddr;
  printf("src ip addr: %d.%d.%d.%d\n", p[0], p[1], p[2], p[3]);
  p = (char *)&ip->daddr;
  printf("dst ip addr: %d.%d.%d.%d\n", p[0], p[1], p[2], p[3]);

  /* UDP header */
  printf("-------- UDP Header --------\n");
  printf("src port: %d\n", ntohs(udp->source));
  printf("dst port: %d\n", ntohs(udp->dest));
  printf("length: %d\n", ntohs(udp->len));
  printf("checksum: 0x%04x\n", ntohs(udp->check));
}

/*
 * Check which the packet is target or not
 */
int checkHeader(unsigned char *packet) {
  struct ethhdr *eth = (struct ethhdr *) packet;
  struct iphdr *ip = (struct iphdr *)(packet + 14);
  struct udphdr *udp = (struct udphdr *)(packet + 34);

  if (ntohs(eth->h_proto) == 0x0800 && ip->protocol == 0x11 && ntohs(udp->dest) == 0x4000) {
    return 1;
  } else {
    return 0;
  }
}

/*
 * Generate permutation values
 */
void generateData(unsigned char *packet) {
  int i;
  unsigned int data[DATA_LEN];

  for (i=0; i<DATA_LEN; i++) {
    data[i] = htonl(i+1);
  }

  memcpy(packet + 42, data, sizeof(data));
}

/*
 * Generate randomized values
 */
void generateRandData(unsigned char *packet) {
  int i;
  unsigned int data[DATA_LEN];

  for (i=0; i<DATA_LEN; i++) {
    data[i] = htonl(1000 + rand()%1000);
  }

  memcpy(packet + 42, data, sizeof(data));
}

/*
 * Print payload whose format is 32-bit value
 */
void printData(unsigned char *packet) {
  int i;
  unsigned int *data = (int *)(packet + 42);

  printf("-------- Data --------\n");
  for (i=0; i<DATA_LEN; i++) {
    printf("%010u", ntohl(data[i]));
    if (i%8 == 7) {
      printf("\n");
    } else if (i%4 == 3) {
      printf("  ");
    } else {
      printf(" ");
    }
  }
  printf("\n");
}

/*
 * Print payload whose format is 8-bit value
 */
void printByte(unsigned char *packet) {
  int i;
  unsigned char *p = packet;

  printf("-------- byte --------\n");
  for (i=0; i<128; i++) {
    printf("%02x", *(p++));
    if (i%16 == 15) {
      printf("\n");
    } else if (i%8 == 7) {
      printf("  ");
    } else {
      printf(" ");
    }
  }
  printf("\n");
}
