#include "ping.h"            

struct proto	proto_v4 = { proc_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP };

#ifdef	IPV6
struct proto	proto_v6 = { proc_v6, send_v6, NULL, NULL, 0, IPPROTO_ICMPV6 };
#endif

int datalen = 56; //发送包长度默认56

int pingnum = 4; //ping的次数  
int getpostcount = 0; //接收到的包数目
double rttcount = 0; //总往返时延
int ttlnum = 64; //默认TTL

int action = 0;


void printhelp(){
	printf("-h	显示帮助信息 \n");	
	//printf("-v  发送IP题头中的服务类型（TOS），默认值是0 \n");
	printf("-b	ping广播地址，只用于IPv4 \n");
	printf("-t	设置ttl值，只用于IPv4\n");
	printf("-q	安静模式。不显示每个收到的包的分析结果，只在结束时，显示汇总结果 \n\n");	
	printf("-n	设置发送次数 \n");
	printf("-s	设置发送包大小 \n");
}

int main(int argc, char **argv)
{
	int				c;
	struct addrinfo	*ai;	//地址信息

	opterr = 0;		/* don't want getopt() writing to stderr */
	while ( (c = getopt(argc, argv, "vhqbn:t:s:")) != -1) { //解析命令可选项
		switch (c) {
		case 'v': //发送回响请求消息的IP标题中的“服务类型（TOS）”字段值，默认值是0
			verbose++;	//.h定义过
			break;
		case'h'://帮助模式
			printf("\n");	
			printhelp();
			exit(0);
			break;
		case'q'://安静模式
			action = 1;
			break;
		case'b'://广播模式
			action = 2;
			break;
		case't'://设置ttl值
			action = 3;
			ttlnum = atoi(argv[optind-1]); 
			printf("%d\n", ttlnum);
			break;
		case'n'://设置发送包数目
			pingnum = atoi(argv[optind-1]);
			break;
		case's'://设置发送包大小
			datalen = atoi(argv[optind-1]);
			if(datalen>1024||datalen<0)
				printf("数据包长度应大于0小于1024\n");
			break;
		case'?':
			err_quit("未知的命令 请输入-h来查看帮助\n");
		}
	}

	printf("函数参数数量: %d\n", argc - 1);
	printf("目的地址: %s\n", argv[optind]);

	if (optind != argc-1)	//调用一次getopt，optind会加一。
		err_quit("usage: ping [ -v ] <hostname>");
	host = argv[optind]; //把参数地址赋给host

	pid = getpid();
	signal(SIGALRM, sig_alrm);  

	ai = host_serv(host, NULL, 0, 0);

	printf("ping %s (%s): %d data bytes\n", ai->ai_canonname,
		   Sock_ntop_host(ai->ai_addr, ai->ai_addrlen), datalen);

		/* 4initialize according to protocol */
	if (ai->ai_family == AF_INET) {
		pr = &proto_v4;
#ifdef	IPV6
	} else if (ai->ai_family == AF_INET6) {
		pr = &proto_v6;
		if (IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)
								 ai->ai_addr)->sin6_addr)))
			err_quit("cannot ping IPv4-mapped IPv6 address");
#endif
	} else
		err_quit("unknown address family %d", ai->ai_family);

	pr->sasend = ai->ai_addr;
	pr->sarecv = calloc(1, ai->ai_addrlen); //在内存的动态存储区中分配n个长度为size的连续空间
	pr->salen = ai->ai_addrlen;

	readloop();

	exit(0);
}


void proc_v4(char *ptr, ssize_t len, struct timeval *tvrecv){//ICMP解包
	int				hlen1, icmplen;
	double			rtt;
	struct ip		*ip;
	struct icmp		*icmp;
	struct timeval	*tvsend;

	ip = (struct ip *) ptr;		/* start of IP header */
	hlen1 = ip->ip_hl << 2;		/* length of IP header */

	icmp = (struct icmp *) (ptr + hlen1);	/* start of ICMP header */
	if ( (icmplen = len - hlen1) < 8) //判断长度是否为ICMP包长度
		err_quit("icmplen (%d) < 8", icmplen);

	if (icmp->icmp_type == ICMP_ECHOREPLY) {//判断该包是ICMP回送回答包且该包是我们发出去的
		if (icmp->icmp_id != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (icmplen < 16)
			err_quit("icmplen (%d) < 16", icmplen);

		tvsend = (struct timeval *) icmp->icmp_data; 
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;
	
	if(action != 1){ //ttl：time to live, rtt: Round-Trip Time往返时延
		printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n", 
		icmplen, Sock_ntop_host(pr->sarecv, pr->salen),icmp->icmp_seq, ip->ip_ttl, rtt);
		//Sock_ntop_host：把一个套接字地址结构中的主机部分转换成表达式
		rttcount += rtt;
		getpostcount ++;
		}
	else{
		rttcount += rtt;
		getpostcount ++;
		}

	} else if (verbose) {
		printf("  %d bytes from %s: type = %d, code = %d\n",
				icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp->icmp_type, icmp->icmp_code);
	}
}

void proc_v6(char *ptr, ssize_t len, struct timeval* tvrecv) {
#ifdef	IPV6
	int					hlen1, icmp6len;
	double				rtt;
	struct ip6_hdr		*ip6;
	struct icmp6_hdr	*icmp6;
	struct timeval		*tvsend;

	ip6 = (struct ip6_hdr *) ptr;		/* start of IPv6 header */
	hlen1 = sizeof(struct ip6_hdr);
	if (ip6->ip6_nxt != IPPROTO_ICMPV6)
		err_quit("next header not IPPROTO_ICMPV6");

	icmp6 = (struct icmp6_hdr *) (ptr + hlen1);
	if ( (icmp6len = len - hlen1) < 8)
		err_quit("icmp6len (%d) < 8", icmp6len);

	if (icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
		if (icmp6->icmp6_id != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (icmp6len < 16)
			err_quit("icmp6len (%d) < 16", icmp6len);

		tvsend = (struct timeval *) (icmp6 + 1);
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		printf("%d bytes from %s: seq=%u, hlim=%d, rtt=%.3f ms\n",
				icmp6len, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp6->icmp6_seq, ip6->ip6_hlim, rtt);

	} else if (verbose) {
		printf("  %d bytes from %s: type = %d, code = %d\n",
				icmp6len, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp6->icmp6_type, icmp6->icmp6_code);
	}
#endif	/* IPV6 */
}

unsigned short in_cksum(unsigned short *addr, int len) {//校验和算法
	int  nleft = len;
	int  sum = 0;
	unsigned short  *w = addr;
	unsigned short  answer = 0;

	/*把ICMP报头二进制数据以2字节为单位累加起来*/
	while (nleft > 1)  {
			sum += *w++;
			nleft -= 2;
	}
	/*若ICMP报头为奇数个字节，会剩下一字节。
	把最后一个字节视为一个2字节数据的高字节，这个2字节数据的低字节为0，继续累加*/
	if (nleft == 1) {
			*(unsigned char *)(&answer) = *(unsigned char *)w ;
			sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);     // 高16位加低16位
	sum += (sum >> 16);                     // 累加
	answer = ~sum;                          // 截取16位
	return(answer);
}

void send_v4(void) {//ICMP发包
	int			len;
	struct icmp	*icmp;

	icmp = (struct icmp *) sendbuf; 
	icmp->icmp_type = ICMP_ECHO; //类型：询问报文，回送请求
	icmp->icmp_code = 0; //同上
	icmp->icmp_id = pid; //标识符
	icmp->icmp_seq = nsent++; //报文序列号
	gettimeofday((struct timeval *) icmp->icmp_data, NULL);//控制发送长度
	
	len = 8 + datalen;		/* checksum ICMP header and data */
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short *) icmp, len); //计算校验和

	sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
}

void send_v6() {
#ifdef	IPV6
	int					len;
	struct icmp6_hdr	*icmp6;

	icmp6 = (struct icmp6_hdr *) sendbuf;
	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_id = pid;
	icmp6->icmp6_seq = nsent++;
	gettimeofday((struct timeval *) (icmp6 + 1), NULL);

	len = 8 + datalen;		/* 8-byte ICMPv6 header */

	sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
		/* 4kernel calculates and stores checksum for us */
#endif	/* IPV6 */
}

void readloop(void){
	int				size;
	char			recvbuf[BUFSIZE];
	socklen_t		len;
	ssize_t			n;
	struct timeval	tval;

	// 数据包套接字（SOCK_DGRAM）：无连接、不可靠的socket套接字，支持并发多socket
	//SOCK_DGRAM和SOCK_RAW 这个两种套接字可以使用函数sendto()来发送数据，使用recvfrom()函数接受数据，recvfrom()接受来自制定IP地址的发送方的数据。
	sockfd = socket(pr->sasend->sa_family, SOCK_DGRAM, pr->icmpproto);//套接字描述符
	printf("socketfd:%d\n", sockfd);
	setuid(getuid());		/* don't need special permissions any more */

	//int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
	//printf("socketfd:%d\n", sockfd);

	if(action == 2){
		printf("开始广播\n");
		if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST,&action, sizeof(action)) < 0) {
			perror ("无法广播");
			exit(2);//结束并返回2
		}
		printf("test\n");	
	}

	if (action == 3) {//设置ttl
		int ittl = ttlnum;
		if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL,&ttlnum, 1) == -1) {
			perror ("ping: can't set multicast time-to-live");
			exit(2);
		}
		if (setsockopt(sockfd, IPPROTO_IP, IP_TTL,&ittl, sizeof(ittl)) == -1) {
			perror ("ping: can't set unicast time-to-live");
			exit(2);
		}
	}

	size = 60 * 1024;		/* OK if setsockopt fails   60k */
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

	sig_alrm(SIGALRM);		/* send first packet */
	
	int i=0;
	for ( i = 0; i < pingnum; i++ ) {//控制接受几次数据包
		len = pr->salen;
		n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			else
				err_sys("recvfrom error");
		}
		gettimeofday(&tval, NULL);
		//指针指向结构体的一个函数，recvbuf中存放udp接受信息的数据
		(*pr->fproc)(recvbuf, n, &tval);
	}
	printf("一共发送 %d 数据包; 接收到 %d; 总rtt= %.3f ms; 平均rtt= %.3f ms\n",
	pingnum,getpostcount,rttcount,rttcount/getpostcount);
}


void
sig_alrm(int signo)
{
        (*pr->fsend)();

        alarm(1);
        return;         /* probably interrupts recvfrom() */
}

void
tv_sub(struct timeval *out, struct timeval *in)
{
	if ( (out->tv_usec -= in->tv_usec) < 0) {	/* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

char *
sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
    static char str[128];               /* Unix domain is largest */

        switch (sa->sa_family) {
        case AF_INET: {
                struct sockaddr_in      *sin = (struct sockaddr_in *) sa;

                if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
                        return(NULL);
                return(str);
        }

#ifdef  IPV6
        case AF_INET6: {
                struct sockaddr_in6     *sin6 = (struct sockaddr_in6 *) sa;

                if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL)
                        return(NULL);
                return(str);
        }
#endif
#ifdef  HAVE_SOCKADDR_DL_STRUCT
        case AF_LINK: {
                struct sockaddr_dl      *sdl = (struct sockaddr_dl *) sa;

                if (sdl->sdl_nlen > 0)
                        snprintf(str, sizeof(str), "%*s",
                                         sdl->sdl_nlen, &sdl->sdl_data[0]);
                else
                        snprintf(str, sizeof(str), "AF_LINK, index=%d", sdl->sdl_index);
                return(str);
        }
#endif
        default:
                snprintf(str, sizeof(str), "sock_ntop_host: unknown AF_xxx: %d, len %d",
                                 sa->sa_family, salen);
                return(str);
        }
    return (NULL);
}

char *
Sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
        char    *ptr;

        if ( (ptr = sock_ntop_host(sa, salen)) == NULL)
                err_sys("sock_ntop_host error");        /* inet_ntop() sets errno */
        return(ptr);
}

struct addrinfo *
host_serv(const char *host, const char *serv, int family, int socktype)
{
        int                             n;
        struct addrinfo hints, *res;

        bzero(&hints, sizeof(struct addrinfo));
        hints.ai_flags = AI_CANONNAME;  /* always return canonical name */
        hints.ai_family = family;               /* AF_UNSPEC, AF_INET, AF_INET6, etc. */
        hints.ai_socktype = socktype;   /* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

        if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
                return(NULL);

        return(res);    /* return pointer to first on linked list */
}
/* end host_serv */

static void err_doit(int errnoflag, int level, const char *fmt, va_list ap) {
        int             errno_save, n;
        char    buf[MAXLINE];

        errno_save = errno;             /* value caller might want printed */
#ifdef  HAVE_VSNPRINTF
        vsnprintf(buf, sizeof(buf), fmt, ap);   /* this is safe */
#else
        vsprintf(buf, fmt, ap);                                 /* this is not safe */
#endif
        n = strlen(buf);
        if (errnoflag)
                snprintf(buf+n, sizeof(buf)-n, ": %s", strerror(errno_save));
        strcat(buf, "\n");

        if (daemon_proc) {
            //    syslog(level, buf);
        } else {
                fflush(stdout);         /* in case stdout and stderr are the same */
                fputs(buf, stderr);
                fflush(stderr);
        }
        return;
}

/* Fatal error unrelated to a system call.
 * Print a message and terminate. */

void err_quit(const char *fmt, ...)
{
        va_list         ap;

        va_start(ap, fmt);
        err_doit(0, LOG_ERR, fmt, ap);
        va_end(ap);
        exit(1);
}

/* Fatal error related to a system call.
 * Print a message and terminate. */

void err_sys(const char *fmt, ...)
{
        va_list         ap;

        va_start(ap, fmt);
        err_doit(1, LOG_ERR, fmt, ap);
        va_end(ap);
        exit(1);
}
