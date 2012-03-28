/*
 *	Copyright (c) 2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifdef	HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <pthread.h>

#include "cisco_netflow.h"
#include "trafshow.h"
#include "session.h"
#include "netstat.h"
#include "show_dump.h"
#include "addrtoname.h"


static void read_netflow(SESSION *sd, const unsigned char *data, int len);
static PCAP_HANDLER *match_feeder(PCAP_HANDLER *ph_list, const struct sockaddr *sa);
static void parse_netflow(PCAP_HANDLER *ph, const unsigned char *data, int len);
static char *get_name(const struct sockaddr *sa, char *dst, int size);
static void fprint_tcpflags(FILE *fp, int flags);
static void fprint_tos(FILE *fp, int tos);
static void dump_netflow_v1(const CNF_DATA_V1 *data);
static void dump_netflow_v5(const CNF_DATA_V5 *data);
static void dump_netflow_v7(const CNF_DATA_V7 *data);

int
cisco_netflow_init(ph_list, port)
	PCAP_HANDLER **ph_list;
	int port;
{
	SESSION *sd;
	int sock, on = 1;
	socklen_t slen;
	static struct sockaddr_in sin; /* why static? */

	if (!ph_list) return -1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);

	if ((sd = session_open(-1, 0, DataSequence)) == 0) {
		perror("session_open");
		return -1;
	}
	sock = session_sock(sd);

	slen = sizeof(on);
#ifdef	SO_REUSEPORT
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, slen) < 0) {
		perror("setsockopt SO_REUSEPORT");
		return -1;
	}
#elif	SO_REUSEADDR
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, slen) < 0) {
		perror("setsockopt SO_REUSEADDR");
		return -1;
	}
#endif
	slen = sizeof(sin);
	if (bind(sock, (struct sockaddr *)&sin, slen) < 0) {
		perror("bind");
		return -1;
	}

	session_setcallback(sd, 0, 0, read_netflow);
	session_setcookie(sd, ph_list);
	return 0;
}

static PCAP_HANDLER *
match_feeder(ph, sa)
	PCAP_HANDLER *ph;
	const struct sockaddr *sa;
{
	const pcap_addr_t *ap;

	if (!sa) return 0;

	for (; ph; ph = ph->next) {
		if (ph->pcap) /* skip pcap devices */
			continue;

		for (ap = ph->addr; ap; ap = ap->next) {
			if (!ap->addr || ap->addr->sa_family != sa->sa_family)
				continue;

			if (ap->addr->sa_family == AF_INET) {
				if (!memcmp(&((struct sockaddr_in *)ap->addr)->sin_addr,
					    &((struct sockaddr_in *)sa)->sin_addr,
					    sizeof(struct in_addr)))
					return ph;
			}
#ifdef	INET6
			else if (ap->addr->sa_family == AF_INET6) {
				if (!memcmp(&((struct sockaddr_in6 *)ap->addr)->sin6_addr,
					    &((struct sockaddr_in6 *)sa)->sin6_addr,
					    sizeof(struct in6_addr)))
					return ph;
			}
#endif
		}
	}
	return 0;
}

static char *
get_name(sa, dst, size)
	const struct sockaddr *sa;
	char *dst;
	int size;
{
	struct hostent *hp = 0;

	if (!sa) return 0;

	if (sa->sa_family == AF_INET) {
		hp = gethostbyaddr((char *)&((struct sockaddr_in *)sa)->sin_addr,
				   sizeof(struct in_addr), AF_INET);
	}
#ifdef	INET6
	else if (sa->sa_family == AF_INET6) {
		hp = gethostbyaddr((char *)&((struct sockaddr_in6 *)sa)->sin6_addr,
				   sizeof(struct in6_addr), AF_INET6);
	}
#endif
	if (hp) {
		int i;
		for (i = 0; i < size-1; i++) {
			if (hp->h_name[i] == '\0' || hp->h_name[i] == '.')
				break;
			dst[i] = hp->h_name[i];
		}
		dst[i] = '\0';
		return dst;
	}
	return 0;
}

static void
read_netflow(sd, data, len)
	SESSION *sd;
	const unsigned char *data;
	int len;
{
	const struct sockaddr *from;
	PCAP_HANDLER *ph, **ph_list = (PCAP_HANDLER **)session_cookie(sd);

	/* sanity check */
	if (!ph_list || !data || len < sizeof(CNF_HDR_V1))
		return;

	if ((from = session_from(sd)) == 0)
		return; /* should not happen */

	if ((ph = match_feeder(*ph_list, from)) == 0) { /* insert new one */
		int cnt = 0;
		PCAP_HANDLER *ph_prev = 0;
		char buf[256];
		pcap_addr_t *ap;

		for (ph = *ph_list; ph; ph = ph->next) {
			if (!ph->pcap) cnt++;
			ph_prev = ph;
		}

		if ((ph = (PCAP_HANDLER *)malloc(sizeof(PCAP_HANDLER))) == 0) {
			perror("malloc");
			return;
		}
		memset(ph, 0, sizeof(PCAP_HANDLER));

		ph->masklen = aggregate;
		if (!get_name(from, buf, sizeof(buf)))
			sprintf(buf, "netflow%d", cnt);
		ph->name = strdup(buf);

		sprintf(buf, "Netflow V%d", ntohs(((CNF_HDR_V1 *)data)->version));
		ph->descr = strdup(buf);

		if ((ap = (pcap_addr_t *)malloc(sizeof(struct pcap_addr))) != 0) {
			memset(ap, 0, sizeof(struct pcap_addr));
			if ((ap->addr = (struct sockaddr *)malloc(sizeof(struct sockaddr))) == 0) {
				perror("malloc");
				return;
			}
			memcpy(ap->addr, from, sizeof(struct sockaddr));
		}
		ph->addr = ap;

		if ((ph->ns_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t))) == 0) {
			perror("malloc");
			return;
		}
		pthread_mutex_init(ph->ns_mutex, 0);

		ph->prev = ph_prev;
		if (ph_prev)
			ph_prev->next = ph;
		else    *ph_list = ph;
	}

	parse_netflow(ph, data, len);
}

static void
parse_netflow(ph, data, len)
	PCAP_HANDLER *ph;
	const unsigned char *data;
	int len;
{
	struct timeval now;
	int version, counter, msec, hdrlen, dump_it;
	CNF_HDR_V1 *v1h;
	CNF_HDR_V5 *v5h;
	CNF_HDR_V7 *v7h;
	CNF_DATA_V1 *v1d = 0;
	CNF_DATA_V5 *v5d = 0;
	CNF_DATA_V7 *v7d = 0;
	NETSTAT ns;

	v1h = (CNF_HDR_V1 *)data;
	if (!v1h || len < sizeof(CNF_HDR_V1))
		return;

	version = ntohs(v1h->version);
	counter = ntohs(v1h->counter);
	if (version == 1) {
		v1d = (CNF_DATA_V1 *)(data + sizeof(CNF_HDR_V1));
		len -= sizeof(sizeof(CNF_HDR_V1));
		len /= sizeof(CNF_DATA_V1);
	} else if (version == 5) {
		v5h = (CNF_HDR_V5 *)data;
		v5d = (CNF_DATA_V5 *)(data + sizeof(CNF_HDR_V5));
		len -= sizeof(sizeof(CNF_HDR_V5));
		len /= sizeof(CNF_DATA_V5);
	} else if (version == 7) {
		v7h = (CNF_HDR_V7 *)data;
		v7d = (CNF_DATA_V7 *)(data + sizeof(CNF_HDR_V7));
		len -= sizeof(sizeof(CNF_HDR_V7));
		len /= sizeof(CNF_DATA_V7);
	} else	return;

	gettimeofday(&now, 0);

	while (counter-- > 0 && len-- > 0) {
		struct ip_address *src = &ns.ip_src_addr;
		struct ip_address *dst = &ns.ip_dst_addr;

		memset(&ns, 0, sizeof(NETSTAT));
		ns.ip_ver = 4; /* XXX what about IPv6? */
		ns.mtime = now;
		msec = 0;
		dump_it = 0;

		if (version == 1 && v1d) {
			ns.ip_proto = v1d->proto;

			src->ip_addr.s_addr = v1d->src_addr;
			src->ip_port = v1d->src_port;

			dst->ip_addr.s_addr = v1d->dst_addr;
			dst->ip_port = v1d->dst_port;

			ns.pkt_cnt = ntohl(v1d->dpkts);
			ns.pkt_len = ntohl(v1d->doctets);

			msec = ntohl(v1d->lasttime) - ntohl(v1d->firsttime);

		} else if (version == 5 && v5d) {
			ns.ip_proto = v5d->proto;

			src->ip_addr.s_addr = v5d->src_addr;
			src->ip_port = v5d->src_port;

			dst->ip_addr.s_addr = v5d->dst_addr;
			dst->ip_port = v5d->dst_port;

			ns.pkt_cnt = ntohl(v5d->dpkts);
			ns.pkt_len = ntohl(v5d->doctets);

			msec = ntohl(v5d->lasttime) - ntohl(v5d->firsttime);

		} else if (version == 7 && v7d) {
			ns.ip_proto = v7d->proto;

			src->ip_addr.s_addr = v7d->src_addr;
			src->ip_port = v7d->src_port;

			dst->ip_addr.s_addr = v7d->dst_addr;
			dst->ip_port = v7d->dst_port;

			ns.pkt_cnt = ntohl(v7d->dpkts);
			ns.pkt_len = ntohl(v7d->doctets);

			msec = ntohl(v7d->lasttime) - ntohl(v7d->firsttime);
		}

		/* suggest data length (dirty fake) */
		hdrlen = sizeof(struct ip);
		switch (ns.ip_proto) {
		case IPPROTO_TCP:
			hdrlen += sizeof(struct tcphdr);
			break;
		case IPPROTO_UDP:
			hdrlen += sizeof(struct udphdr);
			break;
		case IPPROTO_ICMP:
			hdrlen += sizeof(struct icmp);
			break;
		}
		hdrlen *= ns.pkt_cnt;
		if (ns.pkt_len >= hdrlen)
			ns.data_len = ns.pkt_len - hdrlen;

		if (msec > 0) {
			ns.pkt_cnt_rate = ns.pkt_cnt * 1000 / msec;
			ns.pkt_len_rate = ns.pkt_len * 1000 / msec;
			ns.data_len_rate = ns.data_len * 1000 / msec;
		}

		pcap_save(ph, &ns);

		if (cisco_netflow_dump && ph->name &&
		    !strcmp(cisco_netflow_dump, ph->name) &&
		    netstat_match(&ns, dump_match)) {
			dump_it++;
		}
		if (version == 1 && v1d) {
			if (dump_it) dump_netflow_v1(v1d);
			v1d++;
		} else if (version == 5 && v5d) {
			if (dump_it) dump_netflow_v5(v5d);
			v5d++;
		} else if (version == 7 && v7d) {
			if (dump_it) dump_netflow_v7(v7d);
			v7d++;
		}
	}
}

static void
fprint_tcpflags(fp, flags)
	FILE *fp;
	int flags;
{
	fprintf(fp, "TCPflags: %02x", flags);

	if (flags & 0x01) fprintf(fp, " FIN");
	if (flags & 0x02) fprintf(fp, " SYN");
	if (flags & 0x04) fprintf(fp, " RST");
	if (flags & 0x08) fprintf(fp, " PUSH");
	if (flags & 0x10) fprintf(fp, " ACK");
	if (flags & 0x20) fprintf(fp, " URG");

	fprintf(fp, "\n");
}

static void
fprint_tos(fp, tos)
	FILE *fp;
	int tos;
{
	fprintf(fp, "TOS:      %02x", tos);

	switch (tos & 0xe0) { /* precedence bits */
	case 0xe0: fprintf(fp, " NETCONTROL"); break;
	case 0xc0: fprintf(fp, " INTERNETCONTROL"); break;
	case 0xa0: fprintf(fp, " CRITIC_ECP"); break;
	case 0x80: fprintf(fp, " FLASHOVERRIDE"); break;
	case 0x60: fprintf(fp, " FLASH"); break;
	case 0x40: fprintf(fp, " IMMEDIATE"); break;
	case 0x20: fprintf(fp, " PRIORITY"); break;
	}
	tos &= 0x1e; /* type of service bits */
	if (tos & 0x10) fprintf(fp, " LOWDELAY");
	if (tos & 0x08) fprintf(fp, " THROUGHPUT");
	if (tos & 0x04) fprintf(fp, " RELIABILITY");
	if (tos & 0x02) fprintf(fp, " LOWCOST");

	fprintf(fp, "\n");
}

static void
dump_netflow_v1(dp)
	const CNF_DATA_V1 *dp;
{
	FILE *fp;

	if (!dump_file || (fp = fopen(dump_file, "a")) == 0)
		return;

	fprintf(fp, "\nNetflow:  V1\n");
	fprintf(fp, "SrcAddr:  %s\n", intoa(dp->src_addr));
	fprintf(fp, "DstAddr:  %s\n", intoa(dp->dst_addr));
	fprintf(fp, "NextHop:  %s\n", intoa(dp->nexthop));
	fprintf(fp, "InputIf:  %d\n", (int)ntohs(dp->ifin));
	fprintf(fp, "OutputIf: %d\n", (int)ntohs(dp->ifout));
	fprintf(fp, "Packets:  %u\n", (u_int32_t)ntohl(dp->dpkts));
	fprintf(fp, "Octets:   %u\n", (u_int32_t)ntohl(dp->doctets));
	fprintf(fp, "First:    %u\n", (u_int32_t)ntohl(dp->firsttime));
	fprintf(fp, "Last:     %u\n", (u_int32_t)ntohl(dp->lasttime));
	if (dp->proto == IPPROTO_TCP) {
		fprintf(fp, "SrcPort:  %s\n",  tcpport_string(ntohs(dp->src_port)));
		fprintf(fp, "DstPort:  %s\n",  tcpport_string(ntohs(dp->dst_port)));
	} else if (dp->proto == IPPROTO_UDP) {
		fprintf(fp, "SrcPort:  %s\n",  udpport_string(ntohs(dp->src_port)));
		fprintf(fp, "DstPort:  %s\n",  udpport_string(ntohs(dp->dst_port)));
	} else {
		fprintf(fp, "SrcPort:  %d\n",  (int)ntohs(dp->src_port));
		fprintf(fp, "DstPort:  %d\n",  (int)ntohs(dp->dst_port));
	}
	fprintf(fp, "Protocol: %s\n", ipproto_string(dp->proto));
	fprint_tos(fp, dp->tos);
	fprint_tcpflags(fp, dp->flags);

	(void)fclose(fp);
}

static void
dump_netflow_v5(dp)
	const CNF_DATA_V5 *dp;
{
	FILE *fp;

	if (!dump_file || (fp = fopen(dump_file, "a")) == 0)
		return;

	fprintf(fp, "\nNetflow:  V5\n");
	fprintf(fp, "SrcAddr:  %s\n", intoa(dp->src_addr));
	fprintf(fp, "DstAddr:  %s\n", intoa(dp->dst_addr));
	fprintf(fp, "NextHop:  %s\n", intoa(dp->nexthop));
	fprintf(fp, "InputIf:  %d\n", (int)ntohs(dp->ifin));
	fprintf(fp, "OutputIf: %d\n", (int)ntohs(dp->ifout));
	fprintf(fp, "Packets:  %u\n", (u_int32_t)ntohl(dp->dpkts));
	fprintf(fp, "Octets:   %u\n", (u_int32_t)ntohl(dp->doctets));
	fprintf(fp, "First:    %u\n", (u_int32_t)ntohl(dp->firsttime));
	fprintf(fp, "Last:     %u\n", (u_int32_t)ntohl(dp->lasttime));
	if (dp->proto == IPPROTO_TCP) {
		fprintf(fp, "SrcPort:  %s\n",  tcpport_string(ntohs(dp->src_port)));
		fprintf(fp, "DstPort:  %s\n",  tcpport_string(ntohs(dp->dst_port)));
	} else if (dp->proto == IPPROTO_UDP) {
		fprintf(fp, "SrcPort:  %s\n",  udpport_string(ntohs(dp->src_port)));
		fprintf(fp, "DstPort:  %s\n",  udpport_string(ntohs(dp->dst_port)));
	} else {
		fprintf(fp, "SrcPort:  %d\n",  (int)ntohs(dp->src_port));
		fprintf(fp, "DstPort:  %d\n",  (int)ntohs(dp->dst_port));
	}
	fprint_tcpflags(fp, dp->flags);
	fprintf(fp, "Protocol: %s\n", ipproto_string(dp->proto));
	fprint_tos(fp, dp->tos);

	fprintf(fp, "SrcASN:   %d\n", (int)ntohs(dp->src_as));
	fprintf(fp, "DstASN:   %d\n", (int)ntohs(dp->dst_as));
	fprintf(fp, "SrcMask:  %d\n", (int)dp->src_mask);
	fprintf(fp, "DstMask:  %d\n", (int)dp->dst_mask);

	(void)fclose(fp);
}

static void
dump_netflow_v7(dp)
	const CNF_DATA_V7 *dp;
{
	FILE *fp;

	if (!dump_file || (fp = fopen(dump_file, "a")) == 0)
		return;

	fprintf(fp, "\nNetflow:  V7\n");
	fprintf(fp, "SrcAddr:  %s\n", intoa(dp->src_addr));
	fprintf(fp, "DstAddr:  %s\n", intoa(dp->dst_addr));
	fprintf(fp, "NextHop:  %s\n", intoa(dp->nexthop));
	fprintf(fp, "InputIf:  %d\n", (int)ntohs(dp->ifin));
	fprintf(fp, "OutputIf: %d\n", (int)ntohs(dp->ifout));
	fprintf(fp, "Packets:  %u\n", (u_int32_t)ntohl(dp->dpkts));
	fprintf(fp, "Octets:   %u\n", (u_int32_t)ntohl(dp->doctets));
	fprintf(fp, "First:    %u\n", (u_int32_t)ntohl(dp->firsttime));
	fprintf(fp, "Last:     %u\n", (u_int32_t)ntohl(dp->lasttime));
	if (dp->proto == IPPROTO_TCP) {
		fprintf(fp, "SrcPort:  %s\n",  tcpport_string(ntohs(dp->src_port)));
		fprintf(fp, "DstPort:  %s\n",  tcpport_string(ntohs(dp->dst_port)));
	} else if (dp->proto == IPPROTO_UDP) {
		fprintf(fp, "SrcPort:  %s\n",  udpport_string(ntohs(dp->src_port)));
		fprintf(fp, "DstPort:  %s\n",  udpport_string(ntohs(dp->dst_port)));
	} else {
		fprintf(fp, "SrcPort:  %d\n",  (int)ntohs(dp->src_port));
		fprintf(fp, "DstPort:  %d\n",  (int)ntohs(dp->dst_port));
	}
	fprint_tcpflags(fp, dp->flags);
	fprintf(fp, "Protocol: %s\n", ipproto_string(dp->proto));
	fprint_tos(fp, dp->tos);

	fprintf(fp, "SrcASN:   %d\n", (int)ntohl(dp->src_as));
	fprintf(fp, "DstASN:   %d\n", (int)ntohl(dp->dst_as));
	fprintf(fp, "SrcMask:  %d\n", (int)dp->src_mask);
	fprintf(fp, "DstMask:  %d\n", (int)dp->dst_mask);

	fprintf(fp, "RouterSc: %s\n", intoa(dp->router_sc));

	(void)fclose(fp);
}

