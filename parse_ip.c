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

#include "parse_ip.h"
#include "netstat.h"


int
parse_ip(ns, caplen, ip)
	NETSTAT *ns;
	int caplen;
	const struct ip *ip;
{
	int hdrlen = 0, len;
	const u_char *p;

	/* sanity check */
	if (!ip) return -1;

	if (ns) ns->ip_ver = ip->ip_v;

	if (ip->ip_v == 4) {
		struct ip_address *src = 0, *dst = 0;
		if (ns) {
			src = &ns->ip_src_addr;
			dst = &ns->ip_dst_addr;

			ns->ip_proto = ip->ip_p;
			src->ip_addr = ip->ip_src;
			dst->ip_addr = ip->ip_dst;

			ns->pkt_len = ntohs(ip->ip_len);
		}
		hdrlen = ip->ip_hl << 2;
		caplen -= hdrlen;
		if ((ntohs(ip->ip_off) & 0x1fff) == 0) {
			p = (const u_char *)ip + hdrlen;
			switch (ip->ip_p) {
			case IPPROTO_TCP:
#if defined(linux)
				len = ((const struct tcphdr *)p)->doff << 2;
#else
				len = ((const struct tcphdr *)p)->th_off << 2;
#endif
				hdrlen += len;
				caplen -= len;
				if (caplen >= 0 && src && dst) {
#if defined(linux)
					src->ip_port = ((const struct tcphdr *)p)->source;
					dst->ip_port = ((const struct tcphdr *)p)->dest;
#else
					src->ip_port = ((const struct tcphdr *)p)->th_sport;
					dst->ip_port = ((const struct tcphdr *)p)->th_dport;
#endif
				}
				break;
			case IPPROTO_UDP:
				len = sizeof(struct udphdr);
				hdrlen += len;
				caplen -= len;
				if (caplen >= 0 && src && dst) {
#if defined(linux)
					src->ip_port = ((const struct udphdr *)p)->source;
					dst->ip_port = ((const struct udphdr *)p)->dest;
#else
					src->ip_port = ((const struct udphdr *)p)->uh_sport;
					dst->ip_port = ((const struct udphdr *)p)->uh_dport;
#endif
				}
				break;
			case IPPROTO_ICMP:
				len = (u_char *)((const struct icmp *)p)->icmp_data - p;
				hdrlen += len;
				caplen -= len;
				if (caplen >= 0 && src) {
					src->ip_port =
					((((const struct icmp *)p)->icmp_type << 8) |
					 ((const struct icmp *)p)->icmp_code) + 1;
				}
				break;
			}
		}
	}
#ifdef INET6
	else if (ip->ip_v == 6) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)ip;
		struct ip_address *src = 0, *dst = 0;
		if (ns) {
			src = &ns->ip_src_addr;
			dst = &ns->ip_dst_addr;

			ns->ip_proto = ip6->ip6_nxt;
			src->ip6_addr = ip6->ip6_src;
			dst->ip6_addr = ip6->ip6_dst;

			ns->pkt_len = sizeof(struct ip6_hdr) + ntohs(ip6->ip6_plen);
		}
		hdrlen = sizeof(struct ip6_hdr);
		caplen -= hdrlen;
		p = (const u_char *)ip6 + hdrlen;
		switch (ip6->ip6_nxt) {
		case IPPROTO_TCP:
#if defined(linux)
			len = ((const struct tcphdr *)p)->doff << 2;
#else
			len = ((const struct tcphdr *)p)->th_off << 2;
#endif
			hdrlen += len;
			caplen -= len;
			if (caplen >= 0 && src && dst) {
#if defined(linux)
				src->ip_port = ((const struct tcphdr *)p)->source;
				dst->ip_port = ((const struct tcphdr *)p)->dest;
#else
				src->ip_port = ((const struct tcphdr *)p)->th_sport;
				dst->ip_port = ((const struct tcphdr *)p)->th_dport;
#endif
			}
			break;
		case IPPROTO_UDP:
			len = sizeof(struct udphdr);
			hdrlen += len;
			caplen -= len;
			if (caplen >= 0 && src && dst) {
#if defined(linux)
				src->ip_port = ((const struct udphdr *)p)->source;
				dst->ip_port = ((const struct udphdr *)p)->dest;
#else
				src->ip_port = ((const struct udphdr *)p)->uh_sport;
				dst->ip_port = ((const struct udphdr *)p)->uh_dport;
#endif
			}
			break;
		case IPPROTO_ICMPV6:
			len = sizeof(struct icmp6_hdr);
			hdrlen += len;
			caplen -= len;
			if (caplen >= 0 && src) {
				src->ip_port =
				((((const struct icmp6_hdr *)p)->icmp6_type << 8) |
				 ((const struct icmp6_hdr *)p)->icmp6_code) + 1;
			}
			break;
		}
	}
#endif
	else {
		/* unknown IP version */
		return -1;
	}

	if (ns) {
		ns->pkt_cnt = 1;
		if (ns->pkt_len >= hdrlen)
			ns->data_len = ns->pkt_len - hdrlen;
	}
	return hdrlen;
}

