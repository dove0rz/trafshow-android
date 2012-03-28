/*
 *	Copyright (c) 2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifndef	_NETSTAT_H_
#define	_NETSTAT_H_

#include <sys/types.h>
#include <sys/time.h>
#ifdef	linux
#include <linux/if.h>
#else
#include <net/if.h>
#endif
#include <netinet/in.h>
#include <netinet/if_ether.h>

#ifndef	IPPORT_RESERVED
#define	IPPORT_RESERVED	1024
#endif
#ifndef	IPPORT_DYNAMIC
#define	IPPORT_DYNAMIC	49152
#endif

/*
 * Any struct defined here is a storage contained all data.
 */

/*
 * Internet flow record address.
 */
struct ip_address {
	union {
		struct in_addr ipa4;
#ifdef	INET6
		struct in6_addr ipa6;
#endif
	} ipaddr;
	u_int16_t ip_port;
};

#define	ip_addr		ipaddr.ipa4
#ifdef	INET6
#define	ip6_addr	ipaddr.ipa6
#endif

/*
 * Internet flow record header.
 */
struct internet_header {
	u_int8_t ver;			/* ip version */
	u_int8_t proto;			/* ip protocol */
	struct ip_address src;		/* source ip address */
	struct ip_address dst;		/* destination ip address */
};

#ifndef	ETHER_ADDR_LEN
#ifdef	HAVE_ETHER_ADDR
#define	ETHER_ADDR_LEN	sizeof(struct ether_addr)
#else
#define	ETHER_ADDR_LEN	6
#endif
#endif

/*
 * Ethernet flow record header.
 */
struct ethernet_header {
	u_char src[ETHER_ADDR_LEN];	/* source ether address */
	u_char dst[ETHER_ADDR_LEN];	/* destination ether address */
	u_int16_t type;			/* ether type */
	union {
		u_int16_t tag;		/* ether dot1q tag */
		struct {		/* IEEE 802.3 LLC header */
			u_char ssap;	/* source SAP ID */
			u_char dsap;	/* destination SAP ID */
		} llc;
	} param;
};

#define	ETH_VIDOFTAG(tag)	((tag) & 0xfff)
#define	ETH_PRIOFTAG(tag)	(((tag) >> 13) & 7)
#define	ETH_CFIOFTAG(tag)	(((tag) >> 12) & 1)

struct netstat_header {
	struct ethernet_header en_hdr;	/* ether flow record header */
	struct internet_header in_hdr;	/* inet flow record header */
};

typedef	struct netstat {
	/* all header fields in network byte order */
	struct netstat_header ns_hdr; /* must be first in struct netstat! */

#define	eth_src_addr	ns_hdr.en_hdr.src
#define	eth_dst_addr	ns_hdr.en_hdr.dst
#define	eth_type	ns_hdr.en_hdr.type
#define	eth_tag		ns_hdr.en_hdr.param.tag
#define	eth_ssap	ns_hdr.en_hdr.param.llc.ssap
#define	eth_dsap	ns_hdr.en_hdr.param.llc.dsap

#define	ip_ver		ns_hdr.in_hdr.ver
#define	ip_proto	ns_hdr.in_hdr.proto
#define	ip_src_addr	ns_hdr.in_hdr.src
#define	ip_dst_addr	ns_hdr.in_hdr.dst

	/* all data fields in host byte order */
	struct timeval mtime;		/* last modification time */

	u_int32_t pkt_cnt;		/* packet counter */
	u_int32_t pkt_len;		/* length of ip packet */
	u_int32_t data_len;		/* length of ip data */

	u_int32_t gain_pkt_cnt;
	u_int32_t gain_pkt_len;
	u_int32_t gain_data_len;

	u_int32_t pkt_cnt_rate;		/* rate of packet counter */
	u_int32_t pkt_len_rate;		/* rate of packet length */
	u_int32_t data_len_rate;	/* rate of data length */

	int attr;			/* curses video attributes */

} NETSTAT;


struct pcap_handler;
void netstat_aggregate(struct netstat_header *nh, int bits);
int netstat_count(const struct pcap_handler *ph);
int netstat_insert(struct pcap_handler *ph, const NETSTAT *ns);
int netstat_find(struct pcap_handler *ph, NETSTAT *ns);
int netstat_purge(struct pcap_handler *ph, const struct timeval *at);
void netstat_free(struct pcap_handler *ph);
int netstat_match(const NETSTAT *ns1, const NETSTAT *ns2);
int netstat_bidir(const NETSTAT *ns1, const NETSTAT *ns2);
int netstat_fetch(NETSTAT **list[], struct pcap_handler *ph);

#endif	/* !_NETSTAT_H_ */
