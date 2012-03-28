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
#ifdef	linux
#include <linux/if.h>
#else
#include <net/if.h>
#endif
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <string.h>
#include <pcap.h>

#include "parse_dl.h"
#include "parse_ip.h"
#include "netstat.h"
#include "ethertype.h"
#include "sll.h"

#ifndef	DLT_LINUX_SLL
#define	DLT_LINUX_SLL	113
#endif

struct ether_dot1q_header {
	u_char dhost[ETHER_ADDR_LEN];
	u_char shost[ETHER_ADDR_LEN];
	u_int16_t encap_proto;
	u_int16_t tag;
	u_int16_t proto;
};

int
is_parse_dl(type)
	int type;
{
	return (type == DLT_NULL ||
		type == DLT_LOOP ||
		type == DLT_EN10MB ||
		type == DLT_SLIP ||
		type == DLT_PPP_ETHER ||
		type == DLT_PPP ||
		type == DLT_RAW ||
		type == DLT_C_HDLC ||
		type == DLT_PPP_SERIAL ||
		type == DLT_LINUX_SLL);
}

const char *
parse_dl_name(type)
	int type;
{
	switch (type) {
	case DLT_NULL:
	case DLT_LOOP:
		return "Loopback";
	case DLT_EN10MB:
		return "Ethernet";
	case DLT_SLIP:
		return "SLIP";
	case DLT_PPP_ETHER:
		return "PPP over Ethernet";
	case DLT_PPP:
		return "Async PPP";
	case DLT_RAW:
		return "raw IP";
	case DLT_C_HDLC:
		return "Cisco HDLC";
	case DLT_PPP_SERIAL:
		return "Sync PPP";
	case DLT_LINUX_SLL:
		return "Linux cooked socket";
	}
	return "Unknown";
}

int
parse_dl(ns, dlt, caplen, pktlen, pkt)
	NETSTAT *ns;
	int dlt, caplen, pktlen;
	const u_char *pkt;
{
	const struct ether_header *ether = 0;
	const struct ip *ip = 0;
	const u_char *p = pkt;
	u_int length = pktlen;
	u_int type, hdrlen;
	u_char dsap, ssap;

	/* sanity check */
	if (!pkt) return -1;

	switch (dlt) {
	case DLT_NULL:
	case DLT_LOOP:
		if (caplen < 4)
			return -1;
		memcpy((u_char *)&type, p, sizeof(type));
		if (type & 0xffff0000) { /* swap bytes */
			type = (((type & 0xff) << 24) |
				((type & 0xff00) << 8) |
				((type & 0xff0000) >> 8) |
				((type >> 24) & 0xff));
		}
		if (type != AF_INET && type != AF_INET6)
			return -1;
		p += 4;
		ip = (const struct ip *)p;
		caplen -= 4;
		length -= 4;
		break;

	case DLT_EN10MB:
		hdrlen = sizeof(struct ether_header);
		if (caplen < hdrlen)
			return -1;
		ether = (struct ether_header *)p;
		if (ns) {
#ifdef	HAVE_ETHER_ADDR
			memcpy(ns->eth_src_addr,
			       &ether->ether_shost, sizeof(struct ether_addr));
			memcpy(ns->eth_dst_addr,
			       &ether->ether_dhost, sizeof(struct ether_addr));
#else
			memcpy(ns->eth_src_addr,
			       ether->ether_shost, ETHER_ADDR_LEN);
			memcpy(ns->eth_dst_addr,
			       ether->ether_dhost, ETHER_ADDR_LEN);
#endif
			ns->eth_type = ether->ether_type;
		}
		type = ntohs(ether->ether_type);
		if (type <= ETHERMTU) {
			/* IEEE 802.3 frame: the type is data length */
			if (caplen < hdrlen + 3)
				return -1;

			/* extract SAP (Service Access Point) IDs */
			dsap = p[hdrlen];
			ssap = p[hdrlen + 1];
			if (ns) {
				ns->eth_dsap = dsap;
				ns->eth_ssap = ssap;
				ns->data_len = type;
			}
			type = 0; /* no type known yet */

			hdrlen += 3;	/* skip 802.2 LLC header */

			if (dsap == 0x06 && ssap == 0x06) {
				/* 802.3/802.2 encapsulated IP */
				type = ETHERTYPE_IP;

			} else if (dsap == 0xAA && ssap == 0xAA) {
				if (caplen < hdrlen + 5)
					return -1;

				/* extract encap type after 3-bytes OUI */
				type = *(u_int16_t *)(p + hdrlen + 3);
				if (ns) ns->eth_type = type;
				type = ntohs(type);

				hdrlen += 5;	/* skip 802.2 SNAP header */
			}
		} else if (type == ETHERTYPE_8021Q) {
			hdrlen = sizeof(struct ether_dot1q_header);
			if (caplen < hdrlen)
				return -1;
			if (ns) ns->eth_tag = ((struct ether_dot1q_header *)p)->tag;
			type = ntohs(((struct ether_dot1q_header *)p)->proto);
		}
		p += hdrlen;
		if (type == ETHERTYPE_IP || type == ETHERTYPE_IPV6)
			ip = (const struct ip *)p;
		caplen -= hdrlen;
		length -= hdrlen;
		break;

	case DLT_SLIP:
		if (caplen < 16)
			return -1;
		p += 16;
		ip = (const struct ip *)p;
		caplen -= 16;
		length -= 16;
		break;

	case DLT_PPP_ETHER:
		if (caplen < 6 || p[1])
			return -1;
		p += 6;
		caplen -= 6;
		length -= 6;
		/* pass through */

	case DLT_PPP:
		if (caplen < 4)
			return -1;
		hdrlen = 0;
#ifdef SLC_BPFHDR
		if (dlt == DLT_PPP) {
			ip = (const struct ip *)(p + SLC_BPFHDR);/* skip bpf pseudo header */
			p += SLC_BPFHDRLEN; /* now pointer to link level header */
		}
#endif
		/* PPP address and PPP control fields may be present (-acfc) */
		if (p[0] == 0xff && p[1] == 0x03) {
			p += 2;
			hdrlen += 2;
		}
		/* retrive the protocol type */
		if (*p & 01) {	/* compressed protocol field (pfc) */
			type = *p++;
			hdrlen++;
		} else {	/* un-compressed protocol field (-pfc) */
			type = ntohs(*(u_int16_t *)p);
			p += 2;
			hdrlen += 2;
		}
		/* check for IP or IPv6 */
		if (type != 0x21 && type != 0x57 &&
		    type != ETHERTYPE_IP && type != ETHERTYPE_IPV6)
			return -1;
#ifdef SLC_BPFHDR
		if (dlt == DLT_PPP) {
			caplen -= SLC_BPFHDR;
			length -= SLC_BPFHDR;
		} else {
			ip = (const struct ip *)p;
			caplen -= hdrlen;
			length -= hdrlen;
		}
#else
		ip = (const struct ip *)p;
		caplen -= hdrlen;
		length -= hdrlen;
#endif
		break;

	case DLT_RAW:
		ip = (const struct ip *)p;
		break;

	case DLT_C_HDLC:
	case DLT_PPP_SERIAL:
		if (caplen < 4)
			return -1;
		/* check for UNICAST or BCAST */
		if (p[0] != 0x0f && p[0] != 0x8f)
			return -1;
		type = ntohs(*(u_int16_t *)&p[2]);
		if (type != ETHERTYPE_IP && type != ETHERTYPE_IPV6)
			return -1;
		p += 4;
		ip = (const struct ip *)p;
		caplen -= 4;
		length -= 4;
		break;

	case DLT_LINUX_SLL:
		if (caplen < SLL_HDR_LEN)
			return -1;
		if (ntohs(((struct sll_header *)p)->sll_halen) == ETHER_ADDR_LEN) {
			if (ns) {
				/* the source address is in the packet header */
				memcpy(ns->eth_src_addr,
				       ((struct sll_header *)p)->sll_addr,
				       ETHER_ADDR_LEN);
				/* just a fake the destination address */
				memset(ns->eth_dst_addr, 0, ETHER_ADDR_LEN);
				type = ntohs(((struct sll_header *)p)->sll_pkttype);
				if (type != LINUX_SLL_OUTGOING) {
					if (type == LINUX_SLL_BROADCAST)
						memset(ns->eth_dst_addr, 0xff,
						       ETHER_ADDR_LEN);
					else if (type == LINUX_SLL_MULTICAST)
						ns->eth_dst_addr[0] = 1;
					else	ns->eth_dst_addr[ETHER_ADDR_LEN-1] = 1;
				}
				ns->eth_type = ((struct sll_header *)p)->sll_protocol;
			}
			/* point somewhere to avoid return after switch() */
			ether = (struct ether_header *)p;
		}
		type = ntohs(((struct sll_header *)p)->sll_protocol);
		p += SLL_HDR_LEN;
		caplen -= SLL_HDR_LEN;
		length -= SLL_HDR_LEN;
		if (type == ETHERTYPE_IP || type == ETHERTYPE_IPV6)
			ip = (const struct ip *)p;
		break;

	default:
		/* Unknown or unsupported data link type */
		return -1;
	}

	if (!ether && !ip)
		return -1;

	if (caplen > length)
		caplen = length;

	if (ns) {
		if (!ns->pkt_cnt) ns->pkt_cnt = 1;
		if (!ns->pkt_len) ns->pkt_len = pktlen;
		if (!ns->data_len) ns->data_len = length;
	}

	hdrlen = (char *)p - (char *)pkt;
	if (ip && caplen >= sizeof(struct ip)) {
		int hlen = parse_ip(ns, caplen, ip);
		if (hlen > 0) hdrlen += hlen;
	}
	return hdrlen;
}

