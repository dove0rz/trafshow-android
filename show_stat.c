/*
 *	Copyright (c) 1998,2004 Rinet Corp., Novosibirsk, Russia
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
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "show_stat.h"
#include "trafshow.h"
#include "screen.h"
#include "selector.h"
#include "netstat.h"
#include "getkey.h"
#include "addrtoname.h"

ShowStatMode show_stat_mode = Size;
static int find_backflow(NETSTAT **list, int items, NETSTAT *at);
static void sort_backflow(NETSTAT **list, int items);

static void
scale_size(addr, prot, data, rate)
	int *addr, *prot, *data, *rate;
{
	*addr	= line_factor * (double)SHOW_STAT_ADDR;
	*prot	= line_factor * (double)SHOW_STAT_PROT;
	*data	= line_factor * (double)SHOW_STAT_DATA;
	*rate	= line_factor * (double)SHOW_STAT_RATE;
}

static int
compare_pkt_len(p1, p2)
	register const NETSTAT **p1, **p2;
{
	if ((*p1)->pkt_len > (*p2)->pkt_len) return -1;
	if ((*p1)->pkt_len < (*p2)->pkt_len) return 1;
	return 0;
}

static int
compare_data_len(p1, p2)
	register const NETSTAT **p1, **p2;
{
	if ((*p1)->data_len > (*p2)->data_len) return -1;
	if ((*p1)->data_len < (*p2)->data_len) return 1;
	return 0;
}

static int
compare_pkt_cnt(p1, p2)
	register const NETSTAT **p1, **p2;
{
	if ((*p1)->pkt_cnt > (*p2)->pkt_cnt) return -1;
	if ((*p1)->pkt_cnt < (*p2)->pkt_cnt) return 1;
	return 0;
}

static int
find_backflow(list, items, at)
	NETSTAT **list;
	int items;
	NETSTAT *at;
{
	int i;

	/* sanity check */
	if (!list || items < 1 || !at)
		return -1;

	for (i = 0; i < items; i++) {
		if (netstat_bidir(at, list[i]))
			return i;
	}
	return -1;
}

/* too bad implementation -- it take alot of CPU cycles like deadloop. XXX */
static void
sort_backflow(list, items)
	NETSTAT **list;
	int items;
{
	int i = 0, at;
	NETSTAT *ns;

	while (i < items-1) {
		ns = list[i++];
		if ((at = find_backflow(&list[i], items - i, ns)) < 0)
			continue;
		if (at) {
			ns = list[i + at];
			memmove(&list[i + 1], &list[i], at * sizeof(NETSTAT *));
			list[i] = ns;
		}
		i++;
	}
}

/*
 * Pretty print an Internet address (net address + port).
 */
static char *
ip_print(ver, proto, addr, dst, size)
	int ver;
	int proto;
	const struct ip_address *addr;
	char *dst;
	int size;
{
	const char *cp = 0;
	char buf[100];

	if (ver == 4 && addr->ip_addr.s_addr) {
		/*cp = intoa(addr->ip_addr.s_addr);*/
		cp = ipaddr_string(&addr->ip_addr);
	}
#ifdef	INET6
	else if (ver == 6 && !IN6_IS_ADDR_UNSPECIFIED(&addr->ip6_addr)) {
		/*cp = inet_ntop(AF_INET6, &addr->ip6_addr, buf, sizeof(buf));*/
		cp = ip6addr_string(&addr->ip6_addr);
	}
#endif

	if (cp) {
		(void)strncpy(dst, cp, size);
		dst[size-1] = '\0';
	} else	snprintf(dst, size, "IPv%d", ver);

	if (addr->ip_port) {
		char pb[20];
		int len;
		switch (proto) {
		case IPPROTO_TCP:
			if (nflag) {
				sprintf(pb, "%d", ntohs(addr->ip_port));
				cp = pb;
			} else	cp = tcpport_string(ntohs(addr->ip_port));
			break;
		case IPPROTO_UDP:
			if (nflag) {
				sprintf(pb, "%d", ntohs(addr->ip_port));
				cp = pb;
			} else	cp = udpport_string(ntohs(addr->ip_port));
			break;
		case IPPROTO_ICMP:
			if (nflag) {
				sprintf(pb, "%04x", addr->ip_port - 1);
				cp = pb;
			} else	cp = icmp_string(addr->ip_port - 1);
			break;
#ifdef INET6
		case IPPROTO_ICMPV6:
			if (nflag) {
				sprintf(pb, "%04x", addr->ip_port - 1);
				cp = pb;
			} else	cp = icmpv6_string(addr->ip_port - 1);
			break;
#endif
		default: /* nonsense, but be strong */
			sprintf(pb, "%d", ntohs(addr->ip_port));
			cp = pb;
		}
		buf[0] = ':'; // by dove
		(void)strncpy(&buf[1], cp, 10);
		buf[11] = '\0';
		len = strlen(buf);
		if (strlen(dst) + len < size)
			(void)strcat(dst, buf);
		else	(void)strcpy(&dst[size - len - 1], buf);
	}
	return dst;
}

static char *
sap_print(addr, sap, dst, size)
	const u_char *addr;
	u_char sap;
	char *dst;
	int size;
{
	char buf[20];
	int len;

	(void)strncpy(dst, etheraddr_string(addr), size);
	dst[size-1] = '\0';

	buf[0] = '/';
	if (nflag)
		sprintf(&buf[1], "sap-%02x", sap & 0xff);
	else	(void)strncpy(&buf[1], llcsap_string(sap), 10);
	buf[11] = '\0';
	len = strlen(buf);
	if (strlen(dst) + len < size)
		(void)strcat(dst, buf);
	else	(void)strcpy(&dst[size - len - 1], buf);
	return dst;
}

void
hdr2str(nh, src_buf, src_len, dst_buf, dst_len, proto_buf, proto_len)
	const struct netstat_header *nh;
	char *src_buf, *dst_buf, *proto_buf;
	int src_len, dst_len, proto_len;
{
	const NETSTAT *ns;

	if (src_buf) *src_buf = '\0';
	if (dst_buf) *dst_buf = '\0';
	if (proto_buf) *proto_buf = '\0';

	/* sanity check */
	if (!nh) return;

	ns = (NETSTAT *)nh;

	if (ns->ip_ver) {
		if (src_buf && src_len > 1) {
			ip_print(ns->ip_ver, ns->ip_proto, &ns->ip_src_addr,
				 src_buf, src_len);
		}
		if (dst_buf && dst_len > 1) {
			ip_print(ns->ip_ver, ns->ip_proto, &ns->ip_dst_addr,
				 dst_buf, dst_len);
		}
		if (proto_buf && proto_len > 1) {
			if (nflag)
				snprintf(proto_buf, proto_len, "%d", (int)ns->ip_proto);
			else	(void)strncpy(proto_buf, ipproto_string(ns->ip_proto),
					      proto_len);
			proto_buf[proto_len-1] = '\0';
		}
	} else if (ntohs(ns->eth_type) > 1500) { /* Ethernet II (DIX) */
		if (src_buf && src_len > 1) {
			(void)strncpy(src_buf, etheraddr_string(ns->eth_src_addr),
				      src_len);
			src_buf[src_len-1] = '\0';
		}
		if (dst_buf && dst_len > 1) {
			(void)strncpy(dst_buf, etheraddr_string(ns->eth_dst_addr),
				      dst_len);
			dst_buf[dst_len-1] = '\0';
		}
		if (proto_buf && proto_len > 1) {
			if (nflag)
				snprintf(proto_buf, proto_len, "%04x", ntohs(ns->eth_type));
			else	(void)strncpy(proto_buf, ethertype_string(ns->eth_type),
					      proto_len);
			proto_buf[proto_len-1] = '\0';
		}
	} else if (ns->eth_ssap == ns->eth_dsap) {
		if (src_buf && src_len > 1) {
			(void)strncpy(src_buf, etheraddr_string(ns->eth_src_addr),
				      src_len);
			src_buf[src_len-1] = '\0';
		}
		if (dst_buf && dst_len > 1) {
			(void)strncpy(dst_buf, etheraddr_string(ns->eth_dst_addr),
				      dst_len);
			dst_buf[dst_len-1] = '\0';
		}
		if (proto_buf && proto_len > 1) {
			if (nflag)
				snprintf(proto_buf, proto_len, "sap-%02x",
					 (int)(ns->eth_ssap & 0xff));
			else	(void)strncpy(proto_buf, llcsap_string(ns->eth_ssap),
					      proto_len);
			proto_buf[proto_len-1] = '\0';
		}
	} else {
		if (src_buf && src_len > 1) {
			sap_print(ns->eth_src_addr, ns->eth_ssap,
				  src_buf, src_len);
		}
		if (dst_buf && dst_len > 1) {
			sap_print(ns->eth_dst_addr, ns->eth_dsap,
				  dst_buf, dst_len);
		}
		if (proto_buf && proto_len > 1) {
			(void)strncpy(proto_buf, "802.3", proto_len);
			proto_buf[proto_len-1] = '\0';
		}
	}
}

static int
show_stat_header(dst, size, ph)
	char *dst;
	int size;
	const PCAP_HANDLER *ph;
{
	int addr_sz, prot_sz, data_sz, rate_sz;
	char src_buf[100], dst_buf[100];
	const char *data_ptr, *rate_ptr;

	/* sanity check */
	if (!dst || size < 1 || !ph)
		return 0;

	scale_size(&addr_sz, &prot_sz, &data_sz, &rate_sz);

	(void)strcpy(src_buf, "Source");
	(void)strcpy(dst_buf, "Destination");
	if (ph->masklen >= 0) {
		sprintf(src_buf + strlen(src_buf), "/%d", ph->masklen);
		sprintf(dst_buf + strlen(dst_buf), "/%d", ph->masklen);
	}

	data_ptr = rate_ptr = "?";
	switch (show_stat_mode) {
	case Size:
		data_ptr = "Size";
		rate_ptr = "CPS";
		break;
	case Data:
		data_ptr = "Data";
		rate_ptr = "CPS";
		break;
	case Packets:
		data_ptr = "Packets";
		rate_ptr = "PPS";
		break;
	}
	snprintf(dst, size,
		 "%-*.*s %-*.*s %-*.*s %-*.*s %-*.*s",
		 addr_sz, addr_sz,	src_buf,
		 addr_sz, addr_sz,	dst_buf,
		 prot_sz, prot_sz,	"Protocol",
		 data_sz, data_sz,	data_ptr,
		 rate_sz, rate_sz,	rate_ptr);
	return 0;
}

static int
show_stat_line(dst, size, ns_list, idx)
	char *dst;
	int size;
	const NETSTAT **ns_list;
	int idx;
{
	int addr_sz, prot_sz, data_sz, rate_sz;
	const NETSTAT *ns;
	char src_buf[100], dst_buf[100], proto_buf[20], data_buf[20], rate_buf[20];

	/* sanity check */
	if (!dst || size < 1 || !ns_list)
		return 0;

	ns = ns_list[idx];

	scale_size(&addr_sz, &prot_sz, &data_sz, &rate_sz);

	hdr2str(&ns->ns_hdr,
		src_buf, MIN(sizeof(src_buf), addr_sz + 1),
		dst_buf, MIN(sizeof(dst_buf), addr_sz + 1),
		proto_buf, MIN(sizeof(proto_buf), prot_sz + 1));

	data_buf[0] = '\0';
	rate_buf[0] = '\0';
	switch (show_stat_mode) {
	case Size:
		if (ns->pkt_len >= 10000)
			snprintf(data_buf, sizeof(data_buf), "%uK", ns->pkt_len / 1024);
		else	snprintf(data_buf, sizeof(data_buf), "%u", ns->pkt_len);

		if (ns->pkt_len_rate >= 10000)
			snprintf(rate_buf, sizeof(rate_buf), "%uK", ns->pkt_len_rate / 1024);
		else if (ns->pkt_len_rate > 0)
			snprintf(rate_buf, sizeof(rate_buf), "%u", ns->pkt_len_rate);
		break;
	case Data:
		if (ns->data_len >= 10000)
			snprintf(data_buf, sizeof(data_buf), "%uK", ns->data_len / 1024);
		else	snprintf(data_buf, sizeof(data_buf), "%u", ns->data_len);

		if (ns->data_len_rate >= 10000)
			snprintf(rate_buf, sizeof(rate_buf), "%uK", ns->data_len_rate / 1024);
		else if (ns->data_len_rate > 0)
			snprintf(rate_buf, sizeof(rate_buf), "%u", ns->data_len_rate);
		break;
	case Packets:
		snprintf(data_buf, sizeof(data_buf), "%u", ns->pkt_cnt);

		if (ns->pkt_cnt_rate > 0)
			snprintf(rate_buf, sizeof(rate_buf), "%u", ns->pkt_cnt_rate);
		break;
	}

	snprintf(dst, size,
		 "%-*.*s %-*.*s %-*.*s %-*.*s %-*.*s",
		 addr_sz, addr_sz,	src_buf,
		 addr_sz, addr_sz,	dst_buf,
		 prot_sz, prot_sz,	proto_buf,
		 data_sz, data_sz,	data_buf,
		 rate_sz, rate_sz,	rate_buf);

	return ns->attr;
}

static int
show_stat_footer(dst, size, ph)
	char *dst;
	int size;
	const PCAP_HANDLER *ph;
{
	const PCAP_HANDLER *top;
	int addr_sz, prot_sz, data_sz, rate_sz, depth;
	u_int64_t total = 0, rate = 0;
	char stat_buf[50], data_buf[20], rate_buf[20];

	/* sanity check */
	if (!dst || size < 1 || !ph)
		return 0;

	scale_size(&addr_sz, &prot_sz, &data_sz, &rate_sz);

	depth = 0;
	for (top = ph->top; top; top = top->top) depth++;
	if (depth) {
		snprintf(stat_buf, sizeof(stat_buf), "%d Flows (depth %d)",
			 netstat_count(ph), depth);
	} else {
		snprintf(stat_buf, sizeof(stat_buf), "%d Flows",
			 netstat_count(ph));
	}

	switch (show_stat_mode) {
	case Size:
		total = ph->pkt_len;
		rate = ph->pkt_len_rate;
		break;
	case Data:
		total = ph->data_len;
		rate = ph->data_len_rate;
		break;
	case Packets:
		total = ph->pkt_cnt;
		rate = ph->pkt_cnt_rate;
		break;
	}

	if (total >= 10000000)
		snprintf(data_buf, sizeof(data_buf), "%uM",
			 (unsigned int)(total / (1024 * 1024)));
	else if (total >= 10000)
		snprintf(data_buf, sizeof(data_buf), "%uK",
			 (unsigned int)(total / 1024));
	else	snprintf(data_buf, sizeof(data_buf), "%u",
			 (unsigned int)total);

	if (rate >= 10000000)
		snprintf(rate_buf, sizeof(rate_buf), "%uM",
			 (unsigned int)(rate / (1024 * 1024)));
	else if (rate >= 10000)
		snprintf(rate_buf, sizeof(rate_buf), "%uK",
			 (unsigned int)(rate / 1024));
	else	snprintf(rate_buf, sizeof(rate_buf), "%u",
			 (unsigned int)rate);

	snprintf(dst, size,
		 "%-*.*s %-*.*s %-*.*s %-*.*s %-*.*s",
		 addr_sz, addr_sz,	ph->name,
		 addr_sz, addr_sz,	stat_buf,
		 prot_sz, prot_sz,	"Total:",
		 data_sz, data_sz,	data_buf,
		 rate_sz, rate_sz,	rate_buf);
	return 0;
}

int
show_stat_input(ph, ch)
	PCAP_HANDLER *ph;
	int ch;
{
	switch (ch) {
	case '[':       /* rotate list mode left */
	case K_LEFT:
		if (show_stat_mode == Size)
			show_stat_mode = Packets;
		else	show_stat_mode--;
		return 1;
	case ']':       /* rotate list mode right */
	case K_RIGHT:
		if (show_stat_mode == Packets)
			show_stat_mode = Size;
		else	show_stat_mode++;
		return 1;
	case K_CTRL('R'): /* reset current netstat hash */
		if (ph) {
			netstat_purge(ph, 0);
			show_stat_list(ph);
			return 1;
		}
		break;
	case K_TAB:	/* follow to backflow */
		if (ph) {
			SELECTOR *sp = show_stat_selector(ph);
			int idx = selector_get(sp);

			if (idx >= 0) {
				NETSTAT **ns_list = (NETSTAT **)sp->list;
				const NETSTAT *ns = ns_list[idx];

				for (idx = 0; idx < sp->items; idx++) {
					if (netstat_bidir(ns, ns_list[idx])) {
						selector_set(idx, sp);
						return 1;
					}
				}
			}
		}
		break;
	}
	return 0;
}

SELECTOR *
show_stat_selector(ph)
	PCAP_HANDLER *ph;
{
	if (!ph) return 0;
	if (!ph->selector && (ph->selector = selector_init()) != 0) {
		ph->selector->get_header = show_stat_header;
		ph->selector->get_line = show_stat_line;
		ph->selector->get_footer = show_stat_footer;
	}
	return ph->selector;
}

NETSTAT *
show_stat_get(ph, idx)
	PCAP_HANDLER *ph;
	int idx;
{
	SELECTOR *sp;
	NETSTAT **ns_list;

	/* sanity check */
	if (!ph || idx < 0 || (sp = show_stat_selector(ph)) == 0 || idx >= sp->items)
		return 0;

	ns_list = (NETSTAT **)sp->list;
	return ns_list[idx];
}

int
show_stat_search(ph, str)
	PCAP_HANDLER *ph;
	const char *str;
{
	SELECTOR *sp;
	NETSTAT **ns_list;
	const NETSTAT *ns;
	int idx;
	char src_buf[100], dst_buf[100], proto_buf[20];

	/* sanity check */
	if (!ph || !str || *str == '\0' || (sp = show_stat_selector(ph)) == 0)
		return -1;

	ns_list = (NETSTAT **)sp->list;
	for (idx = 0; idx < sp->items; idx++) {
		ns = ns_list[idx];
		hdr2str(&ns->ns_hdr,
			src_buf, sizeof(src_buf),
			dst_buf, sizeof(dst_buf),
			proto_buf, sizeof(proto_buf));
		if (strstr(src_buf, str) ||
		    strstr(dst_buf, str) ||
		    strstr(proto_buf, str))
			return idx;
	}
	return -1;
}

SELECTOR *
show_stat_list(ph)
	PCAP_HANDLER *ph;
{
	SELECTOR *sp;
	int cnt;

	/* sanity check */
	if (!ph || (sp = show_stat_selector(ph)) == 0)
		return 0;

	sp->header = ph;
	sp->footer = ph;

	if ((cnt = netstat_fetch((NETSTAT ***)&sp->list, ph)) < 0)
		return sp;

	sp->items = cnt;
	if (cnt < 2) /* no sorting required */
		return sp;

	/* sort it accroding to current mode */
	switch (show_stat_mode) {
	case Size:
		qsort(sp->list, sp->items, sizeof(NETSTAT *), compare_pkt_len);
		break;
	case Data:
		qsort(sp->list, sp->items, sizeof(NETSTAT *), compare_data_len);
		break;
	case Packets:
		qsort(sp->list, sp->items, sizeof(NETSTAT *), compare_pkt_cnt);
		break;
	}
	if (popbackflow)
		sort_backflow(sp->list, sp->items);

	return sp;
}

