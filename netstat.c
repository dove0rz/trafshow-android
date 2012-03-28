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
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "netstat.h"
#include "hashtab.h"
#include "trafshow.h"
#include "events.h" /* just for tv_diff() */
#include "colormask.h"
#include "addrtoname.h"

int
netstat_count(ph)
	const PCAP_HANDLER *ph;
{
	/* sanity check */
	if (!ph || !ph->ns_hash)
		return 0;

	return hcount(ph->ns_hash);
}

static void
maskit(bp, len, bits)
	u_int8_t *bp;
	int len, bits;
{
	register u_int8_t mask;
	register int i, j;

	for (i = 0; i < len; i++) {
		mask = 0;
		for (j = 0; j < 8 && bits > 0; j++, bits--) {
			mask >>= 1;
			mask |= 0x80;
		}
		bp[i] &= mask;
	}
}

void
netstat_aggregate(nh, bits)
	struct netstat_header *nh;
	int bits;
{
	/* sanity check */
	if (!nh || bits < 0)
		return;

	memset(&nh->en_hdr.src, 0, sizeof(nh->en_hdr.src));
	memset(&nh->en_hdr.dst, 0, sizeof(nh->en_hdr.dst));

	if (nh->in_hdr.ver) {
		struct ip_address *src = &nh->in_hdr.src;
		struct ip_address *dst = &nh->in_hdr.dst;

		maskit((u_int8_t *)&src->ipaddr, sizeof(src->ipaddr), bits);
		maskit((u_int8_t *)&dst->ipaddr, sizeof(dst->ipaddr), bits);

		/* guess server port */
		if (src->ip_port && dst->ip_port) {
			u_int16_t sport = ntohs(src->ip_port);
			u_int16_t dport = ntohs(dst->ip_port);

			if (isservport(sport))
				dst->ip_port = 0;
			else if (isservport(dport))
				src->ip_port = 0;
			else if (sport < IPPORT_RESERVED)
				dst->ip_port = 0;
			else if (dport < IPPORT_RESERVED)
				src->ip_port = 0;
			else if (sport >= IPPORT_DYNAMIC)
				src->ip_port = 0;
			else if (dport >= IPPORT_DYNAMIC)
				dst->ip_port = 0;
			else if (sport > dport)
				src->ip_port = 0;
			else	dst->ip_port = 0;
		}
	}
}

static int
htab_insert(ht, ns)
	struct htab *ht;
	const NETSTAT *ns;
{
	ub1 *key;
	ub4 keyl;
	int op;
	NETSTAT *dp;

	key = (ub1 *)&ns->ns_hdr;
	keyl = sizeof(ns->ns_hdr);
	if ((op = hadd(ht, key, keyl, 0)) < 0)
		return -1;

	if (op) { /* OK, new item inserted */
		if ((dp = (NETSTAT *)malloc(sizeof(NETSTAT))) == 0) {
			hdel(ht);
			return -1;
		}
		memcpy(dp, ns, sizeof(NETSTAT));
		dp->gain_pkt_cnt = ns->pkt_cnt;
		dp->gain_pkt_len = ns->pkt_len;
		dp->gain_data_len = ns->data_len;
		dp->attr = colormask(&dp->ns_hdr);

		hkey(ht) = (ub1 *)&dp->ns_hdr;
		hstuff(ht) = dp;
		return 1;
	}
	/* Failed because already in cache -- update it */

	if ((dp = (NETSTAT *)hstuff(ht)) == 0)
		return 0; /* should not happen */

	dp->pkt_cnt += ns->pkt_cnt;
	dp->pkt_len += ns->pkt_len;
	dp->data_len += ns->data_len;

	dp->gain_pkt_cnt += ns->pkt_cnt;
	dp->gain_pkt_len += ns->pkt_len;
	dp->gain_data_len += ns->data_len;

	if (ns->pkt_cnt_rate || ns->pkt_len_rate || ns->data_len_rate) {
		dp->mtime = ns->mtime;

		dp->pkt_cnt_rate = ns->pkt_cnt_rate;
		dp->pkt_len_rate = ns->pkt_len_rate;
		dp->data_len_rate = ns->data_len_rate;

	} else if ((op = tv_diff(&dp->mtime, &ns->mtime)) >= 1000) {
		dp->mtime = ns->mtime;

		dp->gain_pkt_cnt = dp->gain_pkt_cnt * 1000 / op;
		if (dp->gain_pkt_cnt) {
			dp->pkt_cnt_rate = dp->gain_pkt_cnt;
			dp->gain_pkt_cnt = 0;
		}
		dp->gain_pkt_len = dp->gain_pkt_len * 1000 / op;
		if (dp->gain_pkt_len) {
			dp->pkt_len_rate = dp->gain_pkt_len;
			dp->gain_pkt_len = 0;
		}
		dp->gain_data_len = dp->gain_data_len * 1000 / op;
		if (dp->gain_data_len) {
			dp->data_len_rate = dp->gain_data_len;
			dp->gain_data_len = 0;
		}
	}
	return 0;
}

int
netstat_insert(ph, ns)
	PCAP_HANDLER *ph;
	const NETSTAT *ns;
{
	int op;
	NETSTAT ns_buf;

	/* sanity check */
	if (!ph || !ns) {
		errno = EINVAL;
		return -1;
	}
	if (!ph->ns_hash && (ph->ns_hash = hcreate(65536)) == 0)
		return -1;

	if (ph->masklen >= 0) {
		memcpy(&ns_buf, ns, sizeof(NETSTAT));
		netstat_aggregate(&ns_buf.ns_hdr, ph->masklen);
		ns = &ns_buf;
	}
	if (ph->ns_mutex) pthread_mutex_lock(ph->ns_mutex);

	op = htab_insert(ph->ns_hash, ns);

	if (ph->ns_mutex) pthread_mutex_unlock(ph->ns_mutex);
	return op;
}

int
netstat_find(ph, ns)
	PCAP_HANDLER *ph;
	NETSTAT *ns; /* IN/OUT */
{
	struct htab *ht;
	ub1 *key;
	ub4 keyl;
	NETSTAT *found;
	int ok = 0;

	/* sanity check */
	if (!ph || !ns || netstat_count(ph) < 1)
		return 0;

	if (ph->ns_mutex) pthread_mutex_lock(ph->ns_mutex);
	ht = ph->ns_hash;

	key = (ub1 *)&ns->ns_hdr;
	keyl = sizeof(ns->ns_hdr);
	if (hfind(ht, key, keyl) && (found = hstuff(ht)) != 0) {
		ok = 1;
		*ns = *found;
	}

	if (ph->ns_mutex) pthread_mutex_unlock(ph->ns_mutex);
	return ok;
}

int
netstat_purge(ph, at)
	PCAP_HANDLER *ph;
	const struct timeval *at;
{
	struct htab *ht;
	int op, cnt = 0;
	NETSTAT *ns;

	/* sanity check */
	if (!ph) {
		errno = EINVAL;
		return -1;
	}
	if (netstat_count(ph) < 1)
		return 0;

	if (ph->ns_mutex) pthread_mutex_lock(ph->ns_mutex);
	ht = ph->ns_hash;

	op = hfirst(ht);
	while (op && hcount(ht) > 0) {
		ns = hstuff(ht);
		if (!ns) { /* should not happen */
			op = hdel(ht);
		} else if (!at || timercmp(&ns->mtime, at, <)) {
			free(ns);
			op = hdel(ht);
			cnt++;
		} else {
			op = hnext(ht);
		}
	}
	if (ph->ns_mutex) pthread_mutex_unlock(ph->ns_mutex);
	return cnt;
}

void
netstat_free(ph)
	PCAP_HANDLER *ph;
{
	struct htab *ht;

	/* sanity check */
	if (!ph) return;

	netstat_purge(ph, 0);

	if (ph->ns_mutex) pthread_mutex_lock(ph->ns_mutex);
	ht = ph->ns_hash;
	ph->ns_hash = 0;
	if (ht)	hdestroy(ht);
	if (ph->ns_mutex) pthread_mutex_unlock(ph->ns_mutex);
}

int
netstat_match(p1, p2)
	register const NETSTAT *p1, *p2;
{
	/* sanity check */
	if (!p1 || !p2) return 0;

	return !memcmp(&p1->ns_hdr, &p2->ns_hdr, sizeof(struct netstat_header));
}

int
netstat_bidir(p1, p2)
	register const NETSTAT *p1, *p2;
{
	/* sanity check */
	if (!p1 || !p2) return 0;

	if (p1->ip_ver) {
		if (p1->ip_ver == p2->ip_ver &&
		    p1->ip_proto == p2->ip_proto &&
		    !memcmp(&p1->ip_src_addr, &p2->ip_dst_addr,
			    sizeof(struct ip_address)) &&
		    !memcmp(&p2->ip_src_addr, &p1->ip_dst_addr,
			    sizeof(struct ip_address)))
			return 1;
	} else if (!p2->ip_ver) {
		if (p1->eth_type == p2->eth_type &&
		    !memcmp(p1->eth_src_addr, p2->eth_dst_addr,
			    ETHER_ADDR_LEN) &&
		    !memcmp(p2->eth_src_addr, p1->eth_dst_addr,
			    ETHER_ADDR_LEN))
			return 1;
	}
	return 0;
}

int
netstat_fetch(list, ph)
	NETSTAT **list[];
	PCAP_HANDLER *ph;
{
	struct htab *ht;
	int op, cnt, i;
	NETSTAT *ns, **array;

	/* sanity check */
	if (!list || !ph) {
		errno = EINVAL;
		return -1;
	}

	if ((cnt = netstat_count(ph)) < 1) {
		/* free previous */
		if (*list) free(*list);
		*list = 0;
		return 0;
	}
	if ((array = (NETSTAT **)malloc(cnt * sizeof(NETSTAT *))) == 0)
		return -1;

	if (ph->ns_mutex) pthread_mutex_lock(ph->ns_mutex);
	ht = ph->ns_hash;

	/* reset total statistics */
	ph->pkt_cnt = 0;
	ph->pkt_len = 0;
	ph->data_len = 0;

	ph->pkt_cnt_rate = 0;
	ph->pkt_len_rate = 0;
	ph->data_len_rate = 0;

	op = hfirst(ht);
	i = 0;
	while (op && i < cnt) {
		ns = hstuff(ht);
		if (ns) {
			array[i++] = ns;

			/* collect total statistics */
			ph->pkt_cnt += ns->pkt_cnt;
			ph->pkt_len += ns->pkt_len;
			ph->data_len += ns->data_len;

			ph->pkt_cnt_rate += ns->pkt_cnt_rate;
			ph->pkt_len_rate += ns->pkt_len_rate;
			ph->data_len_rate += ns->data_len_rate;
		}
		op = hnext(ht);
	}
	/* free previous */
	if (*list) free(*list);
	*list = array;

	if (ph->ns_mutex) pthread_mutex_unlock(ph->ns_mutex);
	return i;
}

