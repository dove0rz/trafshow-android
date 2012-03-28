/*
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  Internet, ethernet, port, and protocol string to address
 *  and address to string conversion routines

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/tcpdump/addrtoname.c,v 1.96.2.3 2003/12/15 04:02:53 guy Exp $ (LBL)";
#endif
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/types.h>                  /* concession to AIX */
#include <sys/time.h>
#include <sys/socket.h>
#ifdef	linux
#include <linux/if.h>
#else
#include <net/if.h>
#endif
#include <netinet/in.h>
#include <netinet/if_ether.h>
#ifdef	HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif

#include <arpa/inet.h>

#include <pcap.h>
#include <pcap-namedb.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "addrtoname.h"
#include "ethertype.h"
#include "domain_resolver.h"

#ifndef NTOHL
#define NTOHL(x)	(x) = ntohl(x)
#define NTOHS(x)	(x) = ntohs(x)
#define HTONL(x)	(x) = htonl(x)
#define HTONS(x)	(x) = htons(x)
#endif

/* dirty fake */
#define	error(s)	{ perror(s); exit(1); }

struct tok {
	int v;			/* value */
	const char *s;		/* string */
};

/*
 * hash tables for whatever-to-name translations
 *
 * XXX there has to be error checks against strdup(3) failure
 */

#define HASHNAMESIZE 4096

struct hnamemem {
	int resolving;
	u_int32_t addr;
	const char *name;
	struct hnamemem *nxt;
};

struct hnamemem hnametable[HASHNAMESIZE];
struct hnamemem tporttable[HASHNAMESIZE];
struct hnamemem uporttable[HASHNAMESIZE];
struct hnamemem servtable[HASHNAMESIZE];
struct hnamemem iprototable[HASHNAMESIZE];
struct hnamemem etypetable[HASHNAMESIZE];
struct hnamemem dnaddrtable[HASHNAMESIZE];
struct hnamemem llcsaptable[HASHNAMESIZE];
struct hnamemem ipxsaptable[HASHNAMESIZE];
struct hnamemem icmptable[HASHNAMESIZE];
#ifdef INET6
struct hnamemem icmpv6table[HASHNAMESIZE];
#endif

#ifdef INET6
struct h6namemem {
	struct in6_addr addr;
	char *name;
	struct h6namemem *nxt;
};

struct h6namemem h6nametable[HASHNAMESIZE];
#endif /* INET6 */

struct enamemem {
	u_short e_addr0;
	u_short e_addr1;
	u_short e_addr2;
	const char *e_name;
	u_char *e_nsap;			/* used only for nsaptable[] */
#define e_bs e_nsap			/* for bytestringtable */
	struct enamemem *e_nxt;
};

struct enamemem enametable[HASHNAMESIZE];
struct enamemem nsaptable[HASHNAMESIZE];
struct enamemem bytestringtable[HASHNAMESIZE];

struct protoidmem {
	u_int32_t p_oui;
	u_short p_proto;
	const char *p_name;
	struct protoidmem *p_nxt;
};

struct protoidmem protoidtable[HASHNAMESIZE];

char *
satoa(sa, dst, size)
	const struct sockaddr *sa;
	char *dst;
	int size;
{
	const char *cp = 0;
#ifdef INET6
	char buf[100];
#endif
	if (!sa || !dst || size < 1)
		return 0;
	if (sa->sa_family == AF_INET) {
		cp = intoa(((struct sockaddr_in *)sa)->sin_addr.s_addr);
	}
#ifdef INET6
	else if (sa->sa_family == AF_INET6) {
		cp = inet_ntop(AF_INET6,
			       &((struct sockaddr_in6 *)sa)->sin6_addr,
			       buf, sizeof(buf));
	}
#endif
#if defined(AF_LINK) && defined(LLADDR)
	else if (sa->sa_family == AF_LINK) {
		struct sockaddr_dl *sdl = (struct sockaddr_dl *)sa;
		if (sdl->sdl_alen > 0)
			cp = linkaddr_string((u_char *)LLADDR(sdl), sdl->sdl_alen);
	}
#endif
	if (!cp) return 0;
	(void)strncpy(dst, cp, size);
	dst[size-1] = '\0';
	return dst;
}

/*
 * A faster replacement for inet_ntoa().
 */
const char *
intoa(u_int32_t addr)
{
	register char *cp;
	register u_int byte;
	register int n;
	static char buf[sizeof(".xxx.xxx.xxx.xxx")];

	NTOHL(addr);
	cp = &buf[sizeof buf];
	*--cp = '\0';

	n = 4;
	do {
		byte = addr & 0xff;
		*--cp = byte % 10 + '0';
		byte /= 10;
		if (byte > 0) {
			*--cp = byte % 10 + '0';
			byte /= 10;
			if (byte > 0)
				*--cp = byte + '0';
		}
		*--cp = '.';
		addr >>= 8;
	} while (--n > 0);

	return cp + 1;
}

extern int nflag;

static void
name_resolved(unused, dd)
	void *unused;
	DOMAIN_DATA *dd;
{
	register struct hnamemem *p;

	/* sanity check */
	if (unused || !dd) return;

	p = &hnametable[dd->addr & (HASHNAMESIZE-1)];
	for (; p->nxt; p = p->nxt) {
		if (p->addr == dd->addr) {
			if (p->name) free((char *)p->name);
			p->name = strdup(dd->name);
			p->resolving = 2;
			break;
		}
	}
	domain_data_free(&dd, 0);
}

/*
 * Return a name for the IP address pointed to by ap.  This address
 * is assumed to be in network byte order.
 */
const char *
getname(const u_char *ap)
{
	u_int32_t addr;
	register struct hnamemem *p;
	int found;

	memcpy(&addr, ap, sizeof(addr));

	/*
	 * Do not print names if -n was given.
	 */
	if (nflag)
		return intoa(addr);

	found = 0;
	p = &hnametable[addr & (HASHNAMESIZE-1)];
	for (; p->nxt; p = p->nxt) {
		if (p->addr == addr) {
			found++;
			break;
		}
	}
	if (!found) {
		p->addr = addr;
		p->nxt = newhnamemem();
		p->name = strdup(intoa(addr));
	}
	if (!p->resolving) {
		if (domain_resolve_name(addr, 0, name_resolved) < 0)
			p->resolving = -1;
		else	p->resolving = 1;
	}
	return (p->name);
}

#ifdef INET6
/*
 * Return a name for the IP6 address pointed to by ap.  This address
 * is assumed to be in network byte order.
 */
const char *
getname6(const u_char *ap)
{
	struct hostent *hp;
	struct in6_addr addr;
	static struct h6namemem *p;		/* static for longjmp() */
	const char *cp;
	char ntop_buf[INET6_ADDRSTRLEN];

	memcpy(&addr, ap, sizeof(addr));

	/*
	 * Do not print names if -n was given.
	 */
	if (nflag)
		return inet_ntop(AF_INET6, &addr, ntop_buf, sizeof(ntop_buf));

	p = &h6nametable[*(u_int16_t *)&addr.s6_addr[14] & (HASHNAMESIZE-1)];
	for (; p->nxt; p = p->nxt) {
		if (memcmp(&p->addr, &addr, sizeof(addr)) == 0)
			return (p->name);
	}
	p->addr = addr;
	p->nxt = newh6namemem();

	hp = gethostbyaddr((char *)&addr, sizeof(addr), AF_INET6);
	if (hp) {
		p->name = strdup(hp->h_name);
		return (p->name);
	}
	cp = inet_ntop(AF_INET6, &addr, ntop_buf, sizeof(ntop_buf));
	if (!cp) return 0;
	p->name = strdup(cp);
	return (p->name);
}
#endif /* INET6 */

static char hex[] = "0123456789abcdef";


/* Find the hash node that corresponds the ether address 'ep' */

static inline struct enamemem *
lookup_emem(const u_char *ep)
{
	register u_int i, j, k;
	struct enamemem *tp;

	k = (ep[0] << 8) | ep[1];
	j = (ep[2] << 8) | ep[3];
	i = (ep[4] << 8) | ep[5];

	tp = &enametable[(i ^ j) & (HASHNAMESIZE-1)];
	while (tp->e_nxt)
		if (tp->e_addr0 == i &&
		    tp->e_addr1 == j &&
		    tp->e_addr2 == k)
			return tp;
		else
			tp = tp->e_nxt;
	tp->e_addr0 = i;
	tp->e_addr1 = j;
	tp->e_addr2 = k;
	tp->e_nxt = (struct enamemem *)calloc(1, sizeof(*tp));
	if (tp->e_nxt == NULL)
		error("lookup_emem: calloc");

	return tp;
}

/*
 * Find the hash node that corresponds to the bytestring 'bs'
 * with length 'nlen'
 */

static inline struct enamemem *
lookup_bytestring(register const u_char *bs, const unsigned int nlen)
{
	struct enamemem *tp;
	register u_int i, j, k;

	if (nlen >= 6) {
		k = (bs[0] << 8) | bs[1];
		j = (bs[2] << 8) | bs[3];
		i = (bs[4] << 8) | bs[5];
	} else if (nlen >= 4) {
		k = (bs[0] << 8) | bs[1];
		j = (bs[2] << 8) | bs[3];
		i = 0;
	} else
		i = j = k = 0;

	tp = &bytestringtable[(i ^ j) & (HASHNAMESIZE-1)];
	while (tp->e_nxt)
		if (tp->e_addr0 == i &&
		    tp->e_addr1 == j &&
		    tp->e_addr2 == k &&
		    memcmp((const char *)bs, (const char *)(tp->e_bs), nlen) == 0)
			return tp;
		else
			tp = tp->e_nxt;

	tp->e_addr0 = i;
	tp->e_addr1 = j;
	tp->e_addr2 = k;

	tp->e_bs = (u_char *) calloc(1, nlen + 1);
	memcpy(tp->e_bs, bs, nlen);
	tp->e_nxt = (struct enamemem *)calloc(1, sizeof(*tp));
	if (tp->e_nxt == NULL)
		error("lookup_bytestring: calloc");

	return tp;
}

/* Find the hash node that corresponds the NSAP 'nsap' */

static inline struct enamemem *
lookup_nsap(register const u_char *nsap)
{
	register u_int i, j, k;
	unsigned int nlen = *nsap;
	struct enamemem *tp;
	const u_char *ensap = nsap + nlen - 6;

	if (nlen > 6) {
		k = (ensap[0] << 8) | ensap[1];
		j = (ensap[2] << 8) | ensap[3];
		i = (ensap[4] << 8) | ensap[5];
	}
	else
		i = j = k = 0;

	tp = &nsaptable[(i ^ j) & (HASHNAMESIZE-1)];
	while (tp->e_nxt)
		if (tp->e_addr0 == i &&
		    tp->e_addr1 == j &&
		    tp->e_addr2 == k &&
		    tp->e_nsap[0] == nlen &&
		    memcmp((const char *)&(nsap[1]),
			(char *)&(tp->e_nsap[1]), nlen) == 0)
			return tp;
		else
			tp = tp->e_nxt;
	tp->e_addr0 = i;
	tp->e_addr1 = j;
	tp->e_addr2 = k;
	tp->e_nsap = (u_char *)malloc(nlen + 1);
	if (tp->e_nsap == NULL)
		error("lookup_nsap: malloc");
	memcpy((char *)tp->e_nsap, (const char *)nsap, nlen + 1);
	tp->e_nxt = (struct enamemem *)calloc(1, sizeof(*tp));
	if (tp->e_nxt == NULL)
		error("lookup_nsap: calloc");

	return tp;
}

/* Find the hash node that corresponds the protoid 'pi'. */

static inline struct protoidmem *
lookup_protoid(const u_char *pi)
{
	register u_int i, j;
	struct protoidmem *tp;

	/* 5 octets won't be aligned */
	i = (((pi[0] << 8) + pi[1]) << 8) + pi[2];
	j =   (pi[3] << 8) + pi[4];
	/* XXX should be endian-insensitive, but do big-endian testing  XXX */

	tp = &protoidtable[(i ^ j) & (HASHNAMESIZE-1)];
	while (tp->p_nxt)
		if (tp->p_oui == i && tp->p_proto == j)
			return tp;
		else
			tp = tp->p_nxt;
	tp->p_oui = i;
	tp->p_proto = j;
	tp->p_nxt = (struct protoidmem *)calloc(1, sizeof(*tp));
	if (tp->p_nxt == NULL)
		error("lookup_protoid: calloc");

	return tp;
}

const char *
etheraddr_string(register const u_char *ep)
{
	register u_int i;
	register char *cp;
	register struct enamemem *tp;
	char buf[sizeof("00:00:00:00:00:00")];

	tp = lookup_emem(ep);
	if (tp->e_name)
		return (tp->e_name);
#ifdef USE_ETHER_NTOHOST
	if (!nflag) {
		char buf2[128];
		if (ether_ntohost(buf2, (const struct ether_addr *)ep) == 0) {
			tp->e_name = strdup(buf2);
			return (tp->e_name);
		}
	}
#endif
	cp = buf;
        *cp++ = hex[*ep >> 4 ];
	*cp++ = hex[*ep++ & 0xf];
	for (i = 5; (int)--i >= 0;) {
		*cp++ = ':';
                *cp++ = hex[*ep >> 4 ];
		*cp++ = hex[*ep++ & 0xf];
	}
	*cp = '\0';
	tp->e_name = strdup(buf);
	return (tp->e_name);
}

const char *
linkaddr_string(const u_char *ep, const unsigned int len)
{
	register u_int i, j;
	register char *cp;
	register struct enamemem *tp;

	if (!ep || len < 1) return "";

#ifdef	notdef
	if (len == 6)	/* XXX not totally correct... */
		return etheraddr_string(ep);
#endif

	tp = lookup_bytestring(ep, len);
	if (tp->e_name)
		return (tp->e_name);

	tp->e_name = cp = (char *)malloc(len*3);
	if (tp->e_name == NULL)
		error("linkaddr_string: malloc");
	if ((j = *ep >> 4) != 0)
		*cp++ = hex[j];
	*cp++ = hex[*ep++ & 0xf];
	for (i = len-1; i > 0 ; --i) {
		*cp++ = ':';
		if ((j = *ep >> 4) != 0)
			*cp++ = hex[j];
		*cp++ = hex[*ep++ & 0xf];
	}
	*cp = '\0';
	return (tp->e_name);
}

const char *
ethertype_string(u_short type)
{
	register char *cp;
	register struct hnamemem *tp;
	register u_int32_t i = type;
	char buf[sizeof("0000")];

	for (tp = &etypetable[i & (HASHNAMESIZE-1)]; tp->nxt; tp = tp->nxt)
		if (tp->addr == i)
			return (tp->name);

	tp->addr = i;
	tp->nxt = newhnamemem();

	cp = buf;
	NTOHS(type);
	*cp++ = toupper(hex[type >> 12 & 0xf]);
	*cp++ = toupper(hex[type >> 8 & 0xf]);
	*cp++ = toupper(hex[type >> 4 & 0xf]);
	*cp++ = toupper(hex[type & 0xf]);
	*cp++ = '\0';
	tp->name = strdup(buf);
	return (tp->name);
}

const char *
protoid_string(register const u_char *pi)
{
	register u_int i, j;
	register char *cp;
	register struct protoidmem *tp;
	char buf[sizeof("00:00:00:00:00")];

	tp = lookup_protoid(pi);
	if (tp->p_name)
		return tp->p_name;

	cp = buf;
	if ((j = *pi >> 4) != 0)
		*cp++ = hex[j];
	*cp++ = hex[*pi++ & 0xf];
	for (i = 4; (int)--i >= 0;) {
		*cp++ = ':';
		if ((j = *pi >> 4) != 0)
			*cp++ = hex[j];
		*cp++ = hex[*pi++ & 0xf];
	}
	*cp = '\0';
	tp->p_name = strdup(buf);
	return (tp->p_name);
}

const char *
llcsap_string(u_char sap)
{
	register struct hnamemem *tp;
	register u_int32_t i = sap;
	char buf[sizeof("sap-00")];

	for (tp = &llcsaptable[i & (HASHNAMESIZE-1)]; tp->nxt; tp = tp->nxt)
		if (tp->addr == i)
			return (tp->name);

	tp->addr = i;
	tp->nxt = newhnamemem();

	snprintf(buf, sizeof(buf), "sap-%02x", sap & 0xff);
	tp->name = strdup(buf);
	return (tp->name);
}

const char *
isonsap_string(const u_char *nsap)
{
	register u_int i, nlen = nsap[0];
	register char *cp;
	register struct enamemem *tp;

	tp = lookup_nsap(nsap);
	if (tp->e_name)
		return tp->e_name;

	tp->e_name = cp = (char *)malloc(nlen * 2 + 2);
	if (cp == NULL)
		error("isonsap_string: malloc");

	nsap++;
	*cp++ = '/';
	for (i = nlen; (int)--i >= 0;) {
		*cp++ = hex[*nsap >> 4];
		*cp++ = hex[*nsap++ & 0xf];
	}
	*cp = '\0';
	return (tp->e_name);
}

const char *
tcpport_string(u_short port)
{
	register struct hnamemem *tp;
	register u_int32_t i = port;
	char buf[sizeof("00000")];

	for (tp = &tporttable[i & (HASHNAMESIZE-1)]; tp->nxt; tp = tp->nxt) {
		if (tp->addr == i)
			return (tp->name);
	}
	tp->addr = i;
	tp->nxt = newhnamemem();

	(void)snprintf(buf, sizeof(buf), "%u", i);
	tp->name = strdup(buf);
	return (tp->name);
}

const char *
udpport_string(u_short port)
{
	register struct hnamemem *tp;
	register u_int32_t i = port;
	char buf[sizeof("00000")];

	for (tp = &uporttable[i & (HASHNAMESIZE-1)]; tp->nxt; tp = tp->nxt) {
		if (tp->addr == i)
			return (tp->name);
	}
	tp->addr = i;
	tp->nxt = newhnamemem();

	(void)snprintf(buf, sizeof(buf), "%u", i);
	tp->name = strdup(buf);
	return (tp->name);
}

int
isservport(u_short port)
{
	register struct hnamemem *tp;
        register u_int32_t i = port;

	for (tp = &servtable[i & (HASHNAMESIZE-1)]; tp->nxt; tp = tp->nxt) {
		if (tp->addr == i)
			return 1;
	}
	return 0;
}

const char *
ipxsap_string(u_short port)
{
	register char *cp;
	register struct hnamemem *tp;
	register u_int32_t i = port;
	char buf[sizeof("0000")];

	for (tp = &ipxsaptable[i & (HASHNAMESIZE-1)]; tp->nxt; tp = tp->nxt)
		if (tp->addr == i)
			return (tp->name);

	tp->addr = i;
	tp->nxt = newhnamemem();

	cp = buf;
	NTOHS(port);
	*cp++ = toupper(hex[port >> 12 & 0xf]);
	*cp++ = toupper(hex[port >> 8 & 0xf]);
	*cp++ = toupper(hex[port >> 4 & 0xf]);
	*cp++ = toupper(hex[port & 0xf]);
	*cp++ = '\0';
	tp->name = strdup(buf);
	return (tp->name);
}

static void
init_servarray(void)
{
	struct servent *sv;
	register struct hnamemem *table;
	register int i;

	while ((sv = getservent()) != NULL) {
		int port = ntohs(sv->s_port);
		i = port & (HASHNAMESIZE-1);

		table = &servtable[i];
		if (table->addr != port) {
			while (table->addr)
				table = table->nxt;
			table->addr = port;
			table->nxt = newhnamemem();
		}

		if (strcmp(sv->s_proto, "tcp") == 0)
			table = &tporttable[i];
		else if (strcmp(sv->s_proto, "udp") == 0)
			table = &uporttable[i];
		else	continue;

		while (table->name)
			table = table->nxt;
		table->name = strdup(sv->s_name);
		table->addr = port;
		table->nxt = newhnamemem();
	}
	endservent();
}

static struct tok ethertype_db[] = {
	{ ETHERTYPE_IP,             "ip"	},
	{ ETHERTYPE_MPLS,           "mpls"	},
	{ ETHERTYPE_MPLS_MULTI,     "mpls-mc"	},
	{ ETHERTYPE_IPV6,           "ipv6"	},
	{ ETHERTYPE_8021Q,          "dot1q"	},
	{ ETHERTYPE_VMAN,           "vman"	},
	{ ETHERTYPE_PUP,            "pup"	},
	{ ETHERTYPE_ARP,            "arp"	},
	{ ETHERTYPE_REVARP ,        "rarp"	},
	{ ETHERTYPE_NS,             "ns"	},
	{ ETHERTYPE_SPRITE,         "sprite"	},
	{ ETHERTYPE_TRAIL,          "trail"	},
	{ ETHERTYPE_CDP,            "cdp"	},
	{ ETHERTYPE_MOPDL,          "mop-dl"	},
	{ ETHERTYPE_MOPRC,          "mop-rc"	},
	{ ETHERTYPE_DN,             "dn"	},
	{ ETHERTYPE_LAT,            "lat"	},
	{ ETHERTYPE_SCA,            "sca"	},
	{ ETHERTYPE_LANBRIDGE,      "lanbridge"	},
	{ ETHERTYPE_DECDNS,         "dec-dns"	},
	{ ETHERTYPE_DECDTS,         "dec-dts"	},
	{ ETHERTYPE_VEXP,           "vexp"	},
	{ ETHERTYPE_VPROD,          "vprod"	},
	{ ETHERTYPE_ATALK,          "atalk"	},
	{ ETHERTYPE_AARP,           "atalk-arp"	},
	{ ETHERTYPE_IPX,            "ipx"	},
	{ ETHERTYPE_PPP,            "ppp"	},
	{ ETHERTYPE_PPPOED,         "pppoe-d"	},
	{ ETHERTYPE_PPPOES,         "pppoe-s"	},
	{ ETHERTYPE_LOOPBACK,       "loopback"	},
	{ 0, NULL }
};

static void
init_etypearray(void)
{
	register int i;
	register struct hnamemem *table;

	for (i = 0; ethertype_db[i].s; i++) {
		int j = htons(ethertype_db[i].v) & (HASHNAMESIZE-1);
		table = &etypetable[j];
		while (table->name)
			table = table->nxt;
		table->name = ethertype_db[i].s;
		table->addr = htons(ethertype_db[i].v);
		table->nxt = newhnamemem();
	}
}

static struct protoidlist {
	const u_char protoid[5];
	const char *name;
} protoidlist[] = {
	{{ 0x00, 0x00, 0x0c, 0x01, 0x07 }, "CiscoMLS" },
	{{ 0x00, 0x00, 0x0c, 0x20, 0x00 }, "CiscoCDP" },
	{{ 0x00, 0x00, 0x0c, 0x20, 0x01 }, "CiscoCGMP" },
	{{ 0x00, 0x00, 0x0c, 0x20, 0x03 }, "CiscoVTP" },
	{{ 0x00, 0xe0, 0x2b, 0x00, 0xbb }, "ExtremeEDP" },
	{{ 0x00, 0x00, 0x00, 0x00, 0x00 }, NULL }
};

/*
 * SNAP proto IDs with org code 0:0:0 are actually encapsulated Ethernet
 * types.
 */
static void
init_protoidarray(void)
{
	register int i;
	register struct protoidmem *tp;
	struct protoidlist *pl;
	u_char protoid[5];

	protoid[0] = 0;
	protoid[1] = 0;
	protoid[2] = 0;
	for (i = 0; ethertype_db[i].s; i++) {
		u_short etype = htons(ethertype_db[i].v);

		memcpy((char *)&protoid[3], (char *)&etype, 2);
		tp = lookup_protoid(protoid);
		tp->p_name = strdup(ethertype_db[i].s);
	}
	/* Hardwire some SNAP proto ID names */
	for (pl = protoidlist; pl->name != NULL; ++pl) {
		tp = lookup_protoid(pl->protoid);
		/* Don't override existing name */
		if (tp->p_name != NULL)
			continue;

		tp->p_name = pl->name;
	}
}

static struct etherlist {
	const u_char addr[6];
	const char *name;
} etherlist[] = {
	{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, "ethernet" },
	{{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, "broadcast" },
	{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, NULL }
};

/*
 * Initialize the ethers hash table.  We take two different approaches
 * depending on whether or not the system provides the ethers name
 * service.  If it does, we just wire in a few names at startup,
 * and etheraddr_string() fills in the table on demand.  If it doesn't,
 * then we suck in the entire /etc/ethers file at startup.  The idea
 * is that parsing the local file will be fast, but spinning through
 * all the ethers entries via NIS & next_etherent might be very slow.
 *
 * XXX pcap_next_etherent doesn't belong in the pcap interface, but
 * since the pcap module already does name-to-address translation,
 * it's already does most of the work for the ethernet address-to-name
 * translation, so we just pcap_next_etherent as a convenience.
 */
static void
init_etherarray(void)
{
	register struct etherlist *el;
	register struct enamemem *tp;
#ifdef USE_ETHER_NTOHOST
	char name[256];
#else
	register struct pcap_etherent *ep;
	register FILE *fp;

	/* Suck in entire ethers file */
	fp = fopen(PCAP_ETHERS_FILE, "r");
	if (fp != NULL) {
		while ((ep = pcap_next_etherent(fp)) != NULL) {
			tp = lookup_emem(ep->addr);
			tp->e_name = strdup(ep->name);
		}
		(void)fclose(fp);
	}
#endif

	/* Hardwire some ethernet names */
	for (el = etherlist; el->name != NULL; ++el) {
		tp = lookup_emem(el->addr);
		/* Don't override existing name */
		if (tp->e_name != NULL)
			continue;

#ifdef USE_ETHER_NTOHOST
                /* Use yp/nis version of name if available */
                if (ether_ntohost(name, (const struct ether_addr *)el->addr) == 0) {
                        tp->e_name = strdup(name);
			continue;
		}
#endif
		tp->e_name = el->name;
	}
}

static struct tok llcsap_db[] = {
	/* IEEE SAPs */
	{ 0x00,	"null"		},
	{ 0x02,	"isap"		},
	{ 0x03,	"gsap"		},
	{ 0x06,	"ip-sap"	},
	{ 0x0e,	"proway-nm"	},
	{ 0x42,	"stp"		},
	{ 0x4e,	"rs511"		},
	{ 0x5e,	"isi-ip"	},
	{ 0x7e,	"x25-plp"	},
	{ 0x80,	"3com"		},
	{ 0x8e,	"proway"	},
	{ 0xaa,	"snap"		},
	{ 0xbc,	"banyan"	},
	{ 0xe0,	"ipx"		},
	{ 0xf0,	"netbeui"	},
	{ 0xf4,	"lanman"	},
	{ 0xfe,	"iso-clns"	},
	{ 0xff,	"raw-ipx"	}, /* known as raw 802.3 packet */
	/* IBM SAPs */
	{ 0x04,	"isna"		},
	{ 0x05,	"gsna"		},
	{ 0xd4,	"resource"	},
	{ 0xdc,	"dyn-arp"	},
	{ 0xf0,	"netbios"	},
	{ 0xf8,	"irpl"		},
	{ 0xf4,	"ilan"		},
	{ 0xf5,	"glan"		},
	{ 0xfc,	"discovery"	},
	{ 0, NULL }
};

static void
init_llcsaparray(void)
{
	register int i;
	register struct hnamemem *table;

	for (i = 0; llcsap_db[i].s != NULL; i++) {
		table = &llcsaptable[llcsap_db[i].v];
		while (table->name)
			table = table->nxt;
		table->name = llcsap_db[i].s;
		table->addr = llcsap_db[i].v;
		table->nxt = newhnamemem();
	}
}

static struct tok ipxsap_db[] = {
	{ 0x0000, "Unknown" },
	{ 0x0001, "User" },
	{ 0x0002, "User Group" },
	{ 0x0003, "PrintQueue" },
	{ 0x0004, "FileServer" },
	{ 0x0005, "JobServer" },
	{ 0x0006, "Gateway" },
	{ 0x0007, "PrintServer" },
	{ 0x0008, "ArchiveQueue" },
	{ 0x0009, "ArchiveServer" },
	{ 0x000a, "JobQueue" },
	{ 0x000b, "Administration" },
	{ 0x000F, "Novell TI-RPC" },
	{ 0x0017, "Diagnostics" },
	{ 0x0020, "NetBIOS" },
	{ 0x0021, "NAS SNA Gateway" },
	{ 0x0023, "NACS AsyncGateway" },
	{ 0x0024, "RemoteBridge/RoutingService" },
	{ 0x0026, "BridgeServer" },
	{ 0x0027, "TCP/IP Gateway" },
	{ 0x0028, "Point-to-point X.25 BridgeServer" },
	{ 0x0029, "3270 Gateway" },
	{ 0x002a, "CHI Corp" },
	{ 0x002c, "PC Chalkboard" },
	{ 0x002d, "TimeSynchServer" },
	{ 0x002e, "ARCserve5.0/PalindromeBackup" },
	{ 0x0045, "DI3270 Gateway" },
	{ 0x0047, "AdvertisingPrintServer" },
	{ 0x004a, "NetBlazerModems" },
	{ 0x004b, "BtrieveVAP" },
	{ 0x004c, "NetwareSQL" },
	{ 0x004d, "XtreeNetwork" },
	{ 0x0050, "BtrieveVAP4.11" },
	{ 0x0052, "QuickLink" },
	{ 0x0053, "PrintQueueUser" },
	{ 0x0058, "Multipoint X.25 Router" },
	{ 0x0060, "STLB/NLM" },
	{ 0x0064, "ARCserve" },
	{ 0x0066, "ARCserve3.0" },
	{ 0x0072, "WAN CopyUtility" },
	{ 0x007a, "TES-NetwareVMS" },
	{ 0x0092, "WATCOM Debugger/EmeraldTapeBackupServer" },
	{ 0x0095, "DDA OBGYN" },
	{ 0x0098, "NetwareAccessServer" },
	{ 0x009a, "Netware for VMS II/NamedPipeServer" },
	{ 0x009b, "NetwareAccessServer" },
	{ 0x009e, "PortableNetwareServer/SunLinkNVT" },
	{ 0x00a1, "PowerchuteAPC UPS" },
	{ 0x00aa, "LAWserve" },
	{ 0x00ac, "CompaqIDA StatusMonitor" },
	{ 0x0100, "PIPE STAIL" },
	{ 0x0102, "LAN ProtectBindery" },
	{ 0x0103, "OracleDataBaseServer" },
	{ 0x0107, "Netware386/RSPX RemoteConsole" },
	{ 0x010f, "NovellSNA Gateway" },
	{ 0x0111, "TestServer" },
	{ 0x0112, "HP PrintServer" },
	{ 0x0114, "CSA MUX" },
	{ 0x0115, "CSA LCA" },
	{ 0x0116, "CSA CM" },
	{ 0x0117, "CSA SMA" },
	{ 0x0118, "CSA DBA" },
	{ 0x0119, "CSA NMA" },
	{ 0x011a, "CSA SSA" },
	{ 0x011b, "CSA STATUS" },
	{ 0x011e, "CSA APPC" },
	{ 0x0126, "SNA TEST SSA Profile" },
	{ 0x012a, "CSA TRACE" },
	{ 0x012b, "NetwareSAA" },
	{ 0x012e, "IKARUS VirusScan" },
	{ 0x0130, "CommunicationsExecutive" },
	{ 0x0133, "NNS DomainServer/NetwareNamingServicesDomain" },
	{ 0x0135, "NetwareNamingServicesProfile" },
	{ 0x0137, "Netware386 PrintQueue/NNS PrintQueue" },
	{ 0x0141, "LAN SpoolServer" },
	{ 0x0152, "IRMALAN Gateway" },
	{ 0x0154, "NamedPipeServer" },
	{ 0x0166, "NetWareManagement" },
	{ 0x0168, "Intel PICKIT CommServer/Intel CAS TalkServer" },
	{ 0x0173, "Compaq" },
	{ 0x0174, "Compaq SNMP Agent" },
	{ 0x0175, "Compaq" },
	{ 0x0180, "XTreeServer/XTreeTools" },
	{ 0x018A, "NASI ServicesBroadcastServer" },
	{ 0x01b0, "GARP Gateway" },
	{ 0x01b1, "Binfview" },
	{ 0x01bf, "IntelLanDeskManager" },
	{ 0x01ca, "AXTEC" },
	{ 0x01cb, "ShivaNetModem/E" },
	{ 0x01cc, "ShivaLanRover/E" },
	{ 0x01cd, "ShivaLanRover/T" },
	{ 0x01ce, "ShivaUniversal" },
	{ 0x01d8, "CastelleFAXPressServer" },
	{ 0x01da, "CastelleLANPressPrintServer" },
	{ 0x01dc, "CastelleFAX/Xerox7033 FaxServer/ExcelLanFax" },
	{ 0x01f0, "LEGATO" },
	{ 0x01f5, "LEGATO" },
	{ 0x0233, "NMS Agent/NetwareManagementAgent" },
	{ 0x0237, "NMS IPX Discovery/LANternReadWriteChannel" },
	{ 0x0238, "NMS IP Discovery/LANternTrapAlarmChannel" },
	{ 0x023a, "LANtern" },
	{ 0x023c, "MAVERICK" },
	{ 0x023f, "NovellSMDR" },
	{ 0x024e, "NetwareConnect" },
	{ 0x024f, "NASI ServerBroadcast Cisco" },
	{ 0x026a, "NMS ServiceConsole" },
	{ 0x026b, "TimeSynchronizationServer Netware 4.x" },
	{ 0x0278, "DirectoryServer Netware 4.x" },
	{ 0x027b, "NetwareManagementAgent" },
	{ 0x0280, "Novell File and Printer Sharing Service for PC" },
	{ 0x0304, "NovellSAA Gateway" },
	{ 0x0308, "COM/VERMED" },
	{ 0x030a, "GalacticommWorldgroupServer" },
	{ 0x030c, "IntelNetport2/HP JetDirect/HP Quicksilver" },
	{ 0x0320, "AttachmateGateway" },
	{ 0x0327, "MicrosoftDiagnostiocs" },
	{ 0x0328, "WATCOM SQL Server" },
	{ 0x0335, "MultiTechSystems MultisynchCommServer" },
	{ 0x0343, "Xylogics RemoteAccessServer/LANModem" },
	{ 0x0355, "ArcadaBackupExec" },
	{ 0x0358, "MSLCD1" },
	{ 0x0361, "NETINELO" },
	{ 0x037e, "Powerchute UPS Monitoring" },
	{ 0x037f, "ViruSafeNotify" },
	{ 0x0386, "HP Bridge" },
	{ 0x0387, "HP Hub" },
	{ 0x0394, "NetWare SAA Gateway" },
	{ 0x039b, "LotusNotes" },
	{ 0x03b7, "CertusAntiVirus" },
	{ 0x03c4, "ARCserve4.0" },
	{ 0x03c7, "LANspool3.5" },
	{ 0x03d7, "LexmarkPrinterServer" },
	{ 0x03d8, "LexmarkXLE PrinterServer" },
	{ 0x03dd, "BanyanENS NetwareClient" },
	{ 0x03de, "GuptaSequelBaseServer/NetWareSQL" },
	{ 0x03e1, "UnivelUnixware" },
	{ 0x03e4, "UnivelUnixware" },
	{ 0x03fc, "IntelNetport" },
	{ 0x03fd, "PrintServerQueue" },
	{ 0x040A, "ipnServer" },
	{ 0x040D, "LVERRMAN" },
	{ 0x040E, "LVLIC" },
	{ 0x0414, "NET Silicon (DPI)/Kyocera" },
	{ 0x0429, "SiteLockVirus" },
	{ 0x0432, "UFHELPR???" },
	{ 0x0433, "Synoptics281xAdvancedSNMPAgent" },
	{ 0x0444, "MicrosoftNT SNA Server" },
	{ 0x0448, "Oracle" },
	{ 0x044c, "ARCserve5.01" },
	{ 0x0457, "CanonGP55" },
	{ 0x045a, "QMS Printers" },
	{ 0x045b, "DellSCSI Array" },
	{ 0x0491, "NetBlazerModems" },
	{ 0x04ac, "OnTimeScheduler" },
	{ 0x04b0, "CD-Net" },
	{ 0x0513, "EmulexNQA" },
	{ 0x0520, "SiteLockChecks" },
	{ 0x0529, "SiteLockChecks" },
	{ 0x052d, "CitrixOS2 AppServer" },
	{ 0x0535, "Tektronix" },
	{ 0x0536, "Milan" },
	{ 0x055d, "Attachmate SNA gateway" },
	{ 0x056b, "IBM8235 ModemServer" },
	{ 0x056c, "ShivaLanRover/E PLUS" },
	{ 0x056d, "ShivaLanRover/T PLUS" },
	{ 0x0580, "McAfeeNetShield" },
	{ 0x05B8, "NLM to workstation communication (Revelation Software)" },
	{ 0x05BA, "CompatibleSystemsRouters" },
	{ 0x05BE, "CheyenneHierarchicalStorageManager" },
	{ 0x0606, "JCWatermarkImaging" },
	{ 0x060c, "AXISNetworkPrinter" },
	{ 0x0610, "AdaptecSCSIManagement" },
	{ 0x0621, "IBM AntiVirus" },
	{ 0x0640, "Windows95 RemoteRegistryService" },
	{ 0x064e, "MicrosoftIIS" },
	{ 0x067b, "Microsoft Win95/98 File and Print Sharing for NetWare" },
	{ 0x067c, "Microsoft Win95/98 File and Print Sharing for NetWare" },
	{ 0x076C, "Xerox" },
	{ 0x079b, "ShivaLanRover/E 115" },
	{ 0x079c, "ShivaLanRover/T 115" },
	{ 0x07B4, "CubixWorldDesk" },
	{ 0x07c2, "Quarterdeck IWare Connect V2.x NLM" },
	{ 0x07c1, "Quarterdeck IWare Connect V3.x NLM" },
	{ 0x0810, "ELAN License Server Demo" },
	{ 0x0824, "ShivaLanRoverAccessSwitch/E" },
	{ 0x086a, "ISSC Collector" },
	{ 0x087f, "ISSC DAS AgentAIX" },
	{ 0x0880, "Intel Netport PRO" },
	{ 0x0881, "Intel Netport PRO" },
	{ 0x0b29, "SiteLock" },
	{ 0x0c29, "SiteLockApplications" },
	{ 0x0c2c, "LicensingServer" },
	{ 0x2101, "PerformanceTechnologyInstantInternet" },
	{ 0x2380, "LAI SiteLock" },
	{ 0x238c, "MeetingMaker" },
	{ 0x4808, "SiteLockServer/SiteLockMetering" },
	{ 0x5555, "SiteLockUser" },
	{ 0x6312, "Tapeware" },
	{ 0x6f00, "RabbitGateway" },
	{ 0x7703, "MODEM" },
	{ 0x8002, "NetPortPrinters" },
	{ 0x8008, "WordPerfectNetworkVersion" },
	{ 0x85BE, "Cisco EIGRP" },
	{ 0x8888, "WordPerfectNetworkVersion/QuickNetworkManagement" },
	{ 0x9000, "McAfeeNetShield" },
	{ 0x9604, "CSA-NT_MON" },
	{ 0xb6a8, "OceanIsleReachoutRemoteControl" },
	{ 0xf11f, "SiteLockMetering" },
	{ 0xf1ff, "SiteLock" },
	{ 0xf503, "Microsoft SQL Server" },
	{ 0xF905, "IBM TimeAndPlace" },
	{ 0xfbfb, "TopCallIII FaxServer" },
	{ 0xffff, "AnyService/Wildcard" },
	{ 0, (char *)0 }
};

static void
init_ipxsaparray(void)
{
	register int i;
	register struct hnamemem *table;

	for (i = 0; ipxsap_db[i].s != NULL; i++) {
		int j = htons(ipxsap_db[i].v) & (HASHNAMESIZE-1);
		table = &ipxsaptable[j];
		while (table->name)
			table = table->nxt;
		table->name = ipxsap_db[i].s;
		table->addr = htons(ipxsap_db[i].v);
		table->nxt = newhnamemem();
	}
}

const char *
ipproto_string(u_char proto)
{
	register struct hnamemem *tp;
	register u_int32_t i = proto;
	char buf[sizeof("00000")];

	for (tp = &iprototable[i & (HASHNAMESIZE-1)]; tp->nxt; tp = tp->nxt)
		if (tp->addr == i)
			return (tp->name);

	tp->addr = i;
	tp->nxt = newhnamemem();

	(void)snprintf(buf, sizeof(buf), "%u", i);
	tp->name = strdup(buf);
	return (tp->name);
}

//add by dove
static char *ip_proto_table[] ={
	""		// dummy for IP 				(00)
	"ICMP",		// control message protocol - RFC792
	"IGMP",		// group mgmt protocol - RFC1112
	"GGP",		// gateway^2 (deprecated) - RFC823
	"IPv4",		// IP header
	"Stream",	// Stream - RFC1190, RFC1819
	"TCP",		// TCP - RFC792
	"CBT",		// CBT - <A.Ballardie@cs.ucl.ac.uk>
	"EGP",		// exterior gateway protocol - RFC888
	"IGP",		// any private interior gateway protocol
	"BBN_RCC", 	// BBN RCC Monitoring 				(10)
	"NVPII",	// Network Voice Protocol - RFC741
	"PUP",		// PUP
	"ARGUS",	// ARGUS
	"EMCON", 	// EMCON
	"XNET",		// Cross net debugger - IEN158
	"CHAOS", 	// CHAOS
	"UDP",		// user datagram protocol - RFC768
	"MUX", 		// multiplexing - IEN90
	"DCNMEAS",	// DCN Measurement Subsystems
	"HMP",		// Host Monitoring - RFC869			(20)
	"PRM",		// Packet radio measurement
	"IDP",		// xns idp
	"TRUNK1",
	"TRUNK2",
	"LEAF1",
	"LEAF2",
	"RDP", 		// Reliable Data Protocol - RFC908
	"IRT",		// Internet Reliable Transation - RFC938
	"TP",		// tp-4 w/ class negotiation - RFC905
	"BULK",		// Bulk Data Transfer Protocol - RFC969		(30)
	"MFE_NSP",	// MFE Network Services Protocol
	"MERIT",	// MERIT Internodal Protocol
	"DCCP",		// Datagram Congestion Control Protocol
	"3PC",		// Third party connect protocol
	"IDPR",		// Interdomain policy routing protocol
	"XTP",		// XTP
	"DDP",		// Datagram Delivery Protocol
	"CMTP",		// Control Message Transport Protocol
	"TPPP",		// TP++ Transport Protocol
	"IL",		// IL Transport Protocol			(40)
	"IPv6",		// IP6 header
	"SDRP",		// Source demand routing protocol
	"IP6ROUTING",	// IP6 routing header
	"IP6FRAGMENT",	// IP6 fragmentation header
	"IDRP",		// Inter-Domain Routing Protocol
	"RSVP",		// Resource ReSerVation protocol
	"GRE",		// General Routing Encapsulation
	"MHRP",		// Mobile Host Routing Protocol
	"BNA",		// BNA
	"ESP",		// Encap Security Payload for IPv6 - RFC2406	(50)
	"AH",		// Authentication Header for IPv6 - RFC2402
	"INSLP",	// Integrated Net Layer Security
	"SWIPE",	// IP with Encryption
	"NARP",		// NBMA Address resolution protocol - RFC1735
	"MOBILE",	// IP Mobility
	"TLSP",		// Transport Layer Security Protocol using
	"SKIP",		// SKIP
	"ICMP6",	// ICMP6  - RFC1883
	"IP6NONE",	// IP6 no next header - RFC1883
	"IP6DSTOPTS",	// IP6 destination options - RFC1883		(60)
	"Reserved",	// 61 is reserved by IANA for any host internal protocol
	"MIPV6_OLD",	// Mobile IPv6
	"Reserved",	// 63 is reserved by IANA for any local network
	"SATEXPAK",
	"KRYPTOLAN",
	"RVD",		// MIT Remote virtual disk protocol
	"IPPC",		// Internet Pluribus Packet Core
	"Reserved",	// 68 is reserved by IANA for any distributed file system
	"SATMON",	// SATNET Monitoring
	"VISA",		// VISA Protocol				(70)
	"IPCV",		// Internet Packet Core Utility
	"CPNX",		// Computer Protocol Network Executive
	"CPHB",		// Computer Protocol Heart Beat
	"WSN",		// WANG Span Network
	"PVP",		// Packet Video Protocol
	"BRSATMON",	// Backroon SATNET Monitoring
	"SUNND",	// SUN ND Protocol - Temporary
	"WBMON",	// Wideband Monitoring
	"WBEXPAK",	// Wideband EXPAK
	"EON",		// ISO cnlp					(80)
	"VMTP"          
	"SVMTP",	// Secure VMTP
	"VINES",	// Vines over raw IP
	"TTP"           
	"NSFNETIGP",	// NSFNET IGP
	"DGP",		// Dissimilar Gateway Protocol
	"TCF",
	"EIGRP"		
	"OSPF",		// OSPF Interior Gateway Protocol - RFC1583
	"SPRITE",	// SPRITE RPC protocol				(90)
	"LARP",		// Locus Address Resolution Protocol
	"MTP",		// Multicast Transport Protocol
	"AX25",		// AX.25 frames
	"IPINIP",	// IP within IP Encapsulation protocol
	"MICP",		// Mobile Internetworking Control Protocol
	"SCCCP",	// Semaphore communications security protocol
	"ETHERIP",	// Ethernet-within-IP - RFC 3378
	"ENCAP",	// encapsulation header - RFC1241
	"Reserved", 	// 99 is reserved by IANA for any private encryption scheme
	"GMTP",		//						(100)
	"IFMP",		// Ipsilon flow management protocol
	"PNNI",		// PNNI over IP
	"PIM",		// Protocol Independent Mcast
	"ARIS",	
	"SCPS",	
	"QNX",	
	"AN",		// Active Networks
	"IPCOMP",	// IP payload compression - RFC2393
	"SNP",		// Sitara Networks Protocol
	"COMPAQ",	// Compaq Peer Protocol				(110)
	"IPX",		// IPX over IP
	"VRRP",		// Virtual Router Redundancy Protocol
	"PGM",		// Pragmatic General Multicast
	"Reserved",	// 114 is reserved by IANA for any zero hop protocol
	"L2TP",		// Layer Two Tunnelling Protocol
	"DDX",		// D-II Data Exchange
	"IATP",		// Interactive Agent Transfer Protocol
	"STP",		// Schedule Transfer Protocol
	"SRP",		// Spectralink Radio Protocol
	"UTI",		// 						(120)
	"SMP",		// Simple Message Protocol
	"SM",		// 
	"PTP",		// Performance Transparency Protocol
	"ISIS",		// ISIS over IPv4
	"FIRE",		// 
	"CRTP",		// Combat Radio Transport Protocol
	"CRUDP",	// Combat Radio User Datagram
	"SSCOPMCE",	// 
	"IPLT",		// 
	"SPS",		// Secure Packet Shield				(130)
	"PIPE",		// Private IP Encapsulation within IP
	"SCTP",		// Stream Control Transmission Protocol
	"FC",		// Fibre Channel
	"RSVPE2EI",	// RSVP E2E Ignore - RFC3175
	"MIPV6",	// Mobile IPv6 
	"UDPLITE",	// Lightweight user datagram protocol - RFC3828
	"MPLS_IN_IP",	// MPLS in IP - RFC4023
	//"AX4000",	// AX/4000 Testblock - non IANA (173)
	//"NCS_HEARTBEAT",// Novell NCS Heartbeat - http://support.novell.com/cgi-bin/search/searchtid.cgi?/10071158.htm (224)
};

static void
init_iprotoarray(void)
{
	return; // bionic have no getprotoent/endprotoent, disabled by dove
	/*
	struct protoent *pe;
	register struct hnamemem *tp;
	register u_int32_t i;

	while ((pe = getprotoent()) != NULL) {
		i = pe->p_proto;
		for (tp = &iprototable[i & (HASHNAMESIZE-1)];
		     tp->name; tp = tp->nxt) ;

		tp->name = strdup(pe->p_name);
		tp->addr = i;
		tp->nxt = newhnamemem();
	}
	endprotoent();*/
}

static struct tok icmp_db[] = {
	{ 0x0000,	"echo-reply"	},
	{ 0x0300,	"unrch-net"	},
	{ 0x0301,	"unrch-host"	},
	{ 0x0302,	"unrch-proto"	},
	{ 0x0303,	"unrch-port"	},
	{ 0x0304,	"need-frag"	},
	{ 0x0305,	"src-fail"	},
	{ 0x0306,	"bad-net"	},
	{ 0x0307,	"bad-host"	},
	{ 0x0308,	"isolated"	},
	{ 0x0309,	"net-prhbt"	},
	{ 0x030a,	"host-prhbt"	},
	{ 0x030b,	"bad-ntos"	},
	{ 0x030c,	"bad-htos"	},
	{ 0x030d,	"filtered"	},
	{ 0x030e,	"no-prec"	},
	{ 0x030f,	"prec-cut"	},
	{ 0x0400,	"quench"	},
	{ 0x0500,	"redir-net"	},
	{ 0x0501,	"redir-hst"	},
	{ 0x0502,	"redir-ntos"	},
	{ 0x0503,	"redir-htos"	},
	{ 0x0800,	"echo-reqst"	},
	{ 0x0900,	"advert"	},
	{ 0x0a00,	"solicit"	},
	{ 0x0b00,	"ttl-exceed"	},
	{ 0x0b01,	"frg-exceed"	},
	{ 0x0c00,	"err-atptr"	},
	{ 0x0c01,	"optabsent"	},
	{ 0x0c02,	"bad-len"	},
	{ 0x0d00,	"time-reqst"	},
	{ 0x0e00,	"time-reply"	},
	{ 0x0f00,	"info-reqst"	},
	{ 0x1000,	"info-reply"	},
	{ 0x1100,	"mask-reqst"	},
	{ 0x1200,	"mask-reply"	},
	{ 0, NULL }
};

static void
init_icmparray(void)
{
	register int i;
	register struct hnamemem *table;

	for (i = 0; icmp_db[i].s != NULL; i++) {
		table = &icmptable[icmp_db[i].v & (HASHNAMESIZE-1)];
		while (table->name)
			table = table->nxt;
		table->name = icmp_db[i].s;
		table->addr = icmp_db[i].v;
		table->nxt = newhnamemem();
	}
}

const char *
icmp_string(u_short code)
{
	register struct hnamemem *tp;
	register u_int32_t i = code;
	char buf[sizeof("0000")];

	for (tp = &icmptable[i & (HASHNAMESIZE-1)]; tp->nxt; tp = tp->nxt)
		if (tp->addr == i)
			return (tp->name);

	tp->addr = i;
	tp->nxt = newhnamemem();

	snprintf(buf, sizeof(buf), "%04x", code);
	tp->name = strdup(buf);
	return (tp->name);
}

#ifdef INET6
static struct tok icmpv6_db[] = {
	{ 0x0100,	"no-route"	},
	{ 0x0101,	"adm-prhbt"	},
	{ 0x0102,	"not-nghbr"	},
	{ 0x0103,	"addr-unrch"	},
	{ 0x0104,	"bad-port"	},
	{ 0x0200,	"pkt-toobig"	},
	{ 0x0300,	"hop-exceed"	},
	{ 0x0301,	"frg-exceed"	},
	{ 0x0400,	"bad-hdr"	},
	{ 0x0401,	"unkn-nhdr"	},
	{ 0x0402,	"unkn-opt"	},
	{ 0x8000,	"echo-reqst"	},
	{ 0x8100,	"echo-repl"	},
	{ 0x8200,	"membr-qry"	},
	{ 0x8300,	"membr-rprt"	},
	{ 0x8400,	"membr-red"	},
	{ 0x8500,	"router-sol"	},
	{ 0x8600,	"router-adv"	},
	{ 0x8700,	"nghbr-sol"	},
	{ 0x8800,	"nghbr-adv"	},
	{ 0x8900,	"redirect"	},
	{ 0, NULL }
};

static void
init_icmpv6array(void)
{
	register int i;
	register struct hnamemem *table;

	for (i = 0; icmpv6_db[i].s != NULL; i++) {
		table = &icmpv6table[icmpv6_db[i].v & (HASHNAMESIZE-1)];
		while (table->name)
			table = table->nxt;
		table->name = icmpv6_db[i].s;
		table->addr = icmpv6_db[i].v;
		table->nxt = newhnamemem();
	}
}

const char *
icmpv6_string(u_short code)
{
	register struct hnamemem *tp;
	register u_int32_t i = code;
	char buf[sizeof("0000")];

	for (tp = &icmpv6table[i & (HASHNAMESIZE-1)]; tp->nxt; tp = tp->nxt)
		if (tp->addr == i)
			return (tp->name);

	tp->addr = i;
	tp->nxt = newhnamemem();

	snprintf(buf, sizeof(buf), "%04x", code);
	tp->name = strdup(buf);
	return (tp->name);
}
#endif

/*
 * Initialize the address to name translation machinery.  We map all
 * non-local IP addresses to numeric addresses if fflag is true (i.e.,
 * to prevent blocking on the nameserver).  localnet is the IP address
 * of the local network.  mask is its subnet mask.
 */
void
init_addrtoname()
{
#ifdef	notdef
	if (nflag)
		/*
		 * Simplest way to suppress names.
		 */
		return;
#endif
	init_etherarray();
	init_servarray();
	init_etypearray();
	init_llcsaparray();
	init_protoidarray();
	init_ipxsaparray();
	init_iprotoarray();
	init_icmparray();
#ifdef INET6
	init_icmpv6array();
#endif
}

#ifdef	notdef
const char *
dnaddr_string(u_short dnaddr)
{
	register struct hnamemem *tp;

	for (tp = &dnaddrtable[dnaddr & (HASHNAMESIZE-1)]; tp->nxt != 0;
	     tp = tp->nxt)
		if (tp->addr == dnaddr)
			return (tp->name);

	tp->addr = dnaddr;
	tp->nxt = newhnamemem();
	if (nflag)
		tp->name = dnnum_string(dnaddr);
	else
		tp->name = dnname_string(dnaddr);

	return(tp->name);
}
#endif

/* Return a zero'ed hnamemem struct and cuts down on calloc() overhead */
struct hnamemem *
newhnamemem(void)
{
	register struct hnamemem *p;
	static struct hnamemem *ptr = NULL;
	static u_int num = 0;

	if (num  <= 0) {
		num = 64;
		ptr = (struct hnamemem *)calloc(num, sizeof (*ptr));
		if (ptr == NULL)
			error("newhnamemem: calloc");
	}
	--num;
	p = ptr++;
	return (p);
}

#ifdef INET6
/* Return a zero'ed h6namemem struct and cuts down on calloc() overhead */
struct h6namemem *
newh6namemem(void)
{
	register struct h6namemem *p;
	static struct h6namemem *ptr = NULL;
	static u_int num = 0;

	if (num  <= 0) {
		num = 64;
		ptr = (struct h6namemem *)calloc(num, sizeof (*ptr));
		if (ptr == NULL)
			error("newh6namemem: calloc");
	}
	--num;
	p = ptr++;
	return (p);
}
#endif /* INET6 */
