/*
 *	Copyright (c) 1999-2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifdef	HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef	HAVE_PATHS_H
#include <paths.h>
#endif
#ifdef	HAVE_RESOLV_H
#include <resolv.h>
#endif

#include "domain_resolver.h"
#include "session.h"
#include "util.h"
#include "trafshow.h"	/* just for dprintf() */


#ifndef	_PATH_RESCONF
#define	_PATH_RESCONF		"/etc/resolv.conf"
#endif
#ifndef	NAMESERVER_TOKEN
#define	NAMESERVER_TOKEN	"nameserver"
#endif
#ifndef	NAMESERVER_PORT
#define	NAMESERVER_PORT		53	/* nameserver port */
#endif
#ifndef	PACKETSZ
#define	PACKETSZ		512	/* maximum packet size */
#endif

static struct sockaddr_in *primary = 0, *secondary = 0;

/* currently we handle only following types of nameserver requests */
typedef	enum {
	IpAddress,	/* get A resource records */
	DomainName,	/* get PTR resource records */
	MailExchanger	/* get MX resource records */
} DomainType;

#define	MAX_EXPAND_TRIES	3 /* to resolve MX pointing to CNAME */

typedef	struct domain_transact_ent {
	/* caller supplied data */
	char *name;		/* original requested name (or ip address) */
	SESSION *sd;
	void (*callback)(SESSION *sd, DOMAIN_DATA *dd);

	/* request */
	u_short reqid;		/* request id */
	u_short expand;		/* expand MX pointing to CNAME */
	int retry;		/* retry counter */
	char *domain;		/* actual domain name requested */
	DomainType type;	/* type of request */

	/* response */
	int rcode;		/* nameserver reply code */
	DOMAIN_DATA *data;	/* list of answered data */

	struct domain_transact_ent *next;
} DOMAIN_TRANSACT;

#define	TRANSACT(sd)	((DOMAIN_TRANSACT *)session_cookie(sd))

static DOMAIN_TRANSACT *first_transact = 0;
static DOMAIN_TRANSACT *new_transact();
static DOMAIN_TRANSACT *find_transact(u_short reqid);
static void free_transact(DOMAIN_TRANSACT *dt);
static DOMAIN_TRANSACT *parse_packet(const unsigned char *data, int len);

static void nameserver_error(SESSION *sd, int error);
static void nameserver_close(SESSION *sd);
static void nameserver_reply(SESSION *sd, const unsigned char *data, int len);
static int nameserver_request(const char *domain, DomainType type,
			      SESSION *org,
			      void (*notify)(SESSION *sd, DOMAIN_DATA *dd));
static int nameserver_send(SESSION *sd);
static void discard_request(void *arg); /* (DOMAIN_TRANSACT *) */
static u_short unique_reqid();

#ifdef	HAVE_REPORT_FUNC
static const char *rcode2text[6] = {
 "No error",		/* 0 - NOERROR */
 "Format error",	/* 1 - FORMERR */
 "Server failure",	/* 2 - SERVFAIL */
 "Non existend domain",	/* 3 - NXDOAMIN */
 "Not implemented",	/* 4 - NOTIMP */
 "Query refused"	/* 5 - REFUSED */
};
#endif

#ifdef	DEBUG
void
dump_reply(dt)
	DOMAIN_TRANSACT *dt;
{
	DOMAIN_DATA *dd;
	char ipaddr[50];

	if (!dt) {
		printf("REPLY: domain transaction is null\n");
		return;
	}
	printf("REPLY: reqid=%d retry=%d domain=\"%s\" type=%d rcode=\"%s\"\n",
	       dt->reqid, dt->retry, dt->domain, dt->type, rcode2text[dt->rcode]);
	for (dd = dt->data; dd; dd = dd->next) {
		printf("REPLY:\tttl=%u\tpref=%u\tname=\"%s\"\taddr=%s\n",
		       dd->ttl, dd->pref, dd->name, intoa(ipaddr, dd->addr));

	}
}
#endif

int
domain_resolver_init()
{
	FILE *fp;
	int ns_cnt = 0;
	char *cp, buf[1024];

	if (!primary) {
		primary = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		if (!primary) return -1;
	}
	memset(primary, 0, sizeof(struct sockaddr_in));
	primary->sin_family = AF_INET;
	primary->sin_port = htons(NAMESERVER_PORT);
	primary->sin_addr.s_addr = htonl(0x7f000001);/* 127.0.0.1 by default */

	if (secondary) {
		free(secondary);
		secondary = 0;
	}

	if ((fp = fopen(_PATH_RESCONF, "r")) != 0) {
		while (fgets(buf, sizeof(buf), fp) != 0) {
			buf[sizeof(buf)-1] = '\0';
			for (cp = buf; *cp; cp++) {
				if (*cp == '#' || *cp == '\r' || *cp == '\n') {
					*cp = '\0';
					break;
				}
				if (*cp < ' ') *cp = ' ';
			}
			if (buf[0] == '\0')
				continue; /* skip empty lines and commentary */

			if (!strncasecmp(buf, NAMESERVER_TOKEN, sizeof(NAMESERVER_TOKEN)-1)) {
				cp = strip_blanks(buf + sizeof(NAMESERVER_TOKEN)-1);
				if (!ns_cnt++) {
					primary->sin_addr.s_addr = inet_addr(cp);
				} else if (!secondary) {
					secondary = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
					if (secondary) {
						memset(secondary, 0, sizeof(struct sockaddr_in));
						secondary->sin_family = AF_INET;
						secondary->sin_port = htons(NAMESERVER_PORT);
						secondary->sin_addr.s_addr = inet_addr(cp);
					}
				}
			}
		}
		(void)fclose(fp);
	}
	return ns_cnt;
}

int
domain_resolve_addr(domain, sd, notify)
	const char *domain;
	SESSION *sd;
	void (*notify)(SESSION *sd, DOMAIN_DATA *dd);
{
	return nameserver_request(domain, IpAddress, sd, notify);
}

int
domain_resolve_mxlist(domain, sd, notify)
	const char *domain;
	SESSION *sd;
	void (*notify)(SESSION *sd, DOMAIN_DATA *dd);
{
	return nameserver_request(domain, MailExchanger, sd, notify);
}

int
domain_resolve_name(ipaddr, sd, notify)
	in_addr_t ipaddr;
	SESSION *sd;
	void (*notify)(SESSION *sd, DOMAIN_DATA *dd);
{
	return nameserver_request((char *)&ipaddr, DomainName, sd, notify);
}


/*
 * Callback function: catch all errors during nameserver request.
 */
static void
nameserver_error(sd, error)
	SESSION *sd;
	int error;
{
	DOMAIN_TRANSACT *dt = TRANSACT(sd);
	if (sd && dt) {
		if (error != ETIMEDOUT) {
#ifdef	HAVE_REPORT_FUNC
			report(Warn, 0, error, "%lu: domain_resolver: %s (try=%d)",
			       sd->sid, peertoa(0, session_peer(sd)),
			       dt->retry + 1);
#endif
		} else if (++dt->retry < NAMESERVER_RETRIES) {
			nameserver_send(sd);
			return;
		}
	}
	nameserver_close(sd);
}

/*
 * Normal close nameserver request.
 */
static void
nameserver_close(sd)
	SESSION *sd;
{
	DOMAIN_TRANSACT *dt = TRANSACT(sd);

	session_free(sd);
	if (dt) {
		if (dt->data) { /* purge unresolved names */
			if (dt->type != DomainName)
				domain_data_free(&dt->data, "");
			else if (dt->data->addr == 0 || dt->data->addr == -1)
				memcpy(&dt->data->addr, dt->name, sizeof(dt->data->addr));
		}
#ifdef	DEBUG
		dump_reply(dt);
#endif
		if (dt->callback) {
			(*dt->callback)(dt->sd, dt->data);
			dt->data = 0; /* received data dispatched */
		}
		free_transact(dt);
	}
}

static void
discard_request(arg)
	void *arg;
{
	DOMAIN_TRANSACT *dt = (DOMAIN_TRANSACT *)arg;
	if (dt) {
		dt->sd = 0;
		dt->callback = 0;
	}
}

static u_short
unique_reqid()
{
	static u_short reqid = 0;
	if (++reqid == 0) reqid++; /* prevent 0 reqid */
	return reqid;
}

static DOMAIN_TRANSACT *
new_transact()
{
	DOMAIN_TRANSACT *curr;
	if ((curr = (DOMAIN_TRANSACT *)malloc(sizeof(DOMAIN_TRANSACT))) == 0)
		return 0;
	memset(curr, 0, sizeof(DOMAIN_TRANSACT));

	if (first_transact) {
		DOMAIN_TRANSACT *prev = first_transact;
		while (prev->next) prev = prev->next;
		prev->next = curr;
	} else	first_transact = curr;

	return curr;
}

static DOMAIN_TRANSACT *
find_transact(reqid)
	u_short reqid;
{
	DOMAIN_TRANSACT *curr;
	for (curr = first_transact; curr; curr = curr->next) {
		if (curr->reqid && curr->reqid == reqid)
			return curr;
	}
	return 0;
}

static void
free_transact(dt)
	DOMAIN_TRANSACT *dt;
{
	DOMAIN_TRANSACT *curr, *prev, *next;

	curr = first_transact;
	prev = 0;
	while (curr) {
		if (!dt || curr == dt) {
			next = curr->next;
			if (prev)
				prev->next = next;
			else    first_transact = next;

			if (curr->sd)
				session_unbind(curr->sd, discard_request, curr);
			if (curr->name)
				free(curr->name);
			if (curr->domain)
				free(curr->domain);
			domain_data_free(&curr->data, 0);
			free(curr);

			curr = next;
		} else {
			prev = curr;
			curr = curr->next;
		}
	}
}

DOMAIN_DATA *
domain_data_add(list, name, pref)
	DOMAIN_DATA **list;
	const char *name;
	int pref;
{
	DOMAIN_DATA *curr, *last, *prev;
	int insert;
	char *cp;

	/* sanity check */
	if (!list || !name || !*name) {
		errno = EINVAL;
		return 0;
	}

	/* sort it by pref ascending (bigger pref farther) */
	last = prev = 0;
	insert = 0;
	for (curr = *list; curr; curr = curr->next) {
		/* prevent duplicates */
		if (curr->name && !strcasecmp(curr->name, name))
			return curr;

		if (!insert && pref < curr->pref) {
			insert++;
			prev = last;
		}
		last = curr;
	}
	if ((curr = (DOMAIN_DATA *)malloc(sizeof(DOMAIN_DATA))) == 0)
		return 0;
	memset(curr, 0, sizeof(DOMAIN_DATA));

	if ((curr->name = strdup(name)) == 0) {
		int save_errno = errno;
		free(curr);
		save_errno = errno;
		return 0;
	}
	/* make all lowercase */
	for (cp = curr->name; *cp; cp++) {
		if (*cp >= 'A' && *cp <= 'Z')
			*cp = *cp + 32;
	}
	curr->pref = pref;

	if (insert) {
		if (prev) {
			curr->next = prev->next;
			prev->next = curr;
		} else {
			curr->next = *list;
			*list = curr;
		}
	} else if (last) {
		last->next = curr;
	} else {
		*list = curr;
	}
	return curr;
}

DOMAIN_DATA *
domain_data_find(list, name)
	DOMAIN_DATA **list;
	const char *name;
{
	DOMAIN_DATA *curr;

	/* sanity check */
	if (!list || !name || !*name)
		return 0;

	for (curr = *list; curr; curr = curr->next) {
		if (!strcasecmp(curr->name, name))
			return curr;
	}
	return 0;
}

void
domain_data_free(list, name)
	DOMAIN_DATA **list;
	const char *name;
{
	DOMAIN_DATA *curr, *prev, *next;

	/* sanity check */
	if (!list) return;

	curr = *list;
	prev = 0;
	while (curr) {
		if (!name || (*name == '\0' && curr->addr == 0) ||
		    curr->name == name || !strcasecmp(curr->name, name)) {
			next = curr->next;
			if (prev)
				prev->next = next;
			else    *list = next;

			if (curr->name) free(curr->name);
			free(curr);

			curr = next;
		} else {
			prev = curr;
			curr = curr->next;
		}
	}
}

static int
nameserver_request(domain, type, org, notify)
	const char *domain;
	DomainType type;
	SESSION *org;
	void (*notify)(SESSION *sd, DOMAIN_DATA *dd);
{
	SESSION *sd;
	DOMAIN_TRANSACT *dt;
	char buf[MAXDNAME];
	const u_char *cp;

	/* sanity check */
	if (!domain || !*domain) {
		errno = EINVAL;
		return -1;
	}
	if (!primary && domain_resolver_init() < 0)
		return -1;

	if ((sd = session_open(-1, (struct sockaddr *)primary, DataSequence)) == 0)
		return -1;

	if ((dt = new_transact()) == 0) {
		int save_errno = errno;
		session_free(sd);
		errno = save_errno;
		return -1;
	}
	switch (type) {
	case IpAddress:
	case MailExchanger:
		dt->name = strdup(domain);
		(void)strncpy(buf, domain, sizeof(buf));
		buf[sizeof(buf)-1] = '\0';
		dt->domain = strdup(buf);
		break;
	case DomainName:
		if ((dt->name = (char *)malloc(sizeof(in_addr_t))) == 0)
			break;
		memcpy(dt->name, domain, sizeof(in_addr_t));
		cp = (u_char *)domain;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d.in-addr.arpa",
			 cp[3], cp[2], cp[1], cp[0]);
		dt->domain = strdup(buf);
		break;
	}
	if (!dt->name || !dt->domain) {
		int save_errno = errno;
		session_free(sd);
		free_transact(dt);
		errno = save_errno;
		return -1;
	}
	dt->reqid = unique_reqid();
	dt->type = type;

	session_setcallback(sd, 0, nameserver_error, nameserver_reply);
	session_setcookie(sd, dt);
	session_settimeout(sd, NAMESERVER_TIMEOUT);

	if (nameserver_send(sd) < 0) {
		int save_errno = errno;
#ifdef	HAVE_REPORT_FUNC
		char ipaddr[50];
		report(Warn, 0, errno, "%lu: nameserver_send: %s",
		       sd->sid, peertoa(ipaddr, session_peer(sd)));
#endif
		session_free(sd);
		free_transact(dt);
		errno = save_errno;
		return -1;
	}
	if (org && session_bind(org, discard_request, dt) != -1)
		dt->sd = org;
	dt->callback = notify;
	return 0;
}

static int
nameserver_send(sd)
	SESSION *sd;
{
	DOMAIN_TRANSACT *dt = TRANSACT(sd);
	u_char buf[PACKETSZ];
	HEADER *hp = (HEADER *)buf;
	int len;
	u_char *cp, *dnptrs[50], **dpp, **lastdnptr;

	/* sanity check */
	if (!dt) {
		errno = EINVAL;
		return -1;
	}
	memset(hp, 0, HFIXEDSZ);
	hp->id = htons(dt->reqid);
	hp->rd = 1; /* recursion desired */
	hp->qdcount = htons(1); /* we allways utilize one query per packet */

	cp = buf + HFIXEDSZ;
	len = PACKETSZ - (HFIXEDSZ + QFIXEDSZ);
	dpp = dnptrs;
	*dpp++ = buf;
	*dpp = 0;
	lastdnptr = dnptrs + sizeof(dnptrs) / sizeof(dnptrs[0]);

	if ((len = dn_comp(dt->domain, cp, len, dnptrs, lastdnptr)) < 0)
		return -1;

	cp += len;
	/* translate our type into appropriate NS opcode && type */
	switch (dt->type) {
	case IpAddress:
		PUTSHORT(T_A, cp);
		break;
	case DomainName:
		PUTSHORT(T_PTR, cp);
		break;
	case MailExchanger:
		PUTSHORT(T_MX, cp);
		break;
	}
	PUTSHORT(C_IN, cp);
	len = cp - buf;

	dprintf(("nameserver_send: \"%s\"", dt->domain));

	return session_send(sd, buf, len);
}

static void
nameserver_reply(sd, data, len)
	SESSION *sd;
	const unsigned char *data;
	int len;
{
	DOMAIN_TRANSACT *dt;

	/* sanity check */
	if (!sd) return;

	if ((dt = parse_packet(data, len)) == 0) {
#ifdef	HAVE_REPORT_FUNC
		char ipaddr[50];
		report(Info, 0, 0, "%lu: nameserver_reply: %s: unexpected packet (len=%d)",
		       sd->sid, peertoa(ipaddr, session_peer(sd)), len);
#endif
		return;
	}
	if (dt->rcode < 0) {
#ifdef	HAVE_REPORT_FUNC
		char ipaddr[50];
		report(Info, 0, 0, "%lu: nameserver_reply: %s: broken packet (len=%d try=%d err=%d)",
		       sd->sid, peertoa(ipaddr, session_peer(sd)),
		       len, dt->retry + 1, -dt->rcode);
#endif
		return;
	}
#ifdef	HAVE_REPORT_FUNC
	if (dt->rcode != NOERROR &&
	    dt->rcode != SERVFAIL &&
	    dt->rcode != NXDOMAIN) {
		char ipaddr[50];
		report(Crit, 0, 0, "%lu: nameserver_reply: %s: %s (try=%d)",
		       sd->sid, peertoa(ipaddr, session_peer(sd)),
		       rcode2text[dt->rcode], dt->retry + 1);
	}
#endif
#ifdef	DEBUG
	dump_reply(dt);
#endif
	if (dt->rcode == NOERROR &&
	    (dt->type == MailExchanger ||
	     (dt->type == IpAddress && dt->expand && dt->expand < MAX_EXPAND_TRIES))) {
		DOMAIN_DATA *dd;
		for (dd = dt->data; dd; dd = dd->next) {
			/* it was CNAME -- expand it */
			if (dd->name && !dd->addr) {
				if (dt->domain) {
					if (!strcasecmp(dd->name, dt->domain))
						break; /* to prevent looping */
					free(dt->domain);
				}
				if ((dt->domain = strdup(dd->name)) == 0)
					break;
				dt->reqid = unique_reqid();
				dt->expand++;
				dt->retry = 0;
				dt->type = IpAddress;
				if (nameserver_send(sd) < 0)
					break;
				return;
			}
		}
	}
	nameserver_close(sd); /* caller notified inside */
}

static DOMAIN_TRANSACT *
parse_packet(data, len)
	const unsigned char *data;
	int len;
{
	const u_char *pkt = data;
	HEADER *hp = (HEADER *)pkt;
	const u_char *cp = pkt + HFIXEDSZ;
	int qdcount, ancount, nscount, arcount, nb;
	DOMAIN_TRANSACT *dt;
	DOMAIN_DATA *dd;
	u_short type, class, rdlen, pref;
	u_int ttl;
	char name[MAXDNAME+1];

	/*
	 * first check the response Header.
	 */
	if (!hp || len < HFIXEDSZ) {
		dprintf(("parse_packet: undersized packet, len=%d", len));
		return 0;
	}
	if (!hp->qr) {
		dprintf(("parse_packet: not a response"));
		return 0;
	}
	if (hp->opcode) {
		dprintf(("parse_packet: response not a QUERY"));
		return 0;
	}
	if (hp->rcode < NOERROR || hp->rcode > REFUSED) {
		dprintf(("parse_packet: bad reply code %d", (int)hp->rcode));
		return 0;
	}
	if ((dt = find_transact(ntohs(hp->id))) == 0) {
		dprintf(("parse_packet: invalid reqid"));
		return 0;
	}
	dt->rcode = hp->rcode; /* Header is OK; reply code fixed */

	qdcount = ntohs(hp->qdcount);
	ancount = ntohs(hp->ancount);
	nscount = ntohs(hp->nscount);
	arcount = ntohs(hp->arcount);

	dprintf(("parse_packet: rcode=%d qdcount=%d ancount=%d nscount=%d arcount=%d",
		 hp->rcode, qdcount, ancount, nscount, arcount));

	/*
	 * check Question section.
	 */
	while (qdcount-- > 0) {
		if ((nb = dn_expand(pkt, pkt + len, cp, name, sizeof(name))) < 0) {
			dprintf(("parse_packet: dn_expand: unexpected end of question"));
			dt->rcode = -1;
			return dt;
		}
		if (strcasecmp(name, dt->domain)) {
			dprintf(("parse_packet: question name mismatch transaction"));
			dt->rcode = -2;
			return dt;
		}
		cp += nb;
		if (cp + 2 * INT16SZ > pkt + len) {
			dprintf(("parse_packet: unexpected end of question"));
			dt->rcode = -3;
			return dt;
		}
		GETSHORT(type, cp);
		GETSHORT(class, cp);
		if (class != C_IN) {
			dprintf(("parse_packet: question class mismatch transaction"));
			dt->rcode = -4;
			return dt;
		}
		if ((type == T_A && dt->type == IpAddress) ||
		    (type == T_PTR && dt->type == DomainName) ||
		    (type == T_MX && dt->type == MailExchanger))
			continue;

		dprintf(("parse_packet: question type mismatch transaction"));
		dt->rcode = -5;
		return dt;
	}

	/*
	 * parse Answer section.
	 */
	while (ancount-- > 0) {
		if ((nb = dn_expand(pkt, pkt + len, cp, name, sizeof(name))) < 0) {
			dprintf(("parse_packet: dn_expand: unexpected end of answer"));
			dt->rcode = -10;
			return dt;
		}
		dprintf(("parse_packet: answer name \"%s\"", name));
		cp += nb;
		if (cp + 3 * INT16SZ + INT32SZ > pkt + len) {
			dprintf(("parse_packet: unexpected end of answer"));
			dt->rcode = -11;
			return dt;
		}
		GETSHORT(type, cp);
		GETSHORT(class, cp);
		GETLONG(ttl, cp);
		GETSHORT(rdlen, cp);
		if (cp + rdlen > pkt + len) {
			dprintf(("parse_packet: unexpected end of answer"));
			dt->rcode = -12;
			return dt;
		}
		if (class != C_IN) {
			dprintf(("parse_packet: answer class mismatch transaction"));
			dt->rcode = -13;
			return dt;
		}
		dprintf(("parse_packet: answer rdlen=%d", rdlen));

		if (type == T_A && dt->type == IpAddress) {
			/* XXX IPv6 incompatible yet */
			if (rdlen % sizeof(in_addr_t)) {
				dprintf(("parse_packet: unexpected rdlen in A RR"));
				dt->rcode = -14;
				return dt;
			}
			while (rdlen > 0) {
				dprintf(("parse_packet: A %d.%d.%d.%d (ttl=%d)",
					 cp[0], cp[1], cp[2], cp[3], ttl));
				if ((dd = domain_data_add(&dt->data, name, 0)) != 0) {
					if (!dd->ttl || !ttl || dd->ttl > ttl)
						dd->ttl = ttl;
					if (dd->addr == 0 || dd->addr == -1)
						dd->addr = *((in_addr_t *)cp);
				}
				cp += sizeof(in_addr_t);
				rdlen -= sizeof(in_addr_t);
			}
			continue;
		}
		if (type == T_MX && dt->type == MailExchanger) {
			if (rdlen < INT16SZ) {
				dprintf(("parse_packet: unexpected rdlen in MX RR"));
				dt->rcode = -15;
				return dt;
			}
			GETSHORT(pref, cp);
			rdlen -= INT16SZ;
			while (rdlen > 0) {
				if ((nb = dn_expand(pkt, pkt + len, cp, name, sizeof(name))) < 0) {
					dprintf(("parse_packet: dn_expand: unexpected end of answer"));
					dt->rcode = -16;
					return dt;
				}
				dprintf(("parse_packet: MX %d \"%s\" (ttl=%d)",
					 pref, name, ttl));
				if ((dd = domain_data_add(&dt->data, name, pref)) != 0) {
					if (!dd->ttl || !ttl || dd->ttl > ttl)
						dd->ttl = ttl;
				}
				cp += nb;
				rdlen -= nb;
			}
			continue;
		}
		if (type == T_PTR && dt->type == DomainName) {
			while (rdlen > 0) {
				if ((nb = dn_expand(pkt, pkt + len, cp, name, sizeof(name))) < 0) {
					dprintf(("parse_packet: dn_expand: unexpected end of answer"));
					dt->rcode = -17;
					return dt;
				}
				dprintf(("parse_packet: PTR \"%s\" (ttl=%d)",
					 name, ttl));
				if ((dd = domain_data_add(&dt->data, name, 0)) != 0) {
					if (!dd->ttl || !ttl || dd->ttl > ttl)
						dd->ttl = ttl;
				}
				cp += nb;
				rdlen -= nb;
			}
			continue;
		}
		if (type == T_CNAME) {
			dprintf(("parse_packet: CNAME \"%s\" removed", name));
			domain_data_free(&dt->data, name);
			cp += rdlen;
			continue;
		}
		/* simply skip it */
		dprintf(("parse_packet: answer name \"%s\" type %d",
			 name, type));
		cp += rdlen;
	}

	if (dt->type != MailExchanger)
		return dt;

	/*
	 * skip Authority section.
	 */
	while (nscount-- > 0) {
		if ((nb = dn_expand(pkt, pkt + len, cp, name, sizeof(name))) < 0) {
			dprintf(("parse_packet: dn_expand: unexpected end of authority"));
			dt->rcode = -20;
			return dt;
		}
		cp += nb;
		if (cp + 3 * INT16SZ + INT32SZ > pkt + len) {
			dprintf(("parse_packet: unexpected end of authority"));
			dt->rcode = -21;
			return dt;
		}
		GETSHORT(type, cp);
		GETSHORT(class, cp);
		GETLONG(ttl, cp);
		GETSHORT(rdlen, cp);
		if (cp + rdlen > pkt + len) {
			dprintf(("parse_packet: unexpected end of authority"));
			dt->rcode = -22;
			return dt;
		}
		/* simply skip it */
		dprintf(("parse_packet: authority name \"%s\" type %d",
			 name, type));
		cp += rdlen;
	}

	/*
	 * parse Additional section.
	 */
	while (arcount-- > 0) {
		if ((nb = dn_expand(pkt, pkt + len, cp, name, sizeof(name))) < 0) {
			dprintf(("parse_packet: dn_expand: unexpected end of answer"));
			dt->rcode = -30;
			return dt;
		}
		dprintf(("parse_packet: additional name \"%s\"", name));
		cp += nb;
		if (cp + 3 * INT16SZ + INT32SZ > pkt + len) {
			dprintf(("parse_packet: unexpected end of additional"));
			dt->rcode = -31;
			return dt;
		}
		GETSHORT(type, cp);
		GETSHORT(class, cp);
		GETLONG(ttl, cp);
		GETSHORT(rdlen, cp);
		if (cp + rdlen > pkt + len) {
			dprintf(("parse_packet: unexpected end of additional"));
			dt->rcode = -32;
			return dt;
		}
		if (class == C_IN && type == T_A) {
			/* XXX IPv6 incompatible yet */
			if (rdlen % sizeof(in_addr_t)) {
				dprintf(("parse_packet: unexpected rdlen in A RR"));
				dt->rcode = -33;
				return dt;
			}
			while (rdlen > 0) {
				dprintf(("parse_packet: A %d.%d.%d.%d (ttl=%d)",
					 cp[0], cp[1], cp[2], cp[3], ttl));
				if ((dd = domain_data_find(&dt->data, name)) != 0) {
					if (!dd->ttl || !ttl || dd->ttl > ttl)
						dd->ttl = ttl;
					if (dd->addr == 0 || dd->addr == -1)
						dd->addr = *((in_addr_t *)cp);
				}
				cp += sizeof(in_addr_t);
				rdlen -= sizeof(in_addr_t);
			}
			continue;
		}
		/* simply skip it */
		dprintf(("parse_packet: additional name \"%s\" type %d",
			 name, type));
		cp += rdlen;
	}

	return dt;
}

