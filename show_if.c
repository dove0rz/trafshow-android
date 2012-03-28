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

#include <stdio.h>
#include <string.h>
#include <pcap.h>

#include "show_if.h"
#include "trafshow.h"
#include "screen.h"
#include "selector.h"
#include "addrtoname.h"

#ifdef	notdef
static void addr2str(const pcap_addr_t *ap, char *addr_buf, int addr_len);
#endif

static void
scale_size(name, addr, descr)
	int *name, *addr, *descr;
{
	*name	= line_factor * (double)SHOW_IF_NAME;
	*addr	= line_factor * (double)SHOW_IF_ADDR;
	*descr	= line_factor * (double)SHOW_IF_DESCR;
}

static int
show_if_header(dst, size, unused)
	char *dst;
	int size;
	const void *unused;
{
	int name_sz, addr_sz, desc_sz;

	/* sanity check */
	if (!dst || size < 1 || unused)
		return 0;

	scale_size(&name_sz, &addr_sz, &desc_sz);

	snprintf(dst, size,
		 "%-*.*s %-*.*s %-*.*s",
		 name_sz, name_sz,	"Interface",
		 addr_sz, addr_sz,	"Address",
		 desc_sz, desc_sz,	"Description");
	return 0;
}

#ifdef	notdef
/* extract list of interface addr/mask pairs */
static void
addr2str(ap, addr_buf, addr_len)
	const pcap_addr_t *ap;
	char *addr_buf;
	int addr_len;
{
	int i, rest;
	char *cp;

	*addr_buf = '\0';
	cp = addr_buf;
	rest = addr_len - 1;
	for (; ap && rest > 0; ap = ap->next) {
		if (ap->addr) {
			if (*addr_buf) {
				*cp++ = ' ';
				*cp = '\0';
				rest--;
			}
			if (satoa(ap->addr, cp, rest)) {
				i = strlen(cp);
				cp += i;
				rest -= i;
			}
		}
		if (ap->netmask) {
			if (*addr_buf) {
				*cp++ = ' ';
				*cp = '\0';
				rest--;
			}
			if (satoa(ap->netmask, cp, rest)) {
				i = strlen(cp);
				cp += i;
				rest -= i;
			}
		}
	}
}
#endif

static int
show_if_line(dst, size, ph, idx)
	char *dst;
	int size;
	const PCAP_HANDLER *ph;
	int idx;
{
	int i, name_sz, addr_sz, desc_sz;

	/* sanity check */
	if (!dst || size < 1)
		return 0;

	*dst = '\0';
	for (i = 0; ph; ph = ph->next) {
		if (i++ == idx) break;
	}
	if (!ph) return 0;

	scale_size(&name_sz, &addr_sz, &desc_sz);
	snprintf(dst, size,
		 "%-*.*s %-*.*s %-*.*s",
		 name_sz, name_sz,	ph->name,
		 addr_sz, addr_sz,	ph->addrstr,
		 desc_sz, desc_sz,	ph->descr ? ph->descr : "");
	return 0;
}

static int
show_if_footer(dst, size, unused)
	char *dst;
	int size;
	const void *unused;
{
	/* sanity check */
	if (!dst || size < 1 || unused)
		return 0;

	(void)strncpy(dst, hostname, size);
	dst[size-1] = '\0';
	return 0;
}

SELECTOR *
show_if_selector()
{
	static SELECTOR *sp = 0;
	if (!sp && (sp = selector_init()) != 0) {
		sp->get_header = show_if_header;
		sp->get_line = show_if_line;
		sp->get_footer = show_if_footer;
	}
	return sp;
}

int
show_if_search(ph, str)
	PCAP_HANDLER *ph;
	const char *str;
{
	int idx;

	/* sanity check */
	if (!str || *str == '\0')
		return -1;

	for (idx = 0; ph; ph = ph->next, idx++) {
		if (strstr(ph->name, str))
			return idx;
		if (strstr(ph->addrstr, str))
			return idx;
	}
	return -1;
}

SELECTOR *
show_if_list(ph)
	PCAP_HANDLER *ph;
{
	SELECTOR *sp;

	/* sanity check */
	if (!ph || (sp = show_if_selector()) == 0)
		return 0;

	sp->header = 0; /* unused */
	sp->footer = 0; /* unused */

	sp->list = ph;
	sp->items = 0;
	for (; ph; ph = ph->next)
		sp->items++;

	return sp;
}

