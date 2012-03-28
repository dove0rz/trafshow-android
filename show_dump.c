/*
 *	Copyright (c) 2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifdef	HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef	HAVE_SLCURSES
#include <slcurses.h>
#elif	HAVE_NCURSES
#include <ncurses.h>
#else
#include <curses.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pcap.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>

#include "show_dump.h"
#include "show_stat.h" /* just for hdr2str() */
#include "parse_dl.h"
#include "trafshow.h"
#include "screen.h"
#include "netstat.h"
#include "getkey.h"
#include "addrtoname.h"
#include "util.h"

NETSTAT *dump_match = 0;
const char *cisco_netflow_dump = 0;
const char *dump_file = 0;

static char *build_filter_expr(char *dst, int size, const NETSTAT *ns);
static void *live_pcap_dump();
static void live_pcap_parse(u_char *a, const struct pcap_pkthdr *h, const u_char *p);
static void file_pcap_parse(u_char *a, const struct pcap_pkthdr *h, const u_char *p);
static void show_header_dump(PCAP_HANDLER *ph, const NETSTAT *ns);
static void show_ascii_dump(const u_char *p, int length);
static void show_hex_dump(const u_char *p, int length);

static pcap_t *live_pcap = 0;
static pcap_dumper_t *live_dump = 0;
static pthread_t *live_pcap_thr = 0;
static pcap_t *file_pcap = 0;
static FILE *file_netflow = 0;
static int redraw_lines = 0;

static void
print_mode(void)
{
	const char *cp = cisco_netflow_dump;
	char src_buf[100], dst_buf[100], proto_buf[20];

	/* sanity check */
	if (!dump_match) return;

	hdr2str(&dump_match->ns_hdr,
		src_buf, sizeof(src_buf),
		dst_buf, sizeof(dst_buf),
		proto_buf, sizeof(proto_buf));

	if (!cisco_netflow_dump) {
		switch (show_stat_mode) {
		case Size:	cp = "HexData"; break;
		case Data:	cp = "AsciiData"; break;
		case Packets:	cp = "Packets"; break;
		}
	}

	attrset(A_STANDOUT);
	printw("\n--- %s %s > %s %s flow ---",
	       proto_buf, src_buf, dst_buf, cp);
	attrset(A_NORMAL);

#ifdef	HAVE_WREDRAWLN
	wredrawln(stdscr, 0, LINES);
#endif
	refresh();
}

#ifndef	HAVE_PCAP_DUMP_FLUSH
int
pcap_dump_flush(pcap_dumper_t *p)
{

	if (fflush((FILE *)p) == EOF)
		return (-1);
	else
		return (0);
}
#endif

int
show_dump_open(ph, ns)
	const PCAP_HANDLER *ph;
	const NETSTAT *ns;
{
	int op;
	struct bpf_program filter;
        bpf_u_int32 net;
        bpf_u_int32 mask;
	char name[100], buf[256];

	/* sanity check */
	if (!ph || !ns) return -1;

	show_dump_close();

	if (!dump_match && (dump_match = (NETSTAT *)malloc(sizeof(NETSTAT))) == 0) {
		screen_status("%s: malloc: Out of memory?", ph->name);
		show_dump_close();
		return -1;
	}
	memcpy(dump_match, ns, sizeof(NETSTAT));

	if (ph->pcap) {
		/* open live packet capture */
		buf[0] = '\0';
		live_pcap = pcap_open_live(strcpy(name, ph->name),
					   DUMP_SNAPLEN, promisc, 1, buf);
		if (buf[0] != '\0')
			screen_status("%s: %s", ph->name, buf);
		if (!live_pcap) return -1;
#ifdef	notdef
		if (pcap_setnonblock(live_pcap, 1, buf) < 0) {
			screen_status("%s: %s", ph->name, buf);
			show_dump_close();
			return -1;
		}
#endif
		/* setup filter expression */
		if (pcap_lookupnet(strcpy(name, ph->name), &net, &mask, buf) < 0) {
			/* ignore error */
			net = 0;
			mask = 0;
		}
		if (!build_filter_expr(buf, sizeof(buf), ns)) {
			screen_status("%s: Can't build filter expression", ph->name);
			show_dump_close();
			return -1;
		}
		if (pcap_compile(live_pcap, &filter, buf, Oflag, mask) < 0) {
			screen_status("%s: %s", ph->name, pcap_geterr(live_pcap));
			show_dump_close();
			return -1;
		}
		op = pcap_setfilter(live_pcap, &filter);
		pcap_freecode(&filter);
		if (op < 0) {
			screen_status("%s: %s", ph->name, pcap_geterr(live_pcap));
			show_dump_close();
			return -1;
		}
	} else if ((cisco_netflow_dump = strdup(ph->name)) == 0) {
		screen_status("%s: strdup: Out of memory?", ph->name);
		show_dump_close();
		return -1;
	}

	/* open pcap dump file for writing */

	snprintf(buf, sizeof(buf), "%s/%s.XXXXXX", TEMP_DIR, progname);
	if ((op = mkstemp(buf)) < 0) {
		screen_status("%s: %s: %s",
			      ph->name, buf, strerror(errno));
		show_dump_close();
		return -1;
	}
	(void)close(op);
	if ((dump_file = strdup(buf)) == 0) {
		screen_status("%s: strdup: Out of memory?", ph->name);
		show_dump_close();
		return -1;
	}

	if (!cisco_netflow_dump) {
		if ((live_dump = pcap_dump_open(live_pcap, dump_file)) == 0) {
			screen_status("%s: %s", ph->name, pcap_geterr(live_pcap));
			show_dump_close();
			return -1;
		}
		pcap_dump_flush(live_dump); /* write header right now */

		/* spawn thread to dump live packet capture into the file */
		if ((live_pcap_thr = (pthread_t *)malloc(sizeof(pthread_t))) == 0) {
			screen_status("%s: malloc: Out of memory?", ph->name);
			show_dump_close();
			return -1;
		}
		if (pthread_create(live_pcap_thr, 0, live_pcap_dump, 0)) {
			screen_status("%s: pthread_create: Out of resources?", ph->name);
			show_dump_close();
			return -1;
		}

		/* open pcap dump file for reading */
		if ((file_pcap = pcap_open_offline(dump_file, buf)) == 0) {
			screen_status("%s: %s", ph->name, buf);
			show_dump_close();
			return -1;
		}
	} else if ((file_netflow = fopen(dump_file, "r")) == 0) {
		screen_status("%s: %s: %s",
			      ph->name, dump_file, strerror(errno));
		show_dump_close();
		return -1;
	}

	scrollok(stdscr, 1);
	screen_clear();
	print_mode();
	return 0;
}

static void *
live_pcap_dump()
{
	int op;

	while (live_pcap && live_dump) {
		op = pcap_dispatch(live_pcap, -1, live_pcap_parse,
				   (u_char *)live_dump);
		if (op == -2 || (op == -1 && errno != EAGAIN))
			break;
		if (op < 1) usleep(1000); /* 1ms idle to prevent deadloop */
	}
	return 0;
}

static void
live_pcap_parse(a, h, p)
	u_char *a;
	const struct pcap_pkthdr *h;
	const u_char *p;
{
	NETSTAT ns;

	/* sanity check */
	if (!a || !live_pcap) return;

	memset(&ns, 0, sizeof(NETSTAT));

	if (parse_dl(&ns, pcap_datalink(live_pcap), h->caplen, h->len, p) < 0)
		return;

	if (!netstat_match(&ns, dump_match))
		return;

	pcap_dump(a, h, p);
	pcap_dump_flush((pcap_dumper_t *)a);
}

void
show_dump_close()
{
	if (cisco_netflow_dump) {
		free((char *)cisco_netflow_dump);
		cisco_netflow_dump = 0;
	}
	if (file_netflow) {
		(void)fclose(file_netflow);
		file_netflow = 0;
	}

	if (live_pcap_thr) {
		pthread_cancel(*live_pcap_thr);
		free(live_pcap_thr);
		live_pcap_thr = 0;
	}
	if (live_dump) {
		pcap_dump_close(live_dump);
		live_dump = 0;
	}
	if (live_pcap) {
		pcap_close(live_pcap);
		live_pcap = 0;
	}
	if (file_pcap) {
		pcap_close(file_pcap);
		file_pcap = 0;
	}

	if (dump_file) {
		(void)unlink(dump_file);
		free((char *)dump_file);
		dump_file = 0;
	}
	scrollok(stdscr, 0);
}

void
show_dump_print(ph)
	PCAP_HANDLER *ph;
{
	if (!cisco_netflow_dump) {
		int op;

		/* sanity check */
		if (!file_pcap) return;

		clearerr(pcap_file(file_pcap)); /* tail file */
		while ((op = pcap_dispatch(file_pcap, -1, file_pcap_parse,
					   (u_char *)ph)) > 0);
		if (op < 0) {
			if (op == -1)
				screen_status(pcap_geterr(file_pcap));
			return;
		}
	} else {
		char *cp, buf[256];

		/* sanity check */
		if (!file_netflow) return;

		clearerr(file_netflow); /* tail file */
		while (fgets(buf, sizeof(buf), file_netflow) != 0) {
			buf[sizeof(buf)-1] = '\0';
			if ((cp = strpbrk(buf, "\r\n")) != '\0')
				*cp = '\0';
			printw("%s\n", buf);
			redraw_lines++;
		}
	}
	if (redraw_lines) {
#ifdef	HAVE_WREDRAWLN
		wredrawln(stdscr, 0, LINES);
#endif
		refresh();
		redraw_lines = 0;
	}
}

static void
file_pcap_parse(a, h, p)
	u_char *a;
	const struct pcap_pkthdr *h;
	const u_char *p;
{
	PCAP_HANDLER *ph = (PCAP_HANDLER *)a;
	FILE *fp;
	long sz;
	int hdrlen;
	NETSTAT ns;

	/* sanity check */
	if (!file_pcap) return;

	/* prevent huge output */
	if ((fp = pcap_file(file_pcap)) == 0 || (sz = fd_size(fileno(fp))) < 0)
		return;
	if (sz - ftell(fp) > DUMP_SNAPLEN * LINES)
		return;

	memset(&ns, 0, sizeof(NETSTAT));

	hdrlen = parse_dl(&ns, pcap_datalink(file_pcap), h->caplen, h->len, p);
	if (hdrlen < 0 || hdrlen > h->caplen)
		return;

	if (!netstat_match(&ns, dump_match))
		return;

	ns.mtime = h->ts;

	switch (show_stat_mode) {
	case Size:
		show_hex_dump(p + hdrlen, h->caplen - hdrlen);
		break;
	case Data:
		show_ascii_dump(p + hdrlen, h->caplen - hdrlen);
		break;
	case Packets:
		show_header_dump(ph, &ns);
		break;
	}
}

void
show_dump_input(ch)
	int ch;
{
	if (ch == 'c' || ch == 'C' || ch == K_CTRL('R'))
		screen_clear();
	else if (show_stat_input(0, ch))
		print_mode();
}

static char *
build_filter_expr(dst, size, ns)
	char *dst;
	int size;
	const NETSTAT *ns;
{
	char src_addr[100], dst_addr[100];

	src_addr[0] = '\0';
	dst_addr[0] = '\0';

	if (ns->ip_ver == 4) {
		(void)strcpy(src_addr, intoa(ns->ip_src_addr.ip_addr.s_addr));
		(void)strcpy(dst_addr, intoa(ns->ip_dst_addr.ip_addr.s_addr));
	}
#ifdef	INET6
	else if (ns->ip_ver == 6) {
		(void)inet_ntop(AF_INET6, &ns->ip_src_addr.ip6_addr, src_addr, sizeof(src_addr));
		(void)inet_ntop(AF_INET6, &ns->ip_dst_addr.ip6_addr, dst_addr, sizeof(dst_addr));
	}
#endif
	else if (ns->eth_type) {
		(void)strcpy(src_addr, etheraddr_string(ns->eth_src_addr));
		(void)strcpy(dst_addr, etheraddr_string(ns->eth_dst_addr));
	}

	if (src_addr[0] == '\0' || dst_addr[0] == '\0')
		return 0; /* should not happen */

	if (ns->ip_ver) {
		snprintf(dst, size,
			 "src %s and dst %s",
			 src_addr,  dst_addr);
	} else if (!strcmp(dst_addr, "broadcast") ||
		   !strcmp(dst_addr, "multicast")) {
		snprintf(dst, size,
			 "ether src %s and ether %s",
			 src_addr, dst_addr);
	} else {
		snprintf(dst, size,
			 "ether src %s and ether dst %s",
			 src_addr, dst_addr);
	}
	return dst;
}

static void
show_header_dump(ph, ns)
	PCAP_HANDLER *ph;
	const NETSTAT *ns;
{
	char time_buf[100], src_buf[100], dst_buf[100], proto_buf[20];
#ifdef	notdef
	NETSTAT find = *ns;
	if (netstat_find(ph, &find))
		ns = &find;
#endif
	(void)strftime(time_buf, sizeof(time_buf),
		       "%T", localtime((time_t *)&ns->mtime.tv_sec));
	hdr2str(&ns->ns_hdr,
		src_buf, sizeof(src_buf),
		dst_buf, sizeof(dst_buf),
		proto_buf, sizeof(proto_buf));

	printw("\n%s.%03d %s %s > %s %d/%d bytes",
	       time_buf, (int)(ns->mtime.tv_usec / 1000),
	       proto_buf, src_buf, dst_buf,
	       (int)ns->pkt_len, (int)ns->data_len);

	redraw_lines++;
}

static void
show_ascii_dump(cp, length)
	const u_char *cp;
	int length;
{
	/* sanity check */
	if (!cp || length < 1)
		return;

	if (!redraw_lines)
		addch('\n');
	while (--length >= 0) {
		if (*cp != '\r' && *cp != '\b')
			addch(*cp);
		cp++;
	}
	redraw_lines++;
}

#ifdef	ACS_VLINE
#define	VLINE	ACS_VLINE
#else
#define	VLINE	'|'
#endif

/* stolen from tcpdump's ascii-print() */

#define HEXDUMP_BYTES_PER_LINE		16
#define HEXDUMP_SHORTS_PER_LINE		(HEXDUMP_BYTES_PER_LINE / 2)
#define HEXDUMP_HEXSTUFF_PER_SHORT	5 /* 4 hex digits and a space */
#define HEXDUMP_HEXSTUFF_PER_LINE \
		(HEXDUMP_HEXSTUFF_PER_SHORT * HEXDUMP_SHORTS_PER_LINE)

static void
show_hex_dump(cp, length)
	const u_char *cp;
	int length;
{
	int oset = 0;
	register u_int i;
	register int s1, s2;
	register int nshorts;
	char hexstuff[HEXDUMP_SHORTS_PER_LINE*HEXDUMP_HEXSTUFF_PER_SHORT+1], *hsp;
	char asciistuff[100], *asp;
	u_int maxlength = HEXDUMP_SHORTS_PER_LINE;

	/* sanity check */
	if (!cp || length < 1)
		return;

	nshorts = length / sizeof(u_short);
	i = 0;
	hsp = hexstuff;
	asp = asciistuff;
	while (--nshorts >= 0) {
		s1 = *cp++;
		s2 = *cp++;
		(void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
			       " %02x%02x", s1, s2);
		hsp += HEXDUMP_HEXSTUFF_PER_SHORT;
		*(asp++) = (isgraph(s1) ? s1 : '.');
		*(asp++) = (isgraph(s2) ? s2 : '.');
		if (++i >= maxlength) {
			i = 0;
			*hsp = *asp = '\0';

			printw("\n0x%04X ", oset);
			addch(VLINE);
			printw("%-*s ", HEXDUMP_HEXSTUFF_PER_LINE, hexstuff);
			addch(VLINE);
			addch(' ');
			addstr(asciistuff);

			hsp = hexstuff;
			asp = asciistuff;
			oset += HEXDUMP_BYTES_PER_LINE;

			redraw_lines++;
		}
	}
	if (length & 1) {
		s1 = *cp++;
		(void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
			       " %02x", s1);
		hsp += 3;
		*(asp++) = (isgraph(s1) ? s1 : '.');
		++i;
	}
	if (i > 0) {
		*hsp = *asp = '\0';

		printw("\n0x%04X ", oset);
		addch(VLINE);
		printw("%-*s ", HEXDUMP_HEXSTUFF_PER_LINE, hexstuff);
		addch(VLINE);
		addch(' ');
		addstr(asciistuff);

		redraw_lines++;
	}
}

