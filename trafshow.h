/*
 *	Copyright (c) 1993-2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifndef	_TRAFSHOW_H_
#define	_TRAFSHOW_H_

#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pthread.h>

/*
 * The default snapshot length.  This value allows most printers to print
 * useful information while keeping the amount of unwanted data down.
 */
#ifndef INET6
#define	SNAPLEN		68	/* ether + IPv4 + TCP + 14 */
#define	ADDRBITLEN	32	/* in bits */
#else
#define	SNAPLEN		96	/* ether + IPv6 + TCP + 22 */
#define	ADDRBITLEN	128	/* in bits */
#endif

#define	REFRESH_TIME	2	/* in seconds */
#define	PURGE_TIME	10	/* must be bigger than REFRESH_TIME */

#define	TEMP_DIR	"/tmp"

typedef enum { Interfaces, NetStat, FlowDump, HelpPage } ShowMode;

#ifndef	TRUE
#define	TRUE	1
#endif
#ifndef	FALSE
#define	FALSE	0
#endif

#ifndef	MAX
#define	MAX(a, b)	((b) < (a) ? (a) : (b))
#endif
#ifndef	MIN
#define	MIN(a, b)	((a) < (b) ? (a) : (b))
#endif
#ifndef	ABS
#define	ABS(a)		((a) >= 0  ? (a) : -(a))
#endif

#if defined(htons) && defined(_BIG_ENDIAN) && defined(sparc)
#undef	htons
#define	htons(x)	((uint16_t)(x))
#endif
#if defined(ntohs) && defined(_BIG_ENDIAN) && defined(sparc)
#undef	ntohs
#define	ntohs(x)	((uint16_t)(x))
#endif

#ifdef	DEBUG
#include <time.h>
#include <stdio.h>
#define	dprintf(x)	\
	{\
		char Dbuf[50];\
		struct timeval Dtv;\
		gettimeofday(&Dtv, 0);\
		strftime(Dbuf, sizeof(Dbuf), "%T", localtime(&Dtv.tv_sec));\
		printf("%s.%03d: ", Dbuf, (int)(Dtv.tv_usec / 1000));\
		printf x;\
		printf("\n");\
	}
#else
#define	dprintf(x)
#endif

struct netstat_header;
struct htab;
struct selector;

typedef	struct pcap_handler {
	struct pcap_handler *prev, *next;
	struct pcap_handler *top, *deep;

/* fixed input parameters */

	const char *name;		/* interface name */
	const char *descr;		/* interface description (or null) */
	const char *addrstr;		/* interface network address list */
	pcap_t *pcap;			/* pcap device handler */
	pcap_addr_t *addr;		/* pcap device addresses */

/* aggregation stuff */
	int masklen;			/* mask length in bits */
	struct netstat_header *maskhdr;	/* mask address */

/* operation parameters */

	/*struct timeval pcap_time;*/	/* last packet capture time */

	pthread_mutex_t *ns_mutex;	/* netstat hash table mutex */
	struct htab *ns_hash;		/* netstat hash table */

	struct selector *selector;	/* list items selector */
	int selected;			/* the flag: this item is selected */

	/* total statistics */
	u_int64_t pkt_cnt;              /* packet counter */
	u_int64_t pkt_len;              /* length of ip packet */
	u_int64_t data_len;             /* length of ip data */

	u_int64_t pkt_cnt_rate;         /* rate of packet counter */
	u_int64_t pkt_len_rate;         /* rate of packet length */
	u_int64_t data_len_rate;        /* rate of data length */

} PCAP_HANDLER;


/* function prototypes */
struct netstat;
char *pcap_setexpr(PCAP_HANDLER *ph_list, const char *expr);
PCAP_HANDLER *pcap_get_selected(PCAP_HANDLER *ph);
PCAP_HANDLER *pcap_set_selected(PCAP_HANDLER *ph, int idx);
void pcap_save(PCAP_HANDLER *ph, const struct netstat *ns);
void pcap_purge(void *arg); /* PCAP_HANDLER *ph_list */
void pcap_clear(void *arg); /* PCAP_HANDLER *ph_list */
void pcap_show(void *arg); /* PCAP_HANDLER *ph_list */

PCAP_HANDLER *pcaph_create(PCAP_HANDLER *top, const struct netstat_header *nh);
void pcaph_close(PCAP_HANDLER *ph);

/* global variables */

extern char package[];
extern char version[];
extern char target[];
extern char compiled[];
extern const char *progname;
extern const char *hostname;
extern const char *color_conf;
extern char *expression;
extern char *search;
extern int aggregate;
extern int popbackflow;
extern int refresh_time;
extern int purge_time;
extern int promisc;
extern int Oflag;
extern int nflag;
extern ShowMode show_mode;

#endif	/* !_TRAFSHOW_H_ */
