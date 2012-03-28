/*
 *	Copyright (c) 1993-2006 Rinet Corp., Novosibirsk, Russia
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
#include <sys/types.h>
#include <sys/socket.h>
#ifdef	HAVE_PCAP_GET_SELECTABLE_FD
#include <sys/select.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pcap.h>
#include <pthread.h>
#include <errno.h>
#ifdef	linux
#include <sys/ioctl.h>
#include <linux/if.h>
#endif

#include "trafshow.h"
#include "parse_dl.h"
#include "screen.h"
#include "show_if.h"
#include "show_stat.h"
#include "show_dump.h"
#include "getkey.h"
#include "selector.h"
#include "addrtoname.h"
#include "netstat.h"
#include "util.h"
#include "events.h"
#include "session.h"
#include "cisco_netflow.h"
#include "help_page.h"

char copyright[] = "Copyright (c) 1993-2006 Rinet Corp., Novosibirsk, Russia";

static void vers();
static void usage();
static pcap_if_t *pcap_matchdev(pcap_if_t *dp, const char *name);
static int pcap_init(PCAP_HANDLER **ph_list, pcap_if_t *dp);
static void *pcap_feed(void *arg); /* PCAP_HANDLER *ph */
#ifdef	HAVE_PCAP_GET_SELECTABLE_FD
static void *pcap_feed2(void *arg); /* PCAP_HANDLER *ph */
#endif
static void parse_feed(u_char *a, const struct pcap_pkthdr *h, const u_char *p);
static void *traf_show(void *arg); /* PCAP_HANDLER *ph_list */
static void *catch_signals(void *arg); /* sigset_t *set */
static void cleanup(void);

static int resize_pending = 0;

const char *progname;
const char *hostname;
const char *color_conf = 0;
char *expression = 0;
char *search = 0;
int aggregate = -1;
int popbackflow = 0;
int refresh_time = REFRESH_TIME;
int purge_time = PURGE_TIME;
ShowMode show_mode = Interfaces;

int promisc = 1;	/* promiscuous mode */
int Oflag = 1;		/* optimize filter code */
int nflag = 0;		/* use numeric value of service ports and protocols */

int
main(argc, argv)
	int argc;
	char **argv;
{
	char buf[256], *dev_name = 0, *filter = 0;
	pcap_if_t *dev_list = 0;
	PCAP_HANDLER *ph_list = 0;
	int op, udp_port = CNF_PORT;
	sigset_t sigset;
	pthread_t show_thr, sig_thr, pcap_thr;
	extern char *optarg;
	extern int optind, opterr;

	progname = strdup(strip_path(argv[0]));

	if (gethostname(buf, sizeof(buf)) < 0)
		(void)strcpy(buf, "localhost");
	hostname = strdup(buf);

	/* get list of all pcap devices */
	if (pcap_findalldevs(&dev_list, buf) < 0) {
		fprintf(stderr, "pcap_findalldevs: %s\n", buf);
		exit(1);
	}

	opterr = 0;
	while ((op = getopt(argc, argv, "a:bc:i:ns:u:pF:R:P:vh?")) != EOF) {
		switch (op) {
		case 'a':
			aggregate = atoi(optarg);
			if (aggregate < 0 || aggregate > ADDRBITLEN)
				usage();
			break;
		case 'b':
			popbackflow = 1;
			break;
		case 'c':
			color_conf = optarg;
			break;
		case 'i':
			dev_name = optarg;
			break;
		case 'n':
			nflag = 1;
			break;
		case 's':
			search = strdup(optarg);
			break;
		case 'u':
			udp_port = atoi(optarg);
			break;
		case 'p':
			promisc = 0;
			break;
		case 'F':
			filter = optarg;
			break;
		case 'R':
			if ((refresh_time = atoi(optarg)) < 1)
				usage();
			break;
		case 'P':
			if ((purge_time = atoi(optarg)) < 1)
				usage();
			break;
		case 'v':
			vers();
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	/* check for command line options */
	if (dev_name && (dev_list = pcap_matchdev(dev_list, dev_name)) == 0) {
		fprintf(stderr, "Interface %s not found\n", dev_name);
		exit(1);
	}
	if (refresh_time >= purge_time) {
		fprintf(stderr, "Refresh Time (%d sec) must be less than Purge Time (%d sec)\n",
			refresh_time, purge_time);
		exit(1);
	}

	/* initialize list of pcap handlers */
	if ((op = pcap_init(&ph_list, dev_list)) < 1) {
		fprintf(stderr, "No packet capture device available (no permission?)\n");
		exit(1);
	}

	/* listen for cisco netflow */
	if (udp_port > 1 && (cisco_netflow_init(&ph_list, udp_port) < 0)) {
		fprintf(stderr, "Can't start cisco-netflow collector at UDP port %d\n",
			udp_port);
		exit(1);
	}

	/* if only one interface -- make it selected */
	if (ph_list && op == 1) {
		ph_list->selected = 1;
		show_mode = NetStat;
	}

	/* get back to user process */
	setuid(getuid());

	/* set the filter expression if any */
	if (ph_list && (argv[optind] || filter)) {
		if (filter)
			expression = load_file(filter);
		else	expression = copy_argv(&argv[optind]);
		if (!expression) exit(1);

		if ((filter = pcap_setexpr(ph_list, expression)) != 0) {
			fprintf(stderr, "%s\n", filter);
			exit(1);
		}
	}

	/* intialize addrtoname stuff */
	init_addrtoname();

	/* initialize curses */
	if (screen_open(0) < 0)
		exit(1);

	/* register cleanup function at exit */
	atexit(cleanup);

	show_thr = pthread_self();

	/* spawn thread to catch some usefull signals */
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGWINCH);
	sigprocmask(SIG_BLOCK, &sigset, 0);
	if (pthread_create(&sig_thr, 0, catch_signals, &sigset)) {
		perror("pthread_create(catch_signals)");
		exit(1);
	}

	/* spawn thread for the live packet capture */
	if (ph_list) {
#ifdef	HAVE_PCAP_GET_SELECTABLE_FD
		PCAP_HANDLER *ph;
		for (ph = ph_list; ph; ph = ph->next) {
			if (pcap_get_selectable_fd(ph->pcap) < 0)
				break;
		}
		if (!ph) {
			if (pthread_create(&pcap_thr, 0, pcap_feed2, ph_list)) {
				perror("pthread_create(pcap_feed2)");
				exit(1);
			}
		} else
#endif
		if (pthread_create(&pcap_thr, 0, pcap_feed, ph_list)) {
			perror("pthread_create(pcap_feed)");
			exit(1);
		}
	}

	/* start main loop */
	(void)traf_show(ph_list);

	exit(0);
}

static void
cleanup()
{
	if (dump_file) (void)unlink(dump_file);
	screen_close();
	_exit(0);
}

static void *
catch_signals(arg)
	void *arg;
{
	sigset_t sigset;
	int sig;

	for (;;) {
		sigset = *(sigset_t *)arg;
		if (sigwait(&sigset, &sig))
			break; /* should not happen */

		if (sig == SIGWINCH)
			resize_pending++;
	}
	return 0;
}

static pcap_if_t *
pcap_matchdev(dp, name)
	pcap_if_t *dp;
	const char *name;
{
	for (; dp; dp = dp->next) {
		if (!strcasecmp(dp->name, "any"))
			continue; /* discard linux's any device silently */

		if (!strcasecmp(dp->name, name)) {
			dp->next = 0;
			return dp;
		}
	}
	return 0;
}

static int
pcap_init(ph_list, dp)
	PCAP_HANDLER **ph_list;
	pcap_if_t *dp;
{
	int cnt = 0, err = 0, type;
	pcap_t *pd;
	const pcap_addr_t *ap;
	PCAP_HANDLER *ph, *ph_prev = 0;
	char *cp, buf[256];

	if (!ph_list) return -1;

	for (; dp; dp = dp->next) {
		if (!strcasecmp(dp->name, "any"))
			continue; /* discard linux's any device silently */

		buf[0] = '\0';
		if ((pd = pcap_open_live(dp->name, SNAPLEN, promisc, 1, buf)) == 0) {
			fprintf(stderr, "%s: %s\n", dp->name, buf);
			err++;
			continue;
		}
		type = pcap_datalink(pd);
		if (!is_parse_dl(type)) {
			fprintf(stderr, "%s: datalink type %d is not supported\n",
				dp->name, type);
			pcap_close(pd);
			err++;
			continue;
		}
		if (buf[0] != '\0') {
			fprintf(stderr, "%s: %s\n", dp->name, buf);
			err++;
		}
		if (pcap_setnonblock(pd, 1, buf) < 0) {
			fprintf(stderr, "%s: %s\n", dp->name, buf);
			pcap_close(pd);
			err++;
			continue;
		}
		if ((ph = (PCAP_HANDLER *)malloc(sizeof(PCAP_HANDLER))) == 0) {
			perror("malloc");
			exit(1);
		}
		memset(ph, 0, sizeof(PCAP_HANDLER));

		ph->masklen = aggregate;
		ph->name = strdup(dp->name);
		if (dp->description && *dp->description)
			ph->descr = strdup(dp->description);
		else if (dp->flags & PCAP_IF_LOOPBACK)
			ph->descr = strdup("Loopback");
		else	ph->descr = strdup(parse_dl_name(type));
		ph->pcap = pd;
		ph->addr = dp->addresses; /* XXX must be deep copy? */

		/* make string of network address list */
		buf[0] = '\0';
		cp = buf;
#ifdef  linux
		if (type == DLT_EN10MB && (dp->flags & PCAP_IF_LOOPBACK) == 0) {
			int sfd = socket(AF_INET, SOCK_DGRAM, 0);
			if (sfd != -1) {
				struct ifreq ifr;
				memset(&ifr, 0, sizeof(struct ifreq));
				memcpy(ifr.ifr_name, dp->name,
				       MIN(strlen(dp->name), sizeof(ifr.ifr_name)-1));
				if (ioctl(sfd, SIOCGIFHWADDR, &ifr) != -1) {
					(void)strcpy(cp, linkaddr_string((u_char *)ifr.ifr_hwaddr.sa_data,
									 ETHER_ADDR_LEN));
					cp += strlen(cp);
				}
				close(sfd);
			}
		}
#endif
		for (ap = dp->addresses; ap && cp < (buf + sizeof(buf)-1);
		     ap = ap->next) {
			if (buf[0]) {
				*cp++ = ' ';
				*cp = '\0';
			}
			if (satoa(ap->addr, cp, (buf + sizeof(buf)) - cp))
				cp += strlen(cp);
		}
		*cp = '\0';
		ph->addrstr = strdup(buf);

		if ((ph->ns_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t))) == 0) {
			perror("malloc");
			exit(1);
		}
		pthread_mutex_init(ph->ns_mutex, 0);

		ph->prev = ph_prev;
		if (ph_prev)
			ph_prev->next = ph;
		else	*ph_list = ph;
		ph_prev = ph;

		cnt++;
	}
	if (cnt && err) {
		fflush(stderr);
		sleep(1);
	}
	return cnt;
}

PCAP_HANDLER *
pcaph_create(top, nh)
	PCAP_HANDLER *top;
	const struct netstat_header *nh;
{
	PCAP_HANDLER *ph;

	/* sanity check */
	if (!top || top->masklen < 0 || !nh)
		return 0;

	if ((ph = (PCAP_HANDLER *)malloc(sizeof(PCAP_HANDLER))) == 0)
		return 0;
	memset(ph, 0, sizeof(PCAP_HANDLER));

	ph->masklen = -1;
	ph->maskhdr = (struct netstat_header *)malloc(sizeof(struct netstat_header));
	if (!ph->maskhdr) return 0;
	memcpy(ph->maskhdr, nh, sizeof(struct netstat_header));
	netstat_aggregate(ph->maskhdr, top->masklen);

	if ((ph->ns_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t))) == 0) {
		free(ph->maskhdr);
		return 0;
	}
	pthread_mutex_init(ph->ns_mutex, 0);

	ph->name = top->name;
	ph->descr = top->descr;
	ph->pcap = top->pcap;
	ph->selected = 1;

	ph->top = top;
	top->deep = ph;
	return ph;
}

void
pcaph_close(ph)
	PCAP_HANDLER *ph;
{
	/* sanity check */
	if (!ph || !ph->top) return;

	ph->top->deep = 0;
	if (ph->deep) pcaph_close(ph->deep); /* recursion */

	netstat_free(ph);
	if (ph->ns_mutex) {
		pthread_mutex_destroy(ph->ns_mutex);
		free(ph->ns_mutex);
		ph->ns_mutex = 0;
	}
	remove_event(0, ph);
	if (ph->maskhdr) free(ph->maskhdr);
	if (ph->selector) {
		if (ph->selector->list)
			free(ph->selector->list);
		free(ph->selector);
	}
	free(ph);
}

char *
pcap_setexpr(ph, expr)
	PCAP_HANDLER *ph;
	const char *expr;
{
	int op;
	struct bpf_program filter;
	bpf_u_int32 net;
	bpf_u_int32 mask;
	char name[100], buf[256];

	if (!expr) return 0;

	for (; ph; ph = ph->next) {
		if (!ph->pcap) /* skip non-pcap devices */
			continue;

		if (pcap_lookupnet(strcpy(name, ph->name), &net, &mask, buf) < 0) {
			/* ignore error */
			net = 0;
			mask = 0;
		}

		(void)strncpy(buf, expr, sizeof(buf));
		buf[sizeof(buf)-1] = '\0';
		if (pcap_compile(ph->pcap, &filter, buf, Oflag, mask) < 0)
			return pcap_geterr(ph->pcap);

		op = pcap_setfilter(ph->pcap, &filter);
		pcap_freecode(&filter);
		if (op < 0) return pcap_geterr(ph->pcap);
	}
	return 0;
}

static void *
pcap_feed(arg)
	void *arg;
{
	PCAP_HANDLER *ph, *ph_list = (PCAP_HANDLER *)arg;
	int npkt = -1, ndev, op;

	do {
		if (!npkt) usleep(1000); /* 1ms idle to prevent deadloop */
		npkt = 0;
		ndev = 0;
		for (ph = ph_list; ph; ph = ph->next) {
			if (!ph->pcap) /* skip non-pcap devices */
				continue;
			op = pcap_dispatch(ph->pcap, -1, parse_feed, (u_char *)ph);

			if (op > 0) {
				npkt += op;
			} else if (op == -2 || (op == -1 && errno != EAGAIN)) {
				pcap_close(ph->pcap);
				ph->pcap = 0;
				continue;
			}
			ndev++;
		}
	} while (ndev);

	return 0;
}

#ifdef	HAVE_PCAP_GET_SELECTABLE_FD
static void *
pcap_feed2(arg)
	void *arg;
{
	PCAP_HANDLER *ph, *ph_list = (PCAP_HANDLER *)arg;
	int npkt = -1, ndev, op;
	fd_set readfds;

	for (;;) {
#ifdef	notdef
		if (!npkt) usleep(1000); /* 1ms idle to prevent deadloop */
#endif
		npkt = 0;
		ndev = 0;
		FD_ZERO(&readfds);
		for (ph = ph_list; ph; ph = ph->next) {
			if (!ph->pcap) /* skip non-pcap devices */
				continue;
			op = pcap_get_selectable_fd(ph->pcap);
			if (op < 0) /* should not happen */
				continue;
			if (op + 1 > ndev)
				ndev = op + 1;
			FD_SET(op, &readfds);
		}
		if (ndev < 1) /* no one device fd for selecting? */
			break;

		if ((op = select(ndev, &readfds, 0, 0, 0)) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			/* select error? */
			break;
		}
		if (!op) /* select timed out, try again */
			continue;
		for (ph = ph_list; ph; ph = ph->next) {
			if (!ph->pcap) /* skip non-pcap devices */
				continue;
#ifdef	notdef
			if (!FD_ISSET(pcap_get_selectable_fd(ph->pcap), &readfds))
				continue; /* skip silent devices */
#endif
			op = pcap_dispatch(ph->pcap, -1, parse_feed, (u_char *)ph);
			if (op > 0) {
				npkt += op;
			} else if (op == -2 || (op == -1 && errno != EAGAIN)) {
				pcap_close(ph->pcap);
				ph->pcap = 0;
			}
		}
	}
	return 0;
}
#endif

static void
parse_feed(a, h, p)
	u_char *a;
	const struct pcap_pkthdr *h;
	const u_char *p;
{
	PCAP_HANDLER *ph = (PCAP_HANDLER *)a;
	NETSTAT ns;

	/* sanity check */
	if (!ph || !ph->pcap) return;

	/*ph->pcap_time = h->ts;*/
	memset(&ns, 0, sizeof(NETSTAT));

	if (parse_dl(&ns, pcap_datalink(ph->pcap), h->caplen, h->len, p) < 0)
		return;

	ns.mtime = h->ts;
	pcap_save(ph, &ns);
}

void
pcap_save(ph, ns)
	PCAP_HANDLER *ph;
	const NETSTAT *ns;
{
	int num;
	struct netstat_header nh;

	/* sanity check */
	if (!ph || !ns) return;

	if (netstat_insert(ph, ns) && aggregate < 0) {
		num = netstat_count(ph);
		if (num > 5000) {
			if (ph->masklen)
				ph->masklen = 0;
		} else if (num > 1000) {
			if (ph->masklen < 0 || ph->masklen > 16)
				ph->masklen = 16;
		} else if (num > 250) {
			if (ph->masklen < 0 || ph->masklen > 24)
				ph->masklen = 24;
		}
	}
	while (ph->deep) {
		num = ph->masklen;
		ph = ph->deep;
		if (!ph->maskhdr) /* should not happen */
			continue;
		memcpy(&nh, &ns->ns_hdr, sizeof(struct netstat_header));
		netstat_aggregate(&nh, num);
		if (!memcmp(&nh, ph->maskhdr, sizeof(struct netstat_header)))
			netstat_insert(ph, ns);
	}
}

void
pcap_show(arg)
	void *arg;
{
	PCAP_HANDLER *ph = (PCAP_HANDLER *)arg;
	SELECTOR *sp;
	int idx;
	struct timeval now;

	gettimeofday(&now, 0);

	switch (show_mode) {
	case Interfaces:
		sp = show_if_list(ph);
		if (search && (idx = show_if_search(ph, search)) != -1)
			selector_set(idx, sp);
		selector_redraw(sp);
		break;
	case NetStat:
		ph = pcap_get_selected(ph);
		sp = show_stat_list(ph);
		if (search && (idx = show_stat_search(ph, search)) != -1)
			selector_set(idx, sp);
		selector_redraw(sp);
		break;
	case FlowDump:
		show_dump_print(pcap_get_selected(ph));
		break;
	case HelpPage:
#ifdef	notdef
		/* overlapping is not good idea -- too flicker */
		show_mode = help_page_mode();
		if (show_mode != HelpPage) { /* just for sanity */
			pcap_show(arg);
			show_mode = HelpPage;
		}
#endif
		selector_redraw(help_page_selector());
		break;
	}

	/* schedule next time */
	now.tv_sec += refresh_time;
	add_event(&now, pcap_show, arg);
}

void
pcap_purge(arg)
	void *arg;
{
	PCAP_HANDLER *ph = (PCAP_HANDLER *)arg, *p;
	struct timeval now;

	gettimeofday(&now, 0);
	now.tv_sec -= purge_time;

	for (; ph; ph = ph->next) {
		for (p = ph; p; p = p->deep)
			netstat_purge(p, &now);
	}
	/* schedule next time */
	now.tv_sec += purge_time * 2;
	add_event(&now, pcap_purge, arg);

	pcap_show(arg);
}

void
pcap_clear(arg)
	void *arg;
{
	PCAP_HANDLER *ph = (PCAP_HANDLER *)arg, *p;

	for (; ph; ph = ph->next) {
		for (p = ph; p; p = p->deep)
			netstat_purge(p, 0);
	}
	pcap_show(arg);
}

PCAP_HANDLER *
pcap_get_selected(ph)
	PCAP_HANDLER *ph;
{
	for (; ph; ph = ph->next) {
		if (ph->selected) {
			while (ph->deep) ph = ph->deep;
			return ph;
		}
	}
	return 0;
}

PCAP_HANDLER *
pcap_set_selected(ph, idx)
	PCAP_HANDLER *ph;
	int idx;
{
	PCAP_HANDLER *sel = 0;
	int i = 0;

	for (; ph; ph = ph->next) {
		if (i++ == idx) {
			sel = ph;
			ph->selected = 1;
		} else	ph->selected = 0;
	}
	return sel;
}

static void *
traf_show(arg)
	void *arg;
{
	PCAP_HANDLER *ph_list = (PCAP_HANDLER *)arg;
	int op, nfds;
	fd_set readfds, writefds;
	struct timeval timeout;

	/* start show */
	pcap_purge(ph_list);

	/* init keyboard functions */
	getkey_init(ph_list);

	for (;;) {
		if (resize_pending) {
			if (screen_open(resize_pending) < 0)
				return 0;
			add_event(0, pcap_show, ph_list);
			resize_pending = 0;
		}
		nfds = 0;
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		op = select_event(&timeout);
		if (!session_select(&nfds, &readfds, &writefds, &timeout, &op)) {
			/* no one active session?? should not happen */
			return 0;
		}
		op = select(nfds, &readfds, &writefds, 0, op ? 0 : &timeout);
		if (op < 1) { /* select interrupted by signals or timed out */
			if (op < 0) {
				if (errno == EINTR || errno == EAGAIN)
					continue;
				screen_status("select: %s", strerror(errno));
				return 0;
			} else	session_timeout();
		} else	session_operate(&readfds, &writefds);
	}

	/* NOT REACHED */
	return 0;
}

static void
vers()
{
	extern char pcap_version[];

	int hc = 0;
#ifdef  HAVE_HAS_COLORS
	initscr();
	hc = has_colors();
	endwin();
#endif	/* HAVE_HAS_COLORS */

	fprintf(stderr, "\n%s Version %s\ncompiled for %s with\n %s\n",
		progname, version, target, compiled);

	fprintf(stderr, "\tlibpcap version %s\n", pcap_version);

#ifdef	HAVE_SLCURSES
	fprintf(stderr, "\tslcurses version %d\n", SLang_Version);
#elif	HAVE_NCURSES
#ifdef	NCURSES_VERSION
	fprintf(stderr, "\tncurses version %s\n", NCURSES_VERSION);
#else
	fprintf(stderr, "\tncurses version unknown\n");
#endif	/* NCURSES_VERSION */
#elif	HAVE_CURSES
	fprintf(stderr, "\tunknown curses library\n");
#endif	/* HAVE_SLCURSES */

#ifdef	HAVE_HAS_COLORS
	fprintf(stderr, "\tcolors support\n");
	if (hc) fprintf(stderr, "\tyour current terminal has color capability\n");
#ifndef	HAVE_SLCURSES
	else fprintf(stderr, "\tyour current terminal has no color capability\n");
#endif
#else
	fprintf(stderr, "\tno colors support\n");
#endif	/* HAVE_HAS_COLORS */

	fprintf(stderr, "\n%s\n", copyright);
	fprintf(stderr,"For bug report please email to trafshow@risp.ru (include this page)\n\n");

	exit(1);
}

static void
usage()
{
	fprintf(stderr,
"Usage:\n\
 %s [-vpnb] [-a len] [-c conf] [-i ifname] [-s str] [-u port] [-R refresh] [-P purge] [-F file | expr]\n\
Where:\n\
 -v         Print version number, compile-time definitions, and exit\n\
 -p         Don't put the interface(s) into promiscuous mode\n\
 -n         Don't convert numeric values to names\n\
 -b         To place a backflow near to the main stream\n\
 -a len     To aggregate IP addresses using the prefix length\n\
 -c conf    Color config file instead of default /etc/trafshow\n\
 -i ifname  Network interface name; all by default\n\
 -s str     To search & follow for string in the list show\n\
 -u port    UDP port number to listen for Cisco Netflow; default %d\n\
 -R refresh Set the refresh-period of data show to seconds; default %d sec\n\
 -P purge   Set the expired data purge-period to seconds; default %d sec\n\
 -F file    Use file as input for the filter expression\n\
 expr       Filter expression; see tcpdump(1) for syntax\n\
		\n", progname, CNF_PORT, REFRESH_TIME, PURGE_TIME);

	exit(1);
}
