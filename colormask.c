/*
 *	Copyright (c) 1993-1997,2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 * Redistribution in binary form may occur without any restrictions.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifdef	HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef	HAVE_HAS_COLORS

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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>

#include "colormask.h"
#include "trafshow.h"
#include "netstat.h"
#ifdef	DEBUG
#include "show_stat.h" /* just for hdr2str() */
#endif

/* mask entry */
struct cm_entry {
	struct internet_header in_hdr;
	int src_mask;		/* source ip address mask */
	int dst_mask;		/* destination ip address mask */

	short   pair;		/* color-pair */
	int     attr;		/* video attributes; bold, blink, etc */
};

static struct cm_entry *color_mask = NULL;
static int n_masks = 0;
static int n_pairs = 0;
static const char *rc_file = 0;
static int rc_line;

/* SLcurses can't handle attributes as well; so hack it */
#ifdef	HAVE_SLCURSES
static void
slang_init_pair(short pair, short fc, short bc, int at)
{
	SLtt_set_color_object(pair, ((fc | (bc << 8)) << 8) | at);
}

static int
slang_pair_content(short pair, short *fc, short *bc)
{
	int attr;
	SLtt_Char_Type at;

	at = SLtt_get_color_object(pair);
	attr = at & (A_BOLD | A_BLINK);
	at &= ~(A_BOLD | A_BLINK);
	at >>= 8;
	*fc = at & 0xff;
	*bc = (at >> 8) & 0xff;

	return attr;
}
#endif	/* HAVE_SLCURSES */

static short
findpair(short f, short b, int a)
{
	int i;
	short f1 = -1, b1 = -1;
	struct cm_entry *cm;

	for (cm = color_mask, i = 0; cm != NULL && i < n_masks-1; cm++, i++) {
#ifdef	HAVE_SLCURSES
		int a1 = slang_pair_content(cm->pair, &f1, &b1);
		if (f1 >= COLORS) f1 = -1;
		if (b1 >= COLORS) b1 = -1;
		if (f == f1 && b == b1 && a == a1) return cm->pair;
#else
		pair_content(cm->pair, &f1, &b1);
		if (f1 >= COLORS) f1 = -1;
		if (b1 >= COLORS) b1 = -1;
		if (f == f1 && b == b1) return cm->pair;
#endif
	}
	return 0;
}

static int
add_colormask(const char *s, struct cm_entry *m)
{
	int i, attr = 0;
	short fc, bc;
	char f[100], *b;
	static char *ctab[8] = { "black", "red", "green", "yellow",
				"blue",	"magenta", "cyan", "white" };
#ifdef	HAVE_USE_DEFAULT_COLORS
	static short fc_def = -1, bc_def = -1;
#else
	static short fc_def = COLOR_WHITE, bc_def = COLOR_BLACK;
#endif

	if ((b = strchr(strcpy(f, s), ':')) != NULL) *b++ = '\0';

	if (*f) {
		for (i = 0; i < 8; i++)
			if (!strcasecmp(ctab[i], f)) break;
		if (i < 8) fc = i;
		else {
			fc = atoi(f);
			if (fc < 1 || fc > COLORS) {
				fprintf(stderr, "%s: line %d: Unknown color `%s'\n",
					rc_file, rc_line, f);
				return -1;
			}
		}
		if (isupper((int)*f)) attr |= A_BOLD;
	} else fc = fc_def;

	if (b && *b) {
		for (i = 0; i < 8; i++)
			if (!strcasecmp(ctab[i], b)) break;
		if (i < 8) bc = i;
		else {
			bc = atoi(b);
			if (bc < 1 || bc > COLORS) {
				fprintf(stderr, "%s: line %d: Unknown color `%s'\n",
					rc_file, rc_line, b);
				return -1;
			}
		}
		if (isupper((int)*b)) attr |= A_BLINK;
	} else bc = bc_def;

	if (m != NULL) {
		if ((color_mask = realloc(color_mask, ++n_masks * sizeof(struct cm_entry))) == NULL) {
			fprintf(stderr, "add_colormask: realloc: Out of memory?\n");
			return -1;
		}
		if ((m->pair = findpair(fc, bc, attr)) == 0) {
			if (++n_pairs < COLOR_PAIRS-1) {
#ifdef	HAVE_SLCURSES
				slang_init_pair(n_pairs, fc, bc, attr);
#else
				init_pair(n_pairs, fc, bc);
#endif
			} else {
				fprintf(stderr, "%s: line %d: Max %d color-pairs can be used\n",
					rc_file, rc_line, COLOR_PAIRS-1);
				return -1;
			}
			m->pair = n_pairs;
		}
		m->attr = attr;
		memcpy(color_mask + (n_masks-1), m, sizeof(struct cm_entry));
	} else {	/* default colors */
#ifdef	HAVE_SLCURSES
		slang_init_pair(0, fc, bc, attr);
#else
#ifdef	HAVE_BKGD
		init_pair(COLOR_PAIRS-1, fc, bc);
		bkgd(COLOR_PAIR(COLOR_PAIRS-1) | attr);
#elif	HAVE_WBKGD
		init_pair(COLOR_PAIRS-1, fc, bc);
		wbkgd(stdscr, COLOR_PAIR(COLOR_PAIRS-1) | attr);
#else /* assume the color-pair 0 is background for whole screen */
		init_pair(0, fc, bc);
#endif
#endif
		fc_def = fc;
		bc_def = bc;
	}
	return 0;
}

static int
is_any(const char *s)
{
	if (!s || !*s) return 0;
	return (!strcmp(s, "*") || !strcasecmp(s, "any") || !strcasecmp(s, "all"));
}

static int
is_number(const char *s)
{
	if (!s || !*s) return 0;
	for (; *s; s++) {
		if (!isdigit((int)*s)) return 0;
	}
	return 1;
}

static char *
str2proto(const char *str, int *proto)
{
	int num;
	struct protoent *pe;

	if (is_any(str)) {
		*proto = 0;
		return "";
	}
	if (is_number(str)) {
		num = atoi(str);
		if (num > 0 && num <= 0xff) {
			if ((pe = getprotobynumber(num)) != 0) {
				*proto = pe->p_proto;
				return pe->p_name;
			}
			*proto = num;
			return "";
		}
	}
	if ((pe = getprotobyname(str)) != 0) {
		*proto = pe->p_proto;
		return pe->p_name;
	}
	fprintf(stderr, "%s: line %d: Unknown protocol `%s'\n",
		rc_file, rc_line, str);
	return 0;
}

static int
str2port(const char *str, const char *proto)
{
	int num;
	struct servent *se;

	if (is_any(str))
		return 0;

	num = atoi(str);
	if (num > 0 && num <= 0xffff)
		return htons((u_int16_t)num);

	if ((se = getservbyname(str, (proto && *proto) ? proto : 0)) != 0)
		return se->s_port;

	if (proto && *proto) {
		fprintf(stderr, "%s: line %d: Unknown port `%s' at protocol `%s'\n",
			rc_file, rc_line, str, proto);
	} else {
		fprintf(stderr, "%s: line %d: Unknown port `%s'\n",
			rc_file, rc_line, str);
	}
	return -1;
}

static int
str2addr(const char *str, const char *proto, struct ip_address *addr, int *mask)
{
	int op, ver = 0;
	char buf[256], *cp, *mp, *pp;

	if (proto && !strcasecmp(proto, "IPv6")) {
#ifdef INET6
		ver = 6;
#else
		fprintf(stderr, "%s: line %d: IPv6 is unsupported at this system\n",
			rc_file, rc_line);
		return -1;
#endif
	}
	cp = strcpy(buf, str);
	if ((mp = strchr(cp, '/')) != 0) {
		*mp++ = '\0';
		cp = mp;
	}
	if ((pp = strchr(cp, ',')) != 0) {
		*pp++ = '\0';
	}
	if (mp && !is_number(mp)) {
		fprintf(stderr, "%s: line %d: %s: Mask must be number of bits\n",
			rc_file, rc_line, mp);
		return -1;
	}
	if (!is_any(buf)) {
		op = 0;
#ifdef INET6
		if (ver == 6 || strchr(buf, ':')) {
			ver = 6;
			op = inet_pton(AF_INET6, buf, &addr->ip6_addr);
			if (op < 0) {
				fprintf(stderr, "%s: line %d: %s: %s\n",
					rc_file, rc_line, buf, strerror(errno));
				return -1;
			}
		}
#endif
		if (!op) {
			ver = 4;
			op = inet_pton(AF_INET, buf, &addr->ip_addr);
			if (op < 0) {
				fprintf(stderr, "%s: line %d: %s: %s\n",
					rc_file, rc_line, buf, strerror(errno));
				return -1;
			}
		}
		if (!op) {
			struct hostent *he;
			if ((he = gethostbyname(buf)) == 0) {
				fprintf(stderr, "%s: line %d: %s: Unknown host\n",
					rc_file, rc_line, buf);
				return -1;
			}
			if (he->h_addrtype == AF_INET) {
				ver = 4;
				memcpy(&addr->ip_addr, he->h_addr,
				       MIN(sizeof(addr->ip_addr), he->h_length));
			}
#ifdef INET6
			else if (he->h_addrtype == AF_INET6) {
				ver = 6;
				memcpy(&addr->ip6_addr, he->h_addr,
				       MIN(sizeof(addr->ip6_addr), he->h_length));
			}
#endif
			else {
				fprintf(stderr, "%s: line %d: %s: Unknown address family\n",
					rc_file, rc_line, buf);
				return -1;
			}
		}
	}
	if (pp) {
		if ((op = str2port(pp, proto)) == -1)
			return -1;
		addr->ip_port = op;
	}
	if (mask) {
		if (mp) {
			op = atoi(mp);
			if (op < 8 || op > 128) {
				fprintf(stderr, "%s: line %d: %d: Wrong mask\n",
					rc_file, rc_line, op);
				return -1;
			}
			*mask = op;
		} else	*mask = 0;
	}
	return ver;
}

int
init_colormask()
{
	FILE *fp;
	int num;
	struct cm_entry me, *cm;
	char *cp, buf[1024];
	char s1[256], s2[256], s3[256], s4[256];

	if (rc_file) {
		free((char *)rc_file);
		rc_file = 0;
	}
	if (!color_conf) {
		if ((cp = getenv("HOME")) != 0) {
			(void)strcpy(buf, cp);
			(void)strcat(buf, "/");
		} else	buf[0] = '\0';
		(void)strcat(buf, ".");
		(void)strcat(buf, progname);
		if ((fp = fopen(buf, "r")) == NULL) {
			(void)strcpy(buf, "/etc/");
			(void)strcat(buf, progname);
			if ((fp = fopen(buf, "r")) == NULL) return 0;
		}
		rc_file = strdup(buf);
	} else {
		if ((fp = fopen(color_conf, "r")) == NULL) {
			fprintf(stderr, "%s: %s\n", color_conf, strerror(errno));
			return -1;
		}
		rc_file = strdup(color_conf);
	}
	if (!rc_file) {
		fprintf(stderr, "init_colormask: strdup: Out of memory?\n");
		(void)fclose(fp);
		return -1;
	}
	rc_line = 0;
	cm = &me;

#ifdef	HAVE_USE_DEFAULT_COLORS
	use_default_colors();
#endif
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		rc_line++;
		if (buf[0] == '\n' || buf[0] == '#') continue;
		if ((cp = strchr(buf, '#')) != NULL) {
			*cp++ = '\n';
			*cp = '\0';
		}
		memset(cm, 0, sizeof(struct cm_entry));
		num = sscanf(buf, "%s %s %s %s\n", s1, s2, s3, s4);
		if (num == 2) {
			if (strcasecmp(s1, "default")) {
				if ((cp = strchr(s1, '/')) != 0) {
					*cp++ = '\0';
					if ((cp = str2proto(cp, &num)) == 0) {
						(void)fclose(fp);
						return -1;
					}
					cm->in_hdr.proto = num;
				}
				if ((num = str2port(s1, cp)) == -1) {
					(void)fclose(fp);
					return -1;
				}
				cm->in_hdr.src.ip_port = num;
				cm->in_hdr.dst.ip_port = 0;
				if (add_colormask(s2, cm) < 0) {
					(void)fclose(fp);
					return -1;
				}
				cm->in_hdr.src.ip_port = 0;
				cm->in_hdr.dst.ip_port = num;
				if (add_colormask(s2, cm) < 0) {
					(void)fclose(fp);
					return -1;
				}
			} else if (add_colormask(s2, 0) < 0) {
				(void)fclose(fp);
				return -1;
			}
		} else if (num == 3) {
			num = str2addr(s1, 0, &cm->in_hdr.src, &cm->src_mask);
			if (num == -1) {
				(void)fclose(fp);
				return -1;
			}
			cm->in_hdr.ver = num;
			num = str2addr(s2, 0, &cm->in_hdr.dst, &cm->dst_mask);
			if (num == -1) {
				(void)fclose(fp);
				return -1;
			}
			if (!cm->in_hdr.ver) {
				cm->in_hdr.ver = num;
			} else if (num && num != cm->in_hdr.ver) {
				fprintf(stderr, "%s: line %d: Addresses family mismatch\n",
					rc_file, rc_line);
				(void)fclose(fp);
				return -1;
			}
			if (add_colormask(s3, cm) < 0) {
				(void)fclose(fp);
				return -1;
			}
		} else if (num == 4) {
			if ((cp = str2proto(s1, &num)) == 0) {
				(void)fclose(fp);
				return -1;
			}
			cm->in_hdr.proto = num;
			num = str2addr(s2, cp, &cm->in_hdr.src, &cm->src_mask);
			if (num == -1) {
				(void)fclose(fp);
				return -1;
			}
			cm->in_hdr.ver = num;
			num = str2addr(s3, cp, &cm->in_hdr.dst, &cm->dst_mask);
			if (num == -1) {
				(void)fclose(fp);
				return -1;
			}
			if (!cm->in_hdr.ver) {
				cm->in_hdr.ver = num;
			} else if (num && num != cm->in_hdr.ver) {
				fprintf(stderr, "%s: line %d: Addresses family mismatch\n",
					rc_file, rc_line);
				(void)fclose(fp);
				return -1;
			}
			if (add_colormask(s4, cm) < 0) {
				(void)fclose(fp);
				return -1;
			}
		} else {
			fprintf(stderr, "%s: line %d: Bad format\n",
				rc_file, rc_line);
			(void)fclose(fp);
			return -1;
		}
	}
	(void)fclose(fp);
#ifdef	DEBUG
	for (cm = color_mask, num = 0; cm && num < n_masks; cm++, num++) {
		struct netstat_header nh;
		memset(&nh, 0, sizeof(nh));
		nh.in_hdr = cm->in_hdr;
		hdr2str(&nh, s1, sizeof(s1), s2, sizeof(s2), s3, sizeof(s3));
		fprintf(stderr, "%d:", num+1);
		fprintf(stderr, " proto=%s", s3);
		fprintf(stderr, " src=%s", s1);
		fprintf(stderr, " src_mask=%d", cm->src_mask);
		fprintf(stderr, " dst=%s", s2);
		fprintf(stderr, " dst_mask=%d", cm->dst_mask);
		fprintf(stderr, " color_pair=%d\r\n", (int)cm->pair);
	}
	fflush(stderr);
	pause();
#endif
	return n_masks;
}

static u_int32_t
netmask(int bits)
{
	register u_int32_t mask = 0;
	int i;
	for (i = 0; i < bits; i++) {
		mask >>= 1;
		mask |= 0x80000000L;
	}
	return (u_int32_t)htonl(mask);
}

int
colormask(nh)
	const struct netstat_header *nh;
{
	/* sanity check */
	if (!nh) return A_NORMAL;

	if (nh->in_hdr.ver) {
		register const struct cm_entry *cm;
		int i;
		for (cm = color_mask, i = 0; cm && i < n_masks; cm++, i++) {
			/* IP version */
			if (cm->in_hdr.ver) {
				if (nh->in_hdr.ver != cm->in_hdr.ver)
					continue;
			}
			/* IP protocol */
			if (cm->in_hdr.proto) {
				if (nh->in_hdr.proto != cm->in_hdr.proto)
					continue;
			}
			/* IP source address */
			if (cm->in_hdr.src.ip_addr.s_addr) {
				if (cm->src_mask) {
					u_int32_t mask = netmask(cm->src_mask);
					if ((nh->in_hdr.src.ip_addr.s_addr & mask) ^
					    (cm->in_hdr.src.ip_addr.s_addr & mask))
						continue;
				} else if (nh->in_hdr.src.ip_addr.s_addr !=
					   cm->in_hdr.src.ip_addr.s_addr)
					continue;
			}
			/* IP source port */
			if (cm->in_hdr.src.ip_port) {
				if (nh->in_hdr.src.ip_port != cm->in_hdr.src.ip_port)
					continue;
			}
			/* IP destination address */
			if (cm->in_hdr.dst.ip_addr.s_addr) {
				if (cm->dst_mask) {
					u_int32_t mask = netmask(cm->dst_mask);
					if ((nh->in_hdr.dst.ip_addr.s_addr & mask) ^
					    (cm->in_hdr.dst.ip_addr.s_addr & mask))
						continue;
				} else if (nh->in_hdr.dst.ip_addr.s_addr !=
					   cm->in_hdr.dst.ip_addr.s_addr)
					continue;
			}
			/* IP destination port */
			if (cm->in_hdr.dst.ip_port) {
				if (nh->in_hdr.dst.ip_port != cm->in_hdr.dst.ip_port)
					continue;
			}
#ifdef	HAVE_SLCURSES
			return (COLOR_PAIR(cm->pair));
#else
			return (COLOR_PAIR(cm->pair) | cm->attr);
#endif
		}
	}

	return A_NORMAL;
}

#endif	/* HAVE_HAS_COLORS */
