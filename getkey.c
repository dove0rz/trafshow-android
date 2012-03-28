/*
 *	Copyright (c) 1998,2004 Rinet Corp., Novosibirsk, Russia
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "getkey.h"
#include "screen.h"
#include "session.h"
#include "trafshow.h"
#include "selector.h"
#include "show_if.h"
#include "show_stat.h"
#include "show_dump.h"
#include "events.h"
#include "netstat.h"
#include "help_page.h"


static void read_key(SESSION *sd, const unsigned char *data, int len);
static int scan_key(const unsigned char *buf, int len);
static void parse_key(int key, PCAP_HANDLER *ph);
static void init_edit_string(const char *prompter, const char *charset, int size);
static int edit_string(int ch);

/* edit string stuff */
static const char *numbers = "1234567890";
static const char *spaces = " ,.;@/\\";
static char prompt_buf[MAX_PARAM_LEN], cut_buf[MAX_PARAM_LEN];
static const char *char_set;
static int buf_size, cur, nb, win, scr, bartop, barlen, touch, show_win;


void
getkey_init(ph)
	PCAP_HANDLER *ph;
{
	SESSION *sd;

	if ((sd = session_open(0, 0, PlainFile)) == 0) {
		perror("session_open 0"); /* should not happen */
		exit(1);
	}
	session_setcallback(sd, 0, 0, read_key);
	session_setcookie(sd, ph);
	prompt_mode = 0;
}

static void
read_key(sd, data, len)
	SESSION *sd;
	const unsigned char *data;
	int len;
{
	/* sanity check */
	if (sd && data && len > 0) {
		int key = scan_key(data, len);
		if (key != -1)
			parse_key(key, (PCAP_HANDLER *)session_cookie(sd));
	}
}

static SELECTOR *
get_selector(ph_list)
	PCAP_HANDLER *ph_list;
{
	/* return current selector */
	switch (show_mode) {
	case Interfaces:
		return show_if_selector();
	case NetStat:
		return show_stat_selector(pcap_get_selected(ph_list));
	case FlowDump:
		/* nope */
		break;
	case HelpPage:
		return help_page_selector();
	}
	return 0;
}

static void
parse_key(key, ph_list)
	int key;
	PCAP_HANDLER *ph_list;
{
	int ch = key;
	PCAP_HANDLER *ph = 0;
	SELECTOR *sp = 0;
	struct timeval now;

	if (prompt_mode) {
		const char *txt = 0;
		int redraw = 1;
		if ((ch = edit_string(ch)) == 0) /* still edit */
			return;
		if (ch > 0) {
			switch (prompt_mode) {
			case 'r':	/* end of getting refresh time */
			case 'R':
				ch = atoi(prompt_buf);
				if (ch > 0 && ch != refresh_time) {
					if (ch < purge_time)
						refresh_time = ch;
					else	txt = "Refresh Time must be less than Purge Time";
				}
				break;
			case 'p':	/* end of getting purge time */
			case 'P':
				ch = atoi(prompt_buf);
				if (ch > 0 && ch != purge_time) {
					if (ch > refresh_time) {
						purge_time = ch;
						add_event(0, pcap_purge, ph_list);
						redraw = 0;
					} else	txt = "Purge Time must be bigger than Refresh Time";
				}
				break;
			case 'f':	/* end of getting filter expression */
			case 'F':
				if (!expression || strcmp(prompt_buf, expression)) {
					if (expression) free(expression);
					expression = strdup(prompt_buf);
					if ((txt = pcap_setexpr(ph_list, expression)) == 0) {
						if (prompt_mode == 'F') {
							add_event(0, pcap_clear, ph_list);
							redraw = 0;
						}
					}
				}
				break;
			case '/':	/* end of getting search string */
				if (prompt_buf[0] == '\0') {
					if (search) {
						free(search);
						search = 0;
						txt = "Search mode turned Off";
					}
				} else if (!search || strcmp(prompt_buf, search)) {
					if (search) free(search);
					search = strdup(prompt_buf);
				}
				break;
			case 'a':	/* end of getting aggregation masklen */
			case 'A':
				if (prompt_buf[0]) {
					ch = atoi(prompt_buf);
					if (ch < 0 || ch > ADDRBITLEN) {
						txt = "Wrong netmask length";
						break;
					}
				} else	ch = -1;
				if (show_mode == NetStat &&
				    (ph = pcap_get_selected(ph_list)) != 0) {
					if (ph->masklen != ch) {
						ph->masklen = ch;
						if (prompt_mode == 'A')
							netstat_purge(ph, 0);
					}
				} else {
					aggregate = ch;
					for (ph = ph_list; ph; ph = ph->next) {
						if (ph->masklen != aggregate) {
							ph->masklen = aggregate;
							if (prompt_mode == 'A')
								netstat_purge(ph, 0);
						}
					}
				}
				break;
			}
		}
		prompt_mode = 0;
		if (redraw)
			add_event(0, pcap_show, ph_list);
		if (txt)
			screen_status(txt);
		else	screen_update();
		return;
	}

	/* try global operation keys */
	switch (ch) {
	case K_ESC:	/* get back show mode */
	case 'q':
	case 'Q':
		switch (show_mode) {
		case Interfaces:
			exit(0);
		case NetStat:
			if ((ph = pcap_get_selected(ph_list)) != 0 && ph->top)
				pcaph_close(ph);
			else	show_mode = Interfaces;	
			pcap_show(ph_list);
			return;
		case FlowDump:
			show_dump_close();
			show_mode = NetStat;
			pcap_show(ph_list);
			return;
		case HelpPage:
			show_mode = help_page_mode();
			pcap_show(ph_list);
			return;
		}
		break;
	case K_CTRL('L'):	/* refresh screen */
		clear();
		refresh();
		pcap_show(ph_list);
		return;
	case 'h':	/* help page if any */
	case 'H':
	case '?':
	case K_F1:
		if (help_page_list(show_mode)) {
			show_mode = HelpPage;
			pcap_show(ph_list);
			return;
		}
		break;
	case 'r':	/* start to get refresh time */
	case 'R':
		if (show_mode != FlowDump) {
			prompt_mode = ch;
			snprintf(prompt_buf, sizeof(prompt_buf), "%d", refresh_time);
			init_edit_string("Refresh seconds: ", numbers, 5);
			selector_withdraw(get_selector(ph_list));
			screen_update();
			return;
		}
		break;
	case 'p':	/* start to get purge time */
	case 'P':
		if (show_mode != FlowDump) {
			prompt_mode = ch;
			snprintf(prompt_buf, sizeof(prompt_buf), "%d", purge_time);
			init_edit_string("Purge seconds: ", numbers, 5);
			selector_withdraw(get_selector(ph_list));
			screen_update();
			return;
		}
		break;
	case 'f':	/* start to get filter expression */
	case 'F':
		if (show_mode != FlowDump) {
			prompt_mode = ch;
			prompt_buf[0] = '\0';
			if (expression) {
				(void)strncpy(prompt_buf, expression, sizeof(prompt_buf));
				prompt_buf[sizeof(prompt_buf)-1] = '\0';
			}
			init_edit_string("Filter expression: ", 0, sizeof(prompt_buf));
			selector_withdraw(get_selector(ph_list));
			screen_update();
			return;
		}
		break;
	case '/':	/* start to get search string */
		if (show_mode != FlowDump) {
			prompt_mode = ch;
			prompt_buf[0] = '\0';
			if (search) {
				(void)strncpy(prompt_buf, search, sizeof(prompt_buf));
				prompt_buf[sizeof(prompt_buf)-1] = '\0';
			}
			init_edit_string("Search string: ", 0, sizeof(prompt_buf));
			selector_withdraw(get_selector(ph_list));
			screen_update();
			return;
		}
		break;
	case K_CTRL('_'):	/* turn off search mode */
		if (show_mode != FlowDump) {
			if (search) {
				free(search);
				search = 0;
				screen_status("Search mode turned Off");
			}
			return;
		}
		break;
	case 'a':	/* start to get aggregation masklen */
	case 'A':
		if (show_mode != FlowDump) {
			char buf[100];
			prompt_mode = ch;
			prompt_buf[0] = '\0';
			if (show_mode == NetStat &&
			    (ph = pcap_get_selected(ph_list)) != 0) {
				if (ph->masklen >= 0)
					snprintf(prompt_buf, sizeof(prompt_buf), "%d", ph->masklen);
				snprintf(buf, sizeof(buf), "%s aggregation netmask length: ", ph->name);
			} else {
				if (aggregate >= 0)
					snprintf(prompt_buf, sizeof(prompt_buf), "%d", aggregate);
				(void)strcpy(buf, "Aggregation netmask length: ");
			}
			init_edit_string(buf, numbers, 5);
			selector_withdraw(get_selector(ph_list));
			screen_update();
			return;
		}
		break;
	case K_CTRL('R'): /* reset all netstat hash */
		if (show_mode == Interfaces) {
			add_event(0, pcap_clear, ph_list);
			screen_status("Resetting all flows");
			return;
		}
		break;
	case 'n':	/* toggle numeric values to names conversion */
	case 'N':
		if (show_mode != FlowDump) {
			nflag ^= 1;
			if (ch == 'N') {
				add_event(0, pcap_show, ph_list);
			} else {
				screen_status("Numeric values turned %s",
					      nflag ? "On" : "Off");
			}
			return;
		}
		break;
	}

	/* prevent screen refresh overhead */
	gettimeofday(&now, 0);
	now.tv_sec += refresh_time;
	add_event(&now, pcap_show, ph_list);

	/* get current selector */
	switch (show_mode) {
	case Interfaces:
		sp = show_if_selector();
		break;
	case NetStat:
		if ((ph = pcap_get_selected(ph_list)) == 0)
			return;
		sp = show_stat_selector(ph);

		/* try special input for the show mode */
		if (show_stat_input(ph, ch)) {
			selector_redraw(sp);
			return;
		}
		break;
	case FlowDump:
		/* special input only for the show mode */
		show_dump_input(ch);
		return;
	case HelpPage:
		sp = help_page_selector();
		break;
	}

	/* try special input for the selecting */
	ch = selector_move(ch, sp);
	if (ch < 0) {
		selector_redraw(sp);
		return;
	}

	/* something selected */
	switch (show_mode) {
	case Interfaces:
		if ((ph = pcap_set_selected(ph_list, ch)) == 0)
			return; /* should not happen */
		/*selector_withdraw(sp);*/
		show_mode = NetStat;
		pcap_show(ph_list);
		return;
	case NetStat:
		/*selector_withdraw(sp);*/
		if (ph->masklen == -1) {
			if (show_dump_open(ph, show_stat_get(ph, ch)) == 0)
				show_mode = FlowDump;
		} else if (pcaph_create(ph, (struct netstat_header *)show_stat_get(ph, ch))) {
			pcap_show(ph_list);
		}
		return;
	case FlowDump:
		/* not reached; just to avoid compiler warning */
		return;
	case HelpPage:
		key = help_page_key(ch);
		if (key != -1 && key != 0) {
			show_mode = help_page_mode(); /* get back show mode */
			pcap_show(ph_list);
			parse_key(key, ph_list);
		}
		return;
	}
}

static int
scan_key(buf, len)
	const unsigned char *buf;
	int len;
{
	int i;

	if (buf[0] != ESCAPE) return buf[0];
	if (len == 1) return K_ESC;
	i = 1;
	if (buf[i] == '[' || buf[i] == 'O')
		if (++i >= len) return -1;

	switch (buf[i]) {
	case '\0':	/* xterm */
		return K_HOME;
	case 'A':
	case 'i':
		return K_UP;
	case 'B':
		return K_DOWN;
	case 'D':
		return K_LEFT;
	case 'C':
		return K_RIGHT;
	case 'I':	/* ansi  PgUp */
	case 'V':	/* at386 PgUp */
	case 'S':	/* 97801 PgUp */
	case 'v':	/* emacs style */
		return K_PAGEUP;
	case 'G':	/* ansi  PgDn */
	case 'U':	/* at386 PgDn */
	case 'T':	/* 97801 PgDn */
		return K_PAGEDOWN;
	case 'H':	/* at386  Home */
		return K_HOME;
	case 'F':	/* ansi   End */
	case 'Y':	/* at386  End */
		return K_END;
	case '5':	/* vt200 PgUp */
		return K_PAGEUP;
	case '6':	/* vt200 PgUp */
		return K_PAGEDOWN;
	case '1':	/* vt200 PgUp */
		if (++i >= len) return -1;
		switch(buf[i]) {	/* xterm */
		case '1':
			return K_F1;
		case '2':
			return K_F2;
		case '3':
			return K_F3;
		case '4':
			return K_F4;
		case '5':	/* RS/6000 PgUp is 150g, PgDn is 154g */
			if (++i >= len) return -1;
			if (buf[i] == '0')
				return K_PAGEUP;
			if (buf[i] == '4') 
				return K_PAGEDOWN;
		}
		return K_HOME;
	case '4':	/* vt200 PgUp */
		return K_END;
	case '2':	/* xterm */
	case 'L':
		return K_INS;
	case 'M':
		return K_F1;
	case 'N':
		return K_F2;
	case 'O':
		return K_F3;
	case 'P':
		return K_F4;
	}
	return -1;
}

static void
init_edit_string(prompter, charset, size)
	const char *prompter, *charset;
	int size;
{
	int i;

	char_set = charset;
	touch = 0;
	show_win = 0;

	*cut_buf = '\0';
	bartop = strlen(prompter);
	i = COLS - (bartop + 3);
	barlen = buf_size = size;
	if (barlen < 1 || barlen > i) {
		barlen = i;
		show_win = 1;
	}

	attrset(A_NORMAL);
	move(LINES-1, 0);
	clrtoeol();
	addstr(prompter);

	nb = strlen(prompt_buf);
	if (nb >= buf_size) nb = buf_size - 1;
	prompt_buf[nb] = '\0';
	cur = nb;

	win = cur / barlen;	/* window number */
	scr = cur % barlen;	/* screen position */

	if (show_win) mvprintw(LINES-1, COLS-2, "%-2d", win+1);

	attrset(A_STANDOUT);
	mvprintw(LINES-1, bartop, "%-*.*s", barlen, barlen, &prompt_buf[win * barlen]);

	screen_dock_cursor(LINES-1, bartop + scr);
}

static int
edit_string(ch)
	int ch;
{
	int i;

	switch (ch) {
	case K_ESC:
	case K_CR:
	case K_NL:
		prompt_buf[nb] = '\0';
		attrset(A_NORMAL);
		move(LINES-1, 0);
		clrtoeol();
		screen_dock_cursor(0, 0);
		return (ch == K_ESC ? -1 : 1);

	case K_PAGEUP:	/* move to begin of window */
		cur -= cur % barlen;
		break;
	case K_PAGEDOWN:/* move to end of window */
		if (strlen(&prompt_buf[cur]) < barlen)
			cur = nb;
		else	cur += barlen - cur % barlen - 1;
		break;
	case K_UP:	/* skip to previous word */
	case K_CTRL('P'):
		ch = 0;
		for (i = cur; i > 0; i--) {
			if (!ch) {
				if (strchr(spaces, prompt_buf[i-1]))
					ch++;
			} else if (!strchr(spaces, prompt_buf[i-1]))
				break;
		}
		cur = i;
		break;
	case K_DOWN:	/* skip to next word */
	case K_CTRL('N'):
		ch = 0;
		for (i = cur; i < nb; i++) {
			if (!ch) {
				if (strchr(spaces, prompt_buf[i]))
					ch++;
			} else if (!strchr(spaces, prompt_buf[i]))
				break;
		}
		cur = i;
		break;
	case K_HOME:	/* move to begin of line */
	case K_CTRL('A'):
		cur = 0;
		break;
	case K_END:	/* move to end of line */
	case K_CTRL('E'):
		cur = nb;
		break;
	case K_LEFT:	/* move cursor left */
	case K_CTRL('B'):
		if (cur > 0) cur--;
		break;
	case K_RIGHT:	/* move cursor right */
	case K_CTRL('F'):
		if (cur < nb) cur++;
		break;
	case K_BS:	/* backspace */
		if (nb && cur) {
			memmove(&prompt_buf[cur-1], &prompt_buf[cur], nb - cur);
			cur--;
			nb--;
		}
		break;
	case K_DEL:	/* delete */
	case K_CTRL('D'):
		if (nb && cur < nb) {
			memmove(&prompt_buf[cur], &prompt_buf[cur+1], nb - cur);
			nb--;
		}
		break;
	case K_CTRL('U'):	/* erase entire line */
		(void)strcpy(cut_buf, prompt_buf);
		nb = 0;
		cur = 0;
		break;
	case K_CTRL('W'):	/* erase last word */
		ch = 0;
		for (i = cur; i > 0; i--) {
			if (!ch) {
				if (strchr(spaces, prompt_buf[i-1]))
					ch++;
			} else if (!strchr(spaces, prompt_buf[i-1]))
				break;
		}
		if (cur > i) {
			memcpy(cut_buf, &prompt_buf[i], cur - i);
			cut_buf[cur - i] = '\0';
			memmove(&prompt_buf[i], &prompt_buf[cur], cur - i);
			nb -= cur - i;
			cur = i;
		}
		break;
	case K_CTRL('K'):	/* erase end of line */
		if (prompt_buf[cur] != '\0')
			(void)strcpy(cut_buf, &prompt_buf[cur]);
		nb = cur;
		break;
	case K_TAB:	/* insert cut_buf */
		i = strlen(cut_buf);
		if (i && (buf_size - 1) - strlen(prompt_buf) >= i) {
			memmove(&prompt_buf[cur+i], &prompt_buf[cur], nb - cur);
			memmove(&prompt_buf[cur], cut_buf, i);
			nb += i;
			cur += i;
		}
		break;
	default:
		if (ch < 32 || ch > 126)
			return 0; /* skip garbage chars */

		if (char_set && !strchr(char_set, ch)) {
			beep();
			return 0;
		}
		if (!touch) {
			nb = 0;
			cur = 0;
		}
		if (nb >= buf_size - 1) { /* no more space available */
			beep();
			return 0;
		}
		if (nb > cur)
			memmove(&prompt_buf[cur+1], &prompt_buf[cur], nb - cur);
		prompt_buf[cur++] = ch;
		nb++;
	}
	touch = 1;

	prompt_buf[nb] = '\0';

	win = cur / barlen;	/* window number */
	scr = cur % barlen;	/* screen position */

	attrset(A_STANDOUT);
	mvprintw(LINES-1, bartop, "%-*.*s", barlen, barlen, &prompt_buf[win * barlen]);
	if (show_win) {
		attrset(A_NORMAL);
		mvprintw(LINES-1, COLS-2, "%-2d", win+1);
	}

	screen_dock_cursor(LINES-1, bartop + scr);
	screen_update();
	return 0;
}

