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
#include <stdio.h>
#include <string.h>

#include "trafshow.h"
#include "help_page.h"
#include "getkey.h"
#include "screen.h"
#include "selector.h"

static ShowMode help_mode = HelpPage;

struct help_page_entry {
	int key;
	const char *name;
	const char *descr;
};

static struct help_page_entry Interfaces_help[] = {
 { 'q',		"   Esc",	"Quit the program"	},
 { K_CR,	"  Enter",	"Use Arrow-Keys to select Interface to show" },
 { K_CTRL('L'),	"  Ctrl-L",	"Refresh screen from scratch" },
 { 'r',		"    R",	"Set the screen refresh-period.." },
 { 'p',		"    P",	"Set the expired data purge-period.." },
 { 'f',		"    F",	"Set the filter expression (empty to reset).." },
 { '/',		"    /",	"To search & follow for string in the list.." },
 { K_CTRL('_'),	"  Ctrl-/",	"Turn off search & follow mode" },
 { 'a',		"    A",	"To aggregate/summarize flows totally.." },
 { K_CTRL('R'),	"  Ctrl-R",	"Reset all flow cache totally" },
 { 'n',		"    N",	"Toggle numeric values to names conversion" },

 { 0,0,0 }
};

static struct help_page_entry NetStat_help[] = {
 { 'q',		"   Esc",	"Return to previous page" },
 { K_CR,	"  Enter",	"Use Arrow-Keys to select Flow for detail" },
 { K_LEFT,	"   Left",	"Rotate show mode left" },
 { K_RIGHT,	"  Right",	"Rotate show mode right" },
 { K_TAB,	"   Tab",	"Move cursor to backflow if any" },
 { K_CTRL('L'),	"  Ctrl-L",	"Refresh screen from scratch" },
 { 'r',		"    R",	"Set the screen refresh-period.." },
 { 'p',		"    P",	"Set the expired data purge-period.." },
 { 'f',		"    F",	"Set the filter expression (empty to reset).." },
 { '/',		"    /",	"To search & follow for string in the list.." },
 { K_CTRL('_'),	"  Ctrl-/",	"Turn off search & follow mode" },
 { 'a',		"    A",	"To aggregate/summarize flows in the list.." },
 { K_CTRL('R'),	"  Ctrl-R",	"Reset flow cache on the Interface" },
 { 'n',		"    N",	"Toggle numeric values to names conversion" },

 { 0,0,0 }
};

ShowMode
help_page_mode()
{
	return help_mode;
}

static void
scale_size(name, descr)
	int *name, *descr;
{
	*name	= line_factor * (double)HELP_PAGE_NAME;
	*descr	= line_factor * (double)HELP_PAGE_DESCR;
}

static int
help_page_header(dst, size, unused)
	char *dst;
	int size;
	const void *unused;
{
	int name_sz, desc_sz;

	/* sanity check */
	if (!dst || size < 1 || unused)
		return 0;

	scale_size(&name_sz, &desc_sz);

	snprintf(dst, size,
		 "%-*.*s %-*.*s",
		 name_sz, name_sz,	" KeyPress",
		 desc_sz, desc_sz,	"Action");
	return 0;
}

static int
help_page_line(dst, size, hp, idx)
	char *dst;
	int size;
	const struct help_page_entry *hp;
	int idx;
{
	int name_sz, desc_sz;

	/* sanity check */
	if (!dst || size < 1 || !hp)
		return 0;

	scale_size(&name_sz, &desc_sz);
	snprintf(dst, size,
		 "%-*.*s %-*.*s",
		 name_sz, name_sz,	hp[idx].name,
		 desc_sz, desc_sz,	hp[idx].descr);
	return 0;
}

static int
help_page_footer(dst, size, topic)
	char *dst;
	int size;
	const char *topic;
{
	int i, len;
	SELECTOR *sp = help_page_selector();

	/* sanity check */
	if (!dst || size < 1 || !topic || !sp)
		return 0;
	i = 0;
	len = strlen(topic);
	if (len > 0 && len < sp->COLS) {
		len = sp->COLS/2 - len/2;
		while (i < len) dst[i++] = ' ';
	}
	(void)strncpy(dst + i, topic, size - i);
	dst[size-1] = '\0';
	return 0;
}

SELECTOR *
help_page_selector()
{
	static SELECTOR *sp = 0;
	if (!sp && (sp = selector_init()) != 0) {
		int name_sz, desc_sz;
		scale_size(&name_sz, &desc_sz);

		sp->window_color = A_REVERSE;
		sp->cursor_color = A_NORMAL;
		sp->COLS = MIN(name_sz + desc_sz, COLS);
		sp->LINES = MIN(sp->COLS/3, LINES);
		sp->COL = COLS/2 - sp->COLS/2;
		sp->LINE = LINES/2 - sp->LINES/2;
		sp->get_header = help_page_header;
		sp->get_line = help_page_line;
		sp->get_footer = help_page_footer;
	}
	return sp;
}

int
help_page_key(idx)
	int idx;
{
	int i;
	SELECTOR *sp;
	const struct help_page_entry *hp;

	if ((sp = help_page_selector()) == 0)
		return -1;
	hp = (const struct help_page_entry *)sp->list;
	for (i = 0; hp; hp++) {
		if (i++ == idx) break;
	}
	return (hp ? hp->key : -1);
}

SELECTOR *
help_page_list(mode)
	ShowMode mode;
{
	struct help_page_entry *hp = 0;
	char *topic = 0;
	SELECTOR *sp;

	switch (mode) {
	case Interfaces:
		hp = Interfaces_help;
		topic = "Interface selection Help";
		break;
	case NetStat:
		hp = NetStat_help;
		topic = "Network Flow selection Help";
		break;
	case FlowDump:	/* no help available */
	case HelpPage:	/* help on help?? */
		return 0;
	}

	if ((sp = help_page_selector()) != 0) {
		help_mode = mode;
		sp->header = 0; /* unused */
		sp->footer = topic;
		sp->list = hp;
		sp->items = 0;
		for (; hp && hp->name; hp++)
			sp->items++;
	}
	return sp;
}

