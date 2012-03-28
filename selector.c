/*
 *	Copyright (c) 1998,2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifdef	HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef	HAVE_SLCURSES
#include <slcurses.h>
#elif	HAVE_NCURSES
#include <ncurses.h>
#else
#include <curses.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "selector.h"
#include "screen.h"
#include "getkey.h"

#define	BLANK	' '

#ifdef	ACS_HLINE
#define	HLINE	ACS_HLINE
#else
#define	HLINE	'-'
#endif

static void get_size(const SELECTOR *sp, int *lines, int *cols);
static void get_colors(const SELECTOR *sp, int *foreground, int *cursor);

static void
get_size(sp, lines, cols)
	const SELECTOR *sp;
	int *lines, *cols;
{
	int ln = LINES, cl = COLS;
	if (sp) {
		if (sp->LINES > 0 && sp->LINES < LINES)
			ln = sp->LINES;
		if (sp->get_header)
			ln -= 2;
		if (sp->get_footer)
			ln -= 2;
		if (ln < 1)
			ln = 1;

		if (sp->COLS > 0 && sp->COLS < COLS)
			cl = sp->COLS;
		if (cl < 1)
			cl = 1;
	}
	if (lines) *lines = ln;
	if (cols) *cols = cl;
}

static void
get_colors(sp, fore, curs)
	const SELECTOR *sp;
	int *fore, *curs;
{
	int fg = A_NORMAL, cr = A_REVERSE;
	if (sp && use_colors) {
		if (sp->window_color != -1)
			fg = sp->window_color;
		if (sp->cursor_color != -1)
			cr = sp->cursor_color;
	}
	if (prompt_mode) cr = fg;
	if (fore) *fore = fg;
	if (curs) *curs = cr;
}

/*
 * Allocate & initialize selector handler.
 */
SELECTOR *
selector_init()
{
	SELECTOR *sp = (SELECTOR *)malloc(sizeof(SELECTOR));
	if (sp) {
		memset(sp, 0, sizeof(SELECTOR));
		sp->window_color = -1;
		sp->cursor_color = -1;
	}
	return sp;
}

/*
 * Redraw selector region and refresh screen.
 */
void
selector_redraw(sp)
	SELECTOR *sp;
{
	int i, l, r, lines, cols, first_line, first_col;
	int fg_color, cr_color, attr;
	char *cp, buf[1024];

	/* sanity check */
	if (!sp) return;

	if (sp->index >= sp->items)
		selector_set(sp->items - 1, sp);

	get_size(sp, &lines, &cols);
	get_colors(sp, &fg_color, &cr_color);

	first_line = sp->LINE;
	first_col = sp->COL;

	attrset(A_NORMAL);

#ifdef	HAVE_WREDRAWLN
	wredrawln(stdscr, first_line, lines + 2);
#endif

	/* draw header */
	if (sp->get_header) {
		attr = fg_color;
		attr |= (*sp->get_header)(buf, sizeof(buf), sp->header);

		move(first_line, first_col);
		r = cols;
		for (cp = buf; *cp && r-- > 0; cp++) {
			if (*cp > ' ')
				addch(*cp | attr);
			else	addch(BLANK | attr);
		}
		while (r-- > 0) addch(BLANK | attr);

		move(first_line + 1, first_col);
		r = cols;
		while (r-- > 0) addch(HLINE | attr);

		first_line += 2;
	}

	/* draw main area */
	for (i = sp->fline, l = 0; l < lines; i++, l++) {
		attr = fg_color;
		move(first_line + l, first_col);
		r = cols;
		if (i < sp->items && sp->get_line) {
			attr |= (*sp->get_line)(buf, sizeof(buf), sp->list, i);
			if (i == sp->index)
				attr = cr_color;
			for (cp = buf; *cp && r-- > 0; cp++) {
				if (*cp > ' ')
					addch(*cp | attr);
				else	addch(BLANK | attr);

				/* workaround -- last attr mustbe foreground */
				if (r == 1 && i == sp->items - 1)
					attr = fg_color;
			}
		}
		while (r-- > 0) addch(BLANK | attr);
	}

	/* draw footer */
	if (sp->get_footer) {
		attr = fg_color;
		attr |= (*sp->get_footer)(buf, sizeof(buf), sp->footer);

		first_line += l;
		move(first_line++, first_col);
		r = cols;
		while (r-- > 0) addch(HLINE | attr);

		if (!prompt_mode || first_line != LINES-1) {
			move(first_line, first_col);
			r = cols;
			for (cp = buf; *cp && r-- > 0; cp++) {
				if (*cp > ' ')
					addch(*cp | attr);
				else	addch(BLANK | attr);
			}
			while (r-- > 0) addch(BLANK | attr);
		}
	}

	/* refresh screen */
	screen_update();
}

/*
 * Withdraw selector from the screen.
 */
void
selector_withdraw(sp)
	SELECTOR *sp;
{
	int i, l, r, lines, cols, first_line, first_col;
	int fg_color, attr;
	char *cp, buf[1024];

	/* sanity check */
	if (!sp || !sp->get_line) return;

	get_size(sp, &lines, &cols);
	get_colors(sp, &fg_color, 0);

	first_line = sp->LINE;
	first_col = sp->COL;

	attrset(A_NORMAL);

	if (sp->get_header)
		first_line += 2;

#ifdef	HAVE_WREDRAWLN
	wredrawln(stdscr, first_line, lines);
#endif
	for (i = sp->fline, l = 0; l < lines; i++, l++) {
		if (i != sp->index)
			continue;
		attr = fg_color;
		move(first_line + l, first_col);
		r = cols;
		if (i < sp->items && sp->get_line) {
			attr |= (*sp->get_line)(buf, sizeof(buf), sp->list, i);
			for (cp = buf; *cp && r-- > 0; cp++) {
				if (*cp > ' ')
					addch(*cp | attr);
				else	addch(BLANK | attr);

				/* workaround -- last attr mustbe foreground */
				if (r == 1 && i == sp->items - 1)
					attr = fg_color;
			}
			while (r-- > 0) addch(BLANK | attr);
		}
		break;
	}
}

/*
 * Return current selector position or -1 if no selector present.
 */
int
selector_get(sp)
	SELECTOR *sp;
{
	/* sanity check */
	if (!sp || !sp->list || sp->items < 1 ||
	    sp->index < 0 || sp->index >= sp->items)
		return -1;
	return sp->index;
}

/*
 * Set selector to requested position.
 */
void
selector_set(new_index, sp)
	int new_index;
	SELECTOR *sp;
{
	int lines;

	/* sanity check */
	if (!sp) return;

	if (sp->items < 1) {
		sp->index = 0;
		sp->fline = 0;
		sp->cline = 0;
		return;
	}
	get_size(sp, &lines, 0);

	if (new_index >= sp->items)
		new_index = sp->items - 1;

	sp->fline = (new_index / lines) * lines;
	sp->cline = new_index % lines;
	if (sp->fline + lines >= sp->items) {
		sp->fline = sp->items - lines;
		if (sp->fline < 0) sp->fline = 0;
		sp->cline = new_index - sp->fline;
	}
	sp->index = new_index;
}

/*
 * Move selector on screen.
 * Return index selected or -1.
 */
int
selector_move(ch, sp)
	int ch;
	SELECTOR *sp;
{
	int lines;

	/* sanity check */
	if (!sp) return -1;

	get_size(sp, &lines, 0);

	switch (ch) {
		case 'k':
		case K_CTRL('P'):
		case K_UP:		/* line up */
			if (sp->index - 1 < 0) break;
			sp->index--;
			if (--sp->cline < 0 && sp->fline) {
				sp->cline = 0;
				if (--sp->fline < 0)
					sp->fline = 0;
			}
			break;

		case 'j':
		case K_CTRL('N'):
		case K_DOWN:		/* line down */
			if (sp->index + 1 >= sp->items) break;
			sp->index++;
			if (++sp->cline >= lines) {
				sp->cline--;
				sp->fline = sp->index - sp->cline;
			}
			break;

		case K_BS:
		case K_CTRL('U'):
		case K_CTRL('B'):
		case K_PAGEUP:		/* page up */
			if (sp->cline > 0) {
				sp->index -= sp->cline;
			} else {
				sp->index -= lines;
				sp->fline -= lines;
				if (sp->index < 0 || sp->fline < 0)
					sp->index = sp->fline = 0;
			}
			sp->cline = 0;
			break;

		case ' ':
		case K_CTRL('D'):
		case K_CTRL('F'):
		case K_PAGEDOWN:	/* page down */
			if (sp->items <= lines) {
				sp->index = sp->cline = sp->items - 1;
			} else {
				if (sp->cline < lines - 1) {
					sp->index += lines - sp->cline - 1;
				} else {
					sp->index += lines;
					sp->fline = sp->index - lines + 1;
				}
				if (sp->index >= sp->items) {
					sp->index = sp->items - 1;
					sp->fline = sp->items - lines;
				}
				sp->cline = lines - 1;
			}
			break;

		case K_CTRL('A'):
		case K_HOME:		/* home */
			sp->index = 0;
			sp->fline = 0;
			sp->cline = 0;
			break;

		case K_CTRL('E'):
		case K_END:		/* end */
			if (sp->items <= lines) {
				sp->index = sp->cline = sp->items - 1;
			} else {
				sp->index = sp->items - 1;
				sp->fline = sp->items - lines;
				sp->cline = lines - 1;
			}
			break;

		case K_CR:	/* select index */
		case K_NL:
			return sp->index;

		case K_CTRL('G'):	/* trace; for debug purpose only */
			mvprintw(LINES-1, 0, "items=%d index=%d fline=%d cline=%d LINE=%d COL=%d LINES=%d func=%p",
				 sp->items, sp->index, sp->fline,
				 sp->cline, sp->LINE, sp->COL,
				 lines, sp->get_line);
			clrtoeol();
			break;
	}
	return -1;
}

