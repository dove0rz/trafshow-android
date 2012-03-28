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

#ifdef	HAVE_SLCURSES
#include <slcurses.h>
#elif	HAVE_NCURSES
#include <ncurses.h>
#else
#include <curses.h>
#endif
#include <sys/types.h>
#include <sys/ioctl.h>
#ifdef	HAVE_SYS_TERMIOS_H
#include <asm/termios.h> // sys/termios => asm/termios, by dove
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include "screen.h"
#include "colormask.h"

#ifndef	TIOCGWINSZ
#define	TIOCGWINSZ	104
#endif

int use_colors = 0;
int prompt_mode = 0;
double line_factor = 1;


/*
 * Initialize curses.
 */
int
screen_open(resize)
	int resize;
{
	if (!resize) {
		if (initscr() == (WINDOW *)ERR) {
			fprintf(stderr, "Can't initialize terminal -- unknown terminal type?\n");
			return -1;
		}
#ifdef	HAVE_HAS_COLORS
		use_colors = has_colors();
#ifdef	HAVE_SLCURSES
		SLtt_Use_Ansi_Colors = 1; /* force color mode */
		use_colors = 1;
#endif
		if (use_colors) {
			start_color();
			if (init_colormask() < 0) {
				endwin();
				return -1;
			}
		}
#endif /* HAVE_HAS_COLORS */
		cbreak();
		noecho();
		nonl();

	} else { /* resize terminal */
		int fd, new_rows = 0, new_cols = 0;
		struct winsize ws;
		char *cp;

		if ((fd = open("/dev/tty", 0)) != -1) {
			if (ioctl(fd, TIOCGWINSZ, &ws) != -1) {
				new_rows = ws.ws_row;
				new_cols = ws.ws_col;
			}
			close(fd);
		}
		if (!new_rows) {
			if ((cp = getenv("LINES")) != NULL)
				new_rows = atoi(cp);
			else    new_rows = DEFAULT_LINES;
		}
		if (!new_cols) {
			if ((cp = getenv("COLUMNS")) != NULL)
				new_cols = atoi(cp);
			else    new_cols = DEFAULT_COLUMNS;
		}
#ifdef	HAVE_RESIZETERM
		resizeterm(new_rows, new_cols);
#elif	HAVE_SLCURSES
		SLtt_Screen_Rows = new_rows;
		SLtt_Screen_Cols = new_cols;
		SLcurses_delwin(stdscr);
		SLsmg_reset_smg();
		SLsmg_init_smg();
		stdscr = SLcurses_newwin(0, 0, 0, 0);
#else /* assume it work on all curses */
		endwin();
		initscr();
		cbreak();
		noecho();
		nonl();
#endif
	}
	clear();

	prompt_mode = 0;
	screen_dock_cursor(LINES-1, COLS-1);

	if (LINES < MINPAGESIZE) {
		screen_status("Too small LINES (%d) on screen", LINES);
		return -1;
	}
	if (COLS < MINPAGESIZE * 2) {
		screen_status("Too small COLUMNS (%d) on screen", COLS);
		return -1;
	}

	line_factor = (double)COLS / (double)DEFAULT_COLUMNS;
	return 0;
}

/*
 * Return terminal original settings.
 */
void
screen_close()
{
	attrset(A_NORMAL);
	move(LINES-1, 0);
	clrtoeol();
	refresh();
	endwin();
}

void
screen_clear()
{
	attrset(A_NORMAL);
	clear();
	refresh();
}

static int curs_dock_x = 0, curs_dock_y = 0;

void
screen_update()
{
	move(curs_dock_y, curs_dock_x);
	refresh();
}

void
screen_dock_cursor(y, x)
	int y, x;
{
	curs_dock_x = x ? x : COLS - 1;
	curs_dock_y = y ? y : LINES - 1;
}

void
screen_status(const char *fmt, ...)
{
	va_list ap;
	char buf[1024];

	va_start(ap, fmt);
	(void)strcpy(buf, "[ ");
	vsprintf(buf+2, fmt, ap);
	buf[COLS-4] = '\0';
	(void)strcat(buf, " ]");

	attrset(A_STANDOUT);
	mvaddstr(LINES-2, COLS/2 - strlen(buf)/2, buf);
	attrset(A_NORMAL);

	screen_update();
	(void)sleep(1);
}

