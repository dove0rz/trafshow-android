/*
 *	Copyright (c) 2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifndef	_SCREEN_H_
#define	_SCREEN_H_

#define DEFAULT_COLUMNS		80      /* mandatory */
#define DEFAULT_LINES		24
#define	MINPAGESIZE		20

#ifndef	ACS_HLINE
#define	ACS_HLINE	'-'
#endif

int screen_open(int resize);
void screen_close(void);
void screen_status(const char *fmt, ...);
void screen_update(void);
void screen_clear(void);
void screen_dock_cursor(int y, int x);

extern int use_colors;
extern int prompt_mode;
extern double line_factor;

#endif	/* !_SCREEN_H_ */
