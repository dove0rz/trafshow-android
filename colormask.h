/*
 *	Copyright (c) 2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifndef	_COLORMASK_H_
#define	_COLORMASK_H_

/* SLcurses can't handle attributes as well; so hack it */
#ifdef	HAVE_SLCURSES
#ifdef	SLTT_BOLD_MASK
#undef	A_BOLD
#define	A_BOLD		SLTT_BOLD_MASK
#endif
#ifdef	SLTT_BLINK_MASK
#undef	A_BLINK
#define	A_BLINK		SLTT_BLINK_MASK
#endif
#endif

struct netstat_header;
int init_colormask(void);
int colormask(const struct netstat_header *nh);

#endif	/* !_COLORMASK_H_ */
