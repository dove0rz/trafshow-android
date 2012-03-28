/*
 *	Copyright (c) 2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifndef	_HELP_PAGE_H_
#define	_HELP_PAGE_H_

#define	HELP_PAGE_NAME	10
#define	HELP_PAGE_DESCR	50

struct selector;
struct selector *help_page_selector();
struct selector *help_page_list(ShowMode mode);
ShowMode help_page_mode();
int help_page_key(int idx);

#endif	/* !_HELP_PAGE_H_ */
