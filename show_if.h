/*
 *	Copyright (c) 2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifndef	_SHOW_IF_H_
#define	_SHOW_IF_H_

#define	SHOW_IF_NAME	15
#define	SHOW_IF_ADDR	45
#define	SHOW_IF_DESCR	20

struct selector;
struct pcap_handler;
struct selector *show_if_list(struct pcap_handler *list);
struct selector *show_if_selector();
int show_if_search(struct pcap_handler *list, const char *str);

#endif	/* !_SHOW_IF_H_ */
