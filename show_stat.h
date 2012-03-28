/*
 *	Copyright (c) 2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifndef	_SHOW_STAT_H_
#define	_SHOW_STAT_H_

#define	SHOW_STAT_ADDR	25	/* size * 2 */
#define	SHOW_STAT_PROT	10
#define	SHOW_STAT_DATA	10
#define	SHOW_STAT_RATE	10

typedef	enum { Size, Data, Packets } ShowStatMode;

extern ShowStatMode show_stat_mode;

struct selector;
struct pcap_handler;
struct netstat_header;

struct selector *show_stat_list(struct pcap_handler *ph);
int show_stat_input(struct pcap_handler *ph, int ch);
struct selector *show_stat_selector(struct pcap_handler *ph);
struct netstat *show_stat_get(struct pcap_handler *ph, int at);
int show_stat_search(struct pcap_handler *ph, const char *str);

void hdr2str(const struct netstat_header *nh,
	     char *src_buf, int src_len,
	     char *dst_buf, int dst_len,
	     char *proto_buf, int proto_len);

#endif	/* !_SHOW_STAT_H_ */
