/*
 *	Copyright (c) 2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifndef	_SHOW_DUMP_H_
#define	_SHOW_DUMP_H_

#define	DUMP_SNAPLEN	1536

struct pcap_handler;
struct netstat;

int show_dump_open(const struct pcap_handler *ph, const struct netstat *ns);
void show_dump_print(struct pcap_handler *ph);
void show_dump_close(void);
void show_dump_input(int ch);

extern const char *dump_file;
extern const char *cisco_netflow_dump;
extern struct netstat *dump_match;

#endif	/* !_SHOW_DUMP_H_ */
