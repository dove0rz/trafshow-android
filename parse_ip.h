/*
 *	Copyright (c) 2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifndef	_PARSE_IP_H_
#define	_PARSE_IP_H_

struct netstat;
struct ip;
int parse_ip(struct netstat *ns, int caplen, const struct ip *ip);

#endif	/* !_PARSE_IP_H_ */
