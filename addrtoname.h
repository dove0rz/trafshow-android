/*
 * Copyright (c) 1990, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * @(#) $Header: /tcpdump/master/tcpdump/addrtoname.h,v 1.18 2001/09/17 21:57:51 fenner Exp $ (LBL)
 */

#ifndef	_ADDRTONAME_H_
#define	_ADDRTONAME_H_

/* Name to address translation routines. */

const char *linkaddr_string(const u_char *addr, const unsigned int);
const char *etheraddr_string(const u_char *addr);
const char *ethertype_string(u_short type);
const char *tcpport_string(u_short port);
const char *udpport_string(u_short port);
int isservport(u_short port);
const char *getname(const u_char *addr);
const char *ipproto_string(u_char proto);

#ifdef INET6
const char *getname6(const u_char *addr);
#endif
const char *intoa(u_int32_t);
char *satoa(const struct sockaddr *saddr, char *dst, int size);

void init_addrtoname(void);
struct hnamemem *newhnamemem(void);
#ifdef INET6
struct h6namemem *newh6namemem(void);
#endif

#define ipaddr_string(p) getname((const u_char *)(p))
#ifdef INET6
#define ip6addr_string(p) getname6((const u_char *)(p))
#endif

const char *isonsap_string(const u_char *nsap);
const char *llcsap_string(u_char sap);
const char *ipxsap_string(u_short sap);
const char *icmp_string(u_short code);
#ifdef INET6
const char *icmpv6_string(u_short code);
#endif

#endif	/* !_ADDRTONAME_H_ */
