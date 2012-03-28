/*
 *	Copyright (c) 2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifndef	_PARSE_DL_H_
#define	_PARSE_DL_H_

int is_parse_dl(int type);
const char *parse_dl_name(int type);

struct netstat;
int parse_dl(struct netstat *ns, int dlt, int clen, int plen, const unsigned char *p);

#endif	/* !_PARSE_DL_H_ */
