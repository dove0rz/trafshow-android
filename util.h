/*
 *	Copyright (c) 2004 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifndef	_UTIL_H_
#define	_UTIL_H_

char *strip_path(const char *path);
char *strip_blanks(char *str);
char *copy_argv(char **av);		/* malloc is used */
long fd_size(int fd);
char *load_file(const char *name);	/* malloc is used */

#endif	/* !_UTIL_H_ */
