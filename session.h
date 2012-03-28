/*
 *	Copyright (c) 2003 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifndef	_SESSION_H_
#define	_SESSION_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>

/*
 * Session handler.
 */

/* currently supported session types */
typedef	enum {
	PlainFile,	/* simple I/O with a file descriptor */
	TextStream,	/* CRLFed text lines exchange through TCP */
	DataSequence	/* raw binary data exchange through UDP */
} SessionType;

struct session_binder_ent;

#ifndef	HAVE_SOCKADDR_STORAGE

/*
 * RFC 2553: protocol-independent placeholder for socket addresses
 */
#define _SS_MAXSIZE	128
#define _SS_ALIGNSIZE	(sizeof(u_int64_t))
#define _SS_PAD1SIZE	(_SS_ALIGNSIZE - sizeof(u_char) * 2)
#define _SS_PAD2SIZE	(_SS_MAXSIZE - sizeof(u_char) * 2 - \
				_SS_PAD1SIZE - _SS_ALIGNSIZE)

struct sockaddr_storage {
	u_char	ss_len;		/* address length */
	u_char	ss_family;	/* address family */
	char	__ss_pad1[_SS_PAD1SIZE];
	u_int64_t __ss_align;	/* force desired structure storage alignment */
	char	__ss_pad2[_SS_PAD2SIZE];
};

#endif /* HAVE_SOCKADDR_STORAGE */

typedef	struct session_ent {
	u_long	sid;		/* session id (must not be zero!) */

	/* user supplied parameters */
	int sock;		/* socket file descriptor */
	struct sockaddr_storage peer;	/* remote peer address and port */
	struct sockaddr_storage from;	/* recvfrom peer */
	SessionType type;	/* session type, see above */
	unsigned timeout;	/* reply timeout in seconds */

	/* internal */
	struct timeval expire;	/* time until first timeout */
	char *buf;		/* temporary I/O buffer */

	/* user callback functions */
	void (*connected)(struct session_ent *sd);
	void (*read_error)(struct session_ent *sd, int error);
	void (*read_data)(struct session_ent *sd, const unsigned char *data, int len);

	const void *cookie;	/* user defined container, cast it yourself */

	struct session_binder_ent *sb; /* session binder container */

	struct session_ent *next;
} SESSION;

SESSION *session_open(int sock, const struct sockaddr *peer, SessionType type);
int session_sock(SESSION *sd);
int session_start(SESSION *sd);
void session_stop(SESSION *sd);
int session_idle(SESSION *sd);
void session_free(SESSION *sd);
void session_setcallback(SESSION *sd,
			 void (*connected)(SESSION *sd),
			 void (*read_error)(SESSION *sd, int error),
			 void (*read_data)(SESSION *sd, const unsigned char *data, int len));
void session_setcookie(SESSION *sd, const void *cookie);
const void *session_cookie(SESSION *sd);
unsigned session_settimeout(SESSION *sd, unsigned timeout);
int session_send(SESSION *sd, const unsigned char *data, int len);
int session_select(int *nfds, fd_set *readfds, fd_set *writefds,
		   struct timeval *timeout, int *block);
void session_operate(fd_set *readfds, fd_set *writefds);
void session_timeout();
const struct sockaddr *session_peer(SESSION *sd);
const struct sockaddr *session_from(SESSION *sd);
SESSION *session_find(const struct sockaddr *peer, SessionType type);

int session_bind(SESSION *sd, void (*notify)(void *arg), void *arg);
void session_unbind(SESSION *sd, void (*notify)(void *arg), void *arg);

int socket_nonblock(int sock, int on);
int socket_keepalive(int sock, int on);
int socket_error(int sock);
int socket_peer(struct sockaddr *peer, int sock);
int socket_name(struct sockaddr *name, int sock);

#endif	/* _SESSION_H_ */
