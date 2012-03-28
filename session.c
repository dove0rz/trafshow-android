/*
 *	Copyright (c) 1999-2003 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifdef	HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "session.h"
#include "events.h"	/* just for tv_sub() */

#define	dprintf(x)	/* nope */

#ifndef	BUF_SIZE
#define	BUF_SIZE	8192
#endif
#ifndef	MAX_STR_LEN
#define	MAX_STR_LEN	1500	/* must be vastly smaller then BUF_SIZE */
#endif

#ifdef	O_NONBLOCK
#define	ASYNC_MODE	O_NONBLOCK
#elif	O_NDELAY
#define	ASYNC_MODE	O_NDELAY
#elif	FNDELAY
#define	ASYNC_MODE	FNDELAY
#elif	O_ASYNC
#define	ASYNC_MODE	O_ASYNC
#else
#error the fcntl argument to turn ON/OFF non-blocking I/O is unknown
#endif

static int session_read(SESSION *sd);

static SESSION *first_session = 0;	/* first network session in table */

typedef	struct session_binder_ent {
	void (*notify)(void *arg);	/* call it before free */
	void *arg;
	struct session_binder_ent *next;
} SESSION_BINDER;


SESSION *
session_open(sock, peer, type)
	int sock;
	const struct sockaddr *peer;
	SessionType type;
{
	SESSION *sd, *prev = 0, *next = 0;
	static u_long sid = 0;

	/*
	 * Search for first empty or last session slot.
	 */
	for (sd = first_session; sd; sd = sd->next) {
		if (!sd->sid) {
			next = sd->next;
			break;
		}
		prev = sd;
	}
	if (!sd && (sd = (SESSION *)malloc(sizeof(SESSION))) == 0)
		return 0;
	memset(sd, 0, sizeof(SESSION));

	if (++sid == 0) sid++; /* prevent 0 sid */
	sd->sid = sid;
	sd->sock = sock;
	if (peer)
		memcpy(&sd->peer, peer, sizeof(struct sockaddr));
	else	memset(&sd->peer, 0, sizeof(sd->peer));
	memset(&sd->from, 0, sizeof(sd->from));

	sd->type = type;

	/* make chain */
	if (next) sd->next = next;
	else if (prev) prev->next = sd;
	if (!first_session) first_session = sd;

	if (session_start(sd) < 0) {
		sd->sid = 0; /* this slot may be recycled later */
		sd = 0;
	}
	return sd;
}

int
session_start(sd)
	SESSION *sd;
{
	int af;

	/* sanity check */
	if (!sd) {
		errno = EINVAL;
		return -1;
	}
	errno = EBADF;
	if (sd->sock != -1 &&
	    (sd->type == PlainFile || socket_peer((struct sockaddr *)&sd->peer, sd->sock) != -1)) {
		/* already connected for example by accept() */

		socket_nonblock(sd->sock, 0);
		if (sd->type == TextStream)
			socket_keepalive(sd->sock, 1);
		return 0;
	}

	af = sd->peer.ss_family;
	if (!af) af = AF_INET; /* by default */

	if (errno == EBADF || errno == ENOTSOCK) {
		switch (sd->type) {
		case PlainFile:
			sd->sock = -1;
			errno = EINVAL;
			break;
		case TextStream:
			sd->sock = socket(af, SOCK_STREAM, 0);
			break;
		case DataSequence:
			sd->sock = socket(af, SOCK_DGRAM, 0);
			break;
		/* XXX other session types would be added here */
		}
		if (sd->sock == -1)
			return -1;

		errno = ENOTCONN;
	}
	if (errno == ENOTCONN) {
		/*
		 * Make socket `connected' for any type, so error on this
		 * socket will be returned asynchronously without timing out.
		 */
		socket_nonblock(sd->sock, 1);

		if (!sd->peer.ss_family) {
			errno = 0;
			return 0;
		}

		if (connect(sd->sock, (struct sockaddr *)&sd->peer, sizeof(struct sockaddr)) != -1 ||
		    errno == EINPROGRESS)
			return 0;
	}
	/* prevent lost of unused socket */
	session_stop(sd);

	return -1;
}

int
session_sock(sd)
	SESSION *sd;
{
	return (sd ? sd->sock : -1);
}

unsigned
session_settimeout(sd, timeout)
	SESSION *sd;
	unsigned timeout;
{
	unsigned prev;

	if (!sd || !sd->sid) return 0;

	prev = sd->timeout;
	sd->timeout = timeout;

	if (sd->timeout < 1)
		timerclear(&sd->expire);

	return prev;
}

void
session_setcallback(sd, connected, read_error, read_data)
	SESSION *sd;
	void (*connected)(SESSION *sd);
	void (*read_error)(SESSION *sd, int error);
	void (*read_data)(SESSION *sd, const unsigned char *data, int len);
{
	if (sd && sd->sid) {
		if (connected && sd->type == TextStream) {
			sd->connected = connected;
		}
		if (read_error)
			sd->read_error = read_error;
		if (read_data)
			sd->read_data = read_data;
	}
}

void
session_setcookie(sd, cookie)
	SESSION *sd;
	const void *cookie;
{
	if (sd && sd->sid) sd->cookie = cookie;
}

const void *
session_cookie(sd)
	SESSION *sd;
{
	return ((sd && sd->sid) ? sd->cookie : 0);
}

void
session_stop(sd)
	SESSION *sd;
{
	if (!sd) return;

	if (sd->sock != -1) {
		close(sd->sock);
		sd->sock = -1;
	}
	if (sd->buf) {
		free(sd->buf);
		sd->buf = 0;
	}
	timerclear(&sd->expire);
}

int
session_idle(sd)
	SESSION *sd;
{
	if (!sd || !sd->sid) return -1;
	return (sd->sock != -1 ? 0 : 1);
}

int
session_bind(sd, notify, arg)
	SESSION *sd;
	void (*notify)(void *arg);
	void *arg;
{
	SESSION_BINDER *curr, *last = 0;

	if (!sd || !notify || !arg) {
		errno = EINVAL;
		return -1;
	}
	/* prevent dups and find last */
	for (curr = sd->sb; curr; curr = curr->next) {
		if (curr->notify == notify && curr->arg == arg)
			return 0;
		last = curr;
	}
	if ((curr = (SESSION_BINDER *)malloc(sizeof(SESSION_BINDER))) == 0)
		return -1;
	curr->notify = notify;
	curr->arg = arg;
	curr->next = 0;
	if (last)
		last->next = curr;
	else	sd->sb = curr;
	return 0;
}

void
session_unbind(sd, notify, arg)
	SESSION *sd;
	void (*notify)(void *arg);
	void *arg;
{
	SESSION_BINDER *curr, *prev, *next;

	curr = (sd ? sd->sb : 0);
	prev = 0;
	while (curr) {
		if ((!notify && !arg) ||
		    (curr->notify == notify && curr->arg == arg)) {
			next = curr->next;
			if (prev)
				prev->next = next;
			else	sd->sb = next;
			free(curr);
			curr = next;
		} else {
			prev = curr;
			curr = curr->next;
		}
	}
}

/*
 * This function free all memory only when free_sd = 0 else it just reset
 * session id and does not free memory. The mean of this behaving is to
 * reuse/recycle session slots without new malloc (avoiding it overhead).
 */
void
session_free(free_sd)
	SESSION *free_sd;
{
	SESSION *sd, *prev, *next;
	SESSION_BINDER *sb;

	sd = first_session;
	prev = next = 0;
	while (sd) {
		if (!free_sd || sd == free_sd) {
			if (!free_sd) {
				next = sd->next;
				if (prev)
					prev->next = next;
				else	first_session = next;
			}

			for (sb = sd->sb; sb; sb = sb->next) {
				if (sb->notify && sb->arg)
					(*sb->notify)(sb->arg);
			}
			session_stop(sd);
			session_unbind(sd, 0, 0); /* to free all */

			if (!free_sd) {
				free(sd);
				sd = next;
				continue;
			}
			sd->sid = 0; /* this slot may be recycled later */
		}
		prev = sd;
		sd = sd->next;
	}
}

SESSION *
session_find(peer, type)
	const struct sockaddr *peer;
	SessionType type;
{
	SESSION *sd;

	/* sanity check */
	if (!peer) return 0;

	for (sd = first_session; sd; sd = sd->next) {
		if (!sd->sid || sd->type != type ||
		   sd->peer.ss_family != peer->sa_family)
			continue;

		if (peer->sa_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&sd->peer;
			if (sin->sin_port == ((struct sockaddr_in *)peer)->sin_port &&
			    !memcmp(&sin->sin_addr,
				    &((struct sockaddr_in *)peer)->sin_addr,
				    sizeof(sin->sin_addr)))
				return sd;
		}
#ifdef	INET6
		else if (peer->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin = (struct sockaddr_in6 *)&sd->peer;
			if (sin->sin6_port == ((struct sockaddr_in6 *)peer)->sin6_port &&
			    !memcmp(&sin->sin6_addr,
				    &((struct sockaddr_in6 *)peer)->sin6_addr,
				    sizeof(sin->sin6_addr)))
				return sd;
		}
#endif
	}
	return 0;
}

int
session_send(sd, data, len)
	SESSION *sd;
	const unsigned char *data;
	int len;
{
	int wlen = 0;

	if (!sd || len < 0) {
		errno = EINVAL;
		return -1;
	}
	if (!sd->sid || sd->sock == -1) {
		errno = ENOTCONN;
		return -1;
	}
	if (data) {
		if (sd->type == PlainFile) {
			if (len) wlen = write(sd->sock, data, len);

		} else if (sd->type == TextStream) {
			char buf[BUF_SIZE];

			if (!sd->peer.ss_family) {
				errno = ENOTCONN;
				return -1;
			}
			if (len > sizeof(buf)-2) len = sizeof(buf)-2;
			if (len) memcpy(buf, data, len);
			if (!len || buf[len-1] != '\n') {
				buf[len++] = '\r';
				buf[len++] = '\n';
			}
			wlen = write(sd->sock, buf, len);

		} else if (sd->type == DataSequence) {

			if (!sd->peer.ss_family) {
				errno = ENOTCONN;
				return -1;
			}
			if (len) wlen = send(sd->sock, data, len, 0);

		} else { /* XXX other session types must be added here */
			wlen = -1;
			errno = ESOCKTNOSUPPORT;
		}
	}
	if (wlen == -1) {
		if (errno == EAGAIN || errno == EINPROGRESS) {
			errno = 0;
			wlen = 0;
		} else if (sd->read_error) {
			(*sd->read_error)(sd, errno);
			return wlen;
		}
	}
	if (sd->timeout > 0) {
		gettimeofday(&sd->expire, 0);
		sd->expire.tv_sec += sd->timeout;
	}
	return wlen;
}

static int
session_read(sd)
	SESSION *sd;
{
	int rlen = 0, rest = 0;
	char *cp, *line, buf[BUF_SIZE];

	if (!sd) {
		errno = EINVAL;
		return -1;
	}
	if (!sd->sid || sd->sock == -1) {
		errno = ENOTCONN;
		return -1;
	}
	buf[0] = '\0';

	if (sd->type == PlainFile) {
		rlen = read(sd->sock, buf, sizeof(buf));

	} else if (sd->type == TextStream) {
		if (sd->buf) { /* previous line was truncated */
			rest = strlen(strcpy(buf, sd->buf));
			free(sd->buf);
			sd->buf = 0;
		}
		rlen = read(sd->sock, &buf[rest], (sizeof(buf)-1) - rest);

	} else if (sd->type == DataSequence) {
		struct sockaddr from;
		socklen_t slen = sizeof(from);

		rlen = recvfrom(sd->sock, buf, sizeof(buf), 0, &from, &slen);
		if (rlen != -1) {
			/* just for sanity */
			if (slen < sizeof(struct sockaddr_in) ||
			    slen > sizeof(struct sockaddr))
				return 0; /* should not happen */

			if (sd->peer.ss_family &&
			    sd->peer.ss_family != from.sa_family)
				return 0; /* bad family */

			/* save packet from */
			memcpy(&sd->from, &from, slen);
		} else	memset(&sd->from, 0, sizeof(sd->from));

	} else { /* XXX other session types must be added here */
		errno = ESOCKTNOSUPPORT;
		return -1;
	}

	if (rlen < 1) {
		if (!rlen || !errno)
			errno = ECONNRESET;
		return -1;
	}

	if (sd->type == PlainFile || sd->type == DataSequence) {
		if (!sd->sid || sd->sock == -1)
			return 0;
		if (sd->read_data)
			(*sd->read_data)(sd, (u_char *)buf, rlen);

	} else { /* TextStream */
		buf[rest + rlen] = '\0';
		for (cp = buf; (line = strchr(cp, '\n')) != 0; cp = line) {
			if (line > cp && line[-1] == '\r') line[-1] = '\0';
			*line++ = '\0';
			if (!sd->sid || sd->sock == -1)
				return 0;
			if (sd->read_data) {
				rest = strlen(cp);
				if (rest > MAX_STR_LEN) {
					errno = EMSGSIZE;
					return -1;
				}
				(*sd->read_data)(sd, (u_char *)cp, rest);
			}
		}
		if (cp && *cp) { /* truncated line, save it for next read */
			if (strlen(cp) > MAX_STR_LEN) {
				errno = EMSGSIZE;
				return -1;
			}
			sd->buf = strdup(cp);
		}
	}
	return rlen;
}

int
session_select(nfds, readfds, writefds, timeout, block)
	int *nfds;
	fd_set *readfds, *writefds;
	struct timeval *timeout;
	int *block;
{
	SESSION *sd;
	struct timeval earliest, now;
	int active = 0, pending = 0;

	timerclear(&earliest);

	/*
	 * For each request outstanding, add it's socket to the readfds,
	 * and if it is the earliest timeout to expire, mark it as lowest.
	 */
	for (sd = first_session; sd; sd = sd->next) {
		if (!sd->sid || sd->sock == -1) {
			if (sd->sock != -1) /* lost session? free socket */
				session_stop(sd);
			continue;
		}

		active++;
		if (sd->sock + 1 > *nfds)
			*nfds = sd->sock + 1;

		if (!sd->connected) {
			FD_SET(sd->sock, readfds);

			dprintf(("session_select: sock %d set for read", sd->sock));
		} else {
			FD_SET(sd->sock, writefds);

			dprintf(("session_select: sock %d set for write", sd->sock));
		}

		if (timerisset(&sd->expire)) {
			pending++;
			if (!timerisset(&earliest) ||
			    timercmp(&sd->expire, &earliest, <))
				earliest = sd->expire;
		}
	}

	/*dprintf(("session_select: active=%d pending=%d", active, pending));*/

	if (!pending)
		return active;

	/*
	 * Transforms earliest from an absolute time into a delta time, the
	 * time left until the select should timeout.
	 */
	gettimeofday(&now, 0);
	tv_sub(&earliest, &now);

	/* if it was blocking before or our delta time is less, reset timeout */
	if (*block || timercmp(&earliest, timeout, <)) {
		*timeout = earliest;
		*block = 0;
	}
	return active;
}

/*
 * Checks to see if any of the fd's set in the readfds belong to a session.
 */
void
session_operate(readfds, writefds)
	fd_set *readfds, *writefds;
{
	SESSION *sd;
	int try_conn, error;

	for (sd = first_session; sd; sd = sd->next) {
		if (!sd->sid || sd->sock == -1)
			continue;

		try_conn = (sd->connected != 0);

		if (!try_conn && FD_ISSET(sd->sock, readfds)) {

			dprintf(("session_operate: sock %d ready to read", sd->sock));

			if (sd->type == PlainFile)
				error = 0;
			else	error = socket_error(sd->sock);

			if (!error && session_read(sd) < 0)
				error = errno;
			if (error && sd->sid && sd->read_error)
				(*sd->read_error)(sd, error);
		}

		if (try_conn && FD_ISSET(sd->sock, writefds)) {

			dprintf(("session_operate: sock %d ready to write", sd->sock));

			error = socket_error(sd->sock);
			if (!error) {
				socket_peer((struct sockaddr *)&sd->peer, sd->sock);
				socket_nonblock(sd->sock, 0);
				if (sd->type == TextStream)
					socket_keepalive(sd->sock, 1);
				if (sd->sid && sd->connected)
					(*sd->connected)(sd);
				sd->connected = 0; /* fire a shot only once! */
			} else if (sd->sid && sd->read_error)
				(*sd->read_error)(sd, error);
		}
	}
}

/*
 * Checks to see if any of the sessions have an outstanding request
 * that has timed out.
 */
void
session_timeout()
{
	SESSION *sd;
	struct timeval now;

	gettimeofday(&now, 0);

	for (sd = first_session; sd; sd = sd->next) {
		if (!sd->sid || sd->sock == -1)
			continue;

		if (timerisset(&sd->expire) && timercmp(&sd->expire, &now, <)) {
			if (sd->read_error) (*sd->read_error)(sd, ETIMEDOUT);
		}
	}
}

/*
 * Return session peer pointer.
 */
const struct sockaddr *
session_peer(sd)
	SESSION *sd;
{
	return ((sd && sd->peer.ss_family) ? (struct sockaddr *)&sd->peer : 0);
}

/*
 * Return session from pointer.
 */
const struct sockaddr *
session_from(sd)
	SESSION *sd;
{
	return ((sd && sd->from.ss_family) ? (struct sockaddr *)&sd->from : 0);
}

/*
 * Return connected socket peer ip address and port.
 */
int
socket_peer(peer, sock)
	struct sockaddr *peer;
	int sock;
{
	socklen_t arglen;

	if (!peer) {
		errno = EINVAL;
		return -1;
	}
	arglen = sizeof(struct sockaddr);
	return getpeername(sock, peer, &arglen);
}

/*
 * Return socket name ip address and port.
 */
int
socket_name(name, sock)
	struct sockaddr *name;
	int sock;
{
	socklen_t arglen;

	if (!name) {
		errno = EINVAL;
		return -1;
	}
	arglen = sizeof(*name);
	return getsockname(sock, name, &arglen);
}

/*
 * Return socket error (like errno) in the session or 0 if no errors.
 */
int
socket_error(sock)
	int sock;
{
	int argbuf;
	socklen_t arglen;
	struct sockaddr peer;

	arglen = sizeof(argbuf);
	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &argbuf, &arglen) < 0)
		return errno;
	if (argbuf)
		return argbuf;

	arglen = sizeof(argbuf);
	if (getsockopt(sock, SOL_SOCKET, SO_TYPE, &argbuf, &arglen) < 0)
		return errno;
	if (argbuf == SOCK_STREAM) {
		arglen = sizeof(peer);
		if (getpeername(sock, &peer, &arglen) < 0)
			return errno;
	}
	return 0;
}

/*
 * Make socket blocked or non-blocked for sync/async I/O.
 */
int
socket_nonblock(sock, on)
	int sock;
	int on; /* boolean */
{
	int mode;
	int prev; /* boolean */

	/* get current value of I/O mode */
	if ((mode = fcntl(sock, F_GETFL, 0)) < 0)
		return -1;

	prev = (mode & ASYNC_MODE) != 0;
	if (on != prev) {
		if (on)	mode |= ASYNC_MODE;
		else	mode &= ~ASYNC_MODE;
		if (fcntl(sock, F_SETFL, mode))
			return -1;
	}
	return prev;
}

int
socket_keepalive(sock, on)
	int sock, on;
{
#ifdef  SO_KEEPALIVE
	int curr = 0;
	socklen_t slen = sizeof(curr);
	if (getsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &curr, &slen) < 0)
		return -1;

	curr = (curr != 0);
	if (on != curr) {
		if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0)
			return -1;
	}
	return 0;
#else
	errno = ESOCKTNOSUPPORT;
	return -1;
#endif
}

