/*
 *	Copyright (c) 1999-2003 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifdef	HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "events.h"

#define	dprintf(x)	/* nope */

static EVENT *first_event = 0;	/* first system event in table */

/*
 * Subtract 2 timeval structs: out = out - in. Out result always greater 0.
 */
void
tv_sub(out, in)
	struct timeval *out;
	const struct timeval *in;
{
	if (out->tv_sec > in->tv_sec) {
		out->tv_sec -= in->tv_sec;
		if (out->tv_usec >= in->tv_usec) {
			out->tv_usec -= in->tv_usec;
		} else {
			out->tv_sec--;
			out->tv_usec += 1000000L - in->tv_usec;
		}
	} else if (out->tv_sec == in->tv_sec) {
		out->tv_sec = 0L;
		out->tv_usec -= in->tv_usec;
		if (out->tv_usec < 1)
			out->tv_usec = 100L;	/* not zero anyway */
	} else {
		out->tv_sec = 0L;
		out->tv_usec = 100L;	/* not zero anyway */
	}
}

void
tv_add(out, in)
	struct timeval *out;
	const struct timeval *in;
{
	out->tv_sec += in->tv_sec;
	out->tv_usec += in->tv_usec;
	if (out->tv_usec >= 1000000L) {
		out->tv_sec++;
		out->tv_usec -= 1000000L;
	}
}

/*
 * Round timeval to seconds.
 */
u_long
tv_round(in)
	const struct timeval *in;
{
	u_long sec = in->tv_sec;
	if (in->tv_usec >= 500000L)
		sec++;
	return sec;
}

/*
 * Return time difference in milliseconds.
 */
u_long
tv_diff(tvp1, tvp2)
	const struct timeval *tvp1, *tvp2;
{
	struct timeval diff;

	if (!timerisset(tvp1) || !timerisset(tvp2))
		return 0;

	if (timercmp(tvp1, tvp2, >)) {
		diff = *tvp1;
		tv_sub(&diff, tvp2);
	} else {
		diff = *tvp2;
		tv_sub(&diff, tvp1);
	}
	return (diff.tv_sec * 1000 + diff.tv_usec / 1000);
}

/*
 * Shift the time to be sharp at (12am + N * period), local time.
 */
void
tv_sharp(tvp, period)
	struct timeval *tvp;
	int period;
{
	time_t defect;
	struct tm *tm;

	if (!tvp) return;

	tm = localtime((time_t *)&tvp->tv_sec);
	defect = tm->tm_sec + 60 * tm->tm_min + 3600 * tm->tm_hour;
	defect %= period;
	period -= defect;
	if (period < 1) period = 1;
	tvp->tv_sec += period;
	tvp->tv_usec = (long)random() % 1000000L;
}

/*
 * Execute pending event and schedule the next nearest.
 */
int
select_event(tvp)
	struct timeval *tvp;
{
	EVENT *ep, *next_event;
	struct timeval now, gap, earliest;

	gettimeofday(&now, 0);
	gap.tv_sec = 0;
	gap.tv_usec = 1000L; /* 0.001sec grip */
	tv_add(&gap, &now);
again:
	next_event = 0;
	timerclear(&earliest);

	for (ep = first_event; ep; ep = ep->next) {
		/* skip over the empty slots */
		if (!ep->func) continue;

		if (timercmp(&gap, &ep->tv, >)) {
			void (*func)() = ep->func;
			ep->func = 0;		/* free event slot before */

			dprintf(("-call_event(%p/%p)", func, ep->arg));

			(*func)(ep->arg);	/* call event function */
			goto again;

		} else if (!timerisset(&earliest) ||
			   timercmp(&ep->tv, &earliest, <)) {
			earliest = ep->tv;
			next_event = ep;
		}
	}
	if (!next_event) {	/* no more awaiting events */

		dprintf(("select_event: no timeout"));

		return 1;	/* timeout undefined */
	}
	if (tvp) {
		tv_sub(&earliest, &now);
		*tvp = earliest;

		dprintf(("=wait_event(%p/%p): timeout=%u.%03d",
			 next_event->func, next_event->arg,
			 (unsigned)tvp->tv_sec, (int)(tvp->tv_usec / 1000)));
	}
	return 0;	/* timeout defined */
}

/*
 * Add the new system event to be executed at the given time.
 */
int
add_event(tvp, func, arg)
	struct timeval *tvp;
	void (*func)(void *);
	void *arg;
{
	EVENT *ep, *prev = 0, *next = 0;
	struct timeval now, gap;

	if (!tvp) {
		gettimeofday(&now, 0);
		gap.tv_sec = 0;
		gap.tv_usec = 250000L; /* 0.25sec mean a bit later */
		tv_add(&gap, &now);
		tvp = &gap;
	}

	/*
	 * The same event in queue may cause a looping! Prevent it.
	 */
	for (ep = first_event; ep; ep = ep->next) {
		if (ep->func == func && ep->arg == arg) {
			ep->tv = *tvp;
			dprintf(("=add_event(%p/%p): modify time", func, arg));
			return 0;
		}
	}

	/*
	 * Search for first empty or last event slot.
	 */
	for (ep = first_event; ep; ep = ep->next) {
		if (!ep->func) {
			next = ep->next;
			break;
		}
		prev = ep;
	}
	if (!ep && (ep = (EVENT *)malloc(sizeof(EVENT))) == 0)
		return -1;
	memset(ep, 0, sizeof(EVENT));
	ep->tv = *tvp;
	ep->func = func;
	ep->arg = arg;
	if (next) ep->next = next;
	else if (prev) prev->next = ep;
	if (!first_event) first_event = ep;

#ifdef	notdef
	{
		char at_time[50];
		strftime(at_time, sizeof(at_time), "%T",
			 localtime((time_t *)&ep->tv.tv_sec));
		dprintf(("+add_event(%p/%p): schedule=%s.%03d",
			 func, arg, at_time, (int)(tvp->tv_usec / 1000)));
	}
#endif
	return 0;
}

/*
 * Remove system event from queue if any.
 */
int
remove_event(func, arg)
	void (*func)(void *);
	void *arg;
{
	int found = 0;
	EVENT *ep;

	for (ep = first_event; ep; ep = ep->next) {
		if ((!func || ep->func == func) && ep->arg == arg) {
			ep->func = 0;
			found++;
		}
	}
	return found;
}

/*
 * Modify existing system event in queue for the new function argument.
 */
int
change_event(func, arg, new_arg)
	void (*func)(void *);
	void *arg, *new_arg;
{
	int found = 0;
	EVENT *ep;

	for (ep = first_event; ep; ep = ep->next) {
		if ((!func || ep->func == func) && ep->arg == arg) {
			ep->arg = new_arg;
			found++;
		}
	}
	return found;
}

EVENT *
find_event(func, arg)
	void (*func)(void *);
	void *arg;
{
	EVENT *ep;

	for (ep = first_event; ep; ep = ep->next) {
		if (ep->func == func && ep->arg == arg)
			return ep;
	}
	return 0;
}

void
free_events()
{
	EVENT *ep, *next;

	ep = first_event;
	while (ep) {
		next = ep->next;
		free(ep);
		ep = next;
	}
	first_event = 0;
}
