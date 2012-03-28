/*
 *	Copyright (c) 2003 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifndef	_EVENTS_H_
#define	_EVENTS_H_

#include <sys/types.h>
#include <sys/time.h>

/*
 * Event scheduler.
 */

typedef struct event_ent {
	struct timeval tv;	/* system time in [micro]seconds from UTC */
	void (*func)(void *);	/* function to call at the time */
	void *arg;		/* function argument pointer */

        struct event_ent *next;
} EVENT;

/*
 * Subtract or add two timeval structs:
 * out = out - in
 * out = out + in
 * result always greater 0.
 */
void tv_sub(struct timeval *out, const struct timeval *in);
void tv_add(struct timeval *out, const struct timeval *in);

/*
 * Round timeval to seconds.
 */
u_long tv_round(const struct timeval *tvp);

/*
 * Return difference of time in milliseconds.
 */
u_long tv_diff(const struct timeval *tvp1, const struct timeval *tvp2);

/*
 * Shift the time to be sharp at (12am + N * period), local time.
 */
void tv_sharp(struct timeval *tvp, int period);

/*
 * Execute pending event and schedule the next nearest.
 * Return 0 if timeval was modified.
 */
int select_event(struct timeval *tvp);

/*
 * Add the new system event (or modify) to be executed at the given time.
 * Return 0 on success, -1 for error.
 */
int add_event(struct timeval *tvp, void (*func)(void *), void *arg);

/*
 * Remove system event from queue if any.
 * Null func pointer may be used as wildcard ANY.
 * Return number of removed events.
 */
int remove_event(void (*func)(void *), void *arg);

/*
 * Modify existing system event in queue for the new function argument.
 * Null func pointer may be used as wildcard ANY.
 * Return number of removed events.
 */
int change_event(void (*func)(void *), void *arg, void *new_arg);

EVENT *find_event(void (*func)(void *), void *arg);

/*
 * Clear/free all system events.
 */
void free_events();

#endif	/* _EVENTS_H_ */
