/*
 *	Copyright (c) 2003 Rinet Corp., Novosibirsk, Russia
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * THIS SOURCE CODE IS PROVIDED ``AS IS'' WITHOUT ANY WARRANTIES OF ANY KIND.
 */

#ifndef	_CISCO_NETFLOW_H_
#define	_CISCO_NETFLOW_H_

#include <sys/types.h>

#define	CNF_PORT	9995	/* collector UDP port by default */

/*
 * Cisco Netflow packets format

 */
/*
 * Version 1 Header Format
 */
typedef	struct cnf_hdr_v1 {
	u_int16_t	version;	/* version number=1 */
	u_int16_t	counter;	/* number of exported flows (1-24) */
	u_int32_t	sysuptime;	/* milliseconds since router booted */
	u_int32_t	unix_secs;	/* current seconds since UTC */
	u_int32_t	unix_nsecs;	/* current nanoseconds since UTC */
} CNF_HDR_V1;

/*
 * Version 1 Flow Record Format
 */
typedef	struct cnf_data_v1 {
	u_int32_t	src_addr;	/* source IP address */
	u_int32_t	dst_addr;	/* destination IP address */
	u_int32_t	nexthop;	/* next hop router's IP address */
	u_int16_t	ifin;		/* input interface's SNMP index */
	u_int16_t	ifout;		/* output interface's SNMP index */
	u_int32_t	dpkts;		/* packets in the flow */
	u_int32_t	doctets;	/* total number of L3 bytes */
	u_int32_t	firsttime;	/* sysuptime at start of flow */
	u_int32_t	lasttime;	/* sysuptime at last packet of flow */
	u_int16_t	src_port;	/* source port number */
	u_int16_t	dst_port;	/* destination port number */
	u_int16_t	pad1;		/* unused (zero) bytes */
	u_int8_t	proto;		/* IP protocol */
	u_int8_t	tos;		/* type of service */
	u_int8_t	flags;		/* cumulative OR of TCP flags */
	u_int8_t	tcp_retx_cnt;	/* Number of mis-sequenced packets with delay >1sec */
	u_int8_t	tcp_retx_secs;	/* Cumulative seconds between mis-sequenced packets */
	u_int8_t	tcp_misseq_cnt;	/* Number of mis-sequenced packets seen */
	u_int8_t	reserved[4];	/* unused (zero) bytes */
} CNF_DATA_V1;

/*
 * Version 5 Header Format
 */
typedef	struct cnf_hdr_v5 {
	u_int16_t	version;	/* version number=5 */
	u_int16_t	counter;	/* number of exported flows (1-30) */
	u_int32_t	sysuptime;	/* milliseconds since router booted */
	u_int32_t	unix_secs;	/* current seconds since UTC */
	u_int32_t	unix_nsecs;	/* current nanoseconds since UTC */
	u_int32_t	sequence;	/* sequence counter of total flows seen */
	u_int8_t	engine_type;	/* switching engine type (RP,VIP) */
	u_int8_t	engine_id;	/* switching engine slot number */
	u_int16_t	sampling_interval; /* see bellow */
/*
 * Sampling mode and the sampling interval information.
 * The first two bits of this field indicates the sampling mode:
 *   00 = No sampling mode is configured
 *   01 = `Packet Interval' sampling mode is configured.
 *        (One of every x packet is selected and placed in the NetFlow cache).
 *   10 = Reserved
 *   11 = Reserved
 * The remaining 14 bits hold the value of the sampling interval.
 * The sampling interval can have any value in the range of 10 to 16382
 * (for example, 0x000A to 0x3FFE).
 */
} CNF_HDR_V5;

/*
 * Version 5 Flow Record Format
 */
typedef	struct cnf_data_v5 {
	u_int32_t	src_addr;	/* source IP address */
	u_int32_t	dst_addr;	/* destination IP address */
	u_int32_t	nexthop;	/* next hop router's IP address */
	u_int16_t	ifin;		/* input interface's SNMP index */
	u_int16_t	ifout;		/* output interface's SNMP index */
	u_int32_t	dpkts;		/* packets in the flow */
	u_int32_t	doctets;	/* total number of L3 bytes */
	u_int32_t	firsttime;	/* sysuptime at start of flow */
	u_int32_t	lasttime;	/* sysuptime at last packet of flow */
	u_int16_t	src_port;	/* source port number */
	u_int16_t	dst_port;	/* destination port number */
	u_int8_t	pad1;		/* unused (zero) byte */
	u_int8_t	flags;		/* cumulative OR of TCP flags */
	u_int8_t	proto;		/* IP protocol */
	u_int8_t	tos;		/* type of service */
	u_int16_t	src_as;		/* AS of the source (origin or peer) */
	u_int16_t	dst_as;		/* AS of the destination */
	u_int8_t	src_mask;	/* source address prefix mask bits */
	u_int8_t	dst_mask;	/* dest address prefix mask bits */
	u_int16_t	pad2;		/* unused (zero) bytes */
} CNF_DATA_V5;

/*
 * Version 7 Header Format
 */
typedef	struct cnf_hdr_v7 {
	u_int16_t	version;	/* version number=7 */
	u_int16_t	counter;	/* number of exported flows (1-27) */
	u_int32_t	sysuptime;	/* milliseconds since router booted */
	u_int32_t	unix_secs;	/* current seconds since UTC */
	u_int32_t	unix_nsecs;	/* current nanoseconds since UTC */
	u_int32_t	sequence;	/* sequence counter of total flows */
	u_int32_t	reserved;	/* unused (zero) bytes */
} CNF_HDR_V7;

/*
 * Version 7 Flow Record Format
 */
typedef	struct cnf_data_v7 {
	u_int32_t	src_addr;	/* source IP address */
	u_int32_t	dst_addr;	/* destination IP address */
	u_int32_t	nexthop;	/* next hop router's IP address */
	u_int16_t	ifin;		/* input interface's SNMP index */
	u_int16_t	ifout;		/* output interface's SNMP index */
	u_int32_t	dpkts;		/* packets in the flow */
	u_int32_t	doctets;	/* total number of L3 bytes */
	u_int32_t	firsttime;	/* sysuptime at start of flow */
	u_int32_t	lasttime;	/* sysuptime at last packet of flow */
	u_int16_t	src_port;	/* source port number */
	u_int16_t	dst_port;	/* destination port number */
	u_int8_t	pad1;		/* unused (zero) byte */
	u_int8_t	flags;		/* cumulative OR of TCP flags */
	u_int8_t	proto;		/* IP protocol */
	u_int8_t	tos;		/* type of service */
	u_int32_t	src_as;		/* AS of the source (origin of peer) */
	u_int32_t	dst_as;		/* AS of the destination */
	u_int8_t	src_mask;	/* source address prefix mask bits */
	u_int8_t	dst_mask;	/* dest address prefix mask bits */
	u_int16_t	pad2;		/* unused (zero) bytes */
	u_int32_t	router_sc;	/* router which is shortcut by switch */
} CNF_DATA_V7;

struct pcap_handler;
int cisco_netflow_init(struct pcap_handler **ph_list, int port);

#endif	/* !_CISCO_NETFLOW_H_ */
