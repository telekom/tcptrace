/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001,
 *               2002, 2003, 2004
 *	Ohio University.
 *
 * ---
 * 
 * Starting with the release of tcptrace version 6 in 2001, tcptrace
 * is licensed under the GNU General Public License (GPL).  We believe
 * that, among the available licenses, the GPL will do the best job of
 * allowing tcptrace to continue to be a valuable, freely-available
 * and well-maintained tool for the networking community.
 *
 * Previous versions of tcptrace were released under a license that
 * was much less restrictive with respect to how tcptrace could be
 * used in commercial products.  Because of this, I am willing to
 * consider alternate license arrangements as allowed in Section 10 of
 * the GNU GPL.  Before I would consider licensing tcptrace under an
 * alternate agreement with a particular individual or company,
 * however, I would have to be convinced that such an alternative
 * would be to the greater benefit of the networking community.
 * 
 * ---
 *
 * This file is part of Tcptrace.
 *
 * Tcptrace was originally written and continues to be maintained by
 * Shawn Ostermann with the help of a group of devoted students and
 * users (see the file 'THANKS').  The work on tcptrace has been made
 * possible over the years through the generous support of NASA GRC,
 * the National Science Foundation, and Sun Microsystems.
 *
 * Tcptrace is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Tcptrace is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tcptrace (in the file 'COPYING'); if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 * 
 * Author:	Shawn Ostermann
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		ostermann@cs.ohiou.edu
 *		http://www.tcptrace.org/
 */
static char const GCC_UNUSED rcsid_filter_vars[] =
    "@(#)$Header: /usr/local/cvs/tcptrace/filter_vars.h,v 5.11 2003/11/19 14:38:07 sdo Exp $";


/* just a big table of things that we can filter on */
static tcp_pair ptp_dummy;
#define PTCB_C_S(field) &ptp_dummy.a2b.field,&ptp_dummy.b2a.field
#define PTP(a,b)	&ptp_dummy.a,&ptp_dummy.b
#define PTPA(a,b)	&ptp_dummy.addr_pair.a,&ptp_dummy.addr_pair.b
struct filter_line filters[] = {
    {"hostname",	V_STRING, PTP(a_hostname,b_hostname),"FQDN host name (unless -n)"},
    {"portname",	V_STRING, PTP(a_portname,b_portname),"service name of the port (unless -n)"},
    {"port",		V_USHORT, PTPA(a_port,b_port),"port NUMBER"},

    {"mss",		V_INT,	PTCB_C_S(mss),"maximum segment size"},
    {"f1323_ws",	V_BOOL,	PTCB_C_S(f1323_ws),"1323 window scaling requested"},
    {"f1323_ts",	V_BOOL,	PTCB_C_S(f1323_ts),"1323 time stampts requested"},
    {"fsack_req",	V_BOOL,	PTCB_C_S(fsack_req),"SACKs requested"},
    {"window_scale",	V_BOOL,	PTCB_C_S(window_scale),"window scale factor"},
    {"bad_behavior",	V_BOOL,	PTCB_C_S(bad_behavior),"bad TCP behavior"},

    {"data_bytes",	V_ULLONG, PTCB_C_S(data_bytes),"bytes of data"},
    {"data_segs",	V_ULLONG, PTCB_C_S(data_pkts),"segments of data"},
    {"data_segs_push",	V_ULLONG, PTCB_C_S(data_pkts_push),"segments with PUSH set"},
    {"unique_bytes",	V_ULLONG, PTCB_C_S(unique_bytes),"non-retransmitted bytes"},
    {"rexmit_bytes",	V_ULLONG, PTCB_C_S(rexmit_bytes),"retransmitted bytes"},
    {"rexmit_segs",	V_ULLONG, PTCB_C_S(rexmit_pkts),"segments w/ retransmitted data"},
    {"ack_segs",	V_ULLONG, PTCB_C_S(ack_pkts),"segments containing ACK"},
    {"pureack_segs",	V_ULLONG, PTCB_C_S(pureack_pkts),"segments containing PURE ACK (no data/syn/fin/reset)"},
    {"win_max",		V_ULONG,  PTCB_C_S(win_max),"MAX window advertisement"},
    {"win_min",		V_ULONG,  PTCB_C_S(win_min),"MIN window advertisement"},
    {"win_zero_ct",	V_ULONG,  PTCB_C_S(win_zero_ct),"number of ZERO windows advertised"},
    {"min_seq",		V_ULONG,  PTCB_C_S(min_seq),"smallest sequence number"},
    {"max_seq",		V_ULONG,  PTCB_C_S(max_seq),"largest sequence number"},
    {"num_sacks",	V_ULONG,  PTCB_C_S(num_sacks),"number of ACKs carrying SACKs"},
    {"max_sacks",	V_ULONG,  PTCB_C_S(max_sack_blocks),"most SACK blocks in a single ACK"},

    /* synonyms */
    {"segs",		V_ULLONG, PTCB_C_S(packets),"total segments"},
    {"packets",		V_ULLONG, PTCB_C_S(packets),"total segments"},

    {"syn_count",	V_UCHAR,  PTCB_C_S(syn_count),"SYNs sent"},
    {"fin_count",	V_UCHAR,  PTCB_C_S(fin_count),"FINs sent"},
    {"reset_count",	V_UCHAR,  PTCB_C_S(reset_count),"RESETs sent"},
    {"min_seg_size",	V_ULONG,  PTCB_C_S(min_seg_size),"smallest amount of data in a segment (not 0)"},
    {"max_seg_size",	V_ULONG,  PTCB_C_S(max_seg_size),"largest amount of data in a segment"},
    {"out_order_segs",	V_ULLONG, PTCB_C_S(out_order_pkts),"out of order segments"},
    {"sacks_sent",	V_ULLONG, PTCB_C_S(sacks_sent),"SACKs sent"},
    {"ipv6_segs",	V_ULONG,  PTCB_C_S(ipv6_segments),"number of IPv6 segments sent"},
    {"max_idle",	V_ULLONG, PTCB_C_S(idle_max),"maximum idle time (usecs)"},

    {"num_hw_dups",     V_ULONG,  PTCB_C_S(num_hardware_dups),"number of hardware-level duplicates"},

    {"initwin_bytes",   V_ULONG,  PTCB_C_S(initialwin_bytes),"number of bytes in initial window"},
    {"initwin_segs",    V_ULONG,  PTCB_C_S(initialwin_segs),"number of segments in initial window"},

    {"rtt_min",         V_ULONG, PTCB_C_S(rtt_min), "MIN round trip time (usecs)"},
    {"rtt_max",         V_ULONG, PTCB_C_S(rtt_max), "MAX round trip time (usecs)"},
    {"rtt_count",       V_ULONG, PTCB_C_S(rtt_count), "number of RTT samples"},

    {"rtt_min_last",    V_ULONG, PTCB_C_S(rtt_min_last), "MIN round trip time (usecs) (from last rexmit)"},
    {"rtt_max_last",    V_ULONG, PTCB_C_S(rtt_max_last), "MAX round trip time (usecs) (from last rexmit)"},
    {"rtt_count_last",  V_ULONG, PTCB_C_S(rtt_count_last), "number of RTT samples (from last rexmit)"},

    {"rtt_amback",      V_ULLONG, PTCB_C_S(rtt_amback), "number of ambiguous ACKs"},
    {"rtt_cumack",      V_ULLONG, PTCB_C_S(rtt_cumack), "number of cumulative ACKs"},
    {"rtt_unkack",      V_ULLONG, PTCB_C_S(rtt_unkack), "number of unknown ACKs"},
    {"rtt_dupack",      V_ULLONG, PTCB_C_S(rtt_dupack), "number of duplicate ACKs"},
    {"rtt_nosample",    V_ULLONG, PTCB_C_S(rtt_nosample), "ACKs that generate no valid RTT sample"},
    {"rtt_triple_dupack", V_ULLONG, PTCB_C_S(rtt_triple_dupack), "number of triple duplicate ACKs (fast rexmit)"},

    {"retr_max",        V_ULONG, PTCB_C_S(retr_max), "MAX rexmits of a single segment"},
    {"retr_min_tm",     V_ULONG, PTCB_C_S(retr_min_tm), "MIN time until rexmit (usecs)"},
    {"retr_max_tm",     V_ULONG, PTCB_C_S(retr_max_tm), "MAX time until rexmit (usecs)"},

    {"trunc_bytes",	V_ULLONG, PTCB_C_S(trunc_bytes), "number of bytes not in the file"},
    {"trunc_segs", 	V_ULLONG, PTCB_C_S(trunc_segs), "number of segments not in the file"},
    {"num_zwnd_probes", V_ULONG, PTCB_C_S(num_zwnd_probes), "number of zero window probes"},
    {"zwnd_probe_bytes", V_ULONG, PTCB_C_S(zwnd_probe_bytes), "number of window probe bytes"},
   
    {"urg_data_pkts", V_ULONG, PTCB_C_S(urg_data_pkts), "Number of packets with URGENT bit set"},
    {"urg_data_bytes", V_ULONG, PTCB_C_S(urg_data_bytes), "Number of bytes of urgent data"},

   /* HOST IP addresses */
    {"hostaddr",	V_IPADDR,
     PTP(addr_pair.a_address, addr_pair.b_address),
     "IP Address (v4 or v6 in standard textual notation"},

    /* computed functions */

    /* throughput in bytes/second - 0 for infinite or none */
    {"thruput",		V_UFUNC, (void *)&VFuncClntTput, (void *)&VFuncServTput, "thruput (bytes/sec)"},
};
#define NUM_FILTERS (sizeof(filters)/sizeof(struct filter_line))
