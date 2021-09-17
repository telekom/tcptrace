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
 * Author:	Marina Bykova
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		http://www.tcptrace.org/
 */
#include "tcptrace.h"
static char const GCC_UNUSED rcsid[] =
    "@(#)$Header: /usr/local/cvs/tcptrace/mod_realtime.c,v 5.7 2003/11/19 14:38:03 sdo Exp $";

#ifdef LOAD_MODULE_REALTIME

#include <sys/types.h>
#include "mod_realtime.h"

/* info kept for all traced packets */
struct realtime_conn_info {
  timespec	first_time;	/* time of the connection's first packet */
  timespec	last_time;	/* time of the connection's last packet */
  Bool		is_closed;	/* is the connection has been closed? */
  Bool		is_new;		/* is the connection new? */

  tcp_pair_addrblock	addr_pair;
  tcp_pair		*ptp;

  struct realtime_conn_info *prev; /* pointer to the prev connection */
  struct realtime_conn_info *next; /* pointer to the next connection */
}; 

typedef struct realtime_conn_info rtconn;

struct realtime_info {
  timespec        last_scheduled_time;	/* time of the last network statistics  */
                                        /* as it would appear in the ideal case */
  timespec        last_actual_time;	/* time of the last network statistics  */
                                        /* when it actually happened            */
  rtconn         *conn_head;		/* head of the list of tcp connections */
  rtconn         *conn_tail;		/* tail of the list of tcp connections */

  u_long        open_conns;		/* number of new connections within the 
				   	   time interval */
  u_long        total_conns;		/* number of currect active connections */
};

typedef struct realtime_info rtinfo;

struct protocol {
  u_char ip_p;
  u_llong count;
  struct protocol *next;
};

const static int realtime_update_interval = 60;

/* global variables */
static rtinfo *mod_info;

static u_llong tcp_packets = 0;
static u_llong udp_packets = 0;
static u_llong nontcpudp_packets = 0;
static struct protocol *plist = NULL;

/* declarations of memory management functions for the module */
static long rtconn_pool   = -1;

static rtconn *
MakeRtconn(
	   void)
{
  rtconn *ptr = NULL;

  if (rtconn_pool < 0) {
    rtconn_pool = MakeMemPool(sizeof(rtconn), 0);
  }

  ptr = PoolMalloc(rtconn_pool, sizeof(rtconn));
  return ptr;
}

static void
FreeRtconn(
	   rtconn *ptr)
{
  PoolFree(rtconn_pool, ptr);
}


void
realtime_usage(void)
{
  printf("\t-xrealtime\tan example module showing how to use real-time tcptrace\n");
}

int
realtime_init(
	      int argc,
	      char *argv[])
{
  int		i;
  int		enable = 0;

  /* look for "-xrealtime" */
  for (i = 1; i < argc; ++i) {
    if (!argv[i])
      continue;  /* argument already taken by another module... */

    if (strncmp(argv[i],"-x", 2) == 0) {
      if (strncasecmp(argv[i] + 2, "realtime", 8) == 0) {
	/* I want to be called */
	enable = 1;
	fprintf(stderr, "mod_realtime: Capturing traffic\n");
	argv[i] = NULL;
      }
    }
  }

  if (!enable)
    return(0);	/* don't call me again */

  mod_info = (rtinfo *)malloc(sizeof(rtinfo));
  mod_info->last_scheduled_time = current_time;
  mod_info->last_actual_time = current_time;
  mod_info->conn_head = NULL;
  mod_info->conn_tail = NULL;
  mod_info->open_conns = 0;
  mod_info->total_conns = 0;

  /* DNS lookups are time expensive, we want to disable them in real-time 
     module */
  resolve_ipaddresses = FALSE;
  resolve_ports = FALSE;

  /* we want to run the program in real-time mode */
  run_continuously = TRUE;

  /* if you want to set a threshold on the number of connections the program
   * stores, uncomment this with and modify depending on your needs (must be
   * different for different monitoring points) */
  /* conn_num_threshold = TRUE;
     update_interval = 60;
     max_conn_num = 20000;
   */
  
  do_udp = TRUE;

  return(1);	/* TRUE means call other realtime routines later */
}

void
realtime_done(void)
{
  struct protocol *pp;
 
  fprintf(stdout, "\nrealtime: TCP packets - %" FS_ULL "\n", tcp_packets);
  fprintf(stdout, "realtime: UDP packets - %" FS_ULL "\n", udp_packets);
  fprintf(stdout, "realtime: other packets - %" FS_ULL "\n", nontcpudp_packets);

  for (pp = plist; pp; pp = pp->next)
   fprintf(stdout, "\tprotocol: %3u, number: %" FS_ULL "\n", pp->ip_p, pp->count);

  fprintf(stdout, "\n");
}

void *
realtime_newconn( 
		 tcp_pair *ptp)
{
   rtconn *new_conn = MakeRtconn();
   
   if (mod_info->last_scheduled_time.tv_sec == 0) {
      mod_info->last_scheduled_time = current_time;
      mod_info->last_actual_time = current_time;
   }
   
   new_conn->first_time = current_time;
   new_conn->last_time = current_time;
   new_conn->is_new = TRUE;
   new_conn->is_closed = FALSE;
   new_conn->addr_pair = ptp->addr_pair;
   new_conn->ptp = ptp;
   new_conn->next = NULL;
   new_conn->prev = NULL;
   
   if (mod_info->conn_head != NULL) {
      mod_info->conn_tail->next = new_conn;
      new_conn->prev = mod_info->conn_tail;
      mod_info->conn_tail = new_conn;
   }
   else { /* the list is empty */
      mod_info->conn_head = new_conn;
      mod_info->conn_tail = new_conn;
   }
   mod_info->total_conns++;
   mod_info->open_conns++;
   
   return new_conn;
}

void
realtime_deleteconn(
		    tcp_pair *ptp,	/* info I have about this connection */
		    void *mod_data)	/* module specific info for this conn*/
{
  rtconn *conn = mod_data;
  Bool   done = FALSE;

  if (!conn->is_closed)
    mod_info->open_conns--;

  if (conn == mod_info->conn_head) {
    mod_info->conn_head = mod_info->conn_head->next;
    if (mod_info->conn_head) {
      mod_info->conn_head->prev = NULL;
    }
    done = TRUE;
  }
  if (conn == mod_info->conn_tail) {
    mod_info->conn_tail = mod_info->conn_tail->prev;
    if (mod_info->conn_tail) {
      mod_info->conn_tail->next = NULL;
    }
    done = TRUE;
  }
  if (!done) {
    conn->prev->next = conn->next;
    conn->next->prev = conn->prev;
  }

  FreeRtconn(conn);
  return;
}

void
realtime_read(
	      struct ip *pip,	/* the packet */
	      tcp_pair *ptp,	/* info I have about this connection */
	      void *plast,	/* past byte in the packet */
	      void *mod_data)	/* module specific info for this connection */
{
  rtconn	*conn = mod_data;
  double 	dtime = 0;
  
  ++tcp_packets;

  /* first, discard any connections that we aren't interested in. */
  /* That means that pmodstruct is NULL */
  if (conn == NULL) {
    return;
  }

  if (conn->is_new) {
    dtime = current_time.tv_sec + (current_time.tv_nsec / 1000000000.0);
    fprintf(stdout, "%.6f  %s\t%s new connection\n",
	    dtime, ptp->a_endpoint, ptp->b_endpoint);
    conn->is_new = FALSE;
  }

  conn->last_time = current_time;
   
  if (!conn->is_closed) {
    if ((FinCount(ptp) >= 1) || (ConnReset(ptp))) {
      if (dtime == 0) {
	dtime = current_time.tv_sec + (current_time.tv_nsec / 1000000000.0);
      }
      fprintf(stdout, "%.6f  %s\t%s connection closes (had %" FS_ULL " packets)\n",
	      dtime, ptp->a_endpoint, ptp->b_endpoint, ptp->packets);
      conn->is_closed = TRUE;
      mod_info->open_conns--;
    }
  }

  if ((elapsed(mod_info->last_scheduled_time, current_time) / 1000000000.0) >= 
       realtime_update_interval) {
      if (dtime == 0) {
	dtime = current_time.tv_sec + (current_time.tv_nsec / 1000000000.0);
      }
     fprintf(stdout, "%.6f  number of open connections is %lu\n", 
	     dtime, mod_info->open_conns);
     mod_info->last_scheduled_time.tv_sec += realtime_update_interval;
     mod_info->last_actual_time = current_time;
  }
}

void 
realtime_udp_read(
		  struct ip *pip, 
		  udp_pair *pup, 
		  void *plast, 
		  void *pmodstruct)
{
  ++udp_packets;
}

void
realtime_nontcpudp_read(
			struct ip *pip, 
			void *plast)
{
  struct protocol *last = NULL;
  struct protocol *current; 

  ++nontcpudp_packets;
   
  if (plist == NULL) {
    plist = (struct protocol *)MallocZ(sizeof(struct protocol));
    current = plist;
    current->count = 1;
    current->next = NULL;
    current->ip_p = pip->ip_p;
    last = current;
  }
  else {
    for (current = plist; current; current = current->next) {
      if (current->ip_p == pip->ip_p) {
	current->count++;
        break;
      }
      else {
        last = current;
      }
    }
    if (current == NULL) { /* protocol is not on our list yet */
      current = (struct protocol *)MallocZ(sizeof(struct protocol));
      current->ip_p = pip->ip_p;
      current->count = 1;
      current->next = NULL;
      last->next = current;
      last = current;
    }
  }
}

#endif /* LOAD_MODULE_REALTIME */


