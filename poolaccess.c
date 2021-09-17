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
static char const GCC_UNUSED copyright[] =
    "@(#)Copyright (c) 2004 -- Ohio University.\n";
static char const GCC_UNUSED rcsid[] =
    "@(#)$Header: /usr/local/cvs/tcptrace/poolaccess.c,v 5.5 2003/11/19 14:38:04 sdo Exp $";


static long tcp_pair_pool = -1;
static long udp_pair_pool = -1;
static long seqspace_pool = -1;
static long ptp_snap_pool = -1;
static long ptp_ptr_pool  = -1;
static long segment_pool  = -1;
static long quadrant_pool = -1;

tcp_pair *
MakeTcpPair(
	    void)
{
  tcp_pair	*ptr = NULL;

  if (tcp_pair_pool < 0) {
    tcp_pair_pool = MakeMemPool(sizeof(tcp_pair), 0);
  }
  
  ptr = PoolMalloc(tcp_pair_pool, sizeof(tcp_pair));
  return ptr;
}

void
FreeTcpPair(
	    tcp_pair *ptr)
{
  PoolFree(tcp_pair_pool, ptr);
}

udp_pair *
MakeUdpPair(
	    void)
{
  udp_pair	*ptr = NULL;

  if (udp_pair_pool < 0) {
    udp_pair_pool = MakeMemPool(sizeof(udp_pair), 0);
  }
  
  ptr = PoolMalloc(udp_pair_pool, sizeof(udp_pair));
  return ptr;
}

void
FreeUdpPair(
	    udp_pair *ptr)
{
  PoolFree(udp_pair_pool, ptr);
}

seqspace *
MakeSeqspace(
	     void)
{
  seqspace	*ptr = NULL;

  if (seqspace_pool < 0) {
    seqspace_pool = MakeMemPool(sizeof(seqspace), 0);
  }
  
  ptr = PoolMalloc(seqspace_pool, sizeof(seqspace));
  return ptr;
}

void
FreeSeqspace(
	     seqspace *ptr)
{
  PoolFree(seqspace_pool, ptr);
}

ptp_snap *
MakePtpSnap(
	    void)
{
  ptp_snap	*ptr = NULL;

  if (ptp_snap_pool < 0) {
    ptp_snap_pool = MakeMemPool(sizeof(ptp_snap), 0);
  }
  
  ptr = PoolMalloc(ptp_snap_pool, sizeof(ptp_snap));
  return ptr;
}

void
FreePtpSnap(
	    ptp_snap *ptr)
{
  PoolFree(ptp_snap_pool, ptr);
}

ptp_ptr *
MakePtpPtr(
	   void)
{
  ptp_ptr	*ptr = NULL;

  if (ptp_ptr_pool < 0) {
    ptp_ptr_pool = MakeMemPool(sizeof(ptp_ptr), 0);
  }
  
  ptr = PoolMalloc(ptp_ptr_pool, sizeof(ptp_ptr));
  return ptr;
}

void
FreePtpPtr(
	   ptp_ptr *ptr)
{
  PoolFree(ptp_ptr_pool, ptr);
}

segment *
MakeSegment(
	    void)
{
  segment	*ptr = NULL;

  if (segment_pool < 0) {
    segment_pool = MakeMemPool(sizeof(segment), 0);
  }
  
  ptr = PoolMalloc(segment_pool, sizeof(segment));
  return ptr;
}

void
FreeSegment(
	    segment *ptr)
{
  PoolFree(segment_pool, ptr);
}

quadrant *
MakeQuadrant(
	     void)
{
  quadrant	*ptr = NULL;

  if (quadrant_pool < 0) {
    quadrant_pool = MakeMemPool(sizeof(quadrant), 0);
  }
  
  ptr = PoolMalloc(quadrant_pool, sizeof(quadrant));
  return ptr;
}

void
FreeQuadrant(
	     quadrant *ptr)
{
  PoolFree(quadrant_pool, ptr);
}
