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
#ifndef _POOL_H
#define _POOL_H
static char const GCC_UNUSED rcsid_pool[] =
    "@(#)$Header: /usr/local/cvs/tcptrace/pool.h,v 5.4 2003/11/19 14:38:08 sdo Exp $";

extern int debug;

int MakeMemPool(const unsigned bsize, const int sorted);

void *PoolMalloc(const int poolid, const unsigned bytes);

void PoolFree(const int poolid, void *prt);

#endif

