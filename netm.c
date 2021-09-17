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
#include "tcptrace.h"
static char const GCC_UNUSED copyright[] =
    "@(#)Copyright (c) 2004 -- Ohio University.\n";
static char const GCC_UNUSED rcsid[] =
    "@(#)$Header: /usr/local/cvs/tcptrace/netm.c,v 5.6 2003/11/19 14:38:03 sdo Exp $";


/* 
 * netm.c - NetMetrix specific file reading stuff
 */




#ifdef GROK_NETM

#define NETM_DUMP_OFFSET 0x1000

/* Defining SYS_STDIN which is fp for Windows and stdin for all other systems */
#ifdef __WIN32
static FILE *fp;
#define SYS_STDIN fp
#else
#define SYS_STDIN stdin
#endif /* __WIN32 */

/* netm file header format */
struct netm_header {
	int	netm_key;
	int	version;
};
#define NETM_VERSION_OLD 3
#define NETM_VERSION_NEW 4
#define NETM_KEY 0x6476


/* netm packet header format */
struct netm_packet_header_old {
    int	unused1;
    int	unused2;
    int	tstamp_secs;
    int	tstamp_usecs;
    int	tlen;
    int	len;
};
struct netm_packet_header {
    int	unused1;
    int	tstamp_secs;
    int	tstamp_usecs;
    int	unused2;
    int	unused3;
    int	len;
    int	tlen;  /* truncated length */
    int	unused5;
};


/* netm packet header format */

int netm_oldversion;


/* static buffers for reading */
static struct ether_header *pep;
static int *pip_buf;


/* currently only works for ETHERNET */
static int
pread_netm(
    struct timespec	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip,
    void		**pplast)
{
    int packlen;
    int rlen;
    struct netm_packet_header hdr;
    int len;
    int hlen;

    while (1) {
	hlen = netm_oldversion?
	    (sizeof(struct netm_packet_header_old)):
	    (sizeof(struct netm_packet_header));

	/* read the netm packet header */
	if ((rlen=fread(&hdr,1,hlen,SYS_STDIN)) != hlen) {
	    if (rlen != 0)
		fprintf(stderr,"Bad netm header\n");
	    return(0);
	}

	packlen = ntohl(hdr.tlen);
	/* round up to multiple of 4 bytes */
	len = (packlen + 3) & ~0x3;

	/* read the ethernet header */
	rlen=fread(pep,1,sizeof(struct ether_header),SYS_STDIN);
	if (rlen != sizeof(struct ether_header)) {
	    fprintf(stderr,"Couldn't read ether header\n");
	    return(0);
	}

	/* read the rest of the packet */
	len -= sizeof(struct ether_header);
	if (len >= IP_MAXPACKET) {
	    /* sanity check */
	    fprintf(stderr,
		    "pread_netm: invalid next packet, IP len is %d, return EOF\n", len);
	    return(0);
	}
	if ((rlen=fread(pip_buf,1,len,SYS_STDIN)) != len) {
	    if (rlen != 0)
		if (debug)
		    fprintf(stderr,
			    "Couldn't read %d more bytes, skipping last packet\n",
			    len);
	    return(0);
	}

	if (netm_oldversion) {
	    void *ptr;
	    struct netm_packet_header_old *pho;
	  
	    ptr=&hdr;
	    pho = (struct netm_packet_header_old *) ptr;

	    ptime->tv_sec  = ntohl(pho->tstamp_secs);
	    ptime->tv_nsec = 1000 * ntohl(pho->tstamp_usecs);
	    *plen          = ntohl(pho->len);
	    *ptlen         = ntohl(pho->tlen);
	} else {
	    ptime->tv_sec  = ntohl(hdr.tstamp_secs);
	    ptime->tv_nsec = 1000 * ntohl(hdr.tstamp_usecs);
	    *plen          = ntohl(hdr.len);
	    *ptlen         = ntohl(hdr.tlen);
	}


	*ppip  = (struct ip *) pip_buf;
	*pplast = (char *)pip_buf+packlen-sizeof(struct ether_header)-1; /* last byte in the IP packet */
	*pphys  = pep;
	*pphystype = PHYS_ETHER;


	/* if it's not IP, then skip it */
	if ((ntohs(pep->ether_type) != ETHERTYPE_IP) &&
	    (ntohs(pep->ether_type) != ETHERTYPE_IPV6)) {
	    if (debug > 2)
		fprintf(stderr,"pread_netm: not an IP packet\n");
	    continue;
	}

	return(1);
    }
}



/* is the input file a NetMetrix format file?? */
pread_f *is_netm(char *filename)
{
    struct netm_header nhdr;
    int rlen;
   
#ifdef __WIN32
    if((fp = fopen(filename, "r")) == NULL) {
       perror(filename);
       exit(-1);
    }
#endif /* __WIN32 */   

    /* read the netm file header */
    if ((rlen=fread(&nhdr,1,sizeof(nhdr),SYS_STDIN)) != sizeof(nhdr)) {
	rewind(SYS_STDIN);
	return(NULL);
    }
    rewind(SYS_STDIN);

    /* convert to local byte order */
    nhdr.netm_key = ntohl(nhdr.netm_key);
    nhdr.version = ntohl(nhdr.version);

    /* check for NETM */
    if (nhdr.netm_key != NETM_KEY) {
	return(NULL);
    }


    /* check version */
    if (nhdr.version == NETM_VERSION_OLD)
	netm_oldversion = 1;
    else if (nhdr.version == NETM_VERSION_NEW)
	netm_oldversion = 0;
    else {
	fprintf(stderr,"Bad NETM file header version: %d\n",
		nhdr.version);
	return(NULL);
    }

    if (debug)
	printf("NETM file version: %d\n", nhdr.version);

    /* ignore the header at the top */
    if (fseek(SYS_STDIN,NETM_DUMP_OFFSET,SEEK_SET) == -1) {
	perror("NETM lseek");
	exit(-1);
    }

    /* OK, it's mine.  Init some stuff */
    pep = MallocZ(sizeof(struct ether_header));
    pip_buf = MallocZ(IP_MAXPACKET);
    

    return(pread_netm);
}

#endif /* GROK_NETM */

