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
    "@(#)$Header: /usr/local/cvs/tcptrace/gcache.c,v 5.7 2003/11/19 14:38:02 sdo Exp $";


/*
 * gcache.c - generalized cacheing routines
 */


#include <sys/types.h>
#include "gcache.h"


/* Let's use ANSI C rather than old BSD calls... */
#ifndef bzero
#define bzero(ptr,nbytes) memset(ptr,0,nbytes)
#endif
#ifndef bcopy
#define bcopy(from_ptr,to_ptr,nbytes) memcpy(to_ptr,from_ptr,nbytes)
#endif



static int ca_enabled;


/* control block for a single cache */
enum cb_status { CB_INUSE=1, CB_FREE=2};
typedef enum cb_status cb_status;
struct cacheblk {
    cb_status	cb_status;		/* INUSE or FREE		*/
    char		cb_name[CA_NAMELEN]; /* name of the cache	*/
    u_short		cb_maxent;	/* maximum entries		*/
    u_short		cb_nument;	/* number of entries		*/
    u_short		cb_hashsize;	/* size of hash table		*/
    u_int		cb_maxlife;	/* max life of an entry (secs)	*/
    struct cacheentry *cb_cache;	/* free nodes for the cache	*/
    struct hashentry *cb_hash;		/* the hash table		*/
    tceix		cb_freelist;	/* list of free cacheentries	*/
    /* statistics variables, mostly for debugging			*/
    u_int		cb_lookups;	/* # lookups			*/
    u_int		cb_hits;	/* # hits			*/
    u_int		cb_tos;		/* # timed out entries		*/
    u_int		cb_fulls;	/* # removed, full table	*/
};



/* a single node in the hash table */
struct hashentry {
	tceix	he_ix;
};
#define NULL_PHE	((struct hashentry *) 0)
#define NULL_IX		0


/* a cached item in the hash list */
enum ce_status {CE_INUSE=11, CE_FREE=12};
typedef enum ce_status ce_status;
struct cacheentry {
    ce_status		ce_status;	/* INUSE or FREE		*/
    char		*ce_keyptr;	/* pointer to the key		*/
    tcelen		ce_keylen;	/* length of the key		*/
    char		*ce_resptr;	/* pointer to the result	*/
    tcelen		ce_reslen;	/* length of the result		*/
    thval		ce_hash;	/* value that was hashed in	*/
    ttstamp		ce_tsinsert;	/* timestamp - time inserted	*/
    ttstamp		ce_tsaccess;	/* timestamp - last access	*/
    tceix		ce_prev;	/* next entry on list		*/
    tceix		ce_next;	/* prev entry on list		*/
};
#define NULL_PCE	((struct cacheentry *) 0)


/* locally global information */
static struct cacheblk catab[CA_NUMCACHES];


/* useful macros */
#define ISBADCID(cid) ((cid < 0) || (cid > CA_NUMCACHES) || \
		       (catab[cid].cb_status != CB_INUSE))
#define HASHTOIX(hash,pcb) ((hash) % (pcb->cb_hashsize))

/* debugging hooks */
static int docadebug = 0;
static int docaerror = 1;
#define CADEBUG if (docadebug) fprintf
#define CAERROR if (docaerror) fprintf


/* local routines defns */
static char	*cagetmem(u_int);
static void	cadeleteold(struct cacheblk *);
static void	caclear(struct cacheblk *, tceix);
static void	cafreemem(void *, u_int);
static tceix	cagetfree(struct cacheblk *);
static tceix	cagetindex(struct cacheblk *, char *, tcelen, thval);
static thval	cahash(char *, tcelen);
static int	caisold(struct cacheblk *, struct cacheentry *);
static void	casetsize(struct cacheblk *, int);
static void	caunlink(struct cacheblk *, tceix);



/*************************************************************************/
/**									**/
/**	GLOBAL ROUTINES							**/
/**									**/
/*************************************************************************/

/*
 * ====================================================================
 * cainit - initialize the caching tables
 * ====================================================================
 */
int
cainit(void)
{
    struct cacheblk *pcb;
    int cid;

    for (cid=0; cid < CA_NUMCACHES; ++cid) {
	pcb = &catab[cid];
	bzero(pcb,sizeof(struct cacheblk));
	pcb->cb_status = CB_FREE;
    }
    ca_enabled = TRUE;
    return(OK);
}



/*
 * ====================================================================
 * cacreate - create a new cache
 * ====================================================================
 */
int
cacreate(
    char *name,
    int nentries,
    int lifetime)
{
    int cid;
    tceix ix;
    struct cacheblk *pcb;
    struct cacheentry *pce;

    /* check config limits */
    if (nentries >= CA_MAXENTRIES) {
	CAERROR(stderr,"cacreate(%s,%d,%d): SYSERR, nentries > max (%d)\n",
		name, nentries, lifetime, CA_MAXENTRIES);
	return(SYSERR);
    }

    for (cid=0; cid < CA_NUMCACHES; ++cid) {
	pcb = &catab[cid];
	if (pcb->cb_status == CB_FREE)
	    break;
    }

    if (cid == CA_NUMCACHES) {
	CAERROR(stderr,"cacreate(%s,%d,%d): SYSERR, no more caches\n",
		name, nentries, lifetime);
	return(SYSERR);
    }

    bzero(pcb, sizeof(struct cacheblk));
    pcb->cb_status = CB_INUSE;
#ifdef linux
#ifdef strncpy
    /* stupid Linux (redhat?) bug in macro */
#undef strncpy
#endif /* strncpy */
#endif /* linux */
    strncpy(pcb->cb_name,name,CA_NAMELEN);
    pcb->cb_name[CA_NAMELEN-1] = '\00';
    pcb->cb_maxent = nentries;
    casetsize(pcb,nentries);
    pcb->cb_maxlife = lifetime;

    /* allocate the cache entries */
    /* (0 is reserved as a null pointer, so we allocate from 0 	*/
    /*  to maxent, rather than maxent-1)				*/
    pcb->cb_cache = (struct cacheentry *)
	cagetmem((1+pcb->cb_maxent) * sizeof(struct cacheentry));
    bzero(pcb->cb_cache,
	  (1+pcb->cb_maxent) * sizeof(struct cacheentry));
    /* put them all on the free list (only forward pointers) */
    for (ix=1; ix <= pcb->cb_maxent; ++ix) {
	pce = &pcb->cb_cache[ix];
	pce->ce_status = CE_FREE;
	pce->ce_next = ix+1;
    }
    pcb->cb_cache[pcb->cb_maxent].ce_next = NULL_IX;
    pcb->cb_freelist = 1;

    /* allocate the hash table */
    pcb->cb_hash = (struct hashentry *)
	cagetmem(pcb->cb_hashsize * sizeof(struct hashentry));
    for (ix=0; ix < pcb->cb_hashsize; ++ix) {
	pcb->cb_hash[ix].he_ix = NULL_IX;
    }
	
    CADEBUG(stderr,"cacreate(%s,%d,%d) returns cache %d\n",
	    name, nentries, lifetime, cid);

    return(cid);
}



/*
 * ====================================================================
 * cadestroy - destroy an existing cache
 * ====================================================================
 */
int
cadestroy(
    int cid)
{
    struct cacheblk *pcb;

    if (ISBADCID(cid)) {
	CAERROR(stderr,"cadestroy(%d,...) cid is bad\n", cid);
	return(SYSERR);
    }

    pcb = &catab[cid];

    /* free up all the entries */
    (void) capurge(cid);

    /* free up the hash table */
    cafreemem(pcb->cb_hash,
	      pcb->cb_hashsize * sizeof(struct hashentry));

    /* free up the cached blocks */
    cafreemem(pcb->cb_cache,
	      (1+pcb->cb_maxent) * sizeof(struct cacheentry));

    /* zero out the table */
    bzero(pcb,sizeof(struct cacheblk));
    pcb->cb_status = CB_FREE;

    return(OK);
}



/*
 * ====================================================================
 * cainsert - insert a new entry into an existing cache
 * ====================================================================
 */
int
cainsert(
    int cid,
    char *pkey,
    tcelen keylen,
    char *pres,
    tcelen reslen)
{
    struct cacheblk *pcb;
    struct cacheentry *pce;
    struct hashentry *phe;
    thval hash;
    tceix ixnew;

    /* check argument validity */
    if (ISBADCID(cid)) {
	CAERROR(stderr,"cainsert(%d,...) cid is bad\n", cid);
	return(SYSERR);
    }

    if ((keylen > CA_MAXKEY) || (reslen > CA_MAXRES)) {
	CAERROR(stderr,"cainsert: SYSERR, key or result too large\n");
	return(SYSERR);
    }

    if (!ca_enabled)
	return(OK);

    pcb = &catab[cid];
	
    hash = cahash(pkey,keylen);
    phe = &pcb->cb_hash[HASHTOIX(hash,pcb)];

    if ((ixnew = cagetindex(pcb,pkey,keylen,hash)) != NULL_IX) {
	/* use the old one */
	caclear(pcb,ixnew);
	pce = &pcb->cb_cache[ixnew];

	CADEBUG(stderr,"cainsert(%d): reusing cache slot %d, nument:%d\n",
		cid, ixnew, pcb->cb_nument);
    } else {
	/* get a free cacheentry */
	ixnew = cagetfree(pcb);
	pce = &pcb->cb_cache[ixnew];

	/* ... and put it at the head of the list */
	pce->ce_prev = 0;
	pce->ce_next = phe->he_ix;
	pcb->cb_cache[phe->he_ix].ce_prev = ixnew;
	phe->he_ix = ixnew;

	CADEBUG(stderr,"cainsert(%d): using new cache slot %d, nument:%d\n",
		cid, ixnew, pcb->cb_nument);
    }

    pce->ce_status = CE_INUSE;
    pce->ce_hash = hash;
    pce->ce_keyptr = cagetmem(keylen);
    pce->ce_keylen = keylen;
    bcopy(pkey,pce->ce_keyptr,(int)keylen);
    pce->ce_resptr = cagetmem(reslen);
    pce->ce_reslen = reslen;
    bcopy(pres,pce->ce_resptr,(int)reslen);
    time(&pce->ce_tsinsert);
    pce->ce_tsaccess = pce->ce_tsinsert;
			
    return(OK);
}



/*
 * ====================================================================
 * calookup - find an entry in the cache given the key, return info
 * ====================================================================
 */
int
calookup(
    int cid,
    char *pkey,
    tcelen keylen,
    char *pres,
    tcelen *preslen)
{
    struct cacheblk *pcb;
    struct cacheentry *pce;
    thval hash;
    tceix ix;
	
    if (ISBADCID(cid)) {
	CAERROR(stderr,"calookup(%d,...) cid is bad\n", cid);
	return(SYSERR);
    }

    if (!ca_enabled)
	return(SYSERR);

    pcb = &catab[cid];
    hash = cahash(pkey,keylen);
    if ((ix = cagetindex(pcb,pkey,keylen,hash)) != NULL_IX) {
	pce = &pcb->cb_cache[ix];

	if (pce->ce_reslen <= *preslen) {
	    time(&pce->ce_tsaccess);
	    bcopy(pce->ce_resptr,pres,(int)pce->ce_reslen);
	    *preslen = pce->ce_reslen;
	    return(OK);
	}
    }

    return(SYSERR);
}



/*
 * ====================================================================
 * caremove - remove an entry from the cache if it exists
 * ====================================================================
 */
int
caremove(
    int cid,
    char *pkey,
    tcelen keylen)
{
    struct cacheblk *pcb;
    unsigned hash;
    tceix ix;
	
    if (ISBADCID(cid)) {
	CAERROR(stderr,"caremove(%d,...) cid is bad\n", cid);
	return(SYSERR);
    }

    pcb = &catab[cid];
    hash = cahash(pkey,keylen);
    if ((ix = cagetindex(pcb,pkey,keylen,hash)) != NULL_IX) {
	CADEBUG(stderr,"caremove(%d): killing entry in slot %d:\n",
		cid, ix);
	caunlink(pcb,ix);
    }

    return(OK);
}




/*
 * ====================================================================
 * capurge - remove all entries in an existing cache
 * ====================================================================
 */
int
capurge(
    int cid)
{
    struct cacheblk *pcb;
    struct cacheentry *pce;
    struct hashentry *phe;
    tceix ix;
	
    if (ISBADCID(cid)) {
	CAERROR(stderr,"capurge(%d,...) cid is bad\n", cid);
	return(SYSERR);
    }

    pcb = &catab[cid];

    /* free all cached entries */
    for (ix=1; ix <= pcb->cb_maxent; ++ix) {
	pce = &pcb->cb_cache[ix];
	if (pce->ce_status == CE_INUSE)
	    caunlink(pcb,ix);
	pce->ce_status = CE_FREE;
    }

    /* clear the hash table */
    for (ix=0; ix < pcb->cb_hashsize; ++ix) {
	phe = &pcb->cb_hash[ix];
	bzero(phe,sizeof(struct hashentry));
	phe->he_ix = NULL_IX;
    }

    pcb->cb_nument = 0;

    return(OK);
}



/*
 * ====================================================================
 * cadump - dump contents of the cache structures
 * ====================================================================
 */
void
cadump(void)
{
    int cid;
    int purge;
    int zero;
    struct cacheblk *pcb;

    purge = zero = FALSE;

    fprintf(stderr,"\nmaxcaches: %d   (caching %sabled)\n",
	    CA_NUMCACHES,
	    ca_enabled?"en":"DIS");
    fprintf(stderr,"\
ix name            maxent nument htsize life tos  full finds  hits   hit%%\n");
    fprintf(stderr,"\
== =============== ====== ====== ====== ==== ==== ==== ====== ====== ====\n");
    for (cid=0; cid < CA_NUMCACHES; ++cid) {
	pcb = &catab[cid];
	if (pcb->cb_status == CB_FREE)
	    continue;

	if (purge)
	    capurge(cid);

	if (zero) {
	    pcb->cb_tos = 0;
	    pcb->cb_fulls = 0;
	    pcb->cb_lookups = 0;
	    pcb->cb_hits = 0;
	}

	fprintf(stderr,"%2d %-15s %6d %6d %6d %4d %4d %4d %6d %6d %3d%%",
		cid,
		pcb->cb_name,
		pcb->cb_maxent,
		pcb->cb_nument,
		pcb->cb_hashsize,
		pcb->cb_maxlife,
		pcb->cb_tos,
		pcb->cb_fulls,
		pcb->cb_lookups,
		pcb->cb_hits,
		(pcb->cb_lookups)?
		((100 * pcb->cb_hits) / pcb->cb_lookups):0);
	fprintf(stderr,"\n");
    }
}



/*************************************************************************/
/**									**/
/**	LOCAL FUNCTIONS							**/
/**									**/
/*************************************************************************/


/*
 * ====================================================================
 * cahash - return the hash value for a key
 * ====================================================================
 */
static thval
cahash(
    char *pkey,
    tcelen keylen)
{
    int i;
    thval hval;

    hval = 0;
    for (i=0; i < keylen; ++i)
	hval += *pkey++;
    return(hval);
}



/* try to reduce fragmentation */
#define CAMEMSIZE(nb) ((unsigned) (((nb) + 31) & ~31))
/*
 * ====================================================================
 * cagetmem - get memory for a cached entry
 * ====================================================================
 */
static char *
cagetmem(
    u_int nbytes)
{
    char *ret;

    ret = malloc(CAMEMSIZE(nbytes));
    if (!ret) {
	perror("cagetmem malloc");
	exit(-1);
    }

    return(ret);
}


/*
 * ====================================================================
 * cafreemem - free memory from a cached entry
 * ====================================================================
 */
static void
cafreemem(
    void *ptr,
    u_int nbytes)
{
    free(ptr);
}




/*
 * ====================================================================
 * cadeleteold - delete the "oldest" cached entry
 * ====================================================================
 */
static void
cadeleteold(
    struct cacheblk *pcb)
{
    struct cacheentry *pce;
    unsigned oldtime;
    tceix oldix;
    tceix ix;

    /* check everyone against the first entry */
    oldix = 1;
    pce = &pcb->cb_cache[oldix];
    oldtime = pce->ce_tsaccess;

    for (ix=2; ix <= pcb->cb_maxent; ++ix) {
	pce = &pcb->cb_cache[ix];
	if ((pce->ce_status == CE_INUSE) &&
	    (pce->ce_tsaccess < oldtime)) {
	    oldix = ix;
	    oldtime = pce->ce_tsaccess;
	}
    }

    /* nuke the oldest one */
    pce = &pcb->cb_cache[oldix];
    caunlink(pcb,oldix);
    return;
}


/*
 * ====================================================================
 * caclear - clear out the given entry, set status to FREE
 * ====================================================================
 */
static void
caclear(
    struct cacheblk *pcb,
    tceix ix)
{
    struct cacheentry *pce;

    pce = &pcb->cb_cache[ix];
    if (pce->ce_keyptr)
	cafreemem(pce->ce_keyptr,pce->ce_keylen);
    if (pce->ce_resptr)
	cafreemem(pce->ce_resptr,pce->ce_reslen);
    bzero(pce,sizeof(struct cacheentry));
    pce->ce_status = CE_FREE;
}



/*
 * ====================================================================
 * caisold - return TRUE if the given entry is "too old"
 * ====================================================================
 */
static int
caisold(
    struct cacheblk *pcb,
    struct cacheentry *pce)
{
    time_t now;

    if (pcb->cb_maxlife == 0)
	return(FALSE);

    time(&now);

    return ((now - pce->ce_tsaccess) > pcb->cb_maxlife);
}




/*
 * ====================================================================
 * cagetindex - return the index of a matching entry, or SYSERR
 * ====================================================================
 */
static tceix
cagetindex(
     struct cacheblk *pcb,
     char *pkey,
     tcelen keylen,
     thval hashval)
{
    struct cacheentry *pce;
    tceix ix;
    tceix nextix;
	
    ++pcb->cb_lookups;

    ix = pcb->cb_hash[HASHTOIX(hashval,pcb)].he_ix;

    while (ix != NULL_IX) {
	pce = &pcb->cb_cache[ix];
	nextix = pce->ce_next;

	CADEBUG(stderr,"cagetindex[%d]: ", ix);
	if ((pce->ce_hash == hashval) &&
	    (pce->ce_keylen == keylen) &&
	    (memcmp((void *)pkey,(void *)pce->ce_keyptr,(int) keylen) == 0)) {
	    /* this is a match */
	    ++pcb->cb_hits;
	    if (caisold(pcb,pce)) {
		++pcb->cb_tos;
		CADEBUG(stderr,"OLD\n");
		caunlink(pcb,ix);
		return(NULL_IX);
	    } else {
		CADEBUG(stderr,"YES\n");
		return(ix);
	    }
	}
	CADEBUG(stderr,"NO (%d!=%d, %d!=%d)\n",
		pce->ce_hash, hashval,
		pce->ce_keylen, keylen);
	ix = nextix;
    }

    return(NULL_IX);
}




/*
 * ====================================================================
 * casetsize - set the hash table size
 * ====================================================================
 */
static void
casetsize(
    struct cacheblk *pcb,
    int nentries)
{
    if (nentries <= 10) 
	pcb->cb_hashsize = 13;
    else if (nentries <= 25) 
	pcb->cb_hashsize = 29;
    else if (nentries <= 50) 
	pcb->cb_hashsize = 53;
    else if (nentries <= 100) 
	pcb->cb_hashsize = 101;
    else if (nentries <= 200) 
	pcb->cb_hashsize = 213;
    else 
/*	    pcb->cb_hashsize = nentries * 1.25;*/

	/* avoid the floating point */
	pcb->cb_hashsize = (nentries * 5) >> 2;
    /* 5 >> 2 == 5 / 4 == 1.25 */
	
    return;
}



/*
 * ====================================================================
 * cagetfree - return the index of an unused pce.  If there aren't any
 *            left, delete an old one and return it.
 * ====================================================================
 */
static tceix
cagetfree(
    struct cacheblk *pcb)
{
    struct cacheentry *pce;
    tceix ix;

    /* if the free list is empty, delete the oldest entry */
    if (pcb->cb_freelist == NULL_IX) {
	CADEBUG(stderr,"cagetfree: cache full, deleting old entry, nument:%d\n",
		pcb->cb_nument);
	cadeleteold(pcb);
	++pcb->cb_fulls;
    }

    /* remove the head of the list */
    ix = pcb->cb_freelist;
    pce = &pcb->cb_cache[ix];
    pcb->cb_freelist = pce->ce_next;
    ++pcb->cb_nument;

    CADEBUG(stderr,"cagetfree: returning slot %d\n", ix);
    return(ix);
}



/*
 * ====================================================================
 * caunlink - remove a cached entry from a list (and erase it)
 *	      return it to the free list
 * ====================================================================
 */
static void
caunlink(
    struct cacheblk *pcb,
    tceix ix)
{
    struct cacheentry *pce;
    struct hashentry *phe;
    thval hash;

    pce = &pcb->cb_cache[ix];
    hash = pce->ce_hash;
    phe = &pcb->cb_hash[HASHTOIX(hash,pcb)];

    if (pce->ce_prev == NULL_IX)
	phe->he_ix = pce->ce_next;
    else 
	pcb->cb_cache[pce->ce_prev].ce_next = pce->ce_next;

    pcb->cb_cache[pce->ce_next].ce_prev = pce->ce_prev;

    caclear(pcb,ix);

    /* return it to the free list */
    pce->ce_next = pcb->cb_freelist;
    pcb->cb_freelist = ix;
    --pcb->cb_nument;
}
