/*
 * Copyright (c) 2003, 2013, 2014 by The Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined (_RADMIND_DO_CKSUM_H)
#  define _RADMIND_DO_CKSUM_H "$Id$"

#  include "filepath.h"

extern off_t do_fcksum( int fd, char *cksum_b64 );
extern off_t do_cksum( const filepath_t *path, char *cksum_b64 );
extern off_t do_acksum( const filepath_t *path, char *cksum_b64, 
			struct applefileinfo *afinfo );

#define DEFAULT_RAD_CKSUM_BUFSIZE 8192
extern size_t rad_fcksum_bufsize;
extern size_t rad_cksum_bufsize;
extern size_t rad_acksum_bufsize;

#endif /* defined(_RADMIND_DO_CKSUM_H) */
