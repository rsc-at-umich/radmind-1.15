/*
 * Copyright (c) 2003, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined (_RADMIND_DO_CKSUM_H)
#  define _RADMIND_DO_CKSUM_H "$Id$"

#  include "filepath.h"

extern off_t do_fcksum( int fd, char *cksum_b64 );
extern off_t do_cksum( const filepath_t *path, char *cksum_b64 );
extern off_t do_acksum( const filepath_t *path, char *cksum_b64, 
			struct applefileinfo *afinfo );

#endif /* defined(_RADMIND_DO_CKSUM_H) */
