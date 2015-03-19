/*
 * Copyright (c) 2003, 213 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined(_RADMIND_UPDATE_H)
#  define _RADMIND_UPDATE_H "$Id$"

#  include "filepath.h"
#  include "applefile.h"

extern int update( const filepath_t *path, const filepath_t *displaypath, int present, int newfile,
		   struct stat *st, int tac, char **targv, struct applefileinfo *afinfo );

#endif /* defined(_RADMIND_UPDATE_H) */
