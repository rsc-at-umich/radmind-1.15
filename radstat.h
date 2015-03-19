/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined(_RADMIND_RADSTAT_H)
#  define _RADMIND_RADSTAT_H "$Id$"

#  include "filepath.h"
#  include "applefile.h"

extern int radstat( const filepath_t *path, struct stat *st, char *fstype,
		    struct applefileinfo *afinfo );

#endif /* defined(_RADMIND_FILEPATH_H) */
