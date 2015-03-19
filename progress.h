/*
 * Copyright (c) 2003, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined (_RADMIND_PROGRESS_H)
#  define _RADMIND_PROGRESS_H "$Id$"

#  include "filepath.h"

#define PROGRESSUNIT	1024

extern void   linecheck( char *line, int ac, int linenum );
extern off_t  loadsetsize( FILE *tran );
extern off_t  applyloadsetsize( FILE *tran );
extern off_t  lcksum_loadsetsize( FILE *tran, const char *prefix );
extern void   progressupdate( ssize_t bytes, const filepath_t *path );

extern int    showprogress;
extern int    progress;

#endif /* defined(_RADMIND_PROGRESS_H) */
