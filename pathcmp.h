/*
 * Copyright (c) 2003, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined(_RADMIND_PATHCMP_H)
#  define _RADMIND_PATHCMP_H "$Id"

#  include "filepath.h"

extern int pathcasecmp( const filepath_t *p1, const filepath_t *p2,
			int case_sensitive );
extern int pathcmp( const filepath_t *p1, const filepath_t *p2 );
extern int ischildcase( const filepath_t *child, const filepath_t *parent,
			int case_sensitive );
extern int ischild( const filepath_t *child, const filepath_t *parent );

#endif /* defined (_RADMIND_PATHCMP_H) */
