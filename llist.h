/*
 * Copyright (c) 2003, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined(_RADMIND_LLIST_H)
#  define _RADMIND_LLIST_H "$Id$"

#  include "filepath.h"

typedef struct llist llist_t;

struct llist {
    filepath_t	ll_name[ MAXPATHLEN ];
    llist_t	*ll_next;
};

extern llist_t * ll_allocate( const filepath_t *name );
extern void ll_free( llist_t * );
extern void ll_insert( llist_t **, llist_t * );
extern void ll_insert_case( llist_t **, llist_t * );

#endif /* defined(_RADMIND_LLIST_H) */
