/*
 * Copyright (c) 2003, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined(_RADMIND_LIST_H)
#  define _RADMIND_LIST_H "$Id$"

#  include "filepath.h"

typedef struct node node_t;

struct list
{
    int		l_count;
    node_t	*l_head;	
    node_t	*l_tail;	
};

struct node
{
    filepath_t	n_path[ MAXPATHLEN ];
    node_t 	*n_next;
    node_t 	*n_prev;
};

typedef struct list list_t;

#  define list_size( list )   ((list) ? (list)->l_count : 0 )

extern list_t  	      *	list_new( void );
extern void		list_clear( list_t *list );
extern void		list_free( list_t *list );
extern void 		list_print( list_t *list );
extern int 		list_insert( list_t *list, const filepath_t *path );
extern int 		list_insert_case( list_t *list, const filepath_t *path,
					  int case_sensitive );
extern int 		list_insert_head( list_t *list, const filepath_t *path );
extern int 		list_insert_tail( list_t *list, const filepath_t *path );
extern int 		list_remove( list_t *list, const filepath_t *path );
extern void 		list_remove_head( list_t *list );
extern void 		list_remove_tail( list_t *list );
extern node_t	      * list_pop_head( list_t *list );
extern node_t	      * list_pop_tail( list_t *list );
extern int		list_check( const list_t *list, const filepath_t *path );
extern int		list_check_case( const list_t *list, const filepath_t *path );
#endif /* defined(_RADMIND_LIST_H) */
