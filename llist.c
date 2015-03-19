/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "applefile.h"
#include "transcript.h"
#include "llist.h"

/* Allocate a new list node */
    llist_t *
ll_allocate( const filepath_t *name ) 
{
    llist_t	*new;

    /* allocate space for next item in list */
    if (( new = (llist_t *)malloc( sizeof( llist_t ))) == NULL ) {
	perror( "malloc" );
	exit( 2 );
    } 

    /* copy info into new item */
    strncpy( (char *) new->ll_name, (char *)name, sizeof(new->ll_name)-1 );
    new->ll_name[sizeof(new->ll_name)-1] = '\0';
    new->ll_next = (llist_t *) NULL;

    return new;
}

/* Free the whole list */
    void
ll_free( llist_t *head )
{
    llist_t	*next;
    
    for ( ; head != (llist_t *) NULL; head = next ) {
	next = head->ll_next;
	free( head );
    }
}

    void 
ll_insert( llist_t **headp, llist_t *new ) 
{ 
    llist_t	**current;

    /* find where in the list to put the new entry */
    for ( current = headp; *current != (llist_t *) NULL; current = &(*current)->ll_next) {
      if ( strcmp( (char *) new->ll_name, (char *) ((*current)->ll_name )) <= 0 ) {
	    break;
	}
    }

    new->ll_next = *current;
    *current = new; 
    return; 
}

/* Insert a new node into the list */
    void 
ll_insert_case( llist_t **headp, llist_t *new ) 
{ 
    llist_t	**current;

    /* find where in the list to put the new entry */
    for ( current = headp; *current != (llist_t *) NULL; current = &(*current)->ll_next) {
      if ( strcasecmp( (char *) new->ll_name, (char *) ((*current)->ll_name )) <= 0 ) {
	    break;
	}
    }

    new->ll_next = *current;
    *current = new; 
    return; 
}
