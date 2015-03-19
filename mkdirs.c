/*
 * Copyright (c) 2003, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "mkdirs.h"

/*
 * The right most element of the path is assumed to be a file.
 */
    int 
mkdirs( const filepath_t *path ) 
{
    char 	*p, *q = NULL;
    int		saved_errno;
    char        *tmp_path = strdup ((const char *)path);;

    saved_errno = errno;

    /* try making longest path first, working backward */
    for (;;) {
	if (( p = strrchr( tmp_path, '/' )) == NULL ) {
	    errno = EINVAL;
	    free (tmp_path);
	    return( -1 );
	}
	*p = '\0';
	if ( q != NULL ) {
	    *q = '/';
	}

	if ( mkdir( tmp_path, 0777 ) == 0 ) {
	    break;
	}
	if ( errno != ENOENT ) {
	    free (tmp_path);
	    return( -1 );
	}
	q = p;
    }

    *p = '/';

    if ( q != NULL ) {
	p++;
	for ( p = strchr( p, '/' ); p != NULL; p = strchr( p, '/' )) {
	    *p = '\0';
	    if ( mkdir( tmp_path, 0777 ) < 0 ) {
		if ( errno != EEXIST ) {
		    free (tmp_path);
		    return( -1 );
		}
	    }
	    *p++ = '/';
	}
    }

    free (tmp_path);

    errno = saved_errno;
    return( 0 );
}
