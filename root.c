/*
 * Copyright (c) 2003, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/param.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "root.h"

    int
get_root( const filepath_t *radmind_path, const filepath_t *path,
	  filepath_t *file_root, filepath_t *tran_root, filepath_t *tran_name )
{
    char		real_path[ PATH_MAX ];
    char		test_path[ MAXPATHLEN ];
    char                radmind_real_path[ PATH_MAX ];
    char		*p;

    if ( realpath( (const char *) radmind_path, radmind_real_path ) == NULL ) {
        perror( radmind_real_path );
        return( -1 );
    }
    if ( realpath( (const char *) path, real_path ) == NULL ) {
	perror( real_path );
        return( -1 );
    }

    /* Get transcript name */
    if (( p = strrchr( real_path, '/' )) == real_path ) {
	fprintf( stderr, "%s: invalid transcript location\n", real_path );
	return( -1 );
    }
    *p++ = '\0';
    if ( strlen( p ) >= MAXPATHLEN ) {
        fprintf( stderr, "%s: path too long\n", p );
        return( -1 );
    }
    filepath_cpy( tran_name, (filepath_t *) p );  /* Hope we don't overflow. */

    if ( snprintf( test_path, MAXPATHLEN, "%s/tmp/transcript",
            radmind_real_path ) >= MAXPATHLEN ) {
        fprintf( stderr, "%s/tmp/transcirpt: path too long\n",
	    radmind_real_path );
        return( -1 );
    }

    if ( strstr( real_path, test_path ) != NULL ) {
        if ( snprintf( (char *) file_root, MAXPATHLEN, "%s/tmp/file%s",
		radmind_real_path, &real_path[ strlen( test_path ) ])
		>= MAXPATHLEN ) {
            fprintf( stderr, "%s/tmp/file%s: path too long\n",
		radmind_real_path, &real_path[ strlen( test_path )] );
            return( -1 );
        }
        if ( snprintf( (char *) tran_root, MAXPATHLEN, "%s/tmp/transcript%s",
		radmind_real_path, &real_path[ strlen( test_path ) ])
		>= MAXPATHLEN ) {
            fprintf( stderr, "%s/tmp/transcript%s: path too long\n",
		radmind_real_path, &real_path[ strlen( test_path )] );
            return( -1 );
        }
    } else {
        if ( snprintf( test_path, MAXPATHLEN, "%s/transcript",
		radmind_real_path ) >= MAXPATHLEN ) {
            fprintf( stderr, "%s/transcript: path too long\n",
		radmind_real_path );
            return( -1 );
        }

        if ( strstr( real_path, test_path ) != NULL ) {
	  if ( snprintf( (char *) file_root, MAXPATHLEN, "%s/file%s",
                    radmind_real_path, &real_path[ strlen( test_path ) ])
		    >= MAXPATHLEN ) {
                fprintf( stderr, "%s/file%s: path too long\n",
                    radmind_real_path, &real_path[ strlen( test_path ) ]);
                return( -1 );
            }
	  if ( snprintf( (char *) tran_root, MAXPATHLEN, "%s/transcript%s",
		    radmind_real_path, &real_path[ strlen( test_path ) ])
		    >= MAXPATHLEN ) {
		fprintf( stderr, "%s/transcript%s: path too long\n",
		    radmind_real_path, &real_path[ strlen( test_path )] );
		return( -1 );
	    }
        } else {
	  snprintf( (char *) file_root, MAXPATHLEN, "%s/../file", real_path );
	  snprintf( (char *) tran_root, MAXPATHLEN, "%s", real_path );
        }
    }

    return( 0 );
}
