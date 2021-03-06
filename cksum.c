/*
 * Copyright (c) 2003, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#ifdef __APPLE__
#include <sys/paths.h>
#endif /* __APPLE__ */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "applefile.h"
#include "cksum.h"
#include "base64.h"

size_t rad_fcksum_bufsize	= DEFAULT_RAD_CKSUM_BUFSIZE;
size_t rad_cksum_bufsize	= DEFAULT_RAD_CKSUM_BUFSIZE;
size_t rad_acksum_bufsize	= DEFAULT_RAD_CKSUM_BUFSIZE;

/*
 * do_cksum calculates the checksum for PATH and returns it base64 encoded
 * in cksum_b64 which must be of size SZ_BASE64_E( EVP_MAX_MD_SIZE ).
 *
 * return values:
 *	< 0	system error: errno set, no message given
 *	>= 0	number of bytes check summed
 */

static off_t do_fcksum_size( int fd, char *cksum_b64, size_t bufsize);

    static off_t 
do_fcksum_size( int fd, char *cksum_b64, size_t bufsize )
{
    unsigned int	md_len;
    ssize_t		rr;
    off_t		size = 0;
    unsigned char	*p_buf;
    extern EVP_MD	*md;
    EVP_MD_CTX		mdctx;
    unsigned char 	md_value[ EVP_MAX_MD_SIZE ];

    EVP_DigestInit( &mdctx, md );

    if ((p_buf = (unsigned char *) malloc (bufsize)) == (unsigned char *) NULL) {
        return (-1);
    }

    while (( rr = read( fd, p_buf, bufsize)) > 0 ) {
	size += rr;
	EVP_DigestUpdate( &mdctx, p_buf, (unsigned int)rr );
    }
    free (p_buf);

    if ( rr < 0 ) {
	return( -1 );
    }

    EVP_DigestFinal( &mdctx, md_value, &md_len );
    base64_e( md_value, md_len, cksum_b64 );

    return( size );
}

    off_t
do_fcksum( int fd, char *cksum_b64)
{
    return do_fcksum_size(fd, cksum_b64, rad_fcksum_bufsize);
}



    off_t
do_cksum( const filepath_t *path, char *cksum_b64 )
{
    int			fd;
    off_t		size = 0;

    if (( fd = open( (const char *) path, O_RDONLY, 0 )) < 0 ) {
	return( -1 );
    }

    size = do_fcksum_size( fd, cksum_b64, rad_cksum_bufsize );

    if ( close( fd ) != 0 ) {
	return( -1 );
    }

    return( size );
}

#ifdef __APPLE__

/*
 * do_acksum calculates the checksum for the encoded apple single file of PATH
 * and returns it base64 encoded in cksum_b64 which must be of size
 * SZ_BASE64_E( EVP_MAX_MD_SIZE ). 
 *
 * return values:
 *	>= 0	number of bytes check summed
 * 	< 0 	system error: errno set, no message given
 *
 * do_acksum should only be called on native HFS+ system.
 */

    off_t 
do_acksum( const filepath_t *path, char *cksum_b64, struct applefileinfo *afinfo )
{
    int		    	    	dfd, rfd, rc;
    char			*p_buf;
    filepath_t                  rsrc_path[ MAXPATHLEN ];
    off_t			size = 0;
    extern struct as_header	as_header;
    struct as_entry		as_entries_endian[ 3 ];
    unsigned int		md_len;
    extern EVP_MD		*md;
    EVP_MD_CTX          	mdctx;
    unsigned char       	md_value[ EVP_MAX_MD_SIZE ];

    EVP_DigestInit( &mdctx, md ); 

    if ((p_buf = (unsigned char *) malloc (rad_acksum_bufsize)) == (unsigned char *) NULL) {
        return (-1);
    }

    /* checksum applesingle header */
    EVP_DigestUpdate( &mdctx, (char *)&as_header, AS_HEADERLEN );
    size += (size_t)AS_HEADERLEN;

    /* endian handling, sum big-endian header entries */
    memcpy( &as_entries_endian, &afinfo->as_ents,
		( 3 * sizeof( struct as_entry )));
    as_entry_netswap( &as_entries_endian[ AS_FIE ] );
    as_entry_netswap( &as_entries_endian[ AS_RFE ] );
    as_entry_netswap( &as_entries_endian[ AS_DFE ] );

    /* checksum header entries */
    EVP_DigestUpdate( &mdctx, (char *)&as_entries_endian,
		(unsigned int)( 3 * sizeof( struct as_entry )));
    size += sizeof( 3 * sizeof( struct as_entry ));

    /* checksum finder info data */
    EVP_DigestUpdate( &mdctx, afinfo->ai.ai_data, FINFOLEN );
    size += FINFOLEN;

    /* checksum rsrc fork data */
    if ( afinfo->as_ents[ AS_RFE ].ae_length > 0 ) {
      if ( snprintf( (char *) rsrc_path, MAXPATHLEN, "%s%s",
		     (const char *) path, _PATH_RSRCFORKSPEC ) >= MAXPATHLEN ) {
	    free (p_buf);
            errno = ENAMETOOLONG;
            return( -1 );
        }

        if (( rfd = open( (const char *) rsrc_path, O_RDONLY )) < 0 ) {
	    free (p_buf);
	    return( -1 );
	}
	while (( rc = read( rfd, p_buf, rad_acksum_bufsize)) > 0 ) {
	    EVP_DigestUpdate( &mdctx, p_buf, (unsigned int)rc );
	    size += (size_t)rc;
	}

	if ( close( rfd ) < 0 ) {
	    free (p_buf);
	    return( -1 );
	}
	if ( rc < 0 ) {
	    free (p_buf);
	    return( -1 );
	}
    }

    if (( dfd = open( (const char *) path, O_RDONLY, 0 )) < 0 ) {
	free (p_buf);
	return( -1 );
    }
    /* checksum data fork */
    while (( rc = read( dfd, p_buf, rad_acksum_bufsize)) > 0 ) {
	EVP_DigestUpdate( &mdctx, p_buf, (unsigned int)rc );
	size += (size_t)rc;
    }
    free (p_buf);

    if ( rc < 0 ) {
	return( -1 );
    }
    if ( close( dfd ) < 0 ) {
	return( -1 );
    }

    EVP_DigestFinal( &mdctx, md_value, &md_len );
    base64_e( ( char*)&md_value, md_len, cksum_b64 );

    return( size );
}
#else /* __APPLE__ */

/*
 * stub fuction for non-hfs+ machines.
 *
 * return values:
 * 	-1 	system error: non hfs+ system
 */

    off_t 
do_acksum( const filepath_t *path, char *cksum_b64, struct applefileinfo *afino )
{
    errno = EOPNOTSUPP;
    return( -1 );
}
#endif /* __APPLE__ */
