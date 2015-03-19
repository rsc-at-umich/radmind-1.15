/*
 * Copyright (c) 2003, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined(_RADMIND_CONNECT_H)
#  define _RADMIND_CONNECT_H "$Id"

#  include "filepath.h"
#  include "applefile.h"
 
extern SNET * connectsn( const char *host, unsigned short port );
extern int    closesn( SNET *sn );
extern char **get_capabilities( SNET *sn );

#if defined(HAVE_ZLIB)
extern int negotiate_compression( SNET *sn, char ** );
extern int print_stats( SNET *sn );
extern int zlib_level;
#endif /* HAVE_ZLIB */

extern int retr( SNET *sn, const filepath_t *pathdesc, const filepath_t *path,
	   filepath_t *temppath, mode_t tempmode, off_t transize,
	   const char *trancksum );
extern int retr_applefile( SNET *sn, const filepath_t *pathdesc,
	   const filepath_t *path, filepath_t *temppath, mode_t tempmode,
	   off_t transize, const char *trancksum );

extern int n_stor_file( SNET *sn, const filepath_t *pathdesc, const filepath_t *path );
extern int stor_file( SNET *sn, const filepath_t *pathdesc, const filepath_t *path,
           off_t transize, const char *trancksum );
extern int n_stor_applefile( SNET *sn, const filepath_t *pathdesc, const filepath_t *path );
extern int stor_applefile( SNET *sn, const filepath_t *pathdesc, const filepath_t *path,
	   off_t transize, const char *trancksum, struct applefileinfo *afinfo );
extern int stor_response( SNET *sn, int *respcount, struct timeval * );

extern void v_logger( const char *string);
extern int  check_capability( const char *type, char **capa );

extern void (*logger)( const char * );

#endif /* defined(_RADMND_CONNECT_H) */
