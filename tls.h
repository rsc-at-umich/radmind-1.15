/*
 * Copyright (c) 2003, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined(_RADMIND_TLH_H)
#  define _RADMIND_TLS_H "$Id"

extern int tls_server_setup( int use_randfile, int authlevel,
			     const char *caFile, const char *caDir,
			     const char *crlFile, const char *crlDir,
			     const char *cert, const char *privatekey );
extern int tls_client_setup( int use_randfile, int authlevel, 
			     const char *caFile, const char *caDir,
			     const char *cert, const char *privatekey );
extern int tls_client_start( SNET *sn, const char *host, int authlevel );

#endif /* defined(_RADMIND_TLS_H) */
