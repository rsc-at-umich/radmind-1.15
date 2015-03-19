/*
 * Copyright (c) 2003, 2013-2014 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined(_RADMIND_TLH_H)
#  define _RADMIND_TLS_H "$Id$"

extern long tls_options;    /* For disabling SSLv2 and SSLv3 */

#  if  !defined(RADMIND_DEFAULT_TLS_CIPHER_SUITES)
#    define RADMIND_DEFAULT_TLS_CIPHER_SUITES "DEFAULT:-EXP:-RC4"
#  endif /* RADMIND_DEFAULT_TLS_CIPHER_SUITES */

extern char *tls_cipher_suite;  /* For setting the TLS cipher suite. */

extern int tls_server_setup( int use_randfile, int authlevel,
			     const char *caFile, const char *caDir,
			     const char *crlFile, const char *crlDir,
			     const char *cert, const char *privatekey );
extern int tls_client_setup( int use_randfile, int authlevel, 
			     const char *caFile, const char *caDir,
			     const char *cert, const char *privatekey );
extern int tls_client_start( SNET *sn, const char *host, int authlevel );

extern long tls_str_to_options (const char *str, long init_tls_options);

extern char *tls_options_to_str (char *buffer, size_t len, long opts);
 
#endif /* defined(_RADMIND_TLS_H) */
