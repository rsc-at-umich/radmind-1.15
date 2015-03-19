/*
 * Copyright (c) 2006, 2007, 2014 Regents of The University of Michigan.
 * All Rights Reserved. See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <openssl/evp.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif /* HAVE_ZLIB */

#include <snet.h>

#include "code.h"
#include "applefile.h"
#include "connect.h"
#include "report.h"
#include "tls.h"
#include "usageopt.h"

char	               *progname = "repo";
int			verbose = 0;
extern struct timeval	timeout;
extern char		*version;
extern char		*caFile, *caDir, *cert, *privatekey;
SSL_CTX			*ctx;

static void repo_usage (FILE *out, int verbose);

extern char *optarg;
extern int optind, opterr, optopt;

/*
 * Command-line options
 *
 * Formerly getopt - "e:h:p:P:vVw:x:y:Z:z:"
 *
 * Remaining opts: "e:h:p:P:vVw:x:y:Z:z:"
 */

static const usageopt_t main_usage[] = 
  {
    { (struct option) { "event-name", required_argument, NULL, 'e' },
	      "Set event report name (required)", "event-name" },

    { (struct option) { "hostname",     required_argument, NULL, 'h' },
      "Radmind server hostname to contact, defaults to '" _RADMIND_HOST "'", "domain-name" },

    { (struct option) { "tcp-port",      required_argument, NULL, 'p'},
      "TCP port on radmind server to connect to", "tcp-port#"}, 

    { (struct option) { "ca-directory",  required_argument, NULL, 'P' },
	      "Specify where 'ca.pem' can be found.", "pathname"},

    { (struct option) { "authentication",  required_argument, NULL, 'w' },
	      "Specify the authentication level, default " STRINGIFY(_RADMIND_AUTHLEVEL), "number" },

    { (struct option) { "ca-file",       required_argument, NULL, 'x' },
	      "Specify the certificate authority file", "pem-file" },

    { (struct option) { "cert",          required_argument, NULL, 'y' },
	      "Certificate for authenticating client to radmind server", "pem-file"},

    { (struct option) { "cert-key",      required_argument, NULL, 'z' },
	      "Key file for --cert certificate", "key-file" },

#if defined(HAVE_ZLIB)
    { (struct option) { "zlib-level",   required_argument,   NULL, 'Z'},
	      "Specify zlib compression level", "number"},
#else
    { (struct option) { "zlib-level",   required_argument,   NULL, 'Z'},
	      "Not available", "(number)"},
#endif /* defined(HAVE_ZLIB) */

    { (struct option) { "help",         no_argument,       NULL, 'H' },
     		"This message", NULL },
    
    { (struct option) { "version",      no_argument,       NULL, 'V' },
     		"show version number, and a list of supported checksumming algorithms in descending order of preference and exits", NULL },
    
    { (struct option) { "verbose",           no_argument,       NULL, 'v' },
     		"Be chatty", NULL },


    /* End of list */
    { (struct option) {(char *) NULL, 0, (int *) NULL, 0}, (char *) NULL, (char *) NULL}
  }; /* end of main_usage[] */


   static void
   repo_usage (FILE *out, int verbose)
{
      usageopt_usage (out, verbose, progname,  main_usage,
		      "[message]...", 80);

      return;
} /* End of repo_usage() */




    int
main( int argc, char *argv[] )
{
    SNET		*sn;
    int			c, i = 0, err = 0, len;
    int			authlevel = _RADMIND_AUTHLEVEL;
    int			use_randfile = 0;
    extern int		optind;
    unsigned short	port = 0;
    char		*host = _RADMIND_HOST;
    char		*event = NULL;
    char		repodata[ MAXPATHLEN * 2 ];
    char		**capa = NULL; /* server capabilities */
    int       		optndx = 0;
    struct option	*main_opts;
    char        	*main_optstr;

    /* Get our name from argv[0] */
    for (main_optstr = argv[0]; *main_optstr; main_optstr++) {
        if (*main_optstr == '/')
	    progname = main_optstr+1;
    }

    main_opts = usageopt_option_new (main_usage, &main_optstr);

    while (( c = getopt_long (argc, argv, main_optstr, main_opts, &optndx)) != -1) {
	switch ( c ) {
	case 'e':		/* event to report */
	    event = optarg;
	    break;

	case 'h':
	    host = optarg;
	    break;

	case 'p':
	    /* connect.c handles things if atoi returns 0 */
            port = htons( atoi( optarg ));
	    break;

	case 'P':
	    caDir = optarg;
	    break;

	case 'v':
	    verbose = 1;
	    logger = v_logger;
	    break;

	case 'V':
	    printf( "%s\n", version );
	    exit( 0 );

	case 'w':
	    authlevel = atoi( optarg );
	    if (( authlevel < 0 ) || ( authlevel > 2 )) {
		fprintf( stderr, "%s: invalid authorization level\n",
			optarg );
		exit( 2 );
	    }
	    break;

	case 'x':
	    caFile = optarg;
	    break;

	case 'y':
	    cert = optarg;
	    break;

	case 'z':
	    privatekey = optarg;
	    break;

	case 'Z':
#ifdef HAVE_ZLIB
            zlib_level = atoi( optarg );
            if (( zlib_level < 0 ) || ( zlib_level > 9 )) {
                fprintf( stderr, "Invalid compression level\n" );
                exit( 1 );
            }
            break;
#else /* HAVE_ZLIB */
            fprintf( stderr, "Zlib not supported.\n" );
            exit( 1 );
#endif /* HAVE_ZLIB */

	case 'H': /* --help */
	    repo_usage (stdout, 1);
	    exit (0);
	    /* UNREACHABLE */

	default:
	    err++;
	    break;
	}
    }

    /* repo is useless without an event defined */
    if ( event == NULL ) {
	err++;
    }

    if ( err || (( argc - optind ) < 0 )) {
        repo_usage (stderr, 0);
	exit( 1 );
    }

    if ( argc == optind ) {	/* read message from stdin */
	if ( fgets( repodata, sizeof( repodata ), stdin ) == NULL ) {
	    perror( "fgets" );
	    exit( 2 );
	}

	len = strlen( repodata );
	if ( repodata[ len - 1 ] != '\n' ) {
	    fprintf( stderr, "report too long\n" );
	    exit( 2 );
	}
	repodata[ len - 1 ] = '\0';
    } else {
	if ( strlen( argv[ optind ] ) >= sizeof( repodata )) {
	    fprintf( stderr, "%s: too long\n", argv[ optind ] );
	    exit( 2 );
	}
	strcpy( repodata, argv[ optind ] );

	/* Skip first token in message */
	i = 1;
	for ( i += optind; i < argc; i++ ) {
	    if (( strlen( repodata ) + strlen( argv[ i ] ) + 2 )
			>= sizeof( repodata )) {
		fprintf( stderr, "%s %s: too long\n", repodata, argv[ i ] );
		exit( 2 );
	    }
	    strcat( repodata, " " );
	    strcat( repodata, argv[ i ] );
	}
    }

    if (( sn = connectsn( host, port )) == NULL ) {
	exit( 2 );
    }
    if (( capa = get_capabilities( sn )) == NULL ) {
            exit( 2 );
    }

    if ( authlevel != 0 ) {
	if ( tls_client_setup( use_randfile, authlevel, caFile, caDir, cert,
		privatekey ) != 0 ) {
	    exit( 2 );
	}
	if ( tls_client_start( sn, host, authlevel ) != 0 ) {
	    exit( 2 );
	}
    }

#ifdef HAVE_ZLIB
    /* Enable compression */
    if ( zlib_level > 0 ) {
        if ( negotiate_compression( sn, capa ) != 0 ) {
	    fprintf( stderr, "%s: server does not support reporting\n", host );
            exit( 2 );
        }
    }
#endif /* HAVE_ZLIB */

    /* Check to see if server supports reporting */
    if ( check_capability( "REPO", capa ) == 0 ) {
	fprintf( stderr, "%s: server does not support reporting\n", host );
	exit( 2 );
    }

    if ( report_event( sn, event, repodata ) != 0 ) {
	exit( 2 );
    }

    if (( closesn( sn )) != 0 ) {
	fprintf( stderr, "closesn failed.\n" );
	exit( 2 );
    }

    return( 0 );
}
