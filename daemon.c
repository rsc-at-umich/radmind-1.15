/*
 * Copyright (c) 2003, 2007, 2013-2014 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sysexits.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/*
 * for zeroconf, currently only available on Mac OS X
 */
#ifdef HAVE_DNSSD
#include <dns_sd.h>
#endif /* HAVE_DNSSD */

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif /* HAVE_ZLIB */

#include <snet.h>

#include "command.h"
#include "logname.h"
#include "tls.h"
#include "usageopt.h"

int		debug = 0;
int		backlog = 5;
int		verbose = 0;
int		dodots = 0;
int		cksum = 0;
int		authlevel = _RADMIND_AUTHLEVEL;
int		checkuser = 0;
int		connections = 0;
int             child_signal = 0;
int		maxconnections = _RADMIND_MAXCONNECTIONS; /* 0 = no limit */
int		rap_extensions = 1;			/* 1 for REPO */
int             reinit_ssl_signal = 0;
char		*radmind_path = _RADMIND_PATH;
static char     *progname = "radmind";
SSL_CTX         *ctx = NULL;

#ifdef HAVE_ZLIB
extern int 	max_zlib_level;
#endif /* HAVE_ZLIB */

extern char	*version;

void		hup( int );
void		usr1( int );
void		chld( int );
int		main( int, char *av[] );

static void radmind_usage(FILE *out, int verbose, const char *fmt, ...);

    void
hup( int sig )
{
    /* Hup does nothing at the moment */
    return;
}

    void
usr1( int sig )
{
    /* Set trigger for reinitializing SSL context */
    reinit_ssl_signal = 1;
    return;
}

    void
chld( int sig )
{
    child_signal++;
    return;

}

#ifdef HAVE_DNSSD
    static void
dnsreg_callback( DNSServiceRef dnssrv, DNSServiceFlags flags,
	DNSServiceErrorType error, const char *name, const char *regtype,
	const char *domain, void *context )
{
    if ( error == kDNSServiceErr_NoError ) {
	syslog( LOG_NOTICE, "DNSServiceRegister successful. Name: %s "
		"Type: %s Domain: %s", name, regtype, domain );
    } else {
	syslog( LOG_ERR, "DNSServiceRegister error: %d", ( int )error );
    }
}

    static DNSServiceErrorType
register_service( DNSServiceRef *dnssrv, unsigned int port,
		DNSServiceRegisterReply callback )
{
    DNSServiceErrorType	err;

    /* see dns_sd.h for API details */
    err = DNSServiceRegister( dnssrv,			/* registered service */
				0,			/* service flags */
				0,			/* interface index */
				NULL,			/* service name */
				"_radmind._tcp",	/* service type */
				NULL,			/* domain */
				NULL,			/* SRV target host */
				port,			/* port */
				0,			/* TXT len */
				NULL,			/* TXT record */
				callback,		/* callback */
				NULL );			/* context pointer */

    return( err );
}
#endif /* HAVE_DNSSD */

extern char *optarg;
extern int optind, opterr, optopt;
/*
 * Command-line options, and usage help. Table driven!
 */
static const usageopt_t main_usage[] = 
  {
    { (struct option) { "listen",       no_argument,        NULL, 'a' },
              "Listen (bind()) to the IPv4 address given", "dotted-quad" },

    { (struct option) { "connection-backlog", required_argument, NULL, 'b' },
              "Specify the TCP connection listen queue size", "non-negative-integer" },

    { (struct option) { "bonjour",      no_argument,        NULL, 'B' },
#if defined(HAVE_DNSSD)
              "Register as a Bonjour service", 
#else
              "Register as a Bonjour server (not supported)",
#endif /* defined(HAVE_DNSSD) */
      NULL}, 

    { (struct option) { "radmind-directory",  required_argument, NULL, 'D' },
	      "Specifiy the radmind working directory, by default "
      		_RADMIND_PATH, "pathname"},

    { (struct option) { "debug",	no_argument,	    NULL, 'd'},
      	       "Raise debugging AND verbosity level to see what's happening", NULL},

    { (struct option) { "foreground",   no_argument,        NULL, 'f'},
               "Run in foreground (rather than as daemon in background)", NULL },

    { (struct option) { "syslog-facility", required_argument, NULL, 'F' },
               "Syslog facility", "string?" },

    { (struct option) { "syslog-level", required_argument, NULL, 'L' },
               "Syslog level", "string" },

    { (struct option) { "max-simultaneous", required_argument, NULL, 'm' },
               "Maximum number of simultaneous connections", "non-negative-integer" },

    { (struct option) { "tcp-port",      required_argument, NULL, 'p'},
              "TCP port on radmind server to connect to", "tcp-port#"}, 

    { (struct option) { "ca-directory",  required_argument, NULL, 'P' },
	      "Specify where 'ca.pem' can be found.", "pathname"},

    { (struct option) { "random-file",   no_argument,        NULL, 'r' },
	      "use random seed file $RANDFILE if that environment variable is set, $HOME/.rnd otherwise.  See RAND_load_file(3o).", NULL},

    { (struct option) { "register-bonjour", no_argument,    NULL, 'R' },
             "Deprecated in favor of -B/--bonjour", NULL },

    { (struct option) { "umask",        required_argument,  NULL, 'u' },
	      "specifies the umask for uploaded files, by default 0077", "number" },

    { (struct option) { "check-user",    no_argument, NULL, 'U' },
              "Check user for authentication", NULL },
       
    { (struct option) { "authentication",  required_argument, NULL, 'w' },
	      "Specify the authentication level (auth-level), default " STRINGIFY(_RADMIND_AUTHLEVEL), "number" },

    { (struct option) { "cert-revocation-list", required_argument, NULL, 'C' },
      "Specify CRL (Certificate-Revocation-List) directory or file", "pathname" },

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

    { (struct option) { "help",         no_argument,         NULL, 'H' },
     	      "This message", NULL },

    { (struct option) { "verbose",      no_argument,         NULL, 'v' },
     	      "Be chatty", NULL },
    
    { (struct option) { "tls-options",	required_argument,   NULL, 'O' },
              "Set OpenSSL/TLS options (like NO_SSLv3), or clear (clear)", NULL }, 

    /* End of list */
    { (struct option) {(char *) NULL, 0, (int *) NULL, 0},
      	      (char *) NULL, (char *) NULL}

  }; /* end of main_usage[] */


    static void
    radmind_usage (FILE *out, int verbose, const char *fmt, ...)
{
      va_list ap;

      va_start(ap, fmt);

      if ((fmt != (char *) NULL) && (*fmt != '\0')) {
	  size_t eol = strlen(fmt);

	  fprintf (out, "%s: ", progname);

	  vfprintf (out, fmt, ap);
	  if (fmt[eol-1] != '\n')
	      fprintf(out, "\n");
      }

      usageopt_usage (out, verbose, progname,  main_usage,
		      "", 80);
     
      fprintf (out,
	       "--check-user(-U) requires --authentication(-w) level > 1\n"
	       "--cert-revocation-list(-C) requires --authentication(-w) level > 1\n");

      va_end(ap);

      return;
} /* end of radmind_usage() */


    int
main( int ac, char **av )
{
    struct sigaction	sa, osahup, osausr1, osachld;
    struct sockaddr_in	sin;
    struct in_addr	b_addr;
    struct servent	*se;
    int			c, s, err = 0, fd, trueint;
    socklen_t		addrlen;
    int			dontrun = 0, fg = 0;
    int			use_randfile = 0;
    unsigned short	port = 0;
    int			facility = _RADMIND_LOG;
    int			level = LOG_INFO;
    extern char		*caFile, *caDir, *crlFile, *crlDir, *cert, *privatekey;
    struct stat		st;
    pid_t		pid;
    int			status;
    struct rusage	usage;
    int                 optndx = 0;
    struct option	*main_opts;
    char        	*main_optstr;
#ifdef HAVE_DNSSD
    int			regservice = 0;
    DNSServiceRef	dnssrv;
    DNSServiceErrorType	dnsreg_err;
#endif /* HAVE_DNSSD */

    if (( progname = strrchr( av[ 0 ], '/' )) == NULL ) {
	progname = av[ 0 ];
    } else {
	progname++;
    }

    main_opts = usageopt_option_new (main_usage, &main_optstr);

    b_addr.s_addr = htonl( INADDR_ANY );

    /* Set appropriate TLS paths for server; default values are for client  */
    caFile = "cert/ca.pem";
    cert = "cert/cert.pem"; 	 
    privatekey = "cert/cert.pem";

    while (( c = getopt_long( ac, av, main_optstr, main_opts, &optndx)) != -1 ) {
	switch ( c ) {
	case 'a' :		/* bind address */ 
	    if ( !inet_aton( optarg, &b_addr )) {
	        usageopt_usagef (stderr, 0, progname, main_usage, 80, 
				 "\nbad address ('%s')\n", optarg );
		exit( EX_USAGE );
	    }
	    break;

	case 'B':		/* register as a Bonjour service */
	case 'R':		/* -R: deprecated in favor of -B */
#ifdef HAVE_DNSSD
	    regservice = 1;
	    break;
#else /* HAVE_DNSSD */
	    usageopt_usagef (stderr, 0, progname, main_usage, 80,
			     "\nBonjour not supported.\n" );
	    exit( EX_USAGE );
#endif /* HAVE_DNSSD */

	case 'b':		/* listen backlog */
	    backlog = atoi( optarg );
	    break;

	case 'd':		/* debug */
	    debug++;
	    verbose++;
	    break;

	case 'C':		/* crl file or dir */
	    if ( stat( optarg, &st ) < 0 ) {
	        usageopt_usagef (stderr, 0, progname, main_usage, 80,
				 "\n--certificate-revocation-path(-C) '%s' invalid: %s\n",
			optarg, strerror( errno ));
	        exit( EX_USAGE );
	    }
	    if ( S_ISDIR( st.st_mode ) ) {
	        crlDir = optarg;
	    } else {
	        crlFile = optarg;
	    }
	    break;

	case 'D':	/* --radmind-directory --  Set radmind path */
	    radmind_path = optarg;
	    break;

	case 'F':
	    if (( facility = syslogfacility( optarg )) == -1 ) {
	        usageopt_usagef (stderr, 0, progname, main_usage, 80,
			       "\n--syslog-facility(-F) unknown syslog facility '%s'\n",
				 optarg );
		exit( EX_USAGE );
	    }
	    break;

	case 'f':		/* run in foreground */
	    fg = 1;
	    break;

	case 'L' :		/* syslog level */
	    if (( level = sysloglevel( optarg )) == -1 ) {
	        usageopt_usagef (stderr, 0, progname, main_usage, 80, 
				 "\n--syslog-level(-L) unknown syslog level '%s'\n",
				 optarg );
		exit( EX_USAGE );
	    }
	    break;
	case 'm':	/* --max-simultaneous */
	    maxconnections = atoi( optarg );	/* Set max connections */
	    break;

	case 'p':		/* TCP port */
	    port = htons( atoi( optarg ));
	    break;

	case 'O':    /* TLS options */
	    if ((strcasecmp(optarg, "none") == 0) || (strcasecmp(optarg, "clear") == 0)) {
	        tls_options = 0;
	    }
	    else {
	        long new_tls_opt;

		new_tls_opt = tls_str_to_options(optarg);
		if (new_tls_opt == 0) {
		    usageopt_usagef (stderr, 0, progname, main_usage, 80,
				   "\n--tls-options(-O) Invalid '%s'\n", optarg);
		    exit (EX_USAGE);
		}
		tls_options |= new_tls_opt;
	    }
	    break;

	case 'P':		/* ca dir */
	    caDir = optarg;
	    break;

	case 'r':
	    use_randfile = 1;
	    break;

	case 'u':		/* umask */
	    umask( (mode_t)strtol( optarg, (char **)NULL, 0 ));
	    break;

	case 'U':	/* --check-user -- Check User for upload */
	    checkuser = 1;
	    break;

	case 'H':    /* --help */
	    radmind_usage (stdout, 1, NULL);
	    exit (0);
	    /* UNREACHABLE */

	case 'V' :		/* version */
	    printf( "%s\n", version );
	    exit( 0 );

	case 'v': /* --verbose */
	    verbose ++;
	    break;

	case 'w':  /* --authentication */
	    /*
	     * TLS authlevel
	     *
	     * 0: none
	     * 1: verify server
	     * 2: verify client & server
	     * 3: verify client & server with crl check
	     * 4: client & serv with full-chain crl check
	     */
	    authlevel = atoi( optarg );
	    if (( authlevel < 0 ) || ( authlevel > 4 )) {
	        usageopt_usagef( stderr, 0, progname, main_usage, 80,
				 "\n--authentication(-w) invalid authorization level '%s'\n",
			progname, optarg );
		exit( EX_USAGE );
	    }
	    break;

	case 'x':		/* ca file */
	    caFile = optarg;
	    break;

	case 'y':		/* cert file */
	    cert = optarg;
	    break;

	case 'z':		/* private key */
	    privatekey = optarg;
	    break;

	case 'Z':
#ifdef HAVE_ZLIB
	    max_zlib_level = atoi(optarg);
	    if (( max_zlib_level < 0 ) || ( max_zlib_level > 9 )) {
	      usageopt_usagef (stderr, 0, progname, main_usage, 80,
			       "\n--zlib-level(-Z) Invalid compression level '%s'\n",
			       optarg);
		exit( EX_USAGE);
	    }
	    if ( max_zlib_level > 0 ) {
		rap_extensions++;
	    }
	    break;
#else /* HAVE_ZLIB */
	    usageopt_usagef (stderr, 0, progname, main_usage, 80,
			     "\n--zlib-level(-Z) Zlib not supported ('%s).\n" ,
			     optarg);
	    exit(EX_UNAVAILABLE);
#endif /* HAVE_ZLIB */

	default :
	    err++;
	}
    }

    if ( err || optind != ac ) {
        radmind_usage (stderr, 1, "Too many errors (%d)", err);
	exit(EX_USAGE);
    }

    if ( maxconnections < 0 ) {
        radmind_usage (stderr, 1,
		       "--max-simultaneous(-m) invalid max-connections (%d)\n",
		       maxconnections );
	exit( EX_USAGE );
    }

    if ( checkuser && ( authlevel < 1 )) {
        radmind_usage (stderr, 1, "--check-user(-U) requires auth-level > 0\n" );
	exit( EX_USAGE );
    }

    if (( crlFile || crlDir ) && authlevel < 3 ) {
        radmind_usage(stderr, 1,
		    "--cert-revocation-list(-C) requires auth-level > 2\n" );
	exit( EX_USAGE );
    }

    if ( dontrun ) {
	exit( 0 );
    }

    if ( chdir( radmind_path ) < 0 ) {
        radmind_usage(stderr, 1,
		      "--radmind-directory(-D) -- chdir(\"%s\" failed, errno %d: %s",
		      radmind_path, errno, strerror(errno));
	exit( EX_IOERR );
    }
    /* Create directory structure */
    if ( mkdir( "command", 0750 ) != 0 ) {
	if ( errno != EEXIST ) {
	    fprintf(stderr, 
		    "%s: After chdir(\"%s\"), mkdir(\"command\") failed, errno %d: %s\n", 
		    progname, radmind_path, errno, strerror(errno));
	    exit( EX_IOERR );
	}
    }
    if ( mkdir( "file", 0750 ) != 0 ) {
	if ( errno != EEXIST ) {
	    fprintf(stderr, 
		    "%s: After chdir(\"%s\"), mkdir(\"file\") failed, errno %d: %s\n", 
		    progname, radmind_path, errno, strerror(errno));
	    exit( EX_IOERR );
	}
    }
    if ( mkdir( "special", 0750 ) != 0 ) {
	if ( errno != EEXIST ) {
	    fprintf(stderr, 
		    "%s: After chdir(\"%s\"), mkdir(\"special\") failed, errno %d: %s\n", 
		    progname, radmind_path, errno, strerror(errno));
	    exit( EX_IOERR );
	}
    }
    if ( mkdir( "tmp", 0750 ) != 0 ) {
	if ( errno != EEXIST ) {
	    fprintf(stderr, 
		    "%s: After chdir(\"%s\"), mkdir(\"tmp\") failed, errno %d: %s\n", 
		    progname, radmind_path, errno, strerror(errno));
	    exit( EX_IOERR );
	}
    }
    if ( mkdir( "tmp/file", 0750 ) != 0 ) {
	if ( errno != EEXIST ) {
	    fprintf(stderr, 
		    "%s: After chdir(\"%s\"), mkdir(\"tmp/file\") failed, errno %d: %s\n", 
		    progname, radmind_path, errno, strerror(errno));
	    exit( EX_IOERR );
	}
    }
    if ( mkdir( "tmp/transcript", 0750 ) != 0 ) {
	if ( errno != EEXIST ) {
	    fprintf(stderr, 
		    "%s: After chdir(\"%s\"), mkdir(\"tmp/transcript\") failed, errno %d: %s\n", 
		    progname, radmind_path, errno, strerror(errno));
	    exit( EX_IOERR );
	}
    }
    if ( mkdir( "transcript", 0750 ) != 0 ) {
	if ( errno != EEXIST ) {
	    fprintf(stderr, 
		    "%s: After chdir(\"%s\"), mkdir(\"transcript\") failed, errno %d: %s\n", 
		    progname, radmind_path, errno, strerror(errno));
	    exit( EX_IOERR );
	}
    }

    if ( authlevel != 0 ) {
        if ( tls_server_setup( use_randfile, authlevel, caFile, caDir, crlFile, crlDir, 
			       cert, privatekey ) != 0 ) {
	    exit( EX_SOFTWARE );
	}
    }

    if ( port == 0 ) {
	if (( se = getservbyname( "radmind", "tcp" )) == NULL ) {
	    port = htons( 6222 );
	} else {
	    port = se->s_port;
	}
    }

    /*
     * Set up listener.
     */
    if (( s = socket( PF_INET, SOCK_STREAM, 0 )) < 0 ) {
        fprintf(stderr, 
		"%s: socket (PF_IONET, SOCK_STREAM, 0) failed, errno %d: %s\n", 
		progname, errno, strerror(errno));
	exit( EX_IOERR );
    }
    memset( &sin, 0, sizeof( struct sockaddr_in ));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = b_addr.s_addr;
    sin.sin_port = port;

    trueint = 1;		/* default? */
    if ( setsockopt( s, SOL_SOCKET, SO_REUSEADDR, (void*) &trueint, 
	    sizeof(int)) < 0 ) {
        fprintf(stderr, 
		"%s: setsockopt(%d, SOL_SOCKET, SO_REUSEADDR, ..., %lu) failed, errno %d: %s\n", 
		progname, s, sizeof(int), errno, strerror(errno));
	exit( EX_IOERR );
    }

    if ( bind( s, (struct sockaddr *)&sin, sizeof( struct sockaddr_in )) < 0 ) {
        fprintf(stderr, 
		"%s: bind (%d, .., %lu) failed, errno %d: %s\n", 
		progname, s, sizeof(struct sockaddr_in), errno,  strerror(errno));
	exit( EX_IOERR );
    }
    if ( listen( s, backlog ) < 0 ) {
        fprintf(stderr, 
		"%s: listen (%d, %d) failed, errno %d: %s\n", 
		progname, s, backlog,  errno, strerror(errno));
	exit( EX_IOERR );
    }

    /*
     * Disassociate from controlling tty.
     */
    if ( !debug && !fg ) {
	int		i, dt;

	switch ( fork()) {
	case 0 :
	    if ( setsid() < 0 ) {
		perror( "setsid" );
		exit( EX_OSERR );
	    }
	    dt = getdtablesize();
	    for ( i = 0; i < dt; i++ ) {
		if ( i != s ) {				/* keep socket open */
		    (void)close( i );
		}
	    }
	    if (( i = open( "/", O_RDONLY, 0 )) == 0 ) {
		dup2( i, 1 );
		dup2( i, 2 );
	    }
	    break;

	case -1 :
	    fprintf(stderr, 
		    "%s: fork() failed, errno %d: %s\n", 
		    progname, errno, strerror(errno));
	    exit( EX_OSERR );
	    /* UNREACHABLE */

	default :
	    exit( 0 );
	}
    }

    /*
     * Start logging.
     */
#ifdef ultrix
    openlog( progname, LOG_NOWAIT|LOG_PID );
#else /* ultrix */
    openlog( progname, LOG_NOWAIT|LOG_PID, facility );
#endif /* ultrix */
    setlogmask( LOG_UPTO( level ));

    /* catch SIGHUP */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = hup;
    if ( sigaction( SIGHUP, &sa, &osahup ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( EX_OSERR );
    }

    /* catch SIGUSR1 */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = usr1;
    if ( sigaction( SIGUSR1, &sa, &osausr1 ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( EX_OSERR );
    }

    /* catch SIGCHLD */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = chld;
    if ( sigaction( SIGCHLD, &sa, &osachld ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( EX_OSERR );
    }

    syslog( LOG_INFO, "restart %s", version );
    if (tls_options != 0)  {
        char temp_buff[256];

	syslog (LOG_INFO, "TLS-Options: %s",
		tls_options_to_str( temp_buff, sizeof(temp_buff)-1, 
				    tls_options));
    }
    else {
        syslog( LOG_INFO, "TLS-Options: cleared");
    }

    /*
     * Register as Bonjour service, if requested.
     * We have to wait till we've started 
     * listening for this registration to work.
     */
#ifdef HAVE_DNSSD
    if ( regservice ) {
	dnsreg_err = register_service( &dnssrv, sin.sin_port, dnsreg_callback );
	if ( dnsreg_err != kDNSServiceErr_NoError ) {
	    syslog( LOG_ERR, "Failed to register as a Bonjour service." );
	}
    }
#endif /* HAVE_DNSSD */

    /*
     * Begin accepting connections.
     */
    for (;;) {

        if ( reinit_ssl_signal > 0 ) {

            if ( authlevel != 0 ) {
                if ( tls_server_setup( use_randfile, authlevel, caFile,
				       caDir, crlFile, crlDir, cert, privatekey ) != 0 ) {
                    exit( EX_SOFTWARE );
                }
            }

            reinit_ssl_signal = 0;

            syslog( LOG_NOTICE, "reinitialized SSL context" );
        }

	if ( child_signal > 0 ) {
	    double	utime, stime;

	    child_signal = 0;
	    /* check to see if any children need to be accounted for */
#ifdef HAVE_WAIT4
	    while (( pid = wait4( 0, &status, WNOHANG, &usage )) > 0 )
#else
            while (( pid = wait3(&status, WNOHANG, &usage )) > 0 ) 
#endif
	    {
		connections--;

		/* Print stats */
		utime = usage.ru_utime.tv_sec
		    + 1.e-6 * (double) usage.ru_utime.tv_usec;
		stime = (double) usage.ru_stime.tv_sec
		    + 1.e-6 * (double) usage.ru_stime.tv_usec;
		if ( debug ) {
		    printf( 
			"child %d User time %.3fs, System time %.3fs\n",
			pid, utime, stime );
		} 
		syslog( LOG_ERR, "child %d User time %.3fs, System time %.3fs",
		    pid, utime, stime );

		if ( WIFEXITED( status )) {
		    if ( WEXITSTATUS( status )) {
			if ( debug ) {
			    printf( "child %d exited with %d\n", pid,
				    WEXITSTATUS( status ));
			} else {
			    syslog( LOG_ERR, "child %d exited with %d", pid,
				    WEXITSTATUS( status ));
			}

		    } else {
			syslog( LOG_INFO, "child %d done", pid );
		    }
		} else if ( WIFSIGNALED( status )) {
		    syslog( LOG_ERR, "child %d died on signal %d", pid,
			    WTERMSIG( status ));
		} else {
		    syslog( LOG_ERR, "child %d died", pid );
		}
	    }
	    if ( pid < 0 && errno != ECHILD ) {
		syslog( LOG_ERR, "waitpid: %m" );
		exit( 1 );
	    }
	}

	addrlen = sizeof( struct sockaddr_in );
	if (( fd = accept( s, (struct sockaddr *)&sin, &addrlen )) < 0 ) {
	    if ( errno != EINTR ) {
		syslog( LOG_ERR, "accept: %m" );
	    }
	    continue;
	}

	connections++;

	/* start child */
	switch ( c = fork()) {
	case 0 :
	    close( s );

	    /* reset CHLD, HUP, and SIGUSR1 */
	    if ( sigaction( SIGCHLD, &osachld, 0 ) < 0 ) {
		syslog( LOG_ERR, "sigaction: %m" );
		exit( EX_OSERR );
	    }
	    if ( sigaction( SIGHUP, &osahup, 0 ) < 0 ) {
		syslog( LOG_ERR, "sigaction: %m" );
		exit( EX_OSERR );
	    }
	    if ( sigaction( SIGUSR1, &osausr1, 0 ) < 0 ) {
		syslog( LOG_ERR, "sigaction: %m" );
		exit( EX_OSERR );
	    }

	    exit( cmdloop( fd, &sin ));

	case -1 :
	    close( fd );
	    syslog( LOG_ERR, "fork: %m" );
	    sleep( 10 );
	    break;

	default :
	    close( fd );
	    syslog( LOG_INFO, "child %d for %s", c, inet_ntoa( sin.sin_addr ));

	    break;
	}
    } /* end of for(;;) -- to infinity and beyond! */
    
#ifdef HAVE_DNSSD
    if ( regservice ) 
	DNSServiceRefDeallocate( dnssrv );
#endif /* HAVE_DNSSD */
} /* end of main() */
