/*
 * Copyright (c) 2003, 2014 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/evp.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif /* HAVE_ZLIB */

#include <snet.h>

#include "applefile.h"
#include "radstat.h"
#include "base64.h"
#include "cksum.h"
#include "connect.h"
#include "argcargv.h"
#include "code.h"
#include "tls.h"
#include "largefile.h"
#include "progress.h"
#include "usageopt.h"

/*
 * STOR
 * C: STOR <path-decription> "\r\n"
 * S: 350 Storing file "\r\n"
 * C: <size> "\r\n"
 * C: <size bytes of file data>
 * C: ".\r\n"
 * S: 250 File stored "\r\n"
 */

int		verbose = 0;
int		debug = 0;
int		dodots = 0;
int		cksum = 0;
int		quiet = 0;
int		linenum = 0;
int		force = 0;
char           *progname = "lcreate";
extern off_t	lsize;
extern char	*version;
extern char	*checksumlist;
extern struct timeval   timeout;   
const EVP_MD    *md;
SSL_CTX  	*ctx;

extern char *optarg;
extern int optind, opterr, optopt;

/*
 * Command-line options
 *
 * Formerly getopt - "%c:Fh:ilnNp:P:qrt:TU:vVw:x:y:z:Z:"
 *
 * Remaining "FlnNqrt:TU:vVw:x:y:z:Z:"
 */


static const usageopt_t main_usage[] = 
  {
    { (struct option) { "progress", no_argument,  NULL, '%' },
      "Progress output", NULL },

    { (struct option) { "checksum",     required_argument, NULL, 'c' },
      "specify checksum type",  "checksum-type: [sha1,etc]" },

    { (struct option) { "hostname",     required_argument, NULL, 'h' },
      "Radmind server hostname to contact, defaults to '" _RADMIND_HOST "'", "domain-name" },

    { (struct option) { "tcp-port",      required_argument, NULL, 'p'},
      "TCP port on radmind server to connect to", "tcp-port#"}, 

    { (struct option) { "ca-directory",  required_argument, NULL, 'P' },
	      "Specify where 'ca.pem' can be found.", "pathname"},

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

    { (struct option) { "ignore-file-size", no_argument, NULL, 'F' },
	      "Ignore file size differences", NULL},

    { (struct option) { "transcript-only", no_argument, NULL, 'T' },
      "Upload the transcript only, and not the corresponding files", NULL },

    { (struct option) { "transcript-name", required_argument, NULL, 't' },
      "specifies the name under which the transcript will be stored when saved on the server", "<name>" },

    { (struct option) { "verify-only", no_argument, NULL, 'n' },
	      "Don't upload any files or transcripts.  Verify all files in the transcript exist in the filesystem and have the size listed in the transcript", NULL},

    { (struct option) { "negative", no_argument, NULL, 'N' },
	      "uploads a negative transcript then uploads all corresponding files as zero length.", NULL},

    { (struct option) { "line-buffering", no_argument, NULL, 'i' },
	      "Force line buffering", NULL},

    { (struct option) { "authentication",  required_argument, NULL, 'w' },
              "Specify the authentication level, default " STRINGIFY(_RADMIND_AUTHLEVEL), "number" },

    { (struct option) { "login", no_argument, NULL, 'l' },
	      "Turn on user authentication.  Requires a TLS.", NULL},

    { (struct option) { "user", required_argument, NULL, 'U' },
	      "Specifes the user for user authentication.  By default, the login name returned by getlogin() will be used.", "username" },

    { (struct option) { "random-file",   no_argument,        NULL, 'r' },
	      "use random seed file $RANDFILE if that environment variable is set, $HOME/.rnd otherwise.  See RAND_load_file(3o).", NULL},
    { (struct option) { "debug", no_argument, NULL, 'd' },
      		"Raise debugging level to see what's happening", NULL},

    { (struct option) { "verbose", no_argument, NULL, 'v' },
      		"Turn on verbose mode", NULL },

    { (struct option) { "quiet", no_argument, NULL, 'q' },
	      "Suppress messages", NULL},

    { (struct option) { "help",         no_argument,       NULL, 'H' },
     		"This message", NULL },
    
    { (struct option) { "version",      no_argument,       NULL, 'V' },
     		"show version and list of supported checksums in order of preference", NULL },
    
    { (struct option) { "tls-options",	required_argument,   NULL, 'O' },
              "Set OpenSSL/TLS options (like NO_SSLv3), or clear (clear)", NULL }, 

    { (struct option) { "tls-cipher-suite", required_argument, NULL, 'S' },
              "Set OpenSSL/TLS Cipher Suite", "string" },


    /* End of list */
    { (struct option) {(char *) NULL, 0, (int *) NULL, 0}, (char *) NULL, (char *) NULL}
  }; /* end of main_usage[] */

/* Main */

extern char             *caFile, *caDir, *cert, *privatekey;

    int
main( int argc, char **argv )
{
    int			c,
      			err = 0,
      			tac, 
      			network = 1,
      			len = 0,
      			rc,
      			negative = 0,
      			tran_only = 0,
      			respcount = 0;
    unsigned short	port = 0;
    extern int		optind;
    SNET          	*sn = NULL;
    char		type,
      			tline[ 2 * MAXPATHLEN ],
      			cksumval[ SZ_BASE64_E( EVP_MAX_MD_SIZE ) ];
    char		*tname = NULL,
		        *host = _RADMIND_HOST,
      			*p;
    filepath_t  	pathdesc[ 2 * MAXPATHLEN ];
    const char		*d_path = NULL;
    char		**targv;
    extern char		*optarg;
    struct timeval	tv;
    FILE		*tran = NULL;
    struct stat		st;
    struct applefileinfo	afinfo;
    int                 authlevel = _RADMIND_AUTHLEVEL;
    int                 use_randfile = 0;
    int                 login = 0;
    char                *user = NULL;
    char                *password = NULL;
    char               **capa = NULL; /* capabilities */
    int                  optndx = 0;
    struct option       *main_opts;
    char                *main_optstr;

    /* Get our name from argv[0] */
    for (main_optstr = argv[0]; *main_optstr; main_optstr++) {
        if (*main_optstr == '/')
	    progname = main_optstr+1;
    }

    main_opts = usageopt_option_new (main_usage, &main_optstr);

    while (( c = getopt_long (argc, argv, main_optstr, main_opts, &optndx)) != -1) {
	switch( c ) {
	case '%':
	    showprogress = 1;
	    break;

        case 'c':
            OpenSSL_add_all_digests();
            md = EVP_get_digestbyname( optarg );
            if ( !md ) {
	        usageopt_usage (stderr, 0 /* not verbose */, progname,  main_usage,
				"<transcript>", 80);
	        fprintf( stderr, "%s: unsupported checksum '%s'\n", progname,
			 optarg );
                exit( 2 );
            }
            cksum = 1;
            break;

	case 'F':
	    force = 1;
	    break;

	case 'h':
	    host = optarg; 
	    break;

	case 'i':
	    setvbuf( stdout, ( char * )NULL, _IOLBF, 0 );
	    break;

        case 'l':
            login = 1;
            break;

	case 'n':
	    network = 0;
	    break;

	case 'N':
	    negative = 1;
	    break;

	case 'p':
	    /* connect.c handles things if atoi returns 0 */
            port = htons( atoi( optarg ));
	    break;

	case 'O':  /* --tls-options */
	    if ((strcasecmp(optarg, "none") == 0) || (strcasecmp(optarg, "clear") == 0)) {
	        tls_options = 0;
	    }
	    else {
	        long new_tls_opt;

		new_tls_opt = tls_str_to_options(optarg, tls_options);
		if (new_tls_opt == 0) {
		    fprintf (stderr, 
			     "%s: Invalid --tls-options(-O) '%s'\n", progname, optarg);
		    exit (2);
		}
		tls_options = new_tls_opt;
	    }
	    break;

	case 'S':   /* --tls-cipher-suite <string> */
	    if ((strcasecmp(optarg, "none") == 0) || (strcasecmp(optarg, "clear") == 0)) {
	         tls_cipher_suite = "DEFAULT";
	    } 
	    else if (strcasecmp(optarg, "default") == 0) {
	         tls_cipher_suite =  RADMIND_DEFAULT_TLS_CIPHER_SUITES;
	    }
	    else {
	         char *new;
		 size_t len = strlen (optarg) + strlen(RADMIND_DEFAULT_TLS_CIPHER_SUITES) + 2;
		 
		 new = (char *) malloc (len);
		 strcpy (new, RADMIND_DEFAULT_TLS_CIPHER_SUITES);
		 strcat (new, ":");
		 strcat (new, optarg);

		 tls_cipher_suite = new;
	    }
	    break;

        case 'P' :              /* ca dir */
            caDir = optarg;
            break;

	case 'q':
	    quiet = 1;
	    break;

	case 'r':
	    use_randfile = 1;
	    break;

	case 't':
	    tname = optarg;
	    break;

	case 'T':
	    tran_only = 1;
	    break;

        case 'U':
            user = optarg;
            break;

	case 'd':
	    debug++;
	    break;

	case 'v':
	    verbose = 1;
	    logger = v_logger;
	    if ( isatty( fileno( stdout ))) {
		dodots = 1;
	    }

	    break;

	case 'V':
	    printf( "%s\n", version );
	    printf( "%s\n", checksumlist );
	    exit( 0 );

        case 'w' :              /* authlevel 0:none, 1:serv, 2:client & serv */
            authlevel = atoi( optarg );
            if (( authlevel < 0 ) || ( authlevel > 2 )) {
                fprintf( stderr, "%s: invalid authorization level\n",
                        optarg );
                exit( 1 );
            }
            break;

        case 'x' :              /* ca file */
            caFile = optarg;
            break;

        case 'y' :              /* cert file */
            cert = optarg;
            break;

        case 'z' :              /* private key */
            privatekey = optarg;
            break;

        case 'Z':
#ifdef HAVE_ZLIB
            zlib_level = atoi(optarg);
            if (( zlib_level < 0 ) || ( zlib_level > 9 )) {
                fprintf( stderr, "Invalid compression level\n" );
                exit( 1 );
            }
            break;
#else /* HAVE_ZLIB */
            fprintf( stderr, "Zlib not supported.\n" );
            exit( 1 );
#endif /* HAVE_ZLIB */

	case 'H':  /* --help */
	  usageopt_usage (stdout, 1 /* verbose */, progname,  main_usage,
			  "<transcript-file>", 80);
	  exit (0);


	case '?':
	    err++;
	    break;
	default:
	    err++;
	    break;
	}
    }

    if ( quiet && ( showprogress || verbose )) {
	err++;
    }
    if ( showprogress && verbose ) {
	err++;
    }

    if ( err || ( argc - optind != 1 ))   {
        usageopt_usage (stderr, 0 /* not verbose */, progname,  main_usage,
			"<creatable-transcript>", 80);
	exit( 2 );
    }

    if ( ! tran_only ) {
	if (( tran = fopen( argv[ optind ], "r" )) == NULL ) {
	    perror( argv[ optind ] );
	    exit( 2 );
	}
    }

    if ( network ) {

	/*
	 * Pipelining creates an annoying problem: the server might
	 * have closed our connection a long time before we get around
	 * to reading an error.  In the meantime, we will do a lot
	 * of writing, which may cause us to be killed.
	 */
	if ( signal( SIGPIPE, SIG_IGN ) == SIG_ERR ) {
	    perror( "signal" );
	    exit( 2 );
	}

	if ( authlevel != 0 ) {
	    if ( tls_client_setup( use_randfile, authlevel, caFile, caDir,
		    cert, privatekey ) != 0 ) {
		/* error message printed in tls_setup */
		exit( 2 );
	    }
	}

	/* no name given on command line, so make a "default" name */
	if ( tname == NULL ) {
	    tname = argv[ optind ];
	    /* strip leading "/"s */
	    if (( p = strrchr( tname, '/' )) != NULL ) {
		tname = ++p;
	    }
	}

	if (( sn = connectsn( host, port )) == NULL ) {
	    exit( 2 );
	}
	if (( capa = get_capabilities( sn )) == NULL ) { 
		exit( 2 );
	}           

        if ( authlevel != 0 ) {
            if ( tls_client_start( sn, host, authlevel ) != 0 ) {
                /* error message printed in tls_cleint_starttls */
                exit( 2 );
            }
        }

#ifdef HAVE_ZLIB
	/* Enable compression */
	if ( zlib_level > 0 ) {
	    if ( negotiate_compression( sn, capa ) != 0 ) {
		    exit( 2 );
	    }
	}
#endif /* HAVE_ZLIB */
		
        if ( login ) {
	    char		*line;

	    if ( authlevel < 1 ) {
		fprintf( stderr, "login requires TLS\n" );
		exit( 2 );
	    }
            if ( user == NULL ) {
                if (( user = getlogin()) == NULL ) {
		    perror( "getlogin" );
                    exit( 2 );
                } 
            }

	    printf( "user: %s\n", user );
	    if (( password = getpass( "password:" )) == NULL ) {
		fprintf( stderr, "Invalid null password\n" );
		exit( 2 );
	    }

	    len = strlen( password );
	    if ( len == 0 ) {
		fprintf( stderr, "Invalid null password\n" );
		exit( 2 );
	    }

            if ( verbose ) printf( ">>> LOGIN %s\n", user );
            if ( snet_writef( sn, "LOGIN %s %s\n", user, password ) < 0 ) {
                fprintf( stderr, "login %s failed: 1-%s\n", user, 
                    strerror( errno ));
                exit( 2 );                       
            }                            

	    /* clear the password from memory */
	    memset( password, 0, len );

	    tv = timeout;
	    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
		fprintf( stderr, "login %s failed: 2-%s\n", user,
		    strerror( errno ));
		exit( 2 );
	    }
	    if ( *line != '2' ) {
		fprintf( stderr, "%s\n", line );
		return( 1 );
	    }

        }

	if ( cksum ) {
	  if ( do_cksum( (filepath_t *) argv[ optind ], cksumval ) < 0 ) {
		perror( tname );
		exit( 2 );
	    }
	}

	if ( snprintf( (char *) pathdesc, MAXPATHLEN * 2, "STOR TRANSCRIPT %s",
		tname ) >= ( MAXPATHLEN * 2 )) {
	    fprintf( stderr, "STOR TRANSCRIPT %s: path description too long\n",
		tname );
	}

	/* Get transcript size */
	if ( stat( argv[ optind ], &st ) != 0 ) {
	    perror( argv[ optind ] );
	    exit( 2 );
	}

	if ( ! tran_only ) {
	    lsize = loadsetsize( tran );
	}
	lsize += st.st_size;

	respcount += 2;
	if (( rc = stor_file( sn, pathdesc, (filepath_t *) argv[ optind ], st.st_size,
		cksumval )) <  0 ) {
	    goto stor_failed;
	}

	if ( tran_only ) {	/* don't upload files */
	    goto done;
	}
    }

    while ( fgets( tline, MAXPATHLEN, tran ) != NULL ) {
	if ( network && respcount > 0 ) {
	    tv.tv_sec = 0;
	    tv.tv_usec = 0;
	    if ( stor_response( sn, &respcount, &tv ) < 0 ) {
		exit( 2 );
	    }
	}

	len = strlen( tline );
	if (( tline[ len - 1 ] ) != '\n' ) {
	    fprintf( stderr, "%s: line too long\n", tline );
	    exit( 2 );
	}
	linenum++;
	targv = (char **) NULL; /* Saftey */
	tac = argcargv( tline, &targv );

	/* skips blank lines and comments */
	if (( tac == 0 ) || ( *targv[ 0 ] == '#' )) {
	    continue;
	}

	if ( tac == 1 ) {
	    fprintf( stderr, "Appliable transcripts cannot be uploaded.\n" );
	    exit( 2 );
	}
	if ( *targv[ 0 ] == 'f' || *targv[ 0 ] == 'a' ) {
	    if ( tac != 8 ) {
		fprintf( stderr, "line %d: invalid transcript line\n",
			linenum );
		exit( 2 );
	    }

	    if (( d_path = decode( targv[ 1 ] )) == NULL ) {
		fprintf( stderr, "line %d: path too long\n", linenum );
		return( 1 );
	    } 

	    if ( !negative ) {
		/* Verify transcript line is correct */
	        if ( radstat( (filepath_t *) d_path, &st, &type, &afinfo ) != 0 ) {
		    perror( d_path );
		    exit( 2 );
		}
		if ( *targv[ 0 ] != type ) {
		    fprintf( stderr, "line %d: file type wrong\n", linenum );
		    exit( 2 );
		}
	    }

	    if ( !network ) {
		/* Check size */
	        if ( radstat( (filepath_t *) d_path, &st, &type, &afinfo ) != 0 ) {
		    perror( d_path );
		    exit( 2 );
		}
		if ( st.st_size != strtoofft( targv[ 6 ], NULL, 10 )) {
		    fprintf( stderr, "line %d: size in transcript does "
			"not match size of file\n", linenum );
		    exit( 2 );
		}
		if ( cksum ) {
		    if ( *targv[ 0 ] == 'f' ) {
		        if ( do_cksum( (filepath_t *) d_path, cksumval ) < 0 ) {
			    perror( d_path );
			    exit( 2 );
			}
		    } else {
			/* apple file */
		        if ( do_acksum( (filepath_t *) d_path, cksumval, &afinfo ) < 0  ) {
			    perror( d_path );
			    exit( 2 );
			}
		    }
		    if ( strcmp( cksumval, targv[ 7 ] ) != 0 ) {
			fprintf( stderr,
			    "line %d: checksum listed in transcript wrong\n",
			    linenum );
			return( -1 );
		    }
		} else {
		    if ( access( d_path,  R_OK ) < 0 ) {
			perror( d_path );
			exit( 2 );
		    }
		}
	    } else {
	        if ( snprintf( (char *) pathdesc, MAXPATHLEN * 2, "STOR FILE %s %s", 
			tname, targv[ 1 ] ) >= ( MAXPATHLEN * 2 )) {
		    fprintf( stderr, "STOR FILE %s %s: path description too"
			    " long\n", tname, d_path );
		    exit( 2 );
		}

		if ( negative ) {
		    if ( *targv[ 0 ] == 'a' ) {
		        rc = n_stor_applefile( sn, pathdesc, (filepath_t *) d_path );
		    } else {
		        rc = n_stor_file( sn, pathdesc, (filepath_t *) d_path );
		    }
		    respcount += 2;
		    if ( rc < 0 ) {
			goto stor_failed;
		    }

		} else {
		    if ( *targv[ 0 ] == 'a' ) {
		        rc = stor_applefile( sn, pathdesc, (filepath_t *) d_path,
			    strtoofft( targv[ 6 ], NULL, 10 ), targv[ 7 ],
			    &afinfo );
		    } else {
		        rc = stor_file( sn, pathdesc, (filepath_t *) d_path, 
			    strtoofft( targv[ 6 ], NULL, 10 ), targv[ 7 ]); 
		    }
		    respcount += 2;
		    if ( rc < 0 ) {
			goto stor_failed;
		    }
		}
	    }
	}
    }

done:
    if ( network ) {
	while ( respcount > 0 ) {
	    if ( stor_response( sn, &respcount, NULL ) < 0 ) {
		exit( 2 );
	    }
	}
	if (( closesn( sn )) != 0 ) {
	    fprintf( stderr, "cannot close sn\n" );
	    exit( 2 );
	}
#ifdef HAVE_ZLIB
	if ( verbose && zlib_level > 0 ) print_stats( sn );
#endif /* HAVE_ZLIB */
    }

    exit( 0 );

stor_failed:
    if ( dodots ) { putchar( (char)'\n' ); }
    while ( respcount > 0 ) {
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	if ( stor_response( sn, &respcount, &tv ) < 0 ) {
	    exit( 2 );
	}
    }
    exit( 2 );
}
