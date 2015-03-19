/*
 * Copyright (c) 2003, 2014 by the Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <openssl/evp.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif /* HAVE_ZLIB */

#include <snet.h>

#include "applefile.h"
#include "base64.h"
#include "cksum.h"
#include "connect.h"
#include "argcargv.h"
#include "radstat.h"
#include "code.h"
#include "pathcmp.h"
#include "update.h"
#include "tls.h"
#include "largefile.h"
#include "progress.h"
#include "report.h"
#include "usageopt.h"

char            *progname = "lapply";
int		linenum = 0;
int		cksum = 0;
int		quiet = 0;
int		verbose = 0;
int		dodots = 0;
int		special = 0;
int		network = 1;
int		change = 0;
int		case_sensitive = 1;
int		report = 1;
int		create_prefix = 0;
static filepath_t prepath[ MAXPATHLEN ]  = { 0 };

extern char	*version, *checksumlist;
extern off_t	lsize;
const EVP_MD    *md;
SSL_CTX  	*ctx;

extern char             *caFile, *caDir, *cert, *privatekey;

typedef struct apply_node apply_node_t;

struct apply_node {
    filepath_t         *path;
    int			doline;
    char		*tline;
    filepath_t		*tran;
    apply_node_t        *next;
};

static void             lapply_usage (FILE *out, int verbose);
static apply_node_t 	*apply_node_create( const filepath_t *path, const char *tline,
					    const filepath_t *tran );
static void 		apply_node_free( apply_node_t *ap_node );
static int 		do_line( char *tline, const filepath_t *tran, int present,
				struct stat *st, SNET *sn );

   static apply_node_t *
apply_node_create( const filepath_t *path, const char *tline, const filepath_t *tran )
{
    apply_node_t         *new_ap_node;

    if (( new_ap_node = (apply_node_t *) malloc( sizeof( apply_node_t ))) == NULL) {
	perror( "create_node: malloc" );
	exit( 2 );
    }
    if (( new_ap_node->path = filepath_dup( path )) == NULL ) {
	fprintf( stderr, "create_node: strdup %s: %s\n",
		path, strerror( errno ));
	exit( 2 );
    }
    if ( tran != NULL ) {
	if (( new_ap_node->tran = filepath_dup( tran )) == NULL ) {
	    fprintf( stderr, "apply_node_create: strdup %s: %s\n",
		    path, strerror( errno ));
	    exit( 2 );
	}
    } else {
	new_ap_node->tran = NULL;
    }
    if ( tline != NULL ) {
	if (( new_ap_node->tline = strdup( tline )) == NULL ) {
	    fprintf( stderr, "create_node: strdup: %s: %s\n",
			tline, strerror( errno ));
	    exit( 2 );
	}
	new_ap_node->doline = 1;
    } else {
	new_ap_node->tline = NULL;
	new_ap_node->doline = 0;
    }
    new_ap_node->next = NULL;

    return( new_ap_node );
}

    void 
apply_node_free( apply_node_t *ap_node )
{
    if ( ap_node->tline != NULL ) {
	free( ap_node->tline );
    }
    if ( ap_node->tran != NULL ) {
	free( ap_node->tran );
    }
    free( ap_node->path );
    free( ap_node );
}

    static int
do_line( char *tline, const filepath_t *tran, int present, struct stat *st, SNET *sn )
{
    char                	fstype;
    char        	        *command = "";
    const char                  *d_path;
    ACAV               		*acav;
    int				tac;
    char 	               	**targv;
    struct applefileinfo        afinfo;
    filepath_t 	       		path[ 2 * MAXPATHLEN ];
    filepath_t			temppath[ 2 * MAXPATHLEN ];
    filepath_t			pathdesc[ 2 * MAXPATHLEN ];
    char			cksum_b64[ SZ_BASE64_E( EVP_MAX_MD_SIZE ) ];

    acav = acav_alloc( );

    tac = acav_parse( acav, tline, &targv );
    /* Get argument offset */
    if (( *targv[ 0 ] ==  '+' ) || ( *targv[ 0 ] == '-' )) {
	command = targv[ 0 ];
	targv++;
	tac--;
    }
    if (( d_path = decode( targv[ 1 ] )) == NULL ) {
	fprintf( stderr, "line %d: too long\n", linenum );
	return( 1 );
    } 
    filepath_cpy( path, (filepath_t *) d_path );

    /* DOWNLOAD */
    if ( *command == '+' ) {
	if (( *targv[ 0 ] != 'f' ) && ( *targv[ 0 ] != 'a' )) {
	    fprintf( stderr, "line %d: \"%c\" invalid download type\n",
		    linenum, *targv[ 0 ] );
	    return( 1 );
	}
	strcpy( cksum_b64, targv[ 7 ] );

	if ( special ) {
	  if ( snprintf( (char *) pathdesc, MAXPATHLEN * 2, "SPECIAL %s",
		    targv[ 1 ]) >= ( MAXPATHLEN * 2 )) {
		fprintf( stderr, "SPECIAL %s: too long\n", targv[ 1 ]);
		return( 1 );
	    }
	} else {
	  if ( snprintf( (char *) pathdesc, MAXPATHLEN * 2, "FILE %s %s",
		    tran, targv[ 1 ]) >= ( MAXPATHLEN * 2 )) {
		fprintf( stderr, "FILE %s %s: command too long\n",
		    tran, targv[ 1 ]);
		return( 1 );
	    }
	}
	if ( *targv[ 0 ] == 'a' ) {
	    switch ( retr_applefile( sn, pathdesc, path, temppath, 0600,
		strtoofft( targv[ 6 ], NULL, 10 ), cksum_b64 )) {
	    case -1:
		/* Network problem */
		network = 0;
		return( 1 );
	    case 1:
		return( 1 );
	    default:
		break;
	    }
	} else {
	    switch ( retr( sn, pathdesc, path, temppath, 0600,
		strtoofft( targv[ 6 ], NULL, 10 ), cksum_b64 )) {
	    case -1:
		/* Network problem */
		network = 0;
		return( 1 );
	    case 1:
		return( 1 );
	    default:
		break;
	    }
	}
	if ( radstat( temppath, st, &fstype, &afinfo ) < 0 ) {
	  perror( (char *) temppath );
	    return( 1 );
	}
	/* Update temp file*/
	switch( update( temppath, path, present, 1, st, tac, targv, &afinfo )) {
	case 0:
	    /* rename doesn't mangle forked files */
	  if ( rename( (char *) temppath, (char *) path ) != 0 ) {
		perror( (char *) temppath );
		return( 1 );
	    }
	    break;

	case 2:
	    break;

	default:
	    return( 1 );
	}

    } else { 
	/* UPDATE */
	if ( present ) {
	    if ( radstat( path, st, &fstype, &afinfo ) < 0 ) {
	        perror( (char *) path );
		return( 1 );
	    }
	}
	switch ( update( path, path, present, 0, st, tac, targv, &afinfo )) {
        case 0:
        case 2:	    /* door or socket, can't be created, but not an error */
            break;
        default:
	    return( 1 );
	}
    }
    acav_free( acav ); 
    return( 0 );
}


extern char *optarg;
extern int optind, opterr, optopt;

/*
 * Command-line options
 *
 * Formerly getopt - "%c:Ce:Fh:iInp:P:qru:Vvw:x:y:z:Z:"
 *
 * Remaining opts: ""
 */

static const usageopt_t main_usage[] = 
  {
    { (struct option) { "percentage",   no_argument,       NULL, '%' }, 
     		"Show percentage done progress", NULL }, 

    { (struct option) { "create",    no_argument,       NULL, 'C' },
              "Create missing intermediate directories", NULL},

    { (struct option) { "checksum",     required_argument, NULL, 'c' },
              "specify checksum type",  "checksum-type: [sha1,etc]" },

    { (struct option) { "radmind-directory",  required_argument, NULL, 'D' },
	      "Specifiy the radmind working directory, by default "
      		_RADMIND_PATH, "pathname"},

    { (struct option) { "case-insensitive", no_argument,   NULL, 'I' },
     		"case insensitive when comparing paths", NULL },

    { (struct option) { "line-buffering", no_argument, NULL, 'i' },
	      "Force line buffering", NULL},

    { (struct option) { "no-network", no_argument, NULL, 'n' },
      	      "no network connection will be made, causing only file system removals and updates to be applied. auth-level is implicitly set to 0.", NULL},

    { (struct option) { "event-name", required_argument, NULL, 'e' },
	      "Set event report name (defaults to 'lapply')", "event-name" },

    { (struct option) { "command-file", required_argument, NULL, 'K' },
                "Specify base command file, defaults to '" _RADMIND_COMMANDFILE "'", "command.K" },

    { (struct option) { "random-file",   no_argument,        NULL, 'r' },
	      "use random seed file $RANDFILE if that environment variable is set, $HOME/.rnd otherwise.  See RAND_load_file(3o).", NULL},

    { (struct option) { "force", no_argument, NULL, 'F' },
              "remove all user defined flags for a file if they exist", NULL },

    { (struct option) { "umask",        required_argument,  NULL, 'u' },
	      "specifies the umask for temporary files, by default 0077", "number" },

    { (struct option) { "hostname",     required_argument, NULL, 'h' },
              "Radmind server hostname to contact, defaults to '" _RADMIND_HOST "'", "domain-name" },

    { (struct option) { "tcp-port",      required_argument, NULL, 'p'},
              "TCP port on radmind server to connect to", "tcp-port#"}, 

    { (struct option) { "ca-directory",  required_argument, NULL, 'P' },
	      "Specify where 'ca.pem' can be found.", "pathname"},

    { (struct option) { "authentication",  required_argument, NULL, 'w' },
	      "Specify the authentication level", "number" },

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

    { (struct option) { "quiet", no_argument, NULL, 'q' },
	      "Suppress messages", NULL},

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
   lapply_usage (FILE *out, int verbose)
{
      usageopt_usage (out, verbose, progname,  main_usage,
		      "[ <applicable-transcript> ]", 80);
      return;
} /* End of lapply_usage() */




/*
 * exit values
 * 0 - OKAY
 * 1 - error - system modified
 * 2 - error - no modification
 */

    int
main( int argc, char **argv )
{
    int			c, err = 0;
    unsigned short	port = 0;
    extern int          optind;
    FILE		*f = NULL; 
    char		*host = _RADMIND_HOST;
    const char 		*d_path;
    char		tline[ 2 * MAXPATHLEN ];
    char		targvline[ 2 * MAXPATHLEN ];
    filepath_t		path[ 2 * MAXPATHLEN ];
    filepath_t		transcript[ 2 * MAXPATHLEN ] = { 0 };
    struct applefileinfo	afinfo;
    int			tac, present, len;
    char		**targv;
    char		*command = "";
    char		fstype;
    struct stat		st;
    apply_node_t	*ap_head = NULL,
      			*new_ap_node,
      			*ap_node;
    ACAV		*acav;
    SNET		*sn = NULL;
    int			authlevel = _RADMIND_AUTHLEVEL;
    int			force = 0;
    int			use_randfile = 0;
    char	        **capa = NULL;		/* capabilities */
    char		* event = "lapply";	/* report event type */
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
	switch( c ) {
	case '%':
	    showprogress = 1;
	    break;

	case 'c':
            OpenSSL_add_all_digests();
            md = EVP_get_digestbyname( optarg );
            if ( !md ) {
                fprintf( stderr, "%s: unsupported checksum\n", optarg );
                exit( 2 );
            }
            cksum = 1;
            break;

	case 'C':
	    create_prefix = 1;
	    break;

	case 'e':		/* set the event label for reporting */
	    event = optarg;
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

	case 'I':
	    case_sensitive = 0;
	    break;
	
	case 'n':
	    network = 0;
	    break;

	case 'p':
	    /* connect.c handles things if atoi returns 0 */
	    port = htons( atoi( optarg ));
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

        case 'u' :              /* umask */
            umask( (mode_t)strtol( optarg, (char **)NULL, 0 ));
            break;

	case 'V':
	    printf( "%s\n", version );
	    printf( "%s\n", checksumlist );
	    exit( 0 );

	case 'H': /* --help */
	    lapply_usage (stdout, 1);
	    exit (0);
	    /* UNREACHABLE */

	case 'v':
	    verbose = 1;
	    logger = v_logger;
	    if ( isatty( fileno( stdout ))) {
		dodots = 1;
	    }
	    break;

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

	case '?':
	    err++;
	    break;

	default:
	    err++;
	    break;
	}
    }

    if (( host == NULL ) &&  network ) {
	err++;
    }

    if ( argc - optind == 0 ) {
	showprogress = 0;
	f = stdin; 
    } else if ( argc - optind == 1 ) {
	if (( f = fopen( argv[ optind ], "r" )) == NULL ) { 
	    perror( argv[ optind ]);
	    exit( 2 );
	}
	if ( showprogress ) {
	    lsize = applyloadsetsize( f );
	}
    } else {
	err++;
    }

    if ( quiet && ( verbose || showprogress )) {
	err++;
    }
    if ( verbose && showprogress ) {
	err++;
    }

    if ( err ) {
        lapply_usage (stderr, 0);
	exit( 2 );
    }

    if ( !network ) {
	authlevel = 0;
    }

    if ( authlevel != 0 ) {
        if ( tls_client_setup( use_randfile, authlevel, caFile, caDir, cert, 
                privatekey ) != 0 ) {
            /* error message printed in tls_setup */
            exit( 2 );
        }
    }

    if ( network ) {
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

	/* Turn off reporting if server doesn't support it */
	if ( check_capability( "REPO", capa ) == 0 ) {
	    report = 0;
	}
    } else {
	if ( !quiet ) printf( "No network connection\n" );
    }

    acav = acav_alloc( );

    while ( fgets( tline, MAXPATHLEN, f ) != NULL ) {
	linenum++;

	/* Check line length */
	len = strlen( tline );
        if (( tline[ len - 1 ] ) != '\n' ) {
	    fprintf( stderr, "%s: line %d: line too long\n", tline, linenum  );
	    goto error2;
	}
	if ( strlen( tline ) >= MAXPATHLEN * 2 ) {
	    fprintf( stderr, "line %d: too long\n", linenum );
	    goto error2;
	}
	strcpy( targvline, tline );

	tac = acav_parse( acav, targvline, &targv );

        /* Skip blank lines and comments */
        if (( tac == 0 ) || ( *targv[ 0 ] == '#' )) {
	    continue;
        }

	if ( tac == 1 ) {
	    filepath_ncpy( transcript, (filepath_t *) targv[ 0 ], sizeof(transcript)-1 );
	    len = filepath_len( transcript );
	    if ( transcript[ len - 1 ] != ':' ) { 
		fprintf( stderr, "%s: line %d: invalid transcript name\n",
		    transcript, linenum );
		goto error2;
	    }
	    transcript[ len - 1 ] = '\0';
	    if ( filepath_cmp( transcript, (filepath_t *) "special.T" ) == 0 ) {
		special = 1;
	    } else {
		special = 0;
	    }
	    if ( verbose ) printf( "Transcript: %s\n", transcript );
	    continue;
	}

	/* Get argument offset */
	if (( *targv[ 0 ] ==  '+' ) || ( *targv[ 0 ] == '-' )) {

	    /* Check for transcript name on download */
	    if ( *targv[ 0 ] ==  '+' ) {
	        if ( filepath_cmp( transcript, (filepath_t *) "" ) == 0 ) {
		    fprintf( stderr, "line %d: no transcript indicated\n",
			linenum );
		    goto error2;
		}
	    }

	    command = targv[ 0 ];
	    targv++;
	    tac--;
	}

	if (( *command == '+' ) && ( !network )) {
	    continue;
	}

	if (( d_path = decode( targv[ 1 ] )) == NULL ) {
	    fprintf( stderr, "line %d: too long\n", linenum );
	    return( 1 );
	} 
	filepath_ncpy( path, (filepath_t *) d_path, sizeof (path)-1 );

	/* Check transcript order */
	if ( *prepath != '\0' ) {
	    if ( pathcasecmp( path, prepath, case_sensitive ) <= 0 ) {
		fprintf( stderr, "line %d: bad sort order\n", linenum );
		goto error2;
	    }
	}
	if ( filepath_len( path ) >= MAXPATHLEN ) {
	    fprintf( stderr, "%s: line %d: path too long\n",
		    transcript, linenum );
	    goto error2;
	}
	filepath_cpy( prepath, path );

	/* Do type check on local file */
	switch ( radstat( path, &st, &fstype, &afinfo )) {
	case 0:
	    present = 1;
	    break;
	case 1:
	    fprintf( stderr, "%s is of an unknown type\n", path );
	    goto error2;
	default:
	    if ( errno == ENOENT ) { 
		present = 0;
	    } else {
	        perror( (char *) path );
		goto error2;
	    }
	    break;
	}

#ifdef UF_IMMUTABLE
#define CHFLAGS	( UF_IMMUTABLE | UF_APPEND | SF_IMMUTABLE | SF_APPEND )

	if ( present && force && ( st.st_flags & CHFLAGS )) {
	    if ( chflags( path, st.st_flags & ~CHFLAGS ) < 0 ) {
		perror( path );
		goto error2;
	    }
	}
#endif /* UF_IMMUTABLE */

	if ( *command == '-'
		|| ( present && fstype != *targv[ 0 ] )) {
	    if ( fstype == 'd' ) {
dirchecklist:
		if ( ap_head == NULL ) {
		    /* Add dir to empty list */
		    if ( present && fstype != *targv[ 0 ] ) {
		    	ap_head = apply_node_create( path, tline, transcript );
		    } else {
			/* just a removal, no context necessary */
			ap_head = apply_node_create( path, NULL, NULL );
		    }
		    continue;
		} else {
		    if ( ischildcase( path, ap_head->path, case_sensitive )) {
			/* Add dir to list */
			if ( present && fstype != *targv[ 0 ] ) {
			    new_ap_node = apply_node_create( path, tline, transcript );
			} else {
			    new_ap_node = apply_node_create( path, NULL, NULL );
			}
			new_ap_node->next = ap_head;
			ap_head = new_ap_node;
		    } else {
			/* remove ap_head */
		        if ( rmdir( (char *) ap_head->path ) != 0 ) {
			    perror( (char *) ap_head->path );
			    goto error2;
			}
			if ( !quiet && !showprogress ) {
			    printf( "%s: deleted\n", ap_head->path );
			}
			if ( showprogress ) {
			    progressupdate( PROGRESSUNIT, ap_head->path );
			}
			ap_node = ap_head;
			ap_head = ap_node->next;
			if ( ap_node->doline ) {
			    if ( do_line( ap_node->tline, ap_node->tran, 0,
					&st, sn ) != 0 ) {
				goto error2;
			    }
			    change = 1;
			}
			apply_node_free( ap_node );
			goto dirchecklist;
		    }
		}
	    } else {
filechecklist:
		if ( ap_head == NULL ) {
		    if ( unlink( (char *) path ) != 0 ) {
		        perror( (char *) path );
			goto error2;
		    }
		    if ( !quiet && !showprogress ) {
			printf( "%s: deleted\n", path );
		    }
		    if ( showprogress ) {
			progressupdate( PROGRESSUNIT, path );
		    }
		} else {
		    if ( ischildcase( path, ap_head->path, case_sensitive )) {
		        if ( unlink( (char *) path ) != 0 ) {
			    perror( (char *) path );
			    goto error2;
			}
			if ( !quiet && !showprogress ) {
			    printf( "%s: deleted\n", path );
			}
			if ( showprogress ) {
			    progressupdate( PROGRESSUNIT, path );
			}
		    } else {
			/* remove ap_head */
		        if ( rmdir( (char *) ap_head->path ) != 0 ) {
			    perror( (char *) ap_head->path );
			    goto error2;
			}
			if ( !quiet && !showprogress ) {
			    printf( "%s: deleted\n", ap_head->path );
			}
			if ( showprogress ) {
			    progressupdate( PROGRESSUNIT, ap_head->path );
			}
			ap_node = ap_head;
			ap_head = ap_node->next;
			if ( ap_node->doline ) {
			    if ( do_line( ap_node->tline, ap_node->tran, 0,
					&st, sn ) != 0 ) {
				goto error2;
			    }
			    change = 1;
			}
			apply_node_free( ap_node );
			goto filechecklist;
		    }
		}
	    }
	    present = 0;

	    if ( *command == '-' ) {
		continue;
	    }
	}

	/* Minimize remove list */
	while ( ap_head != NULL && !ischildcase( path, ap_head->path,
		case_sensitive )) {
	    /* remove ap_head */
	    if ( rmdir( (char *) ap_head->path ) != 0 ) {
	        perror( (char *) ap_head->path );
		goto error2;
	    }
	    if ( !quiet && !showprogress ){
		printf( "%s: deleted\n", ap_head->path );
	    }
	    if ( showprogress ) {
		progressupdate( PROGRESSUNIT, ap_head->path );
	    }
	    ap_node = ap_head;
	    ap_head = ap_node->next;
	    if ( ap_node->doline ) {
		if ( do_line( ap_node->tline, ap_node->tran, 0, &st, sn ) != 0 ) {
		    goto error2;
		}
		change = 1;
	    }
	    apply_node_free( ap_node );
	}

	if ( do_line( tline, transcript, present, &st, sn ) != 0 ) {
	    goto error2;
	}
	change = 1;
    }

    /* Clear out remove list */ 
    while ( ap_head != NULL ) {
	/* remove ap_head */
        if ( rmdir( (char *) ap_head->path ) != 0 ) {
	    perror( (char *) ap_head->path );
	    goto error2;
	}
	if ( !quiet && !showprogress ) printf( "%s: deleted\n", ap_head->path );
	if ( showprogress ) {
	    progressupdate( PROGRESSUNIT, ap_head->path );
	}
	ap_node = ap_head;
	ap_head = ap_node->next;
	if ( ap_node->doline ) {
	    if ( do_line( ap_node->tline, ap_node->tran, 0, &st, sn ) != 0 ) {
		goto error2;
	    }
	    change = 1;
	}
	apply_node_free( ap_node );
    }
    acav_free( acav ); 
    
    if ( fclose( f ) != 0 ) {
	perror( argv[ optind ] );
	goto error1;
    }

    if ( network ) {
	if ( report ) {
	    if ( report_event( sn, event,
		    "Changes applied successfully" ) != 0 ) {
		fprintf( stderr, "warning: could not report event\n" );
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

error2:
    fclose( f );
error1:
    if ( network ) {
#ifdef HAVE_ZLIB
	if( verbose && zlib_level < 0 ) print_stats(sn);
#endif /* HAVE_ZLIB */
	if ( change ) {
	    if ( network && report ) {
		if ( report_event( sn, event, "Error, changes made" ) != 0 ) {
		    fprintf( stderr, "warning: could not report event\n" );
		}
	    }
	} else {
	    if ( network && report ) {
		if ( report_event( sn, event,
			"Error, no changes made" ) != 0 ) {
		    fprintf( stderr, "warning: could not report event\n" );
		}
	    }
	}
	closesn( sn );
    }
    if ( change ) {
	exit( 1 );
    } else {
	exit( 2 );
    }
}
