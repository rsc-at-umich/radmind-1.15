/*
 * Copyright (c) 2003, 2014 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/evp.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif /* HAVE_ZLIB */

#include <snet.h>

#include "applefile.h"
#include "connect.h"
#include "argcargv.h"
#include "list.h"
#include "pathcmp.h"
#include "tls.h"
#include "transcript.h"
#include "code.h"
#include "wildcard.h"
#include "usageopt.h"

char	               *progname = "lfdiff";
extern struct timeval	timeout;
int			verbose = 0;
extern int		debug;
int			dodots = 0;
int			linenum = 0;
int			cksum = 0;
int             	case_sensitive = 1;
int			tran_format = -1; 
int			create_prefix = 0;
int			quiet = 1;
int			excluded = 0;
const EVP_MD    	*md;
SSL_CTX  		*ctx;

extern char             *caFile, *caDir, *cert, *privatekey;

static void verbose_transcript_header (const char *file, const struct transcript *tran, int *p_msg);
static void debug_transcript_header (FILE *out, const char *file, const struct transcript *tran, int *p_msg);

   static void
verbose_transcript_header  (const char *file, const struct transcript *tran, int *p_msg)
{
  if (p_msg == (int *) NULL)
    return;

  if (!*p_msg)
    printf ("#  File: '%s' from t:['%s'] k:['%s'] line %d\n#\t",
	    file, tran->t_shortname, tran->t_kfile, tran->t_linenum);
  else
    printf (", ");
  
  (*p_msg)++;

  return;
} /* end of verbose_transcript_header() */


   static void
debug_transcript_header  (FILE *out, const char *file, const struct transcript *tran, int *p_msg)
{
  if (p_msg == (int *) NULL)
    return;


  if (!*p_msg)
    fprintf (out, "*debug: File: '%s' from t:['%s'] k:['%s'] line %d\n*debug: ",
	     file, tran->t_shortname, tran->t_kfile, tran->t_linenum);
  else
    fprintf (out, ", ");
  
  (*p_msg)++;

  return;
} /* end of debug_transcript_header() */



   static struct transcript *
precedent_transcript(const unsigned char *kfile, const unsigned char *file, int where )
{
    extern struct transcript	*tran_head;
    struct stat		file_stat;
    struct transcript	*tran;
    int			cmp = 0;

    /* verify that file exists on the local system */
    memset ((void *) &file_stat, 0, sizeof(file_stat));
    if ( lstat( (char *) file, &file_stat ) < 0 ) {
        perror( (char *) file );
	exit( 2 );
    }

    /* initialize important transcript bits */
    edit_path = APPLICABLE;
    transcript_init( kfile, where );
    outtran = stdout;


    if (debug > 0)
    	fprintf (stderr, "*debug: Searching for '%s' in transcripts\n", file);

    /* check exclude list */
    if ( t_exclude( file )) {
    	if (debug )
	    fprintf (stderr, "*debug: But it's excluded.\n");

	excluded = 1;
	return( NULL );
    }

    for ( tran = tran_head; tran != (struct transcript *) NULL; tran = tran->t_next ) {

	/* Skip NULL/empty transcripts */
	if ( tran->t_eof ) {
	    if (debug > 1)
	    	fprintf (stderr, "*debug: empty transcript t:['%s'] from k:['%s'] line %d, ID=%u\n",
			tran->t_shortname, tran->t_kfile, tran->t_linenum, tran->id);
	    continue;
	}

        while (( cmp = pathcasecmp( tran->t_pinfo.pi_name, file,
		case_sensitive )) < 0 ) {
            transcript_parse( tran );
            if ( tran->t_eof ) {
                break;
            }
        }
        if ( tran->t_eof ) {
	    if (debug > 1)
	    	fprintf (stderr, "*debug: file '%s' not found (EOF) in t:['%s'] from k:['%s'] ID=%u\n",
			file, tran->t_shortname, tran->t_kfile, tran->id);
            continue;
        }

        if ( cmp > 0 ) {
	    if (debug > 1)
	    	fprintf (stderr,
			 "*debug: file '%s' not found before in t:['%s'] from k:['%s'] line %d, ID=%u\n",
			 file, tran->t_shortname, tran->t_kfile, tran->t_linenum, tran->id);
            continue;
        }

        if ( cmp == 0 ) {
	    int msg = 0;

	    if (verbose) {
	    	switch (tran->t_pinfo.pi_type) {
		case 'f':
	    	    if ((file_stat.st_size != tran->t_pinfo.pi_stat.st_size) || (debug)) {
		        verbose_transcript_header (file, tran, &msg);
		        printf ("size (%llu != %llu)", (unsigned long long) tran->t_pinfo.pi_stat.st_size,
				(unsigned long long) file_stat.st_size);
		    }

		    if ((file_stat.st_mtime != tran->t_pinfo.pi_stat.st_mtime) | (debug)) {
		    	char file_time[64], tran_time[64];
			struct tm tm;

		        verbose_transcript_header (file, tran, &msg);
			
			localtime_r ( &(file_stat.st_mtime), &tm);
			strftime (file_time, sizeof(file_time), "%Y-%m-%d %T", &tm);

			memset ((void *)&tm, 0, sizeof(tm));

			localtime_r ( &(tran->t_pinfo.pi_stat.st_mtime), &tm);
			strftime (tran_time, sizeof(tran_time), "%Y-%m-%d %T", &tm);

			printf ("mtime (%s != %s)", tran_time, file_time);
		    }

		    /* Fall through */

		case 'P':
		case 's':
	        case 'd': 
		    if ((file_stat.st_mode & ALLPERMS) != (tran->t_pinfo.pi_stat.st_mode & ALLPERMS)) {
		        verbose_transcript_header (file, tran, &msg);

		        printf ("mode (%o != %o)", (tran->t_pinfo.pi_stat.st_mode & ALLPERMS),
				(file_stat.st_mode & ALLPERMS));
		    }

		    if (file_stat.st_uid != tran->t_pinfo.pi_stat.st_uid) {
		        verbose_transcript_header (file, tran, &msg);

		        printf ("uid (%lu != %lu)", (long unsigned) tran->t_pinfo.pi_stat.st_uid,
				(long unsigned) file_stat.st_uid);
		    }

		    if (file_stat.st_gid != tran->t_pinfo.pi_stat.st_gid) {
		        verbose_transcript_header (file, tran, &msg);

			printf ("gid (%lu != %lu)", tran->t_pinfo.pi_stat.st_gid, file_stat.st_gid);
		    }

		    break;

		default:
		    break;
		} /* switch ... */

		if (msg)
		    printf ("\n");

	    }
	    else if (debug)
	    {
	    	switch (tran->t_pinfo.pi_type) {
		case 'f':
	    	    if ((file_stat.st_size != tran->t_pinfo.pi_stat.st_size)  || (debug > 1)){
		        debug_transcript_header (stderr, file, tran, &msg);

		        fprintf (stderr ,"size (%llu != %llu)", 
				 (unsigned long long) tran->t_pinfo.pi_stat.st_size,
				 (unsigned long long) file_stat.st_size);
		    }

		    if ((file_stat.st_mtime != tran->t_pinfo.pi_stat.st_mtime) || (debug > 1)) {
		    	char file_time[64], tran_time[64];
			struct tm tm;

		        debug_transcript_header (stderr, file, tran, &msg);

			localtime_r ( &(file_stat.st_mtime), &tm);
			strftime (file_time, sizeof(file_time), "%Y-%m-%d %T", &tm);

			memset ((void *)&tm, 0, sizeof(tm));

			localtime_r ( &(tran->t_pinfo.pi_stat.st_mtime), &tm);
			strftime (tran_time, sizeof(tran_time), "%Y-%m-%d %T", &tm);

			fprintf (stderr, "mtime (%s != %s)", tran_time, file_time);
		    }


		    /* Fall through */
		case 'P':
		case 'd':
		case 's':
		    if (((file_stat.st_mode & ALLPERMS) != (tran->t_pinfo.pi_stat.st_mode & ALLPERMS)) || (debug > 1)) {
		        debug_transcript_header (stderr, file, tran, &msg);

		        fprintf (stderr, "mode (%o != %o)", (tran->t_pinfo.pi_stat.st_mode & ALLPERMS),
				 (file_stat.st_mode & ALLPERMS));
   		    }

		    if ((file_stat.st_uid != tran->t_pinfo.pi_stat.st_uid) || (debug > 1)) {
		        debug_transcript_header (stderr, file, tran, &msg);

		        fprintf (stderr, "uid (%lu != %lu)", (unsigned long) tran->t_pinfo.pi_stat.st_uid,
				 (unsigned long) file_stat.st_uid);
		    }

		    if ((file_stat.st_gid != tran->t_pinfo.pi_stat.st_gid) || (debug > 1)) {
		        debug_transcript_header (stderr, file, tran, &msg);

		        fprintf (stderr, "gid (%lu != %lu)", (unsigned long) tran->t_pinfo.pi_stat.st_gid, 
				 (unsigned long) file_stat.st_gid);
		    }
		    break;

		default:
		    fprintf (stderr, "*debug: pi_type='%c'\n", tran->t_pinfo.pi_type);
		     break;
		} /* switch */

		if (msg)
		    fprintf (stderr, "\n");

		/* end of else if debug... */
	    }

	    return( tran );
	}	
    }

    return( NULL );
}

extern char *optarg;
extern int optind, opterr, optopt;

/*
 * Command-line options
 *
 * Formerly getopt - "h:IK:p:P:rST:u:Vvw:x:y:z:Z:bitcdefnC:D:sX:"
 * Remaining ""
 */

static const usageopt_t main_usage[] = 
  {
    { (struct option) { "buffer-size", required_argument,  NULL, 'B' },
      "Max size of transcript file to buffer in memory (reduces file descriptor usage)", "0-maxint"},

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

    { (struct option) { "case-insensitive", no_argument,   NULL, 'I' },
     		"case insensitive when comparing paths", NULL },

    { (struct option) { "random-file",   no_argument,        NULL, 'r' },
	      "use random seed file $RANDFILE if that environment variable is set, $HOME/.rnd otherwise.  See RAND_load_file(3o).", NULL},

    { (struct option) { "command-file", required_argument, NULL, 'K' },
                "Specify command file, defaults to '" _RADMIND_COMMANDFILE "'", "command.K" },

    { (struct option) { "special-file", no_argument,      NULL, 'S' },
	      "<file> is a 'special' file", NULL},

    { (struct option) { "transcript",   required_argument,  NULL, 'T' },
	      "Specify transcript <file> is from", "pathname" },
#if defined(HAVE_ZLIB)
    { (struct option) { "zlib-level",   required_argument,   NULL, 'Z'},
	      "Specify zlib compression level", "number"},
#else
    { (struct option) { "zlib-level",   required_argument,   NULL, 'Z'},
	      "Not available", "(number)"},
#endif /* defined(HAVE_ZLIB) */

    { (struct option) { "debug", no_argument, NULL, 'd' },
      		"Raise debugging level to see what's happening", NULL},

    { (struct option) { "verbose", no_argument, NULL, 'v' },
      		"Turn on verbose mode", NULL },

    { (struct option) { "version",      no_argument,       NULL, 'V' },
     		"show version number of lfdiff and exits", NULL },
    
    { (struct option) { "help",         no_argument,       NULL, 'H' },
     		"This message", NULL },
    
    { (struct option) { "umask",        required_argument,  NULL, 'u' },
	      "specifies the umask for temporary files, by default 0077", "number" },

    { (struct option) { "authentication",  required_argument, NULL, 'w' },
	      "Specify the authentication level", "number" },


    { (struct option) { "ignore-space-change", no_argument, NULL, 'b' },
	      "(diff option -b)", NULL},

    { (struct option) { "ignore-case", no_argument, NULL, 'i' },
	      "(diff option -i)", NULL},

    { (struct option) { "expand-tabs", no_argument, NULL, 't' },
	      "(diff option -t)", NULL},

    { (struct option) { "context-only", no_argument, NULL, 'c' },
	      "(diff option -c - but no NUM)", NULL},
    
    { (struct option) { "ed", no_argument, NULL, 'e' },
	      "(diff option -e)", NULL},

#if defined(DIFF_OPT_f)   
    { (struct option) { "ignore-space-change", no_argument, NULL, 'f' },
	      "(diff option -f)", NULL},
#endif

    { (struct option) { "rcs", no_argument, NULL, 'n' },
	      "(diff option -n)", NULL},

    { (struct option) { "report-identical-files", no_argument, NULL, 's' },
	      "(diff option -s)", NULL},

    { (struct option) { "context", required_argument, NULL, 'C' },
	      "(diff option -C)", NULL},

    { (struct option) { "ifdef", required_argument, NULL, 'D' },
	      "(diff option -D)", NULL},

    { (struct option) { "diff-options", required_argument, NULL, 'X' },
	      "Unsupported 'diff' options", "diff-arg"},

    /* End of list */
    { (struct option) {(char *) NULL, 0, (int *) NULL, 0}, (char *) NULL, (char *) NULL}
  }; /* end of main_usage[] */

/* Main */

/*
 * exit codes:
 *      0       No differences were found.
 *	1	Differences were found.
 *      >1     	An error occurred. 
 */

    int
main( int argc, char **argv, char **envp )
{
    int			c, i, tac, err = 0, len;
    int			special = 0, diffargc = 0;
    int			fd;
    unsigned short	port = 0;
    extern int          optind; 
    extern char		*version;
    char		*host = _RADMIND_HOST;
    filepath_t		*transcript = NULL;
    filepath_t		*file = NULL;
    filepath_t		*kfile = (filepath_t *) _RADMIND_COMMANDFILE;
    char		*diff = _PATH_GNU_DIFF;
    char		**diffargv;
    char		**av = (char **) NULL;
    filepath_t 		pathdesc[ 2 * MAXPATHLEN ];
    filepath_t 		*path = (filepath_t *) "/tmp/lfdiff";
    filepath_t 		temppath[ MAXPATHLEN ];
    char		opt[ 3 ];
    const char 		*epath;		/* encoded path */
    char        	**capa = NULL; /* capabilities */
    SNET		*sn;
    int                 authlevel = _RADMIND_AUTHLEVEL;
    int                 use_randfile = 0;
    int                 optndx = 0;
    int			tmp_i;
    struct transcript	*tran;
    struct option      *main_opts;
    char               *main_optstr;

    /* Get our name from argv[0] */
    for (main_optstr = argv[0]; *main_optstr; main_optstr++) {
        if (*main_optstr == '/')
	    progname = main_optstr+1;
    }

    main_opts = usageopt_option_new (main_usage, &main_optstr);

    /* create argv to pass to diff */
    if (( diffargv = (char **)malloc( 1  * sizeof( char * ))) == NULL ) {
	perror( "malloc" );
	exit( 2 );
    }
    diffargc = 0;
    diffargv[ diffargc++ ] = diff;

    while (( c = getopt_long (argc, argv, main_optstr, main_opts, &optndx)) != -1) {
	switch( c ) {
	case 'B':
	    tmp_i = atoi (optarg);

	    if ((errno == 0) && (tmp_i >= 0)) {
	        transcript_buffer_size = tmp_i;
	    }
	    break;

	case 'I':
	    case_sensitive = 0;
	    break;

	case 'h':
	    host = optarg;
	    break;

	case 'K':
	    kfile = (filepath_t *) optarg;
	    break;

	case 'p':
	    /* connect.c handles things if atoi returns 0 */
            port = htons( atoi( optarg ));
	    break;

        case 'P' :              /* ca dir */
            caDir = optarg;
            break;

	case 'r':
	    use_randfile = 1;
	    break;

	case 'S':
	    special = 1;
	    break;

	case 'T':
	    transcript = (filepath_t *) optarg;
	    break;

        case 'u' :              /* umask */
            umask( (mode_t)strtol( optarg, (char **)NULL, 0 ));
            break;

	case 'V':
	    printf( "%s\n", version );
	    exit( 0 );

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

	case 'd':
	    debug++;
	    break;


	/* diff options */
#if defined(DIFF_OPT_f)
	case 'f':
#endif
	case 'b': case 'c': case 'i': case 't':
	case 'e': case 'n': case 's':
	  /* Add one element to diffargv[] */
	  if (( diffargv = (char **)realloc( diffargv, (diffargc + 1) *
					     sizeof(char *))) == NULL ) {
		perror( "malloc" );
		exit( 2 );
	    }
	    if ( snprintf( opt, sizeof( opt ), "-%c", c ) > sizeof( opt )) {
		fprintf( stderr, "-%c: too large\n", c );
		exit( 2 );
	    }
	    if (( diffargv[ diffargc++ ] = strdup( opt )) == NULL ) {
		perror( "strdup" );
		exit( 2 );
	    };
	    if (debug) {
		fprintf (stderr, "*debug: diffargc = %d, diffargc[%d] = '%s'\n",
			 diffargc, diffargc, diffargv[diffargc-1]);
	    }
	    break;


	case 'C':  /* --context <something> */
	case 'D':  /* --ifdef <something> */
	  /* Add two elements to diffargv */
	  if (( diffargv = (char **)realloc( diffargv, (diffargc + 2) *
					     sizeof(char *))) == NULL ) {
		perror( "malloc" );
		exit( 2 );
	    }
	    if ( snprintf( opt, sizeof( opt ), "-%c", c ) > sizeof( opt )) {
		fprintf( stderr, "-%c: too large\n", c );
		exit( 2 );
	    }
	    if (( diffargv[ diffargc++ ] = strdup( opt )) == NULL ) {
		perror( "strdup" );
		exit( 2 );
	    }
	    if (debug) {
	       fprintf (stderr, "*debug: diffargc = %d, diffargc[%d] = '%s'\n",
			diffargc, diffargc, diffargv[diffargc-1]);
	    }

	    diffargv[ diffargc++ ] = optarg;

	    if (debug) {
		fprintf (stderr, "*debug: diffargc = %d, diffargc[%d] = '%s'\n", diffargc,
			diffargc, diffargv[diffargc-1]);
	    }
	    break;

	case 'X':  /* --diff-opts */
	    av = (char **) NULL;  /* safety */
	    if (( tac = argcargv( optarg, &av )) < 0 ) {
		err++;
	    }
	    /* Add a bunch (tac) elements to diffargv[] */
	    if (( diffargv = (char **)realloc( diffargv, (diffargc + tac) *
					       sizeof(char *))) == NULL ) {
		perror( "malloc" );
		exit( 2 );
	    }
	    for ( i = 0; i < tac; i++ ) {
		diffargv[ diffargc++ ] = av[ i ];

	        if (debug)
		    fprintf (stderr, "*debug: diffargc = %d, diffargc[%d] = '%s'\n",
			     diffargc, diffargc, diffargv[diffargc-1]);

	    }
	    break;

	case 'H':  /* --help */
	    usageopt_usage (stdout, 1 /* verbose */, progname,  main_usage,
			    "<file>", 80);
	    exit (0);

	case '?':
	    err++;
	    break;
	default:
	    err++;
	    break;
	}
    }

    if (( transcript == NULL ) && ( !special )) {
      if (( file = (filepath_t *) argv[ argc - 1 ] ) == NULL ) {
	    err++;
	} else {
	    if (( tran = precedent_transcript( kfile,
			file, K_CLIENT )) == NULL ) {
		if ( excluded ) {
		    fprintf( stderr, "%s: excluded\n", file );
		} else {
		    fprintf( stderr, "%s not found in any transcript\n", file );
		}
		exit( 2 );
	    }

	    if (debug)
	    	fprintf(stderr,
			"*debug: Found '%s' in t:['%s'] from k:['%s'] line %lu, ID=%u\n",
			(char *) file, (char *) tran->t_shortname, (char *) tran->t_kfile,
			(unsigned long) tran->t_linenum, tran->id);

	    /* check for special */
	    if ( strcmp( (char *) tran->t_shortname, "special.T" ) == 0 ) {
		special = 1;
	    } else {
	        transcript = tran->t_shortname;
	    }
	}
    }

    if ((( transcript == NULL ) && ( !special ))
	    || (( special ) && ( transcript != NULL ))
	    || ( host == NULL )) {
	err++;
    }

    if ( err || ( argc - optind != 1 )) {
        usageopt_usage (stderr, 0 /* not verbose */, progname,  main_usage,
			"<file>", 80);
	exit( 2 );
    }
    file = (filepath_t *) argv[ optind ];
    len = filepath_len(file );

    /* Determine if called with relative or absolute pathing.  Path is relative
     * if it's just '.' or starts with './'.  File names that start with a '.'
     * are absolute.
     */
    if ( file[ 0 ] == '.' ) {
	if ( len == 1 ) {
	    tran_format = T_RELATIVE;
	} else if ( file[ 1 ] == '/' ) {
	    tran_format = T_RELATIVE;
	}
    } else {
	tran_format = T_ABSOLUTE;
    }

    if ( authlevel != 0 ) {
        if ( tls_client_setup( use_randfile, authlevel, caFile, caDir, cert, 
                privatekey ) != 0 ) {
            /* error message printed in tls_setup */
            exit( 2 );
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

    /* encode path */
    if (( epath = encode( (char *) file )) == NULL ) {
	fprintf( stderr, "filename too long: %s\n", file );
	exit( 2 );
    }

    /* create path description */
    if ( special ) {
	if ( snprintf( (char *) pathdesc, ( MAXPATHLEN * 2 ), "SPECIAL %s",
		epath ) >= ( MAXPATHLEN * 2 )) {
	    fprintf( stderr, "RETR SPECIAL %s: path description too long\n",
		    file );
	    exit( 2 );
	}
    } else {
	if ( snprintf( (char *) pathdesc, ( MAXPATHLEN * 2 ), "FILE %s %s",
		       (char *) transcript, epath ) >= ( MAXPATHLEN * 2 )) {
	    fprintf( stderr, "RETR FILE %s %s: path description too long\n",
		     (char *) transcript, epath );
	    exit( 2 );
	}
    }

    if ( retr( sn, pathdesc, path, temppath, 0600, -1, "-" ) != 0 ) {
	exit( 2 );
    }

    if (( closesn( sn )) != 0 ) {
	fprintf( stderr, "can not close sn\n" );
	exit( 2 );
    }
#ifdef HAVE_ZLIB
    if ( verbose && zlib_level > 0 ) print_stats( sn );
#endif /* HAVE_ZLIB */

    if (( fd = open( (char *) temppath, O_RDONLY )) < 0 ) {
	perror( (char *) temppath );
	exit( 2 );
    } 

    if (debug == 0) {
        if ( unlink( (char *) temppath ) != 0 ) {
	    perror( (char *) temppath );
	    exit( 2 );
        }
        if ( dup2( fd, 0 ) < 0 ) {
	    perror( (char *) temppath );
	    exit( 2 );
        }
        if (( diffargv = (char **)realloc( diffargv, ( sizeof( *diffargv )
	        + ( 4 * sizeof( char * ))))) == NULL ) {
            perror( "malloc" );
	    exit( 2 );
        }
        diffargv[ diffargc++ ] = "--";
        diffargv[ diffargc++ ] = "-";
        diffargv[ diffargc++ ] = (char *) file; 
        diffargv[ diffargc++ ] = NULL;
    }
    else {
        if (( diffargv = (char **)realloc( diffargv, ( sizeof( *diffargv )
	        + ( 4 * sizeof( char * ))))) == NULL ) {
            perror( "malloc" );
	    exit( 2 );
        }
        diffargv[ diffargc++ ] = "--";
        diffargv[ diffargc++ ] = (char *) temppath;
        diffargv[ diffargc++ ] = (char *) file; 
        diffargv[ diffargc++ ] = NULL;
    }

    if (debug) {
    	int c;

    	fprintf (stderr, "*debug: execve ('%s', [", diff);

	for (c = 0; (c < diffargc) && (diffargv[c] != NULL); c++) {
	    if (c > 0)
	    	fprintf (stderr, ", ");

	    fprintf (stderr, "'%s'", diffargv[c]);
	}

	fprintf (stderr, "], envp=%p)\n", envp);
    } /* if (debug) */


    if ((debug > 0) && (transcript_buffer_size > 0)) {
        printf ("%u transcripts buffered, %u transcripts not buffered\n", 
		transcripts_buffered, transcripts_unbuffered);
    }

    execve( diff, diffargv, envp );

    /* Unreachable ... probably. */
    perror( diff );
    exit( 2 );
}
