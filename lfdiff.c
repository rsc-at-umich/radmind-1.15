/*
 * Copyright (c) 2003-2014 Regents of The University of Michigan.
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

void			(*logger)( char * ) = NULL;
extern struct timeval	timeout;
int			verbose = 0;
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

   static struct transcript *
precedent_transcript( char *kfile, char *file, int where )
{
    extern struct transcript	*tran_head;
    struct stat		file_stat;
    struct transcript	*tran;
    int			cmp = 0;

    /* verify that file exists on the local system */
    memset ((void *) &file_stat, 0, sizeof(file_stat));
    if ( lstat( file, &file_stat ) < 0 ) {
	perror( file );
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
	    	fprintf (stderr, "*debug: file '%s' not found before in t:['%s'] from k:['%s'] line %d, ID=%u\n",
			file, tran->t_shortname, tran->t_kfile, tran->t_linenum, tran->id);
            continue;
        }

        if ( cmp == 0 ) {
	    int msg = 0;

	    if (verbose) {
	    	switch (tran->t_pinfo.pi_type) {
		case 'f':
	    	    if ((file_stat.st_size != tran->t_pinfo.pi_stat.st_size) || (debug)) {
		        if (!msg)
		    	    printf ("#  File: '%s' from t:['%s'] k:['%s'] line %d\n#\t",
				file, tran->t_shortname, tran->t_kfile, tran->t_linenum);
		        else
		    	    printf (", ");

		        msg++;
		        printf ("size (%llu != %llu)", (unsigned long long) tran->t_pinfo.pi_stat.st_size, (unsigned long long) file_stat.st_size);
		    }

		    if ((file_stat.st_mtime != tran->t_pinfo.pi_stat.st_mtime) | (debug)) {
		    	char file_time[64], tran_time[64];
			struct tm tm;

		        if (!msg)
		    	    printf ("#  File: '%s' from t:['%s'] k:['%s'] line %d\n#\t",
				file, tran->t_shortname, tran->t_kfile, tran->t_linenum);
		        else
		    	    printf (", ");

		        msg++;
			
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
			if (!msg)
		    	    printf ("#  File: '%s' from t:['%s'] k:['%s'] line %d\n#\t",
				file, tran->t_shortname, tran->t_kfile, tran->t_linenum);
		        else
		    	    printf (", ");

		        msg++;
		        printf ("mode (%o != %o)", (tran->t_pinfo.pi_stat.st_mode & ALLPERMS), (file_stat.st_mode & ALLPERMS));
		    }

		    if (file_stat.st_uid != tran->t_pinfo.pi_stat.st_uid) {
		        if (!msg)
		    	    printf ("#  File: '%s' from t:['%s'] k:['%s'] line %d\n#\t",
				file, tran->t_shortname, tran->t_kfile, tran->t_linenum);
		        else
		    	    printf (", ");

		        msg++;
		        printf ("uid (%lu != %lu)", tran->t_pinfo.pi_stat.st_uid, file_stat.st_uid);
		    }

		    if (file_stat.st_gid != tran->t_pinfo.pi_stat.st_gid) {
		        if (!msg)
		    	    printf ("#  File: '%s' from t:['%s'] k:['%s'] line %d\n#\t",
				file, tran->t_shortname, tran->t_kfile, tran->t_linenum);
		        else
		    	    printf (", ");

		        msg++;
		
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
		        if (!msg)
		    	    fprintf (stderr, "*debug: File: '%s' from t:['%s'] k:['%s'] line %d\n*debug: ",
				file, tran->t_shortname, tran->t_kfile, tran->t_linenum);
		        else
		    	    fprintf (stderr, ", ");

		        msg++;
		        fprintf (stderr ,"size (%llu != %llu)", (unsigned long long) tran->t_pinfo.pi_stat.st_size, (unsigned long long) file_stat.st_size);
		    }

		    if ((file_stat.st_mtime != tran->t_pinfo.pi_stat.st_mtime) || (debug > 1)) {
		    	char file_time[64], tran_time[64];
			struct tm tm;

		        if (!msg)
		    	    fprintf (stderr, "*debug: File: '%s' from t:['%s'] k:['%s'] line %d\n#\t",
				file, tran->t_shortname, tran->t_kfile, tran->t_linenum);
		        else
		    	    fprintf (stderr, ", ");

		        msg++;
			
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
		        if (!msg)
		    	    fprintf (stderr, "*debug: File: '%s' from t:['%s'] k:['%s'] line %d\n*debug: ",
				file, tran->t_shortname, tran->t_kfile, tran->t_linenum);
		        else
		    	    fprintf (stderr, ", ");

		        msg++;
		        fprintf (stderr, "mode (%o != %o)", (tran->t_pinfo.pi_stat.st_mode & ALLPERMS), (file_stat.st_mode & ALLPERMS));
   		    }

		    if ((file_stat.st_uid != tran->t_pinfo.pi_stat.st_uid) || (debug > 1)) {
		        if (!msg)
		    	    fprintf (stderr, "*debug: File: '%s' from t:['%s'] k:['%s'] line %d\n*debug: ",
				file, tran->t_shortname, tran->t_kfile, tran->t_linenum);
		        else
		    	    fprintf (stderr, ", ");

		        msg++;
		        fprintf (stderr, "uid (%lu != %lu)", tran->t_pinfo.pi_stat.st_uid, file_stat.st_uid);
		    }

		    if ((file_stat.st_gid != tran->t_pinfo.pi_stat.st_gid) || (debug > 1)) {
		        if (!msg)
		    	    fprintf (stderr, "*debug: File: '%s' from t:['%s'] k:['%s'] line %d\n*debug: ",
				file, tran->t_shortname, tran->t_kfile, tran->t_linenum);
		        else
		    	    fprintf (stderr, ", ");

		        msg++;
		        fprintf (stderr, "gid (%lu != %lu)", tran->t_pinfo.pi_stat.st_gid, file_stat.st_gid);
		    }
		    break;

		default:
		    fprintf (stderr, "*debug: pi_type='%c'\n", tran->t_pinfo.pi_type);
		     break;
		} /* switch */

		if (msg)
		    fprintf (stderr, "\n");

	    }

	    return( tran );
	}	
    }

    return( NULL );
}

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
    char		*transcript = NULL;
    char		*file = NULL;
    char		*kfile = _RADMIND_COMMANDFILE;
    char		*diff = _PATH_GNU_DIFF;
    char		**diffargv;
    char		**argcargv;
    char 		pathdesc[ 2 * MAXPATHLEN ];
    char 		*path = "/tmp/lfdiff";
    char 		temppath[ MAXPATHLEN ];
    char		opt[ 3 ];
    char		*epath;		/* encoded path */
    char        	**capa = NULL; /* capabilities */
    SNET		*sn;
    int                 authlevel = _RADMIND_AUTHLEVEL;
    int                 use_randfile = 0;
    struct transcript	*tran;

    /* create argv to pass to diff */
    if (( diffargv = (char **)malloc( 1  * sizeof( char * ))) == NULL ) {
	perror( "malloc" );
	exit( 2 );
    }
    diffargc = 0;
    diffargv[ diffargc++ ] = diff;

    while (( c = getopt ( argc, argv,
	    "h:IK:p:P:rST:u:Vvw:x:y:z:Z:bitcdefnC:D:sX:" )) != EOF ) {
	switch( c ) {
	case 'I':
	    case_sensitive = 0;
	    break;

	case 'h':
	    host = optarg;
	    break;

	case 'K':
	    kfile = optarg;
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
	    transcript = optarg;
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
	case 'b': case 'i': case 't':
	case 'c': case 'e': case 'f': case 'n':
	case 's':
	    if (( diffargv = (char **)realloc( diffargv, ( sizeof( *diffargv )
		    + ( 2 * sizeof( char * ))))) == NULL ) {
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
	    if (debug)
		fprintf (stderr, "*debug: diffargc = %d, diffargc[%d] = '%s'\n", diffargc,
			diffargc, diffargv[diffargc-1]);

	    break;

	case 'C':

	case 'D': 
	    if (( diffargv = (char **)realloc( diffargv, ( sizeof( *diffargv )
		    + ( 3 * sizeof( char * ))))) == NULL ) {
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
	    diffargv[ diffargc++ ] = optarg;

	    if (debug)
		fprintf (stderr, "*debug: diffargc = %d, diffargc[%d] = '%s'\n", diffargc,
			diffargc, diffargv[diffargc-1]);

	    break;

	case 'X':
	    if (( tac = argcargv( opt, &argcargv )) < 0 ) {
		err++;
	    }
	    if (( diffargv = (char **)realloc( diffargv, ( sizeof( *diffargv )
		    + ( tac * sizeof( char * ))))) == NULL ) {
		perror( "malloc" );
		exit( 2 );
	    }
	    for ( i = 0; i < tac; i++ ) {
		diffargv[ diffargc++ ] = argcargv[ i ];

	        if (debug)
		    fprintf (stderr, "*debug: diffargc = %d, diffargc[%d] = '%s'\n", diffargc,
			diffargc, diffargv[diffargc-1]);

	    }
	    break;

	case '?':
	    err++;
	    break;
	default:
	    err++;
	    break;
	}
    }

    if (( transcript == NULL ) && ( !special )) {
	if (( file = argv[ argc - 1 ] ) == NULL ) {
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
	    	fprintf(stderr, "*debug: Found '%s' in t:['%s'] from k:['%s'] line %d, ID=%u\n",
			file, tran->t_shortname, tran->t_kfile, tran->t_linenum, tran->id);

	    /* check for special */
	    if ( strcmp( tran->t_shortname, "special.T" ) == 0 ) {
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
	fprintf( stderr, "usage: %s ", argv[ 0 ] );
	fprintf( stderr, "[ -IrvVd ] " );
	fprintf( stderr, "[ -T transcript | -S ] " );
	fprintf( stderr, "[ -h host ] [ -p port ] [ -P ca-pem-directory ] " );
	fprintf( stderr, "[ -u umask ] " );
        fprintf( stderr, "[ -w auth-level ] [ -x ca-pem-file ] " );
        fprintf( stderr, "[ -y cert-pem-file] [ -z key-pem-file ] " );
	fprintf( stderr, "[ -Z compression-level ] " );
	fprintf( stderr, "[ supported diff options ] " );
	fprintf( stderr, "[ -X \"unsupported diff options\" ] " );
	fprintf( stderr, "file\n" );
	exit( 2 );
    }
    file = argv[ optind ];
    len = strlen( file );

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
    if (( epath = encode( file )) == NULL ) {
	fprintf( stderr, "filename too long: %s\n", file );
	exit( 2 );
    }

    /* create path description */
    if ( special ) {
	if ( snprintf( pathdesc, ( MAXPATHLEN * 2 ), "SPECIAL %s",
		epath ) >= ( MAXPATHLEN * 2 )) {
	    fprintf( stderr, "RETR SPECIAL %s: path description too long\n",
		    file );
	    exit( 2 );
	}
    } else {
	if ( snprintf( pathdesc, ( MAXPATHLEN * 2 ), "FILE %s %s",
		transcript, epath ) >= ( MAXPATHLEN * 2 )) {
	    fprintf( stderr, "RETR FILE %s %s: path description too long\n",
		    transcript, epath );
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

    if (( fd = open( temppath, O_RDONLY )) < 0 ) {
	perror( temppath );
	exit( 2 );
    } 

    if (debug == 0) {
        if ( unlink( temppath ) != 0 ) {
	    perror( temppath );
	    exit( 2 );
        }
        if ( dup2( fd, 0 ) < 0 ) {
	    perror( temppath );
	    exit( 2 );
        }
        if (( diffargv = (char **)realloc( diffargv, ( sizeof( *diffargv )
	        + ( 4 * sizeof( char * ))))) == NULL ) {
            perror( "malloc" );
	    exit( 2 );
        }
        diffargv[ diffargc++ ] = "--";
        diffargv[ diffargc++ ] = "-";
        diffargv[ diffargc++ ] = file; 
        diffargv[ diffargc++ ] = NULL;
    }
    else {
        if (( diffargv = (char **)realloc( diffargv, ( sizeof( *diffargv )
	        + ( 4 * sizeof( char * ))))) == NULL ) {
            perror( "malloc" );
	    exit( 2 );
        }
        diffargv[ diffargc++ ] = "--";
        diffargv[ diffargc++ ] = temppath;
        diffargv[ diffargc++ ] = file; 
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

    execve( diff, diffargv, envp );

    perror( diff );
    exit( 2 );
}
