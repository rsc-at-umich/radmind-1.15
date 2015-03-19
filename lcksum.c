/*
 * Copyright (c) 2003, 2014 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "applefile.h"
#include "base64.h"
#include "argcargv.h"
#include "cksum.h"
#include "code.h"
#include "pathcmp.h"
#include "largefile.h"
#include "progress.h"
#include "root.h"
#include "usageopt.h"

int	cksum = 0;
int	verbose = 1;
int	debug = 0;
int	amode = R_OK | W_OK;
int	case_sensitive = 1;
int	checkall = 0;
int	checkapplefile = 0;
int	updatetran = 1;
char	*prefix = NULL;
char	*progname = "lcksum";
filepath_t	*radmind_path = (filepath_t *) _RADMIND_PATH;
const EVP_MD	*md;
extern off_t	lsize, total;
extern char	*version, *checksumlist;
filepath_t       prepath[ MAXPATHLEN ] = {0};


static void cleanup( int clean, const char *path);
static int do_lcksum( const filepath_t *tpath);
static off_t check_applefile( const filepath_t *applefile, int afd );

/*
 * exit codes:
 *	0 	No changes found, everything okay
 *	1	Changes necessary / changes made
 *	2	System error
 */

    static off_t
check_applefile(const filepath_t *applefile, int afd )
{
    extern struct as_header as_header;
    struct as_header	header;
    struct as_entry	as_ents[ 3 ];
    int			rr;
    off_t		size = 0;

    /* check header */
    rr = read( afd, &header, AS_HEADERLEN );
    if ( rr < 0 ) {
	fprintf( stderr, "%s: read failed: %s\n", applefile, strerror( errno ));
	return( -1 );
    }

    if ( rr != AS_HEADERLEN ||
		memcmp( &as_header, &header, AS_HEADERLEN ) != 0 ) {
	goto invalid_applefile;
    }
    size += rr;

    /* check entries */
    rr = read( afd, &as_ents, ( 3 * sizeof( struct as_entry )));
    if ( rr < 0 ) {
	fprintf( stderr, "%s: read failed: %s\n", applefile, strerror( errno ));
	return( -1 );
    }
    if ( rr != ( 3 * sizeof( struct as_entry ))) {
	goto invalid_applefile;
    }
    size += rr;

    as_entry_netswap( &as_ents[ AS_FIE ] );
    as_entry_netswap( &as_ents[ AS_RFE ] );
    as_entry_netswap( &as_ents[ AS_DFE ] );

    /* check entry IDs */
    if ( as_ents[ AS_FIE ].ae_id != ASEID_FINFO ||
	    as_ents[ AS_RFE ].ae_id != ASEID_RFORK ||
	    as_ents[ AS_DFE ].ae_id != ASEID_DFORK ) {
	goto invalid_applefile;
    }

    /* check offsets */
    if ( as_ents[ AS_FIE ].ae_offset !=
		( AS_HEADERLEN + ( 3 * sizeof( struct as_entry )))) {
	fprintf( stderr, "%s: invalid finder info offset\n", applefile );
	return( -1 );
    }
    if ( as_ents[ AS_RFE ].ae_offset != 
	    	( as_ents[ AS_FIE ].ae_offset +
		as_ents[ AS_FIE ].ae_length )) {
	fprintf( stderr, "%s: incorrect rsrc fork offset\n", applefile );
	return( -1 );
    }
    if ( as_ents[ AS_DFE ].ae_offset !=
		( as_ents[ AS_RFE ].ae_offset +
		as_ents[ AS_RFE ].ae_length )) {
	fprintf( stderr, "%s: incorrect data fork offset\n", applefile );
	return( -1 );
    }

    /* total sizes as stored in entries */
    size += ( as_ents[ AS_FIE ].ae_length +
		as_ents[ AS_RFE ].ae_length +
		as_ents[ AS_DFE ].ae_length );
    
    return( size );

invalid_applefile:
    fprintf( stderr, "%s: invalid applesingle header\n", applefile );
    return( -1 );
}

    static void
cleanup( int clean, const char *path )
{
    if ( ! clean || path == NULL ) {
	return;
    }

    if ( unlink( path ) != 0 ) {
	fprintf( stderr, "unlink %s: %s\n", path, strerror( errno ));
	exit( 2 );
    }
}

    static int
do_lcksum(const filepath_t *tpath )
{
    int			fd, ufd, updateline = 0;
    int			ucount = 0, len, tac = 0;
    int			prefixfound = 0;
    int			remove = 0;
    int			linenum = 0;
    int			exitval = 0;
    ssize_t		bytes = 0;
    char		*line = NULL;
    const char		*d_path = NULL;
    char                **targv;
    filepath_t		cwd[ MAXPATHLEN ];
    filepath_t		temp[ MAXPATHLEN ];
    filepath_t		file_root[ MAXPATHLEN ];
    filepath_t		tran_root[ MAXPATHLEN ];
    filepath_t		tran_name[ MAXPATHLEN ];
    char                tline[ 2 * MAXPATHLEN ];
    filepath_t		path[ 2 * MAXPATHLEN ];
    char		upath[ 2 * MAXPATHLEN ] = { 0 };
    char		lcksum[ SZ_BASE64_E( EVP_MAX_MD_SIZE ) ];
    FILE		*f, *ufs = NULL;
    struct stat		st;
    off_t		cksumsize;

    if ( getcwd( (char *) cwd, sizeof(cwd)-1 ) == NULL ) {
	perror( "getcwd" );
	exit( 2 );
    }
    cwd[sizeof(cwd)-1] = '\0'; /* Safety */

    if ( *tpath == '/' ) {
	if ( filepath_len( tpath ) >= MAXPATHLEN ) {
	    fprintf( stderr, "%s: path too long\n", tpath );
	    exit( 2 );
	}
	filepath_ncpy( cwd, tpath, sizeof(cwd) );
    } else {
      if ( snprintf( (char *) temp, MAXPATHLEN, "%s/%s", 
		     (char *) cwd, (char *) tpath ) >= MAXPATHLEN ) {
	    fprintf( stderr, "%s/%s: path too long\n", cwd, tpath );
	    exit( 2 );
	}
        filepath_ncpy( cwd, temp, sizeof(cwd) );
    }
    if ( get_root( radmind_path, cwd, file_root, tran_root, tran_name ) != 0 ) {
	exit( 2 );
    }

    if ( stat( (char *) tpath, &st ) != 0 ) {
	perror( (char *) tpath );
	exit( 2 );
    }
    if ( !S_ISREG( st.st_mode )) {
	fprintf( stderr, "%s: not a regular file\n", tpath );
	exit( 2 );
    }

    if ( access( (char *) tpath, amode ) != 0 ) {
	perror( (char *) tpath );
	exit( 2 );
    }

    if (( f = fopen( (char *) tpath, "r" )) == NULL ) {
	perror( (char *) tpath );
	exit( 2 );
    }

    if ( updatetran ) {
	memset( upath, 0, MAXPATHLEN );
	if ( snprintf( upath, MAXPATHLEN, "%s.%i", (char *) tpath, (int)getpid() )
		>= MAXPATHLEN ) {
	    fprintf( stderr, "%s.%i: path too long\n", tpath, (int)getpid() );
	}

	if ( stat( (char *) tpath, &st ) != 0 ) {
	    perror( (char *) tpath );
	    exit( 2 );
	}

	/* Open file */
	if (( ufd = open( upath, O_WRONLY | O_CREAT | O_EXCL,
		st.st_mode )) < 0 ) {
	    perror( upath );
	    exit( 2 );
	}
	if (( ufs = fdopen( ufd, "w" )) == NULL ) {
	    perror( upath );
	    cleanup( updatetran, upath );
	    exit( 2 );
	}
    }

    if ( showprogress ) {
	/* calculate the loadset size */
	lsize = lcksum_loadsetsize( f, prefix );
	
	/* reset progress variables */
	total = 0;
	progress = -1;
    }

    memset( prepath, 0, sizeof( prepath ));

    while ( fgets( tline, MAXPATHLEN, f ) != NULL ) {
	linenum++;
	updateline = 0;

	/* Check line length */
	len = strlen( tline );
	if (( tline[ len - 1 ] ) != '\n' ) {
	    fprintf( stderr, "%s: %d: line too long\n", tpath, linenum);
	    goto badline;
	}
	/* save transcript line -- must free */
	if (( line = strdup( tline )) == NULL ) {
	    perror( "strdup" );
	    cleanup( updatetran, upath );
	    exit( 2 );
	}

	tac = acav_parse( NULL, tline, &targv );

        /* Skip blank lines and comments */
        if (( tac == 0 ) || ( *targv[ 0 ] == '#' )) {
	    if ( updatetran ) {
		fprintf( ufs, "%s", line );
	    }
            goto done;
        }
	if ( tac == 1 ) {
	    fprintf( stderr, "line %d: invalid transcript line\n", linenum );
	    goto badline;
	}

	if ( *targv[ 0 ] == '-' ) {
	    remove = 1;
	    targv++;
	    tac--;

	    if ( tac == 1 ) {
		fprintf( stderr, "line %d: invalid transcript line\n", linenum);
		goto badline;
	    }
	} else {
	    remove = 0;
	}

	if (( d_path = decode( targv[ 1 ] )) == NULL ) {
	    fprintf( stderr, "line %d: path too long\n", linenum );
	    goto badline;
	} 
	if ( strlen( d_path ) >= MAXPATHLEN ) {
	    fprintf( stderr, "line %d: path too long\n", linenum );
	    goto badline;
	}
	filepath_ncpy( path, (filepath_t *) d_path, sizeof(path)-1 );
	    
	/* check to see if file against prefix */
	if ( prefix != NULL ) {
	    if ( strncmp( d_path, prefix, strlen( prefix ))
		    != 0 ) {
		if ( updatetran ) {
		    fprintf( ufs, "%s", line );
		}
		goto done;
	    }
	    prefixfound = 1;
	}
	if ( showprogress && ( tac > 0 && *line != '#' )) {
	  progressupdate( bytes, (filepath_t *) d_path );
	}
	bytes = 0;

	/* Check transcript order */
	if ( *prepath != '\0' ) {
	    if ( pathcasecmp( path, prepath, case_sensitive ) <= 0 ) {
		fprintf( stderr, "line %d: bad sort order\n", linenum );
		cleanup( updatetran, upath );
		exit( 2 );
	    }
	}

	if ( filepath_len( path ) >= MAXPATHLEN ) {
	    fprintf( stderr, "line %d: path too long\n", linenum );
	    goto badline;
	}
	filepath_ncpy( prepath, path, sizeof(prepath)-1 );

	if ((( *targv[ 0 ] != 'f' )  && ( *targv[ 0 ] != 'a' )) || ( remove )) {
	    if ( updatetran ) {
		fprintf( ufs, "%s", line );
	    }
	    bytes += PROGRESSUNIT;
	    goto done;
	}

	if ( tac != 8 ) {
	    fprintf( stderr, "line %d: %d arguments should be 8\n",
		    linenum, tac );
	    goto badline;
	}

	if ( snprintf( (char *) path, MAXPATHLEN, "%s/%s/%s",
	        (char *) file_root, (char *) tran_name,
		d_path ) >= MAXPATHLEN ) {
	    fprintf( stderr, "%d: %s/%s/%s: path too long\n", linenum,
		file_root, tran_name, d_path );
	    goto badline;
	}

	/*
	 * Since this tool is run on the server, all files can be treated
	 * as regular files.
	 *
	 * HFS+ files saved onto the server are converted to applesingle files.
	 *
	 * fsdiff uses do_acksum( ) to calculate the cksum of HFS+ files.
	 *
	 * do_acksum( ) creates a cksum for the associated applesingle file.
	 */

	/* open file here to save us some other open calls */
	if (( fd = open( (char *) path, O_RDONLY, 0 )) < 0 ) {
	    fprintf( stderr, "line %d: open %s: %s\n",
			linenum, d_path, strerror( errno ));
	    goto badline;
	}

	/* check size */
	if ( fstat( fd, &st) != 0 ) {
	    fprintf( stderr, "line %d: fstat failed: %s\n",
			linenum, strerror( errno ));
	    goto badline;
	}

	if (( cksumsize = do_fcksum( fd, lcksum )) < 0 ) {
	    fprintf( stderr, "line %d: %s: %s\n", linenum,
			path, strerror( errno ));
	    goto badline;
	}

	/* check size */
	if ( cksumsize != strtoofft( targv[ 6 ], NULL, 10 )) {
	    if ( !updatetran ) {
		if ( verbose ) printf( "line %d: %s: size wrong\n",
		    linenum, d_path );
		exitval = 1;
	    } else {
		ucount++;
		if ( verbose ) printf( "%s: size updated\n", d_path );
	    }
	    updateline = 1;
	}
	bytes += cksumsize;
	bytes += PROGRESSUNIT;

	/* check cksum */
	if ( strcmp( lcksum, targv[ 7 ] ) != 0 ) {
	    if ( !updatetran ) {
		if ( verbose ) printf( "line %d: %s: "
		    "checksum wrong\n", linenum, d_path );
		exitval = 1;
	    } else {
		ucount++;
		if ( verbose ) printf( "%s: checksum updated\n", d_path ); 
	    }
	    updateline = 1;
	}

	if ( *targv[ 0 ] == 'a' && checkapplefile ) {
	    /* rewind the descriptor */
	    if ( lseek( fd, 0, SEEK_SET ) < 0 ) {
		fprintf( stderr, "%s: lseek failed: %s\n",
			path, strerror( errno ));
		goto badline;
	    }
	    if ( check_applefile( path, fd ) != st.st_size ) {
		fprintf( stderr, "%s: corrupted applefile\n", path );
		goto badline;
	    }
	}

	if ( close( fd ) != 0 ) {
	    /* unrecoverable error. can't leak descriptors. */
	    fprintf( stderr, "%s: close failed: %s\n", path, strerror( errno ));
	    cleanup( updatetran, upath );
	    exit( 2 );
	}

	if ( updatetran ) {
	    if ( updateline ) {
		/* Line incorrect */
		/* Check to see if checksum is listed in transcript */
		if ( strcmp( targv[ 7 ], "-" ) != 0) {
		    /* use mtime from server */
		    fprintf( ufs, "%s %-37s %4s %5s %5s %9ld "
			    "%7" PRIofft "d %s\n",
			targv[ 0 ], targv[ 1 ], targv[ 2 ], targv[ 3 ],
			targv[ 4 ], st.st_mtime, st.st_size, lcksum );
		} else {
		    /* use mtime from transcript */
		    fprintf( ufs, "%s %-37s %4s %5s %5s %9s "
			    "%7" PRIofft "d %s\n",
			targv[ 0 ], targv[ 1 ], targv[ 2 ], targv[ 3 ],
			targv[ 4 ], targv[ 5 ], st.st_size, lcksum );
		    }
	    } else {
		/* Line correct */
		fprintf( ufs, "%s", line );
	    }
	}
done:
	if ( updatetran && ( exitval != 0 )) {
	    cleanup( updatetran, upath );
	    exit( 2 );
	}
	free( line );
    }
    if ( showprogress ) {
        progressupdate( bytes, (filepath_t *) "" );
    }

    if ( !prefixfound && prefix != NULL ) {
	if ( verbose ) printf( "warning: prefix \"%s\" not found\n", prefix );
    }

    if ( updatetran ) {
	if ( ucount ) {
	    if ( rename( upath, (char *) tpath ) != 0 ) {
		fprintf( stderr, "rename %s to %s failed: %s\n", upath, tpath,
		    strerror( errno ));
		exit( 2 );
	    }
	    if ( verbose ) printf( "%s: updated\n", tran_name );
	    return( 1 );
	} else {
	    if ( unlink( upath ) != 0 ) {
		perror( upath );
		exit( 2 );
	    }
	    if ( verbose ) printf( "%s: verified\n", tran_name );
	    return( 0 );
	}
    } else {
	if ( exitval == 0 ) {
	    if ( verbose ) printf( "%s: verified\n", tran_name );
	    return( 0 );
	} else {
	    if ( verbose ) printf( "%s: incorrect\n", tran_name );
	    return( 1 );
	}
    }

    /* this restores -a functionality. can't wait to replace lcksum. */
badline:
    exitval = 1;

    if ( checkall ) {
	goto done;
    } else {
	cleanup( updatetran, upath );
	exit( 2 );
    }
}



extern char *optarg;
extern int optind, opterr, optopt;

/*
 * Command-line options
 *
 * Formerly getopt - "%Aac:D:iInP:qV"
 * Remaining ""
 */

static const usageopt_t main_usage[] = 
  {
    { (struct option) { "progress", no_argument,  NULL, '%' },
      "Progress output", NULL },

    { (struct option) { "check-all",     no_argument, NULL, 'a' },
      "Continue checking on error.  Requires -n option", NULL },

    { (struct option) { "apple",      no_argument, NULL, 'p'},
      "Verify AppleSingle headers.", NULL },

    { (struct option) { "checksum",     required_argument, NULL, 'c' },
      "specify checksum type",  "checksum-type: [sha1,etc]" },

    { (struct option) { "radmind-directory",  required_argument, NULL, 'D' },
	      "Specifiy the radmind working directory, by default "
      		_RADMIND_PATH, "pathname"},

    { (struct option) { "line-buffering", no_argument, NULL, 'i' },
	      "Force line buffering", NULL},

    { (struct option) { "case-insensitive", no_argument,   NULL, 'I' },
     		"case insensitive when comparing paths", NULL },

    { (struct option) { "nochange", no_argument, NULL, 'n' },
	      "verify but do not modify transcript", NULL},

    { (struct option) { "debug", no_argument, NULL, 'd' },
      		"Raise debugging level to see what's happening", NULL},

    { (struct option) { "verbose", no_argument, NULL, 'v' },
      		"Turn on verbose mode", NULL },

    { (struct option) { "help",         no_argument,       NULL, 'H' },
     		"This message", NULL },
    
    { (struct option) { "version",      no_argument,       NULL, 'V' },
     		"show version and list of supported checksums in order of preference", NULL },
    

    /* End of list */
    { (struct option) {(char *) NULL, 0, (int *) NULL, 0}, (char *) NULL, (char *) NULL}
  }; /* end of main_usage[] */

/* Main */

    int
main( int argc, char **argv )
{
    int			c, i, err = 0;
    int                 optndx = 0;
    filepath_t		*tpath = NULL;
    struct option      *main_opts;
    char               *main_optstr;

    /* Get our name from argv[0] */
    for (main_optstr = argv[0]; *main_optstr; main_optstr++) {
        if (*main_optstr == '/')
	    progname = main_optstr+1;
    }

    main_opts = usageopt_option_new (main_usage, &main_optstr);

    while (( c = getopt_long (argc, argv, main_optstr, main_opts, &optndx)) != -1) {
	switch( c ) {
	case 'a':
	    checkall = 1;
	    break;

	case 'A':
	    checkapplefile = 1;
	    break;

	case '%':
	    showprogress = 1;
	    break;

	case 'c':
	    OpenSSL_add_all_digests();
	    md = EVP_get_digestbyname( optarg );
	    if ( !md ) {
		
	        usageopt_usage (stderr, 0 /* not verbose */, progname,  main_usage,
				"<transcript>", 80);
		fprintf( stderr, "%s: unsupported checksum '%s'\n", progname, optarg );
		
		exit( 2 );
	    }
	    cksum = 1;  
	    break;

	case 'i':
	    setvbuf( stdout, ( char * )NULL, _IOLBF, 0 );
	    break;

	case 'I':
	    case_sensitive = 0;
	    break;

	case 'D':
	    radmind_path = (filepath_t *) optarg;
	    break;

	case 'P':
	    prefix = optarg;
	    break;

	case 'n':
	    amode = R_OK;
	    updatetran = 0;
	    break;

	case 'q':
	    verbose = 0;
	    break;

	case 'v':
	    verbose++ ;
	    break;

	case 'V':
	    printf( "%s\n", version );
	    printf( "%s\n", checksumlist );
	    exit( 0 );

	case 'd':
	    debug++;
	    break;

	case 'H':  /* --help */
	  usageopt_usage (stdout, 1 /* verbose */, progname,  main_usage,
			  "<transcript>", 80);
	  exit (0);


	case '?':
	    err++;
	    break;
	    
	default:
	    err++;
	    break;
	}
    }

    if ( cksum == 0 ) {
	err++;
    }

    if ( checkall && updatetran ) {
	err++;
    }

    if ( err || (( argc - optind ) == 0 )) {
	usageopt_usage (stderr, 0 /* not verbose */, progname,  main_usage,
			  "<transcript>", 80);
	exit( 2 );
    }

    for ( i = optind; i < argc; i++ ) {
      tpath = (filepath_t *) argv[ i ];

	switch ( do_lcksum( tpath )) {
	case 2:
	    exit( 2 );
	    break;

	case 1:
	    err = 1;
	    if ( !updatetran ) {
		exit( 1 );
	    }
	    break;

	default:
	    break;
	}
    }

    exit( err );
}
