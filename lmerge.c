/*
 * Copyright (c) 2003, 2014-2015 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "argcargv.h"
#include "code.h"
#include "mkdirs.h"
#include "pathcmp.h"
#include "root.h"
#include "filepath.h"
#include "usageopt.h"

char	       *progname = "lmerge";
int		debug = 0;
int		cksum = 1;
int		verbose = 0;
int		noupload = 0;
int		case_sensitive = 1;
extern char   	*version;

typedef struct merge_node merge_node_t;

struct merge_node {
    filepath_t            path[ MAXPATHLEN ];
    merge_node_t         *next;
};

static merge_node_t* merge_node_create( const filepath_t *path );
static void merge_node_free( merge_node_t *node );
static void lmerge_usage (FILE *out, int verbose);

   static merge_node_t *
merge_node_create( const filepath_t *path )
{
    merge_node_t         *new_node;

    if (( new_node = (merge_node_t *) malloc( sizeof( merge_node_t ))) == NULL ) {
	perror( "merge_node_create: malloc(merge_node_t)" );
	return( NULL );
    }
    if ( filepath_len( path ) >= MAXPATHLEN ) {
	fprintf( stderr, "%s: path too long\n", path );
	free (new_node);
	return( NULL );
    }
    filepath_cpy( new_node->path, path );

    return( new_node );
}

    void
merge_node_free( merge_node_t *node )
{
    if (node) {
        free( node );
    }

    return;	/* pedantically */
}

struct tran {
    merge_node_t        *t_next;	/* Next tran in list */
    FILE                *t_fd;		/* open file descriptor */
    int                 t_num;		/* Tran num from command line */
    filepath_t          *t_path;	/* Path from command line */
    int                 t_eof;		/* Tran at end of file */
    int                 t_linenum;	/* Current line number */
    int                 t_remove;	/* Current line has '-' */
    filepath_t          t_prepath[ MAXPATHLEN ]; /* for order check */
    filepath_t		t_tran_root[ MAXPATHLEN ];
    filepath_t		t_file_root[ MAXPATHLEN ];
    filepath_t		t_tran_name[ MAXPATHLEN ];
    char                *t_line;
    char                t_tline[ 2 * MAXPATHLEN ];
    filepath_t          t_filepath[ MAXPATHLEN ];
    char                **t_argv;
    int                 t_tac;
    ACAV                *t_acav;
};

static int getnextline( struct tran *tran ); 

    static int
getnextline( struct tran *tran )
{
    int		len;
    const char	*d_path;

getline:
    if ( fgets( tran->t_tline, MAXPATHLEN, tran->t_fd ) == NULL ) {
	if ( feof( tran->t_fd )) {
	    tran->t_eof = 1;
	    return( 0 );
	}
	perror( (char *) tran->t_path );
	return( -1 );
    }

    tran->t_linenum++;

    if ( tran->t_line != NULL ) {
	free( tran->t_line );
	tran->t_line = NULL;
    }

    if ( ( tran->t_line = strdup( tran->t_tline ) ) == NULL ) {
	perror( tran->t_tline );
	return( -1 );
    }

    /* Check line length */
    len = strlen( tran->t_tline );
    if ( ( tran->t_tline[ len - 1 ] ) != '\n' ) {
	fprintf( stderr, "%s: %d: %s: line too long\n", tran->t_tran_name,
	    tran->t_linenum, tran->t_tline );
	return( -1 );
    }
    if ( ( tran->t_tac = acav_parse( tran->t_acav,
	    tran->t_tline, &(tran->t_argv) )  ) < 0 ) {
	fprintf( stderr, "acav_parse\n" );
	return( -1 );
    }
    /* Skip blank lines and comments */
    if (( tran->t_tac == 0 ) || ( *tran->t_argv[ 0 ] == '#' )) {
	goto getline;
    }

    if ( *tran->t_argv[ 0 ] == '-' ) {
	tran->t_remove = 1;
	tran->t_argv++;
    } else {
	tran->t_remove = 0;
    }

    /* Decode file path */
    if (( d_path = decode( tran->t_argv[ 1 ] )) == NULL ) {
	fprintf( stderr, "%s: line %d: path too long\n", tran->t_tran_name,
	    tran->t_linenum );
	return( 1 );
    } 
    if ( strlen( d_path ) >= MAXPATHLEN ) {
	fprintf( stderr, "%s: line %d: %s: path too long\n",
		tran->t_tran_name, tran->t_linenum, d_path );
	return( 1 );
    }
    filepath_ncpy( tran->t_filepath, (filepath_t *) d_path, sizeof(tran->t_filepath)-1 );

    /* Check transcript order */
    if ( tran->t_prepath != 0 ) {
	 
	if ( pathcasecmp( tran->t_filepath, tran->t_prepath,
		case_sensitive ) <= 0 ) {
	    fprintf( stderr, "%s: line %d: bad sort order\n",
			tran->t_tran_name, tran->t_linenum );
	    return( 1 );
	}
    }
    if ( filepath_len( tran->t_filepath ) >= MAXPATHLEN ) {
	fprintf( stderr, "%s: line %d: %s: path too long\n",
		tran->t_tran_name, tran->t_linenum, tran->t_filepath );
	return( 1 );
    }
    filepath_cpy( tran->t_prepath, tran->t_filepath );


    return( 0 );
}

    static int
copy_file( const char *src_file, const char *dest_file )
{
    int			src_fd, dest_fd = -1;
    int			rr, rc = -1;
    char		buf[ 4096 ];
    struct stat		st;

    if (( src_fd = open( src_file, O_RDONLY )) < 0 ) {
    	fprintf( stderr, "open %s failed: %s\n", src_file, strerror( errno ));
	return( rc );
    }
    if ( fstat( src_fd, &st ) < 0 ) {
	fprintf( stderr, "stat of %s failed: %s\n",
		src_file, strerror( errno ));
	goto cleanup;
    }

    if (( dest_fd = open( dest_file, O_WRONLY | O_CREAT | O_EXCL,
	    st.st_mode & 07777 )) < 0 ) {
	if ( errno == ENOENT ) {
	    rc = errno;
	} else {
	    fprintf( stderr, "open %s failed: %s\n",
		    dest_file, strerror( errno ));
	}
	goto cleanup;
    }
    while (( rr = read( src_fd, buf, sizeof( buf ))) > 0 ) {
	if ( write( dest_fd, buf, rr ) != rr ) {
	    fprintf( stderr, "write to %s failed: %s\n",
		    dest_file, strerror( errno ));
	    goto cleanup;
	}
    }
    if ( rr < 0 ){
	fprintf( stderr, "read from %s failed: %s\n",
		src_file, strerror( errno ));
	goto cleanup;
    }
    if ( fchown( dest_fd, st.st_uid, st.st_gid ) != 0 ) {
	fprintf( stderr, "chown %d:%d %s failed: %s\n",
		st.st_uid, st.st_gid, dest_file, strerror( errno ));
	goto cleanup;
    }

    rc = 0;

cleanup:
    if ( src_fd >= 0 ) {
	if ( close( src_fd ) != 0 ) {
	    fprintf( stderr, "close %s failed: %s\n",
		    src_file, strerror( errno ));
	    rc = -1;
	}
    }
    if ( dest_fd >= 0 ) {
	if ( close( dest_fd ) != 0 ) {
	    fprintf( stderr, "close %s failed: %s\n",
		    dest_file, strerror( errno ));
	    rc = -1;
	}
    }

    return( rc );
}


/*
 * Command-line options
 *
 * Formerly getopt - "CD:fInTu:Vv"
 *
 * Remaining options: ""
 */

static const usageopt_t main_usage[] = 
  {
    { (struct option) { "copy-mode", no_argument, NULL, 'C' },
      "Files listed in dest are copied from their original locations and are not linked", NULL},

    { (struct option) { "case-insensitive", no_argument,   NULL, 'I' },
     		"case insensitive when comparing paths", NULL },

    { (struct option) { "radmind-directory",  required_argument, NULL, 'D' },
	      "Specifiy the radmind working directory, by default "
      		_RADMIND_PATH, "pathname"},

    { (struct option) { "force", no_argument, NULL, 'f' },
	      "Merge <transcript1> into <transcript2>", NULL },

    { (struct option) { "negative", no_argument, NULL, 'n' },
      	      "Merge two transcripts linking all files from the lowest precedence transcript",
      	       NULL},

    { (struct option) { "transcript-only", no_argument, NULL, 'T' },
	      "Merge transcripts only. Do not perform file system linking.  May not be used with the -f",
    	      NULL },
    
    { (struct option) { "umask",        required_argument,  NULL, 'u' },
	      "specifies the umask for temporary files, by default 0077", "number" },

    { (struct option) { "output",       required_argument, NULL, 'o' },
     		"Specify output transcript file", "output-file" },

    { (struct option) { "debug", no_argument, NULL, 'd'},
      		"Raise debugging level to see what's happening", NULL},

    { (struct option) { "verbose", no_argument, NULL, 'v' },
      		"Turn on verbose mode", NULL },

    { (struct option) { "help",         no_argument,       NULL, 'H' },
     		"This message", NULL },
    
    { (struct option) { "version",      no_argument,       NULL, 'V' },
     		"show version number", NULL },


    /* End of list */
    { (struct option) {(char *) NULL, 0, (int *) NULL, 0}, (char *) NULL, (char *) NULL}
  }; /* end of main_usage[] */



   static void
   lmerge_usage (FILE *out, int verbose)
{
    usageopt_usage (out, verbose, progname,  main_usage,
		    "[ <file> ]...", 80);
    
    fprintf( out, "Usage: %s [-vCIVT] [ -D path ] [ -u umask ] transcript... dest\n",
	     progname );

    fprintf( out, "       %s -f [-vCIV] [ -D path ] [ -u umask ] transcript1 transcript2\n",
	     progname );

    fprintf( out, "       %s -n [-vCIVT] [ -D path ] [ -u umask ] transcript1 transcript2 dest\n",
	     progname );

    return;
} /* End of lmerge_usage() */



/* Main 
 *
 * exit codes:
 *	0  	okay	
 *	2	System error
 */

    int
main( int argc, char **argv )
{
    int			c, i, j, cmpval, err = 0, tcount = 0, candidate = 0;
    int			force = 0, ofd, fileloc = 0, match = 0;
    int			merge_trans_only = 0;
    int			copy = 0, rc;
    char		*file = NULL;
    char		npath[ 2 * MAXPATHLEN ];
    char		opath[ 2 * MAXPATHLEN ];
    filepath_t		*radmind_path = (filepath_t *) _RADMIND_PATH;
    filepath_t		cwd[ MAXPATHLEN ];
    filepath_t		file_root[ MAXPATHLEN ];
    filepath_t		tran_root[ MAXPATHLEN ];
    filepath_t		tran_name[ MAXPATHLEN ];
    char		temp[ MAXPATHLEN ];
    struct tran		**trans = NULL;
    merge_node_t	*new_node = NULL;
    merge_node_t	*node = NULL;
    merge_node_t	*dirlist = NULL;
    FILE		*ofs;
    mode_t		mask;
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
	case 'C':		/* copy files instead of using hardlinks */
	    copy = 1;
	    break;

	case 'D':
	    radmind_path = (filepath_t *) optarg;
	    break;

	case 'f':
	    force = 1;
	    break;

	case 'I':
	    case_sensitive = 0;
	    break;

	case 'n':
	    noupload = 1;
	    break;

	case 'u':
	    errno = 0;
	    mask = (mode_t)strtol( optarg, (char **)NULL, 0 );
	    if ( errno != 0 ) {
		err++;
		break;
	    }
	    umask( mask );
	    break;

	case 'H':
	    lmerge_usage (stdout, 1);
	    exit (0);
	    /* UNREACHABLE */

	case 'V':
	    printf( "%s\n", version );
	    exit( 0 );
	    /* UNREACHABLE */

	case 'v':
	    verbose = 1;
	    break;

	case 'T':
	    merge_trans_only = 1;
	    break;

	default:
	    err++;
	    break;
	}
    }

    tcount = argc - ( optind + 1 );	/* "+ 1" accounts for dest tran */

    if ( merge_trans_only && force ) {
	err++;
    }
    if ( merge_trans_only && copy ) {
	err++;
    }
    if ( noupload && ( tcount > 2 ) ) {
	err++;
    }
    /* make sure there's a second transcript */
    if ( force && ( argv[ optind + 1 ] == NULL )) {
	err++;
    }
    if ( force && ( tcount > 1 ) ) {
	err++;
    }
    if ( !force && ( tcount < 2 )) {
	err++;
    }

    if ( err ) {
        lmerge_usage(stderr, 0);
	exit( 2 );
    }

    if ( force ) {
	/* Check for write access */
	if ( access( argv[ argc - 1 ], W_OK ) != 0 ) {
	    perror( argv[ argc - 1 ] );
	    exit( 2 );
	}
	tcount++;			/* add dest to tran merge list */
    }

    /* Create array of transcripts */
    if (( trans = (struct tran**)malloc(
	    sizeof( struct tran* ) * ( tcount ))) == NULL ) {
	perror( "malloc" );
	exit( 2 );
    }
    if ( getcwd( (char *) cwd, sizeof(cwd)-1 ) == NULL ) {
        perror( "getcwd" );
        exit( 2 );
    }
    cwd[sizeof(cwd)-1] = '\0'; /* Safety */

    /* loop over array of trans */
    for ( i = 0;  i < tcount;  i++ ) {

        if ( ( trans[ i ] = (struct tran*)calloc(1,  sizeof( struct tran ) ) )
		== NULL ) {
	    perror( "malloc" );
	    return( 1 );
	}
	memset( trans[ i ], 0, sizeof( struct tran ));
	trans[ i ]->t_num = i;
	trans[ i ]->t_path = (filepath_t *) argv[ i + optind ];

	if ( get_root( radmind_path, trans[ i ]->t_path, trans[ i ]->t_file_root,
		trans[ i ]->t_tran_root, trans[ i ]->t_tran_name ) != 0 ) {
	    exit( 2 );
	}

	/* open tran */
	if (( trans[ i ]->t_fd = fopen( (char *) trans[ i ]->t_path, "r" )) == NULL ) {
	  perror( (char *) trans[ i ]->t_path );
	    return( 1 );
	}

	if ( ( trans[ i ]->t_acav = acav_alloc() ) == NULL ) {
	    fprintf( stderr, "acav_malloc\n" );
	    return( 1 );
	}
	trans[ i ]->t_line = NULL;
	if ( getnextline( trans[ i ] ) < 0 ) {
	    exit( 2 );
	}
    }

    if ( force ) {
	if ( filepath_len( trans[ 1 ]->t_file_root ) >= MAXPATHLEN ) {
	    fprintf( stderr, "%s: path too long\n", trans[ 1 ]->t_file_root );
	    exit( 2 );
	}
	filepath_ncpy( file_root, trans[ 1 ]->t_file_root, sizeof(file_root) );
	if ( filepath_len( trans[ 1 ]->t_tran_root ) >= MAXPATHLEN ) {
	    fprintf( stderr, "%s: path too long\n", trans[ 1 ]->t_tran_root );
	    exit( 2 );
	}
	filepath_ncpy( tran_root, trans[ 1 ]->t_tran_root, sizeof(tran_root) );
	if ( filepath_len( trans[ 1 ]->t_tran_name ) >= MAXPATHLEN ) {
	    fprintf( stderr, "%s: path too long\n", trans[ 1 ]->t_tran_name );
	    exit( 2 );
	}
	filepath_ncpy( tran_name, trans[ 1 ]->t_tran_name, sizeof(tran_name) );
    } else {
	/* Create tran if missing */
	if (( ofd = open( argv[ argc - 1 ], O_WRONLY | O_CREAT, 0666 ) ) < 0 ) {
	    perror( argv[ argc - 1 ] );
	    exit( 2 );
	}
	if ( close( ofd ) != 0 ) {
	    perror( argv[ argc - 1 ] );
	    exit( 2 );
	}

	/* Get paths */
	if ( *argv[ argc - 1 ] == '/' ) {
	    if ( strlen( argv[ argc - 1 ] ) >= MAXPATHLEN ) {
		fprintf( stderr, "%s: path too long\n", argv[ argc - 1 ] );
		exit( 2 );
	    }
	    filepath_ncpy( cwd, (filepath_t *) argv[ argc - 1 ], sizeof(cwd)-1 );
	    cwd[sizeof(cwd)-1] = '\0'; /* Safety */
	} else {
	  if ( snprintf( temp, MAXPATHLEN, "%s/%s", (char *) cwd, argv[ argc - 1 ] )
		    >= MAXPATHLEN ) {
		fprintf( stderr, "%s/%s: path too long\n", cwd,
		    argv[ argc - 1 ] );
		exit( 2 );
	    }
	  filepath_ncpy( cwd, (filepath_t *) temp, sizeof(cwd)-1 );
	    cwd[sizeof(cwd)-1] = '\0'; /* Saftey */
	}
	if ( get_root( radmind_path, cwd, file_root, tran_root, tran_name ) != 0 ) {
	    exit( 2 );
	}

	/* Create file/tname dir */
	if ( snprintf( npath, MAXPATHLEN, "%s/%s.%d", (char *) file_root,
		       (char *) tran_name, (int)getpid()) >= MAXPATHLEN ) {
	    fprintf( stderr, "%s/%s.%d: path too long\n", file_root, tran_name,
		(int)getpid());
	    exit( 2 );
	}
	/* don't bother creating file/tname if only merging trans */
	if ( !merge_trans_only ) {
	    if ( mkdir( npath, (mode_t)0777 ) != 0 ) {
		perror( npath );
		exit( 2 );
	    }
	}
    }

    /* Create temp transcript/tname file */
    if ( snprintf( opath, MAXPATHLEN, "%s/%s.%d", tran_root, tran_name,
	    (int)getpid()) >= MAXPATHLEN ) {
	fprintf( stderr, "%s/%s.%d: path too long\n", tran_root, tran_name,
	    (int)getpid());
	exit( 2 );
    }
    if (( ofd = open( opath, O_WRONLY | O_CREAT | O_EXCL,
	    0666 ) ) < 0 ) {
	perror( opath );
	exit( 2 );
    }
    if ( ( ofs = fdopen( ofd, "w" ) ) == NULL ) {
	perror( opath );
	exit( 2 );
    }

    /* merge */
    for ( i = 0; i < tcount; i++ ) {
	while ( !(trans[ i ]->t_eof)) {
	    candidate = i;
	    fileloc = i;
	    match = 0;

	    if ( force && ( candidate == ( tcount - 1 ))) {
		match = 1;
		goto outputline;
	    }

	    /* Compare candidate to other transcripts */
	    for ( j = i + 1; j < tcount; j++ ) {
		if ( trans[ j ]->t_eof ) {
		    continue;
		}
		cmpval = pathcasecmp( trans[ candidate ]->t_filepath,
		    trans[ j ]->t_filepath, case_sensitive );
		if ( cmpval == 0 ) {
		    /* File match */
		    match = 1;

		    if (( noupload ) &&
			    ( *trans[ candidate ]->t_argv[ 0 ] == 'f' 
			    || *trans[ candidate ]->t_argv[ 0 ] == 'a' )) {
			/* Use lower precedence path */
			trans[ candidate ]->t_path = 
			    trans[ j ]->t_path;

			/* Select which file should be linked */
			if ( ( strcmp( trans[ candidate ]->t_argv[ 6 ], 
				trans[ j ]->t_argv[ 6 ] ) == 0 ) &&
				( strcmp( trans[ candidate ]->t_argv[ 7 ],
				trans[ j ]->t_argv[ 7 ] ) == 0 ) ) {
			    fileloc = j;
			} else {
			    /* don't print file only in highest tran */
			    goto skipline;
			}
		    }
		    if ( ( force ) && ( *trans[ j ]->t_argv[ 0 ] == 'f' 
			    || *trans[ j ]->t_argv[ 0 ] == 'a' )) {
			/* Remove file from lower precedence transcript */
			if ( snprintf( opath, MAXPATHLEN, "%s/%s/%s",
				trans[ j ]->t_file_root,
				trans[ j ]->t_tran_name,
				trans[ j ]->t_filepath ) >= MAXPATHLEN ) {
			    fprintf( stderr,
				"%s/%s/%s: path too long\n",
				trans[ j ]->t_file_root,
				trans[ j ]->t_tran_name,
				trans[ j ]->t_filepath );
			    exit( 2 );
			}
			if ( unlink( opath ) != 0 ) {
			    perror( opath );
			    exit( 2 );
			}
			if ( verbose ) printf( "%s: %s: unlinked\n",
			    trans[ j ]->t_tran_name, trans[ j ]->t_filepath);
		    }
		    /* Advance lower precedence transcript */
		    if ( getnextline( trans[ j ] ) < 0 ) {
			exit( 2 );
		    }
		} else if ( cmpval > 0 ) {
		    candidate = j;
		    fileloc = j;
		}
	    }
	    if ( force && ( candidate == 1 ) ) {
		goto outputline;
	    }
	    /* skip items to be removed or files not uploaded */
	    if (( trans[ candidate ]->t_remove ) ||
		    (( noupload ) && ( candidate == 0 ) && ( fileloc == 0 ))) {
		if ( match && force &&
			( *trans[ candidate ]->t_argv[ 0 ] == 'd' )) {
		    new_node = 
		    	merge_node_create( (filepath_t *) (trans[ candidate ]->t_argv[ 1 ]) );
		    new_node->next = dirlist;
		    dirlist = new_node;
		}
		goto skipline;
	    }
	    /* output non-files, or if we're only merging transcripts 
	     * and there is no file linking necessary
	     */
	    if (( *trans[ candidate ]->t_argv[ 0 ] != 'f'
		    && *trans[ candidate ]->t_argv[ 0 ] != 'a')
		    || merge_trans_only ) {
		goto outputline;
	    }

	    /*
	     * Assume that directory structure is present so the entire path
	     * is not recreated for every file.  Only if link fails is
	     * mkdirs() called.
	     */
	    if ( snprintf( opath, MAXPATHLEN, "%s/%s/%s",
		    trans[ candidate ]->t_file_root,
		    trans[ fileloc ]->t_tran_name,
		    trans[ candidate ]->t_filepath ) >= MAXPATHLEN ) {
		fprintf( stderr, "%s/%s/%s: path too long\n",
		    trans[ candidate ]->t_file_root,
		    trans[ fileloc ]->t_tran_name,
		    trans[ candidate ]->t_filepath );
		exit( 2 );
	    }

	    if ( !force ) {
		if ( snprintf( npath, MAXPATHLEN, "%s/%s.%d/%s",
			file_root, tran_name, (int)getpid(),
			trans[ candidate ]->t_filepath ) >= MAXPATHLEN ) {
		    fprintf( stderr, "%s/%s.%d/%s: path too long\n",
			file_root, tran_name, (int)getpid(),
			trans[ candidate ]->t_filepath );
		    exit( 2 );
		}
	    } else {
		if ( snprintf( npath, MAXPATHLEN, "%s/%s/%s", file_root,
			tran_name, trans[ candidate ]->t_filepath )
			>= MAXPATHLEN ) {
		    fprintf( stderr, "%s/%s/%s: path too long\n", 
			file_root, tran_name, trans[ candidate ]->t_filepath );
		    exit( 2 );
		}
	    }

	    /*
	     * copy or link file into new loadset. it's possible the file's
	     * directory hierarchy won't exist yet. in that case, we catch
	     * ENOENT, call mkdirs to create the parents dirs for the file,
	     * and try again. the second error is fatal.
	     */
	    if ( copy ) {
		rc = copy_file( opath, npath );
	    } else if (( rc = link( opath, npath )) != 0 ) {
		rc = errno;
	    }

	    if ( rc == ENOENT ) {

		/* If that fails, verify directory structure */
		if ( ( file = strrchr( trans[ candidate ]->t_argv[ 1 ], '/' ) )
			!= NULL ) {
		    if ( !force ) {
			if ( snprintf( npath, MAXPATHLEN,
				"%s/%s.%d/%s",
				file_root, tran_name, (int)getpid(), 
				trans[ candidate ]->t_filepath )
				>= MAXPATHLEN ) {
			    fprintf( stderr,
				"%s/%s.%d/%s: path too long\n",
				file_root, tran_name, (int)getpid(),
				trans[ candidate ]->t_filepath );
			    exit( 2 );
			}
		    } else {
			if ( snprintf( npath, MAXPATHLEN,
				"%s/%s/%s", file_root, tran_name,
				trans[ candidate ]->t_filepath )
				>= MAXPATHLEN ) {
			    fprintf( stderr,
				"%s/%s/%s: path too long\n", file_root,
				tran_name, trans[ candidate ]->t_filepath );
			    exit( 2 );
			}
		    }
		    if ( mkdirs( (filepath_t *) npath ) != 0 ) {
			fprintf( stderr, "%s: mkdirs failed\n", npath );
			exit( 2 );
		    }
		} 

		/* Try copy / link again */
    		if ( copy ) {
    		    if (( rc = copy_file( opath, npath )) != 0 ) {
    			fprintf( stderr, "copy %s to %s failed\n",
				opath, npath );
    			exit( 2 );
    		    }
    		} else if ( link( opath, npath ) != 0 ){
    		    fprintf( stderr, "link %s -> %s: %s\n",
			    opath, npath, strerror( errno ));
    		    exit( 2 );
    		}
	    } else if ( rc ) {
		if ( copy ) {
		    fprintf( stderr, "copy %s to %s failed\n", opath, npath );
		} else {
		    fprintf( stderr, "link %s to %s failed: %s\n",
			    opath, npath, strerror( rc ));
		}
		exit( 2 );
	    }

	    if ( verbose ) printf( "%s: %s: merged into: %s\n",
		trans[ candidate ]->t_tran_name, trans[ candidate ]->t_filepath,
		tran_name );
		
outputline:
	    /* Output line */
	    if ( fputs( trans[ candidate ]->t_line, ofs ) == EOF ) {
		perror( trans[ candidate ]->t_line );
		exit( 2 );
	    }
skipline:
	    /* Don't duplicate remove line if it's not a match, or 
	     * we got -f and we're just outputing the last
	     * transcript.
	     */
	    if (( trans[ candidate ]->t_remove )
		    && !match
		    && (!( force && ( candidate == 1 )))) {
		/* Recreate unmatched "-" line */
		if ( fputs( trans[ candidate ]->t_line, ofs ) == EOF ) {
		    perror( trans[ candidate ]->t_line );
		    exit( 2 );

		}
	    }
	    if ( getnextline( trans[ candidate ] ) != 0 ) {
		exit( 2 );
	    }
	}
    }

    if ( force ) {
	while ( dirlist != NULL ) {
	    node = dirlist;
	    dirlist = node->next;
	    if ( snprintf( opath, MAXPATHLEN, "%s/%s/%s", file_root,
		    tran_name, node->path ) >= MAXPATHLEN ) {
		fprintf( stderr, "%s/%s/%s: path too long\n", 
		    file_root, tran_name, node->path );
		exit( 2 );
	    }
	    if ( rmdir( opath ) != 0 ) {
		if (( errno == EEXIST ) || ( errno == ENOTEMPTY )) {
		    fprintf( stderr, "%s: %s: Not empty, continuing...\n",
			tran_name, node->path );
		} else if ( errno != ENOENT ) {
		    perror( opath );
		    exit( 2 );
		}
	    } else {
		if ( verbose ) printf( "%s: %s: unlinked\n", tran_name,
		    node->path );
	    }
	    merge_node_free( node );
	}
    }

    /* Rename temp transcript and file structure */
    if ( !force ) {
	if ( snprintf( opath, MAXPATHLEN, "%s/%s.%d", file_root,
		tran_name, (int)getpid()) >= MAXPATHLEN ) {
	    fprintf( stderr, "%s/%s.%d: path too long\n",
		file_root, tran_name, (int)getpid());
	    exit( 2 );
	}
	if ( snprintf( npath, MAXPATHLEN, "%s/%s", file_root, tran_name )
		>= MAXPATHLEN ) {
	    fprintf( stderr, "%s/%s: path too long\n", file_root, tran_name );
	    exit( 2 );
	}
	/* don't try and move file/tname if doing client only merge,
	 * it was never created.
	 */
	if ( !merge_trans_only ) {
	    if ( rename( opath, npath ) != 0 ) {
		perror( npath );
		exit( 2 );
	    }
	}
    }
    if ( snprintf( opath, MAXPATHLEN, "%s/%s.%d", tran_root, tran_name,
	    (int)getpid()) >= MAXPATHLEN ) {
	fprintf( stderr, "%s/%s.%d: path too long\n", tran_root, tran_name,
	    (int)getpid());
	exit( 2 );
    }
    if ( snprintf( npath, MAXPATHLEN, "%s/%s", tran_root, tran_name )
	    >= MAXPATHLEN ) {
	fprintf( stderr, "%s/%s: path too long\n", tran_root, tran_name );
	exit( 2 );
    }

    if ( rename( opath, npath ) != 0 ) {
	perror( npath );
	exit( 2 );
    }

    exit( 0 );
} 
