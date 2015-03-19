/*
 * Copyright (c) 2003, 2013-2014 by the Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include <openssl/evp.h>

#include "applefile.h"
#include "transcript.h"
#include "pathcmp.h"
#include "radstat.h"
#include "usageopt.h"
#include "cksum.h"

void            (*logger)( char * ) = NULL;

extern char	*version, *checksumlist;

static void	fs_walk( const unsigned char *, struct stat *, char *, struct applefileinfo *,
			 int, int, int );
int		dodots = 0;
int		dotfd;
int		lastpercent = -1;
int		case_sensitive = 1;
int		tran_format = -1; 
char           *progname = "fsdiff";
extern int	exclude_warnings;
const EVP_MD    *md;

static struct fs_list *fs_insert( struct fs_list **, struct fs_list *,
	const unsigned char *, int (*)( const char *, const char * ));

struct fs_list {
    struct fs_list		*fl_next;
    unsigned char		*fl_name;
    struct stat			fl_stat;
    char			fl_type;
    struct applefileinfo	fl_afinfo;
};



    static struct fs_list *
fs_insert( struct fs_list **head, struct fs_list *last,
	const unsigned char *name, int (*cmp)( const char *, const char * ))
{
    struct fs_list	**current, *new;

    if (( last != NULL ) && ( (*cmp)( (const char *) name, (const char *) last->fl_name ) > 0 )) {
	current = &last->fl_next;
    } else {
	current = head;
    }

    /* find where in the list to put the new entry */
    for ( ; *current != NULL; current = &(*current)->fl_next) {
      if ( (*cmp)( (const char *) name, (const char *) (*current)->fl_name ) <= 0 ) {
	    break;
	}
    }

    if (( new = malloc( sizeof( struct fs_list ))) == NULL ) {
	return( NULL );
    }
    if (( new->fl_name = (unsigned char *) strdup( (const char *) name )) == NULL ) {
	free( new );
	return( NULL );
    }

    new->fl_next = *current;
    *current = new; 
    return( new ); 
}

    static void
fs_walk( const unsigned char *path, struct stat *st, char *p_type, struct applefileinfo *afinfo,
	int start, int finish, int pdel ) 
{
    DIR			*dir;
    struct dirent	*de;
    struct fs_list	*head = NULL, *cur, *new = NULL, *next;
    int			len;
    int			count = 0;
    int			del_parent;
    float		chunk, f = start;
    unsigned char	temp[ MAXPATHLEN ];
    struct transcript	*tran;
    int			(*cmp)( const char *, const char * );

    if (( finish > 0 ) && ( start != lastpercent )) {
	lastpercent = start;
	printf( "%%%.2d %s\n", start, path );
	fflush( stdout );
    }

    /* call the transcript code */
    switch ( transcript_check( path, st, p_type, afinfo, pdel )) {
    case 2 :			/* negative directory */
	for (;;) {
	    tran = transcript_select();
	    if ( tran->t_eof ) {
		return;
	    }

	    if ( ischildcase( tran->t_pinfo.pi_name, path, case_sensitive )) {
		struct stat		st0;
		char			type0;
		struct applefileinfo	afinfo0;

		strncpy( (char *) temp, (const char *) tran->t_pinfo.pi_name, sizeof(temp)-1 );
		switch ( radstat( temp, &st0, &type0, &afinfo0 )) {
		case 0:
		    break;
		case 1:
		    fprintf( stderr, "%s is of an unknown type\n", (const char *) temp );
		    exit( 2 );
		    /* UNREACHABLE */

		default:
		    if (( errno != ENOTDIR ) && ( errno != ENOENT )) {
		        perror( (const char *)path );
			exit( 2 );
		    }
		}

		fs_walk( temp, &st0, &type0, &afinfo0, start, finish, pdel );
	    } else {
		return;
	    }
	}

    case 0 :			/* not a directory */
	return;
    case 1 :			/* directory */
	if ( skip ) {
	    return;
	}
	break;
    default :
	fprintf( stderr, "transcript returned an unexpected value!\n" );
	exit( 2 );
    }

    /*
     * store whether object is to be deleted. if we get here, object
     * is a directory, which should mean that if fs_minus == 1 all
     * child objects should be removed as well. tracking this allows
     * us to zap excluded objects whose parent dir will be deleted.
     *
     * del_parent is passed into subsequent fs_walk and transcript
     * calls, where * it's checked when considering whether to
     * exclude an object.
     */
    del_parent = fs_minus;

    if ( case_sensitive ) {
	cmp = strcmp;
    } else {
	cmp = strcasecmp;
    }

    if ( chdir( (const char *) path ) < 0 ) {
      perror( (const char *) path );
	exit( 2 );
    }

    /* open directory */
    if (( dir = opendir( "." )) == NULL ) {
        perror( (const char *) path );
	exit( 2 );	
    }

    /* read contents of directory */
    while (( de = readdir( dir )) != NULL ) {

	/* don't include . and .. */
	if (( strcmp( de->d_name, "." ) == 0 ) || 
		( strcmp( de->d_name, ".." ) == 0 )) {
	    continue;
	}

	count++;

	if (( new = fs_insert( &head, new, (unsigned char *) de->d_name, cmp )) == NULL ) {
	    perror( "malloc" );
	    exit( 1 );
	}

	switch ( radstat( new->fl_name, &new->fl_stat, &new->fl_type,
		&new->fl_afinfo )) {
	case 0:
	    break;

	case 1:
	    fprintf( stderr, "%s is of an unknown type\n", path );
	    exit( 2 );
	    /* UNREACHABLE */

	default:
	    if (( errno != ENOTDIR ) && ( errno != ENOENT )) {
	        perror( (char *) path );
		exit( 2 );
	    }
	}
    }

    if ( closedir( dir ) != 0 ) {
	perror( "closedir" );
	exit( 2 );
    }

    if ( fchdir( dotfd ) < 0 ) {
	perror( "OOPS!" );
	exit( 2 );
    }

    chunk = (( finish - start ) / ( float )count );

    len = strlen( (const char *) path );

    /* call fswalk on each element in the sorted list */
    for ( cur = head; cur != NULL; cur = next ) {
	if ( path[ len - 1 ] == '/' ) {
	  if ( snprintf( (char *) temp, MAXPATHLEN, "%s%s", (const char *) path, (const char *) cur->fl_name )
		    >= MAXPATHLEN ) {
	    fprintf( stderr, "%s%s: path too long\n", (const char *) path, (const char *) cur->fl_name );
		exit( 2 );
	    }
	} else {
	  if ( snprintf( (char *) temp, MAXPATHLEN, "%s/%s", (const char *) path, (const char *) cur->fl_name )
		    >= MAXPATHLEN ) {
	    fprintf( stderr, "%s/%s: path too long\n", (const char *) path, (const char *) cur->fl_name );
                exit( 2 );
            }
	}

	fs_walk( temp, &cur->fl_stat, &cur->fl_type, &cur->fl_afinfo,
		(int)f, (int)( f + chunk ), del_parent );

	f += chunk;

	next = cur->fl_next;
	free( cur->fl_name );
	free( cur );
    }

    return;
}


extern char *optarg;
extern int optind, opterr, optopt;

/*
 * Command-line options
 *
 * Formerly getopt - "B%1ACc:IK:o:VvW"
 */

static const usageopt_t main_usage[] = 
  {
    { (struct option) { "buffer-size", required_argument,  NULL, 'B' },
      "Max size of transcript file to buffer in memory (reduces file descriptor usage)", "0-maxint"},

    { (struct option) { "percentage",   no_argument,       NULL, '%' }, 
     		"percentage done progress output. Requires -o option.", NULL }, 

    { (struct option) { "applicable",   no_argument,       NULL, 'A' },
     		"produces an applicable transcript (default)", NULL },

    { (struct option) { "creatable",    no_argument,       NULL, 'C' },
     		"produces a creatable transcript (vs. '-A')", NULL },

    { (struct option) { "checksum",     required_argument, NULL, 'c' },
      "specify checksum type",  "checksum-type: [sha1,etc]" },

    { (struct option) { "case-insensitive", no_argument,   NULL, 'I' },
     		"case insensitive when comparing paths", NULL },

    { (struct option) { "command-file", required_argument, NULL, 'K' },
                "Specify command file, defaults to '" _RADMIND_COMMANDFILE "'", "command.K" },

    { (struct option) { "debug", no_argument, NULL, 'd'},
      		"Raise debugging level to see what's happening", NULL},

    { (struct option) { "help",         no_argument,       NULL, 'H' },
     		"This message", NULL },
    
    { (struct option) { "output",       required_argument, NULL, 'o' },
     		"Specify output transcript file", "output-file" },

    { (struct option) { "metadata-check",       required_argument, NULL, 'M' },
      		"enable(+) or disable(-) checking of transcript/file metadata", "{+|-}{uid|gid|mode|size|mtime}"},

    { (struct option) { "checksum-buffer-size", required_argument, NULL, 'S' },
                "Buffer size for doing checksums on files", "8192+"},

    { (struct option) { "single-line",  no_argument,       NULL, '1' },
      		"prints out a single transcript line for the given file. Used to build negative transcripts. Implies '-C'", NULL },
    
    { (struct option) { "version",      no_argument,       NULL, 'V' },
     		"show version number of fsdiff, a list of supported checksumming algorithms in descending order of preference and exits", NULL },
    
    { (struct option) { "warning",      no_argument,       NULL, 'W' },
     		"prints a warning to the standard error when encountering an object matching an exclude pattern.", NULL },

    { (struct option) { NULL,           no_argument,       NULL, 'v' },
      		"Same as -%", NULL },


    /* End of list */
    { (struct option) {(char *) NULL, 0, (int *) NULL, 0}, (char *) NULL, (char *) NULL}
  }; /* end of main_usage[] */

/* Main */
   int
main( int argc, char **argv ) 
{
    extern char 	*optarg;
    extern int		optind;
    unsigned char      *kfile = (unsigned char *) _RADMIND_COMMANDFILE;
    int 		c, len, edit_path_change = 0;
    int 		errflag = 0, use_outfile = 0;
    int			finish = 0;
    int                 optndx = 0;
    int			tmp_i;
    struct stat		st;
    struct option      *main_opts;
    char               *main_optstr;
    char		type, buf[ MAXPATHLEN ];
    struct applefileinfo	afinfo;
    char               *tc_switch_str;
    int                 tc_switch;
    char		tc_op;   /* '+' or '-' */
    long		new_bufsize;
    char	       *strtol_end;

    /* Get our name from argv[0] */
    for (main_optstr = argv[0]; *main_optstr; main_optstr++) {
        if (*main_optstr == '/')
	    progname = main_optstr+1;
    }

    edit_path = CREATABLE;
    cksum = 0;
    outtran = stdout;

    main_opts = usageopt_option_new (main_usage, &main_optstr);

    while (( c = getopt_long (argc, argv, main_optstr, main_opts, &optndx)) != -1) {
        switch( c ) {
	case 'B':
	    tmp_i = atoi (optarg);

	    if ((errno == 0) && (tmp_i >= 0)) {
	        transcript_buffer_size = tmp_i;
	    }
	    break;

	case '%':
	case 'v':
	    finish = 100;
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

	case 'd':
	    debug++;
	    break;

	case 'I':
	    case_sensitive = 0;
	    break;

	case 'o':
	    if (( outtran = fopen( optarg, "w" )) == NULL ) {
		perror( optarg );
		exit( 2 );
	    }
	    use_outfile = 1;
	    break;

	case 'K':
	    kfile = (unsigned char *) optarg;
	    break;

	case '1':
	    skip = 1;
	case 'C':
	    edit_path_change++;
	    edit_path = CREATABLE;
	    break;	

	case 'A':
	    edit_path_change++;
	    edit_path = APPLICABLE;
	    break;

	case 'V':		
	    printf( "%s\n", version );
	    printf( "%s\n", checksumlist );
	    exit( 0 );

	case 'W':		/* print a warning when excluding an object */
	    exclude_warnings = 1;
	    break;


	case 'H':  /* --help */
	    usageopt_usage (stdout, 1 /* verbose */, progname,  main_usage, "<path>", 80);
	    exit (0);

	case 'M': /* transcript_check() metadata switches */
	    tc_op = *optarg;
	    if ((tc_op != '+') && (tc_op != '-')) {
	        fprintf( stderr, "%s: --metadata-check (-M) value must begin with '+' (on) or '-' (off)\n",
			 progname);
		errflag++;
		break;
	    }
	    tc_switch_str = optarg + 1;
	    
	    /* should be table driven... */
	    if (strncasecmp ("uid", tc_switch_str, 10) == 0) {
	         tc_switch = RADTC_SWS_UID;
	    }
	    else if (strncasecmp ("gid", tc_switch_str, 10) == 0) {
	         tc_switch = RADTC_SWS_GID;
	    }
	    else if (strncasecmp ("mode", tc_switch_str, 10) == 0) {
	         tc_switch = RADTC_SWS_MODE;
	    }
	    else if (strncasecmp ("size", tc_switch_str, 10) == 0) {
	         tc_switch = RADTC_SWS_SIZE;
	    }
	    else if (strncasecmp ("mtime", tc_switch_str, 10) == 0) {
	         tc_switch = RADTC_SWS_MTIME;
	    }
	    else {
	      fprintf (stderr, 
		       "%s: --metadata-check option '%s' not 'uid', 'gid', 'mode', 'mtime', or 'size'\n",
		       progname, tc_switch_str);
	         errflag++;
	    }

	    if (errflag == 0) {
	        if (tc_op == '+') {
		    radmind_transcript_check_switches |= tc_switch; /* Turn switch ON */
		}
		else {
		    radmind_transcript_check_switches &= ! tc_switch;  /* Turn switch OFF */
		}
	    }
	    break;


	case 'S':
	    strtol_end = (char *) NULL;
	    if (*optarg == '\0') {
	        fprintf (stderr,
			 "%s: --checksum-buffer-size requires digits\n", progname);
		errflag++;
	    }
	    else {
	        new_bufsize = strscaledtol (optarg, &strtol_end, 0);
		if ((strtol_end != (char *) NULL) && (*strtol_end == '\0') &&
		    (new_bufsize >= DEFAULT_RAD_CKSUM_BUFSIZE)) {

		    rad_fcksum_bufsize = new_bufsize;
		    rad_cksum_bufsize = new_bufsize;
		    rad_acksum_bufsize = new_bufsize;
		}
		else {
		  fprintf (stderr, 
			   "%s: --checksum-buffer-size %s is invalid\n", progname, optarg);
		  errflag++;
		}	
	    }
	    break;


	case '?':
	    printf( "bad option '%c'\n", c );
	    errflag++;
	    break;

	default: 
	    break;
	}
    }

    if (( finish != 0 ) && ( !use_outfile )) {
        fprintf (stderr, "%s: -v (or -%%) requires -o\n", progname);
	errflag++;
    }
    if (( edit_path == APPLICABLE ) && ( skip )) {
        fprintf (stderr, "%s: -1 and -A mutually exclusive.\n", progname);
	errflag++;
    }
    if ( edit_path_change > 1 ) {
        fprintf (stderr, "%s: -C, -A, and -1 are mutually exclusive.\n", progname);
	errflag++;
    }

    /* Check that kfile isn't an abvious directory */
    len = strlen( (const char *) kfile );
    if ( kfile[ len - 1 ] == '/' ) {
        errflag++;
    }

    if ( errflag || ( argc - optind != 1 )) {
        usageopt_usage (stderr, 0 /* not verbose */, progname,  main_usage, "<path>", 80);
	fprintf (stderr, "%s: Use --help to get more verbose usage\n", progname);

	exit ( 2 );
    }

    path_prefix = argv[ optind ];
    len = strlen( path_prefix );

    /* Clip trailing '/' */
    if (( len > 1 ) && ( path_prefix[ len - 1 ] == '/' )) {
	path_prefix[ len - 1 ] = '\0';
	len--;
    }

    /* If path_prefix doesn't contain a directory, canonicalize it by
     * prepending a "./".  This allow paths to be dynamically converted between
     * relative and absolute paths without breaking sort order.
     */
    switch( path_prefix[ 0 ] ) {
    case '/':
        break;

    case '.':
	/* Don't rewrite '.' or paths starting with './' */
	if (( len == 1 ) || (  path_prefix[ 1 ] == '/' )) {
	    break;
	}
    default:
        if ( snprintf( buf, sizeof( buf ), "./%s",
                path_prefix ) >= MAXPATHLEN ) {
  	    fprintf( stderr, "%s: path '%s' too long ( > %d)\n", progname, path_prefix, MAXPATHLEN - 3 );
            exit( 2 );
        }
	path_prefix = buf;
        break;
    }

    /* Determine if called with relative or absolute pathing.  Path is relative
     * if it's just '.' or starts with './'.  File names that start with a '.'
     * are absolute.
     */
    if ( path_prefix[ 0 ] == '.' ) {
	if ( len == 1 ) {
	    tran_format = T_RELATIVE;
	} else if ( path_prefix[ 1 ] == '/' ) {
	    tran_format = T_RELATIVE;
	} else {
	    tran_format = T_ABSOLUTE;
	}
    } else {
	tran_format = T_ABSOLUTE;
    }

    if ( radstat( (const unsigned char *) path_prefix, &st, &type, &afinfo ) != 0 ) {
        perror( path_prefix );
	exit( 2 );
    }

    if (( dotfd = open( ".", O_RDONLY, 0 )) < 0 ) {
	perror( "OOPS!" );
	exit( 2 );
    }

    /* initialize the transcripts */
    transcript_init( kfile, K_CLIENT );

    fs_walk( (const unsigned char *) path_prefix, &st, &type, &afinfo, 0, finish, 0 );

    if ( finish > 0 ) {
	printf( "%%%d\n", ( int )finish );
    }

    /* free the transcripts */
    transcript_free( );
    hardlink_free( );

    /* close the output file */     
    fclose( outtran );

    if ((debug > 0) && (transcript_buffer_size > 0)) {
        printf ("%u transcripts buffered, %u transcripts not buffered\n", 
		transcripts_buffered, transcripts_unbuffered);
    }


    exit( 0 );	
}
