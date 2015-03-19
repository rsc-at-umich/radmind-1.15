/*
 * Copyright (c) 2003, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/evp.h>

#include "applefile.h"
#include "transcript.h"
#include "code.h"
#include "pathcmp.h"
#include "list.h"
#include "wildcard.h"
#include "usageopt.h"

const EVP_MD    *md;

int		case_sensitive = 1;
int		tran_format = -1; 

char  *progname = "twhich";

/*
 * exit codes:
 *      0       File found
 *	1	File not found.
 *      >1     	An error occurred. 
 */

    static int
twhich( const filepath_t *pattern, int displayall )
{
    struct node		*node;
    transcript_t	*tran;
    extern struct list	*exclude_list;
    int			cmp = 0, match = 0;

    if (debug)
        fprintf (stderr, "*debug: twhich ('%s', displayall=%d)\n",
		 pattern, displayall);

    /* check exclude list */
    if ( exclude_list->l_count > 0 ) {
    	if (debug > 2)
	    fprintf (stderr, "*debug: exclude_list->l_count=%d\n", exclude_list->l_count);

	for ( node = list_pop_head( exclude_list ); node != (struct node *) NULL;
		node = list_pop_head( exclude_list )) {

	    if (debug > 1)
	    	 fprintf (stderr, "*debug: exclude_list ... node->n_path='%s', pattern='%s', case_sensitive=%d)\n",
		 	node->n_path, pattern, case_sensitive);

	    if ( wildcard( node->n_path, pattern, case_sensitive )) {
		printf( "# Exclude\n" );
		printf( "# exclude pattern: %s\n", node->n_path );
		if ( !displayall ) {
		    goto done;
		}
	    }
	    free( node );
	}
    }

    for ( tran = tran_head; tran->t_next != (transcript_t *) NULL; tran = tran->t_next ) {

	/* Skip NULL/empty transcripts */
	if ( tran->t_eof ) {
	    if (debug)
	    	fprintf (stderr, "*debug: exhausted transcript t:['%s'] from k:['%s'] line %d\n",
			tran->t_shortname, tran->t_kfile, tran->t_linenum);
	    continue;
	}

	while (( cmp = pathcasecmp( tran->t_pinfo.pi_name,
		pattern, case_sensitive )) < 0 ) {
	    transcript_parse( tran );
	    if ( tran->t_eof ) {
		break;
	    }
	}
	if ( tran->t_eof ) {
	    if (debug)
	    	fprintf (stderr, "*debug: pattern '%s' not found (EOF) in t:['%s'] from k:['%s']\n",
			pattern, tran->t_shortname, tran->t_kfile);
	    continue;
	}

	if ( cmp > 0 ) {
	    if (debug)
	    	fprintf (stderr, "*debug: pattern '%s' not found in t:['%s'] from k:['%s'] line %d\n",
			pattern, tran->t_shortname, tran->t_kfile, tran->t_linenum);
	    continue;
	}

	if ( cmp == 0 ) {
	    match++;
	    switch( tran->t_type ) {
	    case T_POSITIVE:
		printf( "# Positive\n" );
		break;

	    case T_NEGATIVE:
		printf( "# Negative\n" );
		break;

	    case T_SPECIAL:
		printf( "# Special\n" );
		break;

	    default:
	        fprintf( stderr,
			 "%s: FATAL - unknown transcript type (%d) from command file '%s' line %d\n",
			 progname, tran->t_type, tran->t_kfile, tran->t_linenum);
		exit( 2 );
	    }
	    printf( "# %s:\n", tran->t_kfile );

	    if ( tran->t_pinfo.pi_minus ) {
		printf( "%s:\n", tran->t_shortname );
		t_print( NULL, tran, PR_STATUS_MINUS );
	    } else {
		t_print( NULL, tran, PR_TRAN_ONLY );
	    }

	    if ( !displayall ) {
		goto done;
	    }
	}
    }

done:
    if ( match ) {
	return( 0 );
    } else {
	return( 1 );
    }
}


extern char *optarg;
extern int optind, opterr, optopt;

/*
 * Command-line options
 *
 * Formerly getopt - "adIK:rsV"
 */

static const usageopt_t main_usage[] = 
  {
    { (struct option) { "all",   no_argument,             NULL, 'a' }, 
     		"list all transcripts that contain <file>", NULL }, 

    { (struct option) { "buffer-size", required_argument,  NULL, 'B' },
      "Max size of transcript file to buffer in memory (reduces file descriptor usage)", "0-maxint"},

    { (struct option) { "case-insensitive", no_argument,   NULL, 'I' },
     		"case insensitive when comparing paths", NULL },

    { (struct option) { "command-file", required_argument, NULL, 'K' },
                "Specify command file, defaults to '" _RADMIND_COMMANDFILE "'", "command.K" },

    { (struct option) { "debug", no_argument, NULL, 'd'},
      		"Raise debugging level to see what's happening", NULL},

    { (struct option) { "server", no_argument, NULL, 's'},
      "Indicate that 'twhich' is running on a 'radmind' server", NULL},

    { (struct option) { "recursive", no_argument, NULL, 'r' },
	        "recursively searches for each path element in <file>", NULL},

    { (struct option) { "help",         no_argument,       NULL, 'H' },
     		"This message", NULL },
    
    { (struct option) { "version",      no_argument,       NULL, 'V' },
     		"show version number and exits", NULL },
    
    /* End of list */
    { (struct option) {(char *) NULL, 0, (int *) NULL, 0}, (char *) NULL, (char *) NULL}
  }; /* end of main_usage[] */

/* Main */

    int
main( int argc, char **argv )
{
    int			c, err = 0, defaultkfile = 1, rc = 0, len;
    int			server = 0, displayall = 0, recursive = 0;
    int                 tmp_i;
    extern char		*version;
    filepath_t	        *kfile = (filepath_t *) _RADMIND_COMMANDFILE;
    filepath_t     	*pattern;
    filepath_t		*p;
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
	case 'a':
	    displayall = 1;
	    break;

	case 'B':
	    tmp_i = atoi (optarg);

	    if ((errno == 0) && (tmp_i >= 0)) {
	        transcript_buffer_size = tmp_i;
	    }
	    break;

	case 'd':
	    debug++;
	    break;

	case 'K':
	    defaultkfile = 0;
	    kfile = (filepath_t *) optarg;
	    break;

	case 'I':
	    case_sensitive = 0;
	    break;

	case 'r':		/* recursively twhich all path elements */
	    recursive = 1;
	    break;

	case 's':
	    server = 1;
	    break;
	
	case 'V':
	    printf( "%s\n", version );
	    exit( 0 );

	case 'H':  /* --help */
	  usageopt_usage (stdout, 1 /* verbose */, progname,  main_usage,
			  "<file>", 80);
	  exit (0);



	default:
	    fprintf (stderr, "%s: Invalid or unsupported option, '-%c'\n",
		     progname, c);
	    err++;
	    break;
	}
    }

    if (( argc - optind ) != 1 ) {
        if (err == 0)
          fprintf (stderr, "%s: <file> missing\n", progname);
	err++;
    }

    pattern = (filepath_t *) argv[ argc - 1 ];
    len = filepath_len( pattern );

    if ( server && defaultkfile ) {
        fprintf (stderr, "%s: -s and -K are mutually exclusive\n",
		 progname);
	err++;
    }

    if ( err ) {
        usageopt_usage (stderr, 0 /* not verbose */, progname,  main_usage,
			"<file>", 80);
	fprintf (stderr, "%s: Use --help to get more verbose usage\n",
		 progname);
        exit( 2 );
    }

    /* clip trailing slash */
    if ( len > 1 && pattern[ len - 1 ] == '/' ) {
	pattern[ len - 1 ] = '\0';
	len--;
    }

    /* Determine if called with relative or absolute pathing.  Path is relative
     * if it's just '.' or starts with './'.  File names that start with a '.'
     * are absolute.
     */
    if ( pattern[ 0 ] == '.' ) {
	if ( len == 1 ) {
	    tran_format = T_RELATIVE;
	} else if ( pattern[ 1 ] == '/' ) {
	    tran_format = T_RELATIVE;
	}
    } else {
	tran_format = T_ABSOLUTE;
    }

    /* initialize the transcripts */
    edit_path = APPLICABLE;
    if ( server ) {
	transcript_init( kfile, K_SERVER );
    } else {
	transcript_init( kfile, K_CLIENT );
    }
    outtran = stdout;

    if ( recursive ) {
    	if (debug)
	    fprintf(stderr, "*debug: recursive search - pattern='%s'\n",
		    pattern);

	/* Skip the the '/' */
	for ( p = pattern; *p == '/'; p++ ) {
	  continue;  /* IBM Compilers don't like empty loops. */
	}

	for ( p = (filepath_t *) strchr( (char *) p, '/' ); p != NULL;
	      p = (filepath_t *) strchr( (char *) p, '/' ))
	{
	    *p = '\0';
	    if ( twhich( pattern, displayall ) != 0 ) {
		printf( "# %s: not found\n", pattern );
	    }

	    *p++ = '/';
	}
    }
    rc = twhich( pattern, displayall );

    if ((debug > 0) && (transcript_buffer_size > 0)) {
        printf ("%u transcripts buffered, %u transcripts not buffered\n", 
		transcripts_buffered, transcripts_unbuffered);
    }

    exit( rc );
}
