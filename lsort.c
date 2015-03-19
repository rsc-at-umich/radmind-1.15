/*
 * Copyright (c) 2014 by the Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "argcargv.h"
#include "code.h"
#include "pathcmp.h"
#include "usageopt.h"

size_t	linecount = 0;		   /* Pedantically set value */
FILE	*outtran = (FILE *) NULL;  /* Pedantically set value */

struct save_line {
    struct save_line 	*next;
    filepath_t 		*key;
    char  		*data;
} *lines;

char	               *progname = "lsort";
int			verbose = 0;
int			debug = 0;

void 			save_it( const char *buffer, const filepath_t *pathname );
static int 		lsort_cmp( const void *a1, const void *b1 );
void 			sort_them( void );
void 			print_them( void );
void 			process( char * arg );

int			case_sensitive = 1;

    void
save_it( const char *buffer, const filepath_t *pathname )
{
    struct save_line 	*sp;

    sp = malloc( sizeof( *sp ) + strlen( buffer ) + filepath_len( pathname ) + 4 /* why not 2? */);

    sp->key = (filepath_t*)( ( &sp[1]));	/* Set pointer to past ent of 'struct save_line' */
    filepath_cpy( sp->key, pathname );

    sp->data = (char *) (sp->key + filepath_len( sp->key ) + 1 ); /* past the end of the string */
    strcpy( sp->data, buffer );
    sp->next = lines;
    lines = sp;
    linecount++;
}

    static int
lsort_cmp( const void *a1, const void *b1 )
{
    const struct	save_line **a, **b;

    a = (const struct save_line**)a1;
    b = (const struct save_line**)b1;

    return( pathcasecmp((*a)->key, (*b)->key, case_sensitive ));
}

    void
sort_them( void )
{
    struct save_line	**x, *sp, **y;

    x = (struct save_line**) calloc( linecount, sizeof( *x ) );
    y = x;

    for ( sp = lines; sp; sp = sp->next ) {
	*y++ = sp;
    }
    
    qsort( x, linecount, sizeof *x, lsort_cmp );

    sp = 0;
    while ( y-- != x ) {
	(*y)->next = sp;
	sp = (*y);
    }

    lines = sp;
}

    void
print_them( void )
{
    struct save_line *sp;

    for ( sp = lines; sp; sp = sp->next ) {
	fputs( sp->data, outtran );
	if ( ferror( outtran )) {
	    perror( "fputs" );
	    exit( 2 );
	}
    }
}

    void
process( char *arg )
{
    FILE	*f;
    ACAV	*acav;
    char	buffer[4096];
    char	*fn;
    int		lineno, argc;
    char	**argv;
    char	*line = NULL;

    if ( strcmp( arg, "-" )) {
	fn = arg;
	f = fopen( arg, "r" );
    } else {
	fn = "(stdin)";
	f = stdin;
    }
    if ( !f ) {
	    perror( arg );
	    exit( 2 );
    }

    acav = acav_alloc();

    lineno = 0;
    while ( fgets( buffer, sizeof buffer, f )) {
	lineno++;

	if (( line = strdup( buffer )) == NULL ) {
	    perror( "strdup" );
	    exit( 1 );
	}

	argc = acav_parse( acav, buffer, &argv );

	/* Skip blank lines */
	if ( argc == 0 ) {
	    continue;
	}

	/* XXX - Drop comments - how would you sort them? */
	if ( *argv[ 0 ] == '#' ) {
	    continue;
	}

	/* Get argument offset */
	if (( *argv[ 0 ] ==  '+' ) || ( *argv[ 0 ] == '-' )) {
	    argv++;
	    argc--;
	}

	if ( argc < 2 ) {
	    fprintf( stderr, "%s: line %d: not enough fields\n", fn, lineno );
	    exit( 1 );
	}
	save_it( line, (filepath_t *) decode( argv[ 1 ] ));
    }

    if ( f == stdin ) {
	clearerr( f );
    } else {
	fclose( f );
    }

    free( line );
    acav_free( acav );
}



/*
 * Command-line options
 *
 * Formerly getopt - "Io:V"
 */

static const usageopt_t main_usage[] = 
  {
    { (struct option) { "case-insensitive", no_argument,   NULL, 'I' },
     		"case insensitive when comparing paths", NULL },

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

/* Main */

    int
main( int argc, char **argv )
{
    char	c;
    int		i, err = 0;
    int         optndx = 0;
    struct option *main_opts;
    char        *main_optstr;
    extern char	*version;

    outtran = stdout;

    /* Get our name from argv[0] */
    for (main_optstr = argv[0]; *main_optstr; main_optstr++) {
        if (*main_optstr == '/')
	    progname = main_optstr+1;
    }

    main_opts = usageopt_option_new (main_usage, &main_optstr);

    while (( c = getopt_long (argc, argv, main_optstr, main_opts, &optndx)) != -1) {
	switch( c ) {
	case 'I':
	    case_sensitive = 0;
	    break;

	case 'o':
	    if (( outtran = fopen( optarg, "w" )) == NULL ) {
		perror( optarg );
		exit( 1 );
	    }
	    break;

	case 'V':
	    printf( "%s\n", version );
	    exit( 0 );

	case 'v':
	    verbose ++;
	    break;

	case 'H':  /* --help */
	    usageopt_usage (stdout, 1 /* verbose */, progname,  main_usage,
			    "<transcript-file>", 80);
	    exit (0);
	    /* UNREACHABLE */

	default:
	    err++;
	    break;
	}
    }

    if ( err ) {
        usageopt_usage (stderr, 0 /* not verbose */, progname,  main_usage,
			"<transcript-file>", 80);
	exit( 1 );
    }

    if ( argc - optind == 0 ) {
	/* Only stdin */
	process( "-" );
    } else {
	/* Process all args */
	for ( i = optind; i < argc; i++ ) {
	    if ( strcmp( argv[ i ], "-" ) == 0 ) {
		process( "-" );
	    } else {
		process( argv[ i ] );
	    }
	}
    }

    sort_them();
    print_them();

    exit( 0 );
}
