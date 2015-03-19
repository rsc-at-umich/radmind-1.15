/*
 * Copyright (c) 2003, 2007, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

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
#include "list.h"
#include "llist.h"
#include "pathcmp.h"
#include "tls.h"
#include "largefile.h"
#include "mkdirs.h"
#include "rmdirs.h"
#include "report.h"
#include "mkprefix.h"

static int cleandirs( const filepath_t *path, llist_t *khead );
static int clean_client_dir( void );
static int check( SNET *sn, const char *type, const filepath_t *path); 
static int createspecial( SNET *sn, struct list *special_list );
static int getstat( SNET *sn, const char *description, char *stats );
static int read_kfile( const filepath_t *kfile, const char *event );
SNET *sn;

int			linenum = 0;
int			cksum = 0;
int			verbose = 0;
int			dodots= 0;
int			quiet = 0;
int			update = 1;
int			change = 0;
int			case_sensitive = 1;
int			report = 1;
int			create_prefix = 0;
static filepath_t	*base_kfile= (filepath_t *) _RADMIND_COMMANDFILE;
static filepath_t	*radmind_path = (filepath_t *) _RADMIND_PATH;
static filepath_t	*kdir= (filepath_t *) "";
const EVP_MD		*md;
SSL_CTX  		*ctx;
list_t			*special_list = (list_t *) NULL,
			*kfile_seen = (list_t *) NULL;

extern struct timeval	timeout;
extern char		*version, *checksumlist;
extern char             *caFile, *caDir, *cert, *privatekey; 

    static void
expand_kfile( llist_t **khead, const filepath_t *kfile )
{
    llist_t		*new;
    FILE		*kf;
    filepath_t		path[ MAXPATHLEN ];
    char		buf[ MAXPATHLEN ];
    char		**tav;
    int			tac;
    size_t		len;
    unsigned int	line = 0;

    if (( kf = fopen( (char *) kfile, "r" )) == NULL ) {
      perror( (const char *) kfile );
	exit( 2 );
    }

    while ( fgets( buf, MAXPATHLEN, kf ) != NULL ) {
	line++;
	len = strlen( buf );
	if ( buf[ len - 1 ] != '\n' ) {
	    fprintf( stderr, "%s line %d: line too long\n", base_kfile, line );
	    fclose( kf );
	    exit( 2 );
	}

	/* skip comments, special and minus lines */
	if ( *buf == '#' || *buf == 's' || *buf == '-' ) {
	    continue;
	}
	/* skip blank lines */
	if (( tac = argcargv( buf, &tav )) == 0 ) {
	    continue;
	}

	if ( snprintf( (char *) path, MAXPATHLEN, "%s%s",
			kdir, tav[ 1 ] ) >= MAXPATHLEN ) {
	    fprintf( stderr, "%s%s: path too long\n",
			kdir, tav[ 1 ] );
	    fclose( kf );
	    exit( 2 );
	}

	new = ll_allocate( path );
	ll_insert( khead, new );
    }

    if ( fclose( kf ) != 0 ) {
	perror( "fclose" );
	exit( 2 );
    }
}

    static int
cleandirs( const filepath_t *path, llist_t *khead )
{
    DIR			*d;
    struct dirent	*de;
    llist_t		*head = (llist_t *) NULL,
      			*kcur,
      			*cur,
      			*new;
    struct stat		st;
    filepath_t		fsitem[ MAXPATHLEN ];
    int			match = 0;

    if (( d = opendir( (const char *) path )) == NULL ) {
        perror( (const char *) path );
	return( -1 );
    }

    while (( de = readdir( d )) != NULL ) {
	/* skip dotfiles and the special transcript */
	if ( de->d_name[ 0 ] == '.' ||
		strcmp( de->d_name, "special.T" ) == 0 ) {
	    continue;
	}

	if ( snprintf( (char *) fsitem, MAXPATHLEN, "%s/%s", (const char *) path, de->d_name )
		>= MAXPATHLEN ) {
	    fprintf( stderr, "%s/%s: path too long\n", path, de->d_name );
	    return( -1 );
	}

	/*
	 * also skip the base command file. second case
	 * handles "-K kfile.K", where kfile path is
	 * same as "./kfile.K", but is passed as "kfile.K"
	 */
	if ( filepath_cmp( fsitem, base_kfile ) == 0 ||
	     ( filepath_ncmp( kdir, path, filepath_len( path )) == 0
	       && filepath_cmp(base_kfile, (filepath_t *) de->d_name ) == 0 )) {
	    continue;
	}


	new = ll_allocate( fsitem );
	ll_insert( &head, new );
    }

    if ( closedir( d ) != 0 ) {
	perror( "closedir" );
	return( -1 );
    }

    for ( cur = head; cur != (llist_t *) NULL; cur = cur->ll_next ) {
      if ( lstat( (char *) cur->ll_name, &st ) != 0 ) {
	    perror( (char *) cur->ll_name );
	    return( -1 );
	}

	for ( kcur = khead; kcur != (llist_t *) NULL; kcur = kcur->ll_next ) {
	    if (( case_sensitive &&
		  strcmp( (char *) cur->ll_name, (char *) kcur->ll_name ) == 0 ) ||
		    ( !case_sensitive &&
		      strcasecmp( (char *) cur->ll_name, (char *) kcur->ll_name ) == 0 ) ||
		ischildcase(kcur->ll_name, cur->ll_name, case_sensitive)) {
		match = 1;
		break;
	    }
	}

	if ( !match ) {
	    if ( S_ISDIR( st.st_mode )) {
	        rmdirs(cur->ll_name );
		if ( verbose ) {
		    printf( "unused directory %s deleted\n", cur->ll_name );
		}
	    } else {
	      if ( unlink( (char *) cur->ll_name ) != 0 ) {
		    perror( (char *) cur->ll_name );
		    return( -1 );
		}
		if ( verbose ) {
		    printf( "unused file %s deleted\n", cur->ll_name );
		}
	    }
	} else if ( S_ISDIR( st.st_mode )) {
	    cleandirs( cur->ll_name, khead );
	}
	match = 0;
    }

    ll_free( head );

    return( 0 );
}

    static int
clean_client_dir( void )
{
    llist_t		*khead = NULL;
    node_t		*node;
    filepath_t		dir[ MAXPATHLEN ];
    char		*p;

    expand_kfile( &khead, base_kfile );

    while (( node = list_pop_head( kfile_seen )) != NULL ) {
	expand_kfile( &khead, node->n_path );
	free( node );
    }

    /*
     * can't pass in kdir, since it has a trailing slash.
     * bounds checking done when creating kdir in main().
     */
    filepath_ncpy( dir, kdir, sizeof(dir)-1 );
    dir[sizeof(dir)-1] = '\0';  /* Safety */

    if (( p = strrchr( (char *) dir, '/' )) != NULL ) {
	*p = '\0';
    }

    cleandirs( dir, khead );

    ll_free( khead );

    return( 0 );
}

    static int 
getstat( SNET *sn, const char *description, char *stats ) 
{
    struct timeval      tv;
    char		*line;

    if( snet_writef( sn, "STAT %s\n", description ) < 0 ) {
	perror( "snet_writef" );
	return( -1 );
    }

    if ( verbose ) printf( ">>> STAT %s\n", description );

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	perror( "snet_getline_multi" );
	return( -1 );
    }
    if ( *line != '2' ) {
	fprintf( stderr, "%s\n", line );
	exit( 2 );
    }

    tv = timeout;
    if (( line = snet_getline( sn, &tv )) == NULL ) {
	perror( "snet_getline 1" );
	return( -1 );
    }
    if ( strlen( line ) >= MAXPATHLEN ) {
	fprintf( stderr, "%s: line too long\n", line );
	return( -1 );
    }
    strcpy( stats, line );

    if ( verbose ) printf( "<<< %s\n", stats );

    return( 0 );
}

    int
createspecial( SNET *sn, struct list *special_list )
{
    FILE	*fs;
    node_t 	*node;
    char	filedesc[ MAXPATHLEN * 2 ];
    char	path[ MAXPATHLEN ];
    char	stats[ MAXPATHLEN ];

    /* Open file */
    if ( snprintf( path, MAXPATHLEN, "%sspecial.T.%i", kdir,
	    getpid()) >= MAXPATHLEN ) {
	fprintf( stderr, "path too long: %sspecial.T.%i\n", kdir,
		(int)getpid());
	exit( 2 );
    }

    if (( fs = fopen( path, "w" )) == NULL ) {
	perror( path );
	return( 1 );
    }

    for ( node = list_pop_head( special_list ); node != NULL;
	    node = list_pop_head( special_list )) {
	if ( snprintf( filedesc, MAXPATHLEN * 2, "SPECIAL %s", node->n_path)
		>= ( MAXPATHLEN * 2 )) {
	    fprintf( stderr, "SPECIAL %s: too long\n", node->n_path );
	    return( 1 );
	}

	if ( getstat( sn, filedesc, stats ) != 0 ) {
	    return( 1 );
	}

	if ( fputs( stats, fs) == EOF ) {
	    fprintf( stderr, "fputs" );
	    return( 1 );
	}
	if ( fputs( "\n", fs) == EOF ) {
	    fprintf( stderr, "fputs" );
	    return( 1 );
	}
	free( node );
    }

    if ( fclose( fs ) != 0 ) {
	perror( path );
	return( 1 );
    }

    return( 0 );
}

/*
 * return codes:
 *	0	okay
 *	1	update made
 *	2	system error
 */

    int
check( SNET *sn, const char *type, const filepath_t *file )
{
    int		needupdate = 0;
    char	**targv;
    char	stats[ MAXPATHLEN ];
    char 	pathdesc[ 2 * MAXPATHLEN ];
    char 	tempfile[ 2 * MAXPATHLEN ];
    char        ccksum[ SZ_BASE64_E( EVP_MAX_MD_SIZE ) ];
    filepath_t	path[ MAXPATHLEN ];
    filepath_t  copy_file[ MAXPATHLEN ];
    filepath_t	*p;
    int		tac;
    struct stat		st;
    struct utimbuf      times;

    if ( file != (filepath_t *) NULL ) {
        if ( snprintf( pathdesc, MAXPATHLEN * 2, "%s %s", type, (const char *) file  )
		>= ( MAXPATHLEN * 2 )) {
	    fprintf( stderr, "%s %s: too long", type, file );
	    return( 2 );
	}

	/* create full path */
	if ( snprintf( (char *) path, MAXPATHLEN, "%s%s", kdir, (const char *) file )
		>= MAXPATHLEN ) {
	    fprintf( stderr, "%s%s: path too long\n", kdir, file );
	    return( 2 );
	}

	strncpy ((char *) copy_file, (const char *) file, sizeof(copy_file)-1);
	copy_file[sizeof(copy_file)-1] = '\0'; /* Saftey */

	/* Check for transcript with directories */
	for ( p = (filepath_t *) strchr( (const char *) copy_file, '/' );
	      p != NULL; p = (filepath_t *) strchr( (char *) p, '/' ))
	{
	    *p = '\0';

	    /* Check to see if path exists as a directory */
	    if ( snprintf( tempfile, MAXPATHLEN, "%s%s", kdir, (char *) copy_file )
		    >= MAXPATHLEN ) {
	        fprintf( stderr, "%s%s: path too long\n", kdir, (char *) copy_file );
		return( 2 );
	    }
	    if ( stat( tempfile, &st ) != 0 ) {
		if ( errno != ENOENT ) {
		    perror( tempfile );
		    return( 2 );
		}
		if ( mkdir( tempfile, 0777 ) != 0 ) {
		    perror( tempfile );
		    return( 2 );
		}

	    } else {
		/* Make sure it is a directory */
		if ( !S_ISDIR( st.st_mode )) {
		    if ( unlink( tempfile ) != 0 ) {
			perror( tempfile );
			return( 2 );
		    }
		    if ( mkdir( tempfile, 0777 )) {
			perror( tempfile );
			return( 2 );
		    }
		}
	    }
	    *p++ = '/';
	}
	if ( stat( (char *) path, &st ) != 0 ) {
	    if ( errno != ENOENT ) {
	        perror( (char *) path );
		return( 2 );
	    }
	} else {
	    if ( S_ISDIR( st.st_mode )) {
		if ( rmdirs( path ) != 0 ) {
		    perror( (char *) path );
		    return( 2 );
		}
	    }
	}


    } else {
	if ( strlen( type ) >= ( MAXPATHLEN * 2 )) {
	    fprintf( stderr, "%s: too long\n", type );
	    return( 2 );
	}
	strcpy( pathdesc, type );

	file = base_kfile;

	/* create full path */
	if ( filepath_len( base_kfile ) >= MAXPATHLEN ) {
	    fprintf( stderr, "%s: path too long\n", base_kfile );
	    return( 2 );
	}
	filepath_cpy( path, base_kfile );
    }

    if ( getstat( sn, pathdesc, stats ) != 0 ) {
	return( 2 );
    }
    tac = acav_parse( NULL, stats, &targv );
    if ( tac != 8 ) {
	perror( "Incorrect number of arguments\n" );
	return( 2 );
    }
    times.modtime = atoi( targv[ 5 ] );
    times.actime = time( NULL );

    if (( stat( (char *) path, &st )) != 0 ) {
	if ( errno != ENOENT ) {
	    perror( (char *) path );
	    return( 2 );
	} 

	/* Local file is missing */
	if ( update ) {
	    if ( !quiet ) {
	        printf( "%s:", path );
		fflush( stdout );
	    }
	    if ( retr( sn, (filepath_t *) pathdesc, path, (filepath_t *) tempfile,
		       0666, strtoofft( targv[ 6 ], NULL, 10 ), targv[ 7 ] ) != 0 ) {
	        return( 2 );
	    }

	    if ( utime( tempfile, &times ) != 0 ) {
	        perror( tempfile );
		return( 1 );
	    }
	    if ( rename( tempfile, (char *) path ) != 0 ) {
	        perror( tempfile );
		return( 2 );
	    }
	    if ( !quiet )
	      printf( " updated\n" );

	} else {
	    if ( !quiet )
	      printf ( "%s: missing\n", path );
	}
	return( 1 );
    }

    /*
     * With cksum we only use cksum and size.
     * Without cksum we only use mtime and size.
     */
    if ( strtoofft( targv[ 6 ], NULL, 10 ) != st.st_size ) {
	needupdate = 1;
    } else {
	if ( cksum ) {
	    if (( do_cksum( path, ccksum )) < 0 ) {
	      perror( (char *) path );
		return( 2 );
	    }
	    if ( strcmp( targv[ 7 ], ccksum ) != 0 ) {
		needupdate = 1;
	    }
	} else {
	    if ( atoi( targv[ 5 ] ) != (int)st.st_mtime )  {
		needupdate = 1;
	    }
	}
    }
    if ( needupdate ) {
	if ( update ) {
	    if ( !quiet ) {
	        printf( "%s:", path );
		fflush( stdout );
	    }

	    if ( unlink( (char *) path ) != 0 ) {
	        perror( (char *) path );
		return( 2 );
	    }

	    if ( retr( sn, (filepath_t *) pathdesc, path, 
		       (filepath_t *) tempfile, 0666, strtoofft( targv[ 6 ], NULL, 10 ),
		       targv[ 7 ] ) != 0 ) {
		return( 2 );
	    }

	    if ( utime( tempfile, &times ) != 0 ) {
	        perror( (char *) path );
		return( 1 );
	    }
	    if ( rename( tempfile, (char *) path ) != 0 ) {
	        perror( (char *) path );
		return( 2 );
	    }
	    if ( !quiet ) printf( " updated\n" );
	} else {
	    if ( !quiet ) printf( "%s: out of date\n", path );
	}
	return( 1 );
    } else {
	return( 0 );
    }
}

/*
 * exit codes:
 *      0       No changes found, everything okay
 *      1       Changes necessary / changes made
 *      2       System error
 */

    int
main( int argc, char **argv )
{
    int			c, err = 0;
    int			authlevel = _RADMIND_AUTHLEVEL;
    int			use_randfile = 0;
    int			clean = 0;
    unsigned short	port = 0;
    char		lcksum[ SZ_BASE64_E( EVP_MAX_MD_SIZE ) ];
    char		tcksum[ SZ_BASE64_E( EVP_MAX_MD_SIZE ) ];
    struct stat		tst, lst;
    extern int          optind;
    char		*host = _RADMIND_HOST, *p;
    filepath_t		path[ MAXPATHLEN ];
    filepath_t		tempfile[ MAXPATHLEN ];
    char	        **capa = (char **) NULL; /* capabilities */
    char		*event = "ktcheck";	 /* report event type */

    while (( c = getopt( argc, argv,
	    "Cc:D:e:h:IiK:np:P:qrvVw:x:y:z:Z:" )) != EOF ) {
	switch( c ) {
	case 'C':	/* clean up dir containing command.K */
	    clean = 1;
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

	case 'D':
	  radmind_path = (filepath_t *) optarg;
	    break;

	case 'e':		/* set the event label for reporting */
	    event = optarg;
	    break;

	case 'h':
	    host = optarg;
	    break;

	case 'I':
	    case_sensitive = 0;
	    break;

	case 'i':
	    setvbuf( stdout, ( char * )NULL, _IOLBF, 0 );
	    break;

	case 'K':
	    base_kfile = (filepath_t *) optarg;
	    break;

	case 'n':
	    update = 0;
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
                exit( 2 );
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

	default:
	    err++;
	    break;
	}
    }

    if ( verbose && quiet ) {
	err++;
    }

    if ( err || ( argc - optind != 0 )) {
	fprintf( stderr, "usage: %s ", argv[ 0 ] );
	fprintf( stderr, "[ -CIinrV ] [ -q | -v ] " );
	fprintf( stderr, "[ -c checksum ] [ -D radmind_path ] " );
	fprintf( stderr, "[ -K command file ] " );
	fprintf( stderr, "[ -h host ] [ -p port ] [ -P ca-pem-directory ] " );
	fprintf( stderr, "[ -w auth-level ] [ -x ca-pem-file ] " );
	fprintf( stderr, "[ -y cert-pem-file] [ -z key-pem-file ] " );
	fprintf( stderr, "[ -Z compression-level ]\n" );
	exit( 2 );
    }

    if (( special_list = list_new( )) == NULL ) {
	perror( "list_new" );
	exit( 2 );
    }
    if (( kfile_seen = list_new( )) == NULL ) {
	perror( "list_new" );
	exit( 2 );
    }

    if ( filepath_len( base_kfile ) >= MAXPATHLEN ) {
	fprintf( stderr, "%s: path too long\n", base_kfile );
	exit( 2 );
    }
    if (( kdir = filepath_dup( base_kfile )) == NULL ) {
        perror( "strdup failed" );
        exit( 2 );
    }
    if (( p = strrchr( (char *) kdir, '/' )) == NULL ) {
        /* No '/' in kfile - use working directory */
        kdir = (filepath_t *) "./";
    } else {
        p++;
        *p = (char)'\0';
    }
    filepath_ncpy( path, base_kfile, sizeof(path)-1 );
    path[sizeof(path)-1] = '\0'; /* Safety */

    if (( sn = connectsn( host, port )) == NULL ) {
	exit( 2 );
    }
    if (( capa = get_capabilities( sn )) == NULL ) {
	exit( 2 );
    }           

    if ( authlevel != 0 ) {
	if ( tls_client_setup( use_randfile, authlevel, caFile, caDir, cert,
		privatekey ) != 0 ) {
	    /* error message printed in tls_setup */
	    exit( 2 );
	}
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

    /* Check/get correct base command file */
    switch( check( sn, "COMMAND", NULL )) { 
    case 0:
	break;

    case 1:
	change++;
	if ( !update ) {
	    goto done;
	}
	break;

    case 2:
	if ( report ) {
	    if ( report_event( sn, event, "Error" ) != 0 ) {
		fprintf( stderr, "warning: could not report event\n" );
	    }
	}
	exit( 2 );
    }

    if ( read_kfile( base_kfile, event ) != 0 ) {
	exit( 2 );
    }

    /* Exit here if there's already been a change to avoid processing
     * the special transcript.
     */
    if ( !update && change ) {
	exit( 1 );
    }

    if ( special_list->l_count > 0 ) {
	if ( createspecial( sn, special_list ) != 0 ) {
	    exit( 2 );
	}

	if ( snprintf( (char *) path, MAXPATHLEN, "%sspecial.T", kdir )
		>= MAXPATHLEN ) {
	    fprintf( stderr, "path too long: %sspecial.T\n", kdir );
	    exit( 2 );
	}
	if ( snprintf( (char *) tempfile, MAXPATHLEN, "%sspecial.T.%i", kdir,
		getpid()) >= MAXPATHLEN ) {
	    fprintf( stderr, "path too long: %sspecial.T.%i\n", kdir,
		    (int)getpid());
	    exit( 2 );
	}
	/* get file sizes */
	if ( stat( (char *) path, &lst ) != 0 ) {
	    if ( errno == ENOENT ) {
		/* special.T did not exist */
		if ( update ) { 
		  if ( rename( (char *) tempfile, (char *) path ) != 0 ) {
			fprintf( stderr, "rename failed: %s %s\n", tempfile,
			    path );
			exit( 2 );
		    }
		    if ( !quiet ) printf( "%s: created\n", path ); 
		} else {
		    /* special.T not updated */
		  if ( unlink( (char *) tempfile ) !=0 ) {
		        perror( (char *) tempfile );
			exit( 2 );
		    }
		    if ( !quiet ) printf( "%s: missing\n", path );
		}
		change++;
		goto done;
	    }
	    perror( (const char *) path );
	    exit( 2 );
	}
	if ( stat( (char *) tempfile, &tst ) != 0 ) {
	    perror( (char *) tempfile );
	    exit( 2 );
	}
	/* get checksums */
	if ( cksum ) {
	    if ( do_cksum( path, lcksum ) < 0 ) {
	        perror( (const char *) path );
		exit( 2 );
	    }
	    if ( do_cksum( tempfile, tcksum ) < 0 ) {
	        perror( (char *) tempfile );
		exit( 2 );
	    }
	}

	/*
	 * Without checksums we must assume that the special 
	 * transcript has changed since there is no way to
	 * verify its contents
	 */
	/* Special exists */
	if ( !cksum ||
		(( tst.st_size != lst.st_size ) ||
		( strcmp( tcksum, lcksum) != 0 ))) {
	    change++;

	    if ( update ) {
	      if ( rename( (char *) tempfile, (char *) path ) != 0 ) {
		    fprintf( stderr, "rename failed: %s %s\n", tempfile,
			    path );
		    exit( 2 );
		}
		if ( !quiet ) printf( "%s: updated\n", path ); 
	    } else {
		if ( !quiet ) printf( "%s: out of date\n", path );
		if ( unlink( (char *) tempfile ) !=0 ) {
		    perror( (char *) tempfile );
		    exit( 2 );
		}
	    }
	} else {
	    /* local special.T correct */
	  if ( unlink( (char *) tempfile ) !=0 ) {
	        perror( (char *) tempfile );
		exit( 2 );
	    }
	}
    }

done:
#ifdef HAVE_ZLIB
    if ( verbose && zlib_level > 0 ) print_stats( sn );
#endif /* HAVE_ZLIB */

    if ( clean && update ) {
	clean_client_dir();
    }

    if ( change ) {
	if ( update ) {
	    if ( report ) {
		if ( report_event( sn, event, "Updates retrieved" ) != 0 ) {
		    fprintf( stderr, "warning: could not report event\n" );
		}
	    }
	} else {
	    if ( report ) {
		if ( report_event( sn, event, "Updates available" ) != 0 ) {
		    fprintf( stderr, "warning: could not report event\n" );
		}
	    }
	}
    } else {
	if ( report ) {
	    if ( report_event( sn, event, "No updates needed" ) != 0 ) {
		fprintf( stderr, "warning: could not report event\n" );
	    }
	}
    }

    if (( closesn( sn )) != 0 ) {
	fprintf( stderr, "cannot close sn\n" );
	exit( 2 );
    }

    if ( change ) {
	exit( 1 );
    }

    if ( !quiet ) printf( "No updates needed\n" );
    exit( 0 );
}

    int
read_kfile( const filepath_t * kfile, const char * event )
{
    int		ac, minus = 0, kline = 0;
    char	**av;
    char        line[ MAXPATHLEN ];
    filepath_t	path[ MAXPATHLEN ];
    ACAV	*acav;
    FILE	*f;

    if (( acav = acav_alloc( )) == NULL ) {
	perror( "acav_alloc" );
	return( -1 );
    }

    if (( f = fopen( (const char *) kfile, "r" )) == NULL ) {
      perror( (const char *) kfile );
	return( -1 );
    }

    while ( fgets( line, MAXPATHLEN, f ) != NULL ) {
	linenum++;
	kline++;

	ac = acav_parse( acav, line, &av );

	if (( ac == 0 ) || ( *av[ 0 ] == '#' )) {
	    continue;
	}

	/* Skip non-special minus lines */
	if ( *av[ 0 ] == '-' ) {
	    if ( ac != 3 ) {
		fprintf( stderr, "%s: line %d: invalid command line\n",
			 kfile, kline );
		goto error;
	    }
	    if ( *av[ 1 ] == 's' ) {
		minus = 1;
		av++;
		ac--;
	    } else {
		continue;
	    }
	} else {
	    /* Set incase previous line was a minus */
	    minus = 0;
	}

	if ( ac != 2 ) {
	    fprintf( stderr, "%s: %d: invalid command line\n",
		kfile, linenum );
	    goto error;
	}

	switch( *av[ 0 ] ) {
	case 'k':
	  if ( snprintf( (char *) path, MAXPATHLEN, "%s%s", kdir,
		    av[ 1 ] ) >= MAXPATHLEN ) {
		fprintf( stderr, "path too long: %s%s\n", kdir, av[ 1 ] );
		goto error;
	    }
	    if ( list_check( kfile_seen, path )) {
		fprintf( stderr,
		    "command file %s loop at line %i: %s already included\n",
		    kfile, kline, av[1] );
		goto error;
	    } else {
		if ( list_insert_tail( kfile_seen, path ) != 0 ) {
		    perror( "list_insert_tail" );
		    goto error;
		}
	    }

	    switch( check( sn, "COMMAND", (filepath_t *) av[ ac - 1] )) {
	    case 0:
		break;
	    case 1:
		change++;
		if ( !update ) {
		    goto done;
		}
		break;
	    case 2:
		if ( report ) {
		    if ( report_event( sn, event, "Error" ) != 0 ) {
			fprintf( stderr, "warning: could not report event\n" );
		    }
		}
		goto error;
	    }
	    if ( read_kfile( path, event ) != 0 ) {
		exit( 2 );
	    }
	    break;

	case 's':
	    /* Added special file if it's not already in the list */
	    if ( minus ) {
	        if ( list_check( special_list, (filepath_t *) av[ 1 ] )) {
		  list_remove( special_list, (filepath_t *) av[ 1 ] );
	        }
	    } else {
	          if ( !list_check( special_list, (filepath_t *) av[ 1 ] )) {
		      if ( list_insert_case( special_list, (filepath_t *) av[ 1 ],
				case_sensitive ) != 0 ) {
			perror( "list_insert" );
			exit( 2 );
		      }
		  }
	    }
	    continue;
	    
	case 'p':
	case 'n':
	  switch( check( sn, "TRANSCRIPT", (filepath_t *) av[ ac - 1] )) {
	    case 0:
		break;
	    case 1:
		change++;
		if ( !update ) {
		    goto done;
		}
		break;
	    case 2:
		if ( report ) {
		    if ( report_event( sn, event, "Error" ) != 0 ) {
			fprintf( stderr, "warning: could not report event\n" );
		    }
		}
		exit( 2 );
	    }
	    break;

	case 'x':
	    /* exclude patterns have no associated transcript */
	    break;
	}
    }
    if ( ferror( f )) {
	perror( "fgets" );
	return( -1 );
    }

done:
    if ( fclose( f ) != 0 ) {
	perror( "fclose" );
	return( -1 );
    }
    if ( acav_free( acav ) != 0 ) {
	perror( "acav_free" );
	return( -1 );
    }
    if ( !update && change ) {
	if ( report ) {
	    if ( report_event( sn, event, "Updates available" ) != 0 ) {
		fprintf( stderr, "warning: could not report event\n" );
	    }
	}
	exit( 1 );
    }
    return( 0 );

error:
    fclose( f );
    acav_free( acav );
    return( -1 );
}
