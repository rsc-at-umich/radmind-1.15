/*
 * Copyright (c) 2003, 2007, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#ifdef sun
#include <sys/mkdev.h>
#endif /* sun */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "applefile.h"
#include "base64.h"
#include "transcript.h"
#include "argcargv.h"
#include "code.h"
#include "cksum.h"
#include "pathcmp.h"
#include "largefile.h"
#include "list.h"
#include "wildcard.h"

static const filepath_t * convert_path_type( const filepath_t *path );
int read_kfile( const filepath_t *kfile, int location );
static void t_remove( int type, const filepath_t *shortname );
static void t_display( void );

transcript_t	 		*tran_head = (transcript_t *) NULL;
static transcript_t		*prev_tran = (transcript_t *) NULL;
extern int			edit_path;
extern int			case_sensitive;
extern int			tran_format;
static filepath_t		*kdir;
static struct list		*kfile_list;
struct list			*special_list;
struct list			*exclude_list;

char				*path_prefix = NULL;
int				edit_path;
int				skip;
int				cksum;
int				fs_minus;
int				exclude_warnings = 0;
FILE				*outtran;
int			        debug = 0;
size_t                          transcript_buffer_size = 0; /* No buffering */
unsigned int                    transcripts_buffered = 0;
unsigned int                    transcripts_unbuffered = 0;

const static filepath_t * 
convert_path_type( const filepath_t *path )
{
    int			len = 0;
    static filepath_t   buf[ MAXPATHLEN ]; 

    len = filepath_len( path );

    if ( len == 1 ) {
        if (( tran_format == T_ABSOLUTE ) && ( path[ 0 ] == '.' )) {
            buf[ 0 ] = '/';
            buf[ 1 ] = '\0';
        } else if (( tran_format == T_RELATIVE ) && ( path[ 0 ] == '/' )) {
            buf[ 0 ] = '.';
            buf[ 1 ] = '\0';
        } else {
	    /* Nothing to convert */
	    return( path );
	}
    } else {
        if (( tran_format == T_ABSOLUTE ) && ( path[ 0 ] == '.' )) {
            if ( path[ 1 ] == '/' ) {
                /* Move past leading '.' */
		path++;
                if ( snprintf( (char *) buf, sizeof( buf ), "%s",
			       (const char *) path ) >= MAXPATHLEN ) {
		    return( NULL );
                }
            } else {
                /* Instert leading '/' */
	      if ( snprintf( (char *) buf, sizeof( buf ), "/%s",
			     (const char *) path ) >= MAXPATHLEN ) {
		    return( NULL );
                }
            }
        } else if (( tran_format == T_RELATIVE ) && ( path[ 0 ] == '/' )) {
            /* Instert leading '.' */
	  if ( snprintf( (char *) buf, sizeof( buf ), ".%s", (const char *) path ) >= MAXPATHLEN ) {
		return( NULL );
            }
        } else { 
	    /* Nothing to convert */
	    return( path );
	}
    }

    return( buf );
}

    void 
transcript_parse( transcript_t *tran ) 
{
    char			line[ 2 * MAXPATHLEN ];
    int				length;
    const filepath_t		*epath;
    char			**argv;
    int				ac;
    unsigned int                counted = 0;

    /* read in the next line in the transcript, loop through blanks and # */
    do {
      if (tran->buffered != (char *) NULL) {
	  char *eol;
	  char *dummy = NULL;

	  if ( *(tran->buffer_position) == '\0') {
	    tran->t_eof = 1;
	    if (debug > 2)
		fprintf (stderr, "*debug: transcript_parse(t:['%s'] from k:['%s']) empty (buffer EOF after line %d, skipping %u)\n",
			 tran->t_shortname, tran->t_kfile, tran->t_linenum, counted);
	    return;
	  }

	  /* Use re-entrant version of strtok() */
	  eol = strtok_r (tran->buffer_position, "\r\n", &dummy);
	  if (eol == (char *) NULL) {
	      strncpy (line, tran->buffer_position, sizeof(line)-1);
	      tran->buffer_position += strlen (tran->buffer_position);
	  }
	  else {
	      strncpy (line, tran->buffer_position, sizeof(line)-1);
	      tran->buffer_position += strlen (tran->buffer_position) + 1;
	  }
	  if (debug > 2)
	    fprintf (stderr, "*debug: transcript_parse(t:['%s'] from k:['%s']) buffered line %u after skipping %u:\n\t%s\n",
		     tran->t_shortname, tran->t_kfile, tran->t_linenum, counted, line);

	  strncat (line, "\n", sizeof(line)-1);  /* Put EOL back. */
        }
	else if (( fgets( line, sizeof(line)-1, tran->t_in )) == NULL ) {
	    tran->t_eof = 1;
	    if (debug > 2)
		fprintf (stderr, "*debug: transcript_parse(t:['%s'] from k:['%s']) empty (EOF after line %d, skipping %u)\n",
			 tran->t_shortname, tran->t_kfile, tran->t_linenum, counted);
	    return;
	}
	tran->t_linenum++;
	counted++;

	/* check to see if line contains the whole line */
	length = strlen( line );
	if ( line[ length - 1 ] != '\n' ) {
	    fprintf( stderr, "%s: line %d: line too long\n",
		    tran->t_fullname, tran->t_linenum );
	    exit( 2 );
	} 
    } while ((( ac = argcargv( line, &argv )) == 0 ) || ( *argv[ 0 ] == '#' ));

    if ( ac < 3 ) {
	fprintf( stderr, "%s: line %d: minimum 3 arguments, got %d\n",
		tran->t_fullname, tran->t_linenum, ac );
	exit( 2 );
    }

    if ( strlen( argv[ 0 ] ) != 1 ) {
	fprintf( stderr, "%s: line %d: %s is too long to be a type\n",
		tran->t_fullname, tran->t_linenum, argv[ 0 ] );
	exit( 2 );
    }

    if ( argv[ 0 ][ 0 ] == '-' ) {
	argv++;
	ac--;
	tran->t_pinfo.pi_minus = 1;
    } else {
	tran->t_pinfo.pi_minus = 0;
    }
    if ( argv[ 0 ][ 0 ] == '+' ) {
	argv++;
	ac--;
    }

    tran->t_pinfo.pi_type = argv[ 0 ][ 0 ];
    if (( epath = (filepath_t *) decode( argv[ 1 ] )) == NULL ) {
	fprintf( stderr, "%s: line %d: path too long\n",
		 (const char *) tran->t_fullname, tran->t_linenum );
	exit( 2 );
    }

    /* Convert path to match transcript type */
    if (( epath = convert_path_type( epath )) == NULL ) {;
	fprintf( stderr, "%s: line %d: path too long\n",
		 (const char *) tran->t_fullname,  tran->t_linenum );
	exit( 2 );
    }

    if ( pathcasecmp( epath, tran->t_pinfo.pi_name, case_sensitive ) <= 0 ) {
	fprintf( stderr, "%s: line %d: bad sort order\n",
		 (const char *) tran->t_fullname, tran->t_linenum );
	exit( 2 );
    }

    filepath_ncpy( tran->t_pinfo.pi_name, epath, sizeof(tran->t_pinfo.pi_name)-1);

    if (debug > 3)
    	fprintf (stderr, "*debug: transcript_parse(t:['%s'] from k:[%s] line %d) - type='%c' path='%s'\n",
		 (const char *) tran->t_shortname, 
		 (const char *) tran->t_kfile,
		 tran->t_linenum, tran->t_pinfo.pi_type, 
		 (const char *) epath);

    memset (&(tran->t_pinfo.pi_stat), 0, sizeof(tran->t_pinfo.pi_stat));

    /* reading and parsing the line */
    switch( *argv[ 0 ] ) {
    case 'd':				    /* dir */
	if (( ac != 5 ) && ( ac != 6 )) {
	    fprintf( stderr, "%s: line %d: expected 5 or 6 arguments, got %d\n",
		     (const char *) tran->t_fullname, tran->t_linenum, ac );
	    exit( 2 );
	}

	tran->t_pinfo.pi_stat.st_mode = strtol( argv[ 2 ], NULL, 8 );
	tran->t_pinfo.pi_stat.st_uid = atoi( argv[ 3 ] );
	tran->t_pinfo.pi_stat.st_gid = atoi( argv[ 4 ] );
	if ( ac == 6 ) {
	    base64_d( argv[ 5 ], strlen( argv[ 5 ] ),
		    (filepath_t *)tran->t_pinfo.pi_afinfo.ai.ai_data );
	} else {
	    memset( tran->t_pinfo.pi_afinfo.ai.ai_data, 0, FINFOLEN );
	}
	break;

    case 'p':
    case 'D':
    case 's':
	if ( ac != 5 ) {
	    fprintf( stderr, "%s: line %d: expected 5 arguments, got %d\n",
		     (const char *) tran->t_fullname, tran->t_linenum, ac );
	    exit( 2 );
	}
	tran->t_pinfo.pi_stat.st_mode = strtol( argv[ 2 ], NULL, 8 );
	tran->t_pinfo.pi_stat.st_uid = atoi( argv[ 3 ] );
	tran->t_pinfo.pi_stat.st_gid = atoi( argv[ 4 ] );
	break;

    case 'b':				    /* block or char */
    case 'c':
	if ( ac != 7 ) {
	    fprintf( stderr, "%s: line %d: expected 7 arguments, got %d\n",
		    tran->t_fullname, tran->t_linenum, ac );
	    exit( 2 );
	}
	tran->t_pinfo.pi_stat.st_mode = strtol( argv[ 2 ], NULL, 8 );
	tran->t_pinfo.pi_stat.st_uid = atoi( argv[ 3 ] );
	tran->t_pinfo.pi_stat.st_gid = atoi( argv[ 4 ] );
	tran->t_pinfo.pi_stat.st_rdev =
		makedev( ( unsigned )( atoi( argv[ 5 ] )), 
		( unsigned )( atoi( argv[ 6 ] )));
	break;

    case 'l':				    /* link */
	if ( ac == 3 ) {	/* link without owner, group, mode */
	    tran->t_pinfo.pi_stat.st_mode = 0777;
	    tran->t_pinfo.pi_stat.st_uid = 0;
	    tran->t_pinfo.pi_stat.st_gid = 0;
	} else if ( ac == 6 ) { /* link with owner, group, mode */
	    tran->t_pinfo.pi_stat.st_mode = strtol( argv[ 2 ], NULL, 8 );
	    tran->t_pinfo.pi_stat.st_uid = atoi( argv[ 3 ] );
	    tran->t_pinfo.pi_stat.st_gid = atoi( argv[ 4 ] );
	} else {
	    fprintf( stderr, "%s: line %d: expected 3 or 6 arguments, got %d\n",
		    tran->t_fullname, tran->t_linenum, ac );
	    exit( 2 );
	}
	if (( epath = (filepath_t *) decode( argv[ ac - 1 ] )) == NULL ) {
	    fprintf( stderr, "%s: line %d: target path too long\n",
		tran->t_fullname, tran->t_linenum );
	    exit( 2 );
	}
	strncpy( (char *) tran->t_pinfo.pi_link, 
		 (const char *) epath, sizeof(tran->t_pinfo.pi_link)-1 );
	break;

    case 'h':				    /* hard */
	if ( ac != 3 ) {
	    fprintf( stderr, "%s: line %d: expected 3 arguments, got %d\n",
		    tran->t_fullname, tran->t_linenum, ac );
	    exit( 2 );
	}
	if (( epath = (filepath_t *) decode( argv[ 2 ] )) == NULL ) {
	    fprintf( stderr, "%s: line %d: target path too long\n",
		tran->t_fullname, tran->t_linenum );
	    exit( 2 );
	}
	if (( epath = convert_path_type( epath )) == NULL ) {
	    fprintf( stderr, "%s: line %d: path too long\n",
		    tran->t_fullname, tran->t_linenum );
	    exit( 2 );
	}
	strncpy( (char *) tran->t_pinfo.pi_link, 
		 (const char *) epath , sizeof(tran->t_pinfo.pi_link)-1);
	break;

    case 'a':				    /* hfs applefile */
    case 'f':				    /* file */
	if ( ac != 8 ) {
	    fprintf( stderr, "%s: line %d: expected 8 arguments, got %d\n",
		    tran->t_fullname, tran->t_linenum, ac );
	    exit( 2 );
	}
	tran->t_pinfo.pi_stat.st_mode = strtol( argv[ 2 ], NULL, 8 );
	tran->t_pinfo.pi_stat.st_uid = atoi( argv[ 3 ] );
	tran->t_pinfo.pi_stat.st_gid = atoi( argv[ 4 ] );
	tran->t_pinfo.pi_stat.st_mtime = atoi( argv[ 5 ] );
	tran->t_pinfo.pi_stat.st_size = strtoofft( argv[ 6 ], NULL, 10 );
	if ( tran->t_type != T_NEGATIVE ) {
	    if (( cksum ) && ( strcmp( "-", argv [ 7 ] ) == 0  )) {
		fprintf( stderr, "%s: line %d: no cksums in transcript\n",
			tran->t_fullname, tran->t_linenum );
		exit( 2 );
	    }
	}
	strncpy( tran->t_pinfo.pi_cksum_b64, argv[ 7 ],
		 sizeof(tran->t_pinfo.pi_cksum_b64)-1 );

	break;

    default:
	fprintf( stderr,
	    "%s: line %d: unknown file type '%c'\n",
	    tran->t_fullname, tran->t_linenum, *argv[ 0 ] );
	exit( 2 );
    }

    return;
}

    void
t_print( pathinfo_t *fs, transcript_t *tran, int flag ) 
{
    pathinfo_t	*cur;
    filepath_t	*epath;
    dev_t		dev;
    int			print_minus = 0;

#ifdef __APPLE__
    static char         null_buf[ 32 ] = { 0 };
#endif /* __APPLE__ */

    if ( edit_path == APPLICABLE ) {
	cur = &tran->t_pinfo;
	if (( fs != NULL ) && ( fs->pi_type != 'd' ) &&
		( fs->pi_type != 'h' ) && ( fs->pi_stat.st_nlink > 1 )) {
	    hardlink_changed( fs, 1 );
	}
    } else {
	cur = fs;	/* What if this is NULL? */
    }

    /* Print name of transcript if it changed since the last t_print */
    if (( edit_path == APPLICABLE )
	    && (( flag == PR_TRAN_ONLY ) || ( flag == PR_DOWNLOAD )
		|| ( flag == PR_STATUS_NEG ))
	    && ( prev_tran != tran )) {
	fprintf( outtran, "%s:\n", tran->t_shortname );
	prev_tran = tran;
    }

    /*
     * If a file is missing from the edit_path that was chosen, a - is 
     * printed and then the file name that is missing is printed.
     */
    if ( edit_path == APPLICABLE ) {
	if ( flag == PR_FS_ONLY ) {
	    print_minus = 1;
	    cur = fs;
	} else if ( flag == PR_STATUS_MINUS ) {
	    fprintf( outtran, "- " );
	}
    } else if (( edit_path ==  CREATABLE ) &&
	    (( flag == PR_TRAN_ONLY ) || ( fs->pi_type == 'X' ))) {
	print_minus = 1;
	cur = &tran->t_pinfo;
    } 

    if ( print_minus ) {
	/* set fs_minus so we can handle excluded files in dirs to be deleted */
	fs_minus = 1;
	fprintf( outtran, "- " );
    }

    if (( epath = (filepath_t *) encode( (const char *) cur->pi_name )) == NULL ) {
      fprintf( stderr, "Filename too long: %s\n", (const char *) cur->pi_name );
	exit( 2 );
    }

    /* print out info to file based on type */
    switch( cur->pi_type ) {
    case 's':
    case 'D':
    case 'p':
	fprintf( outtran, "%c %-37s\t%.4lo %5d %5d\n", cur->pi_type, epath, 
		(unsigned long )( T_MODE & cur->pi_stat.st_mode ), 
		(int)cur->pi_stat.st_uid, (int)cur->pi_stat.st_gid );
	break;

    case 'd':
#ifdef __APPLE__
	if ( memcmp( cur->pi_afinfo.ai.ai_data, null_buf,
		sizeof( null_buf )) != 0 ) { 
	    char	finfo_e[ SZ_BASE64_E( FINFOLEN ) ];

	    base64_e( (char *)cur->pi_afinfo.ai.ai_data, FINFOLEN, finfo_e );
	    fprintf( outtran, "%c %-37s\t%.4lo %5d %5d %s\n", cur->pi_type,
		    epath,
		    (unsigned long)( T_MODE & cur->pi_stat.st_mode ), 
		    (int)cur->pi_stat.st_uid, (int)cur->pi_stat.st_gid,
		    finfo_e );
	    break;
	}
#endif /* __APPLE__ */
	fprintf( outtran, "%c %-37s\t%.4lo %5d %5d\n", cur->pi_type, epath, 
		(unsigned long )( T_MODE & cur->pi_stat.st_mode ), 
		(int)cur->pi_stat.st_uid, (int)cur->pi_stat.st_gid );
	break;

    case 'l':
	fprintf( outtran, "%c %-37s\t%.4lo %5d %5d ", cur->pi_type, epath,
		    (unsigned long)( T_MODE & cur->pi_stat.st_mode ),
		    (int)cur->pi_stat.st_uid, (int)cur->pi_stat.st_gid );
	if (( epath = (filepath_t *) encode((char *)cur->pi_link )) == NULL ) {
	    fprintf( stderr, "Filename too long: %s\n", cur->pi_link );
	    exit( 2 );
	}
	fprintf( outtran, "%s\n", epath );
	break;

    case 'h':
      fprintf( outtran, "%c %-37s\t", cur->pi_type, (char *) epath );
	if (( epath = (filepath_t *) encode( (char *) cur->pi_link )) == NULL ) {
	    fprintf( stderr, "Filename too long: %s\n", 
		     (const char *) cur->pi_link );
	    exit( 2 );
	}
	fprintf( outtran, "%s\n", (const char *) epath );
	break;

    case 'a':		/* hfs applesingle file */
    case 'f':
	if (( edit_path == APPLICABLE ) && (( flag == PR_TRAN_ONLY ) || 
		( flag == PR_DOWNLOAD ))) {
	    fprintf( outtran, "+ " );
	}

	/*
	 * If we don't have a checksum yet, and checksums are on, calculate
	 * it now.  Note that this can only be the case if "cur" is the
	 * filesystem, because transcript_parse() won't read lines without
	 * checksums if they are enabled.  But, don't get the checksum
	 * if we are just going to remove the file.
	 */
	if (( *cur->pi_cksum_b64 == '-' ) && cksum && !print_minus ) {
	    if ( cur->pi_type == 'f' ) {
		if ( do_cksum( cur->pi_name, cur->pi_cksum_b64 ) < 0 ) {
		  perror( (const char *) cur->pi_name );
		    exit( 2 );
		}
	    } else if ( cur->pi_type == 'a' ) {
		if ( do_acksum( cur->pi_name, cur->pi_cksum_b64,
			&cur->pi_afinfo ) < 0 ) {
		  perror( (const char *) cur->pi_name );
		    exit( 2 );
		}
	    }
	}

	/*
	 * PR_STATUS_NEG means we've had a permission change on a file,
	 * but the corresponding transcript is negative, hence, retain
	 * the file system's mtime.  Woof!
	 */
	fprintf( outtran, "%c %-37s\t%.4lo %5d %5d %9d %7" PRIofft "d %s\n",
		cur->pi_type, epath,
		(unsigned long)( T_MODE & cur->pi_stat.st_mode ), 
		(int)cur->pi_stat.st_uid, (int)cur->pi_stat.st_gid,
		( flag == PR_STATUS_NEG ) ?
			(int)fs->pi_stat.st_mtime : (int)cur->pi_stat.st_mtime,
		cur->pi_stat.st_size, cur->pi_cksum_b64 );
	break;

    case 'c':
    case 'b':
	dev = cur->pi_stat.st_rdev;
	fprintf( outtran, "%c %-37s\t%.4lo %5d %5d %5d %5d\n",
		cur->pi_type, epath,
		(unsigned long )( T_MODE & cur->pi_stat.st_mode ), 
		(int)cur->pi_stat.st_uid, (int)cur->pi_stat.st_gid,
		(int)major(dev), (int)minor(dev) );
	break;

    case 'X' :
      perror( (const char *) cur->pi_name );
	exit( 2 );

    default:
	fprintf( stderr, "%s: Unknown type: %c\n", cur->pi_name, cur->pi_type );
	exit( 2 );
    } 
}

   static int 
t_compare( pathinfo_t *fs, transcript_t *tran )
{
    int			cmp;
    mode_t		mode;
    mode_t		tran_mode;
    dev_t		dev;

    /*
     * If the transcript is at EOF, and we've exhausted the filesystem,
     * just return T_MOVE_FS, as this will cause transcript_check() to return.
     */
    if (( tran->t_eof ) && ( fs == NULL )) {
	return T_MOVE_FS;
    }

    if ( tran->t_eof ) {
	cmp = -1;
    } else {
	if ( fs == NULL ) {
	    /*
	     * If we've exhausted the filesystem, cmp = 1 means that
	     * name is in tran, but not fs.
	     */
	    cmp = 1;
	} else {
	    cmp = pathcasecmp( fs->pi_name, tran->t_pinfo.pi_name,
		case_sensitive );
	}
    }

    if ( cmp > 0 ) {
	/* name is in the tran, but not the fs */
	t_print( fs, tran, PR_TRAN_ONLY ); 
	return T_MOVE_TRAN;
    } 

    if ( cmp < 0 ) {
	/* name is not in the tran */
	t_print( fs, tran, PR_FS_ONLY );
	return T_MOVE_FS;
    } 

    /* convert the modes */
    mode = ( T_MODE & fs->pi_stat.st_mode );
    tran_mode = ( T_MODE & tran->t_pinfo.pi_stat.st_mode );

    /* the names match so check types */
    if ( fs->pi_type != tran->t_pinfo.pi_type ) {
	t_print( fs, tran, PR_DOWNLOAD );
	return T_MOVE_BOTH;
    }

    /* compare the other components for each file type */
    switch( fs->pi_type ) {
    case 'a':			    /* hfs applefile */
    case 'f':			    /* file */
	if ( tran->t_type != T_NEGATIVE ) {
	    if ( fs->pi_stat.st_size != tran->t_pinfo.pi_stat.st_size ) {
		t_print( fs, tran, PR_DOWNLOAD );
		break;
	    }
	    if ( cksum ) {
		if ( fs->pi_type == 'f' ) {
		    if ( do_cksum( fs->pi_name, fs->pi_cksum_b64 ) < 0 ) {
		      perror( (const char *) fs->pi_name );
			exit( 2 );
		    }
		} else if ( fs->pi_type == 'a' ) {
		    if ( do_acksum( fs->pi_name, fs->pi_cksum_b64,
			    &fs->pi_afinfo ) < 0 ) {
		      perror( (const char *) fs->pi_name );
			exit( 2 );
		    }
		}
		if ( strcmp( fs->pi_cksum_b64, tran->t_pinfo.pi_cksum_b64 ) != 0 ) {
		    t_print( fs, tran, PR_DOWNLOAD );
		    break;
		}
	    } else if ( fs->pi_stat.st_mtime != tran->t_pinfo.pi_stat.st_mtime ) {
		t_print( fs, tran, PR_DOWNLOAD );
		break;
	    }

	    if ( fs->pi_stat.st_mtime != tran->t_pinfo.pi_stat.st_mtime ) {
		t_print( fs, tran, PR_STATUS );
		break;
	    }
	}

	if (( fs->pi_stat.st_uid != tran->t_pinfo.pi_stat.st_uid ) || 
		( fs->pi_stat.st_gid != tran->t_pinfo.pi_stat.st_gid ) ||
		( mode != tran_mode )) {
	    if (( tran->t_type == T_NEGATIVE ) && ( edit_path == APPLICABLE )) {
		t_print( fs, tran, PR_STATUS_NEG );
	    } else {
		t_print( fs, tran, PR_STATUS );
	    }
	}
	break;

    case 'd':				/* dir */
#ifdef __APPLE__
	if ( tran->t_type != T_NEGATIVE ) {
	    if (( fs->pi_stat.st_uid != tran->t_pinfo.pi_stat.st_uid ) ||
		    ( fs->pi_stat.st_gid != tran->t_pinfo.pi_stat.st_gid ) ||
		    ( memcmp( fs->pi_afinfo.ai.ai_data,
		    tran->t_pinfo.pi_afinfo.ai.ai_data, FINFOLEN ) != 0 ) ||
		    ( mode != tran_mode )) {
		t_print( fs, tran, PR_STATUS );
	    }
	    break;
	}
#endif /* __APPLE__ */
	if (( fs->pi_stat.st_uid != tran->t_pinfo.pi_stat.st_uid ) ||
		( fs->pi_stat.st_gid != tran->t_pinfo.pi_stat.st_gid ) ||
		( mode != tran_mode )) {
	    t_print( fs, tran, PR_STATUS );
	}
	break;

    case 'D':
    case 'p':
    case 's':
	if (( fs->pi_stat.st_uid != tran->t_pinfo.pi_stat.st_uid ) ||
		( fs->pi_stat.st_gid != tran->t_pinfo.pi_stat.st_gid ) ||
		( mode != tran_mode )) {
	    t_print( fs, tran, PR_STATUS );
	}
	break;

    case 'l':			    /* link */
	if ( tran->t_type != T_NEGATIVE ) {
	  if (( filepath_cmp( fs->pi_link, tran->t_pinfo.pi_link ) != 0 )
#ifdef HAVE_LCHOWN
		 || ( fs->pi_stat.st_uid != tran->t_pinfo.pi_stat.st_uid ) ||
		    ( fs->pi_stat.st_gid != tran->t_pinfo.pi_stat.st_gid )
#endif /* HAVE_LCHOWN */
#ifdef HAVE_LCHMOD
		 || ( mode != tran_mode )
#endif /* HAVE_LCHMOD */
	    /* strcmp */ ) {
		t_print( fs, tran, PR_STATUS );
	    }
	}
	break;

    case 'h':			    /* hard */
      if (( filepath_cmp( fs->pi_link, tran->t_pinfo.pi_link ) != 0 ) ||
		( hardlink_changed( fs, 0 ) != 0 )) {
	    t_print( fs, tran, PR_STATUS );
	}
	break;

    case 'c':
	/*
	 * negative character special files only check major and minor
	 * devices numbers. pseudo ttys can change uid, gid and mode for
	 * every login and this is normal behavior.
	 */
	dev = fs->pi_stat.st_rdev;
	if ( tran->t_type != T_NEGATIVE ) {
	    if (( fs->pi_stat.st_uid != tran->t_pinfo.pi_stat.st_uid ) ||
		    ( fs->pi_stat.st_gid != tran->t_pinfo.pi_stat.st_gid ) || 
		    ( dev != tran->t_pinfo.pi_stat.st_rdev ) ||
		    ( mode != tran_mode )) {
		t_print( fs, tran, PR_STATUS );
	    }
	} else if ( dev != tran->t_pinfo.pi_stat.st_rdev ) {
	    t_print( fs, tran, PR_STATUS );
	}	
	break;

    case 'b':
	dev = fs->pi_stat.st_rdev;
	if (( fs->pi_stat.st_uid != tran->t_pinfo.pi_stat.st_uid ) ||
		( fs->pi_stat.st_gid != tran->t_pinfo.pi_stat.st_gid ) || 
		( dev != tran->t_pinfo.pi_stat.st_rdev ) ||
		( mode != tran_mode )) {
	    t_print( fs, tran, PR_STATUS );
	}	
	break;

    default:
	fprintf( stderr, "%s: Unknown type: %c\n", fs->pi_name, fs->pi_type );
	break;
    }

    return T_MOVE_BOTH;
}

    int
t_exclude( const filepath_t *path )
{
    struct node		*cur;

    if ( list_size( exclude_list ) > 0 ) {
	for ( cur = exclude_list->l_head; cur != NULL; cur = cur->n_next ) {
	    if ( wildcard( cur->n_path, path, case_sensitive )) {
		return( 1 );
	    }
	}
    }

    return( 0 );
}

/* 
 * Loop through the list of transcripts and compare each
 * to find which transcript to start with. Only switch to the
 * transcript if it is not at EOF.  A transcript at EOF may
 * still be returned.
 */
    transcript_t *
transcript_select( void )
{
    transcript_t	*next_tran = NULL;
    transcript_t	*begin_tran = NULL;

    for (;;) {
	for ( begin_tran = tran_head, next_tran = tran_head->t_next;
		next_tran != NULL; next_tran = next_tran->t_next ) {
	    if ( begin_tran->t_eof ) {
		begin_tran = next_tran;
		continue;
	    }
	    if ( ! next_tran->t_eof ) {
		if ( pathcasecmp( next_tran->t_pinfo.pi_name,
			begin_tran->t_pinfo.pi_name, case_sensitive ) < 0 ) {
		    begin_tran = next_tran;
		}
	    }
	}

	/* move ahead other transcripts that match */
	for ( next_tran = begin_tran->t_next; next_tran != NULL;
		next_tran = next_tran->t_next ) {
	    if ( pathcasecmp( begin_tran->t_pinfo.pi_name,
		    next_tran->t_pinfo.pi_name, case_sensitive ) == 0 ) {
		transcript_parse( next_tran );
	    }
	}

	/* This is presumably the NULL transcript. */
	if ( !begin_tran->t_eof ) {
	    /*
	     * If the highest precedence transcript line has a leading '-',
	     * then just pretend it's not there.
	     */
	    if ( begin_tran->t_pinfo.pi_minus ) {
		transcript_parse( begin_tran );
		continue;
	    }

	    /* If we match an exclude pattern, pretend we don't see it */
	    if ( begin_tran->t_type != T_SPECIAL &&
		    t_exclude( begin_tran->t_pinfo.pi_name )) {
		if ( exclude_warnings ) {
		    fprintf( stderr, "Warning: excluding %s\n",
				begin_tran->t_pinfo.pi_name );
		}
		transcript_parse( begin_tran );
		continue;
	    }

	    /* Don't look outside of the initial path. */
	
	    if ( !ischildcase( begin_tran->t_pinfo.pi_name,
			       (filepath_t *) path_prefix,
			       case_sensitive )) {
		transcript_parse( begin_tran );
		continue;
	    }
	}

	return( begin_tran );
    }
}

    int
transcript_check( const filepath_t *path, struct stat *st, char *type,
		struct applefileinfo *afinfo, int parent_minus )
{
    pathinfo_t		pi;
    int			enter = 0;
    int 		len;
    char		epath[ MAXPATHLEN ];
    char		*linkpath;
    transcript_t	*tran = NULL;

    fs_minus = 0;

    /*
     * path is NULL when we've been called after the filesystem has been
     * exhausted, to consume any remaining transcripts.
     */
    if ( path != NULL ) {
	/*
	 * check for exclude match first to avoid any unnecessary work.
	 * special files still have highest precedence.
	 */
	if ( t_exclude( path ) && !parent_minus ) {
	    if ( list_size( special_list ) <= 0
		    || list_check( special_list, path ) == 0 ) {
		if ( exclude_warnings ) {
		    fprintf( stderr, "Warning: excluding %s\n", path );
		}

		/* move the transcripts ahead */
		tran = transcript_select();

		return( 0 );
	    }
	}

	strncpy( (char *) pi.pi_name, (const char *) path, sizeof(pi.pi_name)-1 );
	pi.pi_stat = *st;
	pi.pi_type = *type;
	pi.pi_afinfo = *afinfo;

	/* if it's multiply referenced, check if it's a hardlink */
	if ( !S_ISDIR( pi.pi_stat.st_mode ) && ( pi.pi_stat.st_nlink > 1 ) &&
		(( linkpath = hardlink( &pi )) != NULL )) {
	    pi.pi_type = 'h';
	    strncpy( (char *) pi.pi_link, linkpath, sizeof(pi.pi_link)-1 );
	} else if ( S_ISLNK( pi.pi_stat.st_mode )) {
	  len = readlink( (const char *) pi.pi_name, epath, MAXPATHLEN );
	    epath[ len ] = (filepath_t) '\0';
	    strncpy( (char *) pi.pi_link, (const char *) epath , sizeof(pi.pi_link)-1);
	}

	/* By default, go into directories */
	if ( S_ISDIR( pi.pi_stat.st_mode )) {
	    enter = 1;
	} else { 
	    enter = 0;
	}

	/* initialize cksum field. */
	strncpy( pi.pi_cksum_b64, "-", sizeof(pi.pi_cksum_b64)-1 ); /* excessive */
    }

    for (;;) {
	tran = transcript_select();

	switch ( t_compare(( path ? &pi : NULL ), tran )) {
	case T_MOVE_FS :
	    return( enter );

	case T_MOVE_BOTH :
	    /* But don't go into negative directories */
	    if (( tran->t_type == T_NEGATIVE ) &&
		    ( tran->t_pinfo.pi_type == 'd' )) {
		enter = 2;
	    }
	    transcript_parse( tran );
	    return( enter );

	case T_MOVE_TRAN :
	    transcript_parse( tran );
	    break;

	default :
	    fprintf( stderr, "t_compare returned an unexpected value!\n" );
	    exit( 2 );
	}
    }
}

    void
t_new( int type, const filepath_t *fullname, const filepath_t *shortname, const filepath_t *kfile ) 
{
    transcript_t	 *new;
    static int id=0;
    ssize_t got;   /* result of read() */

    id++;
    if (( new = (transcript_t *)calloc(1, sizeof( transcript_t )))
	    == NULL ) {
	perror( "malloc" );
	exit( 2 );
    }
    if (debug > 4)
	fprintf (stderr, "*debug: t_new(%d, '%s', '%s', '%s'), calloc() returns %p\n",
		type, (char *) fullname, (char *) shortname, (char *) kfile, new);

    new->id = id;

    /* Safety. */
    new->buffered = NULL;
    new->buffer_position = NULL;

    new->t_type = type;
    switch ( type ) {
    case T_NULL :
	new->t_eof = 1; 
	break;

    case T_POSITIVE :
    case T_NEGATIVE :
    case T_SPECIAL :
	new->t_eof = 0; 
	new->t_linenum = 0;

	strncpy( (char *) new->t_shortname, (const char *) shortname,
		 sizeof(new->t_shortname)-1 );

	strncpy( (char *) new->t_fullname, (const char *) fullname,
		 sizeof(new->t_fullname)-1 );

	strncpy( (char *) new->t_kfile, (const char *) kfile,
		 sizeof(new->t_kfile)-1);

	if (( new->t_in = fopen((char *) fullname, "r" )) == NULL ) {
	    perror( (const char *)fullname );
	    exit( 2 );
	}

	if (debug > 3)
	  fprintf (stderr, "*debug: t_new (%d, ..., '%s', '%s') id=%u\n",
		   type, (const char *) shortname, (const char *) kfile, id);

	/* Check to see if we do buffering. */
	transcripts_unbuffered ++;

	if( transcript_buffer_size > 0) {
	    struct stat tran_stat;  /* Stat the transcript file */
 
	    if (fstat (fileno(new->t_in), &tran_stat) != 0) {
	      int save_errno = errno;

	      fprintf (stderr,
		       "ERROR: Unable to fstat(%d,...) for '%s', error %d: %s\n",
		       fileno (new->t_in), (char *) fullname, save_errno,
		       strerror (save_errno));
	      fprintf (stderr, "ERROR: Buffering turned off\n");
	      transcript_buffer_size = 0;
	    }
	    else if (tran_stat.st_size <= transcript_buffer_size) {
	      size_t buflen = tran_stat.st_size + 1;

	      if( (new->buffered = (char *) calloc (1, buflen)) == NULL) {
		int save_errno = errno;

		fprintf (stderr, 
			 "ERROR: Unable to allocate transcript buffer size %ul for '%s', error %d: %s\n",
			 
			 (unsigned long) buflen, (char *) fullname,
			 save_errno, strerror (save_errno));
		fprintf (stderr, "ERROR: Buffering turned off\n");
		transcript_buffer_size = 0;
	      }
	      else {
		if (debug > 4)
			fprintf (stderr, "*debug: t_new() - calloc(1, %lu) returns 0x%p\n",
					buflen, new->buffered);

		got = read (fileno(new->t_in), new->buffered, buflen);

		if (got != (buflen-1)) {
		  fprintf (stderr, "FATAL ERROR: Didn't read entire transcript ('%s') at once, %lld of %llu\n",
			   fullname, got, buflen);
		  exit (5);
		}

		new->buffered[got] = '\0'; /* Saftey. */
		new->buffer_position = new->buffered;

		transcripts_buffered ++;
		transcripts_unbuffered --;

		fclose (new->t_in);
		new->t_in = (FILE *) NULL;
	      }
	    } 
	} /* end of if( transcript_buffer_size > 0) */

	transcript_parse( new );
	break;

    default :
    	if (debug > 1)
	   fprintf (stderr, "*debug: t_new (%d, ..., '%s', '%s') id=%u, type error?\n", 
		    type, (const char *) shortname, (const char *) kfile, id);
	break;
    }

    new->t_next = tran_head;
    if ( tran_head != (transcript_t *) NULL ) {
	new->t_num = new->t_next->t_num + 1;
    }
    tran_head = new;

    return;
}

    static void
t_remove( int type, const filepath_t *shortname )
{
    transcript_t
          **p_next = &tran_head,
  	  *cur;
    unsigned int last_id = 0;
    unsigned int count = 0;

    if (debug > 2)
        fprintf (stderr, "*debug: t_remove (%d, '%s')\n", type, shortname);

    while (*p_next != (transcript_t *) NULL)
      {
	cur = *p_next;

	if (debug > 3)
	    fprintf (stderr,
		     "*debug: t_remove() - check type=%d, t:['%s'] from k:['%s'] ID=%d\n", 
		     cur->t_type, (const char *) cur->t_shortname, 
		     (const char *) cur->t_kfile, cur->id);
	if (debug > 4)
	    fprintf (stderr, "*debug: at %p\n", cur);

	if ((cur->t_type == type)  &&
	    (filepath_cmp (cur->t_shortname, shortname) == 0)) {

	   if (debug > 2)
	   	fprintf (stderr,
			 "*debug: t_remove () - found ID=%u after %u\n",
			 cur->id, last_id);

	   /* Cleanup unused file descriptors. */
 	   if (cur->t_in) {
	   	fclose (cur->t_in);
		cur->t_in = (FILE *) NULL;
	   }

	   if (cur->buffered) {
	        free (cur->buffered);
		cur->buffered = NULL;
	   }

	   /*
	    * Unlink current from list.
	    */
	   *p_next = cur->t_next;
	   count ++;

	   free (cur);
	}  /* (filepath_cmp) */
	else {
	   last_id = cur->id;
	   p_next = &(cur->t_next);
        }
    } /* end of while (*p_cur) ... */

    if ((count != 1) && (debug > 2))
    	fprintf (stderr,
		 "*debug: t_remove (%d, '%s') found %u instances\n",
		 type, shortname, count);

    return;
}

    static void
t_display( void )
{
    transcript_t		*cur = NULL;

    for ( cur = tran_head; cur != NULL; cur = cur->t_next ) {
	printf( "%d: ", cur->t_num );
	switch( cur->t_type ) {
	case T_POSITIVE:
	    printf( "p %s\n", cur->t_shortname );
	    break;

	case T_NEGATIVE:
	    printf( "n %s\n", cur->t_shortname );
	    break;

	case T_SPECIAL:
	    printf( "s %s\n", cur->t_shortname );
	    break;

	case T_NULL:
	    printf( "NULL\n" );
	    break;

	default:
	    printf( "? %s\n", cur->t_shortname );
	    break;
	}
    }
    return;
}

    void
transcript_init( const filepath_t *kfile, int location )
{
    filepath_t *special = (filepath_t *) "special.T";
    filepath_t *p;
    filepath_t fullpath[ MAXPATHLEN ];

    /*
     * Make sure that there's always a transcript to read, so other code
     * doesn't have to check it.
     */
    t_new( T_NULL, NULL, NULL, NULL );

    if ( skip ) {
	return;
    }

    if (( kdir = filepath_dup( kfile )) == NULL ) {
        perror( "strdup failed" );
        exit( 2 );
    }
    if (( p = (filepath_t *) strrchr( (const char *) kdir, '/' )) == NULL ) {
        /* No '/' in kfile - use working directory */
	free( kdir );
        kdir = (filepath_t *) "./";
    } else {
        p++;
        *p = (filepath_t) '\0';
    }
    if (( kfile_list = list_new( )) == NULL ) {
	perror( "list_new" );
	exit( 2 );
    }
    if ( list_insert( kfile_list, kfile ) != 0 ) {
	perror( "list_insert" );
	exit( 2 );
    }
    if (( special_list = list_new( )) == NULL ) {
	perror( "list_new" );
	exit( 2 );
    }
    if (( exclude_list = list_new()) == NULL ) {
	perror( "list_new" );
	exit( 2 );
    }
    if ( read_kfile( kfile,location ) != 0 ) {
	exit( 2 );
    }

    if (( list_size( special_list ) > 0 ) && ( location == K_CLIENT )) {
	/* open the special transcript if there were any special files */
      if ( (filepath_len( kdir ) + filepath_len( special ) +2)
	   		 > MAXPATHLEN ) {
	    fprintf( stderr, 
		    "special path too long: %s%s\n", kdir, special );
	    exit( 2 );
	}
	sprintf( (char *) fullpath, "%s%s", (const char *) kdir,
		 ( const char *) special );
	t_new( T_SPECIAL, fullpath, special, (filepath_t *) "special" );
    }

    if ( tran_head->t_type == T_NULL  && edit_path == APPLICABLE ) {
	fprintf( stderr, "-A option requires a non-NULL transcript\n" );
	exit( 2 );
    }

    return;
}

    int
read_kfile( const filepath_t *kfile, int location )
{
    int		        length,
      			ac,
      			linenum = 0,
      			minus = 0;
    char 	     	line[ MAXPATHLEN ];
    filepath_t        	fullpath[ MAXPATHLEN ];
    filepath_t         *subpath;
    const filepath_t   *d_pattern,
      		       *path;
    char	      **av;
    FILE	       *fp;
    static int          depth = 0;

    if (( fp = fopen( (char *) kfile, "r" )) == NULL ) {
        perror( (const char *) kfile );
	return( -1 );
    }

    depth++;
    if (debug > 2)
    	fprintf (stderr,
		 "*debug: read_kfile('%s', %d) fd=%d, depth=%d\n", 
		 (const char *) kfile, location, fileno(fp), depth);

    while ( fgets( line, sizeof( line ), fp ) != NULL ) {
	linenum++;
	length = strlen( line );
	if ( line[ length - 1 ] != '\n' ) {
	    fprintf( stderr, "command file %s: line %d: line too long\n",
		     (const char *) kfile, linenum );
	    depth--;
	    return( -1 );
	}

	/* skips blank lines and comments */
	if ((( ac = argcargv( line, &av )) == 0 ) || ( *av[ 0 ] == '#' )) {
	    continue;
	}

	if ( *av[ 0 ] == '-' ) {
	    minus = 1;
	    av++;
	    ac--;
	} else {
	    minus = 0;
	}

	if ( ac != 2 ) {
	    fprintf( stderr,
		"command file %s: line %d: expected 2 arguments, got %d\n",
		     (const char *) kfile, linenum, ac );
	    depth--;
	    return( -1 );
	} 

	switch( location ) {
	case K_CLIENT:
	  if ( snprintf( (char *) fullpath, MAXPATHLEN, "%s%s", (char *) kdir,
		    av[ 1 ] ) >= MAXPATHLEN ) {
		fprintf( stderr, "comand file %s: line %d: path too long\n",
			kfile, linenum );
		fprintf( stderr, "command file %s: line %d: %s%s\n",
			kfile, linenum, kdir, av[ 1 ] );
	        depth--;
		return( -1 );
	    }
	    break;

	case K_SERVER:
	    if ( *av[ 0 ] == 'k' ) {
	        subpath = (filepath_t *) "command";
	    } else {
	        subpath = (filepath_t *) "transcript";
	    }
	    if ( snprintf( (char *) fullpath, MAXPATHLEN, "%s/%s/%s",
			   _RADMIND_PATH,  (char *) subpath, av[ 1 ] ) >= MAXPATHLEN ) {
		fprintf( stderr, "command file %s: line %d: path too long\n",
			kfile, linenum );
		fprintf( stderr, "command file %s: line %d: %s%s\n",
			kfile, linenum, kdir, av[ 1 ] );
		depth--;
		return( -1 );
	    }
	    break;

	default:
	    fprintf( stderr, "unknown location\n" );
	    depth--;
	    return( -1 );
	}

	switch( *av[ 0 ] ) {
	case 'k':				/* command file */
	    if ( minus ) {
		/* Error on minus command files for now */
		fprintf( stderr, "command file %s: line %d: "
		    "minus 'k' not supported\n", kfile, linenum );
		depth--;
		return( -1 );
	    } else {
		if ( list_check( kfile_list, fullpath )) {
		    fprintf( stderr,
			"command file %s: line %d: command file loop: %s already included\n",
			kfile, linenum, av[ 1 ] );
		    depth--;
		    return( -1 );
		}
		if ( list_insert( kfile_list, fullpath ) != 0 ) {
		    perror( "list_insert" );
		    depth --;
		    return( -1 );
		}
		if ( read_kfile( fullpath, location ) != 0 ) {
		    if(debug) 
		    	fprintf (stderr,
				 "*debug: read_kfile ('%s', ...) failed\n",
				 (char *) fullpath);
		    depth--;
		    return( -1 );
		}
	    }

	    break;

	case 'n':				/* negative */
	    if ( minus ) { 
	      t_remove( T_NEGATIVE, (filepath_t *) av[ 1 ] );
	    } else {
	      t_new( T_NEGATIVE, fullpath, (filepath_t *) av[ 1 ], kfile );
	    }
	    break;

	case 'p':				/* positive */
	    if ( minus ) {
	      t_remove( T_POSITIVE, (filepath_t *) av[ 1 ] );
	    } else {
	      t_new( T_POSITIVE, fullpath, (filepath_t *) av[ 1 ], kfile );
	    }
	    break;

	case 'x':				/* exclude */
	  if (( d_pattern = (filepath_t *) decode( av[ 1 ] )) == NULL ) {
		fprintf( stderr, "%s: line %d: decode buffer too small\n",
			 (const char *) kfile, linenum );
	    }

	    /* Convert path to match transcript type */
	    if (( d_pattern = convert_path_type( d_pattern )) == NULL ) {
		fprintf( stderr, "%s: line %d: path too long\n",
			 (const char *) kfile, linenum );
		depth--;
		exit( 2 );
	    }

	    if ( minus ) {
		list_remove( exclude_list, d_pattern );
	    } else {
		if ( !list_check( exclude_list, d_pattern )) {
		    if ( list_insert( exclude_list, d_pattern ) != 0 ) {
			perror( "list_insert" );
			depth--;
			return( -1 );
		    }
		}
	    }
	    break;

	case 's':				/* special */
	    path = (filepath_t *) av[ 1 ];

	    /* Convert path to match transcript type */
	    if (( path = convert_path_type( path )) == NULL ) {
		fprintf( stderr, "%s: line %d: path too long\n",
			 (const char *) kfile, linenum );
		depth--; 
		exit( 2 );
	    }

	    if ( minus ) {
		if ( list_check( special_list, path )) {
		    list_remove( special_list, path );
		}
	    } else {
		if ( !list_check( special_list, path )) {
		    if ( list_insert( special_list, path ) != 0 ) {
			perror( "list_insert" );
			depth--;
			return( -1 );
		    }
		}

	    }
	    break;

	default:
	    fprintf( stderr, "command file %s: line %d: '%s' invalid\n",
		     (const char *) kfile, linenum, av[ 0 ] );
	    depth--;
	    return( -1 );
	}
    }

    if (debug > 2)
    	fprintf (stderr, "*debug: end of read_kfile() fd=%d, depth=%d\n", 
		fileno (fp), depth);

    depth--;

    if ( fclose( fp ) != 0 ) {
        perror( (const char *) kfile );
	return( -1 );
    }

    return( 0 );
}

    void
transcript_free( )
{
    transcript_t	 *next;

    /*
     * Call transcript_check() with NULL to indicate that we've run out of
     * filesystem to compare against.
     */
    transcript_check( NULL, NULL, NULL, NULL, 0 );

    while ( tran_head != NULL ) {
	next = tran_head->t_next;
	if ( tran_head->t_in != NULL ) {
	    fclose( tran_head->t_in );
	    tran_head->t_in = (FILE *) NULL;
	}
	if ( tran_head->buffered != NULL) {
	  free( tran_head->buffered );
	  tran_head->buffered = NULL;
	}
	free( tran_head );
	tran_head = next;
    }
}
