/*
 * Copyright (c) 2003, 2007, 2013-2015 Regents of The University of Michigan.
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
#include <sysexits.h>
#include <stdarg.h>

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
static int transcript_kfile( const filepath_t *kfile, int location );
static void t_remove( rad_Transcript_t type, const filepath_t *shortname );
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
int				verbose = 0;	 /* For warning messages. */
size_t                          transcript_buffer_size = DEFAULT_TRANSCRIPT_BUFFER_SIZE;  /* If 0, no buffering */
unsigned int                    transcripts_buffered = 0;
unsigned int                    transcripts_unbuffered = 0;

/* switches governing the behavior of transcript_check() */
int radmind_transcript_check_switches = RADTC_SWS_UID | RADTC_SWS_GID | RADTC_SWS_MTIME | RADTC_SWS_MODE | RADTC_SWS_SIZE;


#if defined(__GNUC__)
#  define HAVE_ATTRIBUTE_FORMAT_PRINTF 1
#endif /* __GNUC__ */


#if defined(HAVE_ATTRIBUTE_FORMAT_PRINTF)
#  define ATTR_PRINTF(_begin,_end) __attribute__ (( format( printf,_begin,_end)))
#else
#  define ATTR_PRINTF(_begin,_end) /* empty */
#endif /* HAVE_ATTRIBUTE_FORMAT_PRINTF */


static int t_fprintf_err(FILE *out, const transcript_t *tran, 
			 const char *fmt, ...) ATTR_PRINTF(3,4);


static int
t_fprintf_err(FILE *out, const transcript_t *tran, const char *fmt, ...) 
{
  int result = 0;
  va_list ap;

  va_start(ap, fmt);

  if ((out != (FILE *) NULL) && (tran != (transcript_t *) NULL))  {
      fprintf(out, "'%s' line %u: ", tran->t_fullname, tran->t_linenum);
      vfprintf(out, fmt, ap);
  }

  va_end(ap);

  return result;
} /* end of t_fprintf_err() */



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
    char			**av = (char **) NULL;
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
	          alert_transcript(NULL, stderr, tran,
				   "%s() - empty (buffer EOF, skipping %u)",
				   __func__, counted);

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
	  if (debug > 2) {
	      alert_transcript (NULL, stderr, tran, 
				"%s() - buffered line after skipping %u",
				__func__, counted);
	      fprintf(stderr, "*\t'%s'\n", line);
	  }

	  strncat (line, "\n", sizeof(line)-1);  /* Put EOL back. */
        }
	else if (( fgets( line, sizeof(line)-1, tran->t_in )) == NULL ) {
	    tran->t_eof = 1;
	    if (debug > 2)
	        alert_transcript(NULL, stderr, tran, 
				 "%s() - empty (EOF, skipping %u)",
				 __func__, counted); 

	    return;
	}
	tran->t_linenum++;
	counted++;

	/* check to see if line contains the whole line */
	length = strlen( line );
	if ( line[ length - 1 ] != '\n' ) {
	    t_fprintf_err(stderr, tran, "line too long\n");
	    exit(EX_SOFTWARE);  /* from <sysexits.h> */
	} 

    } while ((( ac = argcargv( line, &av )) == 0 ) || ( *av[ 0 ] == '#' ));

    if ( ac < 3 ) {
        t_fprintf_err(stderr, tran, "minimum 3 arguments, got %d\n",  ac );
	exit( EX_DATAERR ); /* from <sysexits.h> */
    }

    if ( strlen( av[ 0 ] ) != 1 ) {
        t_fprintf_err(stderr, tran, "%s is too long to be a type\n",
		       av[ 0 ] );
	exit( EX_DATAERR ); /* from <sysexits.h> */
    }

    if ( av[ 0 ][ 0 ] == '-' ) {
	av++;
	ac--;
	tran->t_pinfo.pi_minus = 1;
    } else {
	tran->t_pinfo.pi_minus = 0;
    }
    if ( av[ 0 ][ 0 ] == '+' ) {
	av++;
	ac--;
    }

    tran->t_pinfo.pi_type = av[ 0 ][ 0 ];
    if (( epath = (filepath_t *) decode( av[ 1 ] )) == NULL ) {
        t_fprintf_err( stderr, tran, "path decoding failed\n");
	exit( EX_DATAERR ); /* from <sysexits.h> */
    }

    /* Convert path to match transcript type */
    if (( epath = convert_path_type( epath )) == NULL ) {;
        t_fprintf_err( stderr, tran, "path conversion failed\n");
	exit( EX_DATAERR ); /* from <sysexits.h> */
    }

    if ( pathcasecmp( epath, tran->t_pinfo.pi_name, case_sensitive ) <= 0 ) {
        t_fprintf_err( stderr, tran, "bad sort order\n");
	exit( EX_DATAERR ); /* from <sysexits.h> */
    }

    filepath_ncpy( tran->t_pinfo.pi_name, epath,
		   sizeof(tran->t_pinfo.pi_name)-1);

    if (debug > 3)
        alert_transcript (NULL, stderr, tran, "%s() - type='%c', path='%s'",
			  __func__, tran->t_pinfo.pi_type,
			  (const char *) epath);
    
    memset (&(tran->t_pinfo.pi_stat), 0, sizeof(tran->t_pinfo.pi_stat));

    /* reading and parsing the line */
    switch( *av[ 0 ] ) {
    case 'd':				    /* dir */
	if (( ac != 5 ) && ( ac != 6 )) {
	    t_fprintf_err( stderr, tran, "expected 5 or 6 arguments, got %d\n",
			   ac );
	    exit( EX_DATAERR ); /* from <sysexits.h> */
	}

	tran->t_pinfo.pi_stat.st_mode = strtol( av[ 2 ], NULL, 8 );
	tran->t_pinfo.pi_stat.st_uid = atoi( av[ 3 ] );
	tran->t_pinfo.pi_stat.st_gid = atoi( av[ 4 ] );
	if ( ac == 6 ) {
	    base64_d( av[ 5 ], strlen( av[ 5 ] ),
		    (filepath_t *)tran->t_pinfo.pi_afinfo.ai.ai_data );
	} else {
	    memset( tran->t_pinfo.pi_afinfo.ai.ai_data, 0, FINFOLEN );
	}
	break;

    case 'p':
    case 'D':
    case 's':
	if ( ac != 5 ) {
	    t_fprintf_err( stderr, tran, "expected 5 arguments, got %d\n",
			   ac );
	    exit( EX_DATAERR );
	}
	tran->t_pinfo.pi_stat.st_mode = strtol( av[ 2 ], NULL, 8 );
	tran->t_pinfo.pi_stat.st_uid = atoi( av[ 3 ] );
	tran->t_pinfo.pi_stat.st_gid = atoi( av[ 4 ] );
	break;

    case 'b':				    /* block or char */
    case 'c':
	if ( ac != 7 ) {
	    t_fprintf_err( stderr, tran, "expected 7 arguments, got %d\n",
			   ac );
	    exit( EX_DATAERR );
	}
	tran->t_pinfo.pi_stat.st_mode = strtol( av[ 2 ], NULL, 8 );
	tran->t_pinfo.pi_stat.st_uid = atoi( av[ 3 ] );
	tran->t_pinfo.pi_stat.st_gid = atoi( av[ 4 ] );
	tran->t_pinfo.pi_stat.st_rdev =
		makedev( ( unsigned )( atoi( av[ 5 ] )), 
		( unsigned )( atoi( av[ 6 ] )));
	break;

    case 'l':				    /* link */
	if ( ac == 3 ) {	/* link without owner, group, mode */
	    tran->t_pinfo.pi_stat.st_mode = 0777;
	    tran->t_pinfo.pi_stat.st_uid = 0;
	    tran->t_pinfo.pi_stat.st_gid = 0;
	} else if ( ac == 6 ) { /* link with owner, group, mode */
	    tran->t_pinfo.pi_stat.st_mode = strtol( av[ 2 ], NULL, 8 );
	    tran->t_pinfo.pi_stat.st_uid = atoi( av[ 3 ] );
	    tran->t_pinfo.pi_stat.st_gid = atoi( av[ 4 ] );
	} else {
	    t_fprintf_err( stderr, tran, "symlink expected 3 or 6 arguments, got %d\n",
			   ac );
	    exit( EX_DATAERR );
	}

	if (( epath = (filepath_t *) decode( av[ ac - 1 ] )) == NULL ) {
	    t_fprintf_err( stderr, tran, "symlink path decode failed\n");
	    exit( EX_DATAERR );
	}
	strncpy( (char *) tran->t_pinfo.pi_link, 
		 (const char *) epath, sizeof(tran->t_pinfo.pi_link)-1 );
	break;

    case 'h':				    /* hard */
	if ( ac != 3 ) {
	    t_fprintf_err( stderr, tran, "hardlink expected 3 arguments, got %d\n",
			   ac );
	    exit( EX_DATAERR );
	}
	if (( epath = (filepath_t *) decode( av[ 2 ] )) == NULL ) {
	    t_fprintf_err(stderr, tran, "hardlink target path decode failed\n");
			  
	    exit( EX_DATAERR );
	}
	if (( epath = convert_path_type( epath )) == NULL ) {
	    t_fprintf_err( stderr, tran, "hardlink path conversion failed\n");
	    exit( EX_DATAERR );
	}
	strncpy( (char *) tran->t_pinfo.pi_link, 
		 (const char *) epath , sizeof(tran->t_pinfo.pi_link)-1);
	break;

    case 'a':				    /* hfs applefile */
    case 'f':				    /* file */
	if ( ac != 8 ) {
	    t_fprintf_err( stderr, tran, "expected 8 arguments, got %d\n",
			   ac );
	    exit( EX_DATAERR );
	}
	tran->t_pinfo.pi_stat.st_mode = strtol( av[ 2 ], NULL, 8 );
	tran->t_pinfo.pi_stat.st_uid = atoi( av[ 3 ] );
	tran->t_pinfo.pi_stat.st_gid = atoi( av[ 4 ] );
	tran->t_pinfo.pi_stat.st_mtime = atoi( av[ 5 ] );
	tran->t_pinfo.pi_stat.st_size = strtoofft( av[ 6 ], NULL, 10 );
	if ( tran->t_type != T_NEGATIVE ) {
	    if (( cksum ) && ( strcmp( "-", av [ 7 ] ) == 0  )) {
	        t_fprintf_err( stderr, tran, "no cksums in transcript\n" );
		exit( EX_DATAERR );
	    }
	}
	strncpy( tran->t_pinfo.pi_cksum_b64, av[ 7 ],
		 sizeof(tran->t_pinfo.pi_cksum_b64)-1 );

	break;

    default:
        t_fprintf_err( stderr, tran, "unknown file type '%c'\n", *av[ 0 ] );
	exit( EX_DATAERR );
    }

    tran->total_objects ++;

    return;
} /* end of transcript_parse() */



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
        alert_transcript ("FATAL: ", stderr, tran, "Filename too long: '%s'",
			  (const char *) cur->pi_name );
	exit( EX_DATAERR );
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
	    exit( EX_DATAERR );
	}
	fprintf( outtran, "%s\n", epath );
	break;

    case 'h':
      fprintf( outtran, "%c %-37s\t", cur->pi_type, (char *) epath );
	if (( epath = (filepath_t *) encode( (char *) cur->pi_link )) == NULL ) {
	    fprintf( stderr, "Filename too long: %s\n", 
		     (const char *) cur->pi_link );
	    exit( EX_DATAERR );
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
		    exit( EX_DATAERR );
		}
	    } else if ( cur->pi_type == 'a' ) {
		if ( do_acksum( cur->pi_name, cur->pi_cksum_b64,
			&cur->pi_afinfo ) < 0 ) {
		    perror( (const char *) cur->pi_name );
		    exit( EX_DATAERR );
		}
	    }
	}

	/*
	 * PR_STATUS_NEG means we've had a permission change on a file,
	 * but the corresponding transcript is negative, hence, retain
	 * the file system's mtime.  Woof!
	 */
	fprintf( outtran, "%c %-37s\t%.4lo %5d %5d %9d %7" PRIofft " %s\n",
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
	exit( EX_DATAERR );

    default:
	fprintf( stderr, "%s: Unknown type: %c\n", cur->pi_name, cur->pi_type );
	exit( EX_DATAERR );
    } 
}

   static int 
t_compare( pathinfo_t *fs, transcript_t *tran )
{
    int			cmp;
    mode_t		mode;
    mode_t		tran_mode;
    dev_t		dev;

    static unsigned int warn_countdown = 3;  /* Warn about metadata changes requiring download. */

#define _TCC(_flag) ((radmind_transcript_check_switches & _flag) == _flag)
#define _TCC_UID _TCC(RADTC_SWS_UID)
#define _TCC_GID _TCC(RADTC_SWS_GID)
#define _TCC_MTIME _TCC(RADTC_SWS_MTIME)
#define _TCC_MODE _TCC(RADTC_SWS_MODE)
#define _TCC_SIZE _TCC(RADTC_SWS_SIZE)
#define _TCC_CKSUM _TCC(RADTC_SWS_CKSUM)

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
	    /*
	     * A size change is gross enough to force a new download.
	     * Don't even bother with a checksum check.
	     */
	    if ( _TCC_SIZE && (fs->pi_stat.st_size != tran->t_pinfo.pi_stat.st_size )) {
		t_print( fs, tran, PR_DOWNLOAD );
		break;
	    }

	    if ( cksum ) {
	        switch (fs->pi_type) {
		default:
		    /* Shouldn't happen. We'll pretent it can't. */
		    break;

		case 'f':
		    if ( do_cksum( fs->pi_name, fs->pi_cksum_b64 ) < 0 ) {
		        perror( (const char *) fs->pi_name );
			exit( EX_DATAERR );
		    }
		    break;

		case 'a':
		    if ( do_acksum( fs->pi_name, fs->pi_cksum_b64,
			    &fs->pi_afinfo ) < 0 ) {
		        perror( (const char *) fs->pi_name );
			exit( EX_DATAERR );
		    }
		    break;
		} /* switch (fs->pi_type) */

		if ( strcmp( fs->pi_cksum_b64, tran->t_pinfo.pi_cksum_b64 ) != 0 ) {
		    t_print( fs, tran, PR_DOWNLOAD );
		    break;
		}
	    } else if ( _TCC_MTIME && (fs->pi_stat.st_mtime != tran->t_pinfo.pi_stat.st_mtime )) {
	        /*
		 * If we're NOT doing checksums, then a modification time change
		 * will force download.  (But mode, uid, or gid changes won't...)
		 */
	        if (warn_countdown > 0) {
		    alert_transcript ("warning: ", stderr, tran,
				      "st_mtime change without checksums forces a download of '%s'",
				      fs->pi_name);
		    
		    /* If we have verbosity turned up, don't disable the warnings. */ 
		    if (verbose == 0)
		        warn_countdown --;

		    if (warn_countdown == 0) 
		        fprintf(stderr, "... no more warnings issued for this condition.\n");
		}
		t_print( fs, tran, PR_DOWNLOAD );
		break;
	    }

	    /*
	     * Catch for if we ARE doing checksums - and checksums have
	     * succeeded and the modification change time check has passed too.
	     */
	    if ( _TCC_MTIME && (fs->pi_stat.st_mtime != tran->t_pinfo.pi_stat.st_mtime )) {
		t_print( fs, tran, PR_STATUS );
		break;
	    }
	} /* If it's not a negaitive transcript... */

        if ( ( _TCC_UID && ( fs->pi_stat.st_uid != tran->t_pinfo.pi_stat.st_uid ) ) ||
	     ( _TCC_GID && ( fs->pi_stat.st_gid != tran->t_pinfo.pi_stat.st_gid ) ) ||
	     ( _TCC_MODE && ( mode != tran_mode ) ) ) {
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
	    if ( ( _TCC_UID && ( fs->pi_stat.st_uid != tran->t_pinfo.pi_stat.st_uid ) ) ||
		 ( _TCC_GID && ( fs->pi_stat.st_gid != tran->t_pinfo.pi_stat.st_gid ) ) ||
		 ( memcmp( fs->pi_afinfo.ai.ai_data,
			   tran->t_pinfo.pi_afinfo.ai.ai_data, FINFOLEN ) != 0 ) ||
		 ( _TCC_MODE && ( mode != tran_mode ) ) ) {
	        t_print( fs, tran, PR_STATUS );
	    }
	    break;
	}
#endif /* __APPLE__ */
	if ( ( _TCC_UID && ( fs->pi_stat.st_uid != tran->t_pinfo.pi_stat.st_uid ) ) ||
	     ( _TCC_GID && ( fs->pi_stat.st_gid != tran->t_pinfo.pi_stat.st_gid ) ) ||
	     ( _TCC_MODE && ( mode != tran_mode ) ) ) {
	    t_print( fs, tran, PR_STATUS );
	}
	break;

    case 'D':
    case 'p':
    case 's':
        if ( ( _TCC_UID && ( fs->pi_stat.st_uid != tran->t_pinfo.pi_stat.st_uid ) ) ||
	     ( _TCC_GID && ( fs->pi_stat.st_gid != tran->t_pinfo.pi_stat.st_gid ) ) ||
	     ( _TCC_MODE && ( mode != tran_mode ) ) ) {
	    t_print( fs, tran, PR_STATUS );
	}
	break;

    case 'l':			    /* link */
	if ( tran->t_type != T_NEGATIVE ) {
	    if (( filepath_cmp( fs->pi_link, tran->t_pinfo.pi_link ) != 0 )
#ifdef HAVE_LCHOWN
		|| ( _TCC_UID && ( fs->pi_stat.st_uid != tran->t_pinfo.pi_stat.st_uid ) ) 
		|| ( _TCC_GID && ( fs->pi_stat.st_gid != tran->t_pinfo.pi_stat.st_gid ) )
#endif /* HAVE_LCHOWN */
#ifdef HAVE_LCHMOD
		|| ( _TCC_MODE && (mode != tran_mode ) )
#endif /* HAVE_LCHMOD */
		/* strcmp */ ) {
	        t_print( fs, tran, PR_STATUS );
	    }
	}
	break;

    case 'h':			    /* hard */
      /*XXX --- rsc@umich.edu 2010-10-16
       *XXX
       *XXX Does this catch the case where a subsequent update to the target
       *XXX of the hardlink changes?  I think not...
       *XXX*/
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
	    if ( ( _TCC_UID && ( fs->pi_stat.st_uid != tran->t_pinfo.pi_stat.st_uid ) ) ||
		 ( _TCC_GID && ( fs->pi_stat.st_gid != tran->t_pinfo.pi_stat.st_gid ) ) || 
		 ( dev != tran->t_pinfo.pi_stat.st_rdev ) ||
		 ( _TCC_MODE && ( mode != tran_mode ) ) ) {
		t_print( fs, tran, PR_STATUS );
	    }
	} else if ( dev != tran->t_pinfo.pi_stat.st_rdev ) {
	    t_print( fs, tran, PR_STATUS );
	}	
	break;

    case 'b':
	dev = fs->pi_stat.st_rdev;
	if ( ( _TCC_UID && ( fs->pi_stat.st_uid != tran->t_pinfo.pi_stat.st_uid ) ) ||
	     ( _TCC_GID && ( fs->pi_stat.st_gid != tran->t_pinfo.pi_stat.st_gid ) ) || 
	     ( dev != tran->t_pinfo.pi_stat.st_rdev ) ||
	     ( _TCC_MODE && ( mode != tran_mode ) ) ) {
	    t_print( fs, tran, PR_STATUS );
	}	
	break;

    default:
	fprintf( stderr, "%s: Unknown type: %c\n", fs->pi_name, fs->pi_type );
	break;
    }

    return T_MOVE_BOTH;
} /* end of t_compare() */



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

	/* Count the times this transcript contributed something */
	begin_tran->active_objects ++;

	return( begin_tran );
    } /* end of for(;;) */
} /* end of transcript_select() */


/* 
 * Return values:
 * 0 --
 * 1 -- is directory
 */
    int
transcript_check( const filepath_t *path, struct stat *st, char *type,
		  struct applefileinfo *afinfo, int parent_minus )
{
    pathinfo_t		pi;
    int			enter = T_COMP_ISFILE;	/* Default transcript_check() return value */
    ssize_t 		len;  /* readlink() result */
    char		epath[ MAXPATHLEN ];
    char		*linkpath;
    transcript_t	*tran = NULL;
    transcript_t	*temp_tran;

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
		temp_tran = transcript_select();
		if  (temp_tran->active_objects > 0)
		  temp_tran->active_objects --;

		return( T_COMP_ISFILE );
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
	    enter = T_COMP_ISDIR;
	} else { 
	    enter = T_COMP_ISFILE;
	}

	/* initialize cksum field. */
	strncpy( pi.pi_cksum_b64, "-", sizeof(pi.pi_cksum_b64)-1 ); /* excessive - but correct */
    }

    for (;;) {
	tran = transcript_select();

	/* Side effrect of 't_compare()' is possible standard output */
	switch ( t_compare(( path ? &pi : NULL ), tran )) {
	case T_MOVE_FS:
	    if (debug > 0)
	        alert_transcript(NULL, stderr, tran, 
				 "%s() returns T_MOVE_FS, transcript_check() returns %d",
				 __func__, enter);
	    return( enter );

	case T_MOVE_BOTH :
	    /* But don't go into negative directories */
	    if (( tran->t_type == T_NEGATIVE ) &&
		    ( tran->t_pinfo.pi_type == 'd' )) {
		enter = T_COMP_ISNEG;
	    }
	    transcript_parse( tran );

	    if (debug > 0)
	        alert_transcript(NULL, stderr, tran,
				 "%s() returns T_MOVE_BOTH, transcript_check() returns %d",
				 __func__, enter);
	    return( enter );

	case T_MOVE_TRAN :
	    transcript_parse( tran );
	    break;

	default :
	    alert_transcript("FATAL: ", stderr, tran, 
			     "%s() returned an unexpected value for '%s'\n",
			     __func__, path);
	    exit( EX_SOFTWARE);
	} /* switch (t_compare()) ... */
    }

    fprintf(stderr, "%s() falls off the end for '%s'\n",
	    __func__, path);

    return (T_COMP_ERROR);
} /* end of transcript_check() */

    void
t_new( rad_Transcript_t type, const filepath_t *fullname, const filepath_t *shortname, const filepath_t *kfile ) 
{
    transcript_t	 *new;
    static unsigned int id=0;
    ssize_t got;   /* result of read() */

    id++;
    if (( new = (transcript_t *)calloc(1, sizeof( transcript_t )))
	    == NULL ) {
	perror( "malloc for new transcript_t" );
	exit( EX_OSERR );
    }
    if (debug > 4)
	fprintf (stderr,
		 "*debug: %s(%u, '%s', '%s', '%s'), calloc() returns %p\n",
		 __func__, type, (char *) fullname, (char *) shortname,
		 (char *) kfile, new);

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
	    exit( EX_IOERR );
	}

	if (debug > 3)
	  fprintf (stderr, "*debug: t_new (%u, ..., '%s', '%s') id=%u\n",
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
			 "ERROR: Unable to allocate transcript buffer size %zu for '%s', error %d: %s\n",
			 
			 buflen, (char *) fullname,
			 save_errno, strerror (save_errno));
		fprintf (stderr, "ERROR: Buffering turned off\n");
		transcript_buffer_size = 0;
	      }
	      else {
		if (debug > 4)
			fprintf (stderr,
				 "*debug: %s() - calloc(1, %zu) returns 0x%p\n",
				 __func__, buflen, new->buffered);

		got = read (fileno(new->t_in), new->buffered, buflen);

		if (got != (buflen-1)) {
		    fprintf (stderr,
			     "FATAL ERROR: Didn't read entire transcript ('%s') at once, %zd of %zu\n",
			     fullname, got, buflen);
		    exit (EX_IOERR);
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
	   fprintf (stderr, "*debug: t_new (%u, ..., '%s', '%s') id=%u, type error?\n", 
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
t_remove( rad_Transcript_t type, const filepath_t *shortname )
{
    transcript_t
          **p_next = &tran_head,
  	  *cur;
    unsigned int last_id = 0;
    unsigned int count = 0;

    if (debug > 2)
        fprintf (stderr, "*debug: %s(%u, '%s')\n", 
		 __func__, type, shortname);

    while (*p_next != (transcript_t *) NULL)
      {
	cur = *p_next;

	if (debug > 3)
	    alert_transcript (NULL, stderr, cur,
			      "%s() - check type=%u", __func__, cur->t_type); 

	if (debug > 4)
	    fprintf (stderr, "*debug: at %p\n", cur);

	if ((cur->t_type == type)  &&
	    (filepath_cmp (cur->t_shortname, shortname) == 0)) {

	   if (debug > 2)
	   	fprintf (stderr,
			 "*debug: %s() - found ID=%u after %u\n",
			 __func__, cur->id, last_id);

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
		 "*debug: t_remove (%u, '%s') found %u instances\n",
		 type, shortname, count);

    return;
}

    static void
t_display( void )
{
    transcript_t		*cur = NULL;

    for ( cur = tran_head; cur != NULL; cur = cur->t_next ) {
	printf( "%u: ", cur->t_num );
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
        perror( "filepath_dup from kfile to kdir" );
        exit( EX_OSERR );
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
	perror( "list_new for kfile_list" );
	exit( EX_OSERR );
    }
    if ( list_insert( kfile_list, kfile ) != 0 ) {
	perror( "list_insert for kfile_list" );
	exit( EX_SOFTWARE );
    }
    if (( special_list = list_new( )) == NULL ) {
	perror( "list_new for special_list" );
	exit( EX_OSERR );
    }
    if (( exclude_list = list_new()) == NULL ) {
	perror( "list_new for exclude_list" );
	exit( EX_OSERR );
    }
    if ( transcript_kfile( kfile, location ) != 0 ) {
	exit( EX_SOFTWARE );
    }

    if (( list_size( special_list ) > 0 ) && ( location == K_CLIENT )) {
	/* open the special transcript if there were any special files */
      if ( (filepath_len( kdir ) + filepath_len( special ) +2)
	   		 > MAXPATHLEN ) {
	    fprintf( stderr, 
		    "special path too long: %s%s\n", kdir, special );
	    exit( EX_DATAERR );
	}
	sprintf( (char *) fullpath, "%s%s", (const char *) kdir,
		 ( const char *) special );
	t_new( T_SPECIAL, fullpath, special, (filepath_t *) "special" );
    }

    if ( tran_head->t_type == T_NULL  && edit_path == APPLICABLE ) {
	fprintf( stderr, "-A option requires a non-NULL transcript\n" );
	exit( EX_USAGE );
    }

    return;
}

/*
 * Process command ('k') files 
 *
 * Returns:
 * -1 on error (no command file, memory exhaustion, data error, etc. )
 */
static    int
transcript_kfile( const filepath_t *kfile, int location )
{
    int		        length,
      			ac;
    unsigned char       minus = 0; /* Flag - 0 or 1 */
    unsigned int    	linenum = 0;
    unsigned int        objects = 0;  /* Count of real objects in command file */
    char 	     	line[ MAXPATHLEN ];
    filepath_t        	fullpath[ MAXPATHLEN ];
    filepath_t         *subpath;
    const filepath_t   *d_pattern,
      		       *path;
    char	      **av = (char **) NULL;
    FILE	       *fp;
    static int          depth = 0;

    if (( fp = fopen( (char *) kfile, "r" )) == NULL ) {
        perror( (const char *) kfile );
	return( -1 );
    }

    depth++;
    if (debug > 2)
    	fprintf (stderr,
		 "*debug: %s('%s', %d) fd=%d, depth=%d\n", 
		 __func__, (const char *) kfile, location, fileno(fp),
		 depth);

    while ( fgets( line, sizeof( line ), fp ) != NULL ) {
	linenum++;
	length = strlen( line );
	if ( line[ length - 1 ] != '\n' ) {
	    fprintf( stderr, "command file '%s' line %u: line too long\n",
		     (const char *) kfile, linenum );
	    depth--;
	    fclose( fp );
	    return( -1 );
	}

	av = (char **) NULL; /* Safety */

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
		"command file '%s' line %u: expected 2 arguments, got %d\n",
		     (const char *) kfile, linenum, ac );
	    depth--;
	    fclose( fp );
	    return( -1 );
	} 

	switch( location ) {
	case K_CLIENT:
	  if ( snprintf( (char *) fullpath, MAXPATHLEN, "%s%s", (char *) kdir,
		    av[ 1 ] ) >= MAXPATHLEN ) {
		fprintf( stderr, "command file '%s' line %u: path too long\n",
			kfile, linenum );
		fprintf( stderr, "command file '%s' line %u: %s%s\n",
			kfile, linenum, kdir, av[ 1 ] );
	        depth--;
		fclose( fp );
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
		fprintf( stderr, "command file '%s' line %u: path too long\n",
			kfile, linenum );
		fprintf( stderr, "command file '%s' line %u: %s%s\n",
			kfile, linenum, kdir, av[ 1 ] );
		depth--;
		return( -1 );
	    }
	    break;

	default:
	    fprintf( stderr, "unknown location (%u)\n", location );
	    depth--;
	    return( -1 );
	} /* switch(location) */

	objects ++;  				/* if we error-return, no warning generated */ 
	switch( *av[ 0 ] ) {
	case 'k':				/* command file */
	    if ( minus ) {
		/* Error on minus command files for now */
		fprintf( stderr, "command file '%s' line %u: "
			 "minus 'k' not supported\n", kfile, linenum );
		depth--;
		return( -1 );
	    }
	    
	    if ( list_check( kfile_list, fullpath )) {
	        fprintf( stderr,
			 "command file '%s' line %u: command file loop: '%s' already included\n",
			 kfile, linenum, av[ 1 ] );
		depth--;
		return( -1 );
	    }
	

	    if ( list_insert( kfile_list, fullpath ) != 0 ) {
	        perror( "list_insert into kfile_list from fullpath" );
		depth --;
		fclose( fp );
		return( -1 );
	    }

	    if ( transcript_kfile( fullpath, location ) != 0 ) {
	        if(debug) 
		    fprintf (stderr,
			     "*debug: %s() - transcript_kfile ('%s', ...) failed\n",
			     __func__, (char *) fullpath);
		depth--;
		fclose( fp );
		return( -1 );
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
		fprintf( stderr, "'%s' line %u: decode buffer too small\n",
			 (const char *) kfile, linenum );
	    }

	    /* Convert path to match transcript type */
	    if (( d_pattern = convert_path_type( d_pattern )) == NULL ) {
		fprintf( stderr, "'%s' line %u: path too long\n",
			 (const char *) kfile, linenum );
		depth--;
		fclose( fp );
		exit( EX_DATAERR );
	    }

	    if ( minus ) {
		list_remove( exclude_list, d_pattern );
	    } else {
		if ( !list_check( exclude_list, d_pattern )) {
		    if ( list_insert( exclude_list, d_pattern ) != 0 ) {
			perror( "list_insert into exclode_list from d_pattern" );
			depth--;
			fclose( fp );
			return( -1 );
		    }
		}
	    }
	    break;

	case 's':				/* special */
	    path = (filepath_t *) av[ 1 ];

	    /* Convert path to match transcript type */
	    if (( path = convert_path_type( path )) == NULL ) {
		fprintf( stderr, "'%s' line %u: path too long\n",
			 (const char *) kfile, linenum );
		depth--; 
		fclose( fp );
		exit( EX_DATAERR );
	    }

	    if ( minus ) {
		if ( list_check( special_list, path )) {
		    list_remove( special_list, path );
		}
	    } else {
		if ( !list_check( special_list, path )) {
		    if ( list_insert( special_list, path ) != 0 ) {
			perror( "list_insert into special_list from path" );
			depth--;
			fclose( fp );
			return( -1 );
		    }
		}

	    }
	    break;

	default:
	    fprintf( stderr, "command file '%s' line %u: '%s' invalid\n",
		     (const char *) kfile, linenum, av[ 0 ] );
	    depth--;
	    fclose( fp );
	    return( -1 );
	}
    }

    if (debug > 2)
    	fprintf (stderr, "*debug: %s() end .. fd=%d, depth=%d\n", 
		 __func__, fileno (fp), depth);

    depth--;

    if ((objects == 0)  && (verbose > 0)) {
        fprintf (stderr, "Warning: %2u objects in %2u lines of command file '%s'\n",
		 objects, linenum, (const char *) kfile);
    }

    if ( fclose( fp ) != 0 ) {
        perror( (const char *) kfile );
	return( -1 );
    }

    return( 0 );
} /* end of transcript_kfile() */


    void
transcript_free( )
{
    transcript_t	 *next;

    /*
     * Call transcript_check() with NULL to indicate that we've run out of
     * filesystem to compare against.
     */
    (void) transcript_check( NULL, NULL, NULL, NULL, 0 );

    while ( tran_head != NULL ) {
	next = tran_head->t_next;

	/* Generate warning messages if asked
	 * and the transcript isn't the dummy transcript */
	if ( (tran_head->t_shortname[0] != '\0') &&
	     ((debug > 0) || (verbose > 0))) {

	    /* Use verbose (or debug) to complain about counts */
	    unsigned int limit = (verbose>debug ? verbose : debug) - 1;

	    if (tran_head->total_objects == 0) {
	        fprintf (stderr, "Warning: No objects in ");
		fprintf_transcript_id (stderr, tran_head);
		fprintf (stderr, "\n");
	    }
	    else if ((tran_head->active_objects <= limit) &&
		     (tran_head->active_objects < tran_head->total_objects)) {
	        fprintf (stderr,
			 "Warning: %2u active objects of %3u objects in ",
			 tran_head->active_objects, 
			 tran_head->total_objects);
		fprintf_transcript_id (stderr, tran_head);
		fprintf (stderr, "\n");
	    }
	}

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
} /* end of transcript_free( (void) ) */


   int
snprintf_transcript_id (char *buff, size_t bufflen, const transcript_t *tran)
{
    if ((buff == (char *) NULL) || (bufflen < 10) || (tran == (transcript_t *) NULL)) {
        errno = EINVAL;
	return (-1);
    }

    return snprintf (buff, bufflen, 
		     "t:['%s'] k:['%s'] line %u, ID=%u",
		     tran->t_shortname, tran->t_kfile,
		     tran->t_linenum, tran->id);
    
} /* end of snprintf_transcript_id() */


    int
fprintf_transcript_id (FILE *out, const transcript_t *tran)
{
    if ((out == (FILE *) NULL) || (tran == (transcript_t *) NULL)) {
        errno = EINVAL;
	return (-1);
    }

    return fprintf (out,
		    "t:['%s'] k:['%s'] line %u, ID=%u",
		    tran->t_shortname, tran->t_kfile,
		    tran->t_linenum, tran->id);
    
} /* end of fprintf_transcript_id() */



    void
fprintf_transcript_header (const char *pfx, const char *sfx, 
			   FILE *out, const unsigned char *file,
			   const transcript_t *tran, int *p_msg)
{
    int dummy;
    
    if (pfx == (char *) NULL)
        pfx = "";

    if (sfx == (char *) NULL)
        sfx = "\t";

    if (p_msg == (int *) NULL) {
        p_msg = &dummy;
	dummy = 0;  /* Delay stack initialization to here. */
    }

    if (!*p_msg) {
        fprintf (out, "%s", pfx);
        fprintf_transcript_id (out, tran);
        fprintf (out, "\n%s", sfx);
    }
    else
      fprintf (out, ", ");

    (*p_msg) ++;

    return;

}  /* end of fprintf_transcript_header() */

   void
vfprintf_transcript (const char *pfx, const char *sfx, FILE *out,
		     const unsigned char *file, const transcript_t *tran,
		     int *p_msg,
		     const char *fmt, va_list ap)
{
    fprintf_transcript_header (pfx, sfx, out, file, tran, p_msg);

    if ((fmt != (char *) NULL) && (*fmt != '\0'))
        vfprintf (out, fmt, ap);
    
    return;

} /* end of vfprintf_transcript() */

    void
fprintf_transcript (const char *pfx, const char *sfx, FILE *out,
		    const unsigned char *file, const transcript_t *tran,
		    int *p_msg, 
		    const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    
    vfprintf_transcript (pfx, sfx, out, file, tran, p_msg, fmt, ap);
    
    va_end(ap);
    
    return;

} /* end of fprintf_transcript() */
		    
static const char verbose_pfx[] = "#  ";
static const char verbose_sfx[] = "#\t";
static const char debug_pfx[] = "*debug: ";
#define debug_sfx debug_pfx	/* Cheat */


  void
valert_transcript (const char *pfx, FILE *out,
		   const transcript_t *tran,
		   const char *fmt, va_list ap)
{
    if ((out == (FILE *) NULL) || (tran == (transcript_t *) NULL))
        return;

    if (pfx == (char *) NULL)
        pfx = debug_pfx;

    if (*pfx)
        fprintf (out, "%s", pfx);

  /* Put whitespace around message (as needed) */
    if ((fmt != (char *) NULL) && *fmt ) {
        if (*pfx)
	    fprintf(out, " "); /* as needed */

	vfprintf (out, fmt, ap);
	fprintf (out, " ");
    }

    fprintf_transcript_id (out, tran);
    
    fprintf(out, "\n");
    
    return;
} /* end of valert_transcript() */


    void
alert_transcript (const char *pfx, FILE *out, const transcript_t *tran,
		      const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);

    valert_transcript (pfx, out, tran, fmt, ap);
 
    va_end(ap);

    return;
} /* end of alert_transcript() */


 
   void
verbose_transcript_header  (const unsigned char *file, const transcript_t *tran,
			    int *p_msg)
{
    if (p_msg == (int *) NULL)
        return;
    
    fprintf_transcript_header (verbose_pfx, verbose_sfx, stdout, file, tran, p_msg);

    return;

} /* end of verbose_transcript_header() */


   void
verbose_transcript  (const unsigned char *file, const transcript_t *tran,
		     int *p_msg, const char *fmt, ...)
{
    va_list ap;

    va_start (ap, fmt);

    if (p_msg != (int *) NULL) {
        fprintf_transcript_header (verbose_pfx, verbose_sfx, stdout, file, tran, p_msg);

	if ((fmt != (char *) NULL) && (*fmt != '\0')) 
	    vfprintf (stdout, fmt, ap);
    }

    va_end (ap);
  return;

} /* end of verbose_transcript() */


   void
debug_transcript_header  (FILE *out,
			  const unsigned char *file, const transcript_t *tran,
			  int *p_msg)
{
    if (p_msg == (int *) NULL)
        return;

    fprintf_transcript_header (debug_pfx, debug_sfx, stderr, file, tran, p_msg);

    return;
} /* end of debug_transcript_header() */



   void
debug_transcript  (FILE *out,
		   const unsigned char *file, const transcript_t *tran,
		   int *p_msg,
		   const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);

    if (p_msg != (int *) NULL) {
        fprintf_transcript_header (debug_pfx, debug_sfx, stderr, file, tran, p_msg);

	if ((fmt != (char *) NULL) && (*fmt != '\0')) 
	  vfprintf (stderr, fmt, ap);
    }

    va_end(ap);
    return;
} /* end of debug_transcript_header() */
