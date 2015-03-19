/*
 * Copyright (c) 2003, 2013, 2014 by the Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined(_RADMIND_TRANSCRIPT_H)
#  define _RADMIND_TRANSCRIPT_H "$Id$"

#  include "filepath.h"
#  include "applefile.h"

#  include <sys/stat.h>
#  include <stdarg.h>

#define T_NULL		0
#define T_POSITIVE	1
#define T_NEGATIVE	2 
#define T_SPECIAL	3

#define T_RELATIVE	0
#define T_ABSOLUTE	1

#define T_MOVE_TRAN	1
#define T_MOVE_FS	2
#define T_MOVE_BOTH	3 

#define T_COMP_ISFILE   0
#define T_COMP_ISDIR	1
#define T_COMP_ISNEG	2
#define T_COMP_ERROR	-1

#define T_MODE		0x0FFF

#define APPLICABLE	0
#define CREATABLE	1

#define PR_TRAN_ONLY	1  
#define PR_FS_ONLY	2
#define PR_DOWNLOAD	3 
#define PR_STATUS	4 
#define PR_STATUS_NEG	5
#define PR_STATUS_MINUS	6

#define K_CLIENT	0
#define K_SERVER	1

extern int		edit_path;
extern int		skip;
extern int		cksum;
extern int		fs_minus;
extern FILE		*outtran;
extern char		*path_prefix;
extern int		 debug;
extern int		 verbose;

struct pathinfo {
    char			pi_type;
    int				pi_minus;
    filepath_t		        pi_name[ MAXPATHLEN ];
    filepath_t 		        pi_link[ MAXPATHLEN ];
    struct stat			pi_stat;
    char			pi_cksum_b64[ MAXPATHLEN ];
    struct applefileinfo	pi_afinfo;
};

typedef struct pathinfo pathinfo_t;

/* Buffer small transcripts in memory to avoid fd exhaustion */
#  if !defined(DEFAULT_TRANSCRIPT_BUFFER_SIZE)
#    define DEFAULT_TRANSCRIPT_BUFFER_SIZE 2048
#  endif /* DEFAULT_TRANSCRIPT_BUFFER_SIZE */

extern size_t       transcript_buffer_size;  /* 0==NO BUFFERING */
extern unsigned int transcripts_buffered;  /* Count of transcripts */
extern unsigned int transcripts_unbuffered; /* Count of transcripts */

typedef struct transcript transcript_t;

struct transcript {
    transcript_t	*t_next;
    pathinfo_t		t_pinfo;
    int 		t_type;
    int			t_num;
    filepath_t		t_fullname[ MAXPATHLEN ];
    filepath_t		t_shortname[ MAXPATHLEN ];
    filepath_t		t_kfile[ MAXPATHLEN ];
    int			t_linenum;
    int			t_eof;
    FILE		*t_in;
    unsigned int	id;
    char                *buffered; /* Full transcript buffer */
    char		*buffer_position;
};

extern transcript_t *tran_head;	/* Global ordered list of transcripts. */

/*
 * return values:
 * T_COMP_ISFILE (0)
 * T_COMP_ISDIR (1)
 * T_COMP_ISNEG (2)
 * T_COMP_ERROR (-1)
 * 
 */
extern int	     transcript_check( const filepath_t *path, 
				       struct stat *st, char *type,
				       struct applefileinfo *afinfo,
				       int parent_minus);
/* switches governing the behavior of "transcript_check()" */
extern int radmind_transcript_check_switches;
#define RADTC_SWS_UID	0x0001
#define RADTC_SWS_GID	0x0002
#define RADTC_SWS_MTIME	0x0004
#define RADTC_SWS_MODE	0x0008
#define RADTC_SWS_SIZE	0x0010
#define RADTC_SWS_CKSUM	0x0020


extern void	     transcript_init( const filepath_t *kfile, int location );
extern transcript_t *transcript_select( void );
extern void	     transcript_parse( transcript_t *tran );
extern void	     transcript_free( void );
extern void	     t_new( int type, const filepath_t *fullname,
			    const filepath_t *shortname,
			    const filepath_t *kfile );
extern int	     t_exclude( const filepath_t *path );
extern void	     t_print( pathinfo_t *fs, transcript_t *tran, int flag);
extern char	    *hardlink( pathinfo_t *pinfo );
extern int	     hardlink_changed( pathinfo_t *pinfo, int set);
extern void	     hardlink_free( void );

/*
 * Standardized debugging/display routines.
 *
 * Parameters:
 *   const unsigned char *file -- Pathname of object being reported.
 *   const struct transcript *tran -- Transcript where 'file' is referenced from
 *   int   *p_msg  -- Header/line counter. If *p_msg is 0, header generated.	
 *
 *   FILE *out -- output file for printing
 */

extern int snprintf_transcript_id (char *buff, size_t bufflen,
				   const transcript_t *trans);
extern int fprintf_transcript_id  (FILE *out,
				   const transcript_t *tran);

extern void fprintf_transcript     (const char *pfx, const char *sfx, FILE *out, 
				    const unsigned char *file, 
				    const transcript_t *tran, int *p_msg,
				    const char *fmt, ...);

extern void vfprintf_transcript   (const char *pfx, const char *sfx, FILE *out,
				   const unsigned char *file,
				   const transcript_t *tran, int *p_msg,
				   const char *fmt, va_list ap);


extern void verbose_transcript_header (const unsigned char *file,
				       const transcript_t *tran, int *p_msg);

extern void debug_transcript_header   (FILE *out,
				       const unsigned char *file,
				       const transcript_t *tran, int *p_msg);

extern void fprintf_transcript_header  (const char *pfx, const char *sfx, FILE *out, 
					const unsigned char *file,
					const transcript_t *tran, int *p_msg);

extern void verbose_transcript    (const unsigned char *file, 
				   const transcript_t *tran, int *p_msg,
				   const char *fmt, ...);

extern void debug_transcript      (FILE *out, const unsigned char *file,
				   const transcript_t *tran, int *p_msg,
				   const char *fmt, ...);

extern void valert_transcript (const char *pfx, FILE *out,
			       const transcript_t *tran,
			       const char *fmt, va_list ap);

extern void alert_transcript  (const char *pfx, FILE *out, 
			       const transcript_t *tran,
			       const char *fmt, ...);

#endif /* defined (_RADMIND_TRANSCRIPT_H) */
