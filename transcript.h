/*
 * Copyright (c) 2003, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined(_RADMIND_TRANSCRIPT_H)
#  define _RADMIND_TRANSCRIPT_H "$Id$"

#  include "filepath.h"
#  include "applefile.h"

#  include <sys/stat.h>

#define T_NULL		0
#define T_POSITIVE	1
#define T_NEGATIVE	2 
#define T_SPECIAL	3

#define T_RELATIVE	0
#define T_ABSOLUTE	1

#define T_MOVE_TRAN	1
#define T_MOVE_FS	2
#define T_MOVE_BOTH	3 

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
extern size_t       transcript_buffer_size;
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

extern int	     transcript_check( const filepath_t *path, 
				       struct stat *st, char *type,
				       struct applefileinfo *afinfo,
				       int parent_minus);
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

#endif /* defined (_RADMIND_TRANSCRIPT_H) */
