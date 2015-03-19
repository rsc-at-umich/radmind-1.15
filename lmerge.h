/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*
 * THIS FILE IS OBSOLETE AND UNUSED -- 2015-02-21 rsc@umich.edu 
*/
#if 0
struct tran 
{
    int			num;
    int			eof;
    int			tac;
    int			remove;
    int			linenum;
    char		*path;
    char		*name;
    char		*line;
    char		tline[ 2 * MAXPATHLEN ];
    char            	prepath[ MAXPATHLEN ];
    char		filepath[ MAXPATHLEN ];
    char		**targv;
    FILE		*fs;
    ACAV		*acav;
    struct node 	*next;
};
int getnextline( struct tran *tran ); 
#endif /* 0 */
