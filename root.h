/*
 * Copyright (c) 2003, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined (_RADMIND_ROOT_H)
#  define _RADMIND_ROOT_H "$Id$"

#  include "filepath.h"


extern int get_root( const filepath_t *radmind_path, const filepath_t *path,
		     filepath_t *file_root, filepath_t *tran_root, 
		     filepath_t *tran_name );

#endif /* defined(_RADMIND_ROOT_H) */
