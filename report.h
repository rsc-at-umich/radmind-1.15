/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined(_RADMIND_REPORT_H)
#  define _RADMIND_REPORT_H "$Id$"

#  include "filepath.h"

extern int report_event( SNET *sn, const char *event, const char *repodata );
extern void report_error_and_exit( SNET *sn, const char *event,
				   const char *repodata, int rc );

#endif /* defined(_RADMIND_REPORT_H) */
