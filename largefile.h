/*
 * Copyright (c) 2003, 2014 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined(_LARGEFILE_H)
#  define _LARGEFILE_H "$Id$"

#  include <inttypes.h>

#  if !defined(SIZEOF_OFF_T)
#    error "sizeof off_t unknown."
#  endif

#  if defined(PRId64)
#    if defined(HAVE_STRTOLL)
#      define strtoofft(x,y,z)	(strtoll((x),(y),(z)))
#    else
#      define strtoofft(x,y,z)        (strtol((x),(y),(z)))
#    endif

#    define PRIofft PRId64

#  elif SIZEOF_OFF_T == 8
#    if defined(HAVE_STRTOLL)
#      define strtoofft(x,y,z)	(strtoll((x),(y),(z)))
#    else
#      define strtoofft(x,y,z)        (strtol((x),(y),(z)))
#    endif

#    define PRIofft			"lld"

#  else	/* a bit of an assumption, here */
#    define strtoofft(x,y,z)	(strtol((x),(y),(z)))
#    define PRIofft			"ld"
#  endif /* ... SIZEOF_OFF_T */
#endif /* defined(_LARGEFILE_H) */ 
