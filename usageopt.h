/*
 *  usageopt
 *
 * A library to improve getopt_long() by making a usage function easier
 * to write.
 * 
 * Copyright (c) 2013, 2014 by the Regents of the University of Michigan 
 * All Rights reservered. 
 *
 * Original Author:  Richard S. Conto <rsc@umich.edu> 
 * 
 * CVS Revision: $Id: ipaddr.h,v 1.1 2013/03/11 20:08:04 rsc Exp $
 */


#if !defined(_USAGEOPT_H)
#  define _USAGEOPT_H "$Id: ipaddr.h,v 1.1 2013/03/11 20:08:04 rsc Exp $"

#  include <unistd.h>
#  include <getopt.h>

#  define STRINGIFY(s) _X_STRINGIFY(s)
#  define _X_STRINGIFY(s) #s

/* 
 * Local types
 */

typedef struct
{
    struct option  longopt;
    const char    *descr;
    const char    *argtype;
}  usageopt_t;


/*
 * Prototypes
 */

extern int            usageopt_is_last_option (const usageopt_t *usageopts);
extern struct option *usageopt_option_new ( const usageopt_t *usageopts, char **p_optstr);
extern void           usageopt_usage (FILE *out, unsigned int verbose, const char *progname, const usageopt_t *usageopts, const char *extra, unsigned int termwidth);


/* Odd little utility routine. */

/* strscaledtoll() - allows suffices like 'M', 'G', 'K' to strings as follows:
 * 'T' - 1024**4 
 * 't' - 1000**4
 * 'G' - 1024**3
 * 'g' - 1000**3
 * 'M' - 1024**2
 * 'm' - 1000**2
 * 'K' - 1024
 * 'k' - 1000
 */

extern long long strscaledtoll (const char *src, char **p_endstr, int base);
extern long strscaledtol (const char *src, char **p_endstr, int base);

#endif /* _USAGEOPT_H */
