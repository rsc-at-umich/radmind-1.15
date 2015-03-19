/*
 *  usageopt
 *
 * A library to improve getopt_long() by making a usage function easier
 * to write.
 * 
 * Copyright (c) by the Regents of the University of Michigan 
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

extern int            usageopt_debug;
extern int            usageopt_is_last_option (const usageopt_t *usageopts);
extern struct option *usageopt_option_new ( const usageopt_t *usageopts, char **p_optstr);
extern void           usageopt_usage (FILE *out, unsigned int verbose, const char *progname, const usageopt_t *usageopts, const char *extra, unsigned int termwidth);

#endif /* _USAGEOPT_H */
