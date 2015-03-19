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
 * CVS Revision: $Id: ipaddr.c,v 1.29 2013/07/11 19:58:57 rsc Exp $
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <sys/types.h>
#include <errno.h>
#include <limits.h>  /* for LLONG_MAX and LLONG_MIN */
#include <getopt.h>
#include <sysexits.h>

#include "usageopt.h"


#if defined(WANT_LOGERROR)
#  include "logerror.h"
#endif

/*
 * Procedures
 */

/*
 * usageopt_is_last_option()
 *
 * Return true (1) if `help' is at the end of the list, or false (0) otherwise.
 */
int
usageopt_is_last_option (const usageopt_t *help)
{
    if (help == (usageopt_t *) NULL)
        return (1);

    if ((help->longopt.val == 0) && (help->longopt.name == (char *) NULL))
        return (1);

    if ((help->descr == (char *) NULL) && (help->argtype == (char *) NULL))
        return (1);

    return (0);

} /* end of usageopt_is_last_option() */


/*
 * usageopt_option_new()
 *
 * Return a pointer to an array of 'struct options' suitable for `getopt_long()'
 * from the 'usageopt_t *' list
 */

struct option *
usageopt_option_new (const usageopt_t *list, char **p_optstr)
{
#if defined(_LOGERROR_H)
     static char     _func[] = "usageopt_option_new";
#endif /* _LOGERROR_H */
     int             size_list;  /* Initialized in for(;;) loop */
     int	     size_optstr = 0;
     int	     optndx;	
     char           *optstr = (char *) NULL;
     char           *optput = "";
     const usageopt_t  *each;
     struct option  *new;
     struct option  *put;
     struct option  *check;
     
     /* Determine the size of the options. */
     for (size_list = 0, each = list; ! usageopt_is_last_option(each); each++) {
	 if (each->longopt.name != (char *) NULL) 
	     size_list ++;

	 if (each->longopt.val != '\0') {
	     size_optstr ++;
	     switch (each->longopt.has_arg) {
	       case optional_argument:
		   size_optstr += 2;  /* Two ':' in string */
		   break;

	       case required_argument:
		   size_optstr ++;
		   break;

	       default:
		   /* nothing */
		   break;
	     } /* switch (each->longopt.has_arg) */
	 }
     }

#if defined(_LOGERROR_H)
     debug (2, _func, __FILE__, __LINE__, "Creating %d options of size %u", size_list, sizeof(*new));
#endif /* defined(_LOGERROR_H) */

     new = calloc (size_list + 1, sizeof (*new));  /* With an extra, empty one at the end. */

     if ((p_optstr != (char **) NULL) && (size_optstr > 0)) {
         optstr = malloc (size_optstr + 1);
	 optput = optstr;

	 if (optput)
	     *optput = '\0';
     }

     if (! new) {
#if defined(_LOGERROR_H)
	 error (0, _func, __FILE__, __LINE__, "calloc (%u, %u) FAILED", size_list + 1, sizeof(*new));
#endif /* _LOGERROR_H */
	 return ((struct option *) NULL);
     }

     /*
      * Fill the calloc'd (struct options) *new list and the option string.
      */
     for (optndx = 0, put = new, each = list;
	  ! usageopt_is_last_option(each);
	  each++, optndx++)      {
         /*
	  * If (struct option).name is NULL, it confuses getopt_long() into terminating
	  * the search.
	  */
	 if (each->longopt.name != (char *) NULL) {
	     memcpy ((void *) put, (void *) &(each->longopt), sizeof (*put));
	   
#if defined(_LOGERROR_H)
	     debug (2, _func, __FILE__, __LINE__, "Option #%d: -%c, --%s",
		    optndx, each->longopt.val, each->longopt.name);
#endif /* _LOGERROR_H */
	 }
	 

	 if (each->longopt.val != '\0') {
	     for (check = new; check != put; check++) {
		 if (check->val == each->longopt.val) {
#if defined(_LOGERROR_H) 
		     error (0, _func, __FILE__, __LINE__, 
			    "Duplicate switch character '%c' between '%s' and '%s'", each->longopt.val,
			    check->name ? check->name : "?", each->longopt.name ? each->longopt.name : "?");
#endif /* _LOGERROR_H */
		     free (new);
		     return ((struct option *) NULL);
		 }
	     }

	     *optput = each->longopt.val;
	     optput++;

	     switch (each->longopt.has_arg) {
	       case optional_argument:
		   *optput = ':';
		   optput++;
		   *optput = ':';
		   optput++;
		   break;

	       case required_argument:
		   *optput = ':';
		   optput++;
		   break;

	       default:
		   /* nothing */
		   break;
	     } /* switch (each->longopt.has_arg) */
	     *optput = '\0';
	 }

	 /* Delayed conditional increment. */
	 if (each->longopt.name != (char *) NULL)
	     put++;

     } /* for (optndx = 0, put = new; ...) */
     
     /* Zap the terminal 'struct option' */
     memset ((void *) put, 0, sizeof (*put));

     if (p_optstr != (char **) NULL) {
	 *p_optstr = optstr;
#if defined(_LOGERROR_H) 
	 if (optstr) {
	     debug (2, _func, __FILE__, __LINE__,
		    "Options string created is \"%s\"", optstr);
	 }
#endif /* _LOGERROR_H */

	 optstr = (char *) NULL;
     }
     else if (optstr != (char *) NULL) {
	 /* Shouldn't happen. */
	 free (optstr);
	 optstr = (char *) NULL;
     }

     return (new);

} /* end of usageopt_option_new() */


void
usageopt_usage (FILE *out, unsigned int verbose, const char *progname,
		const usageopt_t *usageopts, const char *extra,
		unsigned int termwidth)
{

  if (extra) {
      usageopt_usagef (out, verbose, progname, usageopts, termwidth, "%s", extra);
  }
  else {
      usageopt_usagef (out, verbose, progname, usageopts, termwidth, "");
  }

  return;
    
} /* end of usageopt_usage() */



void
usageopt_usagef (FILE *out, unsigned int verbose, const char *progname,
		 const usageopt_t *usageopts, unsigned int termwidth,
		 const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);

    vusageopt_usagef(out, verbose, progname, usageopts, termwidth, fmt, ap);

    va_end(ap);

    return;
} /* end of usageopt_usagef() */


void
vusageopt_usagef (FILE *out, unsigned int verbose, const char *progname,
		 const usageopt_t *usageopts, unsigned int termwidth,
		 const char *fmt, va_list ap)
{
    const char      *str = "";
    size_t	    width = 0;
    size_t          nextwidth;
    int             printlen;  /* Length printed by varions xxprintxx() funcs */
    const usageopt_t *each;
    int             found = 0;  /* Haven't found a single character switch yet. */

    if (termwidth == 0)
        termwidth = 80;

    if ((progname != (char *) NULL) && (*progname != '\0'))  {
	fprintf (out, "%s: usage -\n", progname);
	printlen = fprintf (out, "%s", progname);
	if (printlen <= 0)
	    exit(EX_IOERR);

	width = printlen;
    }

    /* First, gather together the no-argument single-character options. */
    for(each = usageopts; ! usageopt_is_last_option(each); each++) {
        if (each->longopt.val == 0) {
	    continue;	/* Skip ones that don't have a single-char option */
	}

	if (each->longopt.has_arg != no_argument) {
	    continue;	/* Skip ones that require something. */
	}

	if (! found) {
	    printlen = fprintf (out, " [-");
	    if (printlen <= 0)
	        exit(EX_IOERR);

	    width += printlen;;
	    found = 1;
	}

	printlen = fprintf (out, "%c", each->longopt.val);
	if (printlen <= 0)
	    exit(EX_IOERR);

	width += printlen;
    } /* end of for(each ... over command line arguments.) */

    if (found) {
        printlen = fprintf (out, "]");
	if (printlen <= 0)
	    exit(EX_IOERR);

	width += printlen;
    }

    /* Now, gather together the ones that require an argument. */
    for(each = usageopts; ! usageopt_is_last_option(each); each++) {
        if (each->longopt.val == 0) {
	    continue;	/* Skip ones that don't have a single-char option */
	}

	if ((each->longopt.has_arg != optional_argument)  &&
	    (each->longopt.has_arg != required_argument)) {
	    continue;	/* Skip ones that don't take an argument. */
	}

	nextwidth = 3;
	if (each->longopt.has_arg == optional_argument) {
	    nextwidth += 4;
	}

	if (each->argtype) {
	    str = each->argtype;
	}
	else {
	    str = "something";
	}
	      
	nextwidth += 6 + strlen (str);

	if ((width + nextwidth) > termwidth)  {
	    printlen = fprintf (out, "\n        ");
	    if (printlen <= 1)	/* MUST HAVE NEWLINE */
	        exit(EX_IOERR);

	    /* Reset width. */
	    width = printlen - 1;	/* Drop newline */
	}
	else {
	    printlen = fprintf (out, " ");
	    if (printlen <= 0)
	        exit(EX_IOERR);

	    width += printlen;
	}

	
	printlen = fprintf (out, " [-%c", each->longopt.val);
	if (printlen <= 0)
	    exit(EX_IOERR);

	width += printlen;

	if (each->longopt.has_arg == optional_argument) {
	    printlen = fprintf (out, " [");
	    if (printlen <= 0)
	        exit(EX_IOERR);

	    width += printlen;
	}

	printlen = fprintf (out, " <%s> ", str);
	if (printlen <= 0)
	    exit(EX_IOERR);
	
	width += printlen;

	if (each->longopt.has_arg == optional_argument) {
	    printlen = fprintf (out, " ]");
	    if (printlen <= 0)
	        exit(EX_IOERR);

	    width += printlen;
	}
	printlen = fprintf (out, "]");
	if (printlen <= 0)
	    exit(EX_IOERR);

	width += printlen;
	found = 1;
    } /* end of for(each ... over command line arguments.) */

    /* Now, again for the long-options. */
    for(each = usageopts; ! usageopt_is_last_option(each); each++) {
        if (each->longopt.name == (char *) NULL) {
	    continue;	/* Skip ones that don't have a single-char option */
	}
	
	nextwidth = 3 + strlen (each->longopt.name);
	
	if (each->longopt.has_arg != no_argument) {
	    if (each->longopt.has_arg == optional_argument) {
	        nextwidth += 4;
	    }
	    
	    if (each->argtype) {
	        str = each->argtype;
	    }
	    else {
	        str = "something";
	    }
	    nextwidth += 6 + strlen (str);
	}
	
	if ((width + nextwidth) > termwidth) {
	    printlen = fprintf (out, "\n        ");
	    if (printlen <= 1)
	        exit(EX_IOERR);

	    width = printlen - 1;
	}
	else {
	    printlen = fprintf (out, " ");
	    if (printlen <= 0)
	        exit(EX_IOERR);

	    width += printlen;
	}
	
	width += nextwidth;
	printlen = fprintf (out, "[--%s", each->longopt.name);
	if (printlen <= 0)
	    exit(EX_IOERR);

	if (each->longopt.has_arg != no_argument) {
	    if (each->longopt.has_arg == optional_argument) {
	        printlen = fprintf (out, " [");
		if (printlen <= 0)
		  exit(EX_IOERR);

		width += printlen; 
	    }
	    
	    printlen = fprintf (out, " <%s> ", str);
	    if (printlen <= 0)
	        exit(EX_IOERR);

	    width += printlen;
	    if (each->longopt.has_arg == optional_argument) {
	        printlen = fprintf (out, " ]");
		if (printlen <= 0)
		    exit(EX_IOERR);

		width += printlen; 
	    }
	} /* if (each->longopt.has_arg != no_arguments) */
 
	printlen = fprintf (out, "]");
	if (printlen <= 0)
	    exit(EX_IOERR);

	width += printlen;
	found = 1;
    } /* end of for(each ... over command line arguments.) */

    if ((fmt != (char *) NULL) && (*fmt != '\0')) {
        printlen = vfprintf (out, fmt, ap);
	if (printlen < 0)
	    exit(EX_IOERR);
    }

    if (found) {
	printlen = fprintf (out, "\n");
	if (printlen < 0)
	    exit(EX_IOERR);

	width = 0;
    }

    if (verbose > 0) {
        if (found) {
	    printlen = fprintf (out, "where:\n");
	    if (printlen <= 0)
	        exit(EX_IOERR);
	    
	    for(each = usageopts; ! usageopt_is_last_option(each); each++) {
	        if (each->longopt.name && each->longopt.val) {
		    printlen = fprintf (out, "\t{--%s|-%c}", each->longopt.name,
			     each->longopt.val);
		}
		else if (each->longopt.name) {
		    printlen = fprintf (out, "\t --%s", each->longopt.name);
		}
		else {
		    printlen = fprintf (out, "\t-%c", each->longopt.val);
		}
		if (printlen <= 0)
		    exit(EX_IOERR);
		
		if (each->longopt.has_arg != no_argument) {
		    if (each->argtype) {
		        str = each->argtype;
		    }
		    else {
			str = "something";
		    }
		    
		    if (each->longopt.has_arg == optional_argument) {
			fprintf (out, " [");
		    }
		    
		    printlen = fprintf (out, " <%s> ", str);
		    if (printlen <= 0)
		        exit(EX_IOERR);

		    if (each->longopt.has_arg == optional_argument) {
		        printlen = fprintf (out, " ]");
			if (printlen <= 0)
			    exit(EX_IOERR);
		    }
		} /* if (each->longopt.has_arg != no_argument ) */
		
		printlen = fprintf (out, "\t:: %s\n", each->descr);
		if (printlen <= 0)
		    exit(EX_IOERR);
	    } /* end of for(each ... over command line arguments.) */
	}
    }

    return;

} /* end of vusageopt_usagef () */


/* Strange little utility routines. */

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

long long strscaledtoll (const char *src, char **p_endstr, int base)
{
    long long res;
    long long range;
    unsigned long scale = 1;
    char *tmp = (char *) NULL;

    if (src == (char *) NULL) {
        if (p_endstr)
	    *p_endstr = (char *) NULL;

	errno = EINVAL;
	return (0);
    }

    res = strtoll (src, &tmp, base);

    /* Check for failure... */
    if (src == tmp) {
        if (p_endstr)
	    *p_endstr = tmp;

	return (res);
    }
    
    /* Check for unscaled success. */
    if (*tmp == '\0') {
        if (p_endstr)
	  *p_endstr = tmp;

	return (res);
    }

    switch (*tmp) {
    default:
        break;

    case 'k': 
        scale = 1000;
	tmp++;
	break;

    case 'K': 
        scale = 1024;
	tmp++;
	break;

    case 'm': 
        scale = 1000 * 1000;
	tmp++;
	break;

    case 'M': 
        scale = 1024 * 1024;
	tmp++;
	break;

    case 'g': 
        scale = 1000 * 1000 * 1000;
	tmp++;
	break;

    case 'G': 
        scale = 1024 * 1024 * 1024;
	tmp++;
	break;

    case 't': 
        scale = 1000L * 1000L * 1000L * 1000L;
	tmp++;
	break;

    case 'T': 
        scale = 1024L * 1024L * 1024L * 1024L;
	tmp++;
	break;

    }; /* switch (*tmp) */

    if (p_endstr)
        *p_endstr = tmp;

    if ((scale != 1) && (res != 0)) {
        if (res > 0) {
	    range = LLONG_MAX / scale;
	    if (res > range) {
	        errno = ERANGE;
		return (LLONG_MAX);
	    }
	}
	else { /* res is negative. */
	    range = LLONG_MIN / scale;
	    if (res < range) {
		errno = ERANGE;
		return (LLONG_MIN);
	    }
	}
    }

    return (res * scale);

} /* end of long long strscaledtoll(src, p_endstr, base) */


/* strscaledtol() - allows suffices like 'M', 'G', 'K' to strings as follows:
 * 'T' - 1024**4 
 * 't' - 1000**4
 * 'G' - 1024**3
 * 'g' - 1000**3
 * 'M' - 1024**2
 * 'm' - 1000**2
 * 'K' - 1024
 * 'k' - 1000
 */

long strscaledtol (const char *src, char **p_endstr, int base)
{
    long long res = strscaledtoll (src, p_endstr, base);

    if (res > LONG_MAX) {
	errno = ERANGE;
	return (LONG_MAX);
    }
    else if (res < LONG_MIN) {
	errno = ERANGE;
	return  (LONG_MIN);
    }

    return (res);

} /* end of strscaledtol(src, p_endstr, base) */
