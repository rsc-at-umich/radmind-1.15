/*
 *  usageopt
 *
 * A library to improve getopt_long() by making a usage function easier
 * to write.
 * 
 * Copyright (c) 2013 by the Regents of the University of Michigan 
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

#include <getopt.h>


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
     int             size_list;
     int	     size_optstr = 0;
     int	     optndx;	
     char           *optstr = (char *) NULL;
     char           *optput = "";
     const usageopt_t  *each;
     struct option  *new;
     struct option  *put;
     struct option  *check;
     
     /* Determine the size of the options. */
     for (size_list = 0, each = list; ! usageopt_is_last_option(each); each++)
       {
	 size_list ++;
	 if (each->longopt.val != '\0')
	   {
	     size_optstr ++;
	     switch (each->longopt.has_arg)
	       {
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

     new = calloc (size_list + 1, sizeof (*new));

     if ((p_optstr != (char **) NULL) && (size_optstr > 0))
       {
	 optstr = malloc (size_optstr + 1);
	 optput = optstr;

	 if (optput)
	   *optput = '\0';
       }

     if (! new)
       {
#if defined(_LOGERROR_H)
	 error (0, _func, __FILE__, __LINE__, "calloc (%u, %u) FAILED", size_list + 1, sizeof(*new));
#endif /* _LOGERROR_H */
	 return ((struct option *) NULL);
       }

     for (optndx = 0, put = new, each = list; ! usageopt_is_last_option(each); each++, put++, optndx++)
       {
	 memcpy ((void *) put, (void *) &(each->longopt), sizeof (*put));

#if defined(_LOGERROR_H)
	 debug (2, _func, __FILE__, __LINE__, "Option #%d: -%c, --%s",
		optndx, each->longopt.val, each->longopt.name);
#endif /* _LOGERROR_H */

	 if (each->longopt.val != '\0')
	   {
	     for (check = new; check != put; check++)
	       {
		 if (check->val == each->longopt.val)
		   {
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

	     switch (each->longopt.has_arg)
	       {
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
       }

     memset ((void *) put, 0, sizeof (*put));

     if (p_optstr != (char **) NULL)
       {
	 *p_optstr = optstr;
#if defined(_LOGERROR_H) 
	 if (optstr)
	   {
	     debug (2, _func, __FILE__, __LINE__,
		    "Options string created is \"%s\"", optstr);
	   }
#endif /* _LOGERROR_H */

	 optstr = (char *) NULL;
       }
     else if (optstr != (char *) NULL)
       {
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
    const char      *str = "";
    size_t	    width = 0;
    size_t          nextwidth;
    const usageopt_t *each;
    int             found = 0;  /* Haven't found a single character switch yet. */

    if (termwidth == 0)
      termwidth = 80;

    if (progname != (char *) NULL)
      {
	fprintf (out, "%s: usage -\n", progname);
	fprintf (out, "%s", progname);

	width = strlen (progname);
      }

    /* First, gather together the no-argument single-character options. */
    for(each = usageopts; ! usageopt_is_last_option(each); each++)
      {
	  if (each->longopt.val == 0)
	    {
	      	continue;	/* Skip ones that don't have a single-char option */
	    }

	  if (each->longopt.has_arg != no_argument) 
	    {
	        continue;	/* Skip ones that require something. */
	    }

	  if (! found)
	    {
	        fprintf (out, " [-");
		width += 3;
		found = 1;
	    }

	  fprintf (out, "%c", each->longopt.val);
	  width++;
      } /* end of for(each ... over command line arguments.) */

    if (found)
      {
	fprintf (out, "]");
	width += 1;
      }

    /* Now, gather together the ones that require an argument. */
    for(each = usageopts; ! usageopt_is_last_option(each); each++)
      {
	  if (each->longopt.val == 0)
	    {
	      	continue;	/* Skip ones that don't have a single-char option */
	    }

	  if ((each->longopt.has_arg != optional_argument)  &&
	      (each->longopt.has_arg != required_argument))
	    {
	        continue;	/* Skip ones that don't take an argument. */
	    }

	  nextwidth = 3;
	  if (each->longopt.has_arg == optional_argument)
	    {
	      nextwidth += 4;
	    }
	  if (each->argtype)
	    {
	      str = each->argtype;
	    }
	  else
	    {
	      str = "something";

	    }
	  nextwidth += 6 + strlen (str);
	      
	  if ((width + nextwidth) > termwidth)
	    {
	      fprintf (out, "\n        ");
	      width = 8;
	    }
	  else
	    {
	      fprintf (out, " ");
	      width ++;
	    }

	  width += nextwidth;
	  fprintf (out, " [-%c", each->longopt.val);
	  if (each->longopt.has_arg == optional_argument)
	    {
	      fprintf (out, " [");
	    }

	  fprintf (out, " <%s> ", str);

	  if (each->longopt.has_arg == optional_argument)
	    {
	      fprintf (out, " ]");
	    }
	  fprintf (out, "]");

	  found = 1;
      } /* end of for(each ... over command line arguments.) */

    /* Now, again for the long-options. */
    for(each = usageopts; ! usageopt_is_last_option(each); each++)
      {
	if (each->longopt.name == NULL)
	  {
	    continue;	/* Skip ones that don't have a single-char option */
	  }
	
	nextwidth = 3 + strlen (each->longopt.name);
	
	if (each->longopt.has_arg != no_argument)
	  {
	    if (each->longopt.has_arg == optional_argument)
	      {
		nextwidth += 4;
	      }
	    
	    if (each->argtype)
	      {
		str = each->argtype;
	      }
	    else
	      {
		str = "something";
	      }
	    nextwidth += 6 + strlen (str);
	  }
	
	if ((width + nextwidth) > termwidth)
	  {
	    fprintf (out, "\n        ");
	    width = 8;
	  }
	else
	  {
	    fprintf (out, " ");
	    width ++;
	  }
	
	width += nextwidth;
	fprintf (out, "[--%s", each->longopt.name);
	if (each->longopt.has_arg != no_argument)
	  {
	    if (each->longopt.has_arg == optional_argument)
	      {
		fprintf (out, " [");
	      }
	    
	    fprintf (out, " <%s> ", str);
	    
	      if (each->longopt.has_arg == optional_argument)
	      {
		fprintf (out, " ]");
	      }
	  }
	fprintf (out, "]");

	found = 1;
      } /* end of for(each ... over command line arguments.) */

    if (extra != (char *) NULL)
	fprintf (out, " %s", extra);

    if (found)
      {
	fprintf (out, "\n");
      }


    if (verbose > 0)
      {
	if (found)
	  {
	    fprintf (out, "where:\n");
	    
	    for(each = usageopts; ! usageopt_is_last_option(each); each++)
	      {
		if (each->longopt.name && each->longopt.val)
		  {
		    fprintf (out, "\t{--%s|-%c}", each->longopt.name, each->longopt.val);
		  }
		else if (each->longopt.name)
		  {
		    fprintf (out, "\t --%s", each->longopt.name);
		  }
		else
		  {
		    fprintf (out, "\t-%c", each->longopt.val);
		  }
		
		
		if (each->longopt.has_arg != no_argument)
		  {
		    if (each->argtype)
		      {
			str = each->argtype;
		      }
		    else
		      {
			str = "something";
		      }
		    
		    if (each->longopt.has_arg == optional_argument)
		      {
			fprintf (out, " [");
		      }
		    
		    fprintf (out, " <%s> ", str);
		    
		    if (each->longopt.has_arg == optional_argument)
		      {
			fprintf (out, " ]");
		      }
		  }
		
		fprintf (out, "\t:: %s\n", each->descr);
		
	      } /* end of for(each ... over command line arguments.) */
	  }
      }

    return;

} /* end of usageopt_usage () */
