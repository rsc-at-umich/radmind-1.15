/*
 * Copyright (c) 2003, 2015 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined(_LOGNAME_H)
#  define _LOGNAME_H "$Id$"

/*
 * Return SYSLOG facility or level - or -1 on error. 
 */
extern int syslogfacility (const char *logname);
extern int sysloglevel (const char *loglevel);

#endif /* _LOGNAME_H */
