/*
 * Copyright (c) 2003, 2015 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <syslog.h>
#include <string.h>

#include "logname.h"

typedef struct {
    const char *sl_name;
    int         sl_value;
} name_to_int_t;

#if 0
extern const struct syslogname  _syslogfacility[], _sysloglevel[];
int                             syslogname( const char *restrict name, 
					    const struct syslogname *restrict sln );
#endif /* 0 */

static int name_to_int (const char *name, const name_to_int_t *table);

static const name_to_int_t _sysloglevel[] = {
    { "emerg",          LOG_EMERG },
    { "alert",          LOG_ALERT },
    { "crit",           LOG_CRIT },
    { "err",            LOG_ERR },
    { "warning",        LOG_WARNING },
    { "notice",         LOG_NOTICE },
    { "info",           LOG_INFO },
    { "debug",          LOG_DEBUG },
    /* end-of-list */
    { (char *) NULL,   0 },
};

static const name_to_int_t _syslogfacility[] = {
#ifdef LOG_KERN
    { "kern",		LOG_KERN },
#endif // LOG_KERN
    { "user",		LOG_USER },
    { "mail",		LOG_MAIL },
    { "daemon",		LOG_DAEMON },
    { "auth",		LOG_AUTH },
    { "syslog",		LOG_SYSLOG },
    { "lpr",		LOG_LPR },
    { "news",		LOG_NEWS },
    { "uucp",		LOG_UUCP },
    { "cron",		LOG_CRON },
#ifdef LOG_FTP
    { "ftp",		LOG_FTP },
#endif // LOG_FTP
#ifdef LOG_AUTHPRIV
    { "authpriv",	LOG_AUTHPRIV },
#endif // LOG_AUTHPRIV
    { "local0",		LOG_LOCAL0 },
    { "local1",		LOG_LOCAL1 },
    { "local2",		LOG_LOCAL2 },
    { "local3",		LOG_LOCAL3 },
    { "local4",		LOG_LOCAL4 },
    { "local5",		LOG_LOCAL5 },
    { "local6",		LOG_LOCAL6 },
    { "local7",		LOG_LOCAL7 },
    /* end-of-list */
    { (char *) NULL,	0 },
};

static int
name_to_int( const char *name, const name_to_int_t *table )
{
    if (name != (char *) NULL) {
      for ( ; table->sl_name != 0; table++ ) {
	if ( strcasecmp( table->sl_name, name ) == 0 ) {
	    return( table->sl_value );
	}
      }
    }
    return( -1 );
} /* end of name_to_int() */

int
syslogfacility (const char *logname)
{
    return name_to_int(logname, _syslogfacility);
}

int
sysloglevel (const char *loglevel)
{
  return name_to_int(loglevel, _sysloglevel);
} /* end of sysloglevel() */
