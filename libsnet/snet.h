/*
 * Copyright (c) 1995, 2001, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#if !defined(_LIBSNET_SNET_H)
#  define _LIBSNET_SNET_H "$Id$"

#  ifdef __STDC__
#  define ___P(x)		x
#  else /* __STDC__ */
#  define ___P(x)		()
#  endif /* __STDC__ */

typedef struct {
    int			sn_fd;
    char		*sn_rbuf;
    int			sn_rbuflen;
    char		*sn_rend;
    char		*sn_rcur;
    int			sn_maxlen;
    int			sn_rstate;
    char		*sn_wbuf;
    int			sn_wbuflen;
    int			sn_flag;
    struct timeval	sn_read_timeout;
    struct timeval	sn_write_timeout;

#  ifdef HAVE_ZLIB
    z_stream		sn_zistream;
    z_stream		sn_zostream;
    char		*sn_zbuf;
    int			sn_zbuflen;
#  endif /* HAVE_ZLIB */

#  ifdef HAVE_LIBSSL
    void		*sn_ssl;
#  endif /* HAVE_LIBSSL */

#  ifdef HAVE_LIBSASL
    sasl_conn_t		*sn_conn;
    int			sn_saslssf;
    unsigned int	sn_saslmaxout;
#  endif /* HAVE_LIBSASL */
} SNET;

#  define SNET_EOF		(1<<0)
#  define SNET_TLS		(1<<1)
#  ifdef HAVE_LIBSASL
#    define SNET_SASL		(1<<2)
#  endif /* HAVE_LIBSASL */
#  define SNET_WRITE_TIMEOUT	(1<<3)
#  define SNET_READ_TIMEOUT	(1<<4)

#  define SNET_ZLIB		(1<<5)

#  define snet_fd( sn )	((sn)->sn_fd)
#  define snet_saslssf( sn )	((sn)->sn_saslssf)
#  define snet_flags( sn )	((sn)->sn_flag)
#  define snet_zistream( sn )	((sn)->sn_zistream)
#  define snet_zostream( sn )	((sn)->sn_zostream)

#  define snet_writef( sn, ... ) snet_writeftv((sn),NULL, __VA_ARGS__ )

extern int	snet_eof ___P(( SNET *sn ));
extern SNET	*snet_attach ___P(( int fd, int max));
extern SNET	*snet_open ___P(( const char *path, int flags, int mode,
				  int max));
extern int	snet_close ___P(( SNET *sn ));
extern ssize_t	snet_writeftv ___P(( SNET *sn, struct timeval *tv,
				     const char *format, ... ));
extern char	*snet_getline ___P(( SNET *sn, struct timeval *tv ));
extern char	*snet_getline_multi ___P(( SNET *sn,
					   void (*logger)(const char *),
					   struct timeval *tv ));
extern void	snet_timeout ___P(( SNET *sn, int flag, struct timeval *tv ));
extern int	snet_hasdata ___P(( SNET *sn ));
extern ssize_t	snet_read ___P(( SNET *sn, char *buf, size_t len,
				 struct timeval *tv ));
extern ssize_t	snet_write ___P(( SNET *sn, const char *buf, size_t len,
				  struct timeval *tv ));
extern int	snet_setcompression( SNET *sn, int type, int level );
#  if defined(HAVE_LIBSSL)
extern int	snet_starttls ___P(( SNET *sn, SSL_CTX *sslctx, int sslaccept ));
#  endif /* defined(HAVE_LIBSSL) */
#  ifdef HAVE_LIBSASL
int	snet_setsasl  ___P(( SNET *sn, sasl_conn_t *conn ));
#  endif
#endif /* defined(_LIBSNET_SNET_H) */
