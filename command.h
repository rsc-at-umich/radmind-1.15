/*
 * Copyright (c) 2003, 2013 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

int		cmdloop( int, struct sockaddr_in * );
int		command_k( const unsigned char *path_config, int );
char          **special_t( const unsigned char *transcript, const unsigned char *epath );
int		keyword( int, char*[] );
extern char	*path_radmind;

struct command {
    char	*c_name;
    int		(*c_func)( SNET *, int, char *[] );
};
