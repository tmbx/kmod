/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

#ifndef _KMO_SOCK_H
#define _KMO_SOCK_H

#include "kmo_base.h"

int kmo_sock_create(int *fd);
void kmo_sock_close(int *fd);
int kmo_sock_set_unblocking(int fd);
int kmo_sock_bind(int fd, int port);
int kmo_sock_listen(int fd);
int kmo_sock_accept(int accept_fd, int *conn_fd);
int kmo_sock_connect(int fd, char *host, int port);
int kmo_sock_connect_check(int fd, char *host);
int kmo_sock_read(int fd, char *buf, uint32_t *len);
int kmo_sock_write(int fd, char *buf, uint32_t *len);

#endif
