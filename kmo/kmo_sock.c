/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

#include "kmo_sock.h"
#include "kmo_comm.h"

/* Include the system-dependent implementation file. */
#ifdef __UNIX__
#include "kmo_sock_unix.c"
#endif

#ifdef __WINDOWS__
#include "kmo_sock_win.c"
#endif

/* Setup the socket driver. */
struct kmo_comm_driver kmo_sock_driver = {
    kmo_sock_read,
    kmo_sock_write,
    kmo_sock_close
};
