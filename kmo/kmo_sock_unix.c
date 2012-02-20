/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

/* This file is meant to be included by kmo_sock.c. */


/* This function returns an error string describing the last socket error that
 * occurred.
 */
static char * kmo_sock_err() {
    return kmo_syserror();
}

/* This function creates a socket and sets it in 'fd' (which must be initialized
 * to -1).
 * This function sets the KMO error string. It returns -1 on failure.
 */
int kmo_sock_create(int *fd) {
    assert(*fd == -1);
    int error = socket(AF_INET, SOCK_STREAM, 0);
    
    if (error < 0) {
    	kmo_seterror("cannot create socket: %s", kmo_sock_err());
	return -1;
    }
    
    *fd = error;
    return 0;
}

/* This function closes a socket, if required. The descriptor closed is set to
 * -1.
 */
void kmo_sock_close(int *fd) {
    if (*fd == -1) return;
    close(*fd);
    *fd = -1;
}

/* This function sets the socket unblocking.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int kmo_sock_set_unblocking(int fd) {
    int flag;
    
    if ((flag = fcntl(fd, F_GETFL)) == -1 || fcntl(fd, F_SETFL, flag | O_NONBLOCK) == -1) {
        kmo_seterror("cannot set socket unblocking: %s", kmo_sock_err());
	return -1;
    }
    
    return 0;
}

/* This function binds the socket to the port specified.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int kmo_sock_bind(int fd, int port) {
    struct sockaddr_in addr;
    int reuse_flag = 1;
    
    /* Allow us to reuse the port. */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &reuse_flag, sizeof(reuse_flag)) != 0) {
        kmo_seterror("cannot set socket reuse-port flag: %s", kmo_sock_err());
	return -1;
    }
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        kmo_seterror("cannot bind socket to port %d: %s", port, kmo_sock_err());
        return -1;
    }
    
    return 0;
}

/* This function makes the socket listen for connections on the port it is bound
 * to.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int kmo_sock_listen(int fd) {
    if (listen(fd, 1) != 0) {
    	kmo_seterror("cannot listen on socket: %s", kmo_sock_err());
	return -1;
    }
    
    return 0;
}

/* This function accepts a connection on the socket specified. On success,
 * 'conn_fd' is set to the newly created socket and this function returns 0. The
 * new socket is set unblocking. If 'accept()' failed because there is no
 * established connection at this time, this function returns -2. Otherwise,
 * this function sets the KMO error string and returns -1.
 *
 * Note: this function should never block if 'accept_fd' is set non-blocking.
 * To wait for connections, use the read set of select(). Note that it is
 * possible that no connection is available even if select() says that there is
 * one. 
 */
int kmo_sock_accept(int accept_fd, int *conn_fd) {
    assert(*conn_fd == -1);
    int error = accept(accept_fd, NULL, NULL);
    
    if (error < 0) {
    	if (errno == EWOULDBLOCK) {
    	    return -2;
	}
	
	kmo_seterror("cannot accept connection: %s", kmo_sock_err());
	return -1;
    }
    
    if (kmo_sock_set_unblocking(error)) {
    	kmo_sock_close(&error);
	return -1;
    }
    
    *conn_fd = error;
    return 0;
}

/* This function sends a connection request to the host and port specified.
 * This function sets the KMO error string. It returns -1 on failure.
 *
 * Note: this function should never block if 'fd' is set non-blocking. Thus, the
 * connection may or may not be established during the connect() call. To wait
 * for the connection to go through, use the write set of select(). When
 * select() says that the socket is ready, call kmo_sock_connect_check() to make
 * sure the connection has been established successfully.
 */
int kmo_sock_connect(int fd, char *host, int port) {
    struct sockaddr_in server_addr;
    struct hostent *he;
    
    /* Resolve the server address. */
    he = gethostbyname(host);   
    
    if (he == NULL) {
    	kmo_seterror("cannot resolve %s", host);
	return -1;
    }
    
    /* Setup the server address. */
    server_addr.sin_addr.s_addr = ((struct in_addr *) (he->h_addr_list[0]))->s_addr;
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;
    
    /* Try to connect. */
    if (connect(fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
    	
	/* Connection in progress. */
	if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
	    return 0;
	}
	
	kmo_seterror("cannot connect to %s: %s", host, kmo_sock_err());
    	return -1;
    }
    
    /* We succeeded faster than we expected. Wonderful! */
    return 0;
}

/* This function checks if the connection request initiated with
 * kmo_sock_connect() has been completed.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int kmo_sock_connect_check(int fd, char *host) {
    int error;
    int len = sizeof(error);

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *) &error, &len)) {
        kmo_seterror("cannot get socket option: %s", kmo_sock_err());
	return -1;
    }

    if (error != 0) {
        errno = error;
        kmo_seterror("cannot connect to %s: %s", host, kmo_sock_err());
	return -1;
    }

    return 0;
}

/* This function reads data from the remote side. It takes as argument a
 * file descriptor, a buffer where the data is read and an integer which
 * specify the requested number of bytes to transfer on input and the actual
 * number of bytes transferred on output. This function returns 0 on
 * success. If no data is available for reading, this function returns -2.
 * On failure, this function sets the KMO error string and returns -1.
 */
int kmo_sock_read(int fd, char *buf, uint32_t *len) {
    assert(*len > 0);
    int nb = read(fd, buf, *len);
    
    if (nb == 0) {
    	kmo_seterror("cannot read data: remote side closed connection");
	return -1;
    }
    
    else if (nb < 0) {
    	if (errno == EAGAIN) {
	    return -2;
	}
	
    	kmo_seterror("cannot read data: %s", kmo_sock_err());
	return -1;
    }
    
    *len = nb;
    return 0;
}

/* Same as above. */
int kmo_sock_write(int fd, char *buf, uint32_t *len) {
    assert(*len > 0);
    int nb = write(fd, buf, *len);
    
    if (nb == 0) {
    	kmo_seterror("cannot send data: remote side closed connection");
	return -1;
    }
    
    else if (nb < 0) {
    	if (errno == EAGAIN) {
	    return -2;
	}
	
    	kmo_seterror("cannot send data: %s", kmo_sock_err());
	return -1;
    }
    
    *len = nb;
    return 0;
}

