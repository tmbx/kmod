#include "kmod_link.h"
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#if defined(__KMOD__)

#include "kmod.h"
#include "kbuffer.h"
#include "kmo_comm.h"
#include "kmo_sock.h"

#define kmod_data_transfer kmo_data_transfer
#define kmod_transfer_hub kmo_transfer_hub
#define KMOD_DATA_TRANS_NONE KMO_COMM_TRANS_NONE
#define KMOD_DATA_TRANS_PENDING KMO_COMM_TRANS_PENDING
#define KMOD_DATA_TRANS_COMPLETED KMO_COMM_TRANS_COMPLETED
#define KMOD_DATA_TRANS_ERROR KMO_COMM_TRANS_ERROR
#define kmod_data_transfer_init kmo_data_transfer_init
#define kmod_data_transfer_clean kmo_data_transfer_free
#define kmod_transfer_hub_init kmo_transfer_hub_init
#define kmod_transfer_hub_clean kmo_transfer_hub_free
#define kmod_transfer_hub_add kmo_transfer_hub_add
#define kmod_transfer_hub_remove kmo_transfer_hub_remove
#define kmod_transfer_hub_wait kmo_transfer_hub_wait
#define kmod_data_transfer_err kmo_data_transfer_err
#define kmod_set_error kmo_seterror
#define ksock_create kmo_sock_create
#define ksock_close kmo_sock_close
#define ksock_set_unblocking kmo_sock_set_unblocking
#define ksock_connect kmo_sock_connect
#define ksock_connect_check kmo_sock_connect_check
#define kalloc kmo_malloc
#define kcalloc kmo_calloc
#define kfree free
#define kstr_clean kstr_free
#define kbuffer_init(a) kbuffer_init(a,0)
#define kbuffer_write_nbytes kbuffer_append_nbytes

#elif defined(__KAPPSD__)
#include "kappsd.h"
#include <sys/wait.h>

#else
#error "Don't know how to compile."
#endif

/* KNP object identifiers. */
#define KNP_UINT32		    1
#define KNP_UINT64		    2
#define KNP_STR			    3
#define KNP_BIN			    4

/* KNP SSL driver. */
struct knp_ssl_driver {
    SSL_CTX *ssl_ctx;
    SSL *ssl;
};

/* Kryptiva network protocol session. */
struct klink_session {

    /* This object describes the current transfer operation. */
    struct kmod_data_transfer transfer;

    /* SSL driver. */
    struct knp_ssl_driver *ssl_driver;
    
    struct kmod_transfer_hub *hub;
};

static int lbuffer_read(kbuffer *self, uint8_t *data, size_t len) {
    #ifdef __KMOD__
    return kbuffer_read(self, data, len) == (uint32_t) len ? 0 : -1;
    #else
    return kbuffer_read(self, data, len);
    #endif
}

static int lbuffer_read8(kbuffer *self, uint8_t *data) {
    #ifdef __KMOD__
    *data = kbuffer_read8(self);
    return 0;
    #else
    return kbuffer_read8(self, data);
    #endif
}

static int lbuffer_read32(kbuffer *self, uint32_t *data) {
    #ifdef __KMOD__
    *data = kbuffer_read32(self);
    return 0;
    #else
    return kbuffer_read32(self, data);
    #endif
}

static int lbuffer_read64(kbuffer *self, uint64_t *data) {
    #ifdef __KMOD__
    *data = kbuffer_read64(self);
    return 0;
    #else
    return kbuffer_read64(self, data);
    #endif
}

/* This function executes the current KNP transfer. While the KNP transfer is
 * progressing, this function monitors the K3P connection for activity. If the
 * plugin asks to abort the current K3P transaction, this function returns -2.
 * If the K3P connection is lost, this function sets the KMOD error string and
 * returns -3. Otherwise, this function returns 0 when the KNP transfer is
 * completed (successfully or not).
 */
static int klink_session_exec_transfer(struct klink_session *self) {
    int error = 0;
    
    kmod_log_msg(3, "klink_session_exec_transfer() called.\n");
    
    /* At this point the transfer hub should be empty. */
    assert(! self->hub->transfer_hash.size);
    
    /* Set the status of the KNP transfer to pending, should we return early. */
    self->transfer.status = KMOD_DATA_TRANS_PENDING;
    
    /* Add the KNP transfer in the hub. */
    kmod_transfer_hub_add(self->hub, &self->transfer);
    
    /* Loop until the KNP transfer is completed or an error occurs. */
    while (1) {
    
	/* Wait for the transfers to complete. */
	kmod_transfer_hub_wait(self->hub);
	
	/* The KNP transfer is finished. */
	if (self->transfer.status == KMOD_DATA_TRANS_COMPLETED || self->transfer.status == KMOD_DATA_TRANS_ERROR) {
	    break;
	}
	
	/* The KNP transfer is still pending. */
	else {
	    assert(self->transfer.status == KMOD_DATA_TRANS_PENDING);
	}
    }
    
    /* Remove the KNP transfer from the hub. */
    kmod_transfer_hub_remove(self->hub, &self->transfer);
    
    return error;
}

/* This function waits for the connection to become readable or writable. This
 * function chats with the plugin as required and calls
 * klink_session_network_error() if an error occurs with the connection.
 * This function sets the KMOD error string. It returns 0, -1, -2, or -3.
 */
static int klink_session_wait_for_data(struct klink_session *self, int read_flag, char *err_str) {
    int error = 0;
    struct kmod_data_transfer *transfer = &self->transfer;
    
    kmod_log_msg(3, "klink_session_wait_for_data() called.\n");
    
    transfer->read_flag = read_flag;
    transfer->buf = NULL;
    transfer->min_len = transfer->max_len = 0;
    error = klink_session_exec_transfer(self);
    if (error) return error;
    
    if (transfer->status != KMOD_DATA_TRANS_COMPLETED) {
	assert(transfer->status == KMOD_DATA_TRANS_ERROR);
	kmod_set_error("%s: %s", err_str, kmod_data_transfer_err(transfer));
	return -1;
    }
    
    return 0;
}

/* This function returns a string describing the SSL error that just occurred.
 * Since SSL has proven to be unreliable in that domain, the function does some
 * checking to ensure some string is set.
 */
static char * get_ssl_error_string(int error) {
    char *msg;
    
    kmod_log_msg(3, "get_ssl_error_string() called.\n");
    
    /* The remote side closed the connection. */
    if (error == 0) {
    	return "lost connection";
    }
    
    /* Get the error string from SSL. */
    msg = (char *) ERR_reason_error_string(ERR_get_error());

    /* Oh well. */
    if (msg == NULL) {
    	msg = "lost connection";
    }
    
    return msg;
}

/* This function performs the specified transfer over the SSL connection.
 * This function handles errors just like klink_session_wait_for_data().
 * This function sets the KMOD error string. It returns 0, -1, -2, or -3.
 */
static int klink_session_ssl_transfer(struct klink_session *session, int read_flag, char *buf, int size, char *err_str) {
    int nb_trans = 0;
    
    kmod_log_msg(3, "klink_session_ssl_transfer() called.\n");
    
    while (nb_trans != size) {
    	int error;
    	int nb_left = size - nb_trans;

	if (read_flag)
	    error = SSL_read(session->ssl_driver->ssl, buf + nb_trans, nb_left);
	else
	    error = SSL_write(session->ssl_driver->ssl, buf + nb_trans, nb_left);
	
	/* The remote side closed the connection. */
	if (error == 0) {
	    kmod_set_error("%s: remote side closed connection", err_str);
	    return -1;
	}
	
	/* An error occurred. */
	else if (error < 0) {
	    int ssl_err = SSL_get_error(session->ssl_driver->ssl, error);
	    
	    /* Wait for reading. */
	    if (ssl_err == SSL_ERROR_WANT_READ) {
	    	error = klink_session_wait_for_data(session, 1, err_str);
	    	if (error) return error;
	    }
	    
	    /* Wait for writing. */
	    else if (ssl_err == SSL_ERROR_WANT_WRITE) {
	    	error = klink_session_wait_for_data(session, 0, err_str);
	    	if (error) return error;
	    }
	    
	    /* Oops. */
	    else {
		kmod_set_error("%s: %s", err_str, get_ssl_error_string(error));
		return -1;
            }
	}
	
	/* We managed to transfer data. */
	else {
	    nb_trans += error;
	}
    }
	
    return 0;
}
/* This function sends a message to the server.
 * This function sets the KMOD error string. It returns 0, -1, -2, or -3.
 */
static int klink_session_send_msg(struct klink_session *self, uint32_t msg_type, kbuffer *payload) {
    int error = 0;
    kbuffer msg;
    kbuffer_init(&msg);
    
    kmod_log_msg(3, "klink_session_send_msg() called.\n");
    
    /* Try. */
    do {
	/* Send the message. */
	kbuffer_write32(&msg, msg_type);
	kbuffer_write32(&msg, payload->len);
	kbuffer_write(&msg, payload->data, payload->len);

	error = klink_session_ssl_transfer(self, 0, msg.data, msg.len, "cannot send KAPPS message");
	if (error) break;
	
    } while (0);
    
    kbuffer_clean(&msg);
    
    return error;
}

/* This function receives a message from the server.
 * This function sets the KMOD error string. It returns 0, -1, -2, or -3.
 */
static int klink_session_recv_msg(struct klink_session *self, uint32_t *msg_type, kbuffer *payload) {
    int error = 0;
    uint32_t header_len = 2*4;
    uint32_t payload_size;
    
    kmod_log_msg(3, "klink_session_recv_msg() called.\n");
    
    /* Try. */
    do {
	/* Receive the message header (using the payload buffer temporarily). */
	payload->pos = payload->len = 0;
	error = klink_session_ssl_transfer(self, 1, kbuffer_write_nbytes(payload, header_len), header_len,
	    	    	    	           "cannot receive KAPPS message header");
	if (error) break;

	lbuffer_read32(payload, msg_type);
	lbuffer_read32(payload, &payload_size);
	
	/* Receive the payload. */
	payload->pos = payload->len = 0;
	error = klink_session_ssl_transfer(self, 1, kbuffer_write_nbytes(payload, payload_size), payload_size, 
	    	    	    	           "cannot receive KAPPS message content");
	if (error) break;
    	
    } while (0);
    
    return error;
}

/* This function adds a 32 bit unsigned integer to the buffer. */
void link_msg_write_uint32(kbuffer *buf, uint32_t i) {
    kbuffer_write8(buf, KNP_UINT32);
    kbuffer_write32(buf, i);
}

/* This function adds a 64 bit unsigned integer to the buffer. */
void link_msg_write_uint64(kbuffer *buf, uint64_t i) {
    kbuffer_write8(buf, KNP_UINT64);
    kbuffer_write64(buf, i);
}

/* This function adds a textual kstr to the buffer. */
void link_msg_write_kstr(kbuffer *buf, kstr *str) {
    kbuffer_write8(buf, KNP_STR);
    kbuffer_write32(buf, str->slen);
    kbuffer_write(buf, str->data, str->slen);
}

/* This function adds a C string to the buffer. */
void link_msg_write_cstr(kbuffer *buf, char *str) {
    int len = strlen(str);
    kbuffer_write8(buf, KNP_STR);
    kbuffer_write32(buf, len);
    kbuffer_write(buf, str, len);
}

/* This function adds a binary kstr to the buffer. */
void link_msg_write_bin(kbuffer *buf, kstr *str) {
    kbuffer_write8(buf, KNP_BIN);
    kbuffer_write32(buf, str->slen);
    kbuffer_write(buf, str->data, str->slen);
}

/* Helper function for the link_msg_read_* functions. It ensures that the next
 * value has the expected type.
 * This function sets the KMOD error string. It returns -1 on failure.
 */
static int link_msg_read_ensure_type(kbuffer *buf, uint8_t expected_type) {
    uint8_t actual_type;
	
    if (lbuffer_read8(buf, &actual_type)) return -1;
    
    if (actual_type != expected_type) {
	char *type_name = "unknown";
	
	switch (actual_type) {
	    case KNP_UINT32: type_name = "UINT32"; break;
	    case KNP_UINT64: type_name = "UINT64"; break;
	    case KNP_STR: type_name = "STR"; break;
	    case KNP_BIN: type_name = "BIN"; break;
	}
    
	kmod_set_error("unexpected value of type %s", type_name);
	return -1;
    }
    
    return 0;
}

/* This function reads a 32 bit unsigned integer from the buffer.
 * This function sets the KMOD error string. It returns -1 on failure.
 */
int link_msg_read_uint32(kbuffer *buf, uint32_t *i) {
    int error = 0;
    
    /* Try. */
    do {
	error = link_msg_read_ensure_type(buf, KNP_UINT32);
	if (error) break;
	
	error = lbuffer_read32(buf, i);
	if (error) break;
	
    } while (0);
    
    if (error) {
    	kmod_set_error("cannot read UINT32 value in message");
    	return -1;
    }
    
    return 0;
}

/* This function reads a 64 bit unsigned integer from the buffer.
 * This function sets the KMOD error string. It returns -1 on failure.
 */
int link_msg_read_uint64(kbuffer *buf, uint64_t *i) {
    int error = 0;
    
    /* Try. */
    do {
	error = link_msg_read_ensure_type(buf, KNP_UINT64);
	if (error) break;
	
	error = lbuffer_read64(buf, i);
	if (error) break;
	
    } while (0);
    
    if (error) {
    	kmod_set_error("cannot read UINT64 value in message");
    	return -1;
    }
    
    return 0;
}

/* This function reads a kstr of type STR from the buffer.
 * This function sets the KMOD error string. It returns -1 on failure.
 */
int link_msg_read_str(kbuffer *buf, kstr *str) {
    int error = 0;
    uint32_t len;
    
    /* Try. */
    do {
	error = link_msg_read_ensure_type(buf, KNP_STR);
	if (error) break;
	
	error = lbuffer_read32(buf, &len);
	if (error) break;
	
	kstr_grow(str, len);
	lbuffer_read(buf, str->data, len);
	str->data[len] = 0;
	str->slen = len;

    } while (0);
    
    if (error) {
    	kmod_set_error("cannot read STR value in message");
    	return -1;
    }
    
    return 0;
}

/* This function reads a kstr of type BIN from the buffer.
 * This function sets the KMOD error string. It returns -1 on failure.
 */
int link_msg_read_bin(kbuffer *buf, kstr *str) {
    int error = 0;
    uint32_t len;
    
    /* Try. */
    do {
	error = link_msg_read_ensure_type(buf, KNP_BIN);
	if (error) break;
	
	error = lbuffer_read32(buf, &len);
	if (error) break;
	
	kstr_grow(str, len);
	lbuffer_read(buf, str->data, len);
	str->data[len] = 0;
	str->slen = len;

    } while (0);
    
    if (error) {
    	kmod_set_error("cannot read BIN value in message");
    	return -1;
    }
    
    return 0;
}

/* This function dumps the content of a KNP message buffer in the string
 * specified. This function sets the KMOD error string when it encounters an
 * error in the buffer. It returns -1 on failure.
 */
int link_msg_dump(kbuffer *buf, kstr *dump_str) {
    int error = 0;
    kstr work_str;
    kstr data_str;
    
    kstr_init(&work_str);
    kstr_init(&data_str);
    kstr_clean(dump_str);

    while (! kbuffer_eof(buf)) {
	uint8_t type = buf->data[buf->pos];
	
	if (type == KNP_UINT32) {
	    uint32_t val;
	    error = link_msg_read_uint32(buf, &val);
	    if (error) break;
	    
	    kstr_sf(&work_str, "uint32> %u\n", val);
	    kstr_append_kstr(dump_str, &work_str);
	}
	
	else if (type == KNP_UINT64) {
	    uint64_t val;
	    error = link_msg_read_uint64(buf, &val);
	    if (error) break;
	    
	    kstr_sf(&work_str, "uint64> %lu\n", val);
	    kstr_append_kstr(dump_str, &work_str);
	}
	
	else if (type == KNP_STR) {
	    error = link_msg_read_str(buf, &data_str);
	    if (error) break;
	
	    kstr_sf(&work_str, "string %u> ", data_str.slen);
	    kstr_append_kstr(dump_str, &work_str);
	    kstr_append_kstr(dump_str, &data_str);
	}
	
	else {
	    kmod_set_error("invalid KNP identifier (%u)", type);
	    error = -1;
	    break;
	}
    }
    
    kstr_clean(&work_str);
    kstr_clean(&data_str);
    
    /* Reset the buffer position to 0. */
    buf->pos = 0;
    
    return error;
}

#ifdef __KAPPSD__

/* This function negociates a SSL session with the client.
 * This function sets the KMOD error string. It returns 0, -1, -2, or -3.
 */ 
static int klink_session_negociate_server_session(struct klink_session *session) {
    int error = 0;
    SSL_METHOD *ssl_method;
    BIO *ssl_bio;
    char *ssl_cert_file = global_opts.ssl_cert_path.data;
    char *ssl_key_file = global_opts.ssl_key_path.data;
    
    kmod_log_msg(3, "klink_session_negociate_server_session() called.\n");
    
    /* Create the SSL driver. */
    struct knp_ssl_driver *driver = (struct knp_ssl_driver *) kcalloc(sizeof(struct knp_ssl_driver));
    assert(session->ssl_driver == NULL);
    session->ssl_driver = driver;
    
    ssl_method = SSLv3_server_method();
    if (ssl_method == NULL) {
    	kmod_set_error("cannot initialize SSL method");
	return -1;
    }
    
    driver->ssl_ctx = SSL_CTX_new(ssl_method);
    if (driver->ssl_ctx == NULL) {
    	kmod_set_error("cannot initialize SSL context");
	return -1;
    }

    if (SSL_CTX_use_certificate_chain_file(driver->ssl_ctx, ssl_cert_file) != 1 ||
	SSL_CTX_use_PrivateKey_file(driver->ssl_ctx, ssl_key_file, SSL_FILETYPE_PEM) != 1 ||
	SSL_CTX_load_verify_locations(driver->ssl_ctx, ssl_cert_file, NULL) != 1) {
	kmod_set_error("cannot load certificate");
	return -1;
    }
    
    ssl_bio = BIO_new_socket(session->transfer.fd, BIO_NOCLOSE);
    if (ssl_bio == NULL) {
    	kmod_set_error("cannot initialize SSL BIO");
	return -1;
    }
    
    driver->ssl = SSL_new(driver->ssl_ctx);
    if (driver->ssl == NULL) {
    	kmod_set_error("cannot initialize SSL session");
	return -1;
    }

    /* Set SSL BIO. 'ssl_bio' is owned by 'ssl', do not free. */
    SSL_set_bio(driver->ssl, ssl_bio, ssl_bio);
    
    /* Loop until we connect or fail. */
    while (1) {
	error = SSL_accept(driver->ssl);
	
	/* We're connected. */
	if (error > 0) {
	    error = 0;
	    break;
	}

	else {
	    int ssl_error = SSL_get_error(driver->ssl, error);
	    error = 0;

	    /* SSL wants us to wait for reading data. */
	    if (ssl_error == SSL_ERROR_WANT_READ) {
	    	error = klink_session_wait_for_data(session, 1, "SSL negociation read failed");
		if (error) return error;
	    }

	    /* SSL wants us to wait for writing data. */
	    else if (ssl_error == SSL_ERROR_WANT_WRITE) {
		error = klink_session_wait_for_data(session, 0, "SSL negociation write failed");
		if (error) return error;
	    }

	    /* Life is tough. */
	    else {
		kmod_set_error("SSL negociation failed: %s", get_ssl_error_string(ssl_error));
        	return -1;
	    }
	}
    }

    return 0;
}

/* Process a single connection. */
static void kappsd_handle_conn(int *sock) {
    int error = 0;
    uint32_t in_type, out_type;
    kbuffer in_buf, out_buf;
    struct klink_session session;
    struct kmod_data_transfer *transfer = &session.transfer;
    struct kmod_transfer_hub hub;
    int op_timeout = 10000;
    struct sockaddr_in sock_addr;
    socklen_t sock_len;
    
    kmod_log_msg(3, "kappsd_handle_conn() called.\n");
    
    kbuffer_init(&in_buf);
    kbuffer_init(&out_buf);
    
    kmod_data_transfer_init(transfer);
    transfer->driver = kmod_sock_driver;
    transfer->fd = *sock;
    transfer->op_timeout = op_timeout;
    
    session.ssl_driver = NULL;
    session.hub = &hub;
    
    kmod_transfer_hub_init(&hub);
    
    do {
	/* Get the client address. */
	sock_len = sizeof(sock_addr);
	error = getpeername(*sock, (struct sockaddr *) &sock_addr, &sock_len);
	if (error) {
	    kmod_set_error("cannot get peer name: %s", strerror(errno));
	    break;
	}
	
	kmod_log_msg(2, "Got connection from %s on port %u.\n",
		     inet_ntoa(sock_addr.sin_addr), ntohs(sock_addr.sin_port));
	
	/* Negociate the SSL session. */
	error = klink_session_negociate_server_session(&session);
	if (error) break;
	
	/* Loop processing messages. */
	while (1) {
	
	    /* Wait for message. Stop on error. */
	    transfer->op_timeout = 0;
	    
	    if (klink_session_wait_for_data(&session, 1, "waiting for next request")) {
		kmod_log_msg(2, "-> No more requests from KMOD, job complete (%s).\n", kmod_strerror());
		break;
	    }
	
	    transfer->op_timeout = op_timeout;
	    
	    /* Receive the message payload. Stop on error. */
	    if (klink_session_recv_msg(&session, &in_type, &in_buf)) {
		kmod_log_msg(2, "=> No more requests from KMOD, job complete (%s).\n", kmod_strerror());
		break;
	    }
	    
	    /* Build the message payload. */
	    out_buf.pos = out_buf.len = 0;
	    error = kappsd_handle_plugin_request(in_type, &in_buf, &out_type, &out_buf);
	    if (error) break;
	    
	    /* Send the message payload. */
	    error = klink_session_send_msg(&session, out_type, &out_buf);
	    if (error) break;
	}
	
	if (error) break;
    
    } while (0);
    
    if (session.ssl_driver) {
    	if (session.ssl_driver->ssl) SSL_free(session.ssl_driver->ssl);
	if (session.ssl_driver->ssl_ctx) SSL_CTX_free(session.ssl_driver->ssl_ctx);
	free (session.ssl_driver);
	session.ssl_driver = NULL;
    }
    
    kmod_data_transfer_clean(transfer);
    kmod_transfer_hub_clean(&hub);
    ksock_close(sock);
    
    kbuffer_clean(&in_buf);
    kbuffer_clean(&out_buf);
    
    if (error) {
	kmod_log_msg(2, "Connection handling error: %s\n", kmod_strerror());
    }
}

/* Collect zombies. */
static void collect_zombie() {
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
}

/* Loop accepting connections. */
int kappsd_linkage_loop() { 
    int error = 0;
    int listen_sock = -1;
    int conn_sock = -1;
    fd_set read_set;
    struct timeval tv;
    
    kmod_log_msg(3, "kmod_linkage_loop() called.\n");
    
    do {
	/* Begin listening for connections. */
	error = ksock_create(&listen_sock);
	if (error) break;
	
	error = ksock_bind(listen_sock, global_opts.kappsd_port);
	if (error) break;
	
	error = ksock_listen(listen_sock);
	if (error) break;
	
	error = ksock_set_unblocking(listen_sock);
	if (error) break;
	
	/* Loop accepting connections. */
	while (1) {
	    /* Wait for a connection. */
	    FD_ZERO(&read_set);
	    FD_SET((unsigned int) listen_sock, &read_set);
	    tv.tv_sec = 1;
	    tv.tv_usec = 0;
	    select(listen_sock + 1, &read_set, NULL, NULL, &tv);
	    
	    /* Check if we must quit. */
	    if (global_opts.quit_flag) break;
	    
	    /* Collect zombies. */
	    collect_zombie();
	    
	    /* Try to accept a connection. */
	    error = ksock_accept(listen_sock, &conn_sock);
	    
	    /* Ignore no connection. */
	    if (error == -2) {
		error = 0;
		continue;
	    }
	    
	    /* Connection error. */
	    if (error) break;
	    
	    kmod_log_msg(2, "Received new connection.\n");
	    
	    error = ksock_set_unblocking(conn_sock);
	    if (error) break;
		    
            /* Obtain a port, in case we need it. This has to be done before
             * forking due to the need to be synchronized.
             */
	    error = kappsd_obtain_usable_port(&global_opts.tunnel_port);
	    if (error) break;
	    
	    /* Clear the current captcha, if any. */
	    kstr_reset(&global_opts.captcha);
	    
	    /* Handle single connection. */
	    if (! global_opts.fork_flag) {
		kappsd_handle_conn(&conn_sock);
	    }
	    
	    /* Fork. */
	    else {
		error = fork();
		
		if (error == -1) {
		    kmod_set_error("fork failed: ", kmod_syserror());
		    break;
		}
		
		/* Child. */
		if (error == 0) {
		    kappsd_handle_conn(&conn_sock);
		    kmod_log_msg(2, "Child process exiting.\n");
		    exit(0);
		}
		
		/* Parent. */
		else {
		    ksock_close(&conn_sock);
		}
	    }
	}
	
	if (error) break;
	
    } while (0);
    
    ksock_close(&listen_sock);
    ksock_close(&conn_sock);
    
    return error;
}

#else

static struct klink_session *kappsd_session = NULL;
static struct kmod_transfer_hub kappsd_hub;

/* This function negociates a SSL session with the server.
 * This function sets the KMOD error string. It returns 0, -1, -2, or -3.
 */ 
static int klink_session_negociate_client_session(struct klink_session *session) {
    int error = 0;
    SSL_METHOD *ssl_method;
    BIO *ssl_bio;
    
    kmod_log_msg(3, "klink_session_negociate_client_session() called.\n");
    
    /* Create the SSL driver. */
    struct knp_ssl_driver *driver = (struct knp_ssl_driver *) kcalloc(sizeof(struct knp_ssl_driver));
    assert(session->ssl_driver == NULL);
    session->ssl_driver = driver;
    
    ssl_method = SSLv3_client_method();
    if (ssl_method == NULL) {
    	kmod_set_error("cannot initialize SSL method");
	return -1;
    }
    
    driver->ssl_ctx = SSL_CTX_new(ssl_method);
    if (driver->ssl_ctx == NULL) {
    	kmod_set_error("cannot initialize SSL context");
	return -1;
    }

    driver->ssl = SSL_new(driver->ssl_ctx);
    if (driver->ssl == NULL) {
    	kmod_set_error("cannot initialize SSL session");
	return -1;
    }

    ssl_bio = BIO_new_socket(session->transfer.fd, BIO_NOCLOSE);
    if (ssl_bio == NULL) {
    	kmod_set_error("cannot initialize SSL BIO");
	return -1;
    }
    
    /* Set SSL BIO. 'ssl_bio' is owned by 'ssl', do not free. */
    SSL_set_bio(driver->ssl, ssl_bio, ssl_bio);
    
    /* If we need a certificate, require the server to send us its certificate. */
    SSL_set_verify(driver->ssl, SSL_VERIFY_NONE, NULL);

    /* Loop until we connect or fail. */
    while (1) {
	error = SSL_connect(driver->ssl);

	/* We're connected. */
	if (error > 0) {
	    error = 0;
	    break;
	}

	else {
	    int ssl_error = SSL_get_error(driver->ssl, error);
	    error = 0;

	    /* SSL wants us to wait for reading data. */
	    if (ssl_error == SSL_ERROR_WANT_READ) {
	    	error = klink_session_wait_for_data(session, 1, "SSL negociation read failed");
		if (error) return error;
	    }

	    /* SSL wants us to wait for writing data. */
	    else if (ssl_error == SSL_ERROR_WANT_WRITE) {
		error = klink_session_wait_for_data(session, 0, "SSL negociation write failed");
		if (error) return error;
	    }

	    /* Life is tough. */
	    else {
		kmod_set_error("SSL negociation failed: %s", get_ssl_error_string(ssl_error));
        	return -1;
	    }
	}
    }

    return 0;
}

    
/* This function connects KMOD to kappsd. */
int kmod_open_kappsd_session(char *host, int port) {
    int error = 0;
    
    // YAK.
    host = "kaskappsd.teambox.co";
    port = 443;
    
    kmod_log_msg(3, "kmod_open_kappsd_session() called.\n");
    
    if (kappsd_session) kmod_close_kappsd_session();
    
    do {
    	struct klink_session *session = kappsd_session = kcalloc(sizeof(struct klink_session));
	struct kmod_data_transfer *transfer = &session->transfer;
	int *sock = &transfer->fd;

	kmod_data_transfer_init(transfer);
	transfer->driver = kmo_sock_driver;
	transfer->fd = -1;
	transfer->op_timeout = 10000;
	session->ssl_driver = NULL;
    
	kmod_transfer_hub_init(&kappsd_hub);
	session->hub = &kappsd_hub;
    
	error = ksock_create(sock);
	if (error) break;
	
	error = ksock_set_unblocking(*sock);
	if (error) break;
	
	error = ksock_connect(*sock, host, port);
	if (error) break;
	
	error = klink_session_wait_for_data(session, 0, "cannot connect to KAS");
	if (error) break;
	 
	error = ksock_connect_check(*sock, host);
	if (error) break;
	
	error = klink_session_negociate_client_session(session);
	if (error) break;
    
    } while (0);
    
    if (error) kmod_close_kappsd_session();
    
    return error;
}

/* This function disconnects KMOD from kappsd. */
void kmod_close_kappsd_session() {
    kmod_log_msg(3, "kmod_close_kappsd_session() called.\n");
    
    if (kappsd_session) {
	struct klink_session *session = kappsd_session;
	struct kmod_data_transfer *transfer = &session->transfer;

	if (session->ssl_driver) {
    	    if (session->ssl_driver->ssl) SSL_free(session->ssl_driver->ssl);
	    if (session->ssl_driver->ssl_ctx) SSL_CTX_free(session->ssl_driver->ssl_ctx);
	    free (session->ssl_driver);
	    session->ssl_driver = NULL;
	}

	ksock_close(&transfer->fd);
	kmod_data_transfer_clean(transfer);
	kfree(kappsd_session);
	kappsd_session = NULL;
	
	kmod_transfer_hub_clean(&kappsd_hub);
    }
}

/* This function exchanges messages with kappsd. */
int kmod_exchange_kappsd_message(uint32_t in_type, kbuffer *in_buf, uint32_t *out_type, kbuffer *out_buf) {
    int error = 0;
    struct klink_session *session = kappsd_session;
    
    kmod_log_msg(3, "kmod_exchange_kappsd_message() called.\n");
    
    do {
	if (session == NULL) {
	    kmod_set_error("the kappsd session is closed");
	    error = -1;
	    break;
	}
	
	/* Send the message payload. */
	error = klink_session_send_msg(session, in_type, in_buf);
	if (error) break;

	/* Receive the message payload. */
	error = klink_session_recv_msg(session, out_type, out_buf);
	if (error) break;

    } while (0);
    
    return error;
}

#endif

