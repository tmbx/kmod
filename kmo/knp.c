/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "knp.h"
#include "utils.h"
#include "base64.h"
#include "kmo_sock.h"
#include "kmod.h"

#ifdef __UNIX__
#include <adns.h>
#else
#include <windns.h>
#endif

/* Teambox online servers info. */
static char *ops_address = "ops.teambox.co";
static char *ous_address = "ous.teambox.co";
static char *ots_address = "ots.teambox.co";
static char *iks_address = "iks.teambox.co";
static char *eks_address = "eks.teambox.co";
static int kos_port = 443;

/* BACKPORT. */
static char *srv_ops_address = "_ops._tcp.teambox.co";
static char *srv_ous_address = "_ous._tcp.teambox.co";
static char *srv_ots_address = "_ots._tcp.teambox.co";
static char *srv_iks_address = "_iks._tcp.teambox.co";
static char *srv_eks_address = "_eks._tcp.teambox.co";

/* OpenSSL is a total nitpick about the certificate syntax. Newlines must appear
 * at their place otherwise the certificate is _obviously_ invalid. Thus, to
 * recreate a certificate, we:
 * - create an empty buffer.
 * - append "-----BEGIN CERTIFICATE-----\n".
 * - append the certificate text.
 * - append "-----END CERTIFICATE-----\n\".
 * - substitute all occurrences of '|' by newlines in the buffer. Normally, the
 *   server should have stripped the certificate header and footer and replaced
 *  the newlines by '|'.
 */
static char *kos_cert ="\
MIIDUjCCArugAwIBAgIJAJse38QmvEVTMA0GCSqGSIb3DQEBBAUAMHoxCzAJBgNV|\
BAYTAmNhMQ8wDQYDVQQIEwZxdWViZWMxFjAUBgNVBAoTDUtyeXB0aXZhIGluYy4x|\
HTAbBgNVBAMTFEtyeXB0aXZhIEtPUyByb290IENBMSMwIQYJKoZIhvcNAQkBFhRz|\
dXBwb3J0QGtyeXB0aXZhLmNvbTAeFw0wNjEwMTYxNjI1MDVaFw0xNjEwMTMxNjI1|\
MDVaMHoxCzAJBgNVBAYTAmNhMQ8wDQYDVQQIEwZxdWViZWMxFjAUBgNVBAoTDUty|\
eXB0aXZhIGluYy4xHTAbBgNVBAMTFEtyeXB0aXZhIEtPUyByb290IENBMSMwIQYJ|\
KoZIhvcNAQkBFhRzdXBwb3J0QGtyeXB0aXZhLmNvbTCBnzANBgkqhkiG9w0BAQEF|\
AAOBjQAwgYkCgYEAq6pBQc6QcaVlQ3VKlzX3u4HUF90+lojpp1idwdmHfSGtxYII|\
87rIHs9VHQLkfyaFWeDbJx727psG0cMgA1W59nptD9oV05p0AuRn7N5k2wC7l+JC|\
zt6sdSoH/FPZMA1HFaEgjX0vBxN4WpB4iPD1KJGjMlRiKmDCr1q54C21I/0CAwEA|\
AaOB3zCB3DAdBgNVHQ4EFgQUbOLw/lv9etZyf9PyrEEbHhQWMw0wgawGA1UdIwSB|\
pDCBoYAUbOLw/lv9etZyf9PyrEEbHhQWMw2hfqR8MHoxCzAJBgNVBAYTAmNhMQ8w|\
DQYDVQQIEwZxdWViZWMxFjAUBgNVBAoTDUtyeXB0aXZhIGluYy4xHTAbBgNVBAMT|\
FEtyeXB0aXZhIEtPUyByb290IENBMSMwIQYJKoZIhvcNAQkBFhRzdXBwb3J0QGty|\
eXB0aXZhLmNvbYIJAJse38QmvEVTMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEE|\
BQADgYEAoDw5/sb+sXq3YQlQ2INeCzn8wgjMXq5AbIS+AzLh3RYR1XB0setCKxYp|\
acRkjde7/E4it49M5tQZdvYGUwfuVdeFlVGYwzblDYKW2ee22f4ABAmV0i077aKz|\
daoYu0cMOAziTOKeG1GoDvVsnDOgpSpa0hHH7duuUuUENRQBOEk=|\
";

/* KNP SSL driver. */
struct knp_ssl_driver {
    SSL_CTX *ssl_ctx;
    SSL *ssl;
};

/* This function creates and initializes a KNP query.
 * The login OTUT must be set manually if it's needed.
 */
struct knp_query * knp_query_new(int contact, int login_type, int cmd_type, kbuffer *cmd_payload) {
    struct knp_query *query = (struct knp_query *) kmo_calloc(sizeof(struct knp_query));
    query->contact = contact;
    kstr_init(&query->server_addr);
    query->login_type = login_type;
    query->cmd_type = cmd_type;
    query->cmd_payload = cmd_payload;
    kmo_data_transfer_init(&query->transfer);
    query->transfer.driver = kmo_sock_driver;
    return query;
}

/* This function destroys a server query. The connection to the server is closed
 * if it is open.
 */
void knp_query_destroy(struct knp_query *self) {
    if (self == NULL) return;
    
    knp_query_disconnect(self);
    kstr_free(&self->server_addr);
    kstr_destroy(self->login_otut);
    kbuffer_destroy(self->res_payload);
    kstr_destroy(self->serv_error_msg);
    kmo_data_transfer_free(&self->transfer);
    
    free(self);
}

/* This function closes the connection with the server, if it is open. */
void knp_query_disconnect(struct knp_query *self) {
    
    kmod_log_msg(3, "knp_query_disconnect() called.\n");
    
    if (self->transfer.fd != -1) {
    	self->transfer.driver.disconnect(&self->transfer.fd);
    }
    
    if (self->ssl_driver) {
    	if (self->ssl_driver->ssl) SSL_free(self->ssl_driver->ssl);
	if (self->ssl_driver->ssl_ctx) SSL_CTX_free(self->ssl_driver->ssl_ctx);
	free (self->ssl_driver);
	self->ssl_driver = NULL;
    }
}

/* This function handles a connection error that occurred while processing a
 * query. Normally the connection error message should have been set by 
 * kmo_seterror(). The KNP connection is closed if it is open.
 */
static void knp_query_handle_conn_error(struct knp_query *query, int serv_error_id) {
    kmod_log_msg(3, "knp_query_handle_conn_error() called.\n");
    
    assert(! query->res_type && query->res_payload == NULL);
    query->res_type = KNP_RES_SERV_ERROR;
    query->serv_error_id = serv_error_id;
    query->serv_error_msg = kstr_new();
    kstr_assign_kstr(query->serv_error_msg, kmo_kstrerror());
    knp_query_disconnect(query);
}

/* This function chats with the plugin when K3P elements are available. If the
 * plugin asks to abort the current K3P transaction, this function returns -2.
 * If the K3P connection is lost, this function sets the KMO error string and
 * returns -3. Otherwise, this function returns 0.
 */
static int knp_handle_k3p_activity(k3p_proto *k3p) {
    uint32_t cmd;
    
    kmod_log_msg(3, "knp_handle_k3p_activity() called.\n");
    
    /* Loop until we've read all buffered K3P elements. */
    while (k3p->element_array_pos != k3p->element_array.size) {
	
	/* Read the next instruction. */
	if (k3p_read_inst(k3p, &cmd))
	    return -3;
	
	/* Unexpected command. */
	k3p_proto_disconnect(k3p);
	kmo_seterror("unexpected instruction (%x) while processing KNP query", cmd);
	return -3;
    }

    return 0;
}

/* This function executes the specified KNP transfer. While the KNP transfer is
 * progressing, this function monitors the K3P connection for activity. If the
 * plugin asks to abort the current K3P transaction, this function returns -2.
 * If the K3P connection is lost, this function sets the KMO error string and
 * returns -3. Otherwise, this function returns 0 when the KNP transfer is
 * completed (successfully or not). 
 */
static int knp_exec_transfer(struct kmo_data_transfer *knp_transfer, k3p_proto *k3p) {
    int error = 0;
    
    kmod_log_msg(3, "knp_exec_transfer() called.\n");
    
    /* At this point the transfer hub should be empty. */
    assert(! k3p->hub->transfer_hash.size);
    
    /* The K3P connection should be up. */
    assert(k3p->state == K3P_INTERACTING);
    assert(k3p->transfer.fd != -1);
    
    /* There should be no data in the K3P data buffer. */
    assert(! k3p->data_buf.len);
    
    /* Set the status of the KNP transfer to pending, should we return early. */
    knp_transfer->status = KMO_COMM_TRANS_PENDING;
    
    /* There might be buffered K3P elements. Process them now. */
    error = knp_handle_k3p_activity(k3p);
    if (error) return error;
    
    /* Add the KNP transfer in the hub. */
    kmo_transfer_hub_add(k3p->hub, knp_transfer);
    
    /* Loop until the KNP transfer is completed or an error occurs. */
    while (1) {
	/* Add the K3P transfer in the hub. */
	k3p->transfer.read_flag = 1;
	assert(! k3p->data_buf.len);
	k3p->transfer.buf = kbuffer_begin_write(&k3p->data_buf, 4096);
	k3p->transfer.min_len = 1;
	k3p->transfer.max_len = 4096;
	k3p->transfer.op_timeout = 0;
	kmo_transfer_hub_add(k3p->hub, &k3p->transfer);
	
	/* Wait for the transfers to complete. */
	kmo_transfer_hub_wait(k3p->hub);
	
	/* Remove the K3P transfer from the hub. */
	kmo_transfer_hub_remove(k3p->hub, &k3p->transfer);
	
	/* The K3P transfer is completed. */
	if (k3p->transfer.status == KMO_COMM_TRANS_COMPLETED) {
	    
	    /* Read the K3P elements. */
            kbuffer_end_write(&k3p->data_buf, k3p->transfer.trans_len);
	    assert(k3p->data_buf.len);
	    
	    if (k3p_receive_element(k3p)) {
	    	error = -3;
		break;
	    }
	    
	    /* Process the K3P elements. */
	    error = knp_handle_k3p_activity(k3p);
	    if (error) break;
	}
	
	/* An error occurred with the K3P transfer. */
	else if (k3p->transfer.status == KMO_COMM_TRANS_ERROR) {
	    
	    /* It can't be a timeout. */
	    assert(k3p->transfer.err_msg);
	        
	    /* Bail out. */
	    k3p_proto_disconnect(k3p);
	    kmo_seterror("cannot read data from plugin: %s", k3p->transfer.err_msg->data);
	    error = -3;
	    break;
	}
	
	/* The K3P transfer is still pending. */
	else {
	    assert(k3p->transfer.status == KMO_COMM_TRANS_PENDING);
	}
	
	/* The KNP transfer is finished. */
	if (knp_transfer->status == KMO_COMM_TRANS_COMPLETED || knp_transfer->status == KMO_COMM_TRANS_ERROR) {
	    break;
	}
	
	/* The KNP transfer is still pending. */
	else {
	    assert(knp_transfer->status == KMO_COMM_TRANS_PENDING);
	}
    }
    
    /* Remove the KNP transfer from the hub. */
    kmo_transfer_hub_remove(k3p->hub, knp_transfer);
    
    return error;
}

/* This function waits for the connection to become readable or writable. This
 * function chats with the plugin as required and calls 
 * knp_query_handle_conn_error() if an error occurs with the connection.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int knp_query_wait_for_data(struct knp_query *query, int read_flag, char *err_str, k3p_proto *k3p) {
    int error = 0;
    struct kmo_data_transfer *transfer = &query->transfer;
    
    kmod_log_msg(3, "knp_query_wait_for_data() called.\n");
    
    transfer->read_flag = read_flag;
    transfer->buf = NULL;
    transfer->min_len = transfer->max_len = 0;
    error = knp_exec_transfer(transfer, k3p);
    if (error) return error;
    
    if (transfer->status != KMO_COMM_TRANS_COMPLETED) {
	assert(transfer->status == KMO_COMM_TRANS_ERROR);
	kmo_seterror("%s: %s", err_str, kmo_data_transfer_err(transfer));
	knp_query_handle_conn_error(query, transfer->err_msg ? KMO_SERROR_MISC : KMO_SERROR_TIMEOUT);
	return -1;
    }
    
    return 0;
}

/* This function asks the proxy to connect us to the end server.
 * This function sets the KMO error string. It returns 0, -1, -2 or -3.
 */
static int knp_handle_proxy(struct knp_query *query, k3p_proto *k3p, kstr *proxy_login, kstr *proxy_pwd) {
    int error = 0;
    int first_line = 1;
    struct kmo_data_transfer *transfer = &query->transfer;
    kstr msg;
    kstr str;
    
    kmod_log_msg(3, "knp_handle_proxy() called.\n");
    
    kstr_init(&msg);
    kstr_init(&str);
	
    /* Try. */
    do {
	/* Connect to the specified server and port. */
	kstr_sf(&msg, "CONNECT %s:%d HTTP/1.0\r\n", query->server_addr.data, query->server_port);
    	
	/* Using the following "user:pwd" credentials encoded in base 64. */
	if (proxy_login->slen > 0 || proxy_pwd->slen > 0) {
	    kbuffer in, out;
	    kbuffer_init(&in, 100);
	    kbuffer_init(&out, 100);
	    
	    kbuffer_write(&in, proxy_login->data, proxy_login->slen);
	    kbuffer_write(&in, ":", 1);
	    kbuffer_write(&in, proxy_pwd->data, proxy_pwd->slen);
	    bin2b64(&in, &out);
	    
	    kstr_append_cstr(&msg, "Proxy-Authorization: basic ");
	    kstr_append_buf(&msg, out.data, out.len);
	    kstr_append_cstr(&msg, "\r\n");
	    
	    kbuffer_clean(&in);
	    kbuffer_clean(&out);
	}
	
	/* An empty line marks the end of the request. */
	kstr_append_cstr(&msg, "\r\n");
	
	/* Send the message to the proxy. */
	transfer->read_flag = 0;
	transfer->buf = msg.data;
	transfer->min_len = transfer->max_len = msg.slen;
	error = knp_exec_transfer(transfer, k3p);
	if (error) break;
	
	if (transfer->status != KMO_COMM_TRANS_COMPLETED) {
	    assert(transfer->status == KMO_COMM_TRANS_ERROR);
	    kmo_seterror("proxy error: %s", kmo_data_transfer_err(transfer));
	    knp_query_handle_conn_error(query, transfer->err_msg ? KMO_SERROR_MISC : KMO_SERROR_TIMEOUT);
	    error = -1;
	    break;
	}
    
    	/* Receive the reply from the server, char by char to avoid reading past 
	 * the HTTP reply data.
	 */
	kstr_clear(&msg);
	
	while (1) {
	    char c;
	    transfer->read_flag = 1;
	    transfer->buf = &c;
	    transfer->min_len = transfer->max_len = 1;
	    error = knp_exec_transfer(transfer, k3p);
	    if (error) break;

	    if (transfer->status != KMO_COMM_TRANS_COMPLETED) {
		assert(transfer->status == KMO_COMM_TRANS_ERROR);
		kmo_seterror("proxy error: %s", kmo_data_transfer_err(transfer));
		knp_query_handle_conn_error(query, transfer->err_msg ? KMO_SERROR_MISC : KMO_SERROR_TIMEOUT);
		error = -1;
		break;
	    }
	    
	    kstr_append_char(&msg, c);
	    
	    /* We reached the end of a line. */
	    if (msg.slen >= 2 && msg.data[msg.slen - 2] == '\r' && msg.data[msg.slen - 1] == '\n') {
	    	
		/* This is the response line. Parse it. */
		if (first_line) {
		    int reply_code;
		    
		    /* Expecting "HTTP/x.x ddd <string>\r\n" */
		    if (msg.slen < 16 || msg.data[0] != 'H' || msg.data[1] != 'T' || msg.data[2] != 'T' ||
		        msg.data[3] != 'P' || ! is_digit(msg.data[9]) || ! is_digit(msg.data[10]) ||
			! is_digit(msg.data[11])) {
			
		    	kmo_seterror("invalid proxy HTTP reply");
		    	error = -1;
			break;
		    }
		    
		    /* Get the numeric code. */
		    reply_code = atoi(msg.data + 9);
		    
		    /* Not 200, it didn't work. */
		    if (reply_code != 200) {
		    	
		    	/* Get the reason. */
		    	kstr_assign_buf(&str, msg.data + 13, msg.slen - 2 - 13);
			kmo_seterror("the proxy refuses to connect: %s (code %d)", str.data, reply_code);
			error = -1;
			break;
		    }
		    
		    first_line = 0;
		}
		
		/* The server is sending us some unwanted line. Ignore it. */
		else if (msg.slen != 2) {
		    /* Void. */
		}
		
		/* We reached the end of the reply. The next bytes received will be SSL bytes. */
		else {
		    break;
		}
		
		/* Clear the line buffer. */
	    	kstr_clear(&msg);
	    }
	    
	    /* It's too long. */
	    else if (msg.slen > 1000) {
	    	kmo_seterror("HTTP reply too long");
    	    	error = -1;
		break;
	    }
	}
	
	if (error) break;
    
    } while (0);
    
    kstr_free(&msg);
    kstr_free(&str);
    
    return error;
}

/* This function returns a string describing the SSL error that just occurred.
 * Since SSL has proven to be unreliable in that domain, the function does some
 * checking.
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
    	msg = "unknown SSL error";
    }
    
    return msg;
}

/* This function negociates a SSL session with the server.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */ 
static int knp_negociate_ssl_session(struct knp_query *query, char *cert, k3p_proto *k3p) {
    int error = 0;
    SSL_METHOD *ssl_method;
    BIO *ssl_bio;
    
    kmod_log_msg(3, "knp_negociate_ssl_session() called.\n");
    
    /* Create the SSL driver. */
    struct knp_ssl_driver *driver = (struct knp_ssl_driver *) kmo_calloc(sizeof(struct knp_ssl_driver));
    assert(query->ssl_driver == NULL);
    query->ssl_driver = driver;
    
    ssl_method = SSLv3_client_method();
    if (ssl_method == NULL) {
    	kmo_seterror("cannot initialize SSL method");
	return -1;
    }
    
    driver->ssl_ctx = SSL_CTX_new(ssl_method);
    if (driver->ssl_ctx == NULL) {
    	kmo_seterror("cannot initialize SSL context");
	return -1;
    }

    driver->ssl = SSL_new(driver->ssl_ctx);
    if (driver->ssl == NULL) {
    	kmo_seterror("cannot initialize SSL session");
	return -1;
    }

    ssl_bio = BIO_new_socket(query->transfer.fd, BIO_NOCLOSE);
    if (ssl_bio == NULL) {
    	kmo_seterror("cannot initialize SSL BIO");
	return -1;
    }
    
    /* Set SSL BIO. 'ssl_bio' is owned by 'ssl', do not free. */
    SSL_set_bio(driver->ssl, ssl_bio, ssl_bio);
    
    /* If we have a certificate, set it in SSL. */
    if (cert) {
    	int i;
	BIO *cert_bio = NULL;
	X509 *cert_obj = NULL;
	X509_STORE *cert_store = NULL;
	X509_OBJECT x509_obj;
	kstr cert_buf;
	kstr_init(&cert_buf);

	/* Try. */
	do {
	    /* Recreate the certificate. */
	    kstr_append_cstr(&cert_buf, "-----BEGIN CERTIFICATE-----\n");
	    kstr_append_cstr(&cert_buf, cert);
	    kstr_append_cstr(&cert_buf, "-----END CERTIFICATE-----\n");

	    for (i = 0; i < cert_buf.slen; i++) {
		if (cert_buf.data[i] == '|') {
		    cert_buf.data[i] = '\n';
		}
	    }

	    /* Put the certificate text in a buffer. */
	    cert_bio = BIO_new_mem_buf(cert_buf.data, cert_buf.slen);

	    if (cert_bio == NULL) {
		kmo_seterror("cannot create SSL BIO for reading SSL certificate");
		error = -1;
		break;   
	    }

	    /* Create the certificate object with the buffer data. */
	    cert_obj = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);

	    if (cert_obj == NULL) {
		kmo_seterror("cannot create SSL certificate");
		error = -1;
		break;
	    }

	    /* Add the certificate in the certificate store if it is not
	     * already present.
	     */

	    /* Get the certificate store. */
	    cert_store = SSL_CTX_get_cert_store(driver->ssl_ctx);

	    if (cert_store == NULL) {
		kmo_seterror("cannot get SSL certificate store");
		error = -1;
		break;
	    }

	    /* Understanding SSL's API is a daunting task. I've peeked at
	     * the source code and that code should work. For now. Sigh.
	     * Wouldn't it be nice if programmers bothered to make
	     * *library* APIs that are somewhat sane...
	     *
	     * Check if the certificate is already in the store.
	     */
	    x509_obj.type = X509_LU_X509;
	    x509_obj.data.x509 = cert_obj;

	    /* It seems the certificate is already in the store. */
	    if (X509_OBJECT_retrieve_match(cert_store->objs, &x509_obj)) {
		/* Void. */
	    }

	    /* Add the certificate in the store. We still own cert_obj after
	     * this call.
	     */
	    else if (X509_STORE_add_cert(cert_store, cert_obj) != 1) {
		kmo_seterror("cannot store SSL certificate");
		error = -1;
		break;
	    }

    	} while (0);

	if (cert_obj) X509_free(cert_obj);
	if (cert_bio) BIO_free(cert_bio);
	kstr_free(&cert_buf);
	
	if (error) return error;
    }

    /* If we need a certificate, require the server to send us its certificate. */
    SSL_set_verify(driver->ssl, cert ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);

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
	    	error = knp_query_wait_for_data(query, 1, "SSL negociation read failed", k3p);
		if (error) return error;
	    }

	    /* SSL wants us to wait for writing data. */
	    else if (ssl_error == SSL_ERROR_WANT_WRITE) {
		error = knp_query_wait_for_data(query, 0, "SSL negociation write failed", k3p);
		if (error) return error;
	    }

	    /* Life is tough. */
	    else {
		kmo_seterror("SSL negociation failed: %s", get_ssl_error_string(ssl_error));
        	return -1;
	    }
	}
    }

    /* Validate the server's certificate as needed. */
    if (cert) {

	/* Check if the server sent us a certificate. */
	X509 *peer_cert = SSL_get_peer_certificate(driver->ssl);

	if (peer_cert == NULL) {
	    kmo_seterror("the server did not send its SSL certificate");
	    return -1;
	}

	X509_free(peer_cert);

	/* Verify the certificate. */
	if (SSL_get_verify_result(driver->ssl) != X509_V_OK) {
	    kmo_seterror("the SSL certificate of the server is invalid");
	    return -1;
	}
    }
    
    return 0;
}

/* This function performs the specified transfer over the SSL connection.
 * This function handles errors just like knp_query_wait_for_data().
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int knp_query_ssl_transfer(struct knp_query *query, int read_flag, char *buf, int size,
    	    	    	    	  char *err_str, k3p_proto *k3p) {
    int nb_trans = 0;
    
    kmod_log_msg(3, "knp_query_ssl_transfer() called.\n");
    
    while (nb_trans != size) {
    	int error;
    	int nb_left = size - nb_trans;

	if (read_flag)
	    error = SSL_read(query->ssl_driver->ssl, buf + nb_trans, nb_left);
	else
	    error = SSL_write(query->ssl_driver->ssl, buf + nb_trans, nb_left);
	
	/* The remote side closed connection. */
	if (error == 0) {
	    kmo_seterror("%s: lost connection", err_str);
	    knp_query_handle_conn_error(query, KMO_SERROR_MISC);
	    return -1;
	}
	
	/* An error occurred. */
	else if (error < 0) {
	    int ssl_err = SSL_get_error(query->ssl_driver->ssl, error);
	    
	    /* Wait for reading. */
	    if (ssl_err == SSL_ERROR_WANT_READ) {
	    	error = knp_query_wait_for_data(query, 1, err_str, k3p);
	    	if (error) return error;
	    }
	    
	    /* Wait for writing. */
	    else if (ssl_err == SSL_ERROR_WANT_WRITE) {
	    	error = knp_query_wait_for_data(query, 0, err_str, k3p);
	    	if (error) return error;
	    }
	    
	    /* Oops. */
	    else {
                kmo_seterror("%s: %s", err_str, get_ssl_error_string(error));
                knp_query_handle_conn_error(query, KMO_SERROR_MISC);
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

static int ksock_get_host_addr_list(char *host, unsigned long *addr_array, int *nb_addr) {
    /* Resolve the server address. */
    struct hostent *he = gethostbyname(host);   
    int i = 0;
    
    if (he == NULL) {
    	kmo_seterror("cannot resolve %s", host);
	return -1;
    }
    
    /* Copy the addresses. */
    while (he->h_addr_list[i] && i < *nb_addr) {
	addr_array[i] = ((struct in_addr *) (he->h_addr_list[i]))->s_addr;
	i++;
    }
    
    assert(i);
    *nb_addr = i;
    return 0;
}

#ifdef __UNIX__
/* BACKPORT.
 *
 * There exist a port of ADNS 1.0 to Windows. But the author of ADNS didn't merge
 * the bloody port in version 1.2. I spent 1.5 days trying to get this shitty
 * library to work on Windows, to no avail. So I'm using the Windows API.
 */
 
/* This function resolves the srv name specified and copies the addresses and
 * ports found to 'addr_array' and 'port_array'. Up to '*nb_addr' addresses and
 * ports will be copied. On success, '*nb_addr' is set to the number of
 * addresses actually copied. This function returns -1 on failure, 0 on success.
 */
static int knp_query_resolve_srv_name(char *srv_name, unsigned long *addr_array, unsigned int *port_array,
				      int *nb_addr) {
    int error = 0;
    adns_state state;
    adns_answer *answer = NULL;
    
    /* Try. */
    do {
	int r;
	int i, j;
	int nb_out = 0;
	
	/* Initialize the ADNS state. */
	r = adns_init(&state, 0, NULL);
	if (r) {
	    kmo_seterror("cannot resolve %s: %s", srv_name, kmo_syserror(r));
	    error = -1;
	    state = NULL; /* Don't call adns_finish(): ADNS sucks. */
	    break;
	}
	
	/* Perform the query. */
	r = adns_synchronous(state, srv_name, adns_r_srv, 0, &answer);
	if (r) {
	    kmo_seterror("cannot resolve %s: %s", srv_name, kmo_syserror(r));
	    error = -1;
	    break;
	}
	
	/* The query failed. */
	if (answer->status != adns_s_ok) {
	    kmo_seterror("cannot resolve %s: %s", srv_name, adns_strerror(answer->status));
	    error = -1;
	    break;
	}
	
	/* We got the results. */
	for (i = 0; i < answer->nrrs; i++) {
	    unsigned int port = answer->rrs.srvha[i].port;
	    
	    /* No addresses returned so resolve the SRV host name. */
	    if (! answer->rrs.srvha[i].ha.naddrs) {
		int nb = *nb_addr - nb_out;
		
                /* Ignore errors, since it's likely the DNS that's badly
                 * configured if this function fails.
                 */
		if (ksock_get_host_addr_list(answer->rrs.srvha[i].ha.host, addr_array + nb_out, &nb)) {
		    continue;
		}
		
		for (j = 0; j < nb; j++) {
		    port_array[nb_out + j] = port;
		}
		
		nb_out += nb;
	    }
	    
	    /* Use the returned addresses. */
	    else {
		for (j = 0; j < answer->rrs.srvha[i].ha.naddrs; j++) {
		    unsigned long addr = answer->rrs.srvha[i].ha.addrs[j].addr.inet.sin_addr.s_addr;
		    
		    if (nb_out == *nb_addr) {
			goto out;
		    }
		    
		    addr_array[nb_out] = addr;
		    port_array[nb_out] = port;
		    nb_out++;
		}
	    }
	}
	
	out:
	
	*nb_addr = nb_out;
	
	if (nb_out == 0) {
	    kmo_seterror("cannot resolve %s: no addresses found for service", srv_name);
	    error = -1;
	    break;
	}
	
    } while (0);
    
    free(answer);
    adns_finish(state);
    
    return error;
}
#else

/* Sort function for knp_query_resolve_srv_name(). */
static int srv_entry_sort(DNS_SRV_DATA **key_1, DNS_SRV_DATA **key_2) {
    if ((*key_1)->wPriority > (*key_2)->wPriority) return -1;
    if ((*key_1)->wPriority < (*key_2)->wPriority) return 1;
    return 0;
}

static int knp_query_resolve_srv_name(char *srv_name, unsigned long *addr_array, unsigned int *port_array,
				      int *nb_addr) {
    int error;
    int i, j;
    int used_addr = 0;
    PDNS_RECORD record_list = NULL;
    PDNS_RECORD record;
    karray srv_array;
    
    kmod_log_msg(3, "knp_query_resolve_srv_name() called.\n");
    
    karray_init(&srv_array);
    
    /* Try. */
    do {
	/* Ask Windows to resolve that. */
	error = DnsQuery_A(srv_name, 33, DNS_QUERY_STANDARD, NULL, &record_list, NULL);
	
	if (error) {
            /* No easy way to get the error string? Screw it! */
	    kmo_seterror("cannot resolve %s (error %d)", srv_name, error);
	    error = -1;
	    break;
	}
	
	/* We got the data. */
	record = record_list;
	
        /* Not using constant names since they're not all defined in my
         * environment.
         */
	while (record) {
	    
            /* 1 = DNS_TYPE_A. Resolved address. Ignore. We can't depend on it
             * being set.
             */
	    if (record->wType == 1) {
                /* void */
	    }
	    
	    /* 33 = DNS_TYPE_SRV. SRV entry. */
	    else if (record->wType == 33) {
		karray_add(&srv_array, &record->Data.SRV);
	    }
	    
	    else {
		kmo_seterror("cannot resolve %s (received unexpected DNS entry of type %d)", srv_name, record->wType);
		error = -1;
		break;
	    }
	    
	    record = record->pNext;
	}
	
	if (error) break;
	
	if (! srv_array.size) {
	    kmo_seterror("cannot resolve %s: no addresses returned", srv_name);
	    error = -1;
	    break;
	}
	
	/* Sort the SRV array. */
	qsort(srv_array.data, srv_array.size, sizeof(void *), (int (*)(const void *, const void *)) srv_entry_sort);
	
	/* Resolve each host. */
	for (i = 0; i < srv_array.size && used_addr < *nb_addr; i++) {
	    DNS_SRV_DATA *srv = (DNS_SRV_DATA *) srv_array.data[i];
	    int nb = *nb_addr - used_addr;
	    
	    error = ksock_get_host_addr_list(srv->pNameTarget, addr_array + used_addr, &nb);
	    if (error) {
		error = 0;
		continue;
	    }
	    
	    for (j = 0; j < nb; j++) {
		port_array[used_addr + j] = srv->wPort;
	    }
	    
	    used_addr += nb;
	}
	
    } while (0);
    
    /* Great API MS! Keep it up! */
    if (record_list) DnsRecordListFree(record_list, DnsFreeRecordList);
    
    karray_free(&srv_array);
    
    *nb_addr = used_addr;
    return error;
}
#endif

/* BACKPORT.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int knp_query_srv_connect(struct knp_query *self, struct knp_proto *knp, char *srv_name) {
    int error = 0;
    int i;
    int nb_addr = 4;
    unsigned long addr_array[4];
    unsigned int port_array[4];
    struct kmo_data_transfer *transfer = &self->transfer;
    
    kmod_log_msg(3, "knp_query_srv_connect() called.\n");
    
    /* Resolve srv name. */
    if (knp_query_resolve_srv_name(srv_name, addr_array, port_array, &nb_addr)) {
	knp_query_handle_conn_error(self, KMO_SERROR_UNREACHABLE);
	return -1;
    }
    
    /* Try to connect with each address. */
    for (i = 0; i < nb_addr; i++) {
	int has_more = (i < nb_addr - 1);
	char addr_str[100];
	char reason_str[200];
	
	/* inet_ntoa(): why make an API simple when you just screw up. */
	sprintf(addr_str, "%s", inet_ntoa(*(struct in_addr*) &addr_array[i]));
	sprintf(reason_str, "cannot connect to %s", addr_str);
	
	kmo_sock_close(&transfer->fd);
	
	error = kmo_sock_create(&transfer->fd);
	if (error) break;
	
	error = kmo_sock_set_unblocking(transfer->fd);
	if (error) break;
	    
	error = kmo_sock_connect(transfer->fd, addr_str, port_array[i]);
	if (error) {
	    if (has_more) continue;
	    knp_query_handle_conn_error(self, KMO_SERROR_UNREACHABLE);
	    return -1;
	}
	
	error = knp_query_wait_for_data(self, 0, reason_str, knp->k3p);
	if (error) {
	    if (error == -1) {
		if (has_more) continue;
		self->serv_error_id = KMO_SERROR_UNREACHABLE;
	    }
	    
	    return error;
	}
    	
	error = kmo_sock_connect_check(transfer->fd, addr_str);
	if (error) {
	    if (has_more) continue;
	    knp_query_handle_conn_error(self, KMO_SERROR_UNREACHABLE);
	    return -1;
	}
	
	return 0;
    }
    
    assert(0);
    return -1;
}

/* This function connects to the specified server (possibly through a proxy) and
 * negociates a SSL session. REMARK: a backport was applied to this function. It
 * was ugly in the first place, the backport didn't help any. All of it is
 * rewritten in the next version. REMARK 2: whooops, modified it again. It's
 * getting prettier by the minute.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int knp_query_connect(struct knp_query *self, struct knp_proto *knp) {
    assert(self->transfer.fd == -1);
    assert(self->ssl_driver == NULL);
    
    kmod_log_msg(3, "knp_query_connect() called.\n");
    
    int error = 0;
    kstr str;
    int use_srv = 0;
    int use_proxy = 0;
    kstr proxy_addr;
    uint32_t proxy_port = 0;
    kstr proxy_login;
    kstr proxy_pwd;
    char *cert = NULL;
    struct kmo_data_transfer *transfer = &self->transfer;
    
    kstr_init(&str);
    kstr_init(&proxy_addr);
    kstr_init(&proxy_login);
    kstr_init(&proxy_pwd);
    
    /* Try. */
    do {
	/* We're contacting the KPS. */
	if (self->contact == KNP_CONTACT_KPS && k3p_is_using_kps(knp->server_info)) {
	    kstr_assign_kstr(&self->server_addr, &knp->server_info->kps_net_addr);
	    self->server_port = knp->server_info->kps_port_num;
	    
	    if (knp->server_info->kps_use_proxy) {
	    	use_proxy = 1;
	    	kstr_assign_kstr(&proxy_addr, &knp->server_info->kps_proxy_net_addr);
		proxy_port = knp->server_info->kps_proxy_port_num;
		kstr_assign_kstr(&proxy_login, &knp->server_info->kps_proxy_login);
		kstr_assign_kstr(&proxy_pwd, &knp->server_info->kps_proxy_pwd);
	    }
	}
	
	/* We're contacting the KOS. */
	else {
	    #ifdef __DEBUG_KOS_ADDRESS__
	    kstr_assign_cstr(&self->server_addr, __DEBUG_KOS_ADDRESS__);
	    if (ops_address || ous_address || ots_address || iks_address || eks_address) {}
	    #else
	    
	    if (knp->server_info->kos_use_proxy || knp->use_kpg) {
		switch (self->contact) {
		    case KNP_CONTACT_KPS: kstr_assign_cstr(&self->server_addr, ops_address); break;
		    case KNP_CONTACT_OPS: kstr_assign_cstr(&self->server_addr, ops_address); break;
		    case KNP_CONTACT_OUS: kstr_assign_cstr(&self->server_addr, ous_address); break;
		    case KNP_CONTACT_OTS: kstr_assign_cstr(&self->server_addr, ots_address); break;
		    case KNP_CONTACT_IKS: kstr_assign_cstr(&self->server_addr, iks_address); break;
		    case KNP_CONTACT_EKS: kstr_assign_cstr(&self->server_addr, eks_address); break;
		    default: assert(0);
		};
		
		if (knp->use_kpg) {
		    switch (self->contact) {
			case KNP_CONTACT_OPS: kstr_assign_cstr(&self->server_addr, knp->kpg_addr.data); break;
			case KNP_CONTACT_OUS: kstr_assign_cstr(&self->server_addr, knp->kpg_addr.data); break;
			case KNP_CONTACT_OTS: kstr_assign_cstr(&self->server_addr, knp->kpg_addr.data); break;
		    };
		}
	    }
	    
	    else {
		use_srv = 1;
		
		switch (self->contact) {
		    case KNP_CONTACT_KPS: kstr_assign_cstr(&self->server_addr, srv_ops_address); break;
		    case KNP_CONTACT_OPS: kstr_assign_cstr(&self->server_addr, srv_ops_address); break;
		    case KNP_CONTACT_OUS: kstr_assign_cstr(&self->server_addr, srv_ous_address); break;
		    case KNP_CONTACT_OTS: kstr_assign_cstr(&self->server_addr, srv_ots_address); break;
		    case KNP_CONTACT_IKS: kstr_assign_cstr(&self->server_addr, srv_iks_address); break;
		    case KNP_CONTACT_EKS: kstr_assign_cstr(&self->server_addr, srv_eks_address); break;
		    default: assert(0);
		};
	    }
	    #endif
	    
	    #ifdef __DEBUG_KOS_PORT__
	    self->server_port = __DEBUG_KOS_PORT__;
	    if (kos_port) {}
	    #else
	    self->server_port = kos_port;
	    
	    if (knp->use_kpg) {
		switch (self->contact) {
		    case KNP_CONTACT_OPS: self->server_port = knp->kpg_port; break;
		    case KNP_CONTACT_OUS: self->server_port = knp->kpg_port; break;
		    case KNP_CONTACT_OTS: self->server_port = knp->kpg_port; break;
		};
	    }
	    #endif
	    
	    if (knp->server_info->kos_use_proxy) {
	    	use_proxy = 1;
	    	kstr_assign_kstr(&proxy_addr, &knp->server_info->kos_proxy_net_addr);
		proxy_port = knp->server_info->kos_proxy_port_num;
		kstr_assign_kstr(&proxy_login, &knp->server_info->kos_proxy_login);
		kstr_assign_kstr(&proxy_pwd, &knp->server_info->kos_proxy_pwd);
	    }
	    
	    #ifdef NDEBUG
	    cert = kos_cert;
	    #else
	    if (kos_cert) {}
	    #endif
	}
	
	/* Validate our contact information. */
	if (self->server_addr.slen == 0 || self->server_port == 0) {
	    kmo_seterror("invalid server information");
    	    knp_query_handle_conn_error(self, KMO_SERROR_MISC);
	    error = -1;
    	    break;
	}
	
	if (use_proxy && (proxy_addr.slen == 0 || proxy_port == 0)) {
	    kmo_seterror("invalid proxy information");
    	    knp_query_handle_conn_error(self, KMO_SERROR_MISC);
	    error = -1;
	    break;
	}
    	
	/* Connect to the proxy or the end server directly. */
	if (! use_srv) {
	    error = kmo_sock_create(&transfer->fd);
	    if (error) break;
	
	    error = kmo_sock_set_unblocking(transfer->fd);
	    if (error) break;
	
	    error = kmo_sock_connect(transfer->fd, 
				     use_proxy ? proxy_addr.data : self->server_addr.data,
				     use_proxy ? proxy_port : self->server_port);
	    if (error) {
		knp_query_handle_conn_error(self, KMO_SERROR_UNREACHABLE);
		break;
	    }
	    
	    kstr_sf(&str, "cannot connect to %s", use_proxy ? proxy_addr.data : self->server_addr.data);
	    error = knp_query_wait_for_data(self, 0, str.data, knp->k3p);
	    
	    if (error) {
		if (error == -1) self->serv_error_id = KMO_SERROR_UNREACHABLE;
		break;
	    }
	    
	    error = kmo_sock_connect_check(transfer->fd, use_proxy ? proxy_addr.data : self->server_addr.data);
	    
	    if (error) {
		knp_query_handle_conn_error(self, KMO_SERROR_UNREACHABLE);
		break;
	    }
	    
	    /* If there is a proxy, asks it to connect us to the end server. */
	    if (use_proxy) {
		error = knp_handle_proxy(self, knp->k3p, &proxy_login, &proxy_pwd);
		if (error) break;
	    }
	}
	
	/* Connect using the SRV entries. */
	else {
	    error = knp_query_srv_connect(self, knp, self->server_addr.data);
	    if (error) break;
	}
	
	/* Negociate the SSL session. */
	error = knp_negociate_ssl_session(self, cert, knp->k3p);
	if (error) break;
	
    } while (0);
    
    if (error) knp_query_disconnect(self);
    
    kstr_free(&str);
    kstr_free(&proxy_addr);
    kstr_free(&proxy_login);
    kstr_free(&proxy_pwd);
    
    return error;
}

/* This function logs the content of a message that is sent / received from the
 * network.
 */
static void knp_log_msg(char *side, uint32_t major, uint32_t minor, uint32_t msg_type, kbuffer *payload,
    	    	    	kstr *addr, uint32_t port) {
    assert(knp_log);
    int error = 0;
    kstr dump;

    kstr_init(&dump);
    error = knp_msg_dump(payload->data, payload->len, &dump);

    if (error) {
	fprintf(knp_log, "%s: badly formatted payload: %s.\n", side, kmo_strerror());
	fwrite(payload->data, 1, payload->len, knp_log);
    }

    else {
    	int cat = (msg_type & 0xff00) >> 8;
	int id = msg_type & 0xff;
    
	fprintf(knp_log, "%s version=%u,%u type=%u,%u len=%u address=%s port=%u>\n",
	    	side, major, minor, cat, id, payload->len, addr->data, port);
	fwrite(dump.data, 1, dump.slen, knp_log);
    }

    fprintf(knp_log, "\n");
    kstr_free(&dump);
}

/* This function sends a message to the server.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int knp_query_send_msg(struct knp_query *query, uint32_t msg_type, kbuffer *payload, k3p_proto *k3p) {
    int error = 0;
    kbuffer msg;
    kbuffer_init(&msg, 100);
    
    kmod_log_msg(3, "knp_query_send_msg() called.\n");
    
    /* Try. */
    do {
	/* Validate the payload size. */
	if (payload->len > KNP_MAX_PAYLOAD_SIZE) {
	    kmo_seterror("outgoing KNP message is too big (%d bytes)", payload->len);
	    error = -1;
	    break;
	}

	/* Send the message. */
	kbuffer_write32(&msg, KNP_MAJOR_VERSION);
	kbuffer_write32(&msg, KNP_MINOR_VERSION);
	kbuffer_write32(&msg, msg_type);
	kbuffer_write32(&msg, payload->len);
	kbuffer_write(&msg, payload->data, payload->len);

	if (knp_log) {
	    knp_log_msg("INPUT", KNP_MAJOR_VERSION, KNP_MINOR_VERSION, msg_type, payload,
    	                &query->server_addr, query->server_port);
	}

	error = knp_query_ssl_transfer(query, 0, msg.data, msg.len, "cannot send KNP message", k3p);
	if (error) break;
	
    } while (0);
    
    if (error) knp_query_disconnect(query);
    kbuffer_clean(&msg);
    
    return error;
}

/* This function receives a message from the server.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int knp_query_recv_msg(struct knp_query *query, uint32_t *msg_type, kbuffer *payload, k3p_proto *k3p) {
    int error = 0;
    uint32_t header_len = 4*4;
    uint32_t major, minor;
    uint32_t payload_size;
    
    kmod_log_msg(3, "knp_query_recv_msg() called.\n");
    
    /* Try. */
    do {
	/* Receive the message header (using the payload buffer temporarily). */
        kbuffer_clear(payload);
	error = knp_query_ssl_transfer(query, 1, kbuffer_append_nbytes(payload, header_len), header_len,
	    	    	    	       "cannot receive KNP message", k3p);
	if (error) break;

	major = kbuffer_read32(payload);
	minor = kbuffer_read32(payload);
	*msg_type = kbuffer_read32(payload);

	payload_size = kbuffer_read32(payload);
	
	/* The KOS should always reply to us with our expected version number.
	 * The KPS might reply with an earlier version. In this version we
	 * don't need to validate the version numbers, the servers will tell
	 * us if something is wrong.
	 */
	 
	/* Validate the message type magic number. */
	if ((*msg_type & 0xffff0000) != KNP_MAGIC_NUMBER) {
    	    kmo_seterror("cannot receive KNP message: invalid magic number");
	    error = -1;
	    break;
	}

	/* Validate the payload size. */
	if (payload_size > KNP_MAX_PAYLOAD_SIZE) {
	    kmo_seterror("incoming KNP message is too big (%d bytes)", payload->len);
	    error = -1;
	    break;
	}

	/* Receive the payload. */
        kbuffer_clear(payload);
	error = knp_query_ssl_transfer(query, 1, kbuffer_append_nbytes(payload, payload_size), payload_size, 
	    	    	    	       "cannot receive KNP message", k3p);
	if (error) break;
    	
	if (knp_log) {
	    knp_log_msg("OUTPUT", major, minor, *msg_type, payload, &query->server_addr, query->server_port); 
	}
    
    } while (0);
    
    if (error) knp_query_disconnect(query);
    
    return error;
}

/* This function executes a server query. The function expects that the server
 * info have been set. Furthermore, it expects that there is something to do,
 * i.e. login and/or perform a query. If the function manages to login to the
 * server, the connection is not closed until the query is destroyed or the
 * connection is lost. It is possible to execute another query to the server by
 * calling knp_query_set_cmd() (still unimplemented since it's not needed ATM).
 * This function sets the KMO error string. It returns 0, -2, or -3.
 */
int knp_query_exec(struct knp_query *self, struct knp_proto *knp) {
    kmod_log_msg(3, "knp_query_exec() called.\n");

    assert(knp != NULL);
    assert(knp->k3p != NULL);
    assert(knp->k3p->state == K3P_INTERACTING);
    assert(knp->k3p->transfer.fd != -1);
    assert(knp->server_info != NULL);
    assert(self->transfer.fd == -1 || self->cmd_type);
    assert(self->res_type == 0);
    assert(self->res_payload == NULL);
    assert(self->serv_error_msg == NULL);
    
    int error = 0;
    uint32_t msg_type;
    
    /* The local payload is used to transfer the data of the messages. It may
     * eventually become the result payload of the query.
     */
    kbuffer *local_payload = kbuffer_new(1024);
    
    /* Set the operation timeout. */
    self->transfer.op_timeout = knp->timeout;

     /* Try. */
    do {
	/* If we're not connected, connect to the server. */
	if (self->transfer.fd == -1) {
    	    error = knp_query_connect(self, knp);
	    if (error) break;
	    
	    /* Do login. */
	    if (self->login_type != KNP_CMD_LOGIN_ANON) {
	    	
		/* Write the login message. */
		if (self->login_type == KNP_CMD_LOGIN_USER) {
	    	    knp_msg_write_kstr(local_payload, &knp->server_info->kps_login);
		    knp_msg_write_kstr(local_payload, &knp->server_info->kps_pwd);
		    knp_msg_write_uint32(local_payload, knp->server_info->encrypted_pwd_flag);
		}

		else {
	    	    assert(self->login_type == KNP_CMD_LOGIN_OTUT);
		    assert(self->login_otut != NULL);
		    knp_msg_write_kstr(local_payload, self->login_otut);
		}

		/* Send the login message. */
    		error = knp_query_send_msg(self, self->login_type, local_payload, knp->k3p);
		if (error) break;

		/* Receive the reply. */
		error = knp_query_recv_msg(self, &msg_type, local_payload, knp->k3p);
		if (error) break;

		/* Upgrade required. */
		if (msg_type == KNP_RES_UPGRADE_PLUGIN || msg_type == KNP_RES_UPGRADE_KPS) {
		    knp_query_disconnect(self);
		    self->res_type = msg_type;
		    error = 0;
		    break;
		}
		
		/* Login failed. There are two cases here. If we were only doing a login
		 * to the server, the result type is the error returned by the server.
		 * Otherwise, we set the result type to 'KNP_RES_LOGIN_ERROR', to allow
		 * the caller to distinguish between a login failure and the command
		 * failure. The semantics here are pretty messy :-/.
		 */
		if (msg_type != KNP_RES_LOGIN_OK) {
		    knp_query_disconnect(self);
		    
		    if (self->cmd_type)
		    	self->res_type = KNP_RES_LOGIN_ERROR;
		    else
		    	self->res_type = msg_type;
		    
		    error = -1;
		    break;
		}
		
		/* Assign the result message type and payload to the query. */
		self->res_type = msg_type;
		self->res_payload = local_payload;
	    }
	}
	
	/* If there is a command, process it. */
	if (self->cmd_type) {
	    assert(self->cmd_payload);
	    
	    /* Clear the result message type and payload, if any. */
	    self->res_type = 0;
	    self->res_payload = NULL;
	    
	    /* Send the command message. */
	    error = knp_query_send_msg(self, self->cmd_type, self->cmd_payload, knp->k3p);
	    if (error) break;

	    /* Receive the result. */
	    error = knp_query_recv_msg(self, &msg_type, local_payload, knp->k3p);
	    if (error) break;
	
	    /* Assign the result message type and payload to the query. */
	    self->res_type = msg_type;
	    self->res_payload = local_payload;
	}
	
    } while (0);
    
    /* A miscellaneous error occured. */
    if (error == -1) {
    	
	/* We did not handle the error yet. Convert it to a server error. */
    	if (! self->res_type) {
	    knp_query_handle_conn_error(self, KMO_SERROR_MISC);
	}
	
	/* It's handled. */
	error = 0;
    }
    
    /* Destroy the local buffer, if it did not become the result payload. */
    if (self->res_payload != local_payload)
    	kbuffer_destroy(local_payload);
    
    assert((self->res_type && ! error) || (! self->res_type && (error == -2 || error == -3)));
    return error;
}


/* KNP message buffer processing functions. */

/* This function adds a 32 bit unsigned integer to the buffer. */
void knp_msg_write_uint32(kbuffer *buf, uint32_t i) {
    kbuffer_write8(buf, KNP_UINT32);
    kbuffer_write32(buf, i);
}

/* This function adds a 64 bit unsigned integer to the buffer. */
void knp_msg_write_uint64(kbuffer *buf, uint64_t i) {
    kbuffer_write8(buf, KNP_UINT64);
    kbuffer_write64(buf, i);
}

/* This function adds a kstr to the buffer. */
void knp_msg_write_kstr(kbuffer *buf, kstr *str) {
    kbuffer_write8(buf, KNP_STR);
    kbuffer_write32(buf, str->slen);
    kbuffer_write(buf, str->data, str->slen);
}

/* This function adds a C string to the buffer. */
void knp_msg_write_cstr(kbuffer *buf, char *str) {
    int len = strlen(str);
    kbuffer_write8(buf, KNP_STR);
    kbuffer_write32(buf, len);
    kbuffer_write(buf, str, len);
}

/* This function reads a 32 bit unsigned integer from the buffer.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int knp_msg_read_uint32(kbuffer *buf, uint32_t *i) {
    if (! knp_can_read_bytes(buf, 5) || kbuffer_read8(buf) != KNP_UINT32) {
    	kmo_seterror("cannot read uint32 value in message");
    	return -1;
    }
    
    *i = kbuffer_read32(buf);
    return 0;
}

/* This function reads a 64 bit unsigned integer from the buffer.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int knp_msg_read_uint64(kbuffer *buf, uint64_t *i) {
    if (! knp_can_read_bytes(buf, 9) || kbuffer_read8(buf) != KNP_UINT64) {
    	kmo_seterror("cannot read uint64 value in message");
    	return -1;
    }
    
    *i = kbuffer_read64(buf);
    return 0;
}

/* This function reads a kstr from the buffer.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int knp_msg_read_kstr(kbuffer *buf, kstr *str) {
    uint32_t len;
    
    if (! knp_can_read_bytes(buf, 5) || kbuffer_read8(buf) != KNP_STR) {
    	kmo_seterror("cannot read string value in message");
    	return -1;
    }
    
    len = kbuffer_read32(buf);
    
    if (! knp_can_read_bytes(buf, len)) {
    	kmo_seterror("cannot read string value in message");
	return -1;
    }
    
    kstr_grow(str, len);
    kbuffer_read(buf, str->data, len);
    str->data[len] = 0;
    str->slen = len;
    return 0;
}

/* This function reads a kpstr from the buffer.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int knp_msg_read_kpstr(kbuffer *buf, kpstr *str) {
    uint32_t len;
    
    if (! knp_can_read_bytes(buf, 5) || kbuffer_read8(buf) != KNP_STR) {
    	kmo_seterror("cannot read string value in message");
    	return -1;
    }
    
    len = kbuffer_read32(buf);
    
    if (! knp_can_read_bytes(buf, len)) {
    	kmo_seterror("cannot read string value in message");
	return -1;
    }
    
    str->data = kmo_malloc(len);
    str->length = len;
    kbuffer_read(buf, str->data, len);
    return 0;
}

/* This function returns true if it is possible to read 'nb' bytes from the
 * buffer.
 */
int knp_can_read_bytes(kbuffer *buf, uint32_t nb) {
    return (buf->pos + nb <= buf->len);
}

/* This function dumps the content of a KNP message buffer in the string
 * specified. This function sets the KMO error string when it encounters an
 * error in the buffer. It returns -1 on failure.
 */
int knp_msg_dump(char *buf, int buf_len, kstr *dump_str) {
    
    int error = 0;
    int pos = 0;
    uint32_t u32;
    uint64_t u64;
    kstr work_str;
    
    kstr_init(&work_str);
    kstr_clear(dump_str);

    while (pos < buf_len) {
    	
	uint8_t type = buf[pos];
    	pos++;
	
	if (type == KNP_UINT32) {
	    if (pos + 4 > buf_len) {
	    	kmo_seterror("uint32 specified but not included");
		error = -1;
		break;
	    }
	    
	    memcpy(&u32, buf + pos, 4);
	    kstr_sf(&work_str, "uint32> %u\n", ntohl(u32));
	    kstr_append_kstr(dump_str, &work_str);
	    pos += 4;
	}
	
	else if (type == KNP_UINT64) {
	    if (pos + 8 > buf_len) {
	    	kmo_seterror("uint64 specified but not included");
		error = -1;
		break;
	    }
	    
	    memcpy(&u64, buf + pos, 8);
	    kstr_sf(&work_str, "uint64> %llu\n", ntohll(u64));
	    kstr_append_kstr(dump_str, &work_str);
	    pos += 8;
	}
	
	else if (type == KNP_STR) {
	    if (pos + 4 > buf_len) {
	    	kmo_seterror("string specified but not included");
		error = -1;
		break;
	    }
	
	    memcpy(&u32, buf + pos, 4);
	    pos += 4;
	    u32 = ntohl(u32);
	    
	    if (pos + u32 > (uint32_t) buf_len) {
	    	kmo_seterror("string specified but not included");
		error = -1;
		break;
	    }
	    
	    kstr_sf(&work_str, "string %u> ", u32);
	    kstr_append_kstr(dump_str, &work_str);
	    kstr_append_buf(dump_str, buf + pos, u32);
	    kstr_append_cstr(dump_str, "\n");
	    pos += u32;
	}
	
	else {
	    kmo_seterror("invalid KNP identifier (%u)", type);
	    error = -1;
	    break;
	}
    }
    
    kstr_free(&work_str);
    return error;
}
