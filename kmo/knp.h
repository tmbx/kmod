/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

#ifndef _KNP_H
#define _KNP_H

#include "kmo_base.h"
#include "k3p.h"
#include "knp_core_defs.h"

/* Forward declaration of the KNP SSL driver. */
struct knp_ssl_driver;

/* Kryptiva network protocol handler. */
struct knp_proto {
    	
    /* Operation timeout in milliseconds. 0 for no timeout. */
    uint32_t timeout;
    
    /* K3P protocol handler. */
    k3p_proto *k3p;
    
    /* Current server info. */
    struct kmod_server_info *server_info;
    
    /* True if KPG server should be used. */
    int use_kpg;
    kstr kpg_addr;
    int kpg_port;
};

/* Kryptiva network protocol query. */
struct knp_query {

    /* Server error (e.g. can't contact the server). */
    #define KNP_RES_SERV_ERROR  	    KNP_RES_CAT + 1

    /* Login error (i.e the server refuses to acknowledge us). */
    #define KNP_RES_LOGIN_ERROR     	    KNP_RES_CAT + 2
    
    /* Maximum size of the payload (20 MB). */
    #define KNP_MAX_PAYLOAD_SIZE    	    (20*1024*1024)
    
    /* Server to contact. */
    uint32_t contact;
    
    /* Address of the server to contact. The address is determined when the
     * query is executed (using the server info).
     */
    kstr server_addr;
    
    /* Port of the server to contact. The port is determined when the query
     * is executed (using the server info).
     */
    uint32_t server_port;
    
    /* Login method. */
    uint32_t login_type;
    
    /* OTUT login string, if any. Memory owned by this object. */
    kstr *login_otut;
    
    /* Command type. */
    uint32_t cmd_type;
    
    /* Command payload. Memory not owned by this object. */
    kbuffer *cmd_payload;
    
    /* Result type. If res_type == KNP_RES_SERV_ERROR, the payload is NULL and
     * the error message string is set. If res_type == KNP_RES_LOGIN_OK, the
     * payload is not set. Otherwise, the payload is set.
     */
    uint32_t res_type;
    
    /* Result payload. Memory owned by this object. */
    kbuffer *res_payload;
    
    /* Server error ID (using K3P constants). */
    uint32_t serv_error_id;
    
    /* Server error message. Memory owned by this object. */
    kstr *serv_error_msg;
    
    /* This object describes the current transfer operation. */
    struct kmo_data_transfer transfer;

    /* SSL driver. */
    struct knp_ssl_driver *ssl_driver;
};

struct knp_query * knp_query_new(int contact, int login_type, int cmd_type, kbuffer *cmd_payload);
void knp_query_destroy(struct knp_query *self);
void knp_query_disconnect(struct knp_query *self);
int knp_query_exec(struct knp_query *self, struct knp_proto *knp);
void knp_msg_write_uint32(kbuffer *buf, uint32_t i);
void knp_msg_write_uint64(kbuffer *buf, uint64_t i);
void knp_msg_write_kstr(kbuffer *buf, kstr *str);
void knp_msg_write_cstr(kbuffer *buf, char *str);
int knp_msg_read_uint32(kbuffer *buf, uint32_t *i);
int knp_msg_read_uint64(kbuffer *buf, uint64_t *i);
int knp_msg_read_kstr(kbuffer *buf, kstr *str);
int knp_can_read_bytes(kbuffer *buf, uint32_t nb);
int knp_msg_dump(char *buf, int buf_len, kstr *dump_str);

#endif
