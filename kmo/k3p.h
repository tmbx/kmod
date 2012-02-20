/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

#ifndef _K3P_H
#define _K3P_H

#include "kmo_base.h"
#include "kmo_comm.h"
#include "kbuffer.h"
#include "k3p_core_defs.h"

/* State of the protocol. */
enum {
    /* K3P protocol has been initialized (initial state). Do not transfer
     * K3P elements in this state.
     */
    K3P_INITIALIZED,

    /* Connection is active, i.e waiting for one of KPP_CONNECT_KMO,
     * KPP_DISCONNECT_KMO or KPP_BEG_SESSION.
     */
    K3P_ACTIVE,

    /* Connection is interactive, i.e. waiting for commands that can
     * happen after KPP_BEG_SESSION.
     */
    K3P_INTERACTING,

    /* Connection to the plugin has been lost and has not been cleaned up
     * yet. After clean up, the state becomes K3P_INITIALIZED. Note:
     * KMOD is expected to disconnect from the plugin as soon as an error
     * occur at the protocol level. This state indicates that an error
     * occurred, that the connection has been closed, and that a high-level
     * routine is expected to clean up eventually.
     */
    K3P_DISCONNECTED
};

/* Type of data elements. */
enum {
    /* Instruction. */
    K3P_EL_INS,
    
    /* Integer. */
    K3P_EL_INT,
    
    /* String. */
    K3P_EL_STR
};

/* K3P data element. */
struct k3p_element {
    
    /* Type of element. */
    int type;
    
    /* Instruction or integer value, if applicable, or the string length. */
    uint32_t value;
    
    /* String data, if applicable. */
    char *str;
};

/* This object handles the communication between the plugin and KMOD through
 * the K3P protocol.
 */
typedef struct k3p_proto {
    
    /* State of the protocol. */
    int state;

    /* True if the timeout is currently used. */
    int timeout_enabled;

    /* Time to wait for the other side, in milliseconds. */
    uint32_t timeout;
    
    /* Array of incoming K3P elements. */
    karray element_array;
    
    /* Read position in the element array. We do not add new elements in the
     * array until all elements have been consumed.
     */
    int element_array_pos;
    
    /* Data buffer. When receiving, this buffer contains the data received from
     * the remote side that is being converted to K3P elements (in
     * element_array). When sending, this buffer contains the data to send to
     * the remote side. It is an error to use this buffer to send data when it
     * is already used to contain data being converted to K3P elements, or
     * vice-versa. The size of this buffer is shrunk after each transfer
     * operation.
     */
    kbuffer data_buf;
    
    /* This object describes the current transfer operation. */
    struct kmo_data_transfer transfer;
    
    /* Pointer to the transfer hub. */
    struct kmo_transfer_hub *hub;
} k3p_proto;

/* K3P structures used internally by KMO. These structures are easier to work
 * with than the structures defined in k3p_core_defs.
 */
struct kmod_mail_body {
        uint32_t type;
        kstr text;
        kstr html;
};

struct kmod_mail_attachment {
        uint32_t tie;
        uint32_t data_is_file_path;     
        kstr data;     	
	kstr name; 	
	kstr encoding;
	kstr mime_type;
};

struct kmod_otut {
    	uint32_t status;
	kstr entry_id;    	
	kstr reply_addr;	
	kstr msg;	    	
};

struct kmod_mail {
        kstr msg_id;       
	kstr recipient_list; 
        kstr from_name;
        kstr from_addr;
        kstr to;
        kstr cc;
        kstr subject;
        struct kmod_mail_body body;
        karray attachments;
        struct kmod_otut otut;
};

struct kmod_server_info {
        kstr kps_login;
        kstr kps_pwd;
	uint32_t encrypted_pwd_flag;
	kstr pod_addr;
        kstr kps_net_addr;
        uint32_t kps_port_num;
        kstr kps_ssl_key;
        uint32_t kps_use_proxy;
        kstr kps_proxy_net_addr;
        uint32_t kps_proxy_port_num;
        kstr kps_proxy_login;
        kstr kps_proxy_pwd;
        uint32_t kos_use_proxy;
        kstr kos_proxy_net_addr;
        uint32_t kos_proxy_port_num;
        kstr kos_proxy_login;
        kstr kos_proxy_pwd;
};

struct kmod_mua {
        uint32_t product;
        uint32_t version;
	kstr release;
	uint32_t kmod_major;
	uint32_t kmod_minor;
	uint32_t incoming_attachment_is_file_path;
	uint32_t lang;
};

struct kmod_recipient_pwd {
        kstr recipient;
        kstr password;
        uint32_t give_otut;      
	uint32_t save_pwd;	 
};

struct kmod_mail_process_req {
        struct kmod_mail mail;
        uint32_t decrypt;
        kstr decryption_pwd;
	uint32_t save_pwd;
        uint32_t ack_pod;
        kstr recipient_mail_address;
};

struct kmod_tool_info {
        kstr sig_marker;
        kstr kmod_version;
        kstr k3p_version;
};

struct kmod_server_error {
        uint32_t sid;       	    
        uint32_t error;
        kstr message;
};

struct kmod_eval_res_attachment {
	kstr name;	
	uint32_t status;	
};

struct kmod_eval_res {
    	uint32_t display_pref;
        uint32_t string_status;		
	uint32_t sig_valid;             
	kstr sig_msg;  	
        uint32_t original_packaging;    
        kstr subscriber_name;  
        uint32_t from_name_status;
        uint32_t from_addr_status;
        uint32_t to_status;
        uint32_t cc_status;
        uint32_t subject_status;
        uint32_t body_text_status;
        uint32_t body_html_status;
        karray attachments;
        uint32_t encryption_status; 
        kstr decryption_error_msg; 
	kstr default_pwd;  
        uint32_t pod_status;
        kstr pod_msg;  
	struct kmod_otut otut;  
};

/* Info about the attachments received/sent to the plugin. This is a catch-all
 * structure used in several places for different purposes.
 */
struct kmod_attachment {

    /* Type of attachment. Using K3P constants, with 0 for uninitialized. */
    int tie;
    
    /* Status (using K3P constants, with 0 for uninitialized). */
    int status;
    
    /* Attachment data. */
    kstr *data;
    
    /* Attachment name. */
    kstr *name;
    
    /* Attachment encoding. */
    kstr *encoding;
    
    /* Attachment mime type. */
    kstr *mime_type;
};

void k3p_proto_init(k3p_proto *k3p);
void k3p_proto_free(k3p_proto *k3p);
void k3p_proto_disconnect(k3p_proto *k3p);
int k3p_perform_transfer(k3p_proto *k3p);
int k3p_receive_element(k3p_proto *k3p);
int k3p_read_inst(k3p_proto *k3p, uint32_t *i);
int k3p_read_uint32(k3p_proto *k3p, uint32_t *i);
int k3p_read_kstr(k3p_proto *k3p, kstr *str);
void k3p_write_inst(k3p_proto *k3p, uint32_t i);
void k3p_write_uint32(k3p_proto *k3p, uint32_t i);
void k3p_write_kstr(k3p_proto *k3p, kstr *str);
int k3p_send_data(k3p_proto *k3p);
void k3p_init_mail_body(struct kmod_mail_body *self);
void k3p_free_mail_body(struct kmod_mail_body *self);
int k3p_read_mail_body(k3p_proto *k3p, struct kmod_mail_body *self);
void k3p_write_mail_body(k3p_proto *k3p, struct kmod_mail_body *self);
void k3p_init_mail_attachment(struct kmod_mail_attachment *self);
void k3p_free_mail_attachment(struct kmod_mail_attachment *self);
int k3p_read_mail_attachment(k3p_proto *k3p, struct kmod_mail_attachment *self);
void k3p_write_mail_attachment(k3p_proto *k3p, struct kmod_mail_attachment *self);
void k3p_init_otut(struct kmod_otut *self);
void k3p_free_otut(struct kmod_otut *self);
int k3p_read_otut(k3p_proto *k3p, struct kmod_otut *self);
void k3p_write_otut(k3p_proto *k3p, struct kmod_otut *self);
void k3p_init_mail(struct kmod_mail *self);
void k3p_free_mail(struct kmod_mail *self);
int k3p_read_mail(k3p_proto *k3p, struct kmod_mail *self);
void k3p_write_mail(k3p_proto *k3p, struct kmod_mail *self);
void k3p_init_server_info(struct kmod_server_info *self);
void k3p_free_server_info(struct kmod_server_info *self);
int k3p_read_server_info(k3p_proto *k3p, struct kmod_server_info *self);
void k3p_write_server_info(k3p_proto *k3p, struct kmod_server_info *self);
void k3p_init_mua(struct kmod_mua *self);
void k3p_free_mua(struct kmod_mua *self);
int k3p_read_mua(k3p_proto *k3p, struct kmod_mua *self);
void k3p_write_mua(k3p_proto *k3p, struct kmod_mua *self);
void k3p_init_recipient_pwd(struct kmod_recipient_pwd *self);
void k3p_free_recipient_pwd(struct kmod_recipient_pwd *self);
int k3p_read_recipient_pwd(k3p_proto *k3p, struct kmod_recipient_pwd *self);
void k3p_write_recipient_pwd(k3p_proto *k3p, struct kmod_recipient_pwd *self);
void k3p_init_mail_process_req(struct kmod_mail_process_req *self);
void k3p_free_mail_process_req(struct kmod_mail_process_req *self);
int k3p_read_mail_process_req(k3p_proto *k3p, struct kmod_mail_process_req *self);
void k3p_write_mail_process_req(k3p_proto *k3p, struct kmod_mail_process_req *self);
void k3p_init_tool_info(struct kmod_tool_info *self);
void k3p_free_tool_info(struct kmod_tool_info *self);
int k3p_read_tool_info(k3p_proto *k3p, struct kmod_tool_info *self);
void k3p_write_tool_info(k3p_proto *k3p, struct kmod_tool_info *self);
void k3p_init_eval_res_attachment(struct kmod_eval_res_attachment *self);
void k3p_free_eval_res_attachment(struct kmod_eval_res_attachment *self);
void k3p_clear_eval_res(struct kmod_eval_res *self);
int k3p_read_eval_res_attachment(k3p_proto *k3p, struct kmod_eval_res_attachment *self);
void k3p_write_eval_res_attachment(k3p_proto *k3p, struct kmod_eval_res_attachment *self);
void k3p_init_eval_res(struct kmod_eval_res *self);
void k3p_free_eval_res(struct kmod_eval_res *self);
int k3p_read_eval_res(k3p_proto *k3p, struct kmod_eval_res *self);
void k3p_write_eval_res(k3p_proto *k3p, struct kmod_eval_res *self);

/* This function returns true if the server info specified indicates that the
 * user is a Teambox subscriber. 
 */
static inline int k3p_is_a_member(struct kmod_server_info *server_info) {
    return (server_info->kps_login.slen != 0 && server_info->kps_pwd.slen != 0);
}

/* This function returns true if the server info specified indicates that the
 * user is using a KPS.
 */
static inline int k3p_is_using_kps(struct kmod_server_info *server_info) {
    return (k3p_is_a_member(server_info) && server_info->kps_net_addr.slen != 0 && server_info->kps_port_num != 0);
}

/* This function writes a cstr to the remote side.
 * The data is not sent until a send operation is requested.
 */
static inline void k3p_write_cstr(k3p_proto *k3p, char *str) {
    kstr tmp;
    kstr_init_cstr(&tmp, str);
    k3p_write_kstr(k3p, &tmp);
    kstr_free(&tmp);
}

#endif
