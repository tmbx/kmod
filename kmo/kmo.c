/**
 * kmo/kmo.c
 * Copyright (C) 2005-2012 Opersys inc., All rights reserved.
 *
 * Kryptiva Mail Origin command-line client.
 *
 * @author François-Denis Gonthier
 */

/*
 * TODO: - Make the client connect to an already running kmod.
 */

#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#ifndef __WINDOWS__
#include <termios.h>
#include <error.h>
#endif
#include <unistd.h>

#include "kmo.h"
#include "k3p.h"
#include "k3p_core_defs.h"
#include "k3p_comm.h"
#include "utils.h"
#include "mail.h"

/**
 * Protocol constants that should be defined elsewhere.
 */
#define KMO_MAX_PASSWORD 50
#define KMO_MAX_USERNAME 50

#define OP_LOGIN_ONLY  0x20
#define OP_PROCESS     0x10
#define OP_GET_STATUS  0x40
#define OP_VALIDATE    0x80
#define OP_SIGN        0x01
#define OP_ENCRYPT     0x02
#define OP_POD         0x04

#define MUA_VENDOR    "Teambox"
#define MUA_VERSION   "1.0"
#define MUA_PRODUCT   "KMO"

struct kpp_mua mua_info = 
    { 
        0, // product
        0, // version
        { sizeof(MUA_VERSION) - 1, MUA_VERSION },
        1, // kpp_major
        1, // kpp_minor
        1  // incoming_attachment_is_file_path
    };

struct kmo_tool_info tool_info;

k3p_proto k3p;

const char * msg_link_broken = "KMO/KMOD link broken.";

int keep_silent;

/**
 * This function returns 1 if the mail specified has a HTML body.
 */
int mail_has_html_body(struct k3p_mail *mail) {
    return (mail->body.type == K3P_MAIL_BODY_TYPE_HTML ||
            mail->body.type == K3P_MAIL_BODY_TYPE_TEXT_N_HTML);
}

/**
 * This function returns 1 if the mail specified has a text body.
 */
int mail_has_text_body(struct k3p_mail *mail) {
    return (mail->body.type == K3P_MAIL_BODY_TYPE_TEXT ||
            mail->body.type == K3P_MAIL_BODY_TYPE_TEXT_N_HTML);
}

/**
 * Open connection to kmod.
 */
int kpp_open() {
    uint32_t inst;

    if (k3p_comm_kmo_connect(&k3p) != 0)
        return -1;
    
    /* Send the hello! */
    if (k3p_write_inst(&k3p, KPP_CONNECT_KMO) < 0)
        return -1;

    /* Send the MUA info. */
    if (k3p_write_mua_info(&k3p, &mua_info) < 0)
        return -1;

    /* Wait for news. */
    if (k3p_read_inst(&k3p, &inst) < 0)
        return -1;
    if (inst != KMO_COGITO_ERGO_SUM)
        return -1;

    /* Read the tool infos. */
    if (k3p_read_tool_info(&k3p, &tool_info) < 0)
        return -1;

    return 0;
}

/**
 * Close connection to kmod.
 */
int kpp_close() {
    /* Send the bye bye. */
    k3p_write_inst(&k3p, KPP_DISCONNECT_KMO);
    k3p_comm_disconnect(&k3p);
    return 0;
}

/**
 * Display helpful command line parameter synopsis.
 */
void kpp_print_usage(void) {
    puts("Usage kmo [OPTIONS] \n");
    puts("Operations:");
    puts("   -V      Get the status of a signed message.");
    puts("   -G      Get the previously evaluated status of a mail ID.");
    puts("   -P      Process a mail message.");
    puts("   -S      Sign mail.");
    puts("   -E      Encrypt mail.");
    puts("   -P      Proof-of-Delivery.");
    puts("   -L      Login only.");
    puts("   -I      Show static information provided by KMOD.");
    puts("   -H/-h   Show this help.");
    puts("\nOptions:");
    puts("   -i <message-id>   Message ID to look for.");
    puts("   -s <server-ip>    KPS server address.");
    puts("   -p <port>         KPS server port.");
    puts("   -u <username>     Username for KPS.");
    puts("\nSet the environment variable KPS_PASSWORD to provide KMO the ");
    puts("password otherwise KMO will prompt for it.");
}
	
/**
 * Password input.
 */
int kpp_password_input(const char * prompt, uint8_t * buffer, size_t n) {
    if (!keep_silent) 
        printf((char *)prompt);
	
    /* From GLIBC manual.  Not supported on Windows. */
#ifdef TERMIOS_PWD_INPUT
    struct termios term_old, term_new;
    int nread;
	
    /* Turn echoing off and fail if we can't. */
    if (tcgetattr(0, &term_old) != 0)
        return -1;

    term_new = term_old;
    term_new.c_lflag &= ~ECHO;
    if (tcsetattr(0, TCSAFLUSH, &term_new) != 0)
        return -1;
	
    /* Read the password. */
    nread = getline((void *)&buffer, &n, stdin);
    
    /* Remove the \n */
    buffer[strlen((char *)buffer) - 1] = '\0';

    /* Restore terminal. */
    (void) tcsetattr(0, TCSAFLUSH, &term_old);
	
    return 0;
#else
    /* TODO: Make something more secure here. */

    FILE * conF;

    if ((conF = fopen("CON", "r")) == NULL) 
        return -1;

    n = 0;

    fscanf(conF, "%s", buffer);
    fclose(conF);

    return 0;
#endif
}

/**
 * Validate the content of the server info structure, that is make sure we
 * have the minimum required to attempt the connection.
 */
static int kpp_validate_server_info(struct kpp_server_info * server_info) {
    kmo_clearerror();

    /* Make sure we have all the information we need before
     * login. */
    if (server_info->kps_net_addr.data == NULL) 
        { kmo_seterror("Missing KPS address."); return -1; }
    if (server_info->kps_port_num == 0)
        { kmo_seterror("Missing KPS port."); return -1; }
    if (server_info->kps_login.data == NULL)
        { kmo_seterror("Missing username."); return -1; }
    if (server_info->kps_pwd.data == NULL) 
        { kmo_seterror("Missing password."); return -1; }
	
    /* TODO: Add proxy support. */

    return 0;
}

static int kpp_get_password(struct kpp_server_info * server_info) {
    uint8_t * pwd_str;

    /* Check if we need to input the password and
       do so if required. */
    if (server_info->kps_pwd.data == NULL) {
        server_info->kps_pwd.data = (char *)kmo_malloc(KMO_MAX_PASSWORD);
        pwd_str = (uint8_t *)getenv("KMO_PASSWORD");

        /* Check the environment. */
        if (pwd_str == NULL) {
            if (kpp_password_input("KMO password: ", 
                                   (uint8_t *)server_info->kps_pwd.data, 
                                   KMO_MAX_PASSWORD) != 0)
                return -1;
        } else 
            strncpy(server_info->kps_pwd.data, (char *)pwd_str, KMO_MAX_PASSWORD);
		
        server_info->kps_pwd.length = strlen(server_info->kps_pwd.data);
    }

    return 0;
}

/**
 * Print a k3p_mail structure on a fsource.
 */
static void kpp_write_mail(struct k3p_mail * mail, struct k3p_mail_body * new_body, FILE * ftarget) {
    fprintf(ftarget, "%s\n", mail->msg_id.data);
    fprintf(ftarget, "%s\n", mail->from_name.data);
    fprintf(ftarget, "%s\n", mail->from_addr.data);
    fprintf(ftarget, "%s\n", mail->to.data);
    fprintf(ftarget, "%s\n", mail->cc.data);
    fprintf(ftarget, "%s\n", mail->subject.data);

    fprintf(ftarget, "%d\n", mail->body.type - K3P_MAIL_BODY_TYPE);

    if (new_body->text.length > 0)
        fprintf(ftarget, "%s\n.\n", new_body->text.data);

    if (new_body->html.length > 0)
        fprintf(ftarget, "%s\n.\n", new_body->html.data);
}

/**
 * Read a k3p_mail structure from fsource.
 */
static int kpp_read_mail(struct k3p_mail * mail, FILE * fsource) {
    kstr rcp = { 0, 0, NULL };

    memset(mail, 0, sizeof(struct k3p_mail));

    /* Read the basic fields. */
    if (!keep_silent) printf("Message ID: ");
    if (read_line((char **)&mail->msg_id.data, (size_t *)&mail->msg_id.length, fsource) < 0)
        goto kpp_read_mail_err;
    
    if (!keep_silent) printf("From name: ");
    if (read_line((char **)&mail->from_name.data, (size_t *)&mail->from_name.length, fsource) < 0)
        goto kpp_read_mail_err;

    if (!keep_silent) printf("From address: ");
    if (read_line((char **)&mail->from_addr.data, (size_t *)&mail->from_addr.length, fsource) < 0)
        goto kpp_read_mail_err;

    /* Read the target address. */
    if (!keep_silent) printf("To: ");
    if (read_line((char **)&mail->to.data, (size_t *)&mail->to.length, fsource) < 0)
        goto kpp_read_mail_err;

    if (!keep_silent) printf("CC: ");
    if (read_line((char **)&mail->cc.data, (size_t *)&mail->cc.length, fsource) < 0)
        goto kpp_read_mail_err;

    /* Create the recipient list. */
    if (mail->to.length > 0 || mail->cc.length > 0) {
        /* FIXME: CC and TO are simply appended together. */       
        kstr_init_kpstr(&rcp, &mail->to);
        kstr_append_cstr(&rcp, ";");
        kstr_append_kpstr(&rcp, &mail->cc);        
        
        mail->recipient_list.data = kmo_malloc(rcp.slen);
        mail->recipient_list.length = rcp.slen;
        memcpy(mail->recipient_list.data, rcp.data, rcp.slen);
    }

    if (!keep_silent) printf("Subject: ");
    if (read_line((char **)&mail->subject.data, (size_t *)&mail->subject.length, fsource) < 0)
        goto kpp_read_mail_err;

    /* Read the body type. */
    if (!keep_silent) printf("Body type (1 = text, 2 = html, 3 = both): ");
    fscanf(fsource, "%d", &mail->body.type);
	
    /* Eat the \n */
    getchar();

    mail->body.type += K3P_MAIL_BODY_TYPE;

    if (mail_has_text_body(mail)) {
        if (!keep_silent) printf("Text body (empty line to stop):\n ");
        read_block(&mail->body.text.data, (size_t *)&mail->body.text.length, fsource);
    }

    if (mail_has_html_body(mail)) {
        if (!keep_silent) printf("HTML body (empty line to stop):\n ");
        read_block(&mail->body.html.data, (size_t *)&mail->body.html.length, fsource);
    }

    /* TODO: Attachment support. */
    /* TODO: OTUT support. */
	
    kstr_free(&rcp);

    return 0;

 kpp_read_mail_err:
    k3p_clear_mail(mail);
    return -1;
}

const char * field_changed;
const char * field_intact;
const char * field_absent;

const char * field_val_text[4] = { "WTF!", "ABSENT", "INTACT", "CHANGED" };

static void kpp_print_validity_status(struct kmo_eval_res * er, FILE * ftarget) {
    uint32_t i = 0;

#define VAL2TEXT(X)                                     \
    field_val_text[X - KMO_FIELD_STATUS_MAGIC_NUMBER]
#define BOOL2TEXT(X) (X == 1 ? "YES" : "NO")

    if (er->sig_valid > 0) {
        fprintf(ftarget, "Authoritative sender: %s\n\n", er->subscriber_name.data);
        fprintf(ftarget, "Was signed: %s\n", 
                BOOL2TEXT(((er->original_packaging & KMO_SIGNED_MASK) != 0)));
        fprintf(ftarget, "Was encrypted: %s\n",
                BOOL2TEXT(((er->original_packaging & KMO_ENCRYPTED_MASK) != 0)));
        fprintf(ftarget, "Was encrypted with password: %s\n",
                BOOL2TEXT(((er->original_packaging & KMO_ENCRYPTED_WITH_PWD_MASK) != 0)));
        fprintf(ftarget, "Required PoD: %s\n\n",
                BOOL2TEXT(((er->original_packaging & KMO_REQUIRED_POD_MASK) != 0)));

        fprintf(ftarget, "Encryption status: %s\n", 
                er->encryption_status == KMO_DECRYPTION_STATUS_ENCRYPTED 
                ? "Encrypted" :
                er->encryption_status == KMO_DECRYPTION_STATUS_ENCRYPTED_WITH_PWD
                ? "Encrypted with password" :
                er->encryption_status == KMO_DECRYPTION_STATUS_DECRYPTED
                ? "Decrypted" :
                er->encryption_status == KMO_DECRYPTION_STATUS_ERROR
                ? "Error" : 
                er->encryption_status == KMO_DECRYPTION_STATUS_NONE
                ? "Not encrypted" : NULL);

        fprintf(ftarget, "PoD status: %s\n\n",
                er->pod_status == KMO_POD_STATUS_NONE
                ? "No PoD required" :
                er->pod_status == KMO_POD_STATUS_UNDELIVERED
                ? "PoD undelivered" :
                er->pod_status == KMO_POD_STATUS_DELIVERED
                ? "PoD delivered" :
                er->pod_status == KMO_POD_STATUS_ERROR
                ? "PoD error" : NULL);

        fprintf(ftarget, "Global:\t\t%s\n", BOOL2TEXT(er->sig_valid));
        fprintf(ftarget, "From name:\t%s\n", VAL2TEXT(er->from_name_status));
        fprintf(ftarget, "From addr:\t%s\n", VAL2TEXT(er->from_addr_status));
        fprintf(ftarget, "To:\t\t%s\n", VAL2TEXT(er->to_status));
        fprintf(ftarget, "CC:\t\t%s\n", VAL2TEXT(er->cc_status));
        fprintf(ftarget, "Subject:\t%s\n", VAL2TEXT(er->subject_status));
        fprintf(ftarget, "Body (Text):\t%s\n", VAL2TEXT(er->body_text_status));
        fprintf(ftarget, "Body (HTML):\t%s\n", VAL2TEXT(er->body_html_status));

        for (i = 0; i < er->attachment_nbr; i++)
// FIX ME. 
//            fprintf(ftarget, "Attach. %d:\t%s\n", i, VAL2TEXT(er->attachment_status[i]));
    	      ;
    } else 
        fprintf(ftarget, "Invalid signature.\n");
}

/**
 * Format and print a server error response from KMOD
 */
static void kpp_print_server_error(struct kmo_server_error * se, FILE * ftarget) {
    /* Display the source of the error. */
    switch (se->sid) {
    case KMO_SID_KPS:
        fprintf(ftarget, "--- Local KPS error.\n");
        break;
    case KMO_SID_OPS:
        fprintf(ftarget, "--- Online KPS error.\n");
        break;
    case KMO_SID_OUS:
        fprintf(ftarget, "--- Online Unpackaging service error.\n");
        break;
    case KMO_SID_IKS:
        fprintf(ftarget, "--- Signature key lookup service error.\n");
        break;
    case KMO_SID_EKS:
        fprintf(ftarget, "--- Encryption key lookup server error.\n");
        break;
    case KMO_SID_OTS:
        fprintf(ftarget, "--- Online Ticket Server error.\n");
    }

    /* Interpreter the error code. */
    switch (se->error) {
    case KMO_SERROR_MISC:
        fprintf(ftarget, "Miscelanous error.  Check on the website or with your site administrator.\n");
        break;
    case KMO_SERROR_TIMEOUT:
        fprintf(ftarget, "Timeout while reaching server.\n");
        break;
    case KMO_SERROR_UNREACHABLE:
        fprintf(ftarget, "Server was unreachable.\n");
        break;
    case KMO_SERROR_CRIT_MSG:
        fprintf(ftarget, "Severe error from the server.  Check the message or where your user administrator.\n");
        break;
    }	

    /* Display the error if there is one. */
    if (se->message.length > 0) {
        fprintf(ftarget, "Server report: ");
        fwrite(se->message.data, 1, se->message.length, ftarget);
        fprintf(ftarget, ".\n");
    }
}

/**
 * Input encryption passwords.
 */
static int kpp_input_enc_passwords() {
    uint32_t n, i = 0, r = 0;
    llist * pwd_list;
    llist_iterator * iter;
    struct k3p_string user_str;	
    struct kpp_recipient_pwd rp;
    struct kpp_recipient_pwd * rp_write;
    char * pwd;
    size_t pwd_s;

    if ((pwd_list = list_create()) == NULL)
        return r;

    /* Check the number of passwords. */
    if (k3p_read_uint32(&k3p, &n) < 0)
        return -1;

    for (i = 0; i < n; i++) {
        if (k3p_read_string(&k3p, &user_str) < 0)
            return -1;

        fprintf(stdout, "Input encryption password for %s: ", user_str.data);
        if (read_line(&pwd, &pwd_s, stdin) < 0) {
            r = -1;
            goto cleanup;
        }

        rp.recipient.data = user_str.data;
        rp.recipient.length = user_str.length;
        rp.password.data = pwd;
        rp.password.length = pwd_s;
        rp.give_otut = 0;

        list_append_copy(pwd_list, &rp, sizeof(rp));
    }

    /* Send back the stuff to KMOD. */
    if ((iter = list_iterator_begin(pwd_list)) == NULL) {
        r = -1;
        goto cleanup;
    }
	
    if (k3p_write_inst(&k3p, KPP_USE_PWDS) < 0)
        return -1;
    if (k3p_write_uint32(&k3p, n) < 0)
        return -1;

    while (list_iterator_get(iter, (void **)&rp_write, NULL) != LIST_ITERATOR_END) {
        if (k3p_write_recipient_pwd(&k3p, rp_write) < 0)
            return -1;
        list_iterator_next(iter);
    }

 cleanup:
    list_kill(pwd_list);
    return r;
}

/**
 * Process a message: remove the signature, decrypt and such.
 */
static int kpp_process(struct kpp_server_info * server_info,
                       struct k3p_mail * mail, 
                       char * enc_password, size_t enc_password_s,
                       char * email, size_t email_s,
                       FILE * ftarget) {
    uint32_t r;
    struct kpp_mail_process_req req;
    struct k3p_mail new_mail;	

    kmo_clearerror();

    memcpy(&req.mail, mail, sizeof(req.mail));

    req.decrypt = 1;
    req.ack_pod = 1;
    req.decryption_pwd.length = enc_password_s;
    req.decryption_pwd.data = enc_password;
    req.recipient_mail_address.length = email_s;
    req.recipient_mail_address.data = email;

    if (k3p_write_inst(&k3p, KPP_BEG_SESSION) < 0)
        return -1;

    /* Set server information */
    if (k3p_write_inst(&k3p, KPP_SET_KSERVER_INFO) < 0 ||
        k3p_write_server_info(&k3p, server_info) < 0 ||
        k3p_write_inst(&k3p, KPP_PROCESS_INCOMING) < 0 ||
        k3p_write_process_req(&k3p, &req) < 0 ||
        k3p_read_inst(&k3p, &r) < 0) 
        return -1;

    /* TODO: Support KMO_PROCESS_NACK */
    if (r == KMO_PROCESS_ACK) {
        if (k3p_read_mail(&k3p, &new_mail) < 0)
            return -1;

        kpp_write_mail(&new_mail, &new_mail.body, ftarget);
    } else if (r == KMO_PROCESS_NACK) {
		
    }

    if (k3p_write_inst(&k3p, KPP_END_SESSION) < 0)
        return -1;

    return 0;
}

/**
 * Check the validation status of a message.
 */
static int kpp_validate(struct kpp_server_info * server_info, struct k3p_mail * mail, FILE * ftarget) {
    uint32_t inst;
    struct kmo_eval_res er;

    kmo_clearerror();

    if (k3p_write_inst(&k3p, KPP_BEG_SESSION) < 0 ||   
        k3p_write_inst(&k3p, KPP_SET_KSERVER_INFO) < 0 ||
        k3p_write_server_info(&k3p, server_info) < 0 ||
        k3p_write_inst(&k3p, KPP_EVAL_INCOMING) < 0 ||
        /* Write the message we want to evaluate. */
        k3p_write_mail(&k3p, mail) < 0 ||
        /* FIXME: Handle other situations here. */
        k3p_read_inst(&k3p, &inst) < 0 ||	
        /* Check if the message is valid. */
        k3p_read_eval_res(&k3p, &er) < 0)
        return -1;

    /* Print the message validity status. */
    kpp_print_validity_status(&er, ftarget);

    if (k3p_write_inst(&k3p, KPP_END_SESSION) < 0)
        return -1;

    return 0;
}

/**
 * Return the status of a message using a its unique identifier.
 */
static int kpp_get_status(char * msg_id, FILE * ftarget) {
    uint32_t r;
    struct kmo_eval_res er;
    struct k3p_string msg_id_k3p_str;

    msg_id_k3p_str.data = msg_id;
    msg_id_k3p_str.length = strlen(msg_id);

    kmo_clearerror();

    if (k3p_write_inst(&k3p, KPP_BEG_SESSION) < 0 ||
        k3p_write_inst(&k3p, KPP_GET_EVAL_STATUS) < 0)
        return -1;

    if (/* We support only 1 message at once for now. */
        k3p_write_uint32(&k3p, 1) < 0 ||
        /* Write the ID of the message we want to evaluate. */
        k3p_write_string(&k3p, &msg_id_k3p_str) < 0)
        return -1;

    if (/* Check for the return value. */
        k3p_read_inst(&k3p, &r) < 0)
        return -1;
   
    if (r == KMO_EVAL_STATUS) {
        if (k3p_read_uint32(&k3p, &r) < 0)
            return -1;

        if (r == 1) {
            /* Check if the message is valid. */
            if (k3p_read_eval_res(&k3p, &er) < 0)
                return -1;
			
            /* Print the message validity status. */
            kpp_print_validity_status(&er, ftarget);
        }	
    }

    if (k3p_write_inst(&k3p, KPP_END_SESSION) < 0)
        return -1;

    return 0;
}

/**
 * Package a message (encrypt/sign/PoD)
 */
static int kpp_package(int package_type, struct kpp_server_info * server_info, struct k3p_mail * mail,
                       FILE * ftarget) {
    uint32_t pack_reply;
    uint32_t nack_code;
    k3p_string err_k3p;
    kstr err;
    struct kmo_server_error se;
    struct k3p_mail_body new_body;

    kmo_clearerror();

    if (/* Begin session and write request for the message. */
        k3p_write_inst(&k3p, KPP_BEG_SESSION) < 0 ||
        /* Set server information */
        k3p_write_inst(&k3p, KPP_SET_KSERVER_INFO) < 0 ||
        k3p_write_server_info(&k3p, server_info) < 0 ||
        /* Write mail data. */
        k3p_write_inst(&k3p, package_type) < 0 ||
        k3p_write_mail(&k3p, mail) < 0)
        return -1;

    /* Read the answer. */
    if (k3p_read_inst(&k3p, &pack_reply) < 0)
        return -1;

    if (pack_reply == KMO_NO_RECIPIENT_PUB_KEY) {
        kpp_input_enc_passwords(&k3p);
        if (k3p_read_inst(&k3p, &pack_reply) < 0)
            return -1;
    }

    /* Check the answer. */
    switch (pack_reply) {
    case KMO_PACK_ACK:
        if (k3p_read_mail_body(&k3p, &new_body) < 0)
            return -1;
        
        kpp_write_mail(mail, &new_body, ftarget);

        if (k3p_write_inst(&k3p, KPP_END_SESSION) < 0)
            return -1;
        break;        
    case KMO_SERVER_ERROR:
        k3p_clear_mail(mail);

        if (k3p_read_server_error(&k3p, &se) < 0)
            return -1;

        kpp_print_server_error(&se, ftarget);
        break;
    case KMO_PACK_NACK:
        k3p_clear_mail(mail);

        if (k3p_read_uint32(&k3p, &nack_code) < 0)
            return -1;
        
        if (nack_code == KMO_PACK_EXPL_UNSPECIFIED) {           
            if (k3p_read_string(&k3p, &err_k3p) < 0)
                return -1;

            kstr_init_kpstr(&err, &err_k3p);
            kmo_seterror(err.data);
            kstr_free(&err);
            free(err_k3p.data);
        }

        break;
    }
	
    return 0;
} 

/**
 * Execute a test login.
 */
int kpp_login_test(struct kpp_server_info * server_info) {
    uint32_t r;

    kmo_clearerror();

    /* Write the data for the message. */
    if (k3p_write_inst(&k3p, KPP_BEG_SESSION) < 0 ||
        k3p_write_inst(&k3p, KPP_IS_KSERVER_INFO_VALID) < 0 ||
        k3p_write_server_info(&k3p, server_info) < 0)
        return -1;
	
    /* Wait for the answer. */
    if (k3p_read_inst(&k3p, &r) < 0) 
        return -1;

    if (k3p_write_inst(&k3p, KPP_END_SESSION) < 0)
        return -1;

    if (r == KMO_SERVER_INFO_ACK) 
        printf("Login successful.\n");
    else if (r == KMO_SERVER_INFO_NACK) 
        printf("Login not successful.\n");

    return 0;
}

/**
 * Print static information returned by kmod.
 */
int kpp_print_kmo_info() {
    struct kmo_tool_info tool_info;

    memset(&tool_info, 0, sizeof(tool_info));

    if (k3p_write_inst(&k3p, KPP_BEG_SESSION) < 0)
        return -1;

    if (k3p_write_inst(&k3p, KPP_SET_KSERVER_INFO) < 0)
        return -1;

    k3p_clear_tool_info(&tool_info);

    if (k3p_read_tool_info(&k3p, &tool_info) < 0)
        return -1;

    printf("KMO static information returned:\n");
    printf("Signature header:\t %s", tool_info.sig_marker.data);
    printf("KMO Client version:\t %s\n", tool_info.kmo_version.data);
    printf("KMO Pipe proto. ver.:\t %s\n", tool_info.k3p_version.data);
	
    return 0;
}

/**
 * Convert parameters from command-line numbers
 * to K3P numbers.
 */
static inline int kpp_get_operation(int op) {
    if ((op & (OP_SIGN | OP_POD | OP_ENCRYPT)) == (OP_SIGN | OP_POD | OP_ENCRYPT))
        return KPP_SIGN_N_ENCRYPT_N_POD_MAIL;
    if ((op & (OP_SIGN | OP_POD)) == (OP_SIGN | OP_POD))
        return KPP_SIGN_N_POD_MAIL;
    if ((op & (OP_SIGN | OP_ENCRYPT)) == (OP_SIGN | OP_ENCRYPT))
        return KPP_SIGN_N_ENCRYPT_MAIL;
    if ((op & OP_SIGN) == OP_SIGN)
        return KPP_SIGN_MAIL;

    return 0;
}

int main(int argc, char ** argv) {	
    int error = 0;
    k3p_driver_id comm_driver = K3P_PIPE;
    struct kpp_server_info server_info;	
    struct k3p_mail mail;
    char * msg_id = NULL;
    char * enc_password = NULL;
    size_t enc_password_s = 0;
    char * email = NULL;
    size_t email_s = 0;
    uint32_t operation = 0;
    uint32_t hacks = 0;
    int cmd;
    FILE * fout = stdout;

    /* Initialize the error module. */
    kmo_error_start();
    
#ifdef __WINDOWS__
    WSADATA wsaData;
    int err;

    err = WSAStartup(MAKEWORD(2, 0), &wsaData);
    if (err != 0) 
        fprintf(stderr, "Unable to initialize Winsock.");
#endif

    memset(&mail, 0, sizeof(mail));
    memset(&tool_info, 0, sizeof(tool_info));
    memset(&server_info, 0, sizeof(server_info));

    while (1) {
        cmd = getopt(argc, argv, "hHTe:Lu:s:p:i:w:C:DSo:VGPEQ");

        if (cmd == -1) 
            break;

        switch (cmd) {
        case 'o':
            fout = fopen(optarg, "w");
            if (fout == NULL)
                fprintf(stderr, "Cannot open %s.  Will output to stdout.\n", optarg);
            break;
        case 'e':
            email_s = strlen(optarg);
            email = kmo_malloc(email_s + 1);
            strcpy(email, optarg);
            break;
        case 'H':
        case 'h':
            kpp_print_usage();
            return 0;
        case 'C':
            if (strcmp(optarg, "socket") == 0) 
                comm_driver = K3P_SOCKET;
            else if (strcmp(optarg, "pipe") == 0)
                comm_driver = K3P_PIPE;
            else
                fprintf(stderr, "Unknown transport \"%s\".  Using pipes.", optarg);
            break;
        case 'u':
            server_info.kps_login.data = (char *)kmo_malloc(KMO_MAX_USERNAME + 1);
            strcpy(server_info.kps_login.data, optarg);
            server_info.kps_login.data[KMO_MAX_USERNAME] = '\0';
            server_info.kps_login.length = strlen(server_info.kps_login.data);
            break;
        case 's':
            server_info.kps_net_addr.data = kmo_malloc(strlen(optarg) + 1);
            strcpy(server_info.kps_net_addr.data, optarg);
            server_info.kps_net_addr.length = strlen(optarg);
            break;
        case 'p':
            server_info.kps_port_num = atoi(optarg);
            break;
        case 'i':
            msg_id = kmo_malloc(strlen(optarg));
            strcpy(msg_id, optarg);			
            break;
        case 'w':
            enc_password_s = strlen(optarg);
            enc_password = kmo_malloc(enc_password_s);
            strcpy(enc_password, optarg);
            break;
        case 'P':
            operation |= OP_PROCESS;
            break;
        case 'D':
            operation |= OP_POD;
            break;
        case 'G':
            operation |= OP_GET_STATUS;
            break;
        case 'V':
            operation |= OP_VALIDATE;
            break;
        case 'E':
            operation |= OP_ENCRYPT;
            break;
        case 'S':			
            operation |= OP_SIGN;
            break;
        case 'L':
            operation |= OP_LOGIN_ONLY;
            break;
        case 'I':
            if (kpp_open() == 0)
                return kpp_print_kmo_info();
            kpp_close();
            break;
        case 'Q':
            keep_silent = 1;
            break;
        }
    }	

    if (!keep_silent) {
        printf("Kryptiva Mail Origin (KMO) client\n");
        printf("Copyright (C) 2005-2012 Opersys inc., All rights reserved.\n\n");
    }

    do {
        /* Create a new K3P communication object. */
        k3p_comm_new(comm_driver, &k3p);

        /* Activate timeout. */
        k3p_comm_enable_timeout(&k3p);

        if (hacks != 0)
            k3p_comm_set_hacks(&k3p, hacks);

#ifndef NDEBUG
        /* 
         * Blatantly copied from LB's kmod initialization.
         */

        /* Open the interactions log. */
        k3p_comm_log = fopen("kmo_k3p.log", "wb");
        if (k3p_comm_log == NULL) {
            kmo_seterror("cannot open 'kmo_k3p.log': %s", kmo_syserror());
            error = -1;
            break;
        }
    
        /* Write initial input line. */
        fprintf(k3p_comm_log, "OUTPUT>\n");

        /* Make logs unbuffered. */
        if(setvbuf(stderr, NULL, _IONBF, 0) || setvbuf(k3p_comm_log, NULL, _IONBF, 0)) {
            kmo_seterror("failed to make logs unbuffered");
            error = -1;
            break;
        }
#endif

        if (kpp_open()) {
            fprintf(stderr, "Cannot access KMOD.\n");
            goto cleanup;
        }

        /* Determine the operation to execute. */
        if ((operation & OP_LOGIN_ONLY) != 0) {
            /* Input the password before any operation. */
            if (kpp_get_password(&server_info) == -1)
                { kmo_seterror("Password input error."); goto cleanup; }

            if (kpp_validate_server_info(&server_info) < 0)
                fprintf(stderr, "Error: %s\n", kmo_strerror());
            else if (kpp_login_test(&server_info) < 0) 
                fprintf(stderr, "Error: %s\n", kmo_strerror());

            goto cleanup;
        } 

        if ((operation & OP_GET_STATUS) != 0) {
            if (msg_id == NULL || strlen(msg_id) == 0)
                fprintf(stderr, "You need to specify an message ID to get the status for.\n");

            kpp_get_status(msg_id, fout);

        } else if ((operation & OP_VALIDATE) != 0) {
            if (kpp_read_mail(&mail, stdin) < 0)
                fprintf(stderr, "Unable to read mail data.\n");
		
            kpp_validate(&server_info, &mail, fout);

        }  else if ((operation & OP_PROCESS) != 0) { 
            /* Input the password before any operation. */
            if (kpp_get_password(&server_info) == -1)
                { kmo_seterror("Password input error."); goto cleanup; }

            if (kpp_read_mail(&mail, stdin) < 0) 
                fprintf(stderr, "Unable to read mail data.\n"); 
            else {
                kpp_process(&server_info, &mail, 
                            enc_password, enc_password_s,
                            email, email_s,
                            fout); 
            }

        } else if (operation > 0) {
            /* Input the password before any operation. */
            if (kpp_get_password(&server_info) == -1)
                { kmo_seterror("Password input error."); goto cleanup; }

            /* Make sure the sign flag is always on. */
            operation |= OP_SIGN;

            if (kpp_read_mail(&mail, stdin) < 0)
                fprintf(stderr, "Unable to read mail data.\n");
            else 
                kpp_package(kpp_get_operation(operation), &server_info, &mail, fout);
        } else 
            fprintf(stderr, "You need to specify at least operation of -G -P -L -S, -E and -P.\n");

    } while (0);

 cleanup:
    k3p_clear_tool_info(&tool_info);
    k3p_clear_server_info(&server_info);

    k3p_clear_mail(&mail);

    free(msg_id);
    free(enc_password);
    free(email);

    kpp_close();
    k3p_comm_delete(&k3p);

    fclose(fout);

    return (error ? 1 : 0);
}
