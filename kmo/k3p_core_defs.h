/*
 * k3p_core_defs.h
 *
 * Copyright (C) 2006-2012 Opersys Inc., All rights reserved.
 *
 * Authors:
 *    Mathieu Lemay, original edit.
 *    Karim Yaghmour, "a few" renamings and reformatting ;)
 *
 * Core definitions for communication protocol between misc. plugins and kmo.
 *
 * Acronyms:
 *    KMO, Kryptiva Mail Operator
 *    KPP, Kryptiva Packaging Plugin
 *    K3P, KMO Plugin Pipe Protocol
 *    OTUT, One-Time Use Token (for secure reply to sender)
 *
 * Notes :
 *    Putting it politely, mail clients in general vary greatly in the quality
 *    of their designs, their code maturity, and general sanity. It's fair to
 *    say most mail clients seem to have been hacked in order to be
 *    compatible with as much of what goes around as possible. As a result,
 *    there is hardly any general framework that can be assumed to be true
 *    for *all* mail clients. So ... K3P is built to require as little
 *    intelligence as possible on the part of the mail client.
 *
 *    It is assumed the mail client is sane enough to maintain an internal
 *    *unique* per-message identifier _and_ that we have access to it.
 *    Without this, it becomes very difficult to rapidly report back to the
 *    interface info regarding already processed messages (i.e. mails that
 *    we previously received and had already put through KMO.) We can
 *    always use a hash as the ID, but that's far from optimal.
 */
#ifdef _MSC_VER
typedef signed __int8       int8_t;
typedef unsigned __int8     uint8_t;
typedef signed __int16      int16_t;
typedef unsigned __int16    uint16_t;
typedef signed __int32      int32_t;
typedef unsigned __int32    uint32_t;
typedef signed __int64      int64_t;
typedef unsigned __int64    uint64_t;
#else
#include <inttypes.h>
#endif

#ifndef _K3P_CORE_DEFS_H
#define _K3P_CORE_DEFS_H

/* What version of the protocol does this file specify */
#define K3P_VER_MAJOR     1
#define K3P_VER_MINOR     8

/* Common definition of kpstr between K3P and KNP. */
#ifndef KPSTR
#define KPSTR
typedef struct kpstr
{
    	/* Length of the string. */
        uint32_t length;
	
	/* Data of the string, without the terminating '0'.
	 * Can be NULL if len == 0.
	 */
        char *data;
} kpstr;
#endif

/* Specify various strings passed between KPP and KMO */
#define k3p_string kpstr

/* TEMPORARY HACK. WILL BE REWORKED.
 * Input: entry_id. // SHOULD BE OTUT STRING.
 * Output: 0 if successful, then bool: otut contained valid or not.
 */
#define K3P_CHECK_OTUT			 33

/* MORE TEMPORARY HACKS. MIGHT BE REWORKED. */

/* Open connetion to kappsd if not already open.
 * Input: KPG address.
 * Output: inst 0 if successful, inst 1 if not. Error string follows on error.
 */ 
#define K3P_OPEN_KAPPSD_SESSION	    	34

/* Close connection opened above, if any. Returns inst 0. */
#define K3P_CLOSE_KAPPSD_SESSION	35

/* Send a message to KAPSD, receive reply.
 * Input: sequence of string and int elements, ended by any instruction element.
 *        The instruction is ignored, the other elements are sent as-is to kappsd.
 * Output: inst 0 if successful, followed by all ints and strings returned by kappsd.
 *         inst 1 on error, followed by error string.
 * Kappsd session must be closed if inst 1 is returned.
 */
#define K3P_EXCHANGE_KAAPSD_MESSAGE 	36

/* Kappsd messages:
 * 
 * Obtain port:
 * Input:  Int 1.
 * Output: Int 0 OK.
 *           Int port.
 *         Int 1 failed.
 *           Str error.
 *
 * Create share:
 * Input:  Int 2
 *         Str login name.
 *         Str login ticket.
 * Output: Int 0 OK.
 *           Str share name.
 *           Str share password.
 *         Int 1 failed.
 *           Str error.
 *
 * Ask a captcha for registration:
 * Input:  Int 3
 * Output: Int 0 OK.
 *           Str captcha.
 *         Int 1 failed.
 *           Str error.
 *
 * Do registration:
 * Input:  Int 4
 *           Str first_name.
 *           Str last_name.
 *           Str country.
 *           Str state.
 *           Str phone.
 *           Str email.
 *           Str company.
 *           Str employee.
 *           Str login.
 *           Str password.
 *           Str captcha_text.
 * Output: Int 0 OK.
 *         Int 1 failed.
 *           Str error.
 */

/* NOTE: the crap above will be removed when our "real" version is out. */


/* Instruction 0 means all is OK, query response follow. */
#define K3P_COMMAND_OK				0

/* Obtain a ticket authorizing the creation or joining of a workspace. */
#define K3P_GET_KWS_TICKET    	    	40
/* Input:  None.
 * Output: Str Ticket.
 */

/* Convert Exchange addresses to SMTP addresses. */
#define K3P_CONVERT_EXCHANGE_ADDRESS		41
/* Input:  Int Number of addresses.
 *         For each address:
 *           Str Exchange address.
 * Output: Int Number of addresses.
 *         For each address:
 *           Str SMTP address ("" if cannot convert).
 */

/* Lookup the SMTP addresses specified and determine the key ID and the company
 * name associated to each address, if there is one.
 */
#define K3P_LOOKUP_REC_ADDR			42
/* Input:  Int Number of addresses.
 *         For each address:
 *           Str Address.
 * Output: Int Number of addresses.
 *         For each address:
 *           Str Key ID (marshalled in string, because it's 64 bits long).
 *               "" if the user is a non-member.
 *           Str Company name, if the user is a member.
 */

/* Same as K3P_PROCESS_INCOMING, but the decryption email is returned if it was
 * found.
 */
#define K3P_PROCESS_INCOMING_EX			43
/* Input:  Same as usual.
 * Output: Same as usual.
 *         Str Email address ("" if none).
 */

/* Used by the KCD to validate a ticket. */
#define K3P_VALIDATE_TICKET			44
/* Input:  Str Ticket.
 *         Str Key ID (marshalled as string).
 * Output: Int Result (0: OK, 1: failed).
 *         Str Error String ("" if none).
 */


struct k3p_mail_body
{
#define K3P_MAIL_BODY_TYPE               0x4783AF39
#define K3P_MAIL_BODY_TYPE_TEXT          K3P_MAIL_BODY_TYPE + 1
#define K3P_MAIL_BODY_TYPE_HTML          K3P_MAIL_BODY_TYPE + 2
#define K3P_MAIL_BODY_TYPE_TEXT_N_HTML   K3P_MAIL_BODY_TYPE + 3

        uint32_t type;
        
        struct k3p_string text;
        struct k3p_string html;
};

struct k3p_mail_attachment
{
#define K3P_MAIL_ATTACHMENT_TIE     	0x57252924
#define K3P_MAIL_ATTACHMENT_EXPLICIT	K3P_MAIL_ATTACHMENT_TIE + 1
#define K3P_MAIL_ATTACHMENT_IMPLICIT	K3P_MAIL_ATTACHMENT_TIE + 2
#define K3P_MAIL_ATTACHMENT_UNKNOWN	K3P_MAIL_ATTACHMENT_TIE + 3

        uint32_t tie;

        uint32_t data_is_file_path;     /* filepath or actual content? */
        struct k3p_string data;     	/* path to the file or file content. */
	struct k3p_string name; 	/* name, either a file name or the implicit attachment name. */
	struct k3p_string encoding;
	struct k3p_string mime_type;
};

struct k3p_otut
{
#define KMO_OTUT_STATUS_MAGIC_NUMBER    0xFAEB9091
#define KMO_OTUT_STATUS_NONE            KMO_OTUT_STATUS_MAGIC_NUMBER + 1
#define KMO_OTUT_STATUS_USABLE          KMO_OTUT_STATUS_MAGIC_NUMBER + 2
#define KMO_OTUT_STATUS_USED            KMO_OTUT_STATUS_MAGIC_NUMBER + 3
#define KMO_OTUT_STATUS_ERROR           KMO_OTUT_STATUS_MAGIC_NUMBER + 4

    	uint32_t status; /* NONE    : no OTUT */
                         /* USABLE  : OTUT can be used, time to live in 'msg' */
                         /* USED    : the OTUT has been used (date and time are set in 'msg')  */
                         /* ERROR   : Unable to send with OTUT (expired, etc.), error message set in 'msg' */
	
	struct k3p_string entry_id;    	/* Entry ID of the mail providing the OTUT. */
	struct k3p_string reply_addr;	/* Reply address associated to the sender. */
	struct k3p_string msg;	    	/* Message binded to the status. */
};

struct k3p_mail
{
        struct k3p_string msg_id;       /* native ID stored by mail client */
    	
	struct k3p_string recipient_list; /* Recipient list. */
	
        struct k3p_string from_name;
        struct k3p_string from_addr;
        struct k3p_string to;
        struct k3p_string cc;
        struct k3p_string subject;

        struct k3p_mail_body body;

        uint32_t attachment_nbr;
        struct k3p_mail_attachment *attachments;

        struct k3p_otut otut;
};

/* KPP request IDs */

#define KPP_MAGIC_NUMBER                0x43218765

/* Session management */
#define KPP_CONNECT_KMO                 KPP_MAGIC_NUMBER +  1  /* with kpp_mua struct */
#define KPP_DISCONNECT_KMO              KPP_MAGIC_NUMBER +  2
#define KPP_BEG_SESSION                 KPP_MAGIC_NUMBER +  3
#define KPP_END_SESSION                 KPP_MAGIC_NUMBER +  4

/* Settings and misc. info */
#define KPP_IS_KSERVER_INFO_VALID       KPP_MAGIC_NUMBER + 10  /* use with kpp_server_info struct */
#define KPP_SET_KSERVER_INFO            KPP_MAGIC_NUMBER + 11  /* user info / KPS / KOS */

/* Mail packaging requests */
#define KPP_SIGN_MAIL                   KPP_MAGIC_NUMBER + 20  /* Return k3p_mail_body */
#define KPP_SIGN_N_POD_MAIL             KPP_MAGIC_NUMBER + 21
#define KPP_SIGN_N_ENCRYPT_MAIL         KPP_MAGIC_NUMBER + 22
#define KPP_SIGN_N_ENCRYPT_N_POD_MAIL   KPP_MAGIC_NUMBER + 23
#define KPP_CONFIRM_REQUEST             KPP_MAGIC_NUMBER + 24
#define KPP_USE_PWDS                    KPP_MAGIC_NUMBER + 25  /* nbr recipients + kpp_recipient_pwd array */

/* Dealing with incoming messages */
#define KPP_EVAL_INCOMING               KPP_MAGIC_NUMBER + 30  /* Evaluation an incoming mail. The result is as follow:
    	    	    	    	    	    	    	    	* 0: Can't happen.
                                                                * 1: Kryptiva mail. Evaluation results follow.
								* 2: Not a Kryptiva mail.
								*/
								
#define KPP_PROCESS_INCOMING            KPP_MAGIC_NUMBER + 31  /* with kpp_mail_process_req */

#define KPP_MARK_UNSIGNED_MAIL	    	KPP_MAGIC_NUMBER + 32  /* some mails are not signed...ask KMO to remember that.
    	    	    	    	    	    	    	    	* nbr of entries + msg IDs.
								*/
								
#define KPP_SET_DISPLAY_PREF	    	KPP_MAGIC_NUMBER + 33  /* change the display preference of a Kryptiva mail.
    	    	    	    	    	    	    	    	* input: msg_id, display_pref (0, 1, 2).
								* output: KMO_SET_DISPLAY_PREF_ACK or KMO_SET_DISPLAY_PREF_NACK.
								*/

/* Dealing with stored messages */
#define KPP_GET_EVAL_STATUS             KPP_MAGIC_NUMBER + 40  /* with nbr of entries + msg IDs */
#define KPP_GET_STRING_STATUS		KPP_MAGIC_NUMBER + 41  /* Same input as above. The result is as follow:
								* 0: unknown mail.
								* 1: can't happen (to prevent confusion with
							        *                  KPP_GET_EVAL_STATUS codes).
								* 2: not a Kryptiva mail.
								* 3: Kryptiva invalid signature.
								* 4: Kryptiva corrupted mail.
								* 5: Kryptiva signed mail. Sender name string follows.
								* 6: Kryptiva encrypted mail. Sender name string follows.
								* 7: Kryptiva mail with gray zone display preference.
								* 8: Kryptiva mail with unsigned display preference.
								*/

/* Password management */
struct kpp_email_pwd
{
    	struct k3p_string addr;
	struct k3p_string pwd;
};

#define KPP_GET_EMAIL_PWD   	    	KPP_MAGIC_NUMBER + 50	/* input: nb addresses to get the passwords for,
    	    	    	    	    	    	    	    	 *  	  array of addresses.
    	    	    	    	    	    	    	    	 * output: nb_results, array of results: password if 
								 *         found, empty string if not.
								 */
#define KPP_GET_ALL_EMAIL_PWD     	KPP_MAGIC_NUMBER + 51	/* output: number of user passwords in the DB.
    	    	    	    	    	    	    	    	 *         array of kpp_email_pwd.
								 */
#define KPP_SET_EMAIL_PWD 	    	KPP_MAGIC_NUMBER + 52	/* input: nb passwords to set, kpp_email_pwd containing
    	    	    	    	    	    	    	    	 *        the addr/pwd to set.
								 */
#define KPP_REMOVE_EMAIL_PWD    	KPP_MAGIC_NUMBER + 53	/* input: nb passwords to remove, array of addresses. */


/* Structs used by KPP to send info to KMO */

struct kpp_server_info
{
        struct k3p_string kps_login;
        struct k3p_string kps_secret;
	uint32_t secret_is_pwd;
	struct k3p_string pod_addr;

        struct k3p_string kps_net_addr;
        uint32_t kps_port_num;
        struct k3p_string kps_ssl_key;

        uint32_t kps_use_proxy;
        struct k3p_string kps_proxy_net_addr;
        uint32_t kps_proxy_port_num;
        struct k3p_string kps_proxy_login;
        struct k3p_string kps_proxy_pwd;

        uint32_t kos_use_proxy;
        struct k3p_string kos_proxy_net_addr;
        uint32_t kos_proxy_port_num;
        struct k3p_string kos_proxy_login;
        struct k3p_string kos_proxy_pwd;
};

/* Some MUAs may require special processing because of their limitations */
struct kpp_mua
{
#define KPP_MUA_OUTLOOK     	    1
#define KPP_MUA_THUNDERBIRD 	    2
#define KPP_MUA_LOTUS_NOTES 	    3
	
    	/* Product (e.g. 'Outlook') ID. */
        uint32_t product;
	
	/* Product version (e.g. '11') ID. */
        uint32_t version;
	
	/* Product release string (e.g. 11.0.0.8010). */
	struct k3p_string release;
	
	/* Plugin major number. */
	uint32_t kpp_major;
	
	/* Plugin minor number. */
	uint32_t kpp_minor;
	
	/* This flag is true if the plugin prefers to receive attachments
	 * in files rather than on the pipe/socket.
	 */
	uint32_t incoming_attachment_is_file_path;
	
	/* Language used by the user of the plugin. The codes are defined in
	 * knp_core_defs.h.
	 */
	uint32_t lang;
};

struct kpp_recipient_pwd
{
        struct k3p_string recipient;
        struct k3p_string password;

        uint32_t give_otut;      /* should the recipient be allowed to respond securely? */
	uint32_t save_pwd;	 /* remember the default password */
};

struct kpp_mail_process_req
{
        struct k3p_mail mail;

        uint32_t decrypt;
        struct k3p_string decryption_pwd;
	uint32_t save_pwd;

        uint32_t ack_pod;
        /* This is for returning to the sender on a PoD. It is non-authoritative,
         obviously. So the recipient could fake it. Realistically, though, it
         would take *all* recipients to fake it to potentially confuse the
         sender, who, either way, will be able to determine something fishy is
         going on because of the inconsistencies between the recipient list and
         the PoDs recieved. All that keeping in mind that KOS can be authoritative
         on PoD requestors' IP addresses, if nothing else ... */
        struct k3p_string recipient_mail_address;
};

/* KMO responses to KPP */

#define KMO_MAGIC_NUMBER          0x12349876

/* Session management */
#define KMO_COGITO_ERGO_SUM       KMO_MAGIC_NUMBER +  1  /* with kmo_tool_info struct */
#define KMO_INVALID_REQ           KMO_MAGIC_NUMBER +  2  /* spreken zie deutsch? */
#define KMO_INVALID_CONFIG        KMO_MAGIC_NUMBER +  3  /* sorry joe, trying configuring first */
#define KMO_SERVER_ERROR          KMO_MAGIC_NUMBER +  4  /* with kmo_server_error string */

/* Responses to settings and misc. info reqs. */
#define KMO_SERVER_INFO_ACK       KMO_MAGIC_NUMBER + 10  /* with encrypted password */
#define KMO_SERVER_INFO_NACK      KMO_MAGIC_NUMBER + 11  /* with error string */

/* Responses to mail packaging reqs. */
#define KMO_PACK_ACK              KMO_MAGIC_NUMBER + 20
#define KMO_PACK_NACK             KMO_MAGIC_NUMBER + 21  /* with kmo_pack_explain */
#define KMO_PACK_CONFIRM          KMO_MAGIC_NUMBER + 22  /* with kmo_pack_explain */
#define KMO_PACK_ERROR            KMO_MAGIC_NUMBER + 23  /* misc. */
#define KMO_NO_RECIPIENT_PUB_KEY  KMO_MAGIC_NUMBER + 24  /* with nbr recipients + array of kpp_recipient_pwd */
#define KMO_INVALID_OTUT          KMO_MAGIC_NUMBER + 25  /* the OTUT provided isn't usable */

/* Responses to incoming and stored mail reqs. */
#define KMO_EVAL_STATUS           KMO_MAGIC_NUMBER + 30  /* with array(status + (kmo_eval_res iff status == 1)) */
#define KMO_STRING_STATUS	  KMO_MAGIC_NUMBER + 31	 /* as described above. */
#define KMO_PROCESS_ACK           KMO_MAGIC_NUMBER + 32  /* with k3p_mail struct where only body and attach. are set */
#define KMO_PROCESS_NACK          KMO_MAGIC_NUMBER + 33  /* with kmo_process_nack struct */
#define KMO_MARK_UNSIGNED_MAIL	  KMO_MAGIC_NUMBER + 34  /* ACK for KPP_MARK_UNSIGNED_MAIL */
#define KMO_SET_DISPLAY_PREF_ACK  KMO_MAGIC_NUMBER + 35
#define KMO_SET_DISPLAY_PREF_NACK KMO_MAGIC_NUMBER + 36

#define KMO_PWD_ACK   	    	  KMO_MAGIC_NUMBER + 50

/* Upgrade message. */
#define KMO_MUST_UPGRADE          KMO_MAGIC_NUMBER + 60  /* with one of the values below that indicates why the update
                                                          * is needed
							  */
#define KMO_UPGRADE_SIG     	  1 	    	    	 /* can't handle mail signature */
#define KMO_UPGRADE_KOS  	  2 	    	    	 /* KOS refuses to speak to us */
#define KMO_UPGRADE_KPS     	  3 	    	    	 /* KPS too old, cannot do requested work */

/* Explanation after received KMO_PROCESS_NACK */
struct kmo_process_nack
{
#define KMO_PROCESS_NACK_MAGIC_NUMBER       0x531AB246
#define KMO_PROCESS_NACK_POD_ERROR          KMO_PROCESS_NACK_MAGIC_NUMBER + 1  /* KOS can't deliver PoD */
#define KMO_PROCESS_NACK_PWD_ERROR          KMO_PROCESS_NACK_MAGIC_NUMBER + 2  /* wrong password */
#define KMO_PROCESS_NACK_DECRYPT_PERM_FAIL  KMO_PROCESS_NACK_MAGIC_NUMBER + 3  /* not authorized to decrypt this message */
#define KMO_PROCESS_NACK_MISC_ERROR 	    KMO_PROCESS_NACK_MAGIC_NUMBER + 4  /* miscellaneous error */
    uint32_t error;
    struct k3p_string error_msg;   /* Error message set when a miscellaneous error occurred */
};

struct kmo_tool_info
{
        struct k3p_string sig_marker;
        struct k3p_string kmo_version;
        struct k3p_string k3p_version;
};

struct kmo_server_error
{
/* Designation for server with which there was an error */
#define KMO_SID_MAGIC_NUMBER	    (0x8724U << 16) + (1 << 8)
#define KMO_SID_KPS 	    	    KMO_SID_MAGIC_NUMBER + 1
#define KMO_SID_OPS 	    	    KMO_SID_MAGIC_NUMBER + 2
#define KMO_SID_OUS 	    	    KMO_SID_MAGIC_NUMBER + 3
#define KMO_SID_OTS 	    	    KMO_SID_MAGIC_NUMBER + 4
#define KMO_SID_IKS 	    	    KMO_SID_MAGIC_NUMBER + 5
#define KMO_SID_EKS 	    	    KMO_SID_MAGIC_NUMBER + 6
        uint32_t sid;       	    /* server ID */

#define KMO_SERROR_MAGIC_NUMBER   0X8FBA3CDE
#define KMO_SERROR_MISC           KMO_SERROR_MAGIC_NUMBER + 1
#define KMO_SERROR_TIMEOUT        KMO_SERROR_MAGIC_NUMBER + 2
#define KMO_SERROR_UNREACHABLE    KMO_SERROR_MAGIC_NUMBER + 3
#define KMO_SERROR_CRIT_MSG       KMO_SERROR_MAGIC_NUMBER + 4
        uint32_t error;
        struct k3p_string message;
};

struct kmo_eval_res_attachment
{
#define KMO_EVAL_ATTACHMENT_MAGIC_NUMBER	0X65920424
#define KMO_EVAL_ATTACHMENT_DROPPED		KMO_EVAL_ATTACHMENT_MAGIC_NUMBER + 1
#define KMO_EVAL_ATTACHMENT_INTACT		KMO_EVAL_ATTACHMENT_MAGIC_NUMBER + 2
#define KMO_EVAL_ATTACHMENT_MODIFIED		KMO_EVAL_ATTACHMENT_MAGIC_NUMBER + 3
#define KMO_EVAL_ATTACHMENT_INJECTED		KMO_EVAL_ATTACHMENT_MAGIC_NUMBER + 4
#define KMO_EVAL_ATTACHMENT_ERROR		KMO_EVAL_ATTACHMENT_MAGIC_NUMBER + 5

	struct k3p_string name;	/* Name of the attachment, if any. */
	uint32_t status;	/* Status of the attachment, as described above. */
};

struct kmo_eval_res
{
        uint32_t display_pref;	    	/* 0: Show as gray zone.
	    	    	    	    	 * 1: Show as Kryptiva mail.
					 * 2: Show as unsigned mail.
					 */ 
	
	uint32_t string_status;		/* String status code as defined in KPP_GET_STRING_STATUS. */
	
	uint32_t sig_valid;             /* Mail contains a valid genuine Kryptiva signature.
	    	    	    	    	 * Note that if this is 0, the following fields contain
					 * invalid info that should not be interpreted (statuses might
					 * be 0 and strings might be empty).
					 */
					 
	struct k3p_string sig_msg;  	/* If the signature is not valid, this message explains why. */
	

#define KMO_SIGNED_MASK                 (1 << 0)  //00000001
#define KMO_ENCRYPTED_MASK              (1 << 1)  //00000010
#define KMO_ENCRYPTED_WITH_PWD_MASK     (1 << 2)  //00000100
#define KMO_REQUIRED_POD_MASK           (1 << 3)  //00001000
#define KMO_CONTAINED_OTUT_MASK         (1 << 4)  //00010000
        uint32_t original_packaging;    /* bit fields */
	
        struct k3p_string subscriber_name;  /* who's the authoritative sender? */

#define KMO_FIELD_STATUS_MAGIC_NUMBER   0xFD4812ED
#define KMO_FIELD_STATUS_ABSENT         KMO_FIELD_STATUS_MAGIC_NUMBER + 1
#define KMO_FIELD_STATUS_INTACT         KMO_FIELD_STATUS_MAGIC_NUMBER + 2
#define KMO_FIELD_STATUS_CHANGED        KMO_FIELD_STATUS_MAGIC_NUMBER + 3

        uint32_t from_name_status;
        uint32_t from_addr_status;
        uint32_t to_status;
        uint32_t cc_status;
        uint32_t subject_status;
        uint32_t body_text_status;
        uint32_t body_html_status;

        uint32_t attachment_nbr;
        struct kmo_eval_res_attachment *attachments;

#define KMO_DECRYPTION_STATUS_MAGIC_NUMBER          0xFED123AB
#define KMO_DECRYPTION_STATUS_NONE                  KMO_DECRYPTION_STATUS_MAGIC_NUMBER + 1
#define KMO_DECRYPTION_STATUS_ENCRYPTED             KMO_DECRYPTION_STATUS_MAGIC_NUMBER + 2
#define KMO_DECRYPTION_STATUS_ENCRYPTED_WITH_PWD    KMO_DECRYPTION_STATUS_MAGIC_NUMBER + 3
#define KMO_DECRYPTION_STATUS_DECRYPTED             KMO_DECRYPTION_STATUS_MAGIC_NUMBER + 4
#define KMO_DECRYPTION_STATUS_ERROR                 KMO_DECRYPTION_STATUS_MAGIC_NUMBER + 5

        uint32_t encryption_status; 
	    	    	        /* NONE : the mail is not encrypted   */
                                /* ENCRYPTED : mail is encrypted, but it hasn't been tried to be decrypt yet */
                                /* ENCRYPTED_WITH_PWD : a password is required to decrypt the mail           */
                                /* DECRYPTED : mail has already been decrypted and the  */
                                /*            decryption key is saved in the DB         */
                                /* ERROR : mail has already been tried to decrypt,      */
                                /*         but the mail is corrupted.                   */
        struct k3p_string decryption_error_msg; /* explanation of the decryption status */
	
	struct k3p_string default_pwd;  /* Last password provided to decrypt mails from this message sender. */


#define KMO_POD_STATUS_MAGIC_NUMBER     0xCBA987EF
#define KMO_POD_STATUS_NONE             KMO_POD_STATUS_MAGIC_NUMBER + 1
#define KMO_POD_STATUS_UNDELIVERED      KMO_POD_STATUS_MAGIC_NUMBER + 2
#define KMO_POD_STATUS_DELIVERED        KMO_POD_STATUS_MAGIC_NUMBER + 3
#define KMO_POD_STATUS_ERROR            KMO_POD_STATUS_MAGIC_NUMBER + 4

        uint32_t pod_status;
	    	    	/* NONE        : no PoD to send */
                        /* UNDELIVERED : a PoD must be delivered */
                        /* DELIVERED   : PoD has been delivered successfully (Date and time are set in pod_msg) */
                        /* ERROR       : Unable to send PoD - mail corrupted  */
        struct k3p_string pod_msg;  /* Explanation of the error or time of */
                                    /* the PoD has been sent successfully, */
	
	struct k3p_otut otut;  /* OTUT status */
};

struct kmo_pack_explain
{
#define KMO_PACK_EXPL_MAGIC_NUMBER           0x820994AF
#define KMO_PACK_EXPL_UNSPECIFIED            KMO_PACK_EXPL_MAGIC_NUMBER + 1
#define KMO_PACK_EXPL_SUSPECT_SPAM           KMO_PACK_EXPL_MAGIC_NUMBER + 2
#define KMO_PACK_EXPL_SUSPECT_VIRUS          KMO_PACK_EXPL_MAGIC_NUMBER + 3
#define KMO_PACK_EXPL_SHOULD_ENCRYPT         KMO_PACK_EXPL_MAGIC_NUMBER + 4
#define KMO_PACK_EXPL_SHOULD_POD             KMO_PACK_EXPL_MAGIC_NUMBER + 5
#define KMO_PACK_EXPL_SHOULD_ENCRYPT_N_POD   KMO_PACK_EXPL_MAGIC_NUMBER + 6
#define KMO_PACK_EXPL_CUSTOM                 KMO_PACK_EXPL_MAGIC_NUMBER + 7
        uint32_t type;

        struct k3p_string text;
        struct k3p_string captcha;
};


#endif /* _K3P_CORE_DEFS_H */
