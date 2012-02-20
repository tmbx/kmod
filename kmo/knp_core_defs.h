/* Copyright (C) 2006-2012 Opersys Inc., All rights reserved. */

#ifndef _KNP_CORE_DEFS_H
#define _KNP_CORE_DEFS_H

#include <inttypes.h>

/* Here are the major and minor version numbers of the protocol described in
 * this file.
 *
 * The major is incremented whenever the KOS need to stop supporting older
 * requests because a security breach or a major problem occurred. In other
 * words, when the major number changes, all the existing plugins stop working.
 *
 * The minor is incremented whenever new features are added to the KOS.
 *
 * If the KOS cannot process a request because the plugin is not recent enough
 * (i.e. the major number changed or the KOS determine that the plugin is trying
 * to do something which must be done differently for now on), the KOS return
 * KNP_UPGRADE_PLUGIN.
 *
 * If the KPS cannot process a request because the KPS is too old, the KPS
 * return KNP_UPGRADE_KPS. When that happens, the plugin may try to send an
 * older version of the same request.
 *
 * Version history:
 *
 * Version 1.1:
 * - First released version. The plugin using v. 1.1 did not include the
 *   mechanisms to deal with future versions of the KNP and the KSP, so no
 *   backward compatibility with v. 1.1 is required.
 *
 * Version 2.1:
 * - Added KNP_RES_UPGRADE_PLUGIN and KNP_RES_UPGRADE_KPS.
 * - Added 'lang' in knp_cmd_package_mail.
 * - Added 'subject' in knp_cmd_dec_sym_key.
 *
 * Version 3.1:
 * - Added 'pod_date' in knp_cmd_dec_sym_key.
 * - Added login token in knp_cmd_user_login.
 * - Added key signing in knp_cmd_get_sign_key and knp_cmd_dec_sym_key.
 * - Signature format of TO/CC/From Name/From Address has changed.
 *
 * Version 4.1:
 * - Added 'KNP_CMD_PACKAGE_LIC'.
 * - Added 'KNP_RES_PACKAGE_FAIL'.
 *
 * Version 4.1 KLUDGE 1:
 * - This is a tricky bit. See, our management of protocol versions is
 *   a little subobtimal. That makes it kinda hard to maintain backward
 *   compatibility. So we cheat by including the following fields without
 *   bumping the protocol version...
 * - Added kpg* in knp_cmd_get_user_info.
 *
 * Version 4.1 KLUDGE 2:
 * - Added 'want_dec_email' and 'dec_email' in knp_cmd_dec_sym_key.
 * - Added 'subscriber_array' in knp_cmd_get_enc_key.
 * - Added 'KNP_CMD_GET_ENC_KEY_BY_ID'.
 * - Added 'KNP_CMD_GET_KWS_TICKET'.
 * - Added 'KNP_CMD_CONVERT_EXCHANGE'.
 */
#define KNP_MAJOR_VERSION   	    4
#define KNP_MINOR_VERSION   	    1


/* Protocol commands, replies and other identitifers have the following form:
 * 16 bits: KNP magic number, 8 bits: identifier category, 8 bits: identifier.
 * <----16----><--8--><--8-->
 *    magic      cat    id
 */ 
#define KNP_MAGIC_NUMBER    	    (0x8724U << 16)


/* Server to contact. */
#define KNP_CONTACT_CAT   	    KNP_MAGIC_NUMBER + (1 << 8)

/* Teambox Sign-On Server
 * Authenticated logins only.
 * Deals with mails encrypted with a local public encryption key. POD 
 * processing must be continued with OUS.
 */
#define KNP_CONTACT_KPS     	    KNP_CONTACT_CAT + 1

/* Online Packaging Server.
 * Authenticated logins and OTUT logins.
 * Deals with mails encrypted with an online public encryption key.
 */
#define KNP_CONTACT_OPS     	    KNP_CONTACT_CAT + 2

/* Online Unpackaging Server.
 * Anonymous logins only. Deals with mails encrypted with password / POD.
 */
#define KNP_CONTACT_OUS     	    KNP_CONTACT_CAT + 3

/* Online Token Server. Get FREE tokens in your email!!
 * Anonymous logins only.
 * KMO provides a ticket and the server returns OTUTs.
 */
#define KNP_CONTACT_OTS     	    KNP_CONTACT_CAT + 4

/* Identity (signature) Key Server.
 * KMO provides a key ID and the server returns the key data.
 */
#define KNP_CONTACT_IKS     	    KNP_CONTACT_CAT + 5

/* Encryption Key Server.
 * KMO provides some addresses and the server returns the keys associated to the
 * addresses, if any.
 */
#define KNP_CONTACT_EKS     	    KNP_CONTACT_CAT + 6


/* Server commands and results. */
#define KNP_CMD_CAT	    	    KNP_MAGIC_NUMBER + (2 << 8)
#define KNP_RES_CAT	    	    KNP_MAGIC_NUMBER + (3 << 8)

/* Login method. */
#define KNP_CMD_LOGIN_ANON	    KNP_CMD_CAT + 10	/* Anonymous login. Defined but not 
    	    	    	    	    	    	    	 * actually used on the wire.
							 */
#define KNP_CMD_LOGIN_USER	    KNP_CMD_CAT + 11 	/* User / password login. */
#define KNP_CMD_LOGIN_OTUT	    KNP_CMD_CAT + 12	/* OTUT login. */
#define KNP_RES_LOGIN_OK    	    KNP_RES_CAT + 10	/* Login accepted. */

/* Obtain the member info of the user. */
#define KNP_CMD_GET_USER_INFO       KNP_CMD_CAT + 20
#define KNP_RES_GET_USER_INFO       KNP_RES_CAT + 20
    
/* Obtain an identitiy key given its ID. */
#define KNP_CMD_GET_SIGN_KEY	    KNP_CMD_CAT + 30
#define KNP_RES_GET_SIGN_KEY	    KNP_RES_CAT + 30

/* Obtain an encryption key given its ID. */
#define KNP_CMD_GET_ENC_KEY_BY_ID    KNP_CMD_CAT + 31
#define KNP_RES_GET_ENC_KEY_BY_ID    KNP_RES_CAT + 31
    
/* Obtain encryption keys given email addresses. */
#define KNP_CMD_GET_ENC_KEY         KNP_CMD_CAT + 40
#define KNP_RES_GET_ENC_KEY         KNP_RES_CAT + 40
    
/* Package a mail. */
#define KNP_CMD_PACKAGE_MAIL	    KNP_CMD_CAT + 50
#define KNP_CMD_PACKAGE_LIC         KNP_CMD_CAT + 51    /* Package with license. */
#define KNP_RES_PACKAGE_MAIL	    KNP_RES_CAT + 50
#define KNP_RES_PACKAGE_FAIL	    KNP_RES_CAT + 51    /* string with explanation follows. */
    
/* Obtain an OTUT ticket. */
#define KNP_CMD_GET_OTUT_TICKET     KNP_CMD_CAT + 60
#define KNP_RES_GET_OTUT_TICKET     KNP_RES_CAT + 60

/* Validate an OTUT ticket. */
#define KNP_CMD_VALIDATE_OTUT	    KNP_CMD_CAT + 61
#define KNP_RES_VALIDATE_OTUT	    KNP_RES_CAT + 61
    
/* Obtain OTUT strings. */
#define KNP_CMD_GET_OTUT_STRING     KNP_CMD_CAT + 70
#define KNP_RES_GET_OTUT_STRING     KNP_RES_CAT + 70
        
/* Decrypt a KSP symmetric key. */
#define KNP_CMD_DEC_SYM_KEY 	    KNP_CMD_CAT + 80
#define KNP_RES_DEC_KEY_HALF	    KNP_RES_CAT + 80	/* Key is half decrypted. */
#define KNP_RES_DEC_KEY_FULL   	    KNP_RES_CAT + 81	/* Key is fully decrypted. */
#define KNP_RES_DEC_KEY_POD_ERROR   KNP_RES_CAT + 82	/* The server cannot deliver the PoD. */
#define KNP_RES_DEC_KEY_BAD_PWD	    KNP_RES_CAT + 83    /* The password specified is wrong. */
#define KNP_RES_DEC_KEY_NOT_AUTH    KNP_RES_CAT + 84	/* The user is not listed as a recipient of the mail and 
    	    	    	    	    	    	    	 * thus the KPS refuses to return the key.
							 */
  
/* Get a workspace ticket. */
#define KNP_CMD_GET_KWS_TICKET	    KNP_CMD_CAT + 86
#define KNP_RES_GET_KWS_TICKET	    KNP_RES_CAT + 86	/* Ticket string included. */

/* Convert exchange addresses to SMTP addresses. */
#define KNP_CMD_CONVERT_EXCHANGE    KNP_CMD_CAT + 87    /* Nb addresses + list of addresses. */
#define KNP_RES_CONVERT_EXCHANGE    KNP_RES_CAT + 87    /* Nb addresses + list of addresses ("" if can't convert). */


  
/* A command was processed on the specified server but it failed. */
#define KNP_RES_FAIL	    	    KNP_RES_CAT + 90

/* The command cannot be processed because the plugin is too old. */
#define KNP_RES_UPGRADE_PLUGIN      KNP_RES_CAT + 91

/* The command cannot be processed because the KPS is too old. */
#define KNP_RES_UPGRADE_KPS 	    KNP_RES_CAT + 92

/* Mail part identifiers, used when encrypting mails or signing attachments. */
#define KNP_MAIL_PART_CAT 	    KNP_MAGIC_NUMBER + (4 << 8)
#define KNP_MAIL_PART_IMPLICIT	    KNP_MAIL_PART_CAT + 1
#define KNP_MAIL_PART_EXPLICIT	    KNP_MAIL_PART_CAT + 2
#define KNP_MAIL_PART_UNKNOWN	    KNP_MAIL_PART_CAT + 3
#define KNP_MAIL_PART_TEXT_BODY     KNP_MAIL_PART_CAT + 4
#define KNP_MAIL_PART_HTML_BODY     KNP_MAIL_PART_CAT + 5


/* Common definition of kpstr between K3P and KNP. */
#ifndef KPSTR
#define KPSTR
typedef struct kpstr
{
    	/* Length of the string. */
        int length;
	
	/* Data of the string, without the terminating '0'.
	 * Can be NULL if len == 0.
	 */
        char *data;
} kpstr;
#endif


/* Language codes used by the KNP. */
#define KNP_LANG_EN 0
#define KNP_LANG_FR 1


/* KNP object identifiers. */
#define KNP_UINT32  1
#define KNP_UINT64  2
#define KNP_STR     3


/* KNP message header used for commands and replies. */
struct knp_header {

    /* Version. */
    uint32_t major;
    uint32_t minor;

    /* Type of payload. */
    uint32_t type;

    /* Size of the payload. */
    uint32_t size;
};


/* The following structures define what goes on the wire.
 * Elements labelled with 'input' specify the data to send to the server.
 * Elements labelled with 'output' specify the data to receive from the server.
 */
struct knp_cmd_user_login {
    
    /* Input: user name. */
    kpstr user_name;
    
    /* Input: user login secret. */
    kpstr user_secret;
    
    /* Input: true if the secret is a password. */
    uint32_t secret_is_pwd;
    
    /* Output: the encrypted password. */
    kpstr encrypted_pwd;
};


struct knp_cmd_otut_login {
    
    /* Input: OTUT string. */
    kpstr otut;
};


struct knp_cmd_get_user_info {
    
    /* Output: member ID of the user. */
    uint64_t mid;
    
    /* Output: number of domain names of the organization. */
    uint32_t nb_domain;
    
    /* Output: domain names array. */
    kpstr *domain_array;
    
    /* Output: int 1 if address and port follow, int 0 if KPG is not used. */
};


struct knp_cmd_get_sign_key {
    
    /* Input: ID of the key to retrieve. */
    uint64_t key_id;
    
    /* Output: timestamp key data. */
    kpstr tm_key_data;
    
    /* Output: data of the key. */
    kpstr key_data;
    
    /* Output: owner name. */
    kpstr owner_name;
};


struct knp_cmd_get_enc_key_by_id {
    
    /* Input: ID of the key to retrieve. */
    uint64_t key_id;
    
    /* Output: timestamp key data. */
    kpstr tm_key_data;
    
    /* Output: data of the key. */
    kpstr key_data;
    
    /* Output: owner name. */
    kpstr owner_name;
};


struct knp_cmd_get_enc_key {
    
    /* Input: number of addresses. */
    uint32_t nb_address;
    
    /* Input: addresses array. */
    kpstr *address_array;
    
    /* Output: number of keys. */
    uint32_t nb_key;
    
    /* Output: key array. If an entry is empty, then no key is associated to
     * that address.
     */
    kpstr *key_array;
    
    /* Output: number of subscribers. */
    uint32_t nb_subscriber;
    
    /* Output: subscriber name array. */
    kpstr *subscriber_array;
};


/* This structure describes an email recipient in the knp_cmd_package_mail
 * structure below.
 */
struct knp_pkg_recipient {
    
    /* Address of the recipient, e.g. "left_part@right_part". */
    kpstr addr;

    /* If pkg_type includes KNP_PKG_TYPE_ENC, the encryption type:
     * public encryption key or password. Otherwise it's zero.
     */
#define KNP_PKG_ENC_CAT     KNP_MAGIC_NUMBER + (5 << 8)
#define KNP_PKG_ENC_KEY     KNP_PKG_ENC_CAT + 1
#define KNP_PKG_ENC_PWD     KNP_PKG_ENC_CAT + 2
    uint32_t enc_type;
    
    /* If enc_type == KNP_PKG_ENC_KEY, the public encryption key data. */
    kpstr enc_key_data;
};


/* This structure describes an email password in the knp_cmd_package_mail
 * structure below.
 */
struct knp_pkg_pwd {
    
    /* The password. */
    kpstr pwd;
    
    /* The OTUT string associated to the password. If the field is empty, there
     * is no OTUT.
     */
    kpstr otut;
};


/* This structure describes an attachment in the knp_cmd_package_mail
 * structure below.
 */
struct knp_pkg_attach {

    /* Attachment type: one of
     * KNP_MAIL_PART_IMPLICIT, 
     * KNP_MAIL_PART_EXPLICIT,
     * KNP_MAIL_PART_UNKNOWN.
     */
    uint32_t type;
    
    /* Encoding, if any. */
    kpstr encoding;
    
    /* Mime type. */
    kpstr mime_type;
    
    /* Attachment name. */
    kpstr name;
    
    /* Payload. */
    kpstr payload;
};


struct knp_cmd_package_mail {
    
    /* Input: packaging type: bitwise OR of
     * KNP_PKG_TYPE_ENC,
     * KNP_PKG_TYPE_POD.
     */
#define KNP_PKG_TYPE_ENC 1
#define KNP_PKG_TYPE_POD 2
    uint32_t pkg_type;
    
    /* Input: language used to package the message. This determines the language
     * of the message appearing in the "info" section of the packaged mail and
     * also the language used when returning a POD for that mail.
     */
    uint32_t lang;
    
    /* Input: raw TO field. */
    kpstr to_field;
    
    /* Input: raw CC field. */
    kpstr cc_field;
    
    /* Input: number of TOs and CCs. */
    uint32_t nb_recipient;
    
    /* Input: recipient array. */
    struct knp_pkg_recipient *recipient_array;
    
    /* Input: number of recipient passwords. */
    uint32_t nb_pwd;
    
    /* Input: array of passwords. */	
    struct knp_pkg_pwd *pwd_array;
    
    /* Input: from fields. */
    kpstr from_name;
    kpstr from_addr;
    
    /* Input: email subject. */
    kpstr subject;

    /* Input: email bodies: text only, HTML only, both text and HTML. */
#define KNP_PKG_BODY_CAT 	KNP_MAGIC_NUMBER + (6 << 8)
#define KNP_PKG_BODY_TEXT  	KNP_PKG_BODY_CAT + 1
#define KNP_PKG_BODY_HTML  	KNP_PKG_BODY_CAT + 2
#define KNP_PKG_BODY_BOTH  	KNP_PKG_BODY_CAT + 3
    uint32_t body_type;
    kpstr body_text;
    kpstr body_html;
   
    /* Input: number of attachments. */
    uint32_t nb_attach;
    
    /* Input: attachment array. */
    struct knp_pkg_attach *attach_array;
    
    /* PoD return address, if any. */
    kpstr pod_addr;
    
    /* Output: signature or encrypted body text. */
    kpstr pkg_output;
    
    /* Output: KSN of the packaged mail. */
    kpstr ksn;
    
    /* Output: symmetric key that can decrypt the mail, if any. */
    kpstr sym_key;
};


struct knp_cmd_get_otut_ticket {
    
    /* Input: total number of replies that can be issued with the OTUTs provided
     * by the ticket being requested. In other words, if you want to request two 
     * OTUTs, one with 3 replies allowed and another with 5 replies allowed, you
     * should specify 8 here.
     */
    uint32_t reply_count;
    
    /* Input: the address the user of the OTUT will be allowed to reply to. This
     * may be ignored by the KPS if it decides so.
     */
    kpstr reply_addr;
    
    /* Output: ticket. */
    kpstr ticket;
};


struct knp_cmd_get_otut_string {
    
    /* Input: OTUT ticket. */
    kpstr ticket;
    
    /* Input: number of OTUTs requested. */
    uint32_t in_otut_count;
    
    /* Input: array of integers specifying how many replies are associated to each OTUT. */
    uint32_t *reply_count_array;
    
    /* Output: number of OTUTs issued. */
    uint32_t out_otut_count;
    
    /* Output: array of OTUT strings. */
    kpstr *otut_array;
};


struct knp_cmd_validate_otut {
    
    /* Input: OTUT string to validate. */
    kpstr otut_string;
    
    /* Output: number of times the OTUT can still be used. This is 0 if the OTUT
     * cannot be used anymore.
     */
    uint32_t remaining_use_count;
};


struct knp_cmd_dec_sym_key {
    
    /* Input: signature text from the mail. */
    kpstr sig_text;
    
    /* Input: signature public key data from the mail. */
    kpstr pub_key_data;

    /* Input: timestamp public key that signed the above key. */
    kpstr pub_tm_key_data;

    /* Input: the intermediate symmetric key data, if any. This is required when
     * the key is encrypted with a public encryption key of a recipient and also
     * encrypted with the public signature key of the sender for PoD purposes.
     * First, the key is decrypted by the KPS, then decrypted by the KOS.
     */
    kpstr inter_sym_key_data;
    
    /* Input: password required to decrypt the mail, if any. */
    kpstr pwd;

    /* Input: address from which the PoD is sent, if any. */
    kpstr pod_from;
    
    /* Input: subject of the mail being decrypted. The subject is used when
     * a POD is returned.
     */
    kpstr subject;
    
    /* Input: True if a decryption email is wanted.
     */
    uint32_t want_dec_email;
    
    /* Output: the symmetric key data, either fully decrypted or partially
     * decrypted.
     */
    kpstr sym_key_data;
    
    /* Output: the OTUT associated to the password, if any. */
    kpstr otut;
    
    /* Output: the date (in seconds, UNIX epoch) at which the PoD was
     * delivered. This field must be 0 if no PoD was delivered.
     */
   uint32_t pod_date;
   
   /* Output: decryption email, if requested ("" if none). */
   kpstr dec_email;
};


/* When we package an email for encryption, we encrypt the text and/or HTML
 * bodies along with the attachments and put the resulting blob inside the plain
 * text body of the packaged email. At the reception end we need to restore the
 * encrypted elements. To do this we need to know what's inside the blob and
 * where. We use the following format to identity each entry in the blob: <64
 * bits magic> <b4 bits magic> <entry1> <entry2> ... <entryN>. The number of
 * entries is not recorded but can be deduced implicitely by checking where the
 * encrypted body ends. The format of the blob is the same as a KNP message.
 */
#define KNP_ENC_BODY_MAGIC 	 0x8945869276912348ll
 
struct knp_enc_body_entry {

    /* Mail part. */
    uint32_t mail_part;

    /* Encoding, if any. */
    kpstr encoding;

    /* Mime type. */
    kpstr mime_type;

    /* Name. Only used for implicit, explicit or unknown attachments. */
    kpstr name;
    
    /* Payload associated to this entry. */
    kpstr payload;
};

#endif
