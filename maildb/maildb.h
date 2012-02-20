/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

#ifndef __KMOMAILDB_H__
#define __KMOMAILDB_H__

#include "kmo_base.h"

#define KMOMAILDB_VERSION 1

/** Email fields status bitfield (we store everything in 1 int).
 * Value 0: absent.
 * Value 1: changed.
 * Value 2: intact.
 * Value 3: oops.
 */
enum {
    MAILDB_STATUS_FROM_NAME     = 0,
    MAILDB_STATUS_FROM_ADDR     = 1,
    MAILDB_STATUS_TO	        = 2,
    MAILDB_STATUS_CC            = 3,
    MAILDB_STATUS_SUBJECT       = 4,
    MAILDB_STATUS_TEXT_BODY     = 5,
    MAILDB_STATUS_HTML_BODY     = 6
};

/** The content of a mail entry */
typedef struct _maildb_mail_info {
    int64_t	    	entry_id; /** < Entry ID of this object. It is set when writing / reading this object. */
    kstr                msg_id; /** < id of the mail seen by the mail client. */
    uint32_t            status; /** < 0: Kryptiva mail: invalid signature (all mail_info fields are meaningless, but 'sig_msg'),
    	    	    	    	  *   1: Kryptiva mail: valid signature (all mail_info fields have meanings),
				  *   2: Kryptiva mail: locally sent enc mail, to be able to read it (only the 'ksn' and 'sym_key' are meaningful),
				  *   3: Not a Kryptiva mail (all fields are meaningless).
				  */
    int32_t 	    	display_pref; /** < Mail display preference. */
    kstr    	    	sig_msg; /** < If the signature is not valid, the message explaining why. */
    kstr       		hash;	/** < Hash of the message. */
    kstr       	    	ksn;	/** < Kryptiva Serial Number included in the Kryptiva signature. 24 bytes. */
    int64_t             mid;   /** < mid of the sender */
    uint32_t            original_packaging; /** < packaging_type (sign|enc|pod|encnpod) */
    uint32_t            mua;   /** < mail user agent of the sender */
    uint32_t            field_status; /** < email fields status bitfield */
    uint32_t	    	att_plugin_nbr; /** < number of attachments sent by the plugin the last time. */
    uint32_t            attachment_nbr; /** < number of attachment written in the DB. */
    kstr                attachment_status; /** < attachment_status: (name length, name, status), ... */
    kstr                sym_key; /** < decrypted symmetric key */
    uint32_t            encryption_status; /** < is the message decrypted */
    kstr                decryption_error_msg; /** < message associated with the decryption of the message */
    uint32_t            pod_status; /** < is the message sent ? */
    kstr                pod_msg; /** < message associated with the pod. */
    uint32_t            otut_status; /** < is there an otut, is it used ? */
    kstr                otut_string; /** < OTUT raw string. */
    kstr                otut_msg; /** < message associated with the otut. */
    kstr                kpg_addr; /** True if there is a KPG address and port. */
    int                 kpg_port;
} maildb_mail_info;


/** Sender informations, an icon should be added */
typedef struct _maildb_sender {
    int64_t             mid;	    	    /* Member ID of the sender. */
    kstr                name;       	    /* Name of the sender. */
} maildb_sender_info;


/** A maildb is the object type that represent a database for storing the
 * status of the mail and the passwords.
 */
typedef struct _maildb {
    
    /* Internal database object. */
    void *db;
    
    /* Operations defined on the database. */
    struct _maildb_ops *ops;
} maildb;


/** Operations defined on the database. */
struct _maildb_ops {
    void (*destroy) 	    	(maildb                *mdb);

    int  (*set_mail_info)    	(maildb                *mdb,
                              	 maildb_mail_info      *mail_info);
    
    int  (*get_mail_info_from_entry_id) (maildb                *mdb,
                             	    	 maildb_mail_info      *mail_info,
                            	    	 int64_t               entry_id);
			      
    int  (*get_mail_info_from_msg_id) 	(maildb                *mdb,
                             	    	 maildb_mail_info      *mail_info,
                            	    	 kstr                  *msg_id);
    
    int  (*get_mail_info_from_hash) 	(maildb                *mdb,
                             	    	 maildb_mail_info      *mail_info,
                            	    	 kstr                  *hash,
					 kstr                  *ksn);
					 	      
    int  (*set_sender_info)  	(maildb                *mdb,
                             	 maildb_sender_info    *sender_info);
			      
    int  (*get_sender_info) 	(maildb                *mdb,
                             	 maildb_sender_info    *sender_info,
                             	 int64_t                mid);
			      
    int  (*rm_sender_info)      (maildb                *mdb,
                                 int64_t                mid);
			      
    int  (*set_pwd)             (maildb                *mdb,
                                 kstr                  *email,
                                 kstr                  *pwd);
			      
    int  (*get_pwd)             (maildb                *mdb,
                                 kstr                  *email,
                                 kstr                  *pwd);
    
    int  (*get_all_pwd)     	(maildb     	       *mdb,
    	    	    	    	 karray     	       *addr_array,
				 karray     	       *pwd_array);
    
    int  (*rm_pwd)   	    	(maildb                *mdb,
    	    	    	    	 kstr                  *email);
};

maildb * maildb_sqlite_new(char *db_name);

static inline void maildb_destroy(maildb *mdb) {
    mdb->ops->destroy(mdb);
}

static inline int maildb_set_mail_info(maildb *mdb, maildb_mail_info *mail_info) {
    return mdb->ops->set_mail_info (mdb, mail_info);
}

static inline int maildb_get_mail_info_from_entry_id(maildb *mdb, maildb_mail_info *mail_info, int64_t entry_id) {
    return mdb->ops->get_mail_info_from_entry_id(mdb, mail_info, entry_id);
}

static inline int maildb_get_mail_info_from_msg_id(maildb *mdb, maildb_mail_info *mail_info, kstr *msg_id) {
    return mdb->ops->get_mail_info_from_msg_id(mdb, mail_info, msg_id);
}

static inline int maildb_get_mail_info_from_hash(maildb *mdb, maildb_mail_info *mail_info, 
    	    	    	    	    	    	 kstr *hash, kstr *ksn) {
    return mdb->ops->get_mail_info_from_hash(mdb, mail_info, hash, ksn);
}

static inline int maildb_set_sender_info(maildb *mdb, maildb_sender_info *sender_info) {
    return mdb->ops->set_sender_info (mdb, sender_info);
}

static inline int maildb_get_sender_info(maildb *mdb, maildb_sender_info *sender_info, uint64_t mid) {
    return mdb->ops->get_sender_info (mdb, sender_info, mid);
}

static inline int maildb_rm_sender_info(maildb *mdb, int64_t mid) {
    return mdb->ops->rm_sender_info (mdb, mid);
}

static inline int maildb_set_pwd(maildb *mdb, kstr *email, kstr *pwd) {
    return mdb->ops->set_pwd (mdb, email, pwd);
}

static inline int maildb_get_pwd(maildb *mdb, kstr *email, kstr *pwd) { 
    return mdb->ops->get_pwd (mdb, email, pwd);
}

static inline int maildb_get_all_pwd(maildb *mdb, karray *addr_array, karray *pwd_array) { 
    return mdb->ops->get_all_pwd (mdb, addr_array, pwd_array);
}

static inline int maildb_rm_pwd(maildb *mdb, kstr *email) { 
    return mdb->ops->rm_pwd(mdb, email);
}

void maildb_init_mail_info(maildb_mail_info *mail_info);
void maildb_clear_mail_info(maildb_mail_info *mail_info);
void maildb_free_mail_info(maildb_mail_info *mail_info);
void maildb_init_sender_info(maildb_sender_info *sender_info);
void maildb_clear_sender_info(maildb_sender_info *sender_info);
void maildb_free_sender_info(maildb_sender_info *sender_info);

#endif

