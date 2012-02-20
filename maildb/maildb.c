/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

#include <stdlib.h>
#include "maildb.h"

/* Allocate short string for some mail_info members, and set the others to 0
 */
void maildb_init_mail_info(maildb_mail_info *mail_info) {
    memset(mail_info, 0, sizeof(maildb_mail_info));
    kstr_init(&mail_info->msg_id);
    kstr_init(&mail_info->hash);
    kstr_init(&mail_info->ksn);
    kstr_init(&mail_info->sig_msg);
    kstr_init(&mail_info->attachment_status);
    kstr_init(&mail_info->sym_key);
    kstr_init(&mail_info->decryption_error_msg);
    kstr_init(&mail_info->pod_msg);
    kstr_init(&mail_info->otut_string);
    kstr_init(&mail_info->otut_msg);
    kstr_init(&mail_info->kpg_addr);
}

/* Get the mail to be ready to reuse.
 * Ensure that no string members in mail_info is longer than 1024 and other
 * members are 0
 */
void maildb_clear_mail_info(maildb_mail_info *mail_info) {
    kstr_shrink(&mail_info->msg_id, 1024);
    kstr_shrink(&mail_info->hash, 1024);
    kstr_shrink(&mail_info->ksn, 1024);
    mail_info->mid = 0;
    mail_info->original_packaging = 0;
    mail_info->mua = 0;
    mail_info->field_status = 0;
    mail_info->attachment_nbr = 0;
    kstr_shrink(&mail_info->sig_msg, 1024);
    kstr_shrink(&mail_info->attachment_status, 1024);
    kstr_shrink(&mail_info->sym_key, 1024);
    mail_info->encryption_status = 0;
    kstr_shrink(&mail_info->decryption_error_msg, 1024);
    mail_info->pod_status = 0;
    kstr_shrink(&mail_info->pod_msg, 1024);
    mail_info->otut_status = 0;
    kstr_shrink(&mail_info->otut_string, 1024);
    kstr_shrink(&mail_info->otut_msg, 1024);
    kstr_shrink(&mail_info->kpg_addr, 1024);
}

/* Free the strings members in mail_info */
void maildb_free_mail_info(maildb_mail_info *mail_info) {
    if (mail_info == NULL) return;
    
    kstr_free(&mail_info->msg_id);
    kstr_free(&mail_info->hash);
    kstr_free(&mail_info->ksn);
    kstr_free(&mail_info->sig_msg);
    kstr_free(&mail_info->attachment_status);
    kstr_free(&mail_info->sym_key);
    kstr_free(&mail_info->decryption_error_msg);
    kstr_free(&mail_info->pod_msg);
    kstr_free(&mail_info->otut_string);
    kstr_free(&mail_info->otut_msg);
    kstr_free(&mail_info->kpg_addr);
}

void maildb_init_sender_info(maildb_sender_info *sender_info) {
    kstr_init(&sender_info->name);
}

void maildb_clear_sender_info(maildb_sender_info *sender_info) {
    kstr_clear(&sender_info->name);
}

void maildb_free_sender_info(maildb_sender_info *sender_info) {
    if (sender_info == NULL) return;
    
    kstr_free(&sender_info->name);
}
