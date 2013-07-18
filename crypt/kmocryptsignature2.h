/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

/* Version history:
 *
 * Version 1:
 * - First released version.
 * - Text body signed with kmod_newline2space().
 * - HTML body signed with kmod_merge_whitespace().
 *
 * Version 2:
 * - Text and HTML bodies signed with kmod_trim_whitespace().
 * - Fixed signature format to be able to deal with unhandled packet types.
 */

/* To understand the structure of the KSP, you should read the grammar
 * defined in the signature format specifications.
 * LB: Which should be updated and made _clearer_.
 */

#ifndef __KMOCRYPTSIGNATURE2_H__
#define __KMOCRYPTSIGNATURE2_H__

#include <gcrypt.h>
#include "kmo_base.h"
#include "utils.h"
#include "kmocryptsigcommon.h"
#include "kmocryptpkey.h"

/* Protocol version of the communication between KMOD and KPS.
 * This is used for signature forensic purposes.
 */
struct kmocrypt_proto2 {
    uint32_t major;
    uint32_t minor;
};

/* This structure contains information that describes a mail client. */
struct kmocrypt_mail_client2 {
    uint16_t product;
    uint16_t version;
    uint16_t release;
    uint16_t kpp_version;   
};

/* Subpacket list inside the KSP. */
struct kmocrypt_subpacket_list2 {
    
    /* Pointer to the next subpacket, if any. */
    struct kmocrypt_subpacket_list2 *next;
    
    /* Data of the subpacket. */
    void *data;
};

/* This object represents the data contained in the signature of a Kryptiva
 * message. It is called the KSP (Kryptiva Signature Packet).
 */
struct kmocrypt_signature2 {
    
    /* The major number of the signature format. */
    uint32_t major;     

    /* The minor number of the signature format. */
    uint32_t minor;     

    /* Member ID. */
    uint64_t mid;

    /* The hash algorithm used to hash data in the KSP. */
    uint32_t hash_algo;
    
    /* The public key algorithm used to sign the signature. */
    uint32_t sig_algo;

    /* Packaging type */ 
    uint8_t  pkg_type;
    
    /* The s-expressions used to validate the signature. */
    gcry_sexp_t sig_sexp;
    gcry_mpi_t sig_mpi;

    /* The hash for the signature. */
    gcry_sexp_t sig_hash;

    /* Each slot of this array contains a chained list of subpackets of a given 
     * type.
     */
    struct kmocrypt_subpacket_list2 * subpacket_array[KMO_SP_NB_TYPE]; 
};

int kmocrypt_recognize_ksp2(struct kmocrypt_signature2 *self, kbuffer *buffer);
int kmocrypt_signature_validate2(struct kmocrypt_signature2 *self, kmocrypt_pkey *key);
int kmocrypt_signature_contain2(struct kmocrypt_signature2 *self, int type);
int kmocrypt_signature_check_hash2(struct kmocrypt_signature2 *self, int type, unsigned char *data, uint32_t len);
void kmocrypt_signature_check_attachments2(struct kmocrypt_signature2 *self, karray *attch_array);
int kmocrypt_signature_get_ksn2(struct kmocrypt_signature2 *self, char **ksn, size_t *len);
int kmocrypt_signature_get_ip2(struct kmocrypt_signature2 *self, struct sockaddr *addr);
int kmocrypt_signature_get_mail_client2(struct kmocrypt_signature2 *self, struct kmocrypt_mail_client2 *mailer);
int kmocrypt_signature_has_symkey_for2(struct kmocrypt_signature2 *self, uint64_t mid);
void kmocrypt_signature_free2(struct kmocrypt_signature2 *self);
void kmocrypt_get_kpg_host2(struct kmocrypt_signature2 *self, kstr *addr, int *port);

struct kmocrypt_signed_pkey {
    uint64_t mid;
    kmocrypt_pkey *key;
    struct timeval time;
    struct kmocrypt_signature2 sign;
};

struct kmocrypt_signed_pkey *kmocrypt_sign_get_pkey(kbuffer *buffer);
void kmocrypt_signed_pkey_destroy(struct kmocrypt_signed_pkey *signed_pkey);
int kmocrypt_signed_pkey_check(struct kmocrypt_signed_pkey *signed_pkey, kmocrypt_pkey *pkey);

#endif
