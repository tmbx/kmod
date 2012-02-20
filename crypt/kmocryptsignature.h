/**
 * kmo/crypt/include/kmocryptsignature.h
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * Teambox Sign-On Server Daemon client process manager.
 *
 * @author Kristian Benoit
 */

/**
 * Version history:
 *
 * Version 1:
 * - First released version.
 * - Text body signed with kmod_newline2space().
 * - HTML body signed with kmod_merge_whitespace().
 *
 * Version 2:
 * - Text and HTML bodies signed with ().
  
 */

#ifndef __KMOCRYPTSIGNATURE_H__
#define __KMOCRYPTSIGNATURE_H__

/** To understand the structure of the KSP, you should read the grammar
 * defined in the signature format specifications.
 */

#include <gcrypt.h>
#include "kmocryptpkey.h"
#include "kmocryptsigcommon.h"
#ifdef __WINDOWS__
#include <winsock2.h>
#endif
#ifdef __GLIBC__
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#define MIN_SIGN_VERSION 1
#define MAX_SIGN_VERSION 2

typedef struct kmocrypt_packet kmocrypt_signature;

typedef struct kmocrypt_packet kmocrypt_packet;

/** Protocol version of the communication between KMOD and KPS.
 */
typedef struct kmocrypt_proto {
    uint32_t major;
    uint32_t minor;
} kmocrypt_proto;

/** A subpackets is a list of subpacket
 * \see the grammar.
 */
typedef struct kmocrypt_subpackets kmocrypt_subpackets;
struct kmocrypt_subpackets {
    kmocrypt_subpackets * subpackets; /** < FIXME: rename to next. */
    void                * subpacket;  /** < the data of the subpacket. */
};

/** The KSP type.
 */
struct kmocrypt_packet {
    /** The public key that will be used to verify the signature */
    //gcry_sexp_t           key;  

    /** Remove this please. -- Do it yourself, hippie!*/     
    uint32_t              magic;

    /** The major number of the packet format */
    uint32_t              major;     

    /** The minor number of the packet format */
    uint32_t              minor;     

    /** The mid of the user FIXME: rename to mid */
    uint64_t              keyid;         

    /** The s-expression to validate the signature. */
    gcry_sexp_t           sig_sexp;
    gcry_mpi_t            sig_mpi;

    /** The hash for the signature. */
    gcry_sexp_t           hash;

    /** The hash algorithm used in to hash data in the KSP */
    uint32_t              hash_algo; 

    /** The pkey algorithm, FIXME: remove. */
    uint32_t              sig_algo; 

    /** Packaging type */ 
    uint8_t               type;     

    /** A chained list of subpacket per subpacket type */
    kmocrypt_subpackets * subpackets[KMO_SP_NB_TYPE]; 
};

/**
 *
 */
struct kmocrypt_attachment {
    uint8_t * filename;
    size_t filename_len;

    uint8_t * encoding;
    size_t encoding_len;

    uint8_t * mime_type;
    size_t mime_type_len;

    uint8_t * payload;
    size_t payload_len;
};

/** Release the ressources held by the KSP.
 *
 * \param self the initialized KSP.
 */
void                kmocrypt_signature_clean    (kmocrypt_signature    *self);

/** Check the validity of a hashed field (from, to, text, ...)
 *
 * \param self the KSP containing the field to validate.
 * \param type the type of the field to validate (subpacket_type).
 * \param data the data to validate against the field in the KSP.
 * \param len the length of data in bytes.
 */
int                 kmocrypt_signature_check    (kmocrypt_signature    *self,
                                                 uint8_t                type,
                                                 uint8_t               *data,
                                                 uint32_t               len);

/** Verify the attachments. */
void kmocrypt_signature_check_attachments(kmocrypt_signature * self, karray * attch_array);

/** Get the protocol version of the communication between KMOD and KPS used at signature time.
 *
 * \param self the KSP containing the field to get.
 * \param major the returned major version of the protocol.
 * \param minor the returned minor version of the protocol.
 * \return 0 on success, -1 on error
 *
 * Set kmo_error on error.
 */
int                 kmocrypt_signature_get_proto (kmocrypt_signature   *self,
                                                  uint32_t             *major,
                                                  uint32_t             *minor);

/** Get the ip address of the sender.
 * 
 * \param self the KSP containing the field to get.
 * \param addr the returned address.
 * \return 0 on success, -1 on error
 *
 * Set kmo_error on error.
 */
int                 kmocrypt_signature_get_ip   (kmocrypt_signature    *self,
                                                 struct sockaddr       *addr);

typedef struct _kmocrypt_signature_mail_client {
    uint16_t product;
    uint16_t version;
    uint16_t release;
    uint16_t kpp_version;
} kmocrypt_signature_mail_client;
/** Get the mail client plugin id used to ask for this KSP.
 *
 * \param self the KSP containing the field to get.
 * \param mailer the returned mail client id.
 * \return 0 on success, -1 on error
 *
 * Sets kmo_error on error.
 */
int          kmocrypt_signature_get_mail_client (kmocrypt_signature             *self,
                                                 kmocrypt_signature_mail_client *mailer);

/** Check if a symmetric key exist for a specific mid in the KSP.
 *
 * \param self the KSP to check for the mid.
 * \param mid the member id to check.
 * \return 0 on success, -1 on error
 *
 * Set kmo_error on error.
 */
int                kmocrypt_sign_has_symkey_for (kmocrypt_signature    *self,
                                                 int64_t                mid);

/** Get the mid of the sender from a serialized KSP.
 *
 * \param str the serialized KSP.
 * \param len the length of the serialized KSP.
 * \return the senders mid or 0 on error (invalid packet).
 *
 * FIXME: keyid -> mid.
 */
uint64_t             kmocrypt_get_keyid          (unsigned char *str,
                                                 uint32_t len);

/** Check if a KSP contain a subpacket of a specifig type.
 *
 * \param self the KSP to check for a subpacket type.
 * \param type the subpacket type to check for availability.
 * \return 0 on success, -1 on error
 */
int                 kmocrypt_sign_contain       (kmocrypt_signature    *self,
                                                 enum subpacket_type    type);

int kmocrypt_signature_get_ksn(kmocrypt_signature * self, char ** ksn, size_t * ksn_s);
                          

int kmocrypt_signature_validate(kmocrypt_signature * sign, kmocrypt_pkey * key);

int kmocrypt_recognize_ksp (kmocrypt_packet *packet, kbuffer *buffer);


#endif /*__KMOCRYPTSIGNATURE_H__*/
