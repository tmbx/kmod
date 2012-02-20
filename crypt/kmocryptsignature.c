/**
 * kmo/crypt/kmocryptsignature.c
 * Copyright (C) 2005-2012 Opersys inc., All rights reserved.
 *
 * Teambox Sign-On Server Daemon client process manager.
 *
 * @author Kristian Benoit
 * @author François-Denis Gonthier
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "kmocryptsignature.h"
#include "kmocryptversion.h"
#include "kmo_base.h"
#include "utils.h"
#ifdef __WINDOWS__
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
/* Those 2 files bind Crypt to the core of KMO.  That may not be a good thing
   on the long run but I think we can live with it for now. */
#include "k3p_core_defs.h"
#include "k3p.h"

#define MAX_DIGEST_LEN 64

/* SUBPACKETS DECLARATION */
void kmocrypt_clean_subpackets (kmocrypt_packet *packet);

typedef int(*recognize_fct) (kmocrypt_signature    *sign,
                             kbuffer       *buffer,
                             void                 **subpacket_ret,
                             uint32_t              *ret_len);

typedef void(*clean_fct)    (kmocrypt_signature    *sign,
                             void                  *subpacket);

typedef void*(*oper_fct)    (kmocrypt_signature    *sign,
                             void                  *subpacket,
                             void                  *params);


struct subpackets_ops {
    recognize_fct  recognize;
    clean_fct      clean;
};

/* HASH */

static int recognize_hash (kmocrypt_signature * sign,
                           kbuffer            * buffer,
                           void              ** subpacket_ret,
                           uint32_t           * ret_len) {
    uint8_t *hash;
    if (buffer->len - buffer->pos < sizeof (uint32_t)) {
        kmo_seterror ("signature buffer is too short");
        return -1;
    }
    
    *ret_len = (uint32_t)gcry_md_get_algo_dlen(sign->hash_algo);

    if (buffer->len - buffer->pos < *ret_len) {
        kmo_seterror ("signature buffer is too short");
        return -1;
    }

    hash = (unsigned char *)kmo_malloc (*ret_len);
    kbuffer_read (buffer, hash, *ret_len);

    *subpacket_ret = (void *)hash;

    return 0;
}

static int check_hash (kmocrypt_signature  *self,
                       uint8_t             *hash,
                       uint32_t             len,
                       uint8_t             *data)
{
    int retval = -1;
    uint8_t digest[MAX_DIGEST_LEN];
    assert (MAX_DIGEST_LEN >= gcry_md_get_algo_dlen (self->hash_algo));
    gcry_md_hash_buffer (self->hash_algo, digest, data, len);
    if (memcmp (hash,
                digest,
                gcry_md_get_algo_dlen (self->hash_algo))
        == 0)
        retval = 0;
    else
        kmo_seterror ("invalid hash");

    return retval;
}

static void clean_simple_free (kmocrypt_signature  *sign,
                               void                *subpacket)
{
    free (subpacket);
}

static struct subpackets_ops hash_ops = {
    recognize_hash,
    clean_simple_free
};

/* PODTO */

static int recognize_podto(kmocrypt_signature * sign,
                           kbuffer * buffer,
                           void ** subpacket_ret,
                           uint32_t * ret_len) {
    uint32_t len;

    /* Skip the length of the PoD address. */

    if (buffer->len - buffer->pos < sizeof(uint32_t)) {
        kmo_seterror("ksp buffer is too short");
        return -1;
    }

    len = kbuffer_read32(buffer);

    if (buffer->len < len) {
        kmo_seterror("ksp buffer is too short");
        return -1;
    }

    kbuffer_seek(buffer, len, SEEK_CUR);

    *ret_len = (len + sizeof(uint32_t));
    *subpacket_ret = NULL;
        
    return 0;   
}

static struct subpackets_ops podto_ops = {
    recognize_podto,
    NULL
};

/* PROTO */

static int recognize_proto (kmocrypt_signature      *sign,
                            kbuffer         *buffer,
                            void                   **subpacket_ret,
                            uint32_t                *ret_len)
{
    kmocrypt_proto *proto;
    if (buffer->len - buffer->pos < 2 * sizeof (uint32_t)) {
        kmo_seterror ("ksp buffer is too short");
        return -1;
    }
    proto = (kmocrypt_proto *)kmo_malloc (sizeof(kmocrypt_proto));
    proto->major = kbuffer_read32 (buffer);
    proto->minor = kbuffer_read32 (buffer);
    *subpacket_ret = (void *)proto;
    *ret_len = 2 * sizeof (uint32_t);
    return 0;
}

static int get_proto (kmocrypt_proto *proto, uint32_t *major, uint32_t *minor)
{
    *major = proto->major;
    *minor = proto->minor;
    return 0;
}

static struct subpackets_ops proto_ops = {
    recognize_proto,
    clean_simple_free
};

/* IPV4/IPV6 */

#ifdef __WINDOWS__
#define in_addr_t IN_ADDR
#endif

static int recognize_ipv4 (kmocrypt_signature      *sign,
                           kbuffer                 *buffer,
                           void                   **subpacket_ret,
                           uint32_t                *ret_len)
{
    in_addr_t *ipv4;
    if (buffer->len - buffer->pos < sizeof (in_addr_t)) {
        kmo_seterror ("ksp buffer is too short");
        return -1;
    }
    ipv4 = (in_addr_t *)kmo_malloc (sizeof(in_addr_t));
    kbuffer_read (buffer, (uint8_t *)ipv4, sizeof(in_addr_t));
    *subpacket_ret = (void*)ipv4;
    *ret_len = sizeof(in_addr_t);
    return 0;
}

static int recognize_ipv6 (kmocrypt_signature      *sign,
                           kbuffer                 *buffer,
                           void                   **subpacket_ret,
                           uint32_t                *ret_len)
{
    struct in6_addr *ipv6;
    if (buffer->len - buffer->pos < sizeof (struct in6_addr)) {
        kmo_seterror ("ksp buffer is too short");
        return -1;
    }
    ipv6 = (struct in6_addr *)kmo_malloc (sizeof(struct in6_addr));
    kbuffer_read (buffer, (uint8_t *)ipv6, sizeof(struct in6_addr));
    *subpacket_ret = (void*)ipv6;
    *ret_len = sizeof(struct in6_addr);
    return 0;
}

static struct subpackets_ops ipv4_ops = {
    recognize_ipv4,
    clean_simple_free
};

static struct subpackets_ops ipv6_ops = {
    recognize_ipv6,
    clean_simple_free
};

/* Attachments */
static int recognize_attachment(kmocrypt_signature * sign,
                                kbuffer * buffer,
                                void ** subpacket_ret,
                                uint32_t * ret_len) {
    uint8_t * hash;

    if (buffer->len - buffer->pos < sizeof(uint32_t)) {
        kmo_seterror("signature buffer is too short");
        return -1;
    }

    *ret_len = (uint32_t)gcry_md_get_algo_dlen(sign->hash_algo) * 2;

    if (buffer->len - buffer->pos < *ret_len) {
        kmo_seterror("signature buffer is too short");
        return -1;
    }

    hash = (uint8_t *)kmo_malloc(*ret_len);
    kbuffer_read(buffer, hash, *ret_len);

    *subpacket_ret = (void *)hash;

    return 0;
}

static struct subpackets_ops attachment_ops = {
    recognize_attachment,
    clean_simple_free
};

/* KSN */
static int recognize_ksn(kmocrypt_signature * sign,
                         kbuffer * buffer,
                         void ** subpacket_ret,
                         uint32_t * ret_len) {
    char * ksn;

    if (buffer->len - buffer->pos < KMOCRYPT_KSN_SIZE) {
        kmo_seterror("ksp_buffer is too short");
        return -1;
    }

    ksn = kmo_malloc(KMOCRYPT_KSN_SIZE);
    kbuffer_read(buffer, (uint8_t *)ksn, KMOCRYPT_KSN_SIZE);
    *subpacket_ret = (void *)ksn;
    *ret_len = KMOCRYPT_KSN_SIZE;

    return 0;
}

static struct subpackets_ops ksn_ops = {
    recognize_ksn,
    clean_simple_free
};

/* mail client */

static int recognize_mail_client (kmocrypt_signature      *sign,
                                  kbuffer                 *buffer,
                                  void                   **subpacket_ret,
                                  uint32_t                *ret_len)
{
    kmocrypt_signature_mail_client *client;
    if (buffer->len - buffer->pos < sizeof (kmocrypt_signature_mail_client)) {
        kmo_seterror ("ksp buffer is too short");
        return -1;
    }
    client = (kmocrypt_signature_mail_client *)kmo_malloc (sizeof(kmocrypt_signature_mail_client));

    client->product     = kbuffer_read16 (buffer);
    client->version     = kbuffer_read16 (buffer);
    client->release     = kbuffer_read16 (buffer);
    client->kpp_version = kbuffer_read16 (buffer);

    *subpacket_ret = (void*)client;
    *ret_len = sizeof(kmocrypt_signature_mail_client);
    return 0;
}

static struct subpackets_ops mail_client_ops = {
    recognize_mail_client,
    clean_simple_free
};

/* symkey */

static int recognize_symkey (kmocrypt_signature      *sign,
                             kbuffer                 *buffer,
                             void                   **subpacket_ret,
                             uint32_t                *ret_len)
{
    int64_t *keyid = (int64_t *)kmo_malloc (sizeof (int64_t));
    uint32_t len;

    if (buffer->len - buffer->pos < sizeof (int64_t) + sizeof(uint32_t)) {
        kmo_seterror ("ksp buffer is too short");
        return -1;
    }
    *keyid = kbuffer_read64 (buffer);
    len = kbuffer_read32 (buffer);
    if (buffer->len - buffer->pos < len) {
        kmo_seterror ("ksp buffer is too short");
        return -1;
    }
    kbuffer_seek (buffer, len, SEEK_CUR);
    *ret_len = sizeof (uint64_t) + sizeof (uint32_t) + len;
    *subpacket_ret = keyid;
    
    return 0;
}

static struct subpackets_ops symkey_ops = {
    recognize_symkey,
    clean_simple_free
};

/* SND_SYMKEY */
static int recognize_snd_symkey (kmocrypt_signature      *sign,
                                 kbuffer                 *buffer,
                                 void                   **subpacket_ret,
                                 uint32_t                *ret_len) {
    uint32_t len;

    if (buffer->len - buffer->pos < sizeof (uint32_t)) {
        kmo_seterror ("ksp buffer is too short");
        return -1;
    }
    len = kbuffer_read32 (buffer);
    if (buffer->len - buffer->pos < len) {
        kmo_seterror ("ksp buffer is too short");
        return -1;
    }
    kbuffer_seek (buffer, len, SEEK_CUR);
    *ret_len = sizeof (uint32_t) + len;
    *subpacket_ret = NULL;
    
    return 0;
}

static struct subpackets_ops snd_symkey_ops = {
    recognize_snd_symkey,
    NULL
};

/* TODO: kmo might have to deal with blobs, but not for now. (key signing and token signing is not for kmo). */
static int recognize_blob (kmocrypt_signature * sign,
                           kbuffer            * buffer,
                           void              ** subpacket_ret,
                           uint32_t           * ret_len) {
    uint32_t len;

    
    if (buffer->len - buffer->pos < sizeof (uint32_t)) {
        kmo_seterror ("ksp buffer is too short");
        return -1;
    }
    kbuffer_read32 (buffer);
    if (buffer->len - buffer->pos < sizeof (uint32_t)) {
        kmo_seterror ("ksp buffer is too short");
        return -1;
    }
    len = kbuffer_read32 (buffer);
    if (buffer->len - buffer->pos < len) {
        kmo_seterror ("ksp buffer is too short");
        return -1;
    }
    kbuffer_seek (buffer, len, SEEK_CUR);
    *ret_len = 2 * sizeof (uint32_t) + len;
    *subpacket_ret = NULL;
    
    return 0;
}


static struct subpackets_ops blob_ops = {
    recognize_blob,
    NULL
};
static struct subpackets_ops *subpackets_ops[KMO_SP_NB_TYPE] = {
    NULL,               /* INVALID */
    &proto_ops,         /* KMO_SP_TYPE_PROTO */
    &hash_ops,          /* KMO_SP_TYPE_FROM_NAME */
    &hash_ops,          /* KMO_SP_TYPE_FROM_ADDR */
    &hash_ops,          /* KMO_SP_TYPE_TO */
    &hash_ops,          /* KMO_SP_TYPE_CC */
    &hash_ops,          /* KMO_SP_TYPE_SUBJECT */
    &hash_ops,          /* KMO_SP_TYPE_PLAIN */
    &hash_ops,          /* KMO_SP_TYPE_HTML */
    &ipv4_ops,          /* KMO_SP_TYPE_IPV4 */
    &ipv6_ops,          /* KMO_SP_TYPE_IPV6 */
    &attachment_ops,    /* KMO_SP_TYPE_ATTACHMENT */
    &symkey_ops,        /* KMO_SP_TYPE_SYMKEY */
    &snd_symkey_ops,    /* KMO_SP_TYPE_SND_SYMKEY */
    &snd_symkey_ops,    /* KMO_SP_TYPE_PASSWD */
    &mail_client_ops,   /* KMO_SP_TYPE_MAIL_CLIENT */
    &blob_ops,          /* KMO_SP_TYPE_BLOB */
    &ksn_ops,           /* KMO_SP_TYPE_KSN */ 
    &podto_ops          /* KMO_SP_TYPE_PODTO */
};

static int recognize_subpackets (kmocrypt_signature *sign,
                                 kbuffer *buffer,
                                 uint32_t *ret_len)
{
    uint32_t tmp_len = 0;
    kmocrypt_subpackets *tmp_subpackets = NULL;

    while (*ret_len > 0) {
        uint8_t type = kbuffer_read8 (buffer);
        (*ret_len)--;
        void *subpacket;
 
        if (!subpackets_ops[type]) {
            kmo_seterror("unhandled packet type (%d)", type);
            goto err;
        }

        if (subpackets_ops[type]->recognize (sign, buffer, &subpacket, &tmp_len)) 
            goto err;
        
        assert (type < KMO_SP_NB_TYPE);

        tmp_subpackets = sign->subpackets[type];
        sign->subpackets[type] = (kmocrypt_subpackets *)kmo_malloc (sizeof(kmocrypt_subpackets));
        sign->subpackets[type]->subpackets = tmp_subpackets;

        sign->subpackets[type]->subpacket = subpacket;
        
        *ret_len -= tmp_len;
    }

    return 0;
err:
    kmocrypt_clean_subpackets (sign);
    return -1;
}

#define MAX_SIG_ALGO_NAME_LEN 32
#define MAX_HASH_ALGO_NAME_LEN 32

/**
 * Reads the RSA hash from the email signature.  This function prepare
 * everything but does not actually validate the signature.
 * kmocrypt_signature_validate() does the validation, so make sure the signature
 * has been validated before calling kmocrypt_signature_check() since the result
 * you'll get would be pretty much meaningless.
 */
static int recognize_rsa(kmocrypt_signature * sign, kbuffer * buffer) {
    int err = 0;
    uint32_t len = kbuffer_read32 (buffer);
    size_t nscanned;

    char signame[MAX_SIG_ALGO_NAME_LEN];
    
    strncpy(signame, gcry_pk_algo_name (sign->sig_algo), MAX_SIG_ALGO_NAME_LEN);

    strntolower(signame, MAX_SIG_ALGO_NAME_LEN);
    
    if (buffer->len - buffer->pos < len) {
        kmo_seterror ("ksp buffer is too short");
        return -1;
    }

    /* Get the signature. */
    if (gcry_mpi_scan(&sign->sig_mpi, GCRYMPI_FMT_PGP, kbuffer_current_pos(buffer), (size_t)len, &nscanned)) {
    	kmo_seterror("invalid MPI in signature");
	return -1;
    }
    
    kbuffer_seek(buffer, nscanned, SEEK_CUR);
    
    if (gcry_sexp_build(&sign->sig_sexp, NULL, "(7:sig-val(%s (1:s %m)))", signame, sign->sig_mpi)) {
    	kmo_seterror("cannot build signature from MPI");
	return -1;
    }

    return err;
}

static int recognize_signature(kmocrypt_signature * sign,
                               kbuffer * buffer,
                               uint32_t * ret_len) {
    int result = -1;
    int digest_len = gcry_md_get_algo_dlen(sign->hash_algo);
    unsigned char *digest = (unsigned char *)kmo_malloc(digest_len); 
    char hashname[MAX_HASH_ALGO_NAME_LEN];

    strncpy(hashname, gcry_md_algo_name (sign->hash_algo), MAX_HASH_ALGO_NAME_LEN);

    strntolower(hashname, MAX_HASH_ALGO_NAME_LEN);

    gcry_md_hash_buffer(sign->hash_algo, digest, buffer->data, buffer->pos);
    result = gcry_sexp_build(&sign->hash, NULL, "(4:data(5:flags5:pkcs1)(4:hash %s %b))", 
                             hashname, digest_len, digest);

    if (result) {
        kmo_seterror(gcry_strerror(result));
        goto end;
    }

    /* This is rather useless. */
    switch (sign->sig_algo) {
        case GCRY_AC_RSA:
            result = recognize_rsa(sign, buffer);
            break;
        case GCRY_AC_DSA:
        default:
            break;
    }

 end:
    free(digest);
    return result;
}

int kmocrypt_recognize_ksp (kmocrypt_packet *packet, kbuffer *buffer)
{
    uint32_t tmp_len;
    uint32_t ret_len;
    uint32_t subpackets_pos;

    if (buffer->len < 5*sizeof(uint32_t)+2*sizeof(uint64_t)) {
        kmo_seterror ("ksp buffer is too short");
        return -1;
    }

    /* MAGIC */
    packet->magic = kbuffer_read32 (buffer);
    if (packet->magic != KMOCRYPT_PACKET_MAGIC_NUM) {
        kmo_seterror ("invalid ksp magic number");
        return -1;
    }

    /* MAJOR */
    packet->major= kbuffer_read32 (buffer);
    if (packet->major < MIN_SIGN_VERSION || packet->major > MAX_SIGN_VERSION) {
        kmo_seterror ("unsupported ksp version");
        return -2;
    }

    /* MINOR */
    packet->minor = kbuffer_read32 (buffer);

    /* KEYID */
    packet->keyid = kbuffer_read64 (buffer);
    
    if (packet->keyid == 0) {
    	kmo_seterror("invalid key ID");
	return -1;
    }

    /* HASH_ALGO */
    packet->hash_algo = kbuffer_read8 (buffer);
    if (gcry_md_test_algo (packet->hash_algo)) {
        kmo_seterror ("unsupported hash algorithm");
        return -1;
    }

    /* SIG_ALGO */
    packet->sig_algo = kbuffer_read8 (buffer);
    if (gcry_pk_test_algo (packet->sig_algo)) {
        kmo_seterror ("unsupported signature algorithm");
        return -1;
    }

    /* PACKET_TYPE */
    packet->type = kbuffer_read8 (buffer);
    if (packet->type >= KMO_P_NB_TYPE) {
        kmo_seterror ("invalid signature packet type");
        return -1;
    }

    /* SUBPACKET_LEN */
    tmp_len = kbuffer_read32 (buffer);
    if (!tmp_len) {
        kmo_seterror ("no data in ksp");
        return -1;
    }

    subpackets_pos = kbuffer_tell (buffer);

    kbuffer_seek (buffer, tmp_len, SEEK_CUR);

    if (kbuffer_tell (buffer) != subpackets_pos + tmp_len) {
        kmo_seterror ("ksp buffer too short");
        return -1;
    }

    if (recognize_signature (packet, buffer, &ret_len))
        return -1;

    if (!kbuffer_eof(buffer)) {
        kmo_seterror ("data left at the end of ksp");
        return -1;
    }

    kbuffer_seek (buffer, subpackets_pos, SEEK_SET);

    memset (&packet->subpackets, 0, KMO_SP_NB_TYPE * sizeof (kmocrypt_subpackets *));
    if (recognize_subpackets (packet, buffer, &tmp_len)) {
        return -1;
    }

    return 0;

}

/* operation on type */
int kmocrypt_signature_check (kmocrypt_signature * self,
                              uint8_t              type,
                              uint8_t            * data,
                              uint32_t             len) {
    /* Make sure the type of the subpacket is valid and that it is
       checkable. */
    assert(!(type <= KMO_SP_INVALID_TYPE || type >= KMO_SP_NB_TYPE || 
             subpackets_ops[type]->recognize != recognize_hash));

    if (!self->subpackets[type]) {
        kmo_seterror ("unavailable type %i in ksp", type);
        return -1;
    }

    return check_hash(self, self->subpackets[type]->subpacket, len, data);
}

struct kmocrypt_attachment_hash {
    uint8_t name_hash[MAX_DIGEST_LEN];
    uint8_t payload_hash[MAX_DIGEST_LEN];
};

/**
 * First loop, try to make name/payload match.  Attachments that match here are
 * valid attachments.
 */
static void sig_check_attachments_name_payload(kmocrypt_signature * self, 
                                               size_t spkt_cnt,
                                               karray * attch_array, 
                                               int * sig_seen, 
                                               int * kmo_seen,
                                               struct kmocrypt_attachment_hash * attch_cache) {
    int i;
    size_t n, j;
    kmocrypt_subpackets * sp;
    uint8_t * att_hash;
    struct kmod_attachment * att;

    n = gcry_md_get_algo_dlen(self->hash_algo);

    for (i = 0; i < attch_array->size; i++) {
        att = (struct kmod_attachment *) attch_array->data[i];

        /* If the attachment has already been marked as seen, probably 
           because it was faulty, we skip it. */
        if (kmo_seen[i] == 1)
            continue;

        /* Hash the KMO name and payloads. */
        gcry_md_hash_buffer(self->hash_algo, attch_cache[i].name_hash, 
                            att->name->data, att->name->slen);
        gcry_md_hash_buffer(self->hash_algo, attch_cache[i].payload_hash,
                            att->data->data, att->data->slen);    

        sp = self->subpackets[KMO_SP_TYPE_ATTACHMENT];

        /* Loop through all the attachments. */
        for (j = 0; j < spkt_cnt; j++) {
	    att_hash = sp->subpacket;
	    
            /* Move to next in case there was a match on this signed
               attachment. */
            if (sig_seen[j] == 0) {

                /* If the filename hash match... */
                if (memcmp(att_hash, attch_cache[i].name_hash, n) == 0 && 
                    memcmp(att_hash + n, attch_cache[i].payload_hash, n) == 0) {
		    
                    att->status = KMO_EVAL_ATTACHMENT_INTACT;
                    kmo_seen[i] = 1;
                    sig_seen[j] = 1;
		    break;
                }
            }
            
	    
	    sp = sp->subpackets;
        }
    }
}

/**
 * Second loop, matches attachment by name.  Attachments that match only by name
 * are considered to have an invalid payload.
 */
static void sig_check_attachments_name(kmocrypt_signature * self,
                                       size_t spkt_cnt, 
                                       karray * attch_array, 
                                       int * sig_seen, 
                                       int * kmo_seen,
                                       struct kmocrypt_attachment_hash * attch_cache) {
    int i;
    size_t n, j;
    uint8_t * att_hash;
    kmocrypt_subpackets * sp;
    struct kmod_attachment * att;

    n = gcry_md_get_algo_dlen(self->hash_algo);

    for (i = 0; i < attch_array->size; i++) {
        att = (struct kmod_attachment *) attch_array->data[i];

        /* If the attachment has already been seen above, move to next. */        
        if (kmo_seen[i] == 1) 
            continue;

        sp = self->subpackets[KMO_SP_TYPE_ATTACHMENT];
        
        for (j = 0; j < spkt_cnt; j++) {
	    att_hash = sp->subpacket;
	    
            /* If the signature attachment has already been seen above, move to
               the next element in the signature. */
            if (sig_seen[j] == 0) {
                
                /* If the filename hash matches... */
                if (memcmp(att_hash, attch_cache[i].name_hash, n) == 0) {
                    att->status = KMO_EVAL_ATTACHMENT_MODIFIED;
                    kmo_seen[i] = 1;
                    sig_seen[j] = 1;
		    break;
                }
            }

            sp = sp->subpackets;           
        }
    }    
}

/**
 * Third loop, matches attachment by payload.  Attachments that only match by
 * payload are considered to have an invalid name.
 */
static void sig_check_attachments_payload(kmocrypt_signature * self, 
                                          size_t spkt_cnt,
                                          karray * attch_array, 
                                          int * sig_seen, 
                                          int * kmo_seen,
                                          struct kmocrypt_attachment_hash * attch_cache) {
    int i;
    size_t n, j;
    kmocrypt_subpackets * sp;
    uint8_t * att_hash;
    struct kmod_attachment * att;

    n = gcry_md_get_algo_dlen(self->hash_algo);

    for (i = 0; i < attch_array->size; i++) {
        att = (struct kmod_attachment *) attch_array->data[i];

        /* If the attachment has already been seen above, move to next. */        
        if (kmo_seen[i] == 1) 
            continue;

        /* Hash the KMO name and payloads. */
        sp = self->subpackets[KMO_SP_TYPE_ATTACHMENT];

        for (j = 0; j < spkt_cnt; j++) {
	    att_hash = sp->subpacket + n;
 
            /* If the signature attachment has already been seen above, move to
               the next element in the signature. */
            if (sig_seen[j] == 0) {                

		/* If the payload hash matches... */
                if (memcmp(att_hash, attch_cache[i].payload_hash, n) == 0) {
                    att->status = KMO_EVAL_ATTACHMENT_MODIFIED;
                    kmo_seen[i] = 1;
                    sig_seen[j] = 1;
		    break;
                }
            }

            sp = sp->subpackets;
        }
    }    
}

void kmocrypt_signature_check_attachments(kmocrypt_signature * self, karray * attch_array) {
    int i = 0;
    size_t spkt_cnt = 0;
    int * sig_seen, * kmo_seen;
    struct kmocrypt_attachment_hash * attch_cache;
    struct kmod_attachment * att;
    kmocrypt_subpackets * sp;
    
    /* If there are no attachments in the signature, then any attachment sent by
       the plugin needs to be viewed as injected. */
    if (self->subpackets[KMO_SP_TYPE_ATTACHMENT] == NULL) {
        for (i = 0; i < attch_array->size; i++) {
	    att = (struct kmod_attachment *) attch_array->data[i];
	    
            if (att->status != KMO_EVAL_ATTACHMENT_ERROR) {
	    	att->status = KMO_EVAL_ATTACHMENT_INJECTED;
	    }
	}
        
        /* No need to do any further processing at this point. */
        return;
    }

    /* Count the attachments in the signature. */
    sp = self->subpackets[KMO_SP_TYPE_ATTACHMENT];
    do {
        spkt_cnt++;
	sp = sp->subpackets;
    } while (sp != NULL);

    /* Allocate the seen array and the hash-cache array. */
    sig_seen = kmo_calloc(spkt_cnt * sizeof(uint32_t));
    kmo_seen = kmo_calloc(attch_array->size * sizeof(uint32_t));
    attch_cache = kmo_calloc(attch_array->size * sizeof(struct kmocrypt_attachment_hash));

    /* Mark all faulty attachments sent by KMO as seen so we don't need to care
       about them later. */
    for (i = 0; i < attch_array->size; i++) {
        att = (struct kmod_attachment *) attch_array->data[i];        

        if (att->status == KMO_EVAL_ATTACHMENT_ERROR) 
            kmo_seen[i] = 1;
    }

    /* Check the name/payload matches. */
    sig_check_attachments_name_payload(self, spkt_cnt, attch_array, sig_seen, kmo_seen, attch_cache);
    
    /* Check name-only matches (potentially changed payloads). */
    sig_check_attachments_name(self, spkt_cnt, attch_array, sig_seen, kmo_seen, attch_cache);
    
    /* Check payload matches (potentially changed names). */
    sig_check_attachments_payload(self, spkt_cnt, attch_array, sig_seen, kmo_seen, attch_cache);

    /* Search for injected attachments in what KMO has sent. */
    for (i = 0; i < attch_array->size; i++) {
        att = (struct kmod_attachment *) attch_array->data[i];     

        if (kmo_seen[i] == 0) 
            att->status = KMO_EVAL_ATTACHMENT_INJECTED;
    }
    
    /* Search for dropped attachments in the signature. */
    for (i = 0; i < (int) spkt_cnt; i++) {
        if (sig_seen[i] == 0) {
            /* Append an item saying that an attachment was dropped. */
            att = (struct kmod_attachment *) kmo_calloc(sizeof(struct kmod_attachment));
            att->status = KMO_EVAL_ATTACHMENT_DROPPED;
	    att->name = kstr_new();
            karray_add(attch_array, att);
        }
    }

    /* Cleanup. */
    free(attch_cache);
    free(kmo_seen);
    free(sig_seen);
}

int kmocrypt_signature_get_proto (kmocrypt_signature * self,
                                  uint32_t * major,
                                  uint32_t * minor) {
    if (!self->subpackets[KMO_SP_TYPE_PROTO]) {
        kmo_seterror ("unavailable type (proto) in ksp");
        return -1;
    }
    return get_proto ((kmocrypt_proto *)self->subpackets[KMO_SP_TYPE_PROTO]->subpacket, major, minor);
}

int kmocrypt_signature_get_ksn(kmocrypt_signature * self, char ** ksn, size_t * ksn_s) {
    if (!self->subpackets[KMO_SP_TYPE_KSN]) {
        kmo_seterror("unavailable type (ksn) in ksp");
        return -1;
    }

    *ksn = (char *)self->subpackets[KMO_SP_TYPE_KSN]->subpacket;
    *ksn_s = KMOCRYPT_KSN_SIZE;

    return 0;
}                               

int kmocrypt_signature_get_ip (kmocrypt_signature *self, struct sockaddr *addr)
{
    int retval = -1;
    if (self->subpackets[KMO_SP_TYPE_IPV4]) {
        addr->sa_family = PF_INET;
        memcpy (&((struct sockaddr_in *)addr)->sin_addr.s_addr,
                self->subpackets[KMO_SP_TYPE_IPV4]->subpacket,
                sizeof (in_addr_t));
        retval = 0 ;
    } else if (self->subpackets[KMO_SP_TYPE_IPV6]) {
        addr->sa_family = PF_INET6;
        memcpy (&((struct sockaddr_in6 *)addr)->sin6_addr,
                self->subpackets[KMO_SP_TYPE_IPV6]->subpacket,
                sizeof (struct in6_addr));
        retval = 0 ;
    } else
        kmo_seterror ("unavailable type (ipv4/ipv6) in ksp");

    return retval;
}

int kmocrypt_signature_get_mail_client (kmocrypt_signature              *self,
                                        kmocrypt_signature_mail_client  *mailer)
{
    if (! self->subpackets[KMO_SP_TYPE_MAIL_CLIENT]) {
        kmo_seterror ("unavailable type (mail_client) in ksp");
        return -1;
    }
    memcpy (mailer, self->subpackets[KMO_SP_TYPE_MAIL_CLIENT]->subpacket, sizeof (kmocrypt_signature_mail_client));
    return 0;
}

int kmocrypt_sign_has_symkey_for (kmocrypt_signature   *self,
                                  int64_t               mid)
{
    kmocrypt_subpackets *subpackets = self->subpackets[KMO_SP_TYPE_SYMKEY];
    for (subpackets = self->subpackets[KMO_SP_TYPE_SYMKEY]; subpackets; subpackets = subpackets->subpackets) {
        int64_t spkt_mid = *(int64_t *) subpackets->subpacket;
        if (spkt_mid == mid)
            return 1;
    }

    return 0;
}

void kmocrypt_clean_subpackets (kmocrypt_packet *packet)
{
    int i;
    kmocrypt_subpackets *subpackets;
    kmocrypt_subpackets *delme;
    for (i = 0 ; i < KMO_SP_NB_TYPE ; i++) {
        subpackets = packet->subpackets[i];
        while (subpackets) {
            if (subpackets_ops[i]) //FIXME ugly patch to handle the unfinished job.
                if (subpackets_ops[i]->clean)
                    subpackets_ops[i]->clean (packet, subpackets->subpacket);
            delme = subpackets;
            subpackets = subpackets->subpackets;
            free (delme);
        }
    }
}

void kmocrypt_clean_packet (kmocrypt_packet *packet)
{
    kmocrypt_clean_subpackets (packet);
}

void kmocrypt_signature_clean (kmocrypt_signature *self) {
    /* Free the gcrypt things used to validate the signature. */
    gcry_sexp_release(self->sig_sexp);
    gcry_sexp_release(self->hash);
    
    gcry_mpi_release(self->sig_mpi);

    kmocrypt_clean_packet (self);
}

int kmocrypt_signature_validate(kmocrypt_signature * sign,
                                kmocrypt_pkey * key) {
    int err;
    
    err = gcry_pk_verify(sign->sig_sexp, sign->hash, key->key);

    if (err) {
        kmo_seterror(gcry_strerror(err));
        return -1;
    }

    return 0;
}

int kmocrypt_sign_contain (kmocrypt_signature *sign, enum subpacket_type type) {
    return sign->subpackets[type] != NULL;
}
