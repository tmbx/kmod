/* Copyright(C) 2006-2012 Opersys inc., All rights reserved. */

#include "kmocryptsignature2.h"
#include "kmocryptpkey.h"
#include "kmocryptversion.h"

/* This file binds Crypt to the core of KMO. That may not be a good thing on
 * the long run but I think we can live with it for now.
 */
#include "k3p.h"

#ifdef __WINDOWS__
#include <ws2tcpip.h>
#endif

#define MAX_DIGEST_LEN 64
#define MAX_SIG_ALGO_NAME_LEN 32
#define MAX_HASH_ALGO_NAME_LEN 32

/* This function recognizes the signature of the KSP itself. Note that this
 * function prepares the validation of the signature of the KSP with its
 * corresponding public key but does not actually do the validation. The
 * validation should be done with kmocrypt_signature_validate2() once the public
 * key has been obtained from the KOS.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int recognize_ksp_signature(struct kmocrypt_signature2 *self, kbuffer *buffer, uint32_t total_len) {
    int error = 0;
    uint32_t sig_len;
    size_t scanned_sig_len;
    int digest_len = gcry_md_get_algo_dlen(self->hash_algo);
    uint8_t digest[MAX_DIGEST_LEN];
    char hashname[MAX_HASH_ALGO_NAME_LEN];
    char signame[MAX_SIG_ALGO_NAME_LEN];
    
    /* Verify that we're using the correct signature algorithm. */
    if (self->sig_algo != GCRY_AC_RSA) {
    	kmo_seterror("Signature algorithm is not GCRY_AC_RSA");
	return -1;
    }
    
    /* Get the hash algorithm name. */
    strncpy(hashname, gcry_md_algo_name(self->hash_algo), MAX_HASH_ALGO_NAME_LEN);
    strntolower(hashname, MAX_HASH_ALGO_NAME_LEN);
    
    /* Get the signature algorithm name. */
    strncpy(signame, gcry_pk_algo_name(self->sig_algo), MAX_SIG_ALGO_NAME_LEN);
    strntolower(signame, MAX_SIG_ALGO_NAME_LEN);
    
    /* Hash the content of the KSP up to KSP signature part. */
    gcry_md_hash_buffer(self->hash_algo, digest, buffer->data, buffer->pos);
    
    /* Build the gcrypt hash of the KSP required to verify the signature. */
    error = gcry_sexp_build(&self->sig_hash, NULL, "(4:data(5:flags5:pkcs1)(4:hash %s %b))", 
                            hashname, digest_len, digest);
    if (error) {
        kmo_seterror("cannot build signature hash: %s", gcry_strerror(error));
	return -1;
    }
    
    /* Get the length of the signature. */
    if (total_len < 4) {
    	kmo_seterror("KSP signature section is too short");
	return -1;
    }
    
    sig_len = kbuffer_read32(buffer);
    
    if (total_len != 4 + sig_len) {
    	kmo_seterror("KSP signature section is malformed");
	return -1;
    }
    
    /* Get the signature MPI. */
    error = gcry_mpi_scan(&self->sig_mpi, GCRYMPI_FMT_PGP, kbuffer_current_pos(buffer), sig_len, &scanned_sig_len);
    if (error) {
    	kmo_seterror("invalid MPI in signature: %s", gcry_strerror(error));
	return -1;
    }
    
    if (scanned_sig_len != sig_len) {
    	kmo_seterror("invalid MPI in signature: unexpected size");
	return -1;
    }
    
    /* Skip the signature (just to be thorough, it's not strictly necessary). */
    buffer->pos += sig_len;
    
    /* Build the signature s-expression. */
    error = gcry_sexp_build(&self->sig_sexp, NULL, "(7:sig-val(%s(1:s %m)))", signame, self->sig_mpi);
    if (error) {
    	kmo_seterror("cannot build signature from MPI: %s", gcry_strerror(error));
	return -1;
    }
    
    return 0;
}

/* This function free()'s the specified subpacket. */
static void clean_simple_free(void *data) {
    free(data);
}

/* This function recognizes a hash subpacket.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int recognize_hash(struct kmocrypt_signature2 *self, kbuffer *buffer, void **data_handle, uint32_t packet_len) {
    if (gcry_md_get_algo_dlen(self->hash_algo) != packet_len) {
    	kmo_seterror("KSP HASH subpacket is malformed");
	return -1;
    }
    
    *data_handle = kmo_malloc(packet_len);
    kbuffer_read(buffer, (char *) *data_handle, packet_len);
    return 0;
}

/* This function verifies that the data specified hashes to the hash value
 * specified.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int check_hash(struct kmocrypt_signature2 *self, uint8_t *hash, uint8_t *data, uint32_t len) {
    uint8_t digest[MAX_DIGEST_LEN];
    
    assert(MAX_DIGEST_LEN >= gcry_md_get_algo_dlen(self->hash_algo));
    gcry_md_hash_buffer(self->hash_algo, digest, data, len);
    
    if (memcmp(hash, digest, gcry_md_get_algo_dlen(self->hash_algo))) {
        kmo_seterror("hash verification failed");
	return -1;
    }
    
    return 0;
}

/* This function recognizes a PROTO subpacket.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int recognize_proto(struct kmocrypt_signature2 *self, kbuffer *buffer, void **data_handle, uint32_t packet_len) {
    struct kmocrypt_proto2 *proto;
    
    if (packet_len != 8) {
        kmo_seterror("KSP PROTO subpacket is malformed");
        return -1;
    }
    
    *data_handle = proto = (struct  kmocrypt_proto2 *) kmo_malloc(sizeof(struct kmocrypt_proto2));
    proto->major = kbuffer_read32(buffer);
    proto->minor = kbuffer_read32(buffer);
    return 0;
}

/* This function recognizes an IPV4 subpacket.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int recognize_ipv4(struct kmocrypt_signature2 *self, kbuffer *buffer, void **data_handle, uint32_t packet_len) {
    if (packet_len != 4) {
    	kmo_seterror("KSP IPV4 subpacket is malformed");
	return -1;
    }
    
    *data_handle = kmo_malloc(packet_len);
    *(uint32_t *) *data_handle = kbuffer_read32(buffer);
    return 0;
}

/* This function recognizes an IPV6 subpacket.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int recognize_ipv6(struct kmocrypt_signature2 *self, kbuffer *buffer, void **data_handle, uint32_t packet_len) {
    if (packet_len != 16) {
    	kmo_seterror("KSP IPV6 subpacket is malformed");
	return -1;
    }
    
    /* Normally it should be natively in NBO. */
    *data_handle = kmo_malloc(packet_len);
    kbuffer_read(buffer, (char *) *data_handle, packet_len);
    return 0;
}

/* This function recognizes an attachment subpacket.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int recognize_attachment(struct kmocrypt_signature2 *self, kbuffer *buffer,
    	    	    	    	void **data_handle, uint32_t packet_len) {
    			
    if (packet_len != gcry_md_get_algo_dlen(self->hash_algo) * 2) {
        kmo_seterror("KSP ATTACHMENT subpacket is malformed");
        return -1;
    }
    
    *data_handle = kmo_malloc(packet_len);
    kbuffer_read(buffer, (char *) *data_handle, packet_len);
    return 0;
}

/* This function recognizes a symmetric key subpacket. Only the member ID field
 * is read however.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int recognize_symkey(struct kmocrypt_signature2 *self, kbuffer *buffer,
    	    	    	    void **data_handle, uint32_t packet_len) {
    
    if (packet_len < 8) {
        kmo_seterror("KSP SYMKEY subpacket is malformed");
        return -1;
    }
    
    *data_handle = kmo_malloc(8);
    *(uint64_t *) *data_handle = kbuffer_read64(buffer);
    return 0;
}

/* This function recognizes a subpacket of an "opaque" type. It does not read
 * its content however.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int recognize_opaque(struct kmocrypt_signature2 *self, kbuffer *buffer,
    	    	    	    void **data_handle, uint32_t packet_len) {
    *data_handle = NULL;
    return 0;
}

/* This function recognizes a blob. It does read it in a buffer.
 * This function sets the KMO error string. It returns -1 on failure.
 */
struct kmo_blob {
    uint32_t type;
    kbuffer *buffer;
};

static int recognize_blob(struct kmocrypt_signature2 *self, kbuffer *buffer, void **data_handle, uint32_t packet_len) {
    uint32_t len;
    struct kmo_blob *blob = kmo_calloc(sizeof(struct kmo_blob));
    
    do {
        if (kbuffer_left(buffer) < 2 * sizeof(uint32_t)) {
            kmo_seterror("KSP BLOB subpacket is malformed");
	    break;
	}

        blob->type = kbuffer_read32(buffer);
        len = kbuffer_read32(buffer);

        blob->buffer = kbuffer_new(len);
        if (kbuffer_read_into(buffer, blob->buffer, len) != len) {
	    kmo_seterror("KSP BLOB subpacket is malformed");
            break;
	}
	
	if (packet_len != 8 + len) {
	    kmo_seterror("KSP BLOB subpacket is malformed");
	    break;
	}

        *data_handle = blob;
        return 0;
	
    } while (0);
    
    kbuffer_destroy(blob->buffer);
    free(blob);
    return -1;
}

static void clean_blob(void *data) {
    struct kmo_blob *blob = (struct kmo_blob *) data;
    if (blob)
        kbuffer_destroy(blob->buffer);
    free(blob);
}

/* This function recognizes a KSN subpacket.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int recognize_ksn(struct kmocrypt_signature2 *self, kbuffer *buffer, void **data_handle, uint32_t packet_len) {
    if (packet_len != KMOCRYPT_KSN_SIZE) {
    	kmo_seterror("KSP KSN subpacket is malformed");
	return -1;
    }
    
    *data_handle = kmo_malloc(packet_len);
    kbuffer_read(buffer, (char *) *data_handle, packet_len);
    return 0;
}

/* This function recognizes a mail client subpacket.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int recognize_mail_client(struct kmocrypt_signature2 *self, kbuffer *buffer,
    	    	    	    	 void **data_handle, uint32_t packet_len) {
    
    struct kmocrypt_mail_client2 *client = NULL;
    
    if (packet_len != 64) {
    	kmo_seterror("KSP MAIL CLIENT subpacket is malformed");
	return -1;
    }
    
    client = (struct kmocrypt_mail_client2 *) kmo_malloc(sizeof(struct kmocrypt_mail_client2));
    client->product = kbuffer_read16(buffer);
    client->version = kbuffer_read16(buffer);
    client->release = kbuffer_read16(buffer);
    client->kpp_version = kbuffer_read16(buffer);

    *data_handle = client;
    return 0;
}

static int recognize_date(struct kmocrypt_signature2 *self, kbuffer *buffer,
                          void **data_handle, uint32_t packet_len) {
    if (packet_len < 8)
        return -1;
    struct timeval *tv = (struct timeval *)kmo_malloc(sizeof(struct timeval));
    tv->tv_sec  = kbuffer_read32(buffer);
    tv->tv_usec = kbuffer_read32(buffer);
    *data_handle = tv;

    return 0;
}

struct kpg_data {
    uint8_t type;
    kstr addr;
    uint16_t port; // in native byte order
};

static int recognize_kpg(struct kmocrypt_signature2 *self, kbuffer *buffer,
                          void **data_handle, uint32_t packet_len) {
    struct kpg_data *kpg = (struct kpg_data *) kmo_malloc(sizeof(struct kpg_data));
    uint32_t length;
    uint8_t *buf;
    if (packet_len < 13) {
	free(kpg);
	kmo_seterror("KPG packet too short");
        return -1;
    }
    
    kpg->type = kbuffer_read8(buffer);
    kbuffer_read32(buffer); // Header type
    kbuffer_read32(buffer); // Header length
    length = kbuffer_read32(buffer);
    buf = kbuffer_read_nbytes(buffer, length);
    kstr_init_buf(&kpg->addr, buf, length);
    kpg->port = kbuffer_read16(buffer);
    *data_handle = (void *)kpg;

    return 0;
}

static void clean_kpg (void *data) {
    struct kpg_data *kpg = (struct kpg_data *)data;
    kstr_free(&kpg->addr);
    free(kpg);
}


/* This structure represents an entry in the table below.
 * 'recognize' is the function that recognizes the corresponding subpacket type.
 * 'clean' is the function that frees the subpacket data.
 */
struct subpackets_ops {
    int (*recognize) (struct kmocrypt_signature2 *self, kbuffer *buffer, void **data_handle, uint32_t packet_len);
    void (*clean) (void *data);
};

/* This table is used to dispatch subpacket handling to the right functions. */
static struct subpackets_ops subpackets_ops[KMO_SP_NB_TYPE] = {
    { NULL, NULL },         	    	    	    /* NONE */
    { recognize_proto, clean_simple_free },         /* KMO_SP_TYPE_PROTO */
    { recognize_hash, clean_simple_free },          /* KMO_SP_TYPE_FROM_NAME */
    { recognize_hash, clean_simple_free },          /* KMO_SP_TYPE_FROM_ADDR */
    { recognize_hash, clean_simple_free },          /* KMO_SP_TYPE_TO */
    { recognize_hash, clean_simple_free },          /* KMO_SP_TYPE_CC */
    { recognize_hash, clean_simple_free },          /* KMO_SP_TYPE_SUBJECT */
    { recognize_hash, clean_simple_free },          /* KMO_SP_TYPE_PLAIN */
    { recognize_hash, clean_simple_free },          /* KMO_SP_TYPE_HTML */
    { recognize_ipv4, clean_simple_free },          /* KMO_SP_TYPE_IPV4 */
    { recognize_ipv6, clean_simple_free },          /* KMO_SP_TYPE_IPV6 */
    { recognize_attachment, clean_simple_free },    /* KMO_SP_TYPE_ATTACHMENT */
    { recognize_symkey, clean_simple_free }, 	    /* KMO_SP_TYPE_SYMKEY */	   
    { recognize_opaque, NULL }, 	     	    /* KMO_SP_TYPE_SND_SYMKEY */  
    { recognize_opaque, NULL }, 	     	    /* KMO_SP_TYPE_PASSWD */	   
    { recognize_mail_client, clean_simple_free },   /* KMO_SP_TYPE_MAIL_CLIENT */
    { recognize_blob, clean_blob },          	    /* KMO_SP_TYPE_BLOB */
    { recognize_ksn, clean_simple_free },           /* KMO_SP_TYPE_KSN */
    { recognize_opaque, NULL },          	    /* KMO_SP_TYPE_PODTO */
    { NULL, NULL },                                 /* KMO_SP_TYPE_LANG */
    { recognize_date, clean_simple_free },          /* KMO_SP_TYPE_DATE */
    { recognize_opaque, NULL },                     /* KMO_SP_TYPE_RESERVED1 */
    { recognize_kpg, clean_kpg },                   /* KMO_SP_TYPE_KPG */
};

/* This function recognizes the subpackets inside the KSP.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int recognize_subpackets(struct kmocrypt_signature2 *self, kbuffer *buffer, uint32_t total_len) {
    int error = 0;
    
    /* Pass all subpackets. */
    while (total_len) {
    	uint8_t type;
	uint16_t subpacket_len;
	uint32_t seek_pos;
	
	/* Get the type and length of the current subpacket. */
	if (total_len < 3) {
	    kmo_seterror("last subpacket is malformed");
	    return -1;
	}
    	
	type = kbuffer_read8(buffer);
	subpacket_len = kbuffer_read16(buffer);
	
	if (total_len < 3 + subpacket_len)
	{
	    kmo_seterror("last subpacket is too long");
	    return -1;
	}
	
	seek_pos = buffer->pos + subpacket_len;
	total_len -= 3 + subpacket_len;
    	
	/* We know about this packet type. */
	if (type < KMO_SP_NB_TYPE && subpackets_ops[type].recognize) {
	    void *subpacket_data = NULL;
	    struct kmocrypt_subpacket_list2 *list_node = NULL;
	    
	    /* Recognize the subpacket. */
	    error = subpackets_ops[type].recognize(self, buffer, &subpacket_data, subpacket_len);
	    if (error) return error;
	    
	    /* Store the data. */
	    list_node = (struct kmocrypt_subpacket_list2 *) kmo_malloc(sizeof(struct kmocrypt_subpacket_list2));
	    list_node->next = self->subpacket_array[type];
	    list_node->data = subpacket_data;
	    self->subpacket_array[type] = list_node;
	}
	
	/* In case we didn't read the subpacket, seek to the correct position in the buffer. */
	buffer->pos = seek_pos;
    }
    
    return 0;
}

/* This function recognizes the KSP content.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int kmocrypt_recognize_ksp2(struct kmocrypt_signature2 *self, kbuffer *buffer) {
    uint32_t header_len = 27;
    uint32_t subpackets_len;

    if (buffer->len < header_len) {
        kmo_seterror("KSP header too short");
        return -1;
    }

    /* MAGIC */
    kbuffer_read32(buffer);

    /* MAJOR */
    self->major= kbuffer_read32(buffer);

    /* MINOR */
    self->minor = kbuffer_read32(buffer);

    /* MEMBER ID */
    self->mid = kbuffer_read64(buffer);

    /* HASH ALGO */
    self->hash_algo = kbuffer_read8(buffer);
    if (gcry_md_test_algo(self->hash_algo)) {
        kmo_seterror("unsupported hash algorithm");
        return -1;
    }

    /* SIG ALGO */
    self->sig_algo = kbuffer_read8(buffer);
    if (gcry_pk_test_algo(self->sig_algo)) {
        kmo_seterror("unsupported signature algorithm");
        return -1;
    }

    /* PACKAGING TYPE */
    self->pkg_type = kbuffer_read8(buffer);
    if (self->pkg_type >= KMO_P_NB_TYPE) {
        kmo_seterror("invalid signature packet type");
        return -1;
    }

    /* SUBPACKETS LENGTH */
    subpackets_len = kbuffer_read32(buffer);
    
    if (! subpackets_len) {
        kmo_seterror("no subpacket in KSP");
        return -1;
    }
    
    if (buffer->len < header_len + subpackets_len) {
        kmo_seterror("KSP subpacket section is too short");
        return -1;
    }
    
    /* Recognize the subpackets. */
    if (recognize_subpackets(self, buffer, subpackets_len)) {
        return -1;
    }
    
    /* Recognize the signature of the KSP, unless it's the encryption key. */
    if (self->mid && recognize_ksp_signature(self, buffer, buffer->len - buffer->pos)) {
        return -1;
    }
    
    return 0;
}

/* This function validates the signature with its corresponding public key.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int kmocrypt_signature_validate2(struct kmocrypt_signature2 *self, kmocrypt_pkey *key) {
    int error = gcry_pk_verify(self->sig_sexp, self->sig_hash, key->key);

    if (error) {
        kmo_seterror("signature validation failed: %s", gcry_strerror(error));
        return -1;
    }

    return 0;
}

/* This function returns true if the KSP specified contains a subpacket of the
 * specified type.
 */
int kmocrypt_signature_contain2(struct kmocrypt_signature2 *self, int type) {
    return (self->subpacket_array[type] != NULL);
}

/* This function checks the validity of a hashed field (e.g. from). 'type' is
 * the type of the field to validate (subpacket type), 'data' is the data to
 * validate against the hash in the KSP, 'len' the length of the data.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int kmocrypt_signature_check_hash2(struct kmocrypt_signature2 *self, int type, unsigned char *data, uint32_t len) {
    assert(type < KMO_SP_NB_TYPE && subpackets_ops[type].recognize == recognize_hash);

    if (! self->subpacket_array[type]) {
        kmo_seterror("unavailable type %d in KSP", type);
        return -1;
    }

    return check_hash(self, self->subpacket_array[type]->data, data, len);
}

struct kmocrypt_attachment_hash {
    uint8_t name_hash[MAX_DIGEST_LEN];
    uint8_t payload_hash[MAX_DIGEST_LEN];
};

/* First loop, try to make name/payload match. Attachments that match here are
 * valid attachments.
 */
static void sig_check_attachments_name_payload(struct kmocrypt_signature2 * self, 
                                               size_t spkt_cnt,
                                               karray * attch_array, 
                                               int * sig_seen, 
                                               int * kmo_seen,
                                               struct kmocrypt_attachment_hash * attch_cache) {
    int i;
    size_t n, j;
    struct kmocrypt_subpacket_list2 * sp;
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

        sp = self->subpacket_array[KMO_SP_TYPE_ATTACHMENT];

        /* Loop through all the attachments. */
        for (j = 0; j < spkt_cnt; j++) {
	    att_hash = sp->data;
	    
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
            
	    
	    sp = sp->next;
        }
    }
}

/* Second loop, matches attachment by name. Attachments that match only by name
 * are considered to have an invalid payload.
 */
static void sig_check_attachments_name(struct kmocrypt_signature2 * self,
                                       size_t spkt_cnt, 
                                       karray * attch_array, 
                                       int * sig_seen, 
                                       int * kmo_seen,
                                       struct kmocrypt_attachment_hash * attch_cache) {
    int i;
    size_t n, j;
    uint8_t * att_hash;
    struct kmocrypt_subpacket_list2 * sp;
    struct kmod_attachment * att;

    n = gcry_md_get_algo_dlen(self->hash_algo);

    for (i = 0; i < attch_array->size; i++) {
        att = (struct kmod_attachment *) attch_array->data[i];

        /* If the attachment has already been seen above, move to next. */        
        if (kmo_seen[i] == 1) 
            continue;

        sp = self->subpacket_array[KMO_SP_TYPE_ATTACHMENT];
        
        for (j = 0; j < spkt_cnt; j++) {
	    att_hash = sp->data;
	    
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

            sp = sp->next;           
        }
    }    
}

/* Third loop, matches attachment by payload. Attachments that only match by
 * payload are considered to have an invalid name.
 */
static void sig_check_attachments_payload(struct kmocrypt_signature2 * self, 
                                          size_t spkt_cnt,
                                          karray * attch_array, 
                                          int * sig_seen, 
                                          int * kmo_seen,
                                          struct kmocrypt_attachment_hash * attch_cache) {
    int i;
    size_t n, j;
    struct kmocrypt_subpacket_list2 * sp;
    uint8_t * att_hash;
    struct kmod_attachment * att;

    n = gcry_md_get_algo_dlen(self->hash_algo);

    for (i = 0; i < attch_array->size; i++) {
        att = (struct kmod_attachment *) attch_array->data[i];

        /* If the attachment has already been seen above, move to next. */        
        if (kmo_seen[i] == 1) 
            continue;

        /* Hash the KMO name and payloads. */
        sp = self->subpacket_array[KMO_SP_TYPE_ATTACHMENT];

        for (j = 0; j < spkt_cnt; j++) {
	    att_hash = sp->data + n;
 
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

            sp = sp->next;
        }
    }    
}

/* This function verifies the attachments specified. */
void kmocrypt_signature_check_attachments2(struct kmocrypt_signature2 *self, karray *attch_array) {
    int i = 0;
    size_t spkt_cnt = 0;
    int * sig_seen, * kmo_seen;
    struct kmocrypt_attachment_hash * attch_cache;
    struct kmod_attachment * att;
    struct kmocrypt_subpacket_list2 * sp;
    
    /* If there are no attachments in the signature, then any attachment sent by
       the plugin needs to be viewed as injected. */
    if (self->subpacket_array[KMO_SP_TYPE_ATTACHMENT] == NULL) {
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
    sp = self->subpacket_array[KMO_SP_TYPE_ATTACHMENT];
    do {
        spkt_cnt++;
	sp = sp->next;
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
    
    /* Check name-only matches(potentially changed payloads). */
    sig_check_attachments_name(self, spkt_cnt, attch_array, sig_seen, kmo_seen, attch_cache);
    
    /* Check payload matches(potentially changed names). */
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

/* This function extracts the KSN from the signature, if any.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int kmocrypt_signature_get_ksn2(struct kmocrypt_signature2 *self, char **ksn, size_t *len) {
    if (! self->subpacket_array[KMO_SP_TYPE_KSN]) {
        kmo_seterror("No KSN subpacket in KSP");
        return -1;
    }

    *ksn = (char *) self->subpacket_array[KMO_SP_TYPE_KSN]->data;
    *len = KMOCRYPT_KSN_SIZE;

    return 0;
}

/* This function gets the IP address of the sender.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int kmocrypt_signature_get_ip2(struct kmocrypt_signature2 *self, struct sockaddr *addr) {   
    if (self->subpacket_array[KMO_SP_TYPE_IPV4]) {
        addr->sa_family = PF_INET;
        memcpy(&((struct sockaddr_in *) addr)->sin_addr.s_addr, self->subpacket_array[KMO_SP_TYPE_IPV4]->data, 4);
    }
    
    else if (self->subpacket_array[KMO_SP_TYPE_IPV6]) {
        addr->sa_family = PF_INET6;
        memcpy(&((struct sockaddr_in6 *) addr)->sin6_addr, self->subpacket_array[KMO_SP_TYPE_IPV6]->data, 16);
    }
    
    else {
        kmo_seterror("unavailable type (IPV4/IPV6) in KSP");
	return -1;
    }

    return 0;
}

/* This function gets the ID of the mail client plugin of the sender.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int kmocrypt_signature_get_mail_client2(struct kmocrypt_signature2 *self, struct kmocrypt_mail_client2 *mailer) {
    if (! self->subpacket_array[KMO_SP_TYPE_MAIL_CLIENT]) {
        kmo_seterror("unavailable type (MAIL_CLIENT) in KSP");
        return -1;
    }
    
    memcpy(mailer, self->subpacket_array[KMO_SP_TYPE_MAIL_CLIENT]->data, sizeof(struct kmocrypt_mail_client2));
    return 0;
}

/* This function returns true if a symmetric key exists for the specified member
 * ID.
 */
int kmocrypt_signature_has_symkey_for2(struct kmocrypt_signature2 *self, uint64_t mid) {
    struct kmocrypt_subpacket_list2 *list;
    
    for (list = self->subpacket_array[KMO_SP_TYPE_SYMKEY]; list; list = list->next) {
        uint64_t spkt_mid = *(uint64_t *) list->data;
        if (spkt_mid == mid) return 1;
    }

    return 0;
}

/* This function frees a KSP object. */
void kmocrypt_signature_free2(struct kmocrypt_signature2 *self) {
    int i;
    
    /* Free the gcrypt things used to validate the signature. */
    gcry_sexp_release(self->sig_sexp);
    gcry_mpi_release(self->sig_mpi);
    gcry_sexp_release(self->sig_hash);
    
    /* Free the subpackets. */
    for (i = 1; i < KMO_SP_NB_TYPE; i++) {
        struct kmocrypt_subpacket_list2 *current = self->subpacket_array[i];
	
        while (current) {
	    struct kmocrypt_subpacket_list2 *next = current->next;
	    if (subpackets_ops[i].clean) subpackets_ops[i].clean(current->data);
	    free(current);
	    current = next;
        }
    }
}

void kmocrypt_get_kpg_host2(struct kmocrypt_signature2 *self, kstr *addr, int *port) {
    struct kpg_data *kpg = (struct kpg_data *) self->subpacket_array[KMO_SP_TYPE_KPG]->data;
    if (kpg->type == 0) {
	kstr_assign_kstr(addr, &kpg->addr);
	*port = kpg->port;
    }
}

void kmocrypt_signed_pkey_destroy(struct kmocrypt_signed_pkey *signed_pkey) {
    if (signed_pkey) {
        kmocrypt_signature_free2(&signed_pkey->sign);
        kmocrypt_pkey_destroy(signed_pkey->key);
    }

    free (signed_pkey);
}

int kmocrypt_signed_pkey_check(struct kmocrypt_signed_pkey *signed_pkey, kmocrypt_pkey *pkey) {
    return kmocrypt_signature_validate2(&signed_pkey->sign, pkey);
}

/* The pkey is the kryptiva signing pkey. */
struct kmocrypt_signed_pkey *kmocrypt_sign_get_pkey(kbuffer *buffer) {
    struct kmocrypt_signed_pkey *signed_pkey = kmo_malloc(sizeof(struct kmocrypt_signed_pkey));
    struct kmo_blob *key;
    struct timeval *tv;
    kbuffer *buf_bin = NULL;

    memset(signed_pkey, 0, sizeof(struct kmocrypt_signed_pkey));
    
    do {
        buf_bin = kbuffer_new_b64 (buffer->data, buffer->len);
        if (buf_bin == NULL) break;
            
        if (kmocrypt_recognize_ksp2 (&signed_pkey->sign, buf_bin))
            break;

        signed_pkey->mid = signed_pkey->sign.mid;

        if (signed_pkey->sign.subpacket_array[KMO_SP_TYPE_BLOB] == NULL ||
	    signed_pkey->sign.subpacket_array[KMO_SP_TYPE_DATE] == NULL) {
            kmo_seterror("the required fields (BLOB & DATE) for a signed key are not present in the packet");
            break;
        }

        key = (struct kmo_blob *)signed_pkey->sign.subpacket_array[KMO_SP_TYPE_BLOB]->data;
        if (key == NULL) {
            kmo_seterror("the public key packet does not contain any key");
            break;
        }

        tv = (struct timeval *)signed_pkey->sign.subpacket_array[KMO_SP_TYPE_DATE]->data;
        signed_pkey->time.tv_sec = tv->tv_sec;
        signed_pkey->time.tv_usec = tv->tv_usec;

        signed_pkey->key = kmocrypt_pkey_wired_new(key->buffer->data, key->buffer->len);
    } while (0);

    kbuffer_destroy(buf_bin);
    
    /* If the key is still NULL, an error has occurred. */
    if (signed_pkey->key == NULL) {
        kmocrypt_signed_pkey_destroy(signed_pkey);
        return NULL;
    }

    return signed_pkey;
}

