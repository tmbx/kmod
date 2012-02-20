#ifndef __KMOCRYPTPKEY_H__
#define __KMOCRYPTPKEY_H__

#include <gcrypt.h>
#include "kmo_base.h"
#include "kbuffer.h"

#define MIN_PKEY_VERSION 1
#define MAX_PKEY_VERSION 1

enum key_type {
    KEY_TYPE_MASTER,
    KEY_TYPE_SIGNATURE,
    KEY_TYPE_IDENTITY,
    KEY_TYPE_ENCRYPTION,
};

/** Definition of a public key.
 * Operations should be done by the public key and not by the user of the public key.
 */
typedef struct kmocrypt_pkey {
    enum key_type       type;
    uint32_t            version;
    uint64_t            mid;
    gcry_sexp_t         key;
} kmocrypt_pkey;

/** Allocate a pkey object from a serialized pkey.
 *
 * \param pkey the serialized pkey, binary encoded.
 * \param pkey the length of the serialized pkey.
 * \return a newly allocated pkey object.
 */
kmocrypt_pkey *kmocrypt_pkey_wired_new (unsigned char   *pkey,
                                        uint32_t         len);

/** Initialize a pkey object from a serialized pkey.
 *
 * \param self the pkey object to initialized.
 * \param pkey the serialized pkey, binary encoded.
 * \param pkey the length of the serialized pkey.
 * \return 0 on success, -1 on error and TODO set kmo_error.
 */
int kmocrypt_pkey_wired_init    (kmocrypt_pkey *self,
                                 unsigned char *pkey,
                                 uint32_t       len);

/** Destroy a pkey object.
 *
 * \param self the pkey object to destroy.
 */
void kmocrypt_pkey_destroy (kmocrypt_pkey *self);

/** Release the ressources held by a pkey object.
 *
 * \param self the pkey object to clean.
 */
void kmocrypt_pkey_clean (kmocrypt_pkey *self);


#endif /* __KMOCRYPTPKEY_H__ */
