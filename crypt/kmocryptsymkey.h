#ifndef __KMOCRYPTSYMKEY_H__
#define __KMOCRYPTSYMKEY_H__
#include <gcrypt.h>
#include <stdint.h>

/** A symmetric key object.  */
typedef struct kmocrypt_symkey {
    int cipher; /** < The cipher algo id. */
    int mode; /** < The cipher mode algo id. */
    size_t key_len; /** < The length of the key. */
    size_t block_len; /** < The cipher block length. */
    uint8_t *iv; /** < The initialization vector. */
    gcry_cipher_hd_t hd; /** < The cipher implementation. */
} kmocrypt_symkey;

/** Initialize a symmetric key.
 *
 * \param self the symmetric object to initialize.
 * \param symkey the serialized symmetric key (binary encoded).
 * \param len the length of the serialized symmetric key.
 * \return 0 on success, -1 on error.
 *
 * FIXME: set kmo_error on error.
 */
int kmocrypt_symkey_init (kmocrypt_symkey *self,
                          unsigned char   *symkey,
                          uint32_t         len);

/** Create a new symmetric key.
 *
 * \param symkey the serialized symmetric key (binary encoded).
 * \param len the length of the serialized symmetric key.
 * \return a newly allocated/initilized symmetric key.
 *
 * FIXME: set kmo_error on error.
 */
kmocrypt_symkey *kmocrypt_symkey_new (unsigned char   *symkey,
                                      uint32_t         len);

/** decrypt data encrypted with a symmetric key
 *
 * \param self the symmetric key object.
 * \param in the encrypted data.
 * \param in_len the encrypted data length.
 * \param out the preallocated returned decrypted data. Allocate in_len.
 * \param out_len returned decrypted data length.
 * \return 0 on success, -1 on error.
 *
 * FIXME: set kmo_error on error.
 */
int kmocrypt_symkey_decrypt (kmocrypt_symkey   *self,
                             unsigned char     *in,
                             uint32_t           in_len,
                             unsigned char     *out,
                             uint32_t          *out_len);

/** Destroy a symmetric key object.
 *
 * \param self the symmetric key to destroy.
 */
void kmocrypt_symkey_destroy (kmocrypt_symkey *self);

/** release ressources held by a symmetric key.
 *
 * \param self the symmetric key holding the ressources.
 */
void kmocrypt_symkey_clean (kmocrypt_symkey *self);

#endif /*__KMOCRYPTSYMKEY_H__*/

