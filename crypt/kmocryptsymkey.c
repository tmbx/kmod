#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "kmocryptsymkey.h"
#include "kmo_base.h"
#include "ntohll.h"
#include "utils.h"

kmocrypt_symkey *kmocrypt_symkey_new (unsigned char *symkey,
                     uint32_t len)
{
    kmocrypt_symkey *self = (kmocrypt_symkey *)kmo_malloc (sizeof(kmocrypt_symkey));

    if (self != NULL && kmocrypt_symkey_init (self, symkey, len)) {
        free (self);
        self = NULL;
    }
    
    return self;
}

int kmocrypt_symkey_init (kmocrypt_symkey *self,
                          unsigned char   *symkey,
                          uint32_t         len)
{
    gcry_error_t err = 0;
    unsigned int flags = GCRY_CIPHER_SECURE;

    if (len < 2) {
        kmo_seterror ("symkey to short");
        goto ERR;
    }
    self->cipher = (int) *symkey++;     len--;
    self->mode = (int) *symkey++;       len--;

    err = gcry_cipher_algo_info (self->cipher, GCRYCTL_TEST_ALGO, NULL, NULL);
    if (err) {
        kmo_seterror ("invalid cipher algorithm");
        goto ERR;
    }

    switch (self->mode) {
        case GCRY_CIPHER_MODE_CBC:
            flags |= GCRY_CIPHER_CBC_CTS;
            break;
        case GCRY_CIPHER_MODE_ECB:
        case GCRY_CIPHER_MODE_CFB:
            break;
        default:
            kmo_seterror ("unknown cipher mode %i", self->mode);
            goto ERR;
    }

    err = gcry_cipher_open (&self->hd, self->cipher, self->mode, flags);
    if (err) goto ERR;

    err = gcry_cipher_algo_info (self->cipher, GCRYCTL_GET_KEYLEN, NULL, &self->key_len);
    if (err) goto ERR;

    err = gcry_cipher_algo_info (self->cipher, GCRYCTL_GET_BLKLEN, NULL, &self->block_len);
    if (err) goto ERR;

    if (len != self->key_len + self->block_len){
        kmo_seterror ("symkey too short");
    }

    self->iv = (uint8_t *) kmo_malloc (self->block_len);
    memcpy (self->iv, symkey + self->key_len, self->block_len);

    err = gcry_cipher_setkey (self->hd, symkey, self->key_len);
    if (err) {
        kmo_seterror ("could not set the key (%s)", gcry_strerror (err));
        goto ERR;
    }

    return 0;

ERR:
    return -1;
}

void kmocrypt_symkey_destroy (kmocrypt_symkey *self)
{
    kmocrypt_symkey_clean (self);
    free (self);
}

void kmocrypt_symkey_clean (kmocrypt_symkey *self)
{
    if (self->iv) free (self->iv);
    if (self->hd) gcry_cipher_close (self->hd);
}

#define KMO_SYMKEY_ENC_MAGIC (0x23A6F9DDE35CF931ll)

int kmocrypt_symkey_decrypt (kmocrypt_symkey  *self,
                             unsigned char    *in,
                             uint32_t          in_len,
                             unsigned char    *out, 
                             uint32_t         *out_len)
{
    gcry_error_t err;
    char *tmp        = (char *)kmo_malloc (in_len);
    if (!tmp) {
        kmo_seterror (strerror (errno));
        return -1;
    }
    uint32_t tmp_len = in_len;
    int i;

    err = gcry_cipher_reset (self->hd); if (err) goto GCRY_ERR;
    err = gcry_cipher_setiv (self->hd, self->iv, self->block_len); if (err) goto GCRY_ERR;
    err = gcry_cipher_decrypt (self->hd, tmp, tmp_len, in, in_len); if (err) goto GCRY_ERR;

    if (ntohll(*(uint64_t*)tmp) != KMO_SYMKEY_ENC_MAGIC) {
        kmo_seterror ("invalid decryption");
        goto ERR;
    }

    for (i = 8 ; i < (int) tmp_len ;)
        if (tmp[i++] == '\0')
            break;

    memcpy ((char *)out, tmp + i, tmp_len - i);
    *out_len = tmp_len - i;

    free (tmp);
    return 0;

GCRY_ERR:
    kmo_seterror ("gcrypt error : %s", gcry_strerror (err));
ERR:
    free (tmp);

    return -1;
}
