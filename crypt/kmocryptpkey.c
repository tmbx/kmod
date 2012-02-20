#include "kmocryptversion.h"
#include "kmocryptpkey.h"

enum PKEY_TYPE {
    PKEY_TYPE_PUB = (0 << 7),
    PKEY_TYPE_PRIV = (1 << 7)
};

enum PKEY_ALGO {
    PKEY_ALGO_RSA = 1,
    PKEY_ALGO_DSA = 2
};

kmocrypt_pkey *kmocrypt_pkey_wired_new (unsigned char   *pkey,
                                        uint32_t         len)
{
    kmocrypt_pkey *self = (kmocrypt_pkey *)kmo_malloc (sizeof(kmocrypt_pkey));

    if (kmocrypt_pkey_wired_init (self, pkey, len)) {
        free (self);
        self = NULL;
    }
    
    return self;
}

int kmocrypt_pkey_wired_init    (kmocrypt_pkey *self,
                                 unsigned char *pkey,
                                 uint32_t       len)
{
    kbuffer *buffer = kbuffer_new(len);
    kbuffer_write (buffer, pkey, len);
    gcry_error_t err = 0;
    uint8_t key_type;
    size_t n_size;
    size_t e_size;
    gcry_mpi_t n_mpi = NULL;
    gcry_mpi_t e_mpi = NULL;

    do {
        if (len < 14) {
	    kmo_seterror("public key buffer too short");
	    err = -1;
	    break;
	}
	
	key_type = kbuffer_read8 (buffer);
        if ((key_type & (1 << 7)) != PKEY_TYPE_PUB || (key_type & 0x7F) != PKEY_ALGO_RSA) {
            kmo_seterror("invalid key type");
            err = -1;
            break;
        }
            
        self->mid = kbuffer_read64 (buffer);

        self->type = kbuffer_read8 (buffer);
        
	/* The rest is rsa specific. Move to another function if multiple algo are available. */
	
        n_size = kbuffer_read32 (buffer);
        if (n_size == 0 || n_size > buffer->len - buffer->pos) {
            kmo_seterror("invalid key (bad 'n')");
            err = -1;
            break;
        }
	
        err = gcry_mpi_scan (&n_mpi, GCRYMPI_FMT_USG, kbuffer_current_pos(buffer), n_size, NULL);
        if (err) {
            kmo_seterror(gcry_strerror(err));
            break;
        }
	
        kbuffer_seek(buffer, n_size, SEEK_CUR);
    	
	if (buffer->len - buffer->pos < 4) {
	    kmo_seterror("public key buffer too short");
	    err = -1;
	    break;
	}
	
        e_size = kbuffer_read32 (buffer);
        if (e_size == 0 || e_size > buffer->len - buffer->pos) {
            kmo_seterror("invalid key");
            err = -1;
            break;
        }
	
        err = gcry_mpi_scan (&e_mpi, GCRYMPI_FMT_USG, kbuffer_current_pos(buffer), e_size, NULL);
        if (err) {
            kmo_seterror(gcry_strerror(err));
            break;
        }
	
        kbuffer_seek(buffer, e_size, SEEK_CUR);
	
	if (buffer->pos != buffer->len) {
	    kmo_seterror("public key buffer is malformed");
	}

        err = gcry_sexp_build (&self->key, NULL, "(10:public-key(3:rsa(1:n%m)(1:e%m)))", n_mpi, e_mpi);
        if (err) {
            kmo_seterror(gcry_strerror(err));
            break;
        }
	
    } while (0);
    
    kbuffer_destroy(buffer);
    gcry_mpi_release (n_mpi);
    gcry_mpi_release (e_mpi);

    return err ? -1 : 0;
}

void kmocrypt_pkey_destroy (kmocrypt_pkey *self)
{
    if (self) kmocrypt_pkey_clean (self);
    free (self);
}

void kmocrypt_pkey_clean (kmocrypt_pkey *self)
{
    gcry_sexp_release (self->key);
}

