#ifndef __KBUFFER_H__
#define __KBUFFER_H__

#include "kmo_base.h"
#include "ntohll.h"


/** The structure representing a kbuffer */
typedef struct _kbuffer {
    uint8_t        *data; /** < the data pointer */
    uint32_t        len; /** < the length of the data */
    uint32_t        pos; /** < the read position in the data */
    uint32_t        allocated; /** < the allocated length of the buffer */
#ifndef NDEBUG
    uint32_t        write_max_size;
#endif
} kbuffer;

/** Create a new buffer converting the data from base64 into binary
 *
 * \param b64 the base64 encoded data.
 * \param len the length of the b64 in bytes.
 * \return a newly allocated kbuffer containing the binary version of b64.
 *
 * Sets kmoerror on error and return NULL;
 */
kbuffer            *kbuffer_new_b64 (unsigned char         *b64,
                                     uint32_t               len);

/** Create a new kbuffer
 *
 * \param def_len the length to allocate for the buffer.
 * \return a newly allocated buffer.
 */
kbuffer            *kbuffer_new     (unsigned int           def_len);

/** destroy a kbuffer object
 *
 * \param self the kbuffer to destroy
 */
void                kbuffer_destroy (kbuffer               *self);

/** Initialize a kbuffer to a minimal length
 *
 * \param self the kbuffer object to initialize
 * \param def_len the length at which to initialize the kbuffer.
 */
void                kbuffer_init    (kbuffer               *self,
    	    	    	    	     unsigned int           def_len);

/** release ressoureces held by a kbuffer object.
 *
 * \param self the kbuffer holding ressources.
 */
void                kbuffer_clean   (kbuffer               *self);

/** write data into the kbuffer (increase the len)
 *
 * \param self the kbuffer object.
 * \param data the data to write.
 * \param len the length of the data to write.
 */
void                kbuffer_write   (kbuffer               *self,
                                     const uint8_t   *const data,
                                     uint32_t               len);

/** read data from a kbuffer (advance the reading pos)
 *
 * \param self the kbuffer object.
 * \param data the returned data read.
 * \param the length of the data to read.
 * \return the number of byte read.
 */
uint32_t            kbuffer_read    (kbuffer               *self,
                                     uint8_t               *data,
                                     uint32_t               len);

/** make sure the buffer is at least size bytes
 *
 * \param self the kbuffer object
 * \param size the requested size for the buffer.
 */
void                kbuffer_set_size (kbuffer              *self,
                                      uint32_t              size);

/** grow the buffer length by size bytes and return a pointer
 * to the appended data, so the user can fill it.
 *
 * \param self the kbuffer object
 * \param size the size needed for data to be appended
 * \return a pointer to memory where you can write size bytes.
 */
uint8_t            *kbuffer_append_nbytes (kbuffer         *self,
                                           uint32_t         size);

/** Start writing
 *
 * \param self the kbuffer object
 * \param size the size to reserve for writing in the kbuffer
 * \return a pointer to memory where you can write.
 */
uint8_t            *kbuffer_begin_write(kbuffer *self,
                                        uint32_t max_size);

/** End writing
 *
 * \param self the kbuffer object
 * \param size the size written into the buffer
 */
void                kbuffer_end_write(kbuffer *self,
                                      uint32_t size_written);

/** Change the read position in the buffer
 *
 * \param self the kbuffer object
 * \param offset the number of bytes to move from whence
 * \param whence SEEK_CUR/SEEK_SET/SEEK_END
 * \see man seek
 */
void                kbuffer_seek    (kbuffer               *self,
                                     int32_t                offset,
                                     int                    whence);

/** Empty the buffer without releasing the ressources. (set pos and len to 0)
 *
 * \param self the kbuffer object.
 */
void                kbuffer_clear   (kbuffer               *self);

/** Tell the absolute position in the buffer
 *
 * \param self the kbuffer object.
 * \return the absolute position in the buffer.
 */
static inline uint32_t kbuffer_tell (kbuffer *self)
{
    return self->pos;
}

/** Get a pointer to the current position in the buffer
 *
 * \param self the kbuffer object
 * \return a pointer to the current pos in the buffer.
 */
static inline uint8_t *kbuffer_current_pos (kbuffer *self)
{
    return self->data + self->pos;
}

/** Tell the number of byte left for reading in the buffer
 *
 * \param self the kbuffer object
 * \return the number of bytes left in the buffer.
 */
static inline uint32_t kbuffer_left (kbuffer *self)
{
    return self->len - self->pos;
}

/** write 1 byte in the buffer
 *
 * \param self the kbuffer object
 * \param data the byte to write.
 * \return the value of the byte written
 */
static inline uint8_t kbuffer_write8 (kbuffer              *self,
                                      uint8_t              data)
{
    kbuffer_write  (self,
                    &(data),
                    sizeof(uint8_t));
    return data;
}

/** write 2 byte in nbo into the buffer
 *
 * \param self the kbuffer object
 * \param data the host ordered bytes to write.
 * \return the value of the bytes written.
 */
static inline uint16_t kbuffer_write16 (kbuffer            *self,
                                        uint16_t            data)
{
    uint16_t nbo  = htons(data);

    kbuffer_write  (self,
                    (uint8_t *)&(nbo),
                    sizeof(uint16_t));
    return nbo;
}

/** write 4 byte in nbo into the buffer
 *
 * \param self the kbuffer object
 * \param data the host ordered bytes to write.
 * \return the value of the bytes written.
 */
static inline uint32_t kbuffer_write32 (kbuffer            *self,
                                        uint32_t            data)
{
    uint32_t nbo  = htonl(data);

    kbuffer_write  (self,
                    (uint8_t *)&(nbo),
                    sizeof(uint32_t));
    return nbo;
}

/** write 8 byte in nbo into the buffer
 *
 * \param self the kbuffer object
 * \param data the host ordered bytes to write.
 * \return the value of the bytes written.
 */
static inline uint64_t kbuffer_write64 (kbuffer    *self,
                                        uint64_t            data)
{
    uint64_t nbo  = htonll(data);

    kbuffer_write  (self,
                    (uint8_t *)&(nbo),
                    sizeof(uint64_t));
    return nbo;
}

/** Read one byte
 *
 * \param self the kbuffer object
 * \return the byte read
 */
static inline uint8_t kbuffer_read8 (kbuffer *self)
{
    uint8_t nbo = 0;
    kbuffer_read (self, &nbo, sizeof(uint8_t));
    return nbo;
}

/** Read 2 bytes and convert to host byte order
 *
 * \param self the kbuffer object.
 * \return the host ordered bytes read.
 */
static inline uint16_t kbuffer_read16 (kbuffer *self)
{
    uint16_t nbo = 0;
    kbuffer_read (self, (uint8_t *)&nbo, sizeof(uint16_t));
    return ntohs(nbo);
}

/** Read 4 bytes and convert to host byte order
 *
 * \param self the kbuffer object.
 * \return the host ordered bytes read.
 */
static inline uint32_t kbuffer_read32 (kbuffer *self)
{
    uint32_t nbo = 0;
    kbuffer_read (self, (uint8_t *)&nbo, sizeof(uint32_t));
    return ntohl(nbo);
}

/** Read 8 bytes and convert to host byte order
 *
 * \param self the kbuffer object.
 * \return the host ordered bytes read.
 */
static inline uint64_t kbuffer_read64 (kbuffer *self)
{
    uint64_t nbo = 0;
    kbuffer_read (self, (uint8_t *)&nbo, sizeof(uint64_t));
    return ntohll(nbo);
}

/** Read a number of bytes into another kbuffer.
 *
 * \param self the kbuffer object to read from.
 * \param into, the kbuffer object to write into.
 * \param the length to read from self.
 * \return the number of bytes written into into.
 */
static inline uint32_t kbuffer_read_into (kbuffer *self, kbuffer *into,
                                          uint32_t len) {
    if (self->len - self->pos < len)
        len = self->len - self->pos;

    kbuffer_write(into, self->data + self->pos, len);
    self->pos += len;

    return len;
}

uint8_t *kbuffer_read_nbytes (kbuffer *self, uint32_t size);


/** Are we at the end of the buffer ?
 *
 * \param self the kbuffer object.
 * \return 0 if eof is not reached, the number of bytes left otherwise.
 */
static inline int kbuffer_eof (kbuffer *self)
{
    return (self->len == self->pos);
}

/* This function ensures that the memory pool allocated to the buffer does not
 * get bigger than 'max_size'. When the memory pool is too large, the memory
 * pool is shrunk to 'max_size'. In all cases, both 'pos' and 'len' are set to
 * 0.
 */
static inline void kbuffer_shrink(kbuffer *self, uint32_t max_size) {   
    if (self->allocated > max_size) {
    	kbuffer_clean(self);
	kbuffer_init(self, max_size);
    }
    
    self->pos = self->len = 0;
}

#endif /*__KBUFFER_H__*/
