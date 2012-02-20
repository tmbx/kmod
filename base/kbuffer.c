#include "kbuffer.h"
#include "utils.h"
#include "base64.h"

kbuffer *kbuffer_new (unsigned int initial_len)
{
    kbuffer *self = (kbuffer *)kmo_malloc (sizeof(kbuffer));
    kbuffer_init (self, initial_len);
    return self;
}

void kbuffer_destroy (kbuffer *self)
{
    kbuffer_clean (self);
    free (self);
}

void kbuffer_init (kbuffer          *self,
                   unsigned int     initial_len)
{
    assert (self);

    self->len = 0;
    self->pos = 0;
    self->allocated = next_power_of_2 (initial_len);
    self->data = (uint8_t *)kmo_malloc (self->allocated);
}

void kbuffer_clean (kbuffer *self)
{
    if (self) {
        free (self->data);
    }
}

static inline void  maybe_increase_size (kbuffer    *self,
                                        uint32_t    size)
{
    if (self->allocated >= size) return;

    self->allocated = next_power_of_2 (size);
    self->data = kmo_realloc(self->data, self->allocated); 
}

void  kbuffer_write   (kbuffer                 *self,
                       const uint8_t     *const data,
                       uint32_t                 len)
{
    maybe_increase_size (self, self->len + len);
    memcpy (self->data + self->len, data, len);
    self->len += len;
}

void kbuffer_set_size (kbuffer      *self,
                       uint32_t      size)
{
    maybe_increase_size (self, size);
}

uint8_t *kbuffer_append_nbytes (kbuffer         *self,
                                uint32_t         size)
{
    uint8_t *ret_pos;
    kbuffer_set_size(self, self->len + size);
    ret_pos = self->data + self->len;
    self->len += size;

    return ret_pos;
}

uint8_t *kbuffer_read_nbytes (kbuffer          *self,
                              uint32_t          size)
{
    assert (self->len - self->pos >= size);

    uint8_t *ret_pos = self->data + self->pos;
    kbuffer_seek(self, size, SEEK_CUR);
    return ret_pos;
}

uint8_t *kbuffer_begin_write(kbuffer *self,
                             uint32_t max_size)
{
    kbuffer_set_size(self, self->len + max_size);
#ifndef NDEBUG
    self->write_max_size = max_size;
#endif
    return self->data + self->len;
}

void kbuffer_end_write(kbuffer *self,
                       uint32_t size_written)
{
    assert(size_written <= self->write_max_size);
    self->len += size_written;
}

void kbuffer_seek (kbuffer         *self,
                   int32_t          offset,
                   int              whence)
{
    switch (whence) {
        case SEEK_SET:
            break;
        case SEEK_CUR:
            offset = self->pos + offset;
            break;
        case SEEK_END:
            offset = self->len + offset;
            break;
	default: assert(0);
    }
    
    self->pos = (int32_t) MAX(MIN((int32_t)offset, (int32_t)self->len), 0);
}

uint32_t kbuffer_read (kbuffer      *self,
                       uint8_t      *data,
                       uint32_t      len)
{
    len =  MIN (self->len - self->pos, len);
    memcpy (data, self->data + self->pos, len);
    self->pos += len;
    return len;
}

void kbuffer_clear (kbuffer *self)
{
    self->len = 0;
    self->pos = 0;
}

kbuffer *kbuffer_new_b64 (unsigned char *b64,
                          uint32_t       len)
{
    kbuffer *b64_buf = kbuffer_new (len);
    kbuffer *bin_buf = kbuffer_new (len / 4 * 3);

    if (!b64_buf || !bin_buf) goto ERR;

    kbuffer_write (b64_buf, b64, len);
    if (b642bin (b64_buf, bin_buf, 0)) goto ERR;
    
    kbuffer_destroy (b64_buf);
    return bin_buf;

ERR:

    if (b64_buf) kbuffer_destroy (b64_buf);
    if (bin_buf) kbuffer_destroy (bin_buf);
    return NULL;
}
