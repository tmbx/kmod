/**
 * kmo/crypt/kmocrypt.c
 * Copyright (C) 2005-2012 Opersys inc., All rights reserved.
 *
 * Kmocrypt initialization and misc. functions.
 *
 * @author Kristian Benoit
 * @author François-Denis Gonthier
 */

#include <stdlib.h>
#include "kmocrypt.h"

#ifndef WIN32
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

/**
 * Proceed to a hash on a kbuffer, putting the result in the
 * hash kbuffer.
 */
void kmocrypt_hash(kbuffer * input, kbuffer * hash, int algo) {
    int digest_len;
    uint32_t input_size;
    
    /* Simple hashing, result is put directly in the buffer, no
       copy needed, no payment until 2099. */

    assert(gcry_md_test_algo(algo) == 0);

    digest_len = gcry_md_get_algo_dlen(algo);

    /* Get the length and addresse of unread data from input, and read it to
     * the end */
    input_size = input->len - input->pos;

    /* Hash the buffer. */
    gcry_md_hash_buffer(algo,
                        kbuffer_append_nbytes(hash, digest_len),
                        kbuffer_read_nbytes(input, input_size),
                        (size_t)input_size);
}

void kmocrypt_init()
{
    gcry_check_version (NULL);
#ifndef WIN32
    gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
#endif /* ! WIN32 */
    gcry_control (GCRYCTL_INIT_SECMEM, 4096);
    gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM); 
    //gcry_control (GCRYCTL_SET_VERBOSITY, 10);
    //gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pth);
}
