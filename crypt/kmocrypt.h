/**
 * kmo/crypt/include/kmocrypt.h
 * Copyright (C) 2005-2012 Opersys inc., All rights reserved.
 *
 * Kmocrypt initialization and misc. functions.
 *
 * @author Kristian Benoit
 * @author François-Denis Gonthier
 */

#ifndef __KMOCRYPT_H__
#define __KMOCRYPT_H__

#include <gcrypt.h>
#include <errno.h>
#ifndef WIN32
#include <pthread.h>
#endif
#include "kmo_base.h"
#include "kmocryptpkey.h"
#include "kmocryptsignature.h"
#include "kmocryptsignature2.h"
#include "kmocryptversion.h"

/* Call this function at startup and instantiate the globals. */
void kmocrypt_init ();

/* Front-end to gcrypt for hash functions. */
void kmocrypt_hash(kbuffer * input, kbuffer * hash, int algo);

static inline void kmocrypt_sha1_hash(kbuffer * input, kbuffer * hash) {
    kmocrypt_hash(input, hash, GCRY_MD_SHA1);
}

static inline void kmocrypt_sha256_hash(kbuffer * input, kbuffer * hash) {
    kmocrypt_hash(input, hash, GCRY_MD_SHA256);
}

#endif /* __KMOCRYPT_H__ */
