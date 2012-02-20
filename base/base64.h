/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

/* Reviewed by Laurent Birtz and Kristian Benoit on 22 january 2007.
 * Merged in KMOD on 26 april 2007.
 */

#ifndef _BASE64_H
#define _BASE64_H

#include "kmo_base.h"
#include "kbuffer.h"

void bin2b64(kbuffer *buffer, kbuffer *base64_buffer);
int b642bin(kbuffer *in, kbuffer *out, int ignore_invalid);

#endif
