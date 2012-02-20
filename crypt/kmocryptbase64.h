#ifndef __KMOCRYPTBASE64_H__
#define __KMOCRYPTBASE64_H__

#include <string.h>
#include <stdint.h>
#include <math.h>

/* Convert from base64 into binary. */
int b642bin (const unsigned char *, uint32_t, uint8_t *, uint32_t *);

#endif /* __KMOCRYPTBASE64_H__ */
