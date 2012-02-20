#ifndef _NTOHLL_H
#define _NTOHLL_H

#ifdef __WINDOWS__
#define ntohll(x) (((int64_t)(ntohl((int)((x << 32) >> 32))) << 32) | \
				   (unsigned int)ntohl(((int)(x >> 32)))) //By Runner
#define htonll(x) ntohll(x)
#else
#if __BYTE_ORDER == __BIG_ENDIAN
# define ntohll(x)   (x)
# define htonll(x)   (x)
#else
# if __BYTE_ORDER == __LITTLE_ENDIAN/* LB: removed that, didn't compile: && defined __bswap_64 */
#  define ntohll(x) __bswap_64 (x)
#  define htonll(x) __bswap_64 (x)
# else
#  error No function/macros available to switch between uint64_t endianness.
# endif
#endif
#endif

#endif
