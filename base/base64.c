/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

#include "base64.h"

/* This table maps values to base64 ASCII characters. */
static const unsigned char base64_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

/* This function converts 3 bytes of 'data' to 4 base64 ASCII characters. */ 
static inline void do_convert_and_write(kbuffer *base64, uint8_t *data) {
    uint8_t out[4];

    out[0] = base64_table[data[0]>>2];
    out[1] = base64_table[(data[0]&0x3)<<4 | (data)[1]>>4];
    out[2] = base64_table[(data[1]&0xF)<<2 | (data)[2]>>6];
    out[3] = base64_table[data[2]&0x3F];
    kbuffer_write(base64, (char *)out, 4);
}

/* This function converts the end of the buffer specified into 4 base64 ASCII
 * characters, dealing with padding as necessary.
 */
static void do_convert_and_write_tail(kbuffer *base64, uint8_t *data, uint32_t len) {
    uint8_t out[4];
    uint8_t in[2];

    assert(base64);
    assert(len < 3);

    if (len == 0) return;

    /* Copy the data first then pad the buffer with 0s. */
    in[0] = data[0];
    in[1] = (len == 2) ? data[1] : 0;

    out[0] = base64_table[in[0]>>2];
    out[1] = base64_table[(in[0]&0x3)<<4 | in[1]>>4];
    out[2] = (len == 2) ?  base64_table[(in[1]&0xF)<<2] : '=';
    out[3] = '=';
    
    kbuffer_write(base64, (char *)out, 4);
}

/* This function converts a binary buffer to a base64 buffer. */
void bin2b64(kbuffer *buffer, kbuffer *base64_buffer) {
    uint32_t nb2write = buffer->len;
    
    kbuffer_set_size(base64_buffer, (buffer->len * 4 + 2) / 3);

    while (nb2write >= 3) {
        do_convert_and_write(base64_buffer, (uint8_t *)(buffer->data + buffer->len - nb2write));
        nb2write -=3;
    }
    
    do_convert_and_write_tail(base64_buffer, (uint8_t *)(buffer->data + buffer->len - nb2write), nb2write);
}

/******************** b642bin **********************/
#define INV (-1)
#define PAD (-2)

/* This table converts a base 64 ASCII character (e.g. A, B) to its binary
 * value. For instance, b642bin_tbl['/'] == 63. '=' is the padding character.
 * Base 64 characters are, in order, A-Z, a-z, 0-9, +, /.
 */
static signed char b642bin_tbl[256] = {
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV, 62,    INV,INV,INV, 63,
     52, 53, 54, 55,     56, 57, 58, 59,
     60, 61,INV,INV,    INV,PAD,INV,INV,
    INV,  0,  1,  2,      3,  4,  5,  6,
      7,  8,  9, 10,     11, 12, 13, 14,
     15, 16, 17, 18,     19, 20, 21, 22,
     23, 24, 25,INV,    INV,INV,INV,INV,
    INV, 26, 27, 28,     29, 30, 31, 32,
     33, 34, 35, 36,     37, 38, 39, 40,
     41, 42, 43, 44,     45, 46, 47, 48,
     49, 50, 51,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
    INV,INV,INV,INV,    INV,INV,INV,INV,
};

/* This function handles padding when padding is detected in the third state of
 * the automaton.
 * This function returns -1 on error, 1 if decoding has ended and 0 otherwise. 
 */
static inline int b642bin_pad(kbuffer *in, kbuffer *out, unsigned char *cs, int ignore_invalid) {

    /* Get the fourth character. */
    while (42) {
	
	/* There are no more characters. Error. */
	if (! (cs[3] = kbuffer_read8(in))) {
	    kmo_seterror ("unexpected character/EOF");
    	    return -1;
	}
    
    	/* The character is invalid. */
	if (b642bin_tbl[cs[3]] != PAD) {

	    /* Error, we don't ignore invalid characters. */
	    if (! ignore_invalid)
	    {
	    	kmo_seterror("invalid padding");
	    	return -1;
	    }
	}
	
	/* We got padding. */
	else {
	    if (b642bin_tbl[cs[1]] & 0xF) {
	    	kmo_seterror("invalid padding");
	    	return -1;
	    }
	    
	    kbuffer_write8(out, b642bin_tbl[cs[0]] << 2 | b642bin_tbl[cs[1]] >> 4);
	    return 0;
    	}
    }
}

/* This function handles the fourth state of the automaton.
   This function returns -1 on error, 1 if decoding has ended and 0 otherwise. */
static inline int b642bin_q3(kbuffer *in, kbuffer *out, unsigned char *cs, int ignore_invalid) {
    
    /* Get the fourth character. */
    while (42) {
	
	/* There are no more characters. Error. */
	if (! (cs[3] = kbuffer_read8(in))) {
	    kmo_seterror ("unexpected character/EOF");
    	    return -1;
	}
    
    	/* The character is invalid. */
	if (b642bin_tbl[cs[3]] == INV) {

	    /* Error, we don't ignore invalid characters. */
	    if (! ignore_invalid) {
	    	kmo_seterror("invalid padding");
	    	return -1;
	    }
	}
	
	/* We got padding. */
	else if (b642bin_tbl[cs[3]] == PAD) {
	    
	    /* The last two bits of the third character must be 0. */
	    if (b642bin_tbl[cs[2]] & 0x3) {
	    	kmo_seterror("invalid padding");
	    	return -1;
	    }
	    
	    /* Shuffle the bits to their positions. */
            kbuffer_write8(out, b642bin_tbl[cs[0]] << 2 | b642bin_tbl[cs[1]] >> 4);
            kbuffer_write8(out, b642bin_tbl[cs[1]] << 4 | b642bin_tbl[cs[2]] >> 2);
	    return 1;
    	}

	/* We got 4 significant characters. Shuffle the bits to their positions. */
	else {
	    kbuffer_write8(out, b642bin_tbl[cs[0]] << 2 | b642bin_tbl[cs[1]] >> 4);
            kbuffer_write8(out, b642bin_tbl[cs[1]] << 4 | b642bin_tbl[cs[2]] >> 2);
            kbuffer_write8(out, b642bin_tbl[cs[2]] << 6 | b642bin_tbl[cs[3]]);
	    return 0;
	}
    }
}

/* This function handles the third state of the automaton.
   This function returns -1 on error, 1 if decoding has ended and 0 otherwise. */
static inline int b642bin_q2(kbuffer *in, kbuffer *out, unsigned char *cs, int ignore_invalid) {
    
    /* Get the third character. */
    while (42) {
	
	/* There are no more characters. Error. */
	if (! (cs[2] = kbuffer_read8(in))) {
	    kmo_seterror ("unexpected character/EOF");
    	    return -1;
	}
    
    	/* The character is invalid. */
	if (b642bin_tbl[cs[2]] == INV) {

	    /* Error, we don't ignore invalid characters. */
	    if (! ignore_invalid) {
	    	kmo_seterror("invalid padding");
	    	return -1;
	    }
	}
	
	/* We got padding. */
	else if (b642bin_tbl[cs[2]] == PAD) {
            return b642bin_pad(in, out, cs, ignore_invalid);
    	}

	/* The character is valid, pass to the next state. */
	else {
	    return b642bin_q3(in, out, cs, ignore_invalid);
	}
    }
}

/* This function handles the second state of the automaton.
   This function returns -1 on error, 1 if decoding has ended and 0 otherwise. */
static inline int b642bin_q1(kbuffer *in, kbuffer *out, unsigned char *cs, int ignore_invalid) {
    
    /* Get the second character. */
    while (42) {
	
	/* There are no more characters. Error. */
	if (! (cs[1] = kbuffer_read8(in))) {
	    kmo_seterror ("unexpected character/EOF");
    	    return -1;
	}
    
    	/* The character is invalid. */
	if (b642bin_tbl[cs[1]] == INV || b642bin_tbl[cs[1]] == PAD) {

	    /* Error, we don't ignore invalid characters. */
	    if (! ignore_invalid) {
	    	kmo_seterror("invalid padding");
	    	return -1;
	    }
	}

	/* The character is valid, pass to the next state. */
	else {
	    return b642bin_q2(in, out, cs, ignore_invalid);
	}
    }
}

/* This function converts a buffer in base64 to a binary buffer.
   'ignore_invalid' is true if invalid base64 characters must be skipped
   silently. This function returns -1 on error, 0 otherwise. */
int b642bin(kbuffer *in, kbuffer *out, int ignore_invalid) {
    int error = 0;
    
    /* We convert four base64 characters at a time. */
    unsigned char cs[4];

    /* Get the first character. */
    while (1) {
      
	/* There are no more characters. We decoded the whole buffer. */
	if (! (cs[0] = kbuffer_read8(in))) {
	    break;
	}

	/* The character is invalid. */
	if (b642bin_tbl[cs[0]] == INV || b642bin_tbl[cs[0]] == PAD) {

	    /* Error, we don't ignore invalid characters. */
	    if (! ignore_invalid) {
	    	kmo_seterror("invalid padding");
	    	error = -1;
		break;
	    }
	}

	/* The character is valid, pass to the next state. */
	else {
	    int ret = b642bin_q1(in, out, cs, ignore_invalid);

	    /* Error. */
	    if (ret < 0) {
	    	error = -1;
		break;
	    }
	    
	    /* Decoding has finished. */
	    if (ret > 0) {
	    	
		/* We ignore trailing characters. */
		if (ignore_invalid) break;
		
		/* We don't ignore invalid characters, so we must be at the end
		 * of the file.
		 */
		error = kbuffer_eof(in) ? 0 : -1;
		break;
	    }
	}
    }
    
    if (error == -1) {
    	kmo_seterror("base64 decoding failed: %s", kmo_strerror());
    }
    
    return error;
}
