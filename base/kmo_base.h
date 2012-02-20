/**
 * kmo/shared/kmo_base.h
 * Copyright (C) 2005-2012 Opersys inc., All rights reserved.
 */

#ifndef _KMO_BASE_H
#define _KMO_BASE_H


/*******************************************/
/* INCLUDES */

/* System includes. For some reasons, unistd.h and fctnl.h seem to work for our
 * Windows build.
 */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

/* Platform-specific includes. */
#ifdef __WINDOWS__
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#endif

/* Enable this to redefine assert() so that it causes a segmentation fault on 
 * assertion failure. This allows you to get a stack trace with valgrind.
 */
#ifndef NDEBUG
#undef assert
#define assert(X) if(! (X)) { printf("Assertion failure at file %s, line %d.\n", __FILE__, __LINE__); *(int *) 0 = 0; }
#endif


/*******************************************/
/* MACROS */

#ifndef MIN
#define MIN(a,b) a<b?a:b
#endif

#ifndef MAX
#define MAX(a,b) a>b?a:b
#endif


/*******************************************/
/* Malloc and friends wrappers. We use these functions to exit when KMO is out
 * of memory, since we cannot recover from an 'out of memory' condition in
 * general.
 */
static inline void * kmo_malloc(unsigned int count) {
    void *ptr = malloc(count);
    
    if (ptr == NULL) {
        fprintf(stderr, "out of memory");
        exit(1);
    }
    
    return ptr;
}

static inline void * kmo_calloc(unsigned int count) {
    void *ptr = calloc(1, count);
    
    if (ptr == NULL) {
        fprintf(stderr, "out of memory");
        exit(1);
    }
    
    return ptr;
}

static inline void * kmo_realloc(void *ptr, unsigned int count) {
    ptr = realloc(ptr, count);
    
    if (ptr == NULL) {
        fprintf(stderr, "out of memory");
        exit(1);
    }
    
    return ptr;
}


/*******************************************/
/* Minimal implementation of an array object. */

typedef struct karray {
    
    /* The allocated array size (in terms of elements). */
    int alloc_size;
    
    /* The number of elements in the array. */ 
    int size;
    
    /* The element array. */
    void **data;
} karray;

/* This function allocates and creates an empty array. */
karray * karray_new();

/* This function frees the array data and destroys the array. */
void karray_destroy(karray *self);

/* This function creates an empty array. */
void karray_init(karray *self);

/* This function initializes the array from the karray 'init_array'. */
void karray_init_karray(karray *self, karray *init_array);

/* This function frees the array data. */
void karray_free(karray *self);

/* This function increases the size of the array so that it may contain at least
 * 'min_len' elements.
 */
void karray_grow(karray *self, int min_len);

/* This function adds an element at the end of the array. */
void karray_add(karray *self, void *elem);

/* This function sets an element at the specified position in the array. */
void karray_set(karray *self, int pos, void *elem);

/* This function assigns a karray to this array. */
void karray_assign_karray(karray *self, karray *assign_array);

/* This function appends a karray to this array. */
void karray_append_karray(karray *self, karray *append_array);


/*******************************************/
/* Hash implementation. */

/* A cell in the hash table: a key and its associated value. */
struct khash_cell {
    void *key;
    void *value;
};

/* The hash itself. */
typedef struct khash {
    
    /* The hashing function used by this hash. This function takes a key object
     * as its argument and returns an integer often unique for that object. By
     * default, we use the value of the pointer as the integer.
     */
    unsigned int (*key_func) (void *);

    /* The comparison function used by this hash. This function takes two key
     * objects as its arguments and returns true if the objects are the same. By
     * default, we compare the values of the pointers.
     */
    int (*cmp_func) (void *, void *);

    /* The table containing the hash cells. */
    struct khash_cell *cell_array;

    /* Size of the table. */
    int alloc_size;

    /* Number of cells used in the table. */
    int size;

    /* Maximum number of cells that can be used before the hash is expanded. */
    int used_limit;

    /* Next index in the prime table to grow the hash. */
    int next_prime_index;
} khash;

khash * khash_new();
void khash_destroy(khash *self);
void khash_init(khash *self);
void khash_init_func(khash *self, unsigned int (*key_func) (void *), int (*cmp_func) (void *, void *));
void khash_set_func(khash *self, unsigned int (*key_func) (void *), int (*cmp_func) (void *, void *));
void khash_free(khash *self);
void khash_grow(khash *self);
int khash_locate_key(khash *self, void *key);
void khash_add(khash *self, void *key, void *value);
void khash_remove(khash *self, void *key);
void * khash_get(khash *self, void *key);
void * khash_get_key(khash *self, void *key);
void khash_clear(khash *self);
void khash_iter_next(khash *self, int *index, void **key_handle, void **value_handle);
void * khash_iter_next_key(khash *self, int *index);
void * khash_iter_next_value(khash *self, int *index);

/* This function returns true if the key is in the hash.
 * Arguments:
 * Key to look for.
 */
static inline int khash_exist(khash *self, void *key) {
    return (khash_locate_key(self, key) != -1);
}


/*******************************************/
/* Minimal implementation of a string object. */

typedef struct kstr
{
    /* The allocated buffer size. */
    int mlen;
    
    /* The string length, not including the final '0'. */
    int slen;
    
    /* The character buffer, always terminated by a '0'.
     * Note that there may be other '0' in the string.
     */
    char *data;
} kstr;

/* This function allocates and returns an empty kstr. */
kstr * kstr_new();

/* This function frees the string data and the kstr object. */
void kstr_destroy(kstr *str);

/* This function initializes the string to an empty string. */
void kstr_init(kstr *self);

/* This function initializes the string to the C string 'init_str'. */
void kstr_init_cstr(kstr *self, const char *init_str);

/* This function initializes the string to the kstr 'init_str'. */
void kstr_init_kstr(kstr *self, kstr *init_str);

/* This function initializes the string to the buffer 'buf'. */
void kstr_init_buf(kstr *self, const void *buf, int buf_len);

/* This function frees the string data. */
void kstr_free(kstr *self);

/* This function increases the size of the memory containing the string so that it
 * may contain at least 'min_slen' characters (not counting the terminating '0').
 */
void kstr_grow(kstr *self, int min_slen);

/* This function assigns the empty string to the string. */
void kstr_clear(kstr *self);
void kstr_shrink(kstr *self, int max_size);

/* This function assigns a C string to this string. */
void kstr_assign_cstr(kstr *self, const char *assign_str);

/* This function assigns a kstr to this string. */
void kstr_assign_kstr(kstr *self, kstr *assign_str);

/* This function assigns the content of a raw buffer to the string. */
void kstr_assign_buf(kstr *self, const void *buf, int buf_len);

/* This function appends a character to the string. */
void kstr_append_char(kstr *self, char c);

/* This function appends a C string to the string. */
void kstr_append_cstr(kstr *self, const char *append_str);

/* This function appends a kstr to the string. */
void kstr_append_kstr(kstr *self, kstr *append_str);

/* This function appends a raw buffer to the string (zeros are appended like
 * other characters).
 */
void kstr_append_buf(kstr *self, const void *buf, int buf_len);

/* This function allows you to sprintf() directly inside the string. 
 * Arguments: 
 * Format is the usual printf() format, and the following args are the args that
 *   printf() takes.
 */
void kstr_sf(kstr *self, const char *format, ...);

/* SYSTEM-DEPENDENT function.
 * Same as above, but takes a va_list argument.
 */
void kstr_sfv(kstr *self, const char *format, va_list arg);

/* This function extracts a substring from the string and places it in 'mid_str'.
 * Arguments:
 * Source string.
 * String that will contain the substring.
 * Beginning of the substring in this string.
 * Size of the substring.
 */
void kstr_mid(kstr *self, kstr *mid_str, int begin_pos, int size);

/* This function returns true if the two strings are the same. */
int kstr_equal_cstr(kstr *first, const char *second);

/* This function returns true if the two strings are the same. */
int kstr_equal_kstr(kstr *first, kstr *second);


/*******************************************/
/* KMO error API */

/* The KMO error API should be thread-safe eventually. For now it is not,
 * but the interface should not change even if when we make it thread-safe.
 */

/**
 * This function initializes the error module. Must be done at startup, before
 * calls are made to the functions below.
 */
void kmo_error_start();

/** 
 * This function cleans up the error module. Must be done when the program is
 * exiting, to free all memory.
 */
void kmo_error_end();

/**
 * This function sets an error message. It is ok to refer to the string returned
 * by the last kmo_strerror() call.
 */
void kmo_seterror(const char *format, ...);

/** 
 * This function sets a formatted error message directly.
 */
void kmo_setkerror(kstr *str);

/**
 * This function returns the system error string that is currently set, or NULL
 * if there is none.
 */
char * kmo_syserror();

/**
 * This function returns a string corresponding to the last network error.
 */
char * kmo_neterror();

/**
 * This function returns the error message that is currently set, or NULL if
 * there is none.
 */
char * kmo_strerror();

/**
 * This function returns a pointer to the kstr containing the current error
 * message.
 */
kstr * kmo_kstrerror();

/**
 * This function clears the error message that is currently set.
 */
void kmo_clearerror();

/**
 * This function should be called when a fatal error occurs.
 * The program will terminate immediately.
 */
void kmo_fatalerror(const char *format, ...);


/*******************************************/
/* Misc. functions. */

/* This function allocates 'size' bytes of memory with kmo_malloc(), copies
 * 'size' bytes of object 'data' into the allocated buffer and returns the
 * allocated buffer.
 */
static inline void * kmo_clone_obj(void *data, unsigned int size) {
    return memcpy(kmo_malloc(size), data, size);
}

/* This function returns the power of 2 just over the value specified. This
 * function assumes that your system is at least 32 bits and that you use will
 * not use values larger than 4GB.
 */
static inline int next_power_of_2(int val)
{
    /* Fill every bits at right of the leftmost set bit:
     * 0001 0000 0000
     * 0001 1000 0000
     * 0001 1110 0000
     * 0001 1111 1110
     * 0001 1111 1111
     *
     * Then add one:
     * 0010 0000 0000
     *
     * So only the next bit to the left of the leftmost bit set is set after 
     * those operations.
     */
    val |= (val >>  1);
    val |= (val >>  2);
    val |= (val >>  4);
    val |= (val >>  8);
    val |= (val >> 16);
    val += 1;

    return val;
}


/*******************************************/
/* Utility functions. */

/* This function frees the content of an array of kstr. */
void kmo_clear_kstr_array(karray *array);

/* Some hash functions frequently used. */
unsigned int khash_pointer_key(void *key);
int khash_pointer_cmp(void *key_1, void *key_2);
unsigned int khash_cstr_key(void *key);
int khash_cstr_cmp(void *key_1, void *key_2);
unsigned int khash_kstr_key(void *key);
int khash_kstr_cmp(void *key_1, void *key_2);
unsigned int khash_int_key(void *key);
int khash_int_cmp(void *key_1, void *key_2);


#endif

