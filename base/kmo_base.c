/**
 * kmo/kmo_base.c
 * Copyright (C) 2005-2012 Opersys inc., All rights reserved.
 */


/*******************************************/
/* INCLUDES */

#include "kmo_base.h"


/*******************************************/
/* karray functions */

karray * karray_new() {
    karray *self = (karray *) kmo_malloc(sizeof(karray));
    karray_init(self);
    return self;

}

void karray_destroy(karray *self) {
    karray_free(self);
    free(self);
}

void karray_init(karray *self) {
    self->alloc_size = 0;
    self->size = 0;
    self->data = NULL;
}

void karray_init_karray(karray *self, karray *init_array) {
    self->alloc_size = init_array->size;
    self->size = init_array->size;
    self->data = kmo_malloc(self->size * sizeof(void *));
    memcpy(self->data, init_array->data, self->size * sizeof(void *));
}

void karray_free(karray *self) {
    
    if (self == NULL)
    	return;

    free(self->data);
}

void karray_grow(karray *self, int min_len) {
    assert(min_len >= 0);
    
    if (min_len > self->alloc_size) {
    
        /* Compute the snapped size for a given requested size. By snapping to powers
         * of 2 like this, repeated reallocations are avoided.
         */
        if (min_len < 4) {
            self->alloc_size = 4;
        }
        
        else {
	    self->alloc_size = next_power_of_2(min_len);
        }
        
        assert(self->alloc_size >= min_len);    
        self->data = kmo_realloc(self->data, self->alloc_size * sizeof(void *));
    }
}

void karray_add(karray *self, void *elem) {
    karray_set(self, self->size, elem);
}

void karray_set(karray *self, int pos, void *elem) {
    assert(pos >= 0);

    /* Make sure the array is big enough. */
    karray_grow(self, pos + 1);

    /* Increase the array size to contain at least this position. */
    if (self->size < pos + 1) {
    	self->size = pos + 1;
    }

    self->data[pos] = elem;
}

void karray_assign_karray(karray *self, karray *assign_array) {
    self->size = assign_array->size;
    karray_grow(self, self->size);
    memcpy(self->data, assign_array->data, self->size * sizeof(void *));    
}

void karray_append_karray(karray *self, karray *append_array) {
    karray_grow(self, self->size + append_array->size);
    memcpy(self->data + self->size, append_array->data, append_array->size * sizeof(void *));
    self->size += append_array->size;
}


/*******************************************/
/* khash functions. */

/* Prime table used to grow the hash. */
static unsigned int khash_prime_table[] = {
    23, 53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593, 49157, 98317,
    196613, 393241, 786433, 1572869, 3145739, 6291469, 12582917, 25165843, 50331653,
    100663319, 201326611, 402653189, 805306457, 1610612741, 4294967291u
};

/* The proportion of the cells that must be used before we decide to grow the 
 * hash table.
 */
#define KHASH_FILL_THRESHOLD 0.7

/* This function assumes that pos1 comes before pos2. It returns the distance between the two.
 * It is used internally.
 * Arguments:
 * Position 1.
 * Position 2.
 * Size of the hash (for modulus operation).
 */
inline static int khash_dist(int pos1, int pos2, int base) {
    return (pos1 <= pos2) ? pos2 - pos1 : base - (pos1 - pos2);
}

khash * khash_new() {
    khash *self = (khash *) kmo_malloc(sizeof(khash));
    khash_init(self);
    return self;

}

void khash_destroy(khash *self) {
    khash_free(self);
    free(self);
}

/* This function initializes the hash. By default keys are hashed and compared
 * by pointers.
 */
void khash_init(khash *self) {
    khash_init_func(self, khash_pointer_key, khash_pointer_cmp);
}

void khash_init_func(khash *self, unsigned int (*key_func) (void *), int (*cmp_func) (void *, void *)) {
    self->key_func = key_func;
    self->cmp_func = cmp_func;
    self->size = 0;
    self->used_limit = (int) (11 * KHASH_FILL_THRESHOLD);
    self->next_prime_index = 0;
    self->alloc_size = 11;
    self->cell_array = (struct khash_cell *) kmo_calloc(self->alloc_size * sizeof(struct khash_cell));
}

/* This function sets the key hash and compare functions used to hash objects. */
void khash_set_func(khash *self, unsigned int (*key_func) (void *), int (*cmp_func) (void *, void *)) {
    self->key_func = key_func;
    self->cmp_func = cmp_func;
}

/* This function frees the content of the hash. */
void khash_free(khash *self) {
    if (self == NULL)
    	return;
    
    free(self->cell_array);
}

/* This function increases the size of the hash. */
void khash_grow(khash *self) {
    int index;
    int new_alloc_size;
    struct khash_cell *new_cell_array;
    
    /* Get the new size. */
    new_alloc_size = khash_prime_table[self->next_prime_index];
    self->next_prime_index++;
    self->used_limit = (int) (new_alloc_size * KHASH_FILL_THRESHOLD);

    /* Allocate the new table. */
    new_cell_array = (struct khash_cell *) kmo_calloc(new_alloc_size * sizeof(struct khash_cell));
    
    /* Copy the elements. */
    for (index = 0; index < self->alloc_size; index++) {
        void *key = self->cell_array[index].key;
        
        if (key != NULL) {
            /* Put the key at the right place. */
            int i = self->key_func(key) % new_alloc_size;
            
            while (1) {
                /* OK, found an empty slot. */
                if (new_cell_array[i].key == NULL) {
                    /* Set the key / value pair. */
                    new_cell_array[i].key = key;
                    new_cell_array[i].value = self->cell_array[index].value;
                    break;
    	    	}

                i = (i + 1) % new_alloc_size;
    	    }
    	}
    }
    
    /* Free the old table. */
    free(self->cell_array);
    
    /* Assign the new table and the new size. */
    self->alloc_size = new_alloc_size;
    self->cell_array = new_cell_array;
}    

/* This function returns the position corresponding to the key in the hash, or -1
 * if it is not there.
 * Arguments:
 * Key to locate.
 */
int khash_locate_key(khash *self, void *key) {
    int index;
    assert(key != NULL);
    
    /* Go where the key should be close. */
    index = self->key_func(key) % self->alloc_size;
        
    while (1) {
        /* Empty slot (the key is not there). */
        if (self->cell_array[index].key == NULL)
            return -1;
            
        /* Same slot. Must compare key values. */
        else if (self->cmp_func(self->cell_array[index].key, key))
            return index;
        
        /* Not the same key. Advance to the next position, possibly looping back
	 * to the beginning.
	 */
        index = (index + 1) % self->alloc_size;
    }
}

/* This function adds a key / value pair in the hash. If the key is already
 * present, it will be replaced. The key cannot be NULL.
 * Arguments:
 * Key to add.
 * Value to add.
 */
void khash_add(khash *self, void *key, void *value) {
    int index;
    assert(key != NULL);
    
    /* Grow hash if it is too small. */
    if (self->size >= self->used_limit)
        khash_grow(self);

    /* Go where the key should be close. */
    index = self->key_func(key) % self->alloc_size;

    while (1) {
    
        /* Empty slot. It's a new key. */
        if (self->cell_array[index].key == NULL) {
	
            /* Increment use count. */
            self->size++;
            
            /* Set the key / value pair. */
            self->cell_array[index].key = key;
            self->cell_array[index].value = value;
            return;
    	}
        
        /* Must compare key values. If they are the same, replace them. */
        if (self->cmp_func(self->cell_array[index].key, key)) {
	
            /* Replace key / value pair. */
            self->cell_array[index].key = key;
            self->cell_array[index].value = value;
            return;
    	}
        
        /* Not the same key. Advance to the next position, possibly looping back
	 * to the beginning.
	 */
        index = (index + 1) % self->alloc_size;
    }
}

/* This function removes the key / value pair from the hash (if any).
 * Arguments:
 * Key to remove.
 */
void khash_remove(khash *self, void *key) {
    int index = khash_locate_key(self, key);
    int gap_position = index;
    int scanned_pos = index;
    
    /* Key is not present in the hash. */
    if(index == -1)
        return;
    
    /* We must ensure that other keys remain contiguous when we remove a key.
     * The situation where we need to move a key up is when the position of the
     * key given by key_func() is farther than the actual position of the key in
     * the hash, counting  from the position of the gap. Picture:
     *
     * The key wants to be here. (Distance between gap and pos wanted is far.)
     * A gap is here.            (So we move the key here.)
     * The key is here.          (Distance between gap and key is close.)
     *
     * In this situation, we don't move:
     * The gap is here.        
     * The key wants to be here. (Distance between gap and pos wanted is short.)
     * The key is here.          (Distance between gap and key is far.)
     *
     * If the gap position matches the wanted pos, we must move the key to fill
     * the gap.
     *
     * So here's the plan:
     * First we locate the key to remove. Removing it causes a gap. We start
     * scanning the keys coming next. If we meet a NULL, we're done. If we meet
     * a key, we check where it wants to be. If it wants to be before the gap,
     * we move it there. Then the gap is now at the position of the key we
     * moved, and we continue at the next position. Otherwise, we just continue 
     * with the next position.
     */
    while (1) {
    	int wanted_pos_dist;
	int key_dist;
	
        /* Scan the next position. */
        scanned_pos = (scanned_pos + 1) % self->alloc_size;

        /* We're done. Just set the gap to NULL. */
        if (self->cell_array[scanned_pos].key == NULL) {
            self->cell_array[gap_position].key = NULL;
            break;
    	}

        /* Calculate the distances. */
        wanted_pos_dist = khash_dist(gap_position,
	    	    	    	     self->key_func(self->cell_array[scanned_pos].key) % self->alloc_size,
				     self->alloc_size);
        key_dist = khash_dist(gap_position, scanned_pos, self->alloc_size);    

        /* Situations where we must move key (and value). */
        if (wanted_pos_dist > key_dist || wanted_pos_dist == 0) {
            self->cell_array[gap_position].key = self->cell_array[scanned_pos].key;
            self->cell_array[gap_position].value = self->cell_array[scanned_pos].value;
            gap_position = scanned_pos;
    	}
    }

    /* Decrement the usage count. */
    self->size--;
}

/* This function returns the value corresponding to the key, or NULL if the key
 * is not in the hash.
 * Arguments:
 * Key to look for.
 */
void * khash_get(khash *self, void *key) {
    int index = khash_locate_key(self, key);

    if (index == -1)
    	return NULL;

    return self->cell_array[index].value;
}
    
/* This function returns the key in the hash corresponding to the key, or NULL
 * if it is not in the hash. This function is useful when the key you supplied
 * is dynamically allocated and you don't have a pointer to it anywhere except
 * in the hash itself.
 * Arguments:
 * Key to look for.
 */
void * khash_get_key(khash *self, void *key) {
    int index = khash_locate_key(self, key);

    if (index == -1)
        return NULL;
    
    return self->cell_array[index].key;
}

/* This function clears all entries in the hash. */
void khash_clear(khash *self) {
    self->size = 0;
    self->used_limit = (int) (11 * KHASH_FILL_THRESHOLD);
    self->next_prime_index = 0;
    self->alloc_size = 11;
    self->cell_array = (struct khash_cell *) kmo_realloc(self->cell_array,
    	    	    	    	    	    	    	 self->alloc_size * sizeof(struct khash_cell));
    memset(self->cell_array, 0, self->alloc_size * sizeof(struct khash_cell));
}

/* This function sets the key / value pair of the next element in the
 * enumeration. It is safe to call this function even if some of the keys in
 * the hash are invalid, e.g. if you freed the pointers to the objects used as
 * the keys. Be careful not to iterate past the end of the hash.
 * Arguments:
 * Pointer to iterator index, which should be initialized to -1 prior to the 
 *   first call.
 * Pointer to the location where you wish the key to be set; can be NULL.
 * Pointer to the location where you wish the value to be set; can be NULL.
 */
void khash_iter_next(khash *self, int *index, void **key_handle, void **value_handle) {
    
    for ((*index)++; *index < self->alloc_size; (*index)++) {
        if (self->cell_array[*index].key != NULL) {
            if (key_handle != NULL)
                *key_handle = self->cell_array[*index].key;
            
            if (value_handle != NULL)
                *value_handle = self->cell_array[*index].value;
    	    
            return;
        }
    }
    
    assert(0);
}

/* Same as above, except that it returns only the next key. */
void * khash_iter_next_key(khash *self, int *index) {

    for ((*index)++; *index < self->alloc_size; (*index)++)
        if (self->cell_array[*index].key != NULL)
            return self->cell_array[*index].key;
    
    assert(0);
    return NULL;
}

/* Same as above, except that it returns only the next value. */
void * khash_iter_next_value(khash *self, int *index) {
    
    for ((*index)++; *index < self->alloc_size; (*index)++)
        if (self->cell_array[*index].key != NULL)
            return self->cell_array[*index].value;
    
    assert(0);
    return NULL;
}


/*******************************************/
/* kstr functions */

kstr * kstr_new() {
    kstr *str = (kstr *) kmo_malloc(sizeof(kstr));
    kstr_init(str);
    return str;
}

void kstr_destroy(kstr *str) {
    kstr_free(str);
    free(str);
}

void kstr_init(kstr *self) {
    self->slen = 0;
    self->mlen = 8;
    self->data = (char *) kmo_malloc(self->mlen);
    self->data[0] = 0;
}

void kstr_init_cstr(kstr *self, const char *init_str) {
    if (init_str == NULL) {
        init_str = "";
    }
    
    kstr_init_buf(self, init_str, strlen(init_str));
}

void kstr_init_kstr(kstr *self, kstr *init_str) {
    kstr_init_buf(self, init_str->data, init_str->slen);
}

void kstr_init_buf(kstr *self, const void *buf, int buf_len) {
    self->slen = buf_len;
    self->mlen = buf_len + 1;
    self->data = (char *) kmo_malloc(self->mlen);
    memcpy(self->data, buf, buf_len);
    self->data[buf_len] = 0;
}

void kstr_free(kstr *self) {
    
    if (self == NULL)
    	return;

    free(self->data);
}

void kstr_grow(kstr *self, int min_slen) {
    assert(min_slen >= 0);
    
    if (min_slen >= self->mlen) {
    
        /* Compute the snapped size for a given requested size. By snapping to powers
         * of 2 like this, repeated reallocations are avoided.
         */
        if (min_slen < 8) {
            self->mlen = 8;
        }
        
        else {
	    self->mlen = next_power_of_2(min_slen);
        }
        
        assert(self->mlen > min_slen);    
        self->data = (char *) kmo_realloc(self->data, self->mlen);
    }
}

void kstr_clear(kstr *self) {
    self->slen = 0;
    self->data[0] = 0;
}

/* This function ensures that the string specified does not get too large. If
 * the internal memory associated to the string is bigger than the threshold
 * specified, the memory associated to the string is released and a new, small
 * buffer is allocated for the string. In all cases, the string is cleared
 * ('slen' is set to 0).
 */
void kstr_shrink(kstr *self, int max_size) {
    if (self->slen > max_size) {
    	kstr_free(self);
	kstr_init(self);
    }

    self->slen = 0;
}

void kstr_assign_cstr(kstr *self, const char *assign_str) {
    if (assign_str == NULL) {
        assign_str = "";
    }
    
    kstr_assign_buf(self, assign_str, strlen(assign_str)); 
}

void kstr_assign_kstr(kstr *self, kstr *assign_str) {
    kstr_assign_buf(self, assign_str->data, assign_str->slen);   
}

void kstr_assign_buf(kstr *self, const void *buf, int buf_len) {
    kstr_grow(self, buf_len);
    memcpy(self->data, buf, buf_len);
    self->data[buf_len] = 0;
    self->slen = buf_len;
}

void kstr_append_char(kstr *self, char c) {
    self->slen++;
    kstr_grow(self, self->slen);
    self->data[self->slen - 1] = c;
    self->data[self->slen] = 0;
}

void kstr_append_cstr(kstr *self, const char *append_str) {
    kstr_append_buf(self, append_str, strlen(append_str));
}

void kstr_append_kstr(kstr *self, kstr *append_str) {
    kstr_append_buf(self, append_str->data, append_str->slen);
}

void kstr_append_buf(kstr *self, const void *buf, int buf_len) {
    kstr_grow(self, self->slen + buf_len);
    memcpy(self->data + self->slen, buf, buf_len);
    self->slen += buf_len;
    self->data[self->slen] = 0;
}

void kstr_sf(kstr *self, const char *format, ...) {
    va_list arg;
    va_start(arg, format);
    kstr_sfv(self, format, arg);
    va_end(arg);
}

void kstr_sfv(kstr *self, const char *format, va_list arg) {

    /* vsnprintf() is defined in a standard. Some UNIX systems implement it
     * correctly.
     */
    #ifndef __WINDOWS__
    
    /* Determine the size of the resulting string. */
    int print_size;
    va_list arg2;
    
    va_copy(arg2, arg);
    print_size = vsnprintf(NULL, 0, format, arg2);
    assert(print_size >= 0);
    va_end(arg2);
    
    self->slen = print_size;
    kstr_grow(self, self->slen);
    
    /* Do the sprintf(). */
    print_size = vsnprintf(self->data, self->slen + 1, format, arg);
    assert(print_size == self->slen);
    
    /* Windows doesn't support it correctly, though. */
    #else
    while (1) {
        /* Use _vsnprintf() with its ugly semantics. */
        va_list arg2;
        int print_size;
        
        va_copy(arg2, arg);
        print_size = _vsnprintf(self->data, self->mlen, format, arg2);
        va_end(arg2);
        
        if (print_size == -1) {
            kstr_grow(self, self->mlen * 2);
        }
        
        else {
            self->slen = print_size;
            break;
        }
    }
    #endif
}

void kstr_mid(kstr *self, kstr *mid_str, int begin_pos, int size) {
    assert(begin_pos + size <= self->slen);
    kstr_grow(mid_str, size);
    memcpy(mid_str->data, self->data + begin_pos, size);
    mid_str->data[size] = 0;
    mid_str->slen = size;
}

int kstr_equal_cstr(kstr *first, const char *second) {
    return (strcmp(first->data, second) == 0);
}

int kstr_equal_kstr(kstr *first, kstr *second) {
    return (strcmp(first->data, second->data) == 0);
}


/*******************************************/
/* KMO error API */

/* Error string currently set. */
static kstr kmo_error_str;

/* Scratch space for sprintf() and friends. */
static kstr kmo_scratch_str;

void kmo_error_start() {
    kstr_init(&kmo_error_str);
    kstr_init(&kmo_scratch_str);
}

void kmo_error_end() {
    kstr_free(&kmo_error_str);
    kstr_free(&kmo_scratch_str);
}

void kmo_seterror(const char *format, ...) {
    /* Make the sprintf(). */
    va_list arg;
    va_start(arg, format);
    kstr_sfv(&kmo_scratch_str, format, arg);
    va_end(arg);
    
    /* Set the error string. */
    kstr_assign_kstr(&kmo_error_str, &kmo_scratch_str);
}

void kmo_setkerror(kstr *str) {
    kstr_assign_kstr(&kmo_error_str, str);
}

char * kmo_syserror() {
    return (errno ? strerror(errno) : NULL);
}

char * kmo_neterror() {
    #ifdef __WINDOWS__
    return strerror(WSAGetLastError());
    #else
    return kmo_syserror();
    #endif
}

char * kmo_strerror() {
    return ((kmo_error_str.slen == 0) ? NULL: kmo_error_str.data);
}

kstr * kmo_kstrerror() {
    return &kmo_error_str;
}

void kmo_clearerror() {
    kstr_clear(&kmo_error_str);
}

void kmo_fatalerror(const char *format, ...) {
    /* Make the fprintf(). */
    va_list arg;
    va_start(arg, format);
    vfprintf(stderr, format, arg);
    va_end(arg);
    
    /* Exit now. */
    _exit(1);
}


/*******************************************/
/* Utility functions. */

void kmo_clear_kstr_array(karray *array) {
    int i;

    for (i = 0; i < array->size; i++) {
    	kstr_destroy((kstr *) array->data[i]);
    }
	
    array->size = 0;
}

unsigned int khash_pointer_key(void *key) {
    return (unsigned int) (((size_t) key) * 3);
}

int khash_pointer_cmp(void *key_1, void *key_2) {
    return key_1 == key_2;
}

unsigned int khash_cstr_key(void *key) {
    char *str = (char *) key;
    unsigned int value = 0;
    int str_size = strlen(str);
    int index ;

    for(index = 0; index < str_size; index++)
    	value += str[index];

    return value;
}

int khash_cstr_cmp(void *key_1, void *key_2) {
    return (strcmp((char *) key_1, (char *) key_2) == 0);
}

unsigned int khash_kstr_key(void *key) {
    return khash_cstr_key(((kstr *) key)->data);
}

int khash_kstr_cmp(void *key_1, void *key_2) {
    kstr *str_1 = (kstr *) key_1;
    kstr *str_2 = (kstr *) key_2;
    return (str_1->slen == str_2->slen && ! memcmp(str_1->data, str_2->data, str_1->slen));
}

unsigned int khash_int_key(void *key) {
    unsigned int *i = (unsigned *) key;

    return (*i * 3);
}

int khash_int_cmp(void *key_1, void *key_2) {
    return *(unsigned int *) key_1 == *(unsigned int *) key_2;
}
