/**
 * kmo/list.h
 * Copyright (C) 2005-2012 Opersys inc., All rights reserved.
 *
 * List utilities.
 *
 * @author François-Denis Gonthier
 */

#ifndef _KLIB_LIST_H
#define _KLIB_LIST_H

#include "kmo_base.h"


typedef struct __llist_item {
	void * data;
	struct __llist_item * prev_item;
	struct __llist_item * next_item;
	size_t data_size;
	int is_copy;
} llist_item;

typedef struct __llist {
	llist_item * first_item;
	llist_item * last_item;
	int length;
} llist;

#define LIST_OK             10
#define LIST_ERROR          -10
#define LIST_MALLOC_ERROR   -11

#define LIST_ITERATOR_START 512
#define LIST_ITERATOR_END   -255
#define LIST_ITERATOR_OK    255
#define LIST_ITERATOR_ERROR 0 

typedef struct __list_iterator {
	llist_item * current_item;
	llist * parent_list;
} llist_iterator;

llist * list_create();
void list_kill(llist *);

void list_dump(llist *, FILE *);

void list_clear(llist *);
llist * list_append_copy(llist * list, void * data, unsigned int n);
llist * list_append(llist *, void *, size_t);
int list_get_item(llist *, int, void **, size_t *);
int list_remove_item_by_ptr(llist *, void *);

int list_get_first(llist *, void **, size_t *);

int list_remove_first(llist *, void **, size_t *);
int list_remove_last(llist *, void **, size_t *);
int list_remove_all(llist *);

llist_iterator * list_iterator_begin(llist *);
void list_iterator_reset(llist_iterator *);
void list_iterator_end(llist_iterator *);
int list_iterator_next(llist_iterator *);
int list_iterator_prev(llist_iterator *);
int list_iterator_get(llist_iterator *, void **, size_t *);
int list_iterator_remove(llist_iterator *, void **, size_t *);

#endif // _KLIB_LIST_H
