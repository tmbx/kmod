/**
 * kmo/list.c
 * Copyright (C) 2005-2012 Opersys inc., All rights reserved.
 *
 * List utilities.
 *
 * @author François-Denis Gonthier
 */

#include "list.h"

static llist_item * list_alloc_item_copy(void * data, size_t n) {
	void * item_data_ptr = NULL;
	llist_item * item;

	if (data != NULL) {
		item_data_ptr = malloc(n);
		if (item_data_ptr != NULL)	   
			memcpy(item_data_ptr, data, n);
		else
			return NULL;
	}

	item = (llist_item *) malloc(sizeof(llist_item));
	if (item != NULL) {
		item->data = item_data_ptr;
		item->data_size = n;
		item->is_copy = 1;
		item->prev_item = NULL;
		item->next_item = NULL;
	} else {
		free(item_data_ptr);
		return NULL;
	}
		
	return item;
}

static llist_item * list_alloc_item(void * data, size_t n) {
	llist_item * item;

	item = (llist_item *) malloc(sizeof(llist_item));
	if (item != NULL) {
		item->data = data;
		item->data_size = n;
		item->is_copy = 0;
		item->prev_item = NULL;
		item->next_item = NULL;
	} else 
		return NULL;

	return item;
}

/**
 * Dump the whole list on a particular file.
 *
 * This procedure expects data to be char *, and thus
 * printfable.  Results will be unexpected on other kind
 * of data.
 */
void list_dump(llist * list, FILE * f) {
	llist_iterator * iter;
	void * item_data;

	iter = list_iterator_begin(list);
	if (iter == NULL) return;

	while (list_iterator_get(iter, NULL, NULL) != LIST_ITERATOR_END) {
		list_iterator_get(iter, &item_data, NULL);		
		fprintf(f, "%s", (char *)item_data);
		list_iterator_next(iter);
		
		if (list_iterator_get(iter, NULL, NULL) != LIST_ITERATOR_END)
			fprintf(f, ", ");
	}

	list_iterator_end(iter);
}

/**
 * Allocates an empty list.
 */
llist * list_create() {
	llist * list;

	list = malloc(sizeof(llist));
	
	if (list == NULL) 
		return NULL;
	else {
		list->first_item = NULL;
		list->last_item = NULL;
		list->length = 0;
	}

	return list;
}

/**
 * Terminates the list with prejudice.
 *
 * Erase every item in the list that was allocated
 * by the list code.  That means items not added with
 * list_append_static.
 */
void list_kill(llist * list) {
	if (list != NULL) {
		list_clear(list);
		free(list);
	}
}

/**
 * Empty the list.
 *
 * Calls list_iterator_remove() for every items in the
 * list.
 */
void list_clear(llist * list) {
	llist_iterator * iter;

	if (list == NULL)
		return;
	else
		iter = list_iterator_begin(list);

	while (list_iterator_get(iter, NULL, NULL) != LIST_ITERATOR_END) 
		list_iterator_remove(iter, NULL, NULL);

	list_iterator_end(iter);
}

static llist * list_append_item(llist * list, llist_item * new_item) {
	if (new_item == NULL)
		return NULL;
	else {
		new_item->prev_item = list->last_item;
		new_item->next_item = NULL;

		if (list->first_item == NULL) {
			list->first_item = new_item;
			list->last_item = new_item;
		} else {
			list->last_item->next_item = new_item;
			list->last_item = new_item;			
		}
		list->length++;
	}
	
	return list;
}

llist * list_append_copy(llist * list, void * data, unsigned int n) {
	llist_item * new_item;

	if (list == NULL)
		return NULL;

	new_item = list_alloc_item_copy(data, n);
	
	return list_append_item(list, new_item);
}

llist * list_append(llist * list, void * data, size_t n) {
	llist_item * new_item;

	if (list == NULL)
		return NULL;

	new_item = list_alloc_item(data, n);
	
	return list_append_item(list, new_item);
}

int list_get_first(llist * list, void ** data, size_t * data_size) {
	llist_item * ci;

	if (list != NULL && list->length != 0)
		ci = list->first_item;
	else
		return LIST_ERROR;

	if (data != NULL)
		*data = ci->data;
	if (data_size != NULL)
		*data_size = ci->data_size;
	
	return LIST_OK;
}

/**
 *
 */
int list_remove_all(llist * list) {
	llist_iterator * iter;

	iter = list_iterator_begin(list);
	
	if (iter == NULL) 
		return LIST_MALLOC_ERROR;

	while (list_iterator_get(iter, NULL, NULL) != LIST_ITERATOR_END) 
		list_iterator_remove(iter, NULL, NULL);

	list_iterator_end(iter);
	return LIST_OK;
}

/**
 *
 */
int list_remove_first(llist * list, void ** data, size_t * data_size) {
	llist_item * ci;

	if (list != NULL && list->length != 0)
		ci = list->first_item;
	else
		return LIST_ERROR;

	if (data != NULL)
		*data = ci->data;
	if (data_size != NULL)
		*data_size = ci->data_size;
		
	if (list->first_item == list->last_item) {
		list->first_item = NULL;
		list->last_item = NULL;
		list->length = 0;
	} else {
		list->first_item = ci->next_item;
		list->first_item->prev_item = NULL;
		list->length--;
	}

	if (ci->is_copy && data == NULL) 
		free(ci->data);
	free(ci);

	return LIST_OK;
}

/**
 *
 */
int list_remove_last(llist * list, void ** data, size_t * data_size) {
	llist_item * ci;
	
	if (list != NULL && list->length != 0)
		ci = list->last_item;
	else
		return LIST_ERROR;

	if (data != NULL)
		*data = ci->data;
	if (data_size != NULL)
		*data_size = ci->data_size;

	if (list->first_item == list->last_item) {
		list->first_item = NULL;
		list->last_item = NULL;
		list->length = 0;
	} else {
		list->last_item = ci->prev_item;
		ci->prev_item->next_item = NULL;
		list->length--;
	}

	if (ci->is_copy && data == NULL)
		free(ci->data);
	free(ci);

	return LIST_OK;
}

int list_get_item(llist * list, int n, void ** data, size_t * data_size) {
	int i;
	llist_item * ci = list->first_item;

	for (i = 0; i < n; i++) {
		if (ci->next_item == NULL)
			return -1;
		else
			ci = ci->next_item;
	}

	if (data != NULL)
		*data = ci->data;
	if (data_size != NULL)
		*data_size = ci->data_size;
	
	return i;	
}

int list_remove_item_by_ptr(llist * list, void * item_data) {
	llist_iterator * iter;
	void * id;

	iter = list_iterator_begin(list);
	
	if (iter == NULL) 
		return LIST_MALLOC_ERROR;

	while (list_iterator_get(iter, &id, NULL) != LIST_ITERATOR_END) {
		if (item_data == id) {
			list_iterator_remove(iter, NULL, NULL);
			return LIST_OK;
		}
	}

	return LIST_ERROR;
}

void list_iterator_reset(llist_iterator * iterator) {
	iterator->current_item = iterator->parent_list->first_item;
}

/**
 * Allocates and initializes a new list iterator.
 */
llist_iterator * list_iterator_begin(llist * list) {
	llist_iterator * iterator;

	if (list == NULL)
		return NULL;

	iterator = (llist_iterator *) malloc(sizeof(llist_iterator));
	
	if (iterator == NULL)
		return NULL;
	else {
		iterator->current_item = list->first_item;
		iterator->parent_list = list;
	}

	return iterator;
}

/**
 * Frees the iterator.
 */
void list_iterator_end(llist_iterator * iterator) {	
	if (iterator != NULL)
		free(iterator);
}

/**
 * Return the item currently selected by the iterator.
 */
int list_iterator_get(llist_iterator * iterator, void ** data, size_t * data_size) {	
	if (iterator != NULL) {
		if (iterator->current_item != NULL) {
			if (data != NULL)
				*data = iterator->current_item->data;
			if (data_size != NULL)
				*data_size = iterator->current_item->data_size;

			return LIST_ITERATOR_OK;
		} else
			return LIST_ITERATOR_END;
	}

	return LIST_ITERATOR_ERROR;
}

/**
 * Make the iterator move to the next item.
 */
int list_iterator_next(llist_iterator * iterator) {
	if (iterator != NULL) {
		if (iterator->current_item != NULL) {
			iterator->current_item = iterator->current_item->next_item;
			return LIST_ITERATOR_OK;
		} else
			return LIST_ITERATOR_END;
	} else
		return LIST_ITERATOR_ERROR;
}

/**
 * Make the iterator move to the previous item.
 */
int list_iterator_prev(llist_iterator * iterator) {
	if (iterator != NULL) {
		if (iterator->current_item->prev_item != NULL) {
			iterator->current_item = iterator->current_item->prev_item;
			return LIST_ITERATOR_OK;
		} else
			return LIST_ITERATOR_START;
	} else
		return LIST_ITERATOR_ERROR;
}

/**
 * Removes the item currently selected by the iterator.
 *
 * Notes that this action will make the iterator move to
 * the next item and thus does not make calling
 * list_iterator_next() necessary.
 */
int list_iterator_remove(llist_iterator * iterator, void ** data, size_t * data_size) {
	llist_item * ci;

	if (iterator != NULL) {
		if (iterator->current_item != NULL) {
			ci = iterator->current_item;
			
			/* Update item data. */
			if (ci->prev_item != NULL) 
				((llist_item *) ci->prev_item)->next_item = ci->next_item;
			if (ci->next_item != NULL)
				((llist_item *) ci->next_item)->prev_item = ci->prev_item;
				
			/* Update list data. */
			if (iterator->parent_list->first_item == ci)
				iterator->parent_list->first_item = ci->prev_item;
			if (iterator->parent_list->last_item == ci)
				iterator->parent_list->last_item = ci->prev_item;

			/* Update the iterator to the next item. */
			iterator->current_item = ci->next_item;			

			/* Clear the item data if the user doesn't want it. */
			if (data_size != NULL)
				*data_size = ci->data_size;
			
			if (data != NULL) 
				*data = ci->data;
			else 
				if (ci->is_copy)
					free(ci->data);
			
			/* Clear the item. */
			ci->next_item = NULL;
			ci->prev_item = NULL;
			ci->data      = NULL;
			free(ci);
			
			iterator->parent_list->length--;

			return LIST_ITERATOR_OK;

		} else
			return LIST_ITERATOR_END;

	} else
		return LIST_ITERATOR_ERROR;
}

#ifdef _LIST_UNIT_TEST
int main() {
	char item1[] = "Item 1";
	char item2[] = "Item 2";
	char item3[] = "Item 3";
	char * item_ptr;
	llist * l1 = list_create();
	llist * l2 = list_create();

	puts("NORMAL APPEND TESTS.");
	TASSERT(l1 != NULL);
	TASSERT(list_append(l1, item1, sizeof(item1)));
	TASSERT(list_append(l1, item2, sizeof(item2)));
	TASSERT(list_append(l1, item3, sizeof(item3)));

	puts("INDEXED ITEM GET TESTS.");
	list_get_item(l1, 0, (void *) &item_ptr, NULL);	
	TASSERT(strcmp("Item 1", item_ptr) == 0);
	list_get_item(l1, 2, (void *) &item_ptr, NULL);
	TASSERT(strcmp("Item 3", item_ptr) == 0);

	/*
	 * Testing iterator loop.
	 */
	llist_iterator * iter1 = list_iterator_begin(l1);

	puts("ITERATOR TESTS.");
	list_iterator_get(iter1, (void *) &item_ptr, NULL);
	TASSERT(strcmp("Item 1", item_ptr) == 0);
	list_iterator_next(iter1);
	list_iterator_get(iter1, (void *) &item_ptr, NULL);
	TASSERT(strcmp("Item 2", item_ptr) == 0);
	list_iterator_next(iter1);
	list_iterator_get(iter1, (void *) &item_ptr, NULL);
	TASSERT(strcmp("Item 3", item_ptr) == 0);	
	list_iterator_next(iter1);
	TASSERT(list_iterator_get(iter1, NULL, NULL) == LIST_ITERATOR_END);
	list_iterator_end(iter1);
	iter1 = NULL;

	/*
	 * Testing iterator item removal.
	 */

	llist_iterator * iter2 = list_iterator_begin(l1);	

	puts("REMOVAL TESTS.");
	list_iterator_next(iter2);	
	list_iterator_remove(iter2, (void *) &item_ptr, NULL);
	TASSERT(strcmp("Item 2", item_ptr) == 0);
	list_iterator_get(iter2, (void *) &item_ptr, NULL);
	TASSERT(strcmp("Item 3", item_ptr) == 0);
	list_get_item(l1, 0, (void *) &item_ptr, NULL);
	TASSERT(strcmp("Item 1", item_ptr) == 0);
	list_get_item(l1, 1, (void *) &item_ptr, NULL);
	TASSERT(strcmp("Item 3", item_ptr) == 0);
	list_iterator_end(iter2);

	puts("KILLING LIST.");
	list_kill(l1);

	puts("COPY APPEND TESTS.");
	TASSERT(l2 != NULL);
	TASSERT(list_append_copy(l2, item1, sizeof(item1)));
	TASSERT(list_append_copy(l2, item2, sizeof(item2)));
	TASSERT(list_append_copy(l2, item3, sizeof(item3)));

	puts("INDEXED ITEM GET TESTS.");
	list_get_item(l2, 0, (void *) &item_ptr, NULL);	
	TASSERT(strcmp("Item 1", item_ptr) == 0);
	list_get_item(l2, 2, (void *) &item_ptr, NULL);
	TASSERT(strcmp("Item 3", item_ptr) == 0);

	puts("KILLING LIST.");
	list_kill(l2);
}
#endif // _LIST_UNIT_TEST
		
