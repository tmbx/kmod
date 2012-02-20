/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

#ifndef _UTILS_H
#define _UTILS_H

#include "kmo_base.h"
#include "kbuffer.h"

#ifdef __WINDOWS__
#define portable_strncasecmp _strnicmp
#else
#define portable_strncasecmp strncasecmp	
#endif

void util_get_current_time(struct timeval *tv);
int util_timeval_cmp(struct timeval *first, struct timeval *second);
void util_timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y);
void util_timeval_add(struct timeval *result, struct timeval *x, struct timeval *y);
void util_get_elapsed_time(struct timeval *start, struct timeval *result);
int util_get_timeval_msec(struct timeval *tv);
void util_set_timeval_msec(struct timeval *tv, int delay);
void format_time(time_t t, kstr *str);
void format_gmtime(time_t t, kstr *str);
void strntolower(char *str, size_t max_len);
char *portable_strcasestr(const char *haystack, const char *needle);
char * reverse_strcasestr(const char *start, const char *haystack, const char *needle);
int read_line(char **, size_t *, FILE *);
int read_block(char **, size_t *, FILE *);
int util_open_file(FILE **file_handle, char *path, char *mode);
int util_close_file(FILE **file_handle, int silent_flag);
int util_truncate_file(FILE *file);
int util_rename_file(char *from_path, char *to_path);
int util_read_file(FILE *file, void *buf, int size);
int util_write_file(FILE *file, void *buf, int size);
int util_get_file_pos(FILE *file, int *pos);
int util_get_file_size(FILE *file, int *size);
int util_file_seek(FILE *file, int offset, int whence);
int util_check_regular_file_exist(char *path);
int util_delete_regular_file(char *path);
int util_check_dir_exist(char *path);
int util_create_dir(char *path);
int util_list_dir(char *path, karray *listing);
int util_generate_random(char *buf, int len);
void util_bin_to_hex(unsigned char *in, int n, kstr *out);
void util_dump_buf_64(unsigned char *buf, int n, FILE *stream);
void util_dump_buf_ascii(unsigned char *buf, int n, FILE *stream);

/* This function returns true if the character specified is a digit. */
static inline int is_digit(char c) { return (c >= '0' && c <= '9'); }



#endif
