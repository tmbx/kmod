/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

#include "utils.h"

#ifdef __UNIX__
#include <dirent.h>
#endif

#ifdef __WINDOWS__
#include <wincrypt.h>
#endif

/* This function puts the current time in the timeval passed in the parameters.
 * Arguments:
 * Timeval.
 */
void util_get_current_time(struct timeval *tv) {
    #ifdef __WINDOWS__
    /* Get the number of 100-nanosecond intervals since January 1, 1601 (UTC). */
    uint64_t nb_100nsec_1601;
    uint64_t nb_100nsec_1970;
    GetSystemTimeAsFileTime((struct _FILETIME *) &nb_100nsec_1601);

    /* Get the number of 100-nanoseconds between January 1, 1601 and 1970, January 1.
     * Magic number explanation:
     * Both epochs are Gregorian. 1970 - 1601 = 369. Assuming a leap
     * year every four years, 369 / 4 = 92. However, 1700, 1800, and 1900
     * were NOT leap years, so 89 leap years, 280 non-leap years.
     * 89 * 366 + 280 * 365 = 134744 days between epochs. Of course
     * 60 * 60 * 24 = 86400 seconds per day, so 134744 * 86400 =
     * 11644473600 = SECS_BETWEEN_EPOCHS.
     */
    nb_100nsec_1970 = nb_100nsec_1601 - (11644473600ll * 10000000ll);

    tv->tv_sec = nb_100nsec_1970 / 10000000;
    tv->tv_usec = (nb_100nsec_1970 % 10000000) / 10;
    
    #else
    if (gettimeofday(tv, NULL) != 0) {
	    kmo_fatalerror("cannot get current time");
    }
    #endif
}

/* This function returns -1 if first comes before second, 0 if the times are the
 * same and 1 if first comes after second.
 * Arguments:
 * Timeval 1.
 * Timeval 2.
 */
int util_timeval_cmp(struct timeval *first, struct timeval *second) {
    if (first->tv_sec < second->tv_sec)
    	return -1;

    else if (first->tv_sec > second->tv_sec)
    	return 1;

    else if (first->tv_usec < second->tv_usec)
	return -1;

    else if (first->tv_usec > second->tv_usec)
	return 1;
	    
    else
	return 0;
}

/* This function subtracts y from x and put the result in result.
 * Arguments:
 * Result (can be one of the sources).
 * Timeval to subtract from.
 * Timeval containing the time to subtract.
 */	 
void util_timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y) {
    int real_sec = x->tv_sec - y->tv_sec;
    int real_usec = x->tv_usec - y->tv_usec;

    /* Perform the carry for the subtraction. */
    if (real_usec < 0) {
	    real_sec -= 1;
	    real_usec += 1000000;
    }

    result->tv_sec = real_sec;
    result->tv_usec = real_usec;
}

/* Complement of above function. */
void util_timeval_add(struct timeval *result, struct timeval *x, struct timeval *y) {
    int real_sec = x->tv_sec + y->tv_sec;
    int real_usec =  x->tv_usec + y->tv_usec;

    /* Perform the carry for the addition. */
    if (real_usec >= 1000000) {
	    real_sec += 1;
	    real_usec -= 1000000;
    }

    result->tv_sec = real_sec;
    result->tv_usec = real_usec;
}

/* This function calculates the time elapsed since 'start' was set and puts the
 * result in 'result'.
 * Arguments:
 * Start timeval.
 * Result timeval.
 */
void util_get_elapsed_time(struct timeval *start, struct timeval *result) {
    
    /* Get current time. */
    struct timeval current_tv;
    util_get_current_time(&current_tv);

    /* Do the subtraction. */
    util_timeval_subtract(result, &current_tv, start);
}

/* This function returns the number of milliseconds that a timeval represents.
 * Beware of overflows.
 * Arguments:
 * Timeval.
 */
int util_get_timeval_msec(struct timeval *tv) {
    return (tv->tv_sec * 1000 + tv->tv_usec / 1000);
}

/* This function sets the number of milliseconds specified in a timeval struct.
 * Arguments:
 * Timeval.
 * Delay in milliseconds.
 */
void util_set_timeval_msec(struct timeval *tv, int delay) {
	tv->tv_sec = delay / 1000;
	tv->tv_usec = (delay % 1000) * 1000;
}

/* This function transforms the time 't' (as returned by time()) into a string
 * understandable by the user, in localtime.
 * Arguments:
 * Time to transform (seconds elapsed from UNIX Epoch).
 * String that will contain the result.
 */
void format_time(time_t t, kstr *str) {
    struct tm *tm = localtime(&t);
    tm->tm_year += 1900;
    tm->tm_mon += 1;

    kstr_sf(str, "%.2d/%.2d/%.4d %.2d:%.2d:%.2d", tm->tm_mday, tm->tm_mon, tm->tm_year,
						  tm->tm_hour, tm->tm_min, tm->tm_sec);
}

/* This function transforms the time 't' (as returned by time()) into a string
 * understandable by the user, in GMT.
 * Arguments:
 * Time to transform (seconds elapsed from UNIX Epoch).
 * String that will contain the result.
 */
void format_gmtime(time_t t, kstr *str) {
    struct tm *tm = gmtime(&t);
    tm->tm_year += 1900;
    tm->tm_mon += 1;

    kstr_sf(str, "%.2d/%.2d/%.4d %.2d:%.2d:%.2d GMT", tm->tm_mday, tm->tm_mon, tm->tm_year,
						      tm->tm_hour, tm->tm_min, tm->tm_sec);
}

/* This function puts all the characters of a string in lowercase. */
void strntolower(char *str, size_t max_len) {
    for (; max_len-- > 0 && *str; str++)
        *str = tolower(*str);
}

/* This function implements a portable version of strcasestr().*/
char * portable_strcasestr(const char *haystack, const char *needle) {
    size_t needle_len = strlen(needle);
    const char *last_start = haystack + strlen(haystack) - needle_len;

    while (haystack <= last_start) {
	if (portable_strncasecmp(haystack, needle, needle_len) == 0)
	    return (char *) haystack;
    
    	haystack++;
    }

    return NULL;
}

/* This function looks for 'needle' inside 'haystack' like in
 * portable_strcasestr(), except that the function scans backward inside
 * 'haystack' until either 'needle' is found or 'start' is passed.
 */
char * reverse_strcasestr(const char *start, const char *haystack, const char *needle) {
    size_t needle_len = strlen(needle);
    
    while (haystack >= start) {
	if (portable_strncasecmp(haystack, needle, needle_len) == 0)
	    return (char *) haystack;
    
    	haystack--;
    }
    
    return NULL;
}

/* Used by KMO. MARKED FOR DELETION. */
int read_line(char ** str, size_t * str_s , FILE * fsource) {
	static char line_buff[1024] = { 0 };
	size_t s;
	size_t cs = 0;

	*str = NULL;
	*str_s = 0;
	memset(line_buff, 0, sizeof(line_buff));
	
	/* Read the line. */
	if (fgets(line_buff, sizeof(line_buff), fsource) == NULL) {
		return -1;
	}

	while (1) {
		/* Check if we have a line. */
		if (line_buff[sizeof(line_buff) - 1] == '\0') {
			/* if so, it is safe to call strlen */
			s = strlen(line_buff);
			*str = realloc(*str, cs + s + 1);
			line_buff[s - 1] = '\0';
			strcpy(*(str + cs), line_buff);
			*str_s = cs + s - 1;
			break;
		} else {			
			*str = realloc(*str, cs + sizeof(line_buff));
			memcpy(*(str + cs), line_buff, sizeof(line_buff));
			cs += sizeof(line_buff);
		}
	} 	
	
	return 0;
}

/* Used by KMO. MARKED FOR DELETION. */
int read_block(char ** str, size_t * str_s, FILE * fsource) {
	char * block = NULL;
	size_t block_s = 0;
	char * line;
	size_t line_s;

	while (1) {
		if (read_line(&line, &line_s, fsource) < 0) {
			if (block_s > 0)
				break;
			else {
				free(block);
				free(line);
				*str = NULL;
				*str_s = 0;
				return -1;
			}				
		}

		if (strlen(line) == 1 && block != NULL && line[0] == '.') {	
			block[block_s] = '\0';
			break;
		}

		if ((block = realloc(block, block_s + line_s + 2)) == NULL) 
			return -1;

		if (block_s > 0) {
			block[block_s] = '\n';
			block_s++;
		}

		memcpy(block + block_s, line, line_s);
		block_s += line_s;
		free(line);
	} 

	free(line);

	*str = block;
	*str_s = block_s;

	return 0;
}

/* This function opens a file in mode 'mode' ('mode' is the standard argument of
 * fopen(). Better to add the 'b' flag in case we run on Windows).
 * This function sets the KMO error string. It returns -1 on failure.
 * Arguments:
 * Handle to the file pointer that will be set.
 * Path to the file.
 * Mode of the file.
 */
int util_open_file(FILE **file_handle, char *path, char *mode) {
    FILE *file = fopen(path, mode);

    if (file == NULL) {
    	kmo_seterror("cannot open %s: %s", path, kmo_syserror());
    	return -1;
    }

    *file_handle = file;
    return 0;
}

/* This function closes a file. file_handle will be set to NULL even on error.
 * The function does nothing if *file_handle is NULL.
 * This function sets the KMO error string. It returns -1 on failure.
 * Arguments:
 * Handle to the pointer of the file to close.
 * Silence error flag (do not call kmo_seterror()).
 */
int util_close_file(FILE **file_handle, int silent_flag) {
    int error = 0;
    
    if (*file_handle == NULL)
    	return 0;

    error = fclose(*file_handle);
    *file_handle = NULL;

    if (error && ! silent_flag) {
    	kmo_seterror("cannot close file: %s", kmo_syserror());
	return -1;
    }
    
    return 0;
}

/* This function truncates a file to 0 byte and sets the file position to 0.
 * This function sets the KMO error string. It returns -1 on failure.
 * Arguments:
 * File descriptor of the file.
 */
int util_truncate_file(FILE *file) {
    #ifdef __UNIX__
    if (ftruncate(fileno(file), 0)) {
    #endif

    #ifdef __WINDOWS__
    if (_chsize(fileno(file), 0)) {
    #endif
	kmo_seterror("cannot truncate file: %s", kmo_syserror());
    	return -1;
    }
    
    if (util_file_seek(file, 0, SEEK_SET)) {
    	return -1;
    }
    
    return 0;
}

/* This function renames file 'from_path' to 'to_path'. to_path will be
 * overwritten if it exists. Make sure you don't cross filesystem boundaries.
 * This function sets the KMO error string. It returns -1 on failure.
 * Arguments:
 * Path of the file to rename.
 * Destination path.
 */
int util_rename_file(char *from_path, char *to_path) {
    if (rename(from_path, to_path) == -1) {
    	kmo_seterror("failed to rename %s to %s: %s", from_path, to_path, kmo_syserror());
	return -1;
    }
    
    return 0;
}

/* This function reads the number of bytes specified.
 * This function sets the KMO error string. It returns -1 on failure.
 * Arguments:
 * File pointer.
 * Buffer pointer.
 * Buffer size.
 */
int util_read_file(FILE *file, void *buf, int size) {

    /* Note: do not use 'fread(buf, size, 1, file) != 1', because it does
     * not work when the user tries to read 0 byte.
     */
    if (fread(buf, 1, size, file) != (unsigned int) size) {
    
	/* Error occurred because of end of file. */
	if (feof(file)) {
	    kmo_seterror("cannot read data from file: end of file reached");
	    return -1;
	}

	/* Other error. */
	kmo_seterror("cannot read data from file: %s", kmo_syserror());
	return -1;
    }
    
    return 0;
}

/* Same as above, but the data is written. */
int util_write_file(FILE *file, void *buf, int size) {
    if (fwrite(buf, 1, size, file) != (unsigned int) size) {
	kmo_seterror("cannot write data to file: %s", kmo_syserror());
	return -1;
    }
    
    return 0;
}

/* This function gets the current position in the file specified.
 * This function sets the KMO error string. It returns -1 on failure.
 * Arguments:
 * File pointer.
 * Pointer to the position to set.
 */
int util_get_file_pos(FILE *file, int *pos) {
    *pos = ftell(file);

    if (*pos == -1) {
	kmo_seterror("cannot get current position in file: %s", kmo_syserror());
	return -1;
    }

    return 0;
}
 
/* This function gets the size of an open file. Warning: it will seek at the 
 * beginning of the file.
 * This function sets the KMO error string. It returns -1 on failure.
 * Arguments:
 * File pointer.
 * Pointer to the size to set.
 */
int util_get_file_size(FILE *file, int *size) {

    /* Seek to the end. */
    if (util_file_seek(file, 0, SEEK_END)) {
    	return -1;
    }
    
    /* Get the current position. */
    if (util_get_file_pos(file, size)) {
    	return -1;
    }

    /* Seek to the beginning. */
    rewind(file);
    
    return 0;
}

/* This function seeks in a file.
 * This function sets the KMO error string. It returns -1 on failure.
 * Arguments:
 * File ptr, offset, whence, like with the fseek() function.
 */
int util_file_seek(FILE *file, int offset, int whence) {
    
    if (fseek(file, offset, whence)) {
    	kmo_seterror("cannot seek in file: %s", kmo_syserror());
	return -1;
    }
    
    return 0;
}

/* This function returns true if the file specified is a regular file.
 * Arguments:
 * Path to the file to check.
 */
int util_check_regular_file_exist(char *path) {
    #ifdef __UNIX__
    struct stat stat_buf;
    int error = stat(path, &stat_buf);
    return (error != -1 && S_ISREG(stat_buf.st_mode));
    #endif

    /* Does not do exactly what we want, but it'll have to do. */
    #ifdef __WINDOWS__
    unsigned int error = GetFileAttributes(path);
    return (error != INVALID_FILE_ATTRIBUTES && (! (error & FILE_ATTRIBUTE_DIRECTORY)));
    #endif
}

/* This function deletes the regular file 'path', which must exists.
 * This function sets the KMO error string. It returns -1 on failure.
 * Arguments:
 * Path to the file to delete.
 */
int util_delete_regular_file(char *path) {
    if (remove(path) == -1) {
    	kmo_seterror("failed to delete %s: %s", path, kmo_syserror());
	return -1;
    }
    
    return 0;
}

/* This function returns true if the file specified is a directory.
 * Arguments:
 * Path to the file to check.
 */
int util_check_dir_exist(char *path) {
    #ifdef __WINDOWS__
    unsigned int error = GetFileAttributes(path);
    return (error != INVALID_FILE_ATTRIBUTES && (error & FILE_ATTRIBUTE_DIRECTORY));
    #else
    struct stat stat_buf;
    int error = stat(path, &stat_buf);
    return (error != -1 && S_ISDIR(stat_buf.st_mode));
    #endif
}

/* This function creates the directory specified.
 * This function sets the KMO error string. It returns -1 on failure.
 * Arguments:
 * Path to the directory to create.
 */
int util_create_dir(char *path) {
    #ifdef __WINDOWS__
    if (_mkdir(path) == -1)
    #else
    if (mkdir(path, 0777) == -1)
    #endif
    {
    	kmo_seterror("cannot create directory %s: %s", path, kmo_syserror());
	return -1;
    }
    
    return 0;
}

/* This function fills an array with the name of the files and directories
 * contained within the directory specified. The array's content must be freed
 * by the user.
 * This function sets the KMO error string. It returns -1 on failure.
 * Arguments:
 * Path to the directory to list.
 * Array that will contain the file names.
 */
int util_list_dir(char *path, karray *listing) {
    int error = 0;
    listing->size = 0;
    
    #ifdef __UNIX__
    DIR *dir = NULL;
    struct dirent *dir_entry;
    
    /* Try. */
    do {
        dir = opendir(path);

        if (dir == NULL) {
	    kmo_seterror("cannot list directory %s: %s", path, kmo_syserror());
	    error = -1;
	    break;
	}

        /* Loop until there are no more files. */
        while (1) {
            dir_entry = readdir(dir);
	    kstr *file_name = NULL;
    	    
	    /* OK, error occurred because there is no file (we must assume this
             * since readdir()'s semantics are not fully specified).
	     */
            if (dir_entry == NULL) {
        	break;
            }

            /* Skip '.' and '..'. */
            if (strcmp(dir_entry->d_name, ".") == 0 || strcmp(dir_entry->d_name, "..") == 0) {
        	continue;
            }

            /* Add the file name in the array. */
	    file_name = kstr_new();
	    kstr_assign_cstr(file_name, dir_entry->d_name);
            karray_add(listing, file_name);
        }
	
    } while (0);
    
    if (dir) closedir(dir);
    #endif

    /* A twisted mind you need indeed to come up with functions such as
     * FindFirstFile() and FindNextFile().
     */
    #ifdef __WINDOWS__
    HANDLE search_handle = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA find_data;
    int first_flag = 1;
    kstr *file_name;

    /* Try. */
    do {
        /* Loop until there are no more files. */
        while (1) {
	
            /* Get the data about the next file, if any. */
            if (first_flag) {
                first_flag = 0;
                search_handle = FindFirstFile(path, &find_data);

                if (search_handle == INVALID_HANDLE_VALUE) {
		    error = GetLastError();
		    
                    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_NO_MORE_FILES) {
                        kmo_seterror("cannot list directory %s", path);
			error = -1;
			break;
                    }
		    
		    else {
		    	error = 0;
		    }

                    /* OK, error occurred because there was no file. */
                    break;
                }
            }

            else {
                if (FindNextFile(search_handle, &find_data) == 0) {
                    error = GetLastError();
		    
		    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_NO_MORE_FILES) {
                        kmo_seterror("cannot list directory %s", path);
			error = -1;
			break;
                    }
		    
		    else {
		    	error = 0;
		    }

                    /* OK, error occurred because there was no file. */
                    break;
                }
            }

            /* Add the file name in the array. */
	    file_name = kstr_new();
	    kstr_assign_cstr(file_name, find_data.cFileName);
            karray_add(listing, file_name);
        }
	
	if (error) break;
	
    } while (0);

    if (search_handle != INVALID_HANDLE_VALUE) FindClose(search_handle);
    #endif
    
    if (error) kmo_clear_kstr_array(listing);
    
    return error;
}

/* This function generates 'len' bytes of random data.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int util_generate_random(char *buf, int len) {
    int error = 0;
       
    #ifdef __WINDOWS__
    
    /* Don't use this code: it doesn't work on some machines where the
     * cryptographic layer is broken.
     *
     * Update: Ah, but openssl requires that call to work.
     * Gcrypt also, but I disabled it.
     *
     * Update2: Openssl *does not* require the call to work. It masks
     * failures. If CryptAcquireContext has to fail, it takes a lot of
     * time to fail if the last argument is 0, but it fails fast if
     * CRYPT_VERIFYCONTEXT or CRYPT_NEWKEYSET is used. Openssl doesn't
     * attempt to create the context (it's buggy in that respect), but
     * it uses CRYPT_VERIFY_CONTEXT so it fails fast. We disable call
     * to CryptAcquireContext for now to avoid problems.
     */
    
    #if 0 
    HCRYPTPROV hCryptProv;
    if (! CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
	if (! CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
	    kmo_seterror("cannot acquire crypt context (error %u)", GetLastError());
	    return -1;
	}
    }

    error = CryptGenRandom(hCryptProv, len, (BYTE *) buf);
    CryptReleaseContext(hCryptProv, 0);
    
    if (error == 0) {
	kmo_seterror("cannot generate random data");
	return -1;
    }
    return 0;
    #else
    /* Sigh. Better than nothing, I guess. */
    int i;
    DWORD seed = GetTickCount();
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    seed ^= (DWORD) li.LowPart;
    seed ^= (DWORD) li.HighPart;
    srand((unsigned int) seed);
    
    for (i = 0; i < len; i++) {
    	buf[i] = rand() % 256;
    }
    
    return error;
    #endif
    
    #else
    FILE *file_ptr = NULL;
    
    /* Try. */
    do {
	error = util_open_file(&file_ptr, "/dev/urandom", "rb");
	if (error) break;

	error = util_read_file(file_ptr, buf, len);
	if (error) break;

	error = util_close_file(&file_ptr, 0);
	if (error) break;
		
    } while (0);
    
    util_close_file(&file_ptr, 1);
    return error;
    #endif
}

/* This function converts a binary buffer to an hexadecimal kstr.
 */
void util_bin_to_hex(unsigned char *in, int n, kstr *out) {
    static unsigned char hex_table[16] =
    	{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    
    int i;
    
    kstr_grow(out, 2*n);
    
    for (i = 0; i < n; i++) {
	out->data[i*2] = hex_table[in[i] >> 4];
	out->data[i*2 + 1] = hex_table[in[i] & 0xf];
    }
    
    out->data[2*n] = 0;
}

/* This function dumps the content of a buffer on the stream specified, in base
 * 64. A newline is inserted after 20 characters have been printed on a line.
 */
void util_dump_buf_64(unsigned char *buf, int n, FILE *stream) {
    int i;
    
    for (i = 0; i < n; i++) {
    	
	if (i > 0 && i % 20 == 0) fprintf(stream, "\n");
	else if (i % 20) fprintf(stream, " ");
	
	fprintf(stream, "%2.2x", buf[i]);
    }
}

/* This function dumps the content of a buffer on the stream specified, in
 * ASCII. A newline is inserted after 20 characters have been printed on a line.
 */
void util_dump_buf_ascii(unsigned char *buf, int n, FILE *stream) {
    int i;
    
    for (i = 0; i < n; i++) {
    	
	if (i > 0 && i % 20 == 0) fprintf(stream, "\n");
	else if (i % 20) fprintf(stream, " ");
	
	if (buf[i] == '\n') fprintf(stream, "\\n");
	else if (buf[i] == '\r') fprintf(stream, "\\r");
	else fprintf(stream, "%c ", buf[i]);
    }
}
