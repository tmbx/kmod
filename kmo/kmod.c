/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

/* WARNING: this program has become unmaintainable. I'm sorry if you must modify
 * it. A complete rewrite was half-done, but had to be abandonned due to time
 * constraints.
 */

/* DOCUMENTATION 
 *
 * KMOD command handlers return codes:
 *
 * When we process a command from the plugin (process mail, package mail, etc.),
 * we have to remember the state of the command and the state of the connection
 * with the plugin. While processing the command, we may encounter server
 * errors, invalid configuration errors, connection errors and other
 * miscelleanous errors.
 *
 * Errors like server errors and invalid configuration errors are handled as
 * soon as they are detected: we tell the plugin about it and exit from the
 * command handler ASAP.
 *
 * Miscellaneous errors are not handled as soon as they are detected: we unwind
 * the stack until we reach the command handler and then we report the error
 * to the plugin.
 *
 * Connection errors are fatal: we unwind the stack and stop KMOD.
 *
 * To track those information, we use a return code with 4 states:
 *  0: no error so far.
 * -1: a miscellaneous error occurred, it was not reported yet and the
 *     connection with the plugin is still OK, so return to the command
 *     handler ASAP to handle it.
 * -2: an error occurred, we reported it to the plugin and the connection with
 *     the plugin is still OK, so exit from the command handler ASAP.
 * -3: an unrecoverable error occurred so stop KMOD ASAP.
 */


#include <openssl/ssl.h>
#include <openssl/err.h>
#include "base64.h"
#include "k3p.h"
#include "k3p_core_defs.h"
#include "kmo_sock.h"
#include "kmocrypt.h"
#include "kmocryptsymkey.h"
#include "kmod.h"
#include "knp.h"
#include "mail.h"
#include "maildb.h"
#include "utils.h"
#include "kmod_link.h"

/* K3P version. When this is modified, update the file 'k3p_core_defs.h' as well. */
#define K3P_VERSION 	            "1.8"

/* KMOD version. */
#define KMOD_VERSION                "1.8"

/* Default port to which network connections are made with the plugin. */
#define K3P_SOCKET_PORT     	    31000

/* Time to wait for the plugin to connect to KMOD. */
#define K3P_ACCEPT_TIMEOUT  	    2000

/* Default K3P & KNP operation timeout in milliseconds. 0 means no timeout. */
#define DEFAULT_OPERATION_TIMEOUT       8000

/* Maximum size of the KMOD log before it is truncated. */
#define KMOD_MAX_KMOD_LOG_SIZE	    100*1024

/* KMOD-KPP connection type:
 * Inherited socket placed in file descriptor 0 (stdin),
 * KMOD connects to KPP.
 * KPP connects to KMOD.
 */
#define KPP_CONN_NONE	    	    0
#define KPP_CONN_INHERITED  	    1
#define KPP_CONN_KMOD_CONNECT	    2
#define KPP_CONN_KPP_CONNECT	    3

/* Directory used to store KMO files. */
#ifdef __WINDOWS__
#define KMOD_HOME_VAR 	    	    "APPDATA"
#else
#define KMOD_HOME_VAR 	    	    "HOME"
#endif

/* Define this to debug messages with a modified bodies. */
/* #define BODY_CHANGED_DEBUG */


/* Logging globals. */
FILE *k3p_log = NULL;
FILE *knp_log = NULL;
FILE *kmod_log = NULL;
int k3p_log_mode = 0;

/* KMOD logging level:
 * 0: no logging.
 * 1: K3P, KNP and basic KMOD actions (including errors).
 * 2: Same as 1, plus important calls.
 * 3: same as 2, with more details.
 */
static int kmod_log_level = 0;

/* True if the logs should be truncated before dealing with a new session. */
static int kmod_truncate_log_flag = 0;

/* Operation timeout for the K3P and the KNP. */
static int operation_timeout = DEFAULT_OPERATION_TIMEOUT;

/* Characters allowed in a file name. */
static char kmod_allowed_file_char[256];


/* The high-level state of KMOD is kept inside this object. */
struct kmod_context {
    
    /* This field determines the method used to communicate with the plugin.
     * Note that we use "socket-like" descriptors to communicate with the plugin
     * in all cases.
     */
    int kpp_conn_type;
    
    /* If the connection method type is KPP_CONN_KMOD_CONNECT or
     * KPP_CONN_KPP_CONNECT, this field contains the port to connect to.
     */
    int kpp_conn_port;
    
    /* KMOD tool info. */
    struct kmod_tool_info tool_info;
   
    /* Mail user agent info. */
    struct kmod_mua mua;
    
    /* Current server info. */
    struct kmod_server_info server_info;
    
    /* Member ID of the user, or 0 if none. */
    uint64_t user_mid;

    /* Array of domain names. */
    karray domain_array;
    
    /* KPG address and port, if any, when packaging without OTUT. */
    int use_kpg;
    kstr kpg_addr;
    int kpg_port;
    
    /* Path to the Teambox directory. */
    kstr teambox_dir_path;
    
    /* Path to the database. */
    kstr kryptiva_db_path;
    
    /* Date of the logs opened for this process. */
    kstr log_date;
    
    /* Encryption key lookup address, if any. */
    kstr enc_key_lookup_str;

    /* KMOD user mail database. */
    maildb *mail_db;

    /* KMOD hacks. Not used at the moment. */
    int hacks;
    
    /* K3P handler object. */
    k3p_proto k3p;
    
    /* KNP handler object. */
    struct knp_proto knp;
    
    /* Transfer hub. */
    struct kmo_transfer_hub hub;
    
    /* Initialized scratch string. */
    kstr str;
};

/* This function initializes the KMOD context. */
static void kmod_context_init(struct kmod_context *kc) {
    memset(kc, 0, sizeof(struct kmod_context));
    kc->kpp_conn_type = KPP_CONN_NONE;
    kc->kpp_conn_port = K3P_SOCKET_PORT;
    k3p_init_tool_info(&kc->tool_info);
    kstr_assign_cstr(&kc->tool_info.sig_marker, KRYPTIVA_BODY_START);
    kstr_assign_cstr(&kc->tool_info.kmod_version, KMOD_VERSION);
    kstr_assign_cstr(&kc->tool_info.k3p_version, K3P_VERSION);
    k3p_init_mua(&kc->mua);
    k3p_init_server_info(&kc->server_info);
    karray_init(&kc->domain_array);
    kstr_init(&kc->kpg_addr);
    kstr_init(&kc->teambox_dir_path);
    kstr_init(&kc->kryptiva_db_path);
    kstr_init(&kc->log_date);
    kstr_init(&kc->enc_key_lookup_str);
    k3p_proto_init(&kc->k3p);
    kc->k3p.transfer.driver = kmo_sock_driver;
    kc->k3p.hub = &kc->hub;
    kc->knp.k3p = &kc->k3p;
    kc->knp.server_info = &kc->server_info;
    kc->knp.use_kpg = 0;
    kstr_init(&kc->knp.kpg_addr);
    kmo_transfer_hub_init(&kc->hub);
    kstr_init(&kc->str);
}

/* This function frees the KMOD context. */
static void kmod_context_free(struct kmod_context *kc) {
    k3p_free_tool_info(&kc->tool_info);
    k3p_free_mua(&kc->mua);
    k3p_free_server_info(&kc->server_info);
    kmo_clear_kstr_array(&kc->domain_array);
    karray_free(&kc->domain_array);
    kstr_free(&kc->kpg_addr);
    kstr_free(&kc->teambox_dir_path);
    kstr_free(&kc->kryptiva_db_path);
    kstr_free(&kc->log_date);
    kstr_free(&kc->enc_key_lookup_str);
    if (kc->mail_db) maildb_destroy(kc->mail_db);
    k3p_proto_free(&kc->k3p);
    kstr_free(&kc->knp.kpg_addr);
    kmo_transfer_hub_free(&kc->hub);
    kstr_free(&kc->str);
}

/* This function should be called to log a message in the KMOD log.
 * Arguments:
 * Message logging level (1 or 2).
 * Format is the usual printf() format, and the following args are the args that
 *   printf() takes.
 */
void kmod_log_msg(int level, const char *format, ...) {
    va_list arg;
    
    assert(level == 1 || level == 2 || level == 3);
    if (level > kmod_log_level || kmod_log == NULL) return;
    
    va_start(arg, format);
    vfprintf(kmod_log, format, arg);
    va_end(arg);
}

/* This function tries to delete the logs having the date specified. */
static void kmod_delete_log(struct kmod_context *kc, kstr *date) {
   kstr_sf(&kc->str, "%s/kmod_logs/%s_k3p.log", kc->teambox_dir_path.data, date->data);
   if (util_check_regular_file_exist(kc->str.data)) util_delete_regular_file(kc->str.data);
   
   kstr_sf(&kc->str, "%s/kmod_logs/%s_knp.log", kc->teambox_dir_path.data, date->data);
   if (util_check_regular_file_exist(kc->str.data)) util_delete_regular_file(kc->str.data);
   
   kstr_sf(&kc->str, "%s/kmod_logs/%s_kmod.log", kc->teambox_dir_path.data, date->data);
   if (util_check_regular_file_exist(kc->str.data)) util_delete_regular_file(kc->str.data);
   
   kstr_sf(&kc->str, "%s/kmod_logs/%s_OPEN_LOG", kc->teambox_dir_path.data, date->data);
   if (util_check_regular_file_exist(kc->str.data)) util_delete_regular_file(kc->str.data);
}

/* This function closes the logs, if they are open. The OPEN_LOG file is
 * deleted, if it exists. No error checking is performed.
 */
static void kmod_close_log(struct kmod_context *kc) {
    
    if (k3p_log) {
    	fclose(k3p_log);
    	k3p_log = NULL;
    }

    if (knp_log) {
    	fclose(knp_log);
    	knp_log = NULL;
    }
    
    if (kmod_log) {
    	fclose(kmod_log);
    	kmod_log = NULL;
    }
    
    if (kc->log_date.slen > 0) {
    	kstr_sf(&kc->str, "%s/kmod_logs/%s_OPEN_LOG", kc->teambox_dir_path.data, kc->log_date.data);
	if (util_check_regular_file_exist(kc->str.data)) util_delete_regular_file(kc->str.data); 	
    }
}

/* Sort function for kmod_open_log(). */
static int kmod_open_log_sort(const void *key_1, const void *key_2) {
    kstr **str_1 = (kstr **) key_1;
    kstr **str_2 = (kstr **) key_2;
    return strcmp((**str_1).data, (**str_2).data);
}

/* This function should be called to open the logs at startup, if required.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_open_log(struct kmod_context *kc) {
    int error = 0;
    int i;
    karray log_file_array;
    karray clean_date_array;
    karray error_date_array;
    khash date_hash;
    time_t now;
    struct tm *tm;
    FILE *open_log_file = NULL;
    
    /* If the file 'debug' exists in the teambox directory, set the logging
     * level to 3 and disable log truncation.
     */
    kstr_sf(&kc->str, "%s/debug", kc->teambox_dir_path.data);

    if (util_check_regular_file_exist(kc->str.data))
    {
    	kmod_log_level = 3;
	kmod_truncate_log_flag = 0;
    }
    
    if (! kmod_log_level) return 0;
    
    karray_init(&log_file_array);
    karray_init(&clean_date_array);
    karray_init(&error_date_array);
    khash_init_func(&date_hash, khash_kstr_key, khash_kstr_cmp);
    
    /* Get the current date for the logs. */
    now = time(NULL);
    tm = localtime(&now);
    tm->tm_year += 1900;
    tm->tm_mon += 1;
    kstr_sf(&kc->log_date, "%.4d_%.2d_%.2d_at_%.2d_%.2d_%.2d", tm->tm_year, tm->tm_mon, tm->tm_mday,
						               tm->tm_hour, tm->tm_min, tm->tm_sec);
    /* Try. */
    do {
    	/* Obtain the list of the log files in the KMOD log directory. */
    	kstr_sf(&kc->str, "%s/kmod_logs/", kc->teambox_dir_path.data);
	error = util_list_dir(kc->str.data, &log_file_array);
    	if (error) break;
	
	/* Sort the logs in two categories: cleanly closed logs and incorrectly
	 * closed logs.
	 */
	for (i = 0; i < log_file_array.size; i++) {
	    kstr *log_file = (kstr *) log_file_array.data[i];
	    
	    /* No regexp support is a pain...it's apparently a valid date. */
	    if (log_file->slen > 22 && ! strncmp(log_file->data + 10, "_at_", 4)) {
		kstr_assign_buf(&kc->str, log_file->data, 22);
		
		/* It's the first time we saw this date. */
		if (! khash_exist(&date_hash, &kc->str)) {
		    
		    /* Add the date in the hash. */
		    kstr *date = kstr_new();
		    kstr_assign_kstr(date, &kc->str);
		    khash_add(&date_hash, date, date);
		    
		    /* Check if the logs for this date have been closed correctly. */
		    kstr_sf(&kc->str, "%s/kmod_logs/%s_OPEN_LOG", kc->teambox_dir_path.data, date->data);
		    
		    /* Error logs. */
		    if (util_check_regular_file_exist(kc->str.data)) {
		    	karray_add(&error_date_array, date);
		    }
		    
		    /* Clean logs. */
		    else {
		    	karray_add(&clean_date_array, date);
		    }
		}
	    }
	}
	
	qsort(clean_date_array.data, clean_date_array.size, sizeof(void *), kmod_open_log_sort);
	qsort(error_date_array.data, error_date_array.size, sizeof(void *), kmod_open_log_sort);
	
	/* Keep at most 20 clean logs and 10 error logs. */
	for (i = 0; i < clean_date_array.size - 20; i++) {
	    kmod_delete_log(kc, (kstr *) clean_date_array.data[i]);
	}
	
	for (i = 0; i < error_date_array.size - 10; i++) {
	    kmod_delete_log(kc, (kstr *) error_date_array.data[i]);
	}
	
	/* Open the logs. */
	kstr_sf(&kc->str, "%s/kmod_logs/%s_k3p.log", kc->teambox_dir_path.data, kc->log_date.data);
	k3p_log = fopen(kc->str.data, "wb"); 
	if (k3p_log == NULL) {
	    kmo_seterror("cannot open '%s': %s", kc->str.data, kmo_syserror());
	    error = -1;
	    break;
	}
	
	kstr_sf(&kc->str, "%s/kmod_logs/%s_knp.log", kc->teambox_dir_path.data, kc->log_date.data);
	knp_log = fopen(kc->str.data, "wb"); 
	if (knp_log == NULL) {
	    kmo_seterror("cannot open '%s': %s", kc->str.data, kmo_syserror());
	    error = -1;
	    break;
	}
	
    	kstr_sf(&kc->str, "%s/kmod_logs/%s_kmod.log", kc->teambox_dir_path.data, kc->log_date.data);
	kmod_log = fopen(kc->str.data, "wb"); 
	if (kmod_log == NULL) {
	    kmo_seterror("cannot open '%s': %s", kc->str.data, kmo_syserror());
	    error = -1;
	    break;
	}
	
	/* Make the logs unbuffered. */
	if (setvbuf(kmod_log, NULL, _IONBF, 0) ||
	    setvbuf(k3p_log, NULL, _IONBF, 0) || 
	    setvbuf(knp_log, NULL, _IONBF, 0)) {
	    
	    kmo_seterror("failed to make logs unbuffered");
	    error = -1;
	    break;
    	}
	
	/* Create the OPEN_LOG file. */
	kstr_sf(&kc->str, "%s/kmod_logs/%s_OPEN_LOG", kc->teambox_dir_path.data, kc->log_date.data);
	open_log_file = fopen(kc->str.data, "wb"); 
	if (open_log_file == NULL) {
	    kmo_seterror("cannot open '%s': %s", kc->str.data, kmo_syserror());
	    error = -1;
	    break;
	}

	fclose(open_log_file);
    
    } while (0);
    
    if (error) {
    	kmod_close_log(kc);
    }
    
    else {
    	kmod_log_msg(1, "Logs opened: level=%d, truncate=%d. KMOD version %s build %s.\n",
		     kmod_log_level, kmod_truncate_log_flag, K3P_VERSION, BUILD_ID);
    }
    
    kmo_clear_kstr_array(&log_file_array);
    karray_free(&log_file_array);
    
    kmo_clear_kstr_array(&clean_date_array);
    karray_free(&clean_date_array);
    
    kmo_clear_kstr_array(&error_date_array);
    karray_free(&error_date_array);
    
    khash_free(&date_hash);
    
    return error;
}

/* This function truncates the open logs, if any.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_truncate_log() {
    k3p_log_mode = 0;
    
    if (kmod_log) {
    	int log_size;
	if (util_get_file_pos(kmod_log, &log_size)) return -1;
	if (log_size > KMOD_MAX_KMOD_LOG_SIZE && util_truncate_file(kmod_log)) return -1;
    }
    
    kmod_log_msg(2, "kmod_truncate_log() called.\n");
    
    if (k3p_log && util_truncate_file(k3p_log)) return -1;
    if (knp_log && util_truncate_file(knp_log)) return -1;
    
    return 0;
}

/* Some code to deal with the different signature versions. This is major ugliness. */
struct kmod_crypt_sig {
    
    /* Version we are dealing with. */
    uint32_t major;
    uint32_t minor;
    
    /* Packaging type. */
    uint32_t pkg_type;
    
    /* Pointer to the right object. */
    union {
	kmocrypt_signature *obj1;
	struct kmocrypt_signature2 *obj2;
	void *obj;
    };
};

static void kmod_sig_free(struct kmod_crypt_sig *self) {
    if (self == NULL) return;
    
    if (self->obj) {    
	if (self->major == 1)
    	    kmocrypt_signature_clean(self->obj1);
	else
    	    kmocrypt_signature_free2(self->obj2);
	
	free(self->obj);
    }
}

/* This function initialises a kmod_crypt_sig object. 'data' is the buffer
 * containing the signature data in base 64, 'len' is the size of the buffer.
 * This function sets the KMO error string. It returns 0 on success, -1 on
 * generic error and -2 if the plugin must be updated to deal with this version
 * of the signature.
 */
static int kmod_sig_init(struct kmod_crypt_sig *self, unsigned char *data, uint32_t len) {
    int error = 0;
    kbuffer *buffer = NULL;
    kmod_log_msg(2, "kmod_sig_init() called.\n");
    memset(self, 0, sizeof(struct kmod_crypt_sig));
    
    /* Try. */
    do {
    	/* Convert the data to binary, store it in a buffer to process it. */	
	buffer = kbuffer_new_b64(data, len);
    	if (buffer == NULL) {
	    kmo_seterror("cannot convert signature: %s", kmo_strerror());
	    error = -1;
	    break;
	}
	
	/* Verify that the buffer is big enough. */
	if (buffer->len < 3*sizeof(uint32_t)) {
	    kmo_seterror("KSP header too short");
	}
	
    	/* Validate the magic number. */
	if (kbuffer_read32(buffer) != KMOCRYPT_PACKET_MAGIC_NUM) {
            kmo_seterror("invalid KSP magic number");
            error = -1;
	    break;
	}
	
	/* Get the major and minor. */
	self->major = kbuffer_read32(buffer);
	self->minor = kbuffer_read32(buffer);
	
	if (self->major < 1 || self->major > 2) {
            kmo_seterror("unsupported KSP version %d", self->major);
            error = -2;
	    break;
	}
	
	/* Reset the buffer read position. */
	buffer->pos = 0;
	
	if (self->major == 1) {
	    self->obj1 = (kmocrypt_signature *) kmo_calloc(sizeof(kmocrypt_signature));
	    error = kmocrypt_recognize_ksp(self->obj, buffer);
	    if (error) break;
    
	    self->pkg_type = self->obj1->type;
	}
	
	else {
	    self->obj2 = (struct kmocrypt_signature2 *) kmo_calloc(sizeof(struct kmocrypt_signature2));
	    error = kmocrypt_recognize_ksp2(self->obj2, buffer);
	    if (error) break;
    
	    self->pkg_type = self->obj2->pkg_type;
	}
    
    } while (0);
    
    kbuffer_destroy(buffer);
    if (error) kmod_sig_free(self);
    
    return error;
}

static int kmod_sig_check_hash(struct kmod_crypt_sig *self, int type, unsigned char *data, uint32_t len) {
    if (self->major == 1)
    	return kmocrypt_signature_check(self->obj1, type, data, len);
    else
    	return kmocrypt_signature_check_hash2(self->obj2, type, data, len);
}

static void kmod_sig_check_attachments(struct kmod_crypt_sig *self, karray *attch_array) {
    if (self->major == 1)
    	kmocrypt_signature_check_attachments(self->obj1, attch_array);
    else
    	kmocrypt_signature_check_attachments2(self->obj2, attch_array);
}

static int kmod_sig_get_ksn(struct kmod_crypt_sig *self, char **ksn, size_t *len) {
    if (self->major == 1)
    	return kmocrypt_signature_get_ksn(self->obj1, ksn, len);
    else
    	return kmocrypt_signature_get_ksn2(self->obj2, ksn, len);
}

static uint64_t kmod_sig_get_mid(struct kmod_crypt_sig *self) {
    if (self->major == 1)
    	return self->obj1->keyid;
    else
    	return self->obj2->mid;
}

static int kmod_sig_has_symkey_for(struct kmod_crypt_sig *self, uint64_t mid) {
    if (self->major == 1)
    	return kmocrypt_sign_has_symkey_for(self->obj1, mid);
    else
    	return kmocrypt_signature_has_symkey_for2(self->obj2, mid);
}

static int kmod_sig_validate(struct kmod_crypt_sig *self, kmocrypt_pkey *key) {
    if (self->major == 1)
    	return kmocrypt_signature_validate(self->obj1, key);
    else
    	return kmocrypt_signature_validate2(self->obj2, key);
}

static int kmod_sig_contain(struct kmod_crypt_sig *self, int type) {
    if (self->major == 1)
    	return kmocrypt_sign_contain(self->obj1, type);
    else
    	return kmocrypt_signature_contain2(self->obj2, type);
}

/* This function returns true if the address specified is an Exchange address. */
static int kmod_is_exchange_addr(char *addr) {
    return (addr[0] == '/' && tolower(addr[1]) == 'e' && tolower(addr[2]) == 'x' && addr[3] == '=');
}

/* This function returns true if the address specified should be queried by the
 * KPS to determine if it is the address of a member.
 */
static int kmod_is_addr_of_kps_domain(char *addr, struct kmod_context *kc) {
    int i, ret = 0;
    kstr str;
    kstr_init(&str);
    
    /* Check the domain names. */
    for (i = 0; i < kc->domain_array.size; i++) {
	kstr *domain_name = (kstr *) kc->domain_array.data[i];
	kstr_assign_cstr(&str, "@");
	kstr_append_kstr(&str, domain_name);
	char *domain_loc = portable_strcasestr(addr, str.data);
	
	/* The address belongs to one of the domains of the KPS. */
	if (domain_loc != NULL) {
	    ret = 1;
	    break;
	}
    }
    
    kstr_free(&str);
    return ret;
}

/* This function enables the KPG in the KNP. */
static void kmod_enable_kpg(struct kmod_context *kc, kstr *addr, int port) {
    kmod_log_msg(2, "kmod_enable_kpg() called.\n");
    kmod_log_msg(2, "kmod_enable_pkg(): using KPG address %s, port %d.\n", addr->data, port);
    
    kc->knp.use_kpg = 1;
    kstr_assign_kstr(&kc->knp.kpg_addr, addr);
    kc->knp.kpg_port = port;
}

/* This functio disables the KPG in the KNP. */
static void kmod_disable_kpg(struct kmod_context *kc) {
    if (kc->knp.use_kpg) {
	kmod_log_msg(2, "kmod_disable_kpg(): No longer using the KPG.\n");
	kc->knp.use_kpg = 0;
	kstr_assign_cstr(&kc->knp.kpg_addr, "");
	kc->knp.kpg_port = 0;
    }
}

/* This function returns true if the data associated to a kmod_otut *looks*
 * valid, i.e. the entry ID and the reply address are set.
 */
static int kmod_is_otut_set(struct kmod_otut *otut) {
    return (otut->entry_id.slen != 0 && otut->reply_addr.slen != 0);
}

/* This function flushes the cached user info, if any. */
static void kmod_flush_user_info(struct kmod_context *kc) {
    kc->user_mid = 0;
    kmo_clear_kstr_array(&kc->domain_array);
    kc->use_kpg = 0;
}

/* This function should be called when an invalid request is detected. The
 * function will send an invalid request instruction to the plugin and close the
 * connection with the plugin. Furthermore, it will update the KMO error string.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_handle_invalid_request(k3p_proto *k3p) {
    kmod_log_msg(2, "kmod_handle_invalid_request() called.\n");
    kmo_seterror("an invalid request occurred");
    k3p_write_inst(k3p, KMO_INVALID_REQ);
    return k3p_send_data(k3p);
}

/* This function should be called when the configuration is wrong. The function
 * will send an invalid config instruction to the plugin.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_handle_invalid_config(k3p_proto *k3p) {
    kmod_log_msg(2, "kmod_handle_invalid_config() called.\n");
    k3p_write_inst(k3p, KMO_INVALID_CONFIG);
    return k3p_send_data(k3p);
}

/* This function should be called when a server error is detected. The function
 * attempts to tell the plugin about the server error. If it fails, the KMO
 * error string is set and -3 is returned to indicate that the connection is
 * dead. Otherwise, -2 is returned to indicate that the error has been handled
 * locally.
 */
static int kmod_handle_server_error(k3p_proto *k3p, struct knp_query *query) { 
    kmod_log_msg(2, "kmod_handle_server_error() called.\n");
    assert(query->res_type == KNP_RES_SERV_ERROR);
    assert(query->serv_error_msg != NULL);
    
    k3p_write_inst(k3p, KMO_SERVER_ERROR);
    k3p_write_uint32(k3p, query->contact);
    k3p_write_uint32(k3p, query->serv_error_id);
    k3p_write_kstr(k3p, query->serv_error_msg);
    
    return k3p_send_data(k3p) ? -3 : -2;
}

/* Utility function to convert an error related to a KNP query to a miscellaneous
 * server error. Normally the server error message should have been set by 
 * kmo_seterror(). This function returns the error code returned by 
 * kmod_handle_server_error().
 */
static int kmod_convert_to_serv_error(k3p_proto *k3p, struct knp_query *query) {
    kmod_log_msg(2, "kmod_convert_to_serv_error() called.\n");
    assert(query->serv_error_msg == NULL);
    
    query->res_type = KNP_RES_SERV_ERROR;
    query->serv_error_id = KMO_SERROR_MISC;
    query->serv_error_msg = kstr_new();
    kstr_assign_kstr(query->serv_error_msg, kmo_kstrerror());
    
    return kmod_handle_server_error(k3p, query);
}

/* This function should be called when the KNP layer complains about the
 * plugin/KPS being too old. The function reports the error to the plugin.
 * This function sets the KMO error string. It returns -2 or -3.
 */
static int kmod_handle_incomp_version(k3p_proto *k3p, struct knp_query *query) {
    kmod_log_msg(2, "kmod_handle_incomp_version() called.\n");
    assert(query->res_type == KNP_RES_UPGRADE_PLUGIN || query->res_type == KNP_RES_UPGRADE_KPS);
    k3p_write_inst(k3p, KMO_MUST_UPGRADE);
    k3p_write_uint32(k3p, (query->res_type == KNP_RES_UPGRADE_PLUGIN) ? KMO_UPGRADE_KOS : KMO_UPGRADE_KPS);
    return k3p_send_data(k3p) ? -3 : -2; 
}

/* This function should be called to set the KMO error string when a
 * server request fails or returns something unexpected.
 */
void kmod_handle_failed_query(struct knp_query *query, char *req_msg) {
    char *reason = NULL;
    
    kmod_log_msg(2, "kmod_handle_failed_query() called.\n");
    
    switch (query->res_type) {
    	case 0: reason = "uninitialized request"; break;
    	case KNP_RES_FAIL: reason = "request failed"; break;
	case KNP_RES_SERV_ERROR: reason  = "server error"; break;
	case KNP_RES_LOGIN_ERROR: reason = "login error"; break;
	case KNP_RES_UPGRADE_PLUGIN: reason = "must upgrade plugin"; break;
	case KNP_RES_UPGRADE_KPS: reason = "must upgrade KPS"; break;
	default: reason = "unexpected KNP message";
    };
    
    kmo_seterror("%s: %s", req_msg, reason);
}

/* This function transforms the newlines of the kstr specified into spaces.
 * Note: this function was used in KSP v1 for signing text bodies. It has been
 * replaced by kmod_trim_whitespace() in KSP v2.
 */
static void kmod_newline2space(kstr *str) {
    int i;
    int new_len = 0;
    
    for (i = 0; i < str->slen; i++) {
    	if (str->data[i] == '\r') {
	    
	    if (str->data[i + 1] == '\n') {
	    	i++;
	    }
	    
	    str->data[new_len] = ' ';
	}
	
	else if (str->data[i] == '\n') {
	    str->data[new_len] = ' ';
	}
	
	else {
	    str->data[new_len] = str->data[i];
	}
	
	new_len++;
    }
    
    str->slen = new_len;
    str->data[new_len] = 0;
}

/* This function merges the sequences of white spaces inside the kstr specified.
 * Each contiguous sequence of whitespaces is replaced by a single space.
 * Note: this function was used in KSP v1 for signing HTML bodies. It has been
 * replaced by kmod_trim_whitespace() in KSP v2.
 */
static void kmod_merge_whitespace(kstr *str) {
    int i;
    int new_len = 0;
    int white_space_mode = 1;
    
    for (i = 0; i < str->slen; i++) {
    	char c = str->data[i];
	
    	if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
	    if (! white_space_mode) {
	    	str->data[new_len] = ' ';
		new_len++;
		white_space_mode = 1;
	    }
	}
	
	else {
	    str->data[new_len] = c;
	    new_len++;
	    white_space_mode = 0;
	}
    }
    
    str->slen = new_len;
    str->data[new_len] = 0;
}

/* This function merges the sequences of white spaces inside the kstr specified.
 * Each contiguous sequence of whitespaces is replaced by a single space.
 * Furthermore, all leading and trailing whitespaces are skipped. This is
 * necessary since MUAs fiddle a lot with white spaces. 
 */
static void kmod_trim_whitespace(kstr *str) {
    int i;
    int new_len = 0;
    int white_space_mode = 1;
    
    for (i = 0; i < str->slen; i++) {
    	char c = str->data[i];
	
    	if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
	    if (! white_space_mode) {
	    	str->data[new_len] = ' ';
		new_len++;
		white_space_mode = 1;
	    }
	}
	
	else {
	    str->data[new_len] = c;
	    new_len++;
	    white_space_mode = 0;
	}
    }
    
    if (new_len && str->data[new_len - 1] == ' ') {
    	new_len--;
    }
    
    str->slen = new_len;
    str->data[new_len] = 0;
}

/* This function cleans up the TO/CC field passed by the plugin to be signed. So
 * far this function fixes the Outlook bogus single quotes damage.
 */
static void kmod_cleanup_signable_to_cc(kstr *field) {
    int read_pos = 0;
    int write_pos = 0;
    
    kmod_log_msg(2, "kmod_cleanup_signable_to_cc() called.\n");
    
    /* We want to remove leading and trailing single quotes in the display name
     * parts.
     */
    while (1) {
    	char *first_double_quote;
	char *second_double_quote;
	
	/* Scan until '"' is found. */
	while (read_pos < field->slen && field->data[read_pos] != '"') {
	    field->data[write_pos++] = field->data[read_pos++];
	}
	
	/* End of string. */
	if (read_pos == field->slen) break;
	
	/* We got '"'. This is necessarily a character introducing the TO/CC
	 * name. Find the ending '"'. There cannot be another double quote in
	 * the name as per the spec.
	 */
	assert(field->data[read_pos] == '"');
	first_double_quote = field->data + read_pos;
	read_pos++;
	
	while (read_pos < field->slen && field->data[read_pos] != '"') {
	    read_pos++;
	}
	
	/* End of string. This is unexpected. */
	if (read_pos == field->slen) {
	    kmod_log_msg(1, "kmod_cleanup_signable_to_cc(): plugin error: no matching '\"' found in name.\n");
	    break;
	}
	
	/* We got the second '"'. Record its position and skip it. */
	assert(field->data[read_pos] == '"');
	second_double_quote = field->data + read_pos;
	read_pos++;
	
	/* Write '"'. */
	field->data[write_pos++] = '"';
	
	/* We have "'...'". Only copy the stuff inside the single quotes. */
	if (second_double_quote - first_double_quote >= 3 &&
	    first_double_quote[1] == '\'' && second_double_quote[-1] == '\'') {
	    
	    memmove(field->data + write_pos, first_double_quote + 2, second_double_quote - first_double_quote - 3);
	    write_pos += second_double_quote - first_double_quote - 3;
	}
	
	/* It's something else, copy all the stuff. */
	else {
	    memmove(field->data + write_pos, first_double_quote + 1, second_double_quote - first_double_quote - 1);
	    write_pos += second_double_quote - first_double_quote - 1;
	}
	
	/* Write '"'. */
	field->data[write_pos++] = '"';
    }
    
    /* Null terminate the string and set its length. */
    field->data[write_pos] = 0;
    field->slen = write_pos;
}

/* This function returns true if the name specified is a valid name for an
 * attachment. If the name is invalid, the KMO error string is set to a string
 * explaining why.
 */
static int kmod_is_valid_attachment_name(kstr *name) {
    int i;
    
    if (name->slen == 0 || name->slen > 255) {
	kmo_seterror("invalid attachment name (incorrect length)");
	return 0;
    }
    
    if (name->data[0] == '.' && (name->data[1] == 0 || (name->data[1] == '.' && name->data[2] == 0))) {
    	kmo_seterror("invalid attachment name (%s)", name->data);
	return 0;
    }
    
    for (i = 0; i < name->slen; i++) {
    	unsigned char c = name->data[i];
    	if (! kmod_allowed_file_char[c]) {
	    kmo_seterror("invalid name '%s' (invalid character code %d, '%c')", name->data, c, c);
	    return 0;
	}
    }
    
    return 1;
}

/* This function fetches an array of attachments from the plugin. If silent_flag
 * is true, attachments in error are marked as such and all attachments are
 * read (best effort). Otherwise, the function aborts as soon as an error occurs.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_fetch_attachment(struct kmod_mail *orig_mail, karray *att_array, int silent_flag) {
    int error = 0;
    int i;
    
    kmod_log_msg(2, "kmod_fetch_attachment() called.\n");
    
    assert(! att_array->size);
    
    /* Fetch the attachments. */
    for (i = 0; i < orig_mail->attachments.size; i++) {
    	struct kmod_mail_attachment *mail_att = (struct kmod_mail_attachment *) orig_mail->attachments.data[i];
    	struct kmod_attachment *att = (struct kmod_attachment *) kmo_calloc(sizeof(struct kmod_attachment));
	karray_add(att_array, att);
	
	/* Validate the tie. */
    	att->tie = mail_att->tie;
	
	if (att->tie != K3P_MAIL_ATTACHMENT_EXPLICIT &&
	    att->tie != K3P_MAIL_ATTACHMENT_IMPLICIT &&
	    att->tie != K3P_MAIL_ATTACHMENT_UNKNOWN) {
	    
	    kmo_seterror("invalid tie value (%x)", att->tie);
	    
	    /* Keep going. */
	    if (silent_flag) {
		att->status = KMO_EVAL_ATTACHMENT_ERROR;
	    	kmod_log_msg(1, "Attachment error: %s.\n", kmo_strerror());
	    }
	    
	    else {
		error = -1;
		break;
	    }
	}
    
    	/* Get the name, encoding, mime type and attachment data. */
	att->name = kstr_new();
	kstr_assign_kstr(att->name, &mail_att->name);
	
	att->encoding = kstr_new();
	kstr_assign_kstr(att->encoding, &mail_att->encoding);
    	
	att->mime_type = kstr_new();
	kstr_assign_kstr(att->mime_type, &mail_att->mime_type);
	
	att->data = kstr_new();
	kstr_assign_kstr(att->data, &mail_att->data);
	
    	/* Validate the attachment name. */
	if (! kmod_is_valid_attachment_name(att->name)) {
	    
	    /* Keep going. */
	    if (silent_flag) {
	    	att->status = KMO_EVAL_ATTACHMENT_ERROR;
	    	kmod_log_msg(1, "Attachment error: %s.\n", kmo_strerror());
	    }
	    
	    else {
	    	error = -1;
		break;
	    }
	}
    
	/* If we have received the data already, copy it then clear it to save memory. */
	if (! mail_att->data_is_file_path) {
	    kstr_shrink(&mail_att->data, 1024);
	}
	
	/* Otherwise, read the data from the file specified. */
	else {
	    FILE *file = NULL;
	    int file_size;
	    
	    /* Try. */
	    do {
	    	error = util_open_file(&file, att->data->data, "rb");
		if (error) break;
	
		error = util_get_file_size(file, &file_size);
		if (error) break;

		kstr_grow(att->data, file_size);
		att->data->slen = file_size;
		att->data->data[file_size] = 0;
		error = util_read_file(file, att->data->data, file_size);
		if (error) break;

		error = util_close_file(&file, 0);
		if (error) break;
		
	    } while (0);
	    
	    /* Close the file silently, if required. */
	    util_close_file(&file, 1);
	    
	    if (error) {
	    
	    	/* Keep going. */
	    	if (silent_flag) {
	    	    error = 0;
		    att->status = KMO_EVAL_ATTACHMENT_ERROR;
		    kmod_log_msg(1, "Attachment error: %s.\n", kmo_strerror());
	    	}
		
		else {
		    break;
		}
	    }
	}
    }
    
    return error;
}

/* This function clears and destroys an attachment array. */
static void kmod_free_attachment_array(karray *att_array) {
    int i;
    
    if (att_array == NULL) return;
    
    for (i = 0; i < att_array->size; i++) {
    	struct kmod_attachment *att = (struct kmod_attachment *) att_array->data[i];
	
	kstr_destroy(att->data);
	kstr_destroy(att->name);
	kstr_destroy(att->encoding);
	kstr_destroy(att->mime_type);
	free(att);
    }
    
    karray_destroy(att_array);
}

/* This function maps maildb field statuses to K3P field statuses. */
static uint32_t kmod_get_mail_info_field_status(maildb_mail_info *mail_info, int flag) {
    int status = (mail_info->field_status & (3 << (flag*2))) >> (flag*2);
    
    switch (status)
    {
    	case 0: return KMO_FIELD_STATUS_ABSENT;
	case 1: return KMO_FIELD_STATUS_CHANGED;
	case 2: return KMO_FIELD_STATUS_INTACT;
	default: assert(0); return 0;
    }
}

/* This function returns true if the bodies of the mail and/or the attachments
 * are valid. If not, this function sets the KMO error string with a message
 * explaining why.
 */
static int kmod_has_valid_critical_field(maildb_mail_info *mail_info) {
    kbuffer buf;
    int i = 0;
    
    kmod_log_msg(2, "kmod_has_valid_critical_field() called.\n");
    
    if (kmod_get_mail_info_field_status(mail_info, MAILDB_STATUS_TEXT_BODY) == KMO_FIELD_STATUS_CHANGED ||
	kmod_get_mail_info_field_status(mail_info, MAILDB_STATUS_HTML_BODY) == KMO_FIELD_STATUS_CHANGED) {
	kmo_seterror("mail body has changed");
	return 0;
    }
    
    kbuffer_init(&buf, mail_info->attachment_status.slen);
    kbuffer_write(&buf, mail_info->attachment_status.data, mail_info->attachment_status.slen);
    
    for (i = 0; i < (int) mail_info->attachment_nbr; i++) {
    	uint32_t str_len = kbuffer_read32(&buf);
	kbuffer_seek(&buf, str_len, SEEK_CUR);
	uint32_t status = kbuffer_read32(&buf);

	if (status != KMO_EVAL_ATTACHMENT_INTACT) {
	    kbuffer_clean(&buf);
	    kmo_seterror("corrupted attachment");
	    return 0;
	}
    }
    
    kbuffer_clean(&buf);
    return 1;
}

/* This function returns true if the OTUT string specified is valid. If not, the
 * function returns false and sets the KMO error string with a message
 * explaining why the OTUT string is not valid.
 */
static int kmod_is_valid_otut_string(kstr *otut_string) {
    int error = 0;
    kstr str;
    kbuffer buf;
    uint32_t u32;
    
    kmod_log_msg(2, "kmod_is_valid_otut_string() called.\n");
    
    /* Try to parse the OTUT string. */
    kstr_init(&str);
    kbuffer_init(&buf, otut_string->slen);
    kbuffer_write(&buf, otut_string->data, otut_string->slen);
    
    do {
    	/* Read the return address. */
    	error = knp_msg_read_kstr(&buf, &str);
	if (error) break;
	
	/* Read the timeval fields. */
    	error = knp_msg_read_uint32(&buf, &u32);
	if (error) break;
	
    	error = knp_msg_read_uint32(&buf, &u32);
	if (error) break;
	
	/* Read the random data string. */
	error = knp_msg_read_kstr(&buf, &str);
	if (error) break;
	
    } while (0);
    
    kbuffer_clean(&buf);
    kstr_free(&str);
    
    return (error == 0);
}

/* This function ensures that the OTUT information inside a maildb_mail_info
 * object is consistent. If the OTUT is not in error, then we should be able
 * to parse the OTUT string. If an error is encountered, the OTUT information
 * is updated.
 */
static void kmod_check_otut_info_integrity(maildb_mail_info *mail_info) {
    kmod_log_msg(2, "kmod_check_otut_info_integrity() called.\n");
    
    /* If there is no OTUT or the OTUT is in error, bail out. */
    if (mail_info->otut_status == KMO_OTUT_STATUS_NONE || mail_info->otut_status == KMO_OTUT_STATUS_ERROR) {
    	return;
    }
    
    assert(mail_info->otut_status == KMO_OTUT_STATUS_USABLE || mail_info->otut_status == KMO_OTUT_STATUS_USED);
    
    /* Update the OTUT status if the OTUT is not valid. */
    if (! kmod_is_valid_otut_string(&mail_info->otut_string)) {
    	mail_info->otut_status = KMO_OTUT_STATUS_ERROR;
    	kstr_sf(&mail_info->otut_msg, "invalid token string: %s", kmo_strerror());
    }
}

/* This function returns true if the mail specified can be safely processed.
 * If not, this function sets the KMO error string with a message explaining
 * why it cannot be processed.
 */
static int kmod_can_process_mail(maildb_mail_info *mail_info) {
    kmod_log_msg(2, "kmod_can_process_mail() called.\n");
    
    /* The mail is not a Kryptiva mail. */
    if (mail_info->status == 2 || mail_info->status == 3) {
    	kmo_seterror("not a Kryptiva mail");
	return 0;
    }
    
    /* If the signature is not valid or a critical field has changed, refuse
     * to process the mail.
     */
    if (mail_info->status != 1) {
	kmo_seterror("invalid signature");
	return 0;
    }
    
    if (! kmod_has_valid_critical_field(mail_info))
    	return 0;
    
    /* If an encryption error has occurred, refuse to process the mail. */
    if (mail_info->encryption_status == KMO_DECRYPTION_STATUS_ERROR) {
	kmo_seterror("encryption error");
	return 0;
    }

    /* If a PoD error has occurred, refuse to process the mail. */
    if (mail_info->pod_status == KMO_POD_STATUS_ERROR) {
	kmo_seterror("PoD error");
	return 0;
    }
	
    return 1;
}

/* This function returns the string status corresponding to the mail info
 * specified.
 */
static int kmod_get_mail_info_string_status(maildb_mail_info *mail_info) {
    
    /* The status of the mail is unknown. */
    if (mail_info->status == 2) return 0;
    
    /* The mail is not a Kryptiva mail. */
    if (mail_info->status == 3) return 2;
    
    assert(mail_info->status == 0 || mail_info->status == 1);
    
    /* The Kryptiva mail is in the grey zone. */
    if (mail_info->display_pref == 0) return 7;
    
    /* The Kryptiva mail must be displayed as an unsigned mail. */
    if (mail_info->display_pref == 2) return 8;
    
    assert(mail_info->display_pref == 1);
    
    /* The Kryptiva mail has an invalid signature. */
    if (mail_info->status == 0) return 3;

    /* The Kryptiva mail is corrupted. */
    if (! kmod_can_process_mail(mail_info)) return 4;

    /* The Kryptiva mail is signed correctly. */
    if (mail_info->encryption_status == KMO_DECRYPTION_STATUS_NONE) return 5;

    /* The Kryptiva mail is encrypted correctly. */
    return 6;
}

/* This function converts the OTUT fields of a mail_info object to a kmod_otut
 * object. The kmod_otut object should have been cleared prior to this call.
 */
static void kmod_mail_info_2_kmod_otut(maildb_mail_info *mail_info, struct kmod_otut *to) {
    int valid_string;
    struct timeval now, expire;
    
    kmod_log_msg(2, "kmod_mail_info_2_kmod_otut() called.\n");

    /* Copy the OTUT status. */
    to->status = mail_info->otut_status;

    /* If there is no OTUT, we're done. */
    if (to->status == KMO_OTUT_STATUS_NONE)
    	return;

    /* Copy the entry ID. */
    kstr_sf(&to->entry_id, "%lld", mail_info->entry_id);

    /* Determine if the OTUT string is valid. Even if the OTUT is in error,
     * the OTUT string itself can be well-formed.
     */
    valid_string = kmod_is_valid_otut_string(&mail_info->otut_string);

    /* Consistency check. */
    assert(mail_info->otut_status == KMO_OTUT_STATUS_ERROR || valid_string);

    /* If the OTUT string is valid, try to extract the return address and
     * the expiration date from it.
     */
    if (valid_string) {
	int error = 0;
	kbuffer buf;
	kbuffer_init(&buf, mail_info->otut_string.slen);
	kbuffer_write(&buf, mail_info->otut_string.data, mail_info->otut_string.slen);

	/* Copy the return address. */
	error = knp_msg_read_kstr(&buf, &to->reply_addr);
	assert(error == 0);

	/* Read the date. */
	error = knp_msg_read_uint32(&buf, (uint32_t *) &expire.tv_sec);
	assert(error == 0);

	error = knp_msg_read_uint32(&buf, (uint32_t *) &expire.tv_usec);
	assert(error == 0);

	kbuffer_clean(&buf);
    }

    /* If the OTUT is in error, copy the error message and we're done.
     * If the OTUT has already been used, copy the used date string and stop.
     */
    if (to->status == KMO_OTUT_STATUS_ERROR || to->status == KMO_OTUT_STATUS_USED) {
    	kstr_assign_kstr(&to->msg, &mail_info->otut_msg);
	return;
    }
    
    /* The OTUT seems usable. However, we have to check the date to see if
     * it is expired.
     */
    assert(to->status == KMO_OTUT_STATUS_USABLE);
    util_get_current_time(&now);

    /* Expired. */
    if (util_timeval_cmp(&now, &expire) == 1) {
    	to->status = KMO_OTUT_STATUS_ERROR;
	format_time(expire.tv_sec, &to->msg);
	kmo_seterror("token expired on %s", to->msg.data);
	kstr_assign_kstr(&to->msg, kmo_kstrerror());
    }

    /* Still usable. */
    else {
	format_time(expire.tv_sec, &to->msg);
    }
}

/* This function converts a mail_info object to an kmod_eval_res object (with
 * the subscriber name and the default password provided). The eval_res object
 * should have been cleared prior to this call.
 */
static void kmod_mail_info_2_eval_res(maildb_mail_info *mail_info, kstr *subscriber_name, kstr *default_pwd,
    	    	    	    	      struct kmod_eval_res *eval_res) {
    kmod_log_msg(2, "kmod_mail_info_2_eval_res() called.\n");
    assert(mail_info->status == 0 || mail_info->status == 1);
    
    eval_res->display_pref = mail_info->display_pref;
    eval_res->string_status = kmod_get_mail_info_string_status(mail_info);
    eval_res->sig_valid = mail_info->status;
    kstr_assign_kstr(&eval_res->sig_msg, &mail_info->sig_msg);
    
    if (mail_info->status == 1) {
	eval_res->original_packaging = mail_info->original_packaging;
	
	assert(subscriber_name != NULL);
	kstr_assign_kstr(&eval_res->subscriber_name, subscriber_name);

	eval_res->from_name_status = kmod_get_mail_info_field_status(mail_info, MAILDB_STATUS_FROM_NAME);
	eval_res->from_addr_status = kmod_get_mail_info_field_status(mail_info, MAILDB_STATUS_FROM_ADDR);
	eval_res->to_status = kmod_get_mail_info_field_status(mail_info, MAILDB_STATUS_TO);
	eval_res->cc_status = kmod_get_mail_info_field_status(mail_info, MAILDB_STATUS_CC);
	eval_res->subject_status = kmod_get_mail_info_field_status(mail_info, MAILDB_STATUS_SUBJECT);
	eval_res->body_text_status = kmod_get_mail_info_field_status(mail_info, MAILDB_STATUS_TEXT_BODY);
	eval_res->body_html_status = kmod_get_mail_info_field_status(mail_info, MAILDB_STATUS_HTML_BODY);
    		
	if (mail_info->attachment_nbr) {
	    kbuffer buf;
	    int i;
	    
	    kbuffer_init(&buf, mail_info->attachment_status.slen);
	    kbuffer_write(&buf, mail_info->attachment_status.data, mail_info->attachment_status.slen);
	    
	    for (i = 0; i < (int) mail_info->attachment_nbr; i++) {	  
	    	struct kmod_eval_res_attachment *att = kmo_malloc(sizeof(struct kmod_eval_res_attachment));
		uint32_t str_len = kbuffer_read32(&buf);
		
	    	k3p_init_eval_res_attachment(att);
	    	karray_add(&eval_res->attachments, att);
		kstr_assign_buf(&att->name, buf.data + buf.pos, str_len);
		kbuffer_seek(&buf, str_len, SEEK_CUR);
		att->status = kbuffer_read32(&buf);
	    }
	    
	    kbuffer_clean(&buf);
	}

	eval_res->encryption_status = mail_info->encryption_status;
	kstr_assign_kstr(&eval_res->decryption_error_msg, &mail_info->decryption_error_msg);
	
	if (default_pwd) {
	    kstr_assign_kstr(&eval_res->default_pwd, default_pwd);
	}
	
	eval_res->pod_status = mail_info->pod_status;
	kstr_assign_kstr(&eval_res->pod_msg, &mail_info->pod_msg);
	
	kmod_mail_info_2_kmod_otut(mail_info, &eval_res->otut);
    }
}

/* This function contacts the KPS to obtain the member ID of the user and the
 * domain names array.
 * This function sets the KMO error string. It returns 0, -2, or -3.
 */
static int kmod_get_user_info(struct kmod_context *kc) {
    int error = 0;
    int convert_flag = 0;
    kbuffer empty_payload;
    struct knp_query *query;
    k3p_proto *k3p = &kc->k3p;

    memset (&empty_payload, 0, sizeof(kbuffer));
    
    kmod_log_msg(2, "kmod_get_user_info() called.\n");
    assert(k3p_is_a_member(&kc->server_info));
    
    /* Flush the current user info. */
    kmod_flush_user_info(kc);
    
    query = knp_query_new(KNP_CONTACT_KPS, KNP_CMD_LOGIN_USER, KNP_CMD_GET_USER_INFO, &empty_payload);
    
    /* Try. */
    do {
    	error = knp_query_exec(query, &kc->knp);
	if (error) break;
	
	if (query->res_type == KNP_RES_SERV_ERROR) {
	    error = kmod_handle_server_error(k3p, query);
	    break;
	}
	
	if (query->res_type == KNP_RES_UPGRADE_PLUGIN || query->res_type == KNP_RES_UPGRADE_KPS) {
	    error = kmod_handle_incomp_version(k3p, query);
	    break;
	}
	
	if (query->res_type == KNP_RES_LOGIN_ERROR) {
	    error = (kmod_handle_invalid_config(k3p) == -1) ? -3 : -2;
	    break;
	}
	
	/* Convert this to a server error. */
	if (query->res_type != KNP_RES_GET_USER_INFO) {
	    kmod_handle_failed_query(query, "cannot obtain user's info");
	    convert_flag = 1;
	    break;
	}
	
	/* Try. */
	do {
	    uint32_t nb_domain;
	    uint32_t i;
	    
	    /* Get the member ID. */
	    error = knp_msg_read_uint64(query->res_payload, &kc->user_mid);
	    if (error) break;
	    
	    /* Get the domain names. */
	    error = knp_msg_read_uint32(query->res_payload, &nb_domain);
	    if (error) break;
	    
	    for (i = 0; i < nb_domain; i++) {
	    	kstr *domain_name = kstr_new();
		karray_add(&kc->domain_array, domain_name);
		error = knp_msg_read_kstr(query->res_payload, domain_name);
		if (error) break;
	    }
	    
	    if (error) break;
	    
	    /* KPG kludge. */
	    if (! knp_msg_read_uint32(query->res_payload, &i) && i == 1) {
		kc->use_kpg = 1;
		
		error = knp_msg_read_kstr(query->res_payload, &kc->kpg_addr);
		if (error) break;
		
		error = knp_msg_read_uint32(query->res_payload, &kc->kpg_port);
		if (error) break;
	    }
	    
	} while (0);
	
	/* Convert this to a server error. */
	if (error) {
	    kmod_flush_user_info(kc);
	    convert_flag = 1;
	    break;
	}
	
    } while (0);
    
    /* Convert the error to a server error. */
    if (convert_flag) {
    	error = kmod_convert_to_serv_error(k3p, query);
    }
    
    knp_query_destroy(query);
    return error;
}


/* Info about the internal state of eval/process incoming. */
struct kmod_eval_state {
    
    /* Mail to evaluate. Memory not owned by this object. */
    struct kmod_mail *orig_mail;

    /* Array of attachments received from the plugin. We might also append
     * some attachments in this array when we evaluate the mail.
     */
    karray *recv_att_array;
    
    /* Signature text extracted from the mail body. */
    kstr *sig_text;
    
    /* Mail signature object. */
    struct kmod_crypt_sig *sig_obj;
    
    /* Public signature key data. */
    kstr *sig_key_data;

    /* Public timestamp key data. */
    kstr *sig_key_tm_data;

    /* Public signature key object. */
    struct kmocrypt_signed_pkey *sig_key_obj;
    
    /* Subscriber name, if any. */
    kstr *subscriber_name;
    
    /* Default password for the decryption, if any. */
    kstr *default_pwd;
    
    /* Intermediate symmetric key data. */
    kstr *inter_sym_key_data;
    
    /* Final symmetric key data. */
    kstr *sym_key_data;
    
    /* True if the symmetric key data has been proven to be valid. */
    int sym_key_valid;
    
    /* The date at which the PoD has been delivered. */
    uint32_t pod_date;

    /* Status codes for the bodies. */
#define KMOD_BODY_NONE	    	0   	    /* No body. */
#define KMOD_BODY_UNSIGNED  	1   	    /* Body of a signed message without the signature. */
#define KMOD_BODY_ENCODED   	2   	    /* Body of an encrypted message without the signature, in base 64. */
#define KMOD_BODY_DECODED   	3   	    /* Body of an encrypted message in raw binary data. */
#define KMOD_BODY_DECRYPTED 	4   	    /* Message blob obtained from the decrypted body. */
#define KMOD_BODY_EXTRACTED 	5   	    /* Text/HTML body extracted from the message blob. */
    
    /* Unsigned/encoded/decoded/decrypted/extracted text body. */
    kstr *text_body;
    int text_body_status;
    
    /* Unsigned/extracted HTML body. */
    kstr *html_body;
    int html_body_status;
    
    /* Array of attachments sent to the plugin in kmod_process_incoming(), for
     * encrypted mails.
     */
    karray *decrypted_att_array;
    
    /* Previous maildb_mail_info associated to the mail, if any. */
    maildb_mail_info *prev_mail_info;
    
    /* Current maildb_mail_info associated to the mail. */
    maildb_mail_info *mail_info;
    
    /* True if the previous mail info's display preference should override the
     * current mail info display preference.
     */
    int use_prev_display_pref;
    
    /* Process message special condition. This is queried in some places to
     * change the default control flow.
     */
#define KMOD_PROCESS_COND_NONE	    	0   /* No special condition. */
#define KMOD_PROCESS_COND_POD_ERROR 	1   /* The server cannot deliver the PoD. */
#define KMOD_PROCESS_COND_BAD_PWD	2   /* The password specified is wrong. */
#define KMOD_PROCESS_COND_NOT_AUTH	3   /* The user is not authorized to decrypt the mail. */
#define KMOD_PROCESS_COND_ATT_ERROR 	4   /* An error has occurred while writing the attachments to the filesystem. */
    int process_special_cond;
    
    /* True if the decryption email address is wanted (as per
     * K3P_PROCESS_INCOMING_EX).
     */
    int want_dec_email;
    
    /* Decryption email. */
    kstr *dec_email;
    
    /* Initialized scratch payload. */
    kbuffer payload;
    
    /* Initialized scratch string. */
    kstr str;
};

/* This function initializes the kmod_eval_state object. */
static void kmod_eval_init(struct kmod_eval_state *state, struct kmod_mail *orig_mail) {
    memset(state, 0, sizeof(struct kmod_eval_state));
    state->orig_mail = orig_mail;
    kbuffer_init(&state->payload, 200);
    kstr_init(&state->str);
}

/* This function frees the kmod_eval_state object. */
static void kmod_eval_free(struct kmod_eval_state *state) {
    kmod_free_attachment_array(state->recv_att_array);
    kstr_destroy(state->sig_text);
    
    if (state->sig_obj) {
    	kmod_sig_free(state->sig_obj);
    	free(state->sig_obj);
    }
    
    kstr_destroy(state->sig_key_data);
    kstr_destroy(state->sig_key_tm_data);
    kmocrypt_signed_pkey_destroy(state->sig_key_obj);
    kstr_destroy(state->subscriber_name);
    kstr_destroy(state->default_pwd);
    kstr_destroy(state->inter_sym_key_data);
    kstr_destroy(state->sym_key_data);
    kstr_destroy(state->text_body);
    kstr_destroy(state->html_body);
    kmod_free_attachment_array(state->decrypted_att_array);
    
    if (state->prev_mail_info) {
    	maildb_free_mail_info(state->prev_mail_info);
	free(state->prev_mail_info);
    }
    
    if (state->mail_info) {
    	maildb_free_mail_info(state->mail_info);
	free(state->mail_info);
    }
    
    kstr_destroy(state->dec_email);
    kbuffer_clean(&state->payload);
    kstr_free(&state->str);
}

/* This function writes the 'maildb_mail_info' and 'maildb_sender_info' objects
 * to the database. It also obtains the entry ID associated to the
 * maildb_mail_info object in the database.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_eval_write_maildb_info(struct kmod_context *kc, struct kmod_eval_state *state) {
    int error = 0;
    maildb_sender_info sender_info;
    
    kmod_log_msg(2, "kmod_eval_write_maildb_info() called.\n");    
    maildb_init_sender_info(&sender_info);
    
    /* If we have proven the symmetric key to be valid, it becomes the key
     * stored in the database. Otherwise, we store the key we previously
     * obtained from the database, if any.
     */
    if (state->sym_key_valid) {
    	assert(state->sym_key_data);
	kstr_assign_kstr(&state->mail_info->sym_key, state->sym_key_data);
    }
   
    /* Set the sender_info fields. */
    if (state->mail_info->status == 1) {
	sender_info.mid = state->mail_info->mid;
	assert(state->subscriber_name);
	kstr_assign_kstr(&sender_info.name, state->subscriber_name);
    }
    
    /* Try. */
    do {
    	/* We do not do these updates inside the same transaction, but it's OK
	 * since we store the sender info first.
	 */
    	
    	/* Store the sender_info in the database. */
	if (state->mail_info->status == 1) {    	    
    	    error = maildb_set_sender_info(kc->mail_db, &sender_info);
    	    if (error) break;
	}
	
	/* Store the mail info in the database. */
	error = maildb_set_mail_info(kc->mail_db, state->mail_info);
	if (error) break;
	
    } while (0);
    
    maildb_free_sender_info(&sender_info);
    return error;
}

/* This function determines the PoD status of the mail. */
static void kmod_eval_check_pod(struct kmod_eval_state *state) {
    kmod_log_msg(2, "kmod_eval_check_pod() called.\n");
    
    /* We managed to decrypt the mail already. */
    if (state->text_body_status == KMOD_BODY_DECRYPTED) {

	/* If we have a previous mail info object and it says the PoD has been
	 * delivered, remember that the PoD has been delivered. Otherwise, the
	 * PoD does not apply to us.
	 */
	if (state->prev_mail_info && state->prev_mail_info->pod_status == KMO_POD_STATUS_DELIVERED) {
	    state->mail_info->original_packaging |= KMO_REQUIRED_POD_MASK;
	    state->mail_info->pod_status = KMO_POD_STATUS_DELIVERED;
	    kstr_assign_kstr(&state->mail_info->pod_msg, &state->prev_mail_info->pod_msg);
	}
    }

    /* We need to deliver the PoD, even if was already delivered successfully
     * in the past.
     */
    else {
	state->mail_info->original_packaging |= KMO_REQUIRED_POD_MASK;
	state->mail_info->pod_status = KMO_POD_STATUS_UNDELIVERED;	
    }
}

/* This function decrypts the decoded text body of an encrypted mail.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_eval_decrypt_body(struct kmod_eval_state *state) {
    kmod_log_msg(2, "kmod_eval_decrypt_body() called.\n");
    
    assert(state->text_body_status == KMOD_BODY_DECODED);    
    
    int error = 0;
    int i;
    kmocrypt_symkey *sym_key_obj = NULL;
    char *decrypted_data = (char *) kmo_malloc(state->text_body->slen);
    int decrypted_data_len = state->text_body->slen;
    kbuffer msg;
    uint64_t magic;

    kbuffer_init(&msg, 1000);
    
    /* Try. */
    do {
	/* Create the symmetric key. */
    	sym_key_obj = kmocrypt_symkey_new(state->sym_key_data->data, state->sym_key_data->slen);
	
	if (sym_key_obj == NULL) {
	    error = -1;
	    break;
	}

	/* Decrypt the decoded data. */
	kstr_grow(&state->str, state->text_body->slen);
	error = kmocrypt_symkey_decrypt(sym_key_obj, state->text_body->data, state->text_body->slen,
					decrypted_data, &decrypted_data_len);
	if (error) break;
	
	/* Verify the magic numbers. */
	kbuffer_write(&msg, decrypted_data, decrypted_data_len);
	
	for (i = 0; i < 2; i++) {
	    error = knp_msg_read_uint64(&msg, &magic);
	    if (error) break;
	    
	    if (magic != KNP_ENC_BODY_MAGIC) {
	    	kmo_seterror("invalid magic number in decrypted message payload");
		error = -1;
		break;
	    }
	}
	
	if (error) break;

	/* Replace the decoded data with the decrypted data. */
	state->text_body_status = KMOD_BODY_DECRYPTED;
	kstr_assign_buf(state->text_body, decrypted_data, decrypted_data_len);
	
	/* The symmetric key data is valid. */
	state->sym_key_valid = 1;

    } while (0);
    
    if (sym_key_obj != NULL) kmocrypt_symkey_destroy(sym_key_obj);
    kbuffer_clean(&msg);
    free(decrypted_data);
 
    return error;
}

/* This function decodes the text body of an encrypted mail.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_eval_decode_body(struct kmod_eval_state *state) {
    kmod_log_msg(2, "kmod_eval_decode_body() called.\n");
    
    assert(state->text_body_status == KMOD_BODY_ENCODED);
    int error = 0;
    kbuffer in, out;
    
    kbuffer_init(&in, state->text_body->slen);
    kbuffer_write(&in, state->text_body->data, state->text_body->slen);
    kbuffer_init(&out, state->text_body->slen);
    error = b642bin(&in, &out, 0);
    
    /* Replace the encoded data with the decoded data. */
    if (! error) {
    	state->text_body_status = KMOD_BODY_DECODED;
	kstr_assign_buf(state->text_body, out.data, out.len);
    }
    
    kbuffer_clean(&in);
    kbuffer_clean(&out);
    
    return error;
}

/* This function determines the encryption status of the mail.
 * This function sets the KMO error string. It returns 0, -2, or -3.
 */
static int kmod_eval_check_encryption(struct kmod_context *kc, struct kmod_eval_state *state) {
    int error = 0;
    
    kmod_log_msg(2, "kmod_eval_check_encryption() called.\n");
    
    /* Verify the encryption. */
    do {
    	/* If a body/attachment has been modified, don't attempt to decrypt. */
	if(! kmod_has_valid_critical_field(state->mail_info)) {
	    error = -1;
	    break;
	}
	
	/* The body is encoded in base 64. Decode it. */
	assert(state->text_body_status == KMOD_BODY_ENCODED);
	error = kmod_eval_decode_body(state);
	if (error) break;
	
	/* We might have obtained the key data from the previous mail info
	 * entry. Try it in that case.
	 */
	if (state->mail_info->sym_key.slen > 0) {
	    assert(state->sym_key_data == NULL);
	    state->sym_key_data = kstr_new();
	    kstr_assign_kstr(state->sym_key_data, &state->mail_info->sym_key);
	    kmod_eval_decrypt_body(state);
	    
	    /* The decryption key appears to be working. Tell the plugin that the
	     * mail is decrypted. We should be able to honor our words later.
	     */
    	    if (state->text_body_status == KMOD_BODY_DECRYPTED) {

		/* Do not change the status for PoD only. PoD is handled later. */
    		if (state->sig_obj->pkg_type & KMO_P_TYPE_ENC) {
	    	    state->mail_info->original_packaging |= KMO_ENCRYPTED_MASK;
	    	    state->mail_info->encryption_status = KMO_DECRYPTION_STATUS_DECRYPTED;
		}

		break;
	    }
	    
	    kstr_destroy(state->sym_key_data);
	    state->sym_key_data = NULL;
	}
	
	/* Obtain the user member ID if we don't have it, the user is a member and
	 * a public encryption key was used to encrypt the mail.
	 */
	if (kc->user_mid == 0 &&
	    k3p_is_a_member(&kc->server_info) &&
	    kmod_sig_contain(state->sig_obj, KMO_SP_TYPE_SYMKEY)) {
	    
	    error = kmod_get_user_info(kc);

	    /* This has been handled locally in one way or another; not an
	     * encryption error.
	     */
	    if (error) break;
	}

	/* The mail is encrypted with the user's public encryption key. */
	if (kc->user_mid != 0 && kmod_sig_has_symkey_for(state->sig_obj, kc->user_mid)) {
	    state->mail_info->original_packaging |= KMO_ENCRYPTED_MASK;
	    state->mail_info->encryption_status = KMO_DECRYPTION_STATUS_ENCRYPTED;
	}

	/* The mail is encrypted with a password. */
	else if (kmod_sig_contain(state->sig_obj, KMO_SP_TYPE_PASSWD)) {
	    state->mail_info->original_packaging |= KMO_ENCRYPTED_WITH_PWD_MASK;
	    state->mail_info->encryption_status = KMO_DECRYPTION_STATUS_ENCRYPTED_WITH_PWD;

	    /* Get the default password from the database, if any. */
	    state->default_pwd = kstr_new();
	    
	    if (maildb_get_pwd(kc->mail_db, &state->orig_mail->from_addr, state->default_pwd)) {
	    	kstr_destroy(state->default_pwd);
		state->default_pwd = NULL;
	    }
	}
	
	/* The mail is encrypted for PoD and only for PoD. */
	else if ((state->sig_obj->pkg_type & KMO_P_TYPE_ENC) == 0) {
	    /* Encryption status is already set correctly. PoD is handled later. */
	}

	/* The mail is encrypted but the user has no way to decrypt it. This is
	 * deemed to be a permanent error. The user has to reprocess the mail to
	 * clear this error.
	 */
	else {
	    kmo_seterror("the mail has not been encrypted for you");
	    error = -1;
	    break;
	}
	
    } while (0);
    
    /* If a miscelleanous error occurred, the mail cannot be decrypted,
     * permanently. Remember that fact and return 0.
     */
   if (error == -1) {
    	state->mail_info->original_packaging |= KMO_ENCRYPTED_MASK;
    	state->mail_info->encryption_status = KMO_DECRYPTION_STATUS_ERROR;
	kstr_assign_kstr(&state->mail_info->decryption_error_msg, kmo_kstrerror());
	error = 0;
   }
   
   return error;
}

/* Utility function for kmod_eval_check_field(). It updates the field status
 * flags of the 'mail_info' object.
 */
static int kmod_eval_one_check_field(struct kmod_eval_state *state, kstr *field, int crypt_type, int maildb_type) {
    int status;
 
    /* If the field was present when the message was sent, it must be present
     * when the message was received.
     */
    if (kmod_sig_contain(state->sig_obj, crypt_type)) {
    	
    	if (! kmod_sig_check_hash(state->sig_obj, crypt_type, field->data, field->slen)) {
            status = 2; /* Intact. */
	}
	
	else {
	    status = 1; /* Changed. */
	}
    }
    
    /* If the field was not present when the message was sent, it must not be
     * present when the message was received.
     */
    else if (field->slen == 0) {
    	status = 0; /* Absent. */
    }
	
    else {
    	status = 1; /* Changed. */
    }
    
    return (status << (maildb_type*2));
}

/* Set the email field and attachments statuses. */
static void kmod_eval_check_field(struct kmod_eval_state *state) {
    int i;
    kbuffer buf;
    maildb_mail_info *mail_info = state->mail_info;
    
    kmod_log_msg(2, "kmod_eval_check_field() called.\n");
    
    /* Verify TO, subject, etc. */
    mail_info->field_status = 0;
    
    /* The TO, CC, from name and from address fields must be converted to lower
     * case before they are verified.
     */
    kstr_assign_kstr(&state->str, &state->orig_mail->from_name);
    strntolower(state->str.data, state->str.slen);
    mail_info->field_status |= kmod_eval_one_check_field(state, &state->str,
	    	    	    	    	    	         KMO_SP_TYPE_FROM_NAME, MAILDB_STATUS_FROM_NAME);
    
    kstr_assign_kstr(&state->str, &state->orig_mail->from_addr);
    strntolower(state->str.data, state->str.slen);
    mail_info->field_status |= kmod_eval_one_check_field(state, &state->str,
	    	    	    	    	    	         KMO_SP_TYPE_FROM_ADDR, MAILDB_STATUS_FROM_ADDR);
    
    /* The TO and CC strings need to be cleaned up. */
    kstr_assign_kstr(&state->str, &state->orig_mail->to);
    kmod_cleanup_signable_to_cc(&state->str);
    strntolower(state->str.data, state->str.slen);
    mail_info->field_status |= kmod_eval_one_check_field(state, &state->str,
	    	    	    	    	    	         KMO_SP_TYPE_TO, MAILDB_STATUS_TO);
    
    kstr_assign_kstr(&state->str, &state->orig_mail->cc);
    kmod_cleanup_signable_to_cc(&state->str);
    strntolower(state->str.data, state->str.slen);
    mail_info->field_status |= kmod_eval_one_check_field(state, &state->str,
	    	    	    	    	    	         KMO_SP_TYPE_CC, MAILDB_STATUS_CC);
    
    /* The subject must have its whitespace trimmed, since MUAs (Outlook) mess
     * with it too.
     */
    kstr_assign_kstr(&state->str, &state->orig_mail->subject);
    kmod_trim_whitespace(&state->str);
    mail_info->field_status |= kmod_eval_one_check_field(state, &state->str,
	    	    	    	    	    	         KMO_SP_TYPE_SUBJECT, MAILDB_STATUS_SUBJECT);
    
    /* Verify the bodies. */
    if (state->text_body == NULL) { 
	kstr_clear(&state->str);
    }

    else {
	kstr_assign_kstr(&state->str, state->text_body);
	
	if (state->sig_obj->major == 1)
	    kmod_newline2space(&state->str);
	else
	    kmod_trim_whitespace(&state->str);
	
	#ifdef BODY_CHANGED_DEBUG
	fprintf(kmod_log, "RECEIVING: dumping signed text body:\n");
	util_dump_buf_ascii(state->str.data, state->str.slen, kmod_log);
	fprintf(kmod_log, "END END END.\n\n");
	#endif  
    }

    mail_info->field_status |= kmod_eval_one_check_field(state, &state->str,
    	    	    	    	    	    	    	 KMO_SP_TYPE_PLAIN, MAILDB_STATUS_TEXT_BODY);

    if (state->html_body == NULL) { 
	kstr_clear(&state->str);
    }

    else { 
	kstr_assign_kstr(&state->str, state->html_body);
	mail_repair_outlook_html_damage(&state->str);

	if (state->sig_obj->major == 1)
	    kmod_merge_whitespace(&state->str);
	else
	    kmod_trim_whitespace(&state->str);
	
	#ifdef BODY_CHANGED_DEBUG
	fprintf(kmod_log, "RECEIVING: dumping signed HTML body:\n");
	util_dump_buf_ascii(state->str.data, state->str.slen, kmod_log);
	fprintf(kmod_log, "END END END.\n\n");
	#endif  
    }

    mail_info->field_status |= kmod_eval_one_check_field(state, &state->str,
    	    	    	    	    	    	    	 KMO_SP_TYPE_HTML, MAILDB_STATUS_HTML_BODY);
    
    /* Remember the number of attachments received from the plugin. */
    mail_info->att_plugin_nbr = state->recv_att_array->size;
    
    /* Verify the attachments. */
    kmod_sig_check_attachments(state->sig_obj, state->recv_att_array);
    
    /* Create the attachments blob for the DB, replacing the previous one as
     * needed.
     */
    kbuffer_init(&buf, 1024);
    mail_info->attachment_nbr = state->recv_att_array->size;
    
    for (i = 0; i < state->recv_att_array->size; i++) {
    	struct kmod_attachment *att = (struct kmod_attachment *) state->recv_att_array->data[i];
    	kbuffer_write32(&buf, att->name->slen);
	kbuffer_write(&buf, att->name->data, att->name->slen);
	kbuffer_write32(&buf, att->status);
    }
    
    kstr_assign_buf(&mail_info->attachment_status, buf.data, buf.len);
    kbuffer_clean(&buf);
}

/* This function removes the signature tags and other junk from the mail
 * bodies.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_eval_remove_sig(struct kmod_eval_state *state) {
    int error = 0;
    
    kmod_log_msg(2, "kmod_eval_remove_sig() called.\n");
    
    /* Remove the signature from the signed mail bodies. */
    if (state->sig_obj->pkg_type == KMO_P_TYPE_SIGN) {
    	if (state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT ||
	    state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT_N_HTML) {

	    state->text_body = kstr_new();
	    state->text_body_status = KMOD_BODY_UNSIGNED;
	    error = mail_strip_text_signature(&state->orig_mail->body.text, state->text_body);
	    if (error) return -1;
	}

	if (state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_HTML ||
	    state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT_N_HTML) {

	    state->html_body = kstr_new();
	    state->html_body_status = KMOD_BODY_UNSIGNED;
	    error = mail_strip_html_signature(&state->orig_mail->body.html, state->html_body);
	    if (error) return -1;
	}
    }

    /* Remove the signature from the encrypted body. */
    else {

	/* If the mail is encrypted and/or requires a PoD, we should have
	 * a text body and only a text body. However, some MUA automatically 
	 * generate HTML mails from text mails and therefore we may receive
	 * an HTML body here. Consequently, if the mail has an HTML body and
	 * no text body, we use the HTML body. If a text body is provided,
	 * we ignore the HTML body, if any.
	 */
	state->text_body = kstr_new();
	state->text_body_status = KMOD_BODY_ENCODED;
	error = mail_get_encrypted_body(state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_HTML ?
	    	    	    	    	&state->orig_mail->body.html : &state->orig_mail->body.text,
					state->text_body);
	if (error) return -1;
    }
    
    return 0;
}

/* This function obtains the signature key data from the IKS.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int kmod_eval_do_sig_key_query(struct kmod_context *kc, struct kmod_eval_state *state) {
    int error = 0;
    int convert_flag = 0;
    struct knp_query *query;
    kbuffer *buffer = NULL;
    
    kmod_log_msg(2, "kmod_eval_do_sig_key_query() called.\n");
    
    /* Don't fetch the key if we already have it. */
    if (state->sig_key_data) return 0;
    
    kbuffer_clear(&state->payload);
    knp_msg_write_uint64(&state->payload, state->mail_info->mid);
    
    query = knp_query_new(KNP_CONTACT_IKS, KNP_CMD_LOGIN_ANON, KNP_CMD_GET_SIGN_KEY, &state->payload);
    
    /* Try. */
    do {
    	error = knp_query_exec(query, &kc->knp);
	if (error) break;
	
	if (query->res_type == KNP_RES_SERV_ERROR) {
	    error = kmod_handle_server_error(&kc->k3p, query);
	    break;
	}
	
	if (query->res_type == KNP_RES_UPGRADE_PLUGIN || query->res_type == KNP_RES_UPGRADE_KPS) {
	    error = kmod_handle_incomp_version(&kc->k3p, query);
	    break;
	}
    	
	/* This is deemed to be a permanent error. */
	if (query->res_type == KNP_RES_FAIL) {
	    kmo_seterror("cannot obtain public signature key: no such key");
	    error = -1;
	    break;
	}
	
	/* Convert this to a server error. */
	if (query->res_type != KNP_RES_GET_SIGN_KEY) {
	    kmod_handle_failed_query(query, "cannot obtain public signature key");
	    convert_flag = 1;
	    break;
	}

        /* Get the timestamp key data. */
        state->sig_key_tm_data = kstr_new();
        error = knp_msg_read_kstr(query->res_payload, state->sig_key_tm_data);
        if (error) { convert_flag = 1; break; }
    	
	/* Get the key data. */
	state->sig_key_data = kstr_new();
	error = knp_msg_read_kstr(query->res_payload, state->sig_key_data);
	if (error) { convert_flag = 1; break; }
    	
        /* Get the key. Assume the timestamp is correct since we got it directly
         * from the server.
	 */
        buffer = kbuffer_new(32);
        kbuffer_write(buffer, state->sig_key_data->data, strlen(state->sig_key_data->data));
    	
        state->sig_key_obj = kmocrypt_sign_get_pkey(buffer);
        if (!state->sig_key_obj) { convert_flag = 1; break; }
    	
	/* Get the subscriber name. */
	if (! state->subscriber_name)
	    state->subscriber_name = kstr_new();
	
	error = knp_msg_read_kstr(query->res_payload, state->subscriber_name);
	if (error) { convert_flag = 1; break; }
	
    } while (0);
    
    /* Convert the error to a server error. */
    if (convert_flag) {
    	error = kmod_convert_to_serv_error(&kc->k3p, query);
    }
    
    kbuffer_destroy(buffer);
    knp_query_destroy(query);
    return error;
}

/* This function obtains the signature key data from the IKS and validates the
 * mail signature.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int kmod_eval_verify_sig(struct kmod_context *kc, struct kmod_eval_state *state) {    
    int error = 0;
    
    kmod_log_msg(2, "kmod_eval_verify_sig() called.\n");
    
    assert(state->sig_obj);
    
    /* Contact the IKS to obtain the data associated to the signature key ID. */
    error = kmod_eval_do_sig_key_query(kc, state);
    if (error) return error;
    
    /* Verify the signature. Note that the mail_info statuses and the signature message
     * will be set later, should this call fails.
     */
    return kmod_sig_validate(state->sig_obj, state->sig_key_obj->key);
}

/* This function computes the hash of the mail. */
static void kmod_eval_compute_hash(struct kmod_eval_state *state) {
    kbuffer in, out;
    int i;
    
    kmod_log_msg(2, "kmod_eval_compute_hash() called.\n");
    
    /* Don't recompute the hash if we already have it. */
    if (state->mail_info->hash.slen) return;
    
    kbuffer_init(&in, 2000);
    kbuffer_init(&out, 20);
    
    /* Put the from name, from address, TO, CC, subject, the bodies and the attachments
     * in the hash.
     */
    kbuffer_write(&in, state->orig_mail->from_name.data, state->orig_mail->from_name.slen);
    kbuffer_write(&in, state->orig_mail->from_addr.data, state->orig_mail->from_addr.slen);
    kbuffer_write(&in, state->orig_mail->to.data, state->orig_mail->to.slen);
    kbuffer_write(&in, state->orig_mail->cc.data, state->orig_mail->cc.slen);
    kbuffer_write(&in, state->orig_mail->subject.data, state->orig_mail->subject.slen);
    
    /* The hash of a body may change when the message is moved in another
     * folder. Therefore, we try to hash only the content inside the Kryptiva
     * signature.
     */
    if (state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT ||
        state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT_N_HTML) {
	    
    	kstr body;
	kstr_init(&body);
	
	if (! mail_strip_text_signature(&state->orig_mail->body.text, &body)) {
	    kbuffer_write(&in, body.data, body.slen);
	}
    	
	else {
	    kbuffer_write(&in, state->orig_mail->body.text.data, state->orig_mail->body.text.slen);
	}

	kstr_free(&body);
    }
    
    if (state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_HTML ||
    	state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT_N_HTML) {
	
	kstr body;
	kstr_init(&body);
    
	if (! mail_strip_html_signature(&state->orig_mail->body.text, &body)) {
	    kbuffer_write(&in, body.data, body.slen);
	}
    	
	else {
	    kbuffer_write(&in, state->orig_mail->body.html.data, state->orig_mail->body.html.slen);
	}

	kstr_free(&body);
    }
    
    /* Hash the attachments. */
    for (i = 0; i < state->recv_att_array->size; i++) {
    	struct kmod_attachment *att = (struct kmod_attachment *) state->recv_att_array->data[i];
	kbuffer_write(&in, att->data->data, att->data->slen);
	kbuffer_write(&in, att->name->data, att->name->slen);
    }
    
    /* Compute the hash. */
    kmocrypt_sha1_hash(&in, &out);
    kstr_assign_buf(&state->mail_info->hash, out.data, 20);
    
    kbuffer_clean(&in);
    kbuffer_clean(&out);
}

/* This function fetches the mail information stored in the database, if any.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static void kmod_eval_get_prev_mail_info(struct kmod_context *kc, struct kmod_eval_state *state) {
    int error = 0;
    maildb_mail_info *prev = (maildb_mail_info *) kmo_malloc(sizeof(maildb_mail_info));
    maildb_init_mail_info(prev);
    state->prev_mail_info = prev;
    
    kmod_log_msg(2, "kmod_eval_get_prev_mail_info() called.\n");
   
    /* Try. */
    do {
    	/* Try to find the mail from its message ID. */
	error = maildb_get_mail_info_from_msg_id(kc->mail_db, prev, &state->orig_mail->msg_id);
    	
	/* We found the mail. */
	if (error == 0) {
	    kmod_log_msg(3, "kmod_eval_get_prev_mail_info(): found previous entry with message id %s.\n",
	    	         state->orig_mail->msg_id.data);
	}
	
	/* Error. */
	else if (error == -1) break;
	
	/* Not found. Try to find the mail from its hash and KSN. */
	else {
	    assert(error == -2);
	    
	    kmod_eval_compute_hash(state);
	    error = maildb_get_mail_info_from_hash(kc->mail_db, prev, &state->mail_info->hash, &state->mail_info->ksn);
	    
	    if (error == 0) {
	    	if (kmod_log_level == 3) {
		    kstr hash_str, ksn_str;
		    kstr_init(&hash_str);
		    kstr_init(&ksn_str);
		    util_bin_to_hex(state->mail_info->hash.data, state->mail_info->hash.slen, &hash_str);
		    util_bin_to_hex(state->mail_info->ksn.data, state->mail_info->ksn.slen, &ksn_str);
		    kmod_log_msg(3, "kmod_eval_get_prev_mail_info(): found previous entry with hash %s, ksn %s.\n",
	    	            	 hash_str.data, ksn_str.data);
		    kstr_free(&hash_str);
		    kstr_free(&ksn_str);
		}
	    }
	    
	    /* Error. */
	    else if (error == -1) break;
	    
	    /* Not found. */
	    else {
	    	assert(error == -2);
		break;
	    }
	}
	
	/* The mail has been found. */
	assert(error == 0);
	
	/* If the signature is valid, obtain the subscriber name. */
	if (prev->status == 1) {
	    maildb_sender_info sender_info;
	    maildb_init_sender_info(&sender_info);
	    error = maildb_get_sender_info(kc->mail_db, &sender_info, prev->mid);
	      
	    if (! error) {
	    	if (! state->subscriber_name)
		    state->subscriber_name = kstr_new();
		        
		kstr_assign_kstr(state->subscriber_name, &sender_info.name);
	    }
	    
	    maildb_free_sender_info(&sender_info);
	    
	    /* Not found? Shouldn't happen. */
	    if (error == -2) {
		kmo_seterror("cannot find sender info");
		error = -1;
		break;
    	    }
	    
	    /* Shouldn't happen either. */
	    else if (error) break;
	}
	
    } while (0);
    
    /* Unexpected DB error. Complain and continue. */
    if (error == -1) {
    	kmod_log_msg(1, "Maildb error while finding mail: %s\n", kmo_strerror()); 
    }
    
    /* No valid entry, forget we asked. */
    if (error) {
    	maildb_free_mail_info(prev);
    	free(prev);
	state->prev_mail_info = NULL;
	return;
    }
    
    /* Extract as much stuff as we can. */
    
    /* We don't need the signature message since we'll regenerate it. */
    
    /* Copy the hash if it's available and we don't have it yet. */
    if (state->mail_info->hash.slen == 0 && prev->hash.slen > 0) {
    	assert(prev->status == 0 || prev->status == 1);
    	kstr_assign_kstr(&state->mail_info->hash, &prev->hash);
    }
    
    /* The KSN and member ID should not be obtained from the DB if we could not
     * extract them (that case should never happen however).
     */
    
    /* Use the previous display preference if requested. */
    if (state->use_prev_display_pref &&
        (state->mail_info->status == 0 || state->mail_info->status == 1) &&
	(prev->status == 0 || prev->status == 1)) {
	
	state->mail_info->display_pref = prev->display_pref;
    }
    
    /* Copy some of the fields associated to a valid signature if the current 
     * mail seems to have a valid signature.
     */
    if (state->mail_info->status == 1 && prev->status == 1) {
	kmod_check_otut_info_integrity(prev);
	
	state->mail_info->field_status = prev->field_status;
	state->mail_info->att_plugin_nbr = prev->att_plugin_nbr;
	state->mail_info->attachment_nbr = prev->attachment_nbr;
	kstr_assign_kstr(&state->mail_info->attachment_status, &prev->attachment_status);
	state->mail_info->sym_key.slen = prev->sym_key.slen;
	state->mail_info->encryption_status = prev->encryption_status;
	state->mail_info->otut_status = prev->otut_status;
	
	if (state->mail_info->otut_status != KMO_OTUT_STATUS_NONE) {
	    kstr_assign_kstr(&state->mail_info->otut_string, &prev->otut_string);
	    kstr_assign_kstr(&state->mail_info->otut_msg, &prev->otut_msg);
	}
    }
    
    /* If a decryption key has been proven to work in the past, it is saved in
     * the DB. We must keep this key even if the mail status switches from valid
     * signature to invalid signature (to recover from errors).
     */
    if (prev->sym_key.slen > 0) {
    	kstr_assign_kstr(&state->mail_info->sym_key, &prev->sym_key);
    }
}

/* This function extracts the signature text and the key ID from the mail
 * bodies, if possible. Then, it tries to create the signature object and to
 * extract the KSN from it.
 * This function sets the KMO error string. It returns -1, -2 or -3.
 */
static int kmod_eval_get_sig_info(struct kmod_context *kc, struct kmod_eval_state *state) {
    int error = 0;
    char *ksn_packet = NULL;
    kstr *body;
    size_t size;
    
    kmod_log_msg(2, "kmod_eval_get_sig_info() called.\n");
    
    /* Extract the signature text from the body. */    
    if (state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT ||
        state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT_N_HTML) {
    	
	body = &state->orig_mail->body.text;
    }
    
    else {
    	body = &state->orig_mail->body.html;
    }
    
    state->sig_text = kstr_new();
    error = mail_get_signature(body, state->sig_text);
    
    if (error) {
    	kstr_destroy(state->sig_text);
	state->sig_text = NULL;
    	return -1;
    }
    
    /* Create the signature object. */
    state->sig_obj = (struct kmod_crypt_sig *) kmo_malloc(sizeof(struct kmod_crypt_sig));
    error = kmod_sig_init(state->sig_obj, state->sig_text->data, state->sig_text->slen);
    
    /* On generic error, just return -1. The caller will deal with that. */
    if (error == -1) {
    	free(state->sig_obj);
	state->sig_obj = NULL;
	return -1;
    }
    
    /* If the plugin is too old, tell it to upgrade. */
    else if (error == -2) {
    	free(state->sig_obj);
	state->sig_obj = NULL;
    	k3p_write_inst(&kc->k3p, KMO_MUST_UPGRADE);
	k3p_write_uint32(&kc->k3p, KMO_UPGRADE_SIG);
	return k3p_send_data(&kc->k3p) ? -3 : -2;
    }
    
    else assert(error == 0);
    
    /* Extract the signature key ID. */
    state->mail_info->mid = kmod_sig_get_mid(state->sig_obj);
   
    /* Extract the KSN. */
    error = kmod_sig_get_ksn(state->sig_obj, &ksn_packet, &size);
    if (error) return -1;
    
    kstr_assign_buf(&state->mail_info->ksn, ksn_packet, size);
    
    /* Verify that the signature has either a text or HTML body. KMO Crypt doesn't do that. */
    if (! kmod_sig_contain(state->sig_obj, KMO_SP_TYPE_PLAIN) &&
        ! kmod_sig_contain(state->sig_obj, KMO_SP_TYPE_HTML)) {
	
	kmo_seterror("no text or HTML subpacket found");
	return -1;
    }
    
    /* Get the KPG address and port, if any. */
    if (kmod_sig_contain(state->sig_obj, KMO_SP_TYPE_KPG)) {
	kmocrypt_get_kpg_host2(state->sig_obj->obj2, &state->mail_info->kpg_addr, &state->mail_info->kpg_port);
    }
    
    /* KPG kludge. */
    if (state->mail_info->kpg_addr.slen) {
	kmod_enable_kpg(kc, &state->mail_info->kpg_addr, state->mail_info->kpg_port);
    }
	    
    return 0;
}

/* This function evaluates a message, either for kmod_eval_incoming() or for
 * kmod_process_incoming().
 * This function sets the KMO error string. It returns 0, -2, or -3.
 */
static int kmod_eval_msg(struct kmod_context *kc, struct kmod_eval_state *state) {
    int error = 0;
    int k3p_mail_status;
    kstr *text_body = NULL;
    kstr *html_body = NULL;
    
    kmod_log_msg(2, "kmod_eval_msg() called.\n");
    
    /* Verify that the mail has a msg ID. */
    if (! state->orig_mail->msg_id.slen) {
    	kmod_log_msg(1, "Invalid request: mail has no message ID.\n");
    	kmod_handle_invalid_request(&kc->k3p);
	return -3;
    }
    
    /* Verify that the mail has a text and/or HTML body. */
    if (state->orig_mail->body.type != K3P_MAIL_BODY_TYPE_TEXT &&
	state->orig_mail->body.type != K3P_MAIL_BODY_TYPE_HTML &&
	state->orig_mail->body.type != K3P_MAIL_BODY_TYPE_TEXT_N_HTML) {
    	
	kmod_log_msg(1, "Invalid request: mail has an invalid body type (%x).\n", state->orig_mail->body.type);
    	kmod_handle_invalid_request(&kc->k3p);
	return -3;
    }
    
    /* Fetch the attachments. This should not fail. */
    assert(state->recv_att_array == NULL);
    state->recv_att_array = karray_new();
    error = kmod_fetch_attachment(state->orig_mail, state->recv_att_array, 1);
    assert(error == 0);
   
    /* Try to fill up 'mail_info' while updating the state. */
    state->mail_info = (maildb_mail_info *) kmo_malloc(sizeof(maildb_mail_info));
    maildb_init_mail_info(state->mail_info);
    
    /* Set the message ID. */
    kstr_assign_kstr(&state->mail_info->msg_id, &state->orig_mail->msg_id);
    
    /* Check if the mail is a Kryptiva mail. */
    if (state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT ||
	state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT_N_HTML) {
	text_body = &state->orig_mail->body.text;
    }

    if (state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_HTML ||
	state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT_N_HTML) {
	html_body = &state->orig_mail->body.html;
    }
    
    k3p_mail_status = mail_get_mail_status(text_body, html_body);
    
    /* This is an unsigned mail. We're done. */
    if (k3p_mail_status == 2) {
    	state->mail_info->status = 3;
	return 0;
    }
    
    /* Assume that this is a Kryptiva mail with a valid signature. */
    state->mail_info->status = 1;
    
    /* Set the display preference. */
    state->mail_info->display_pref = k3p_mail_status;
    
    /* Assume that there is no OTUT. */
    state->mail_info->otut_status = KMO_OTUT_STATUS_NONE;
    
    do {
	/* Try to get the signature info. */
	error = kmod_eval_get_sig_info(kc, state);

	/* On generic error, remember that the signature is invalid, but keep going. */
	if (error == -1) {
	    state->mail_info->status = 0;
	    kstr_assign_kstr(&state->mail_info->sig_msg, kmo_kstrerror());
	}
	
	/* If the signature cannot be handled, stop. */
	else if (error == -2) {
	    break;
	}
	
	else assert(error == 0);

	/* Get the previous information from the DB, if it's available. */
	kmod_eval_get_prev_mail_info(kc, state);
	
	/* If we don't have the hash of the mail yet, obtain it. */
	kmod_eval_compute_hash(state);
	
	/* At this point, we have the hash, the KSN if it exists and the
	 * previous mail information, if it exists. That's all we need if the
	 * signature is wrong.
	 */
	if (state->mail_info->status == 0) {
	    /* Unfortunate back-and-forth string copies here... */
	    kstr_assign_kstr(kmo_kstrerror(), &state->mail_info->sig_msg);
	    error = -1;
	    break;
	}
	
	/* We did not verify the signature yet. If we have a previous mail_info
	 * entry and it says that the signature is good, don't try to verify it
	 * (we might not be able to if the key is expired). Otherwise, try to
	 * validate that signature again, since this is necessary to recover
	 * from errors.
	 */
	if (! state->prev_mail_info || state->prev_mail_info->status != 1) {
	    
	    /* If the signature is wrong or an error occurred, we're done. */
	    error = kmod_eval_verify_sig(kc, state);
	    if (error) break;
	}
	
	/* At this point the subscriber name should be set. */
	assert(state->subscriber_name);

	/* Remove the signature from the bodies. */
	error = kmod_eval_remove_sig(state);
	if (error) break;
	
	/* Same as above: verify the fields unless:
	 * 
	 * 1) We have a previous mail_info entry that says that they're computed
	 *    and that says that the critical fields have not been modified.
	 * 
	 * 2) The number of attachments provided by the plugin did not change
	 *    since the last time.
	 */
	if (! state->prev_mail_info || state->prev_mail_info->status != 1 ||
	    ! kmod_has_valid_critical_field(state->mail_info) ||
	    state->prev_mail_info->att_plugin_nbr != (uint32_t) state->recv_att_array->size) {
	    
	    kmod_eval_check_field(state);
	}
	
	/* Set the original packaging and the encryption and PoD statuses.
	 * The original packaging might be overriden later if a previous mail_info
	 * entry was found.
	 */
	state->mail_info->original_packaging = KMO_SIGNED_MASK;
	state->mail_info->encryption_status = KMO_DECRYPTION_STATUS_NONE;
	state->mail_info->pod_status = KMO_POD_STATUS_NONE;
	
	/* The mail is encrypted (combination of encryption key / password / PoD).
	 * We validate the encryption and update the encryption status.
	 */
    	if (state->sig_obj->pkg_type != KMO_P_TYPE_SIGN) {
    	    error = kmod_eval_check_encryption(kc, state);
	    if (error) break;
	}
	
	/* The mail requires a PoD. */
	if (state->sig_obj->pkg_type & KMO_P_TYPE_POD) {
	    kmod_eval_check_pod(state);
	}

	/* If we have a previous mail info object and its status says we had a valid signature,
	 * copy its original packaging value in 'mail_info'.
	 */
    	if (state->prev_mail_info && state->prev_mail_info->status == 1) {
	    state->mail_info->original_packaging = state->prev_mail_info->original_packaging;
	}
	
    } while (0);
    
    /* If an unreported miscellaneous error occurred, then we consider that the
     * signature is not valid.
     */
    if (error == -1) {
	state->mail_info->status = 0;
	kstr_assign_kstr(&state->mail_info->sig_msg, kmo_kstrerror());
	error = 0;
    }
    
    /* Notice that if error == -2 or error == -3, then the info obtained is NOT
     * consistent. This is deliberate: don't use it!
     */
    return error;
}
 
/* This function sends the processed mail to the plugin.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_process_send_mail(struct kmod_context *kc, struct kmod_eval_state *state) {
    int error = 0;
    int i;
    struct kmod_mail mail;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_process_send_mail() called.\n");
    
    k3p_init_mail(&mail);

    if (state->text_body != NULL) {
    	kstr_assign_kstr(&mail.body.text, state->text_body);
    	mail.body.type = K3P_MAIL_BODY_TYPE_TEXT;
    }

    if (state->html_body != NULL) {
    	kstr_assign_kstr(&mail.body.html, state->html_body);
    	mail.body.type = K3P_MAIL_BODY_TYPE_HTML;
    }

    if (state->text_body != NULL && state->html_body != NULL) {
	mail.body.type = K3P_MAIL_BODY_TYPE_TEXT_N_HTML;
    }

    assert(mail.body.type != 0);

    for (i = 0; i < state->decrypted_att_array->size; i++) {
	struct kmod_attachment *att = (struct kmod_attachment *) state->decrypted_att_array->data[i];
	struct kmod_mail_attachment *mail_att = (struct kmod_mail_attachment *)
	    	    	    	    	    	kmo_malloc(sizeof(struct kmod_mail_attachment));
	k3p_init_mail_attachment(mail_att);
	karray_add(&mail.attachments, mail_att);
	
	assert(att->tie != 0);
	mail_att->tie = att->tie;
	mail_att->data_is_file_path = kc->mua.incoming_attachment_is_file_path;
	kstr_assign_kstr(&mail_att->data, att->data);
	kstr_assign_kstr(&mail_att->name, att->name);
	kstr_assign_kstr(&mail_att->encoding, att->encoding);
	kstr_assign_kstr(&mail_att->mime_type, att->mime_type);
	
	/* Save memory. */
	kstr_destroy(att->data);
	att->data = NULL;
    }
    
    kmod_mail_info_2_kmod_otut(state->mail_info, &mail.otut);

    k3p_write_inst(k3p, KMO_PROCESS_ACK);
    k3p_write_mail(k3p, &mail);
    
    if (state->want_dec_email) {
	if (state->dec_email) k3p_write_kstr(k3p, state->dec_email);
	else k3p_write_cstr(k3p, "");
    }
    
    error = k3p_send_data(k3p);
    
    k3p_free_mail(&mail);
    return error;
}

/* This function extracts the bodies and attachments from the decrypted message
 * blob.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_process_extract_field(struct kmod_context *kc, struct kmod_eval_state *state) {
    int error = 0;
    int next_file_id = 0;
    uint64_t magic;
    kbuffer msg;
    
    kmod_log_msg(2, "kmod_process_extract_field() called.\n");
    
    /* Create a buffer to hold the decrypted message blob. */
    kbuffer_init(&msg, state->text_body->slen);
    kbuffer_write(&msg, state->text_body->data, state->text_body->slen);
    
    /* Free the text body. */
    state->text_body_status = KMOD_BODY_NONE;
    kstr_destroy(state->text_body);
    state->text_body = NULL;
    
    /* Flush the magic numbers. This should not fail since we've done it before. */
    knp_msg_read_uint64(&msg, &magic);
    knp_msg_read_uint64(&msg, &magic);
    
    /* Read the entries in the blob. */
    while (msg.pos != msg.len) {
    	
	/* Identify the part to read. */
	uint32_t part;
	
	error = knp_msg_read_uint32(&msg, &part);
	if (error) break;
    	
	/* Bodies. */
	if (part == KNP_MAIL_PART_TEXT_BODY || part == KNP_MAIL_PART_HTML_BODY) {
	    
	    /* Ignore encoding, mime type and name. */
    	    error = knp_msg_read_kstr(&msg, &state->str);
	    if (error) break;

	    error = knp_msg_read_kstr(&msg, &state->str);
	    if (error) break;

	    error = knp_msg_read_kstr(&msg, &state->str);
	    if (error) break;
	    
	    if (part == KNP_MAIL_PART_TEXT_BODY) {

		if (state->text_body != NULL) {
	    	    kmo_seterror("unexpected second encrypted text body");
		    error = -1;
		    break;
		}

		state->text_body_status = KMOD_BODY_EXTRACTED;
		state->text_body = kstr_new();
		error = knp_msg_read_kstr(&msg, state->text_body);
    	    	if (error) break;
	    }
	    
	    else {
		if (state->html_body != NULL) {
	    	    kmo_seterror("unexpected second encrypted HTML body");
		    error = -1;
		    break;
		}

		state->html_body_status = KMOD_BODY_EXTRACTED;
		state->html_body = kstr_new();
		error = knp_msg_read_kstr(&msg, state->html_body);
    	    	if (error) break;
	    }
	}
	
	/* Attachments. */
	else if (part == KNP_MAIL_PART_IMPLICIT || part == KNP_MAIL_PART_EXPLICIT || part == KNP_MAIL_PART_UNKNOWN) {
	    struct kmod_attachment *att = (struct kmod_attachment *) kmo_calloc(sizeof(struct kmod_attachment));
	    
	    switch (part) {
	    	case KNP_MAIL_PART_IMPLICIT: att->tie = K3P_MAIL_ATTACHMENT_IMPLICIT; break;
		case KNP_MAIL_PART_EXPLICIT: att->tie = K3P_MAIL_ATTACHMENT_EXPLICIT; break;
		case KNP_MAIL_PART_UNKNOWN: att->tie = K3P_MAIL_ATTACHMENT_UNKNOWN; break;
		default: assert(0); 
	    }
	    
	    /* Store the attachment. */
	    karray_add(state->decrypted_att_array, att);
	    
	    /* Read the data. */
	    att->encoding = kstr_new();
	    error = knp_msg_read_kstr(&msg, att->encoding);
	    if (error) break;
    	    
	    att->mime_type = kstr_new();
	    error = knp_msg_read_kstr(&msg, att->mime_type);
	    if (error) break;
    	    
	    att->name = kstr_new();
	    error = knp_msg_read_kstr(&msg, att->name);
	    if (error) break;
    	    
	    att->data = kstr_new();
	    error = knp_msg_read_kstr(&msg, att->data);
	    if (error) break;
	    
	    /* Validate the attachment name. */
	    if (! kmod_is_valid_attachment_name(att->name)) {
	    	error = -1;
		break;
	    }
	    
	    /* Write the attachment in a file if requested. */
	    if (kc->mua.incoming_attachment_is_file_path) {
	    	FILE *file = NULL;
		int file_id;
		
		/* Try to find a non-existing directory name. */
		while (1) {
		    file_id = next_file_id;
		    next_file_id++;
		    kstr_sf(&state->str, "%s/incoming/file_%d", kc->teambox_dir_path.data, file_id);
		    
		    /* We found it. Create the directory. */
		    if (! util_check_dir_exist(state->str.data)) {
			error = util_create_dir(state->str.data);
		    	break;
		    }
		    
		    if (next_file_id > 2000) {
		    	state->process_special_cond = KMOD_PROCESS_COND_ATT_ERROR;
		    	kmo_seterror("cannot find empty directory for attachment");
			error = -1;
			break;
		    }
		}
		
		if (error) break;
		
		/* Set the path of the file. */
		kstr_sf(&state->str, "%s/incoming/file_%d/%s", kc->teambox_dir_path.data, file_id, att->name->data);
		
		/* Try. */
		do {
	    	    error = util_open_file(&file, state->str.data, "wb");
		    if (error) break;

		    error = util_write_file(file, att->data->data, att->data->slen);
		    if (error) break;

		    error = util_close_file(&file, 0);
		    if (error) break;

		} while (0);
		
	    
	    	/* Close the file silently, if required. */
	    	util_close_file(&file, 1);
		
		/* Set the path to the directory containing the file. */
		kstr_shrink(att->data, 1024);
		kstr_sf(att->data, "%s/incoming/file_%d", kc->teambox_dir_path.data, file_id);
		
		/* File errors are transient. */
		if (error) {
		    state->process_special_cond = KMOD_PROCESS_COND_ATT_ERROR;
		    break;
		}
	    }
	}
	
	/* Oops. */
	else {
	    kmo_seterror("invalid decrypted message part identifier (%x)", part);
	    error = -1;
	    break;
	}
    }
    
    /* Clean up. */
    kbuffer_clean(&msg);
    
    /* No error so far, verify that we got either a text body or an HTML body. */
    if (! error && state->text_body == NULL && state->html_body == NULL) {
	kmo_seterror("found no text or HTML body in decrypted message");
	error = -1;
    }
    
    return error;
}

/* This function does the query to obtain the symmetric key.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int kmod_process_do_sym_key_query(struct kmod_context *kc, int contact,
    	    	    	    	    	 struct kmod_eval_state *state, struct kmod_mail_process_req *req) {
    int error = 0;
    int login_type = (contact == (int) KNP_CONTACT_KPS) ? KNP_CMD_LOGIN_USER : KNP_CMD_LOGIN_ANON;
    int convert_flag = 0;
    int half_decrypted_flag = 0;
    struct knp_query *query = NULL;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_process_do_sym_key_query() called.\n");
    
    kbuffer_clear(&state->payload);
    knp_msg_write_kstr(&state->payload, state->sig_text);
    knp_msg_write_kstr(&state->payload, state->sig_key_tm_data);
    knp_msg_write_kstr(&state->payload, state->sig_key_data);
    knp_msg_write_kstr(&state->payload, state->inter_sym_key_data);
    knp_msg_write_kstr(&state->payload, &req->decryption_pwd);
    knp_msg_write_kstr(&state->payload, &req->recipient_mail_address);
    knp_msg_write_kstr(&state->payload, &state->orig_mail->subject);
    if (state->want_dec_email) knp_msg_write_uint32(&state->payload, 1);

    query = knp_query_new(contact, login_type, KNP_CMD_DEC_SYM_KEY, &state->payload);
    
    /* Try. */
    do {
	error = knp_query_exec(query, &kc->knp);
	if (error) break;

	if (query->res_type == KNP_RES_SERV_ERROR) {
	    error = kmod_handle_server_error(k3p, query);
	    break;
	}
	
	if (query->res_type == KNP_RES_UPGRADE_PLUGIN || query->res_type == KNP_RES_UPGRADE_KPS) {
	    error = kmod_handle_incomp_version(k3p, query);
	    break;
	}

	if (query->res_type == KNP_RES_LOGIN_ERROR) {
    	    error = (kmod_handle_invalid_config(k3p) == -1) ? -3 : -2;
	    break;
	}
	
	/* The key is half decrypted. The only case where this should happen
	 * is when the mail is encrypted without a password, PoD is required
	 * and the server contacted was the KPS.
	 */
	if (query->res_type == KNP_RES_DEC_KEY_HALF) {
	    
	    /* Context OK for this result type. */
	    if (state->sig_obj->pkg_type == KMO_P_TYPE_PODNENC &&
	    	req->decryption_pwd.slen == 0 &&
		contact == (int) KNP_CONTACT_KPS) {
		
		/* Get the intermediate key data. */
		error = knp_msg_read_kstr(query->res_payload, state->inter_sym_key_data);
		if (error) { convert_flag = 1; break; }
		
		/* We do the connection at the end of the function, so that the
		 * current query gets destroyed. It is important not to keep a
		 * lingering connection, in particular it causes problems if we
		 * contact the same single-threaded server for debugging.
		 */
		half_decrypted_flag = 1;
		break;
	    }
	    
	    /* Convert this to a server error. */
	    kmo_seterror("unexpected half-decrypted symmetric key");
	    convert_flag = 1;
	    break;
	}
	
	/* The user entered a bad password. This is a transient error. */
    	if (query->res_type == KNP_RES_DEC_KEY_BAD_PWD) {
	    state->process_special_cond = KMOD_PROCESS_COND_BAD_PWD;
	    kmo_seterror("you provided a bad password");
	    error = -1;
	    break;
	}
	
	/* The server cannot deliver the PoD. This is a permanent error. */
	if (query->res_type == KNP_RES_DEC_KEY_POD_ERROR) {
	    state->process_special_cond = KMOD_PROCESS_COND_POD_ERROR;
	    kmo_seterror("the PoD cannot be delivered");
	    error = -1;
	    break;
	}
	
	/* The user is not authorized to decrypt the mail. This is a permanent error. */
	if (query->res_type == KNP_RES_DEC_KEY_NOT_AUTH) {
	    state->process_special_cond = KMOD_PROCESS_COND_NOT_AUTH;
	    kmo_seterror("you are not authorized to decrypt the mail");
	    error = -1;
	    break;
	}
	
	/* The server cannot/refuse to decrypt the mail for some unspecified reason.
	 * This is a permanent error.
	 */
	if (query->res_type == KNP_RES_FAIL) {
	    kmo_seterror("the server refuses to decrypt the mail");
	    error = -1;
	    break;
	}
		
	/* Convert this to a server error. */
	if (query->res_type != KNP_RES_DEC_KEY_FULL) {
	    kmod_handle_failed_query(query, "cannot obtain decryption key");
	    convert_flag = 1;
	    break;
	}
	
    	/* Get the fully decrypted symmetric key. */
	assert(state->sym_key_data == NULL);
	state->sym_key_data = kstr_new();	
    	error = knp_msg_read_kstr(query->res_payload, state->sym_key_data);
	
	if (error) {
	    kstr_destroy(state->sym_key_data);
	    state->sym_key_data = NULL;
	    convert_flag = 1;
	    break;
	}
    	
	/* Get the OTUT string, if any. */
	error = knp_msg_read_kstr(query->res_payload, &state->str);
	if (error) { convert_flag = 1; break; }
	
	/* If there is an OTUT string, validate it. */
	if (state->str.slen && ! kmod_is_valid_otut_string(&state->str)) {
	    kmo_seterror("the server returned an invalid reply token: %s", kmo_strerror());
	    convert_flag = 1;
	    break;
	}
	
	/* Flush the previous OTUT info, if any. */
	state->mail_info->otut_status = KMO_OTUT_STATUS_NONE;
	kstr_clear(&state->mail_info->otut_string);
	kstr_clear(&state->mail_info->otut_msg);
	
	/* If there is an OTUT string, the OTUT becomes usable. */
	if (state->str.slen) {
	    state->mail_info->otut_status = KMO_OTUT_STATUS_USABLE;
	    state->mail_info->original_packaging |= KMO_CONTAINED_OTUT_MASK;
	    kstr_assign_kstr(&state->mail_info->otut_string, &state->str);
	}
	
	/* Read the PoD date, if any. */
	error = knp_msg_read_uint32(query->res_payload, &state->pod_date);
	if (error) { convert_flag = 1; break; }
	
	/* Read the decryption ticket, if there is one. */
	state->dec_email = kstr_new();
	
	if (knp_msg_read_kstr(query->res_payload, state->dec_email)) {
	    kstr_destroy(state->dec_email);
	    state->dec_email = NULL;
	}
    
    } while (0);
    
    /* Convert the error to a server error. */
    if (convert_flag) {
    	error = kmod_convert_to_serv_error(k3p, query);
    }
    
    /* Destroy the current query. */
    knp_query_destroy(query);
    
    /* Ask the OUS to complete the job. */
    if (half_decrypted_flag)
    {
    	assert(! error && ! convert_flag);
	error = kmod_process_do_sym_key_query(kc, KNP_CONTACT_OUS, state, req);
    }
    
    return error;
}

/* This function obtains the symmetric key required to decrypt the mail from
 * the KPS or the OUS.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int kmod_process_get_sym_key(struct kmod_context *kc,
    	    	    	    	    struct kmod_eval_state *state, struct kmod_mail_process_req *req) {
    int error = 0;
    int contact;
    
    kmod_log_msg(2, "kmod_process_get_sym_key() called.\n");
    
    /* Don't fetch the key if we already have it. */
    if (state->sym_key_data) return 0;

    /* The KPS/OUS needs the identity key. Fetch it if we don't have it. */
    error = kmod_eval_do_sig_key_query(kc, state);
    if (error) return error;

    /* Create the intermediate symmetric key data. It is empty initially. */
    assert(state->inter_sym_key_data == NULL);
    state->inter_sym_key_data = kstr_new();

    /* Encryption only. Contact the OUS to decrypt with the password, or contact
     * the KPS to decrypt with the private encryption key.
     */
    if (state->sig_obj->pkg_type == KMO_P_TYPE_ENC)
    	contact = (req->decryption_pwd.slen != 0) ? KNP_CONTACT_OUS : KNP_CONTACT_KPS;

    /* PoD only. Contact the OUS to decrypt with the private signature key. */
    else if (state->sig_obj->pkg_type == KMO_P_TYPE_POD)
    	contact = KNP_CONTACT_OUS;

    /* Encrypt and PoD. */
    else {
    	assert(state->sig_obj->pkg_type == KMO_P_TYPE_PODNENC);

	/* Contact the OUS to decrypt with the password and the private 
	 * signature key.
	 */
	if (req->decryption_pwd.slen != 0)
	    contact = KNP_CONTACT_OUS;

	/* Contact the KPS to decrypt with the private encryption key, then perhaps
	 * contact the OUS to decrypt with the private signature key.
	 */
	else
	    contact = KNP_CONTACT_KPS;
    }

    /* Do the query. */
    return kmod_process_do_sym_key_query(kc, contact, state, req);
}

/* This function decrypts the mail and extracts the packaged fields contained
 * within.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int kmod_process_decrypt_mail(struct kmod_context *kc,
    	    	    	    	     struct kmod_eval_state *state, struct kmod_mail_process_req *req) {
    int error = 0;
    
    kmod_log_msg(2, "kmod_process_decrypt_mail() called.\n");
    
    assert(state->text_body_status == KMOD_BODY_DECODED || state->text_body_status == KMOD_BODY_DECRYPTED);
    
    /* If we do not have the decrypted message blob yet, obtain the symmetric
     * key from the KPS/OUS and decrypt the blob.
     */
    if (state->text_body_status == KMOD_BODY_DECODED) {
    	assert(state->mail_info->encryption_status == KMO_DECRYPTION_STATUS_ENCRYPTED ||
	       state->mail_info->encryption_status == KMO_DECRYPTION_STATUS_ENCRYPTED_WITH_PWD ||
	       state->mail_info->pod_status == KMO_POD_STATUS_UNDELIVERED);
    	
	/* Get the symmetric key. */
	error = kmod_process_get_sym_key(kc, state, req);
	if (error) return error;
	
	/* Try to decrypt. */
	error = kmod_eval_decrypt_body(state);
	if (error) return error;
    }

    assert(state->text_body_status == KMOD_BODY_DECRYPTED);
    
    /* The decrypted blob contains the packaged mail bodies and attachements.
     * Extract them.
     */
    error = kmod_process_extract_field(kc, state);
    if (error) return error;
    
    return 0;
}

/* This function processes an incoming message (decrypt or remove signature).
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_process_incoming(struct kmod_context *kc, struct kmod_mail_process_req *req, int want_dec_email) {
    int error = 0;
    struct kmod_eval_state state;
    kstr error_msg;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_process_incoming() called.\n");

    /* Initialize the eval state and the error string */
    kmod_eval_init(&state, &req->mail);
    state.use_prev_display_pref = 1;
    kstr_init(&error_msg);
    if (want_dec_email) state.want_dec_email = 1;
    
    kmod_log_msg(3, "kmod_process_incoming: want_dec_email is %d.\n", want_dec_email);
    
    /* Create the decrypted attachment array. */
    state.decrypted_att_array = karray_new();
    
    /* Try. */
    do {
    	/* Evaluate the message. After this call, 'mail_info' can be written
	 * safely to the DB.
	 */
    	error = kmod_eval_msg(kc, &state);
	if (error) break;
	
	/* Check if the mail is sane enough to be processed. */
	if (! kmod_can_process_mail(state.mail_info)) {
	    error = -1;
	    break;
	}
	
	/* If the mail must be decrypted or acknowledged and the plugin did not
	 * ask for it, refuse to process the mail.
	 */
    	if ((state.mail_info->encryption_status == KMO_DECRYPTION_STATUS_ENCRYPTED ||
	     state.mail_info->encryption_status == KMO_DECRYPTION_STATUS_ENCRYPTED_WITH_PWD) &&
	    ! req->decrypt) {
	    kmo_seterror("decryption required but not requested");
	    error = -1;
	    break;
	}
	
	if (state.mail_info->pod_status == KMO_POD_STATUS_UNDELIVERED && ! req->ack_pod) {
	    kmo_seterror("PoD acknowledgement required but not requested");
	    error = -1;
	    break;
	}
	
	/* If the mail requires a password and none was provided, refuse to
	 * process the mail.
	 */
	if (state.mail_info->encryption_status == KMO_DECRYPTION_STATUS_ENCRYPTED_WITH_PWD &&
	    req->decryption_pwd.slen == 0) {
	    kmo_seterror("password required but none provided");
	    error = -1;
	    break;
	}
	
	/* If the mail does not require a password and one was provide, refuse
	 * to process the mail.
	 */
	if (state.mail_info->encryption_status != KMO_DECRYPTION_STATUS_ENCRYPTED_WITH_PWD &&
	    req->decryption_pwd.slen != 0) {
	    kmo_seterror("superfluous password provided");
	    error = -1;
	    break;
	}
	
	/* Decrypt the mail if the mail is encrypted or requires a PoD. */
	if (state.sig_obj->pkg_type != KMO_P_TYPE_SIGN) {
	
	    error = kmod_process_decrypt_mail(kc, &state, req);
	    
	    /* Transient bad password / attachment error. Deal with that below. */
	    if (state.process_special_cond == KMOD_PROCESS_COND_BAD_PWD ||
	    	state.process_special_cond == KMOD_PROCESS_COND_ATT_ERROR) {
	    	assert(error == -1);
		break;
	    }
	    
	    /* No error occurred. Update the encryption status and the PoD
	     * status as needed.
	     */
	    else if (error == 0) {
		
	    	if (state.mail_info->encryption_status == KMO_DECRYPTION_STATUS_ENCRYPTED ||
	     	    state.mail_info->encryption_status == KMO_DECRYPTION_STATUS_ENCRYPTED_WITH_PWD) {
		    
		    state.mail_info->encryption_status = KMO_DECRYPTION_STATUS_DECRYPTED;
		}
		
		if (state.mail_info->pod_status == KMO_POD_STATUS_UNDELIVERED) {
		
		    state.mail_info->pod_status = KMO_POD_STATUS_DELIVERED;
		    format_gmtime(state.pod_date, &state.mail_info->pod_msg);
		}
	    }
	    
	    /* If another miscellaneous error occurred, then the mail cannot be decrypted,
	     * permanently. Update 'mail_info' to remember that fact and tell the plugin
	     * that we cannot process the mail.
	     */
	    else if (error == -1) {
	    	
		/* PoD only error. */
		if (state.sig_obj->pkg_type == KMO_P_TYPE_POD) {
		    state.mail_info->pod_status = KMO_POD_STATUS_ERROR;
		    kstr_assign_kstr(&state.mail_info->pod_msg, kmo_kstrerror());
		}
		
		/* Encryption error. */
		else {
		    state.mail_info->encryption_status = KMO_DECRYPTION_STATUS_ERROR;
		    kstr_assign_kstr(&state.mail_info->decryption_error_msg, kmo_kstrerror());
		}
		
	    	kmo_seterror("decryption error");
		break;
	    }
	    
	    /* Other transient errors bubble up. */
	    if (error) break;
	}
    
    } while (0);
    
    if (error == 0 || error == -1) {
    
    	/* Remember the error message, if any. */ 
    	kstr_assign_kstr(&error_msg, kmo_kstrerror());
	
	/* Try. */
	do {
	    /* The mail status is valid and must be written in the database. */
    	    if (kmod_eval_write_maildb_info(kc, &state)) {
	    	error = -1;
		break;
	    }
	    
	    /* Save the password in the database if requested. */
	    if (error == 0 && req->decryption_pwd.slen != 0 && req->save_pwd && state.mail_info->status == 1 &&
		state.mail_info->encryption_status == KMO_DECRYPTION_STATUS_DECRYPTED) {
		
		/* Ignore failure. */
	    	maildb_set_pwd(kc->mail_db, &state.orig_mail->from_addr, &req->decryption_pwd);
	    }
	    
	    /* If no error occurred yet, send the mail to the plugin. */
	    if (error == 0) {
	    	error = kmod_process_send_mail(kc, &state);
	    }
	    
	    /* Otherwise, tell the plugin that we could not process the mail. */
	    else {
	    	int nack_type = 0;
		
		switch (state.process_special_cond) {
		    case KMOD_PROCESS_COND_NONE:
		    case KMOD_PROCESS_COND_ATT_ERROR: nack_type = KMO_PROCESS_NACK_MISC_ERROR; break;
		    case KMOD_PROCESS_COND_POD_ERROR: nack_type = KMO_PROCESS_NACK_POD_ERROR; break;
		    case KMOD_PROCESS_COND_BAD_PWD: nack_type = KMO_PROCESS_NACK_PWD_ERROR; break;
		    case KMOD_PROCESS_COND_NOT_AUTH: nack_type = KMO_PROCESS_NACK_DECRYPT_PERM_FAIL; break;
		    default: assert(0);
		}
		
	    	k3p_write_inst(k3p, KMO_PROCESS_NACK);
		k3p_write_uint32(k3p, nack_type);
		k3p_write_kstr(k3p, &error_msg);
		
		if (k3p_send_data(k3p)) {
    	    	    error = -1;
		    break;
    	    	}
		
		/* The error was handled correctly. */
		error = 0;
    	    }
    	
	} while (0);
	
	/* If we fail here, KMO has failed, don't attempt to recover. */
    }
    
    /* An error occurred and it was reported successfully, keep interacting. */
    else if (error == -2) {
    	error = 0;
    }
    
    /* An error occurred and it was not reported successfully, stop interacting. */
    else {
    	assert(error == -3);
	error = -1;
    }
    
    /* Free the eval state and the error string. */
    kmod_eval_free(&state);
    kstr_free(&error_msg);
 
    return error;
}
                          
/* This function evaluates an incoming message.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_eval_incoming(struct kmod_context *kc, struct kmod_mail *orig_mail) {
    int error = 0;
    struct kmod_eval_state state;
    k3p_proto *k3p = &kc->k3p;

    /* Initialize the eval state. */
    kmod_eval_init(&state, orig_mail);
    
    kmod_log_msg(2, "kmod_eval_incoming() called.\n");
   
    /* Evaluate the message. */
    error = kmod_eval_msg(kc, &state);

    if (error == 0) {
    	struct kmod_eval_res eval_res;
	k3p_init_eval_res(&eval_res);
	    
	/* Try. */
    	do {
	    /* Store the information in the database. */
	    error = kmod_eval_write_maildb_info(kc, &state);
	    if (error) break;
	    
	    /* Send the evaluation result to the plugin. */
	    k3p_write_inst(k3p, KMO_EVAL_STATUS);
	    
	    /* The mail is an unsigned mail. */
	    if (state.mail_info->status == 3) {
	    	k3p_write_uint32(k3p, 2);
	    }

	    /* The mail is a Kryptiva mail. */
	    else {
		kmod_mail_info_2_eval_res(state.mail_info, state.subscriber_name, state.default_pwd, &eval_res);
		k3p_write_uint32(k3p, 1);
		k3p_write_eval_res(k3p, &eval_res);
    	    }
	    
	    error = k3p_send_data(k3p);
	    if (error) break;
	    
	} while (0);
	
	k3p_free_eval_res(&eval_res);
	
	/* If we fail here, KMO has failed, don't attempt to recover. */
    }
    
    /* An error occurred and it was reported successfully, keep interacting. */
    else if (error == -2) {
    	error = 0;
    }
    
    /* An error occurred and it was not reported successfully, stop interacting. */
    else {
    	assert(error == -3);
	error = -1;
    }

    /* Free the eval state. */
    kmod_eval_free(&state);
   
    return error;
}

/* This function remembers that the mails specified by the plugin are not
 * Kryptiva mails.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_mark_unsigned_mail(struct kmod_context *kc) {
    int error = 0;
    int i;
    uint32_t nb_mail;
    k3p_proto *k3p = &kc->k3p;
    maildb_mail_info mail_info;
    
    kmod_log_msg(2, "kmod_mark_unsigned_mail() called.\n");
    
    maildb_init_mail_info(&mail_info);
    mail_info.status = 3;
    
    /* Try. */
    do {    
	/* Get the number of IDs to mark. */
	error = k3p_read_uint32(k3p, &nb_mail);
	if (error) break;

	/* Get the IDs and set their statuses in the DB. */
	for (i = 0; i < (int) nb_mail; i++) {
	    error = k3p_read_kstr(k3p, &mail_info.msg_id);
	    if (error) break;
	    
	    if (mail_info.msg_id.slen == 0) {
	    	kmo_seterror("empty message ID");
		error = -1;
		break;
	    }
	    
	    error = maildb_set_mail_info(kc->mail_db, &mail_info);
	    if (error) break;
	}
	
	if (error) break;
	
	/* Tell the plugin that we did it. */
	k3p_write_inst(k3p, KMO_MARK_UNSIGNED_MAIL);
    	error = k3p_send_data(k3p);
	if (error) break;
	
    } while (0);

    maildb_free_mail_info(&mail_info);
    
    return error;
}

/* This function sets the display preference of a Kryptiva mail.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_set_display_pref(struct kmod_context *kc) {
    int error = 0;
    uint32_t display_pref;
    kstr msg_id;
    maildb_mail_info mail_info;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_set_display_pref() called.\n");
    
    kstr_init(&msg_id);
    maildb_init_mail_info(&mail_info);
    
    /* Try. */
    do {
    	/* Get the message ID. */
	error = k3p_read_kstr(k3p, &msg_id);
	if (error) break;
	
	if (msg_id.slen == 0) {
	    kmo_seterror("empty message ID");
	    error = -1;
	    break;
	}
	
	/* Get the display pref. */
	error = k3p_read_uint32(k3p, &display_pref);
    	if (error) break;
	
	/* Make sure display_pref is one of 0, 1 or 2. */ 
	if (display_pref != 0 && display_pref != 1 && display_pref != 2) {	
    	    kmod_log_msg(1, "Invalid request: bad display pref value (%d).\n", display_pref);
	    error = kmod_handle_invalid_request(k3p);
	    break;
	}
	
	/* Get the mail info corresponding to the message ID. */
    	error = maildb_get_mail_info_from_msg_id(kc->mail_db, &mail_info, &msg_id);
	if (error == -1) break;
	
	/* No such mail. */
	if (error == -2) {
	    kmod_log_msg(1, "kmod_set_display_pref(): message ID %s not found.\n", msg_id.data);
	    k3p_write_inst(k3p, KMO_SET_DISPLAY_PREF_NACK);
	    error = 0;
	}
	
	/* We got the mail. */
	else {
	    assert(error == 0);
	    
	    /* Not a Kryptiva mail. */
	    if (mail_info.status != 0 && mail_info.status != 1) {
	    	kmod_log_msg(1, "kmod_set_display_pref(): message ID %s is not a Kryptiva mail.\n", msg_id.data);
		k3p_write_inst(k3p, KMO_SET_DISPLAY_PREF_NACK);
	    	error = 0;
	    }
	    
	    /* Very well, change the status. */
	    else {
	    	mail_info.display_pref = display_pref;
		error = maildb_set_mail_info(kc->mail_db, &mail_info);
		if (error) break;
		
		k3p_write_inst(k3p, KMO_SET_DISPLAY_PREF_ACK);
	    }
	}
	
	/* Send the data. */
	error = k3p_send_data(k3p);
	if (error) break;
    
    } while (0);
    
    maildb_free_mail_info(&mail_info);
    kstr_free(&msg_id);
    
    return error;
}

/* This function sends the status of the mail specified to the plugin.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_get_eval_status_send_status(struct kmod_context *kc, maildb_mail_info *mail_info,
    	    	    	    	    	    maildb_sender_info *sender_info, int full_flag) {
    int error = 0;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_get_eval_status_send_status() called.\n");    
    
    /* The status of the mail is unknown. */
    if (mail_info == NULL || mail_info->status == 2) {
    	k3p_write_uint32(k3p, 0);
    }
    
    /* The mail is not a Kryptiva mail. */
    else if (mail_info->status == 3) {
    	k3p_write_uint32(k3p, 2);
    }
    
    /* The mail is a known Kryptiva mail. */
    else {
    	assert(mail_info->status == 0 || mail_info->status == 1);
	assert(sender_info);
    	
	struct kmod_eval_res eval_res;
	k3p_init_eval_res(&eval_res);
	
	kmod_check_otut_info_integrity(mail_info);
	
	/* Try. */
	do {
	    /* Full status. */
	    if (full_flag) {
	    
		/* Tell the plugin that this is a Kryptiva mail. */
		k3p_write_uint32(k3p, 1);

		/* Fill up 'eval_res'. We cannot get passwords from the database here,
		 * since we don't have the from address.
		 */
		kmod_mail_info_2_eval_res(mail_info, &sender_info->name, NULL, &eval_res);
	    
		/* Send 'eval_res' to the plugin. */
		k3p_write_eval_res(k3p, &eval_res);
	    }
	    
	    /* String status. */
	    else {
	    	int string_status = kmod_get_mail_info_string_status(mail_info);
		k3p_write_uint32(k3p, string_status);
		if (string_status == 5 || string_status == 6) k3p_write_kstr(k3p, &sender_info->name);
	    }
	    
	} while (0);
	
	k3p_free_eval_res(&eval_res);
    }
    
    return error;
}

/* This function evaluates the status of messages and returns the results
 * to the plugin (either the complete statuses or just the "string" statuses).
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_get_eval_status(struct kmod_context *kc, int full_flag) {
    int eval_cnt;
    int error = 0;
    int i;
    k3p_proto *k3p = &kc->k3p;
    karray id_array;
    maildb_mail_info mail_info;
    maildb_sender_info sender_info;
    
    kmod_log_msg(2, "kmod_get_eval_status() called.\n");
    
    karray_init(&id_array);
    maildb_init_mail_info(&mail_info);
    maildb_init_sender_info(&sender_info);

    /* Try. */
    do {
    	/* Get the number of IDs to receive. */
    	error = k3p_read_uint32(k3p, (uint32_t *) &eval_cnt);
	if (error) break;
	
	/* Get these IDs. */    
	for (i = 0; i < eval_cnt; i++) {
	    kstr *str = kstr_new();

	    error = k3p_read_kstr(k3p, str);

	    if (error) {
		kstr_destroy(str);
		break;
	    }
	    
	    if (str->slen == 0) {
	    	kmo_seterror("empty message ID");
		error = -1;
		break;
	    }

	    karray_add(&id_array, str);
	}

	if (error) break;
	
	/* Write back the evaluation results. */
	k3p_write_inst(k3p, full_flag ? KMO_EVAL_STATUS : KMO_STRING_STATUS);
	
	for (i = 0; i < eval_cnt; i++) {
	    kstr *id_str = (kstr *) id_array.data[i];
   
	    /* Get the information from the database. */
	    maildb_clear_sender_info(&sender_info);
	    error = maildb_get_mail_info_from_msg_id(kc->mail_db, &mail_info, id_str);
	    
	    /* Get the server info if required and if no error occurred. */
	    if (! error && mail_info.status == 1) {
	    	error = maildb_get_sender_info(kc->mail_db, &sender_info, mail_info.mid);
		
		/* Not found? Shouldn't happen. */
		if (error == -2) {
		    kmo_seterror("cannot find sender info");
		    error = -1;
		}
		
		assert(error == 0 || error == -1);
	    }
	    
	    /* An error occurred. Log the error. Pretend the information is not there. */
	    if (error == -1) {
	    	kmod_log_msg(1, "Maildb error while finding mail: %s\n", kmo_strerror()); 
		error = kmod_get_eval_status_send_status(kc, NULL, NULL, full_flag);
		if (error) break;
	    }

	    /* The information is not in the database.*/
	    else if (error == -2) {
	    	error = kmod_get_eval_status_send_status(kc, NULL, NULL, full_flag);
		if (error) break;
	    }

	    /* The information is in the database.*/
	    else {
	    	assert(error == 0);
		error = kmod_get_eval_status_send_status(kc, &mail_info, &sender_info, full_flag);
		if (error) break;		
	    }
	}
	
	if (error) break;
	
	error = k3p_send_data(k3p);
	if (error) break;
	
    } while (0);
    
    maildb_free_sender_info(&sender_info);
    maildb_free_mail_info(&mail_info);
    
    for (i = 0; i < id_array.size; i++)
    	kstr_destroy((kstr *) id_array.data[i]);
    
    karray_free(&id_array);

    return error;
}


/* Info about a mail recipient in kmod_package(). */
struct kmod_pkg_rec {
    
    /* Address of the recipient. */
    kstr *addr;

    /* True if the recipient has been referenced by the plugin (see below). */
    int ref_flag;
    
    /* The server to contact to query the address of this recipient.
     * This field is only meaningful when the mail must be encrypted.
     */
    int contact;
    
    /* True if the recipient has an encryption key. Otherwise it's a password.
     * This field is only meaningful when the mail must be encrypted.
     */
    int key_flag;

    /* If the recipient has an encryption key, the data associated to the
     * encryption key.
     */
    kstr *key;

    /* If the recipient has a password, here it is. */
    kstr *pwd;

    /* Number of OTUTs to assign to the recipient. */
    int give_otut;

    /* True if the plugin wants us to remember the password. */
    int save_pwd;
};

/* Info about passwords required for encryption in kmod_package(). */
struct kmod_pkg_pwd {

    /* Password. Memory not owned by this object. */
    kstr *pwd;

    /* Number of replies to assign to the password. */
    int nb_reply;

    /* OTUT string associated to the password. */
    kstr *otut;
};

/* Info about the internal state of kmod_package(). */
struct kmod_pkg_state {
    
    /* K3P requested packaging type. */
    uint32_t pack_type;
    
    /* Mail to package. Memory not owned by this object. */
    struct kmod_mail *orig_mail;
    
    /* Number of passwords required for encryption. */
    int nb_pwd_needed;
    
    /* Number of OTUT replies required for encryption. */
    int nb_otut_reply;
    
    /* Total number of recipients. */
    int nb_rec;
    
    /* Recipient info array. */
    struct kmod_pkg_rec *rec_array;
    
    /* Password info array. */
    karray pwd_array;
    
    /* Hash mapping password strings to password info.
     * Memory not owned by this object.
     */
    khash pwd_hash;
    
    /* Attachment array. */
    karray *att_array;
    
    /* OTUT mail. */
    maildb_mail_info *otut_mail;
    
    /* OTUT ticket. */
    kstr *otut_ticket;
    
    /* Server package query output. */
    kstr *pkg_output;
    
    /* KSN of the packaged mail. */
    kstr *pkg_ksn;
    
    /* Symmetric key that was used to encrypt the mail. */
    kstr *pkg_key;
    
    /* Initialized scratch payload. */
    kbuffer payload;
    
    /* Initialized scratch string. */
    kstr str;
};

/* This function initializes the kmod_pkg_state object. */
static void kmod_package_init(struct kmod_pkg_state *state, uint32_t pack_type, struct kmod_mail *orig_mail) {
    memset(state, 0, sizeof(struct kmod_pkg_state));
    state->pack_type = pack_type;
    state->orig_mail = orig_mail;
    karray_init(&state->pwd_array);
    khash_init_func(&state->pwd_hash, khash_cstr_key, khash_cstr_cmp);
    kbuffer_init(&state->payload, 200);
    kstr_init(&state->str);
}

/* This function frees the kmod_pkg_state object. */
static void kmod_package_free(struct kmod_pkg_state *state) {
    int i;
    
    for (i = 0; i < state->nb_rec; i++) {
    	struct kmod_pkg_rec *rec = &state->rec_array[i];
	kstr_destroy(rec->addr);
	kstr_destroy(rec->key);
	kstr_destroy(rec->pwd);
    }
    
    free(state->rec_array);
    
    for (i = 0; i < state->pwd_array.size; i++) {
    	struct kmod_pkg_pwd *pkg_pwd = (struct kmod_pkg_pwd *) state->pwd_array.data[i];
	kstr_destroy(pkg_pwd->otut);
    	free(pkg_pwd);
    }
    
    karray_free(&state->pwd_array);
    khash_free(&state->pwd_hash); 
    kmod_free_attachment_array(state->att_array);
    kstr_destroy(state->otut_ticket);
    maildb_free_mail_info(state->otut_mail);
    free(state->otut_mail);
    kstr_destroy(state->pkg_output);
    kstr_destroy(state->pkg_ksn);
    kstr_destroy(state->pkg_key);
    kbuffer_clean(&state->payload);
    kstr_free(&state->str);
}

/* This function sends the packaging output to the plugin.
 * This function sets the KMO error string. It returns 0 or -3.
 */
static int kmod_pkg_send_pkg_output(k3p_proto *k3p, struct kmod_pkg_state *state) {
    int error = 0;
    struct kmod_mail_body body;
    k3p_init_mail_body(&body);
    
    kmod_log_msg(2, "kmod_pkg_send_pkg_output() called.\n");
    
    /* Try. */
    do {
	/* If it's a signature, put the signature in both mail bodies. */
	if (state->pack_type == KPP_SIGN_MAIL) {
	    body.type = state->orig_mail->body.type;

	    if (state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT ||
		state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT_N_HTML) {

		mail_build_signed_text_body(state->pack_type, &state->orig_mail->body.text,
		    	    	    	    state->pkg_output, &body.text);
	    }

	    if (state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_HTML ||
		state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT_N_HTML) {

		mail_build_signed_html_body(state->pack_type, &state->orig_mail->body.html,
		    	    	    	    state->pkg_output, &body.html);
	    }
	}

	/* It's a full encrypted body. */
	else {
    	    body.type = K3P_MAIL_BODY_TYPE_TEXT;
	    mail_build_encrypted_body(state->pack_type, state->pkg_output, &body.text);
	}
	
	/* Finally, send the output to the plugin. */
	k3p_write_inst(k3p, KMO_PACK_ACK);
	k3p_write_mail_body(k3p, &body);
	
	if (k3p_send_data(k3p)) {
	    error = -3;
	    break;
	}
	
    } while (0);

    k3p_free_mail_body(&body);
    
    return error;
}

/* This function records the symmetric key that was used to encrypt the mail in
 * the database.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_pkg_write_sym_key(struct kmod_context *kc, struct kmod_pkg_state *state) {
    assert(state->pkg_ksn != NULL);
    assert(state->pkg_key != NULL);
    
    kmod_log_msg(2, "kmod_pkg_write_sym_key() called.\n");
    
    int error = 0;
    maildb_mail_info mail_info;
    maildb_init_mail_info(&mail_info);

    /* Try. */
    do {
    	mail_info.status = 2;
	kstr_assign_kstr(&mail_info.ksn, state->pkg_ksn);
	kstr_assign_kstr(&mail_info.sym_key, state->pkg_key);
	error = maildb_set_mail_info(kc->mail_db, &mail_info);
	if (error) break;
	
    } while (0);
    
    maildb_free_mail_info(&mail_info);
    
    return error;
}

/* This function does the query to obtain the packaging output.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int kmod_pkg_do_output_query(struct kmod_context *kc, struct kmod_pkg_state *state) {
    int error = 0;
    int convert_flag = 0;
    uint32_t login_type = state->otut_mail ? KNP_CMD_LOGIN_OTUT : KNP_CMD_LOGIN_USER;
    struct knp_query *query = NULL;
    k3p_proto *k3p = &kc->k3p;
    int contact = k3p_is_a_member(&kc->server_info) ? KNP_CONTACT_KPS : KNP_CONTACT_OPS;
   
    kmod_log_msg(2, "kmod_pkg_do_output_query() called.\n");
    
    /* Contact the KPS or the OPS to package the mail. */
    query = knp_query_new(contact, login_type, KNP_CMD_PACKAGE_MAIL, &state->payload);
    
    if (login_type == KNP_CMD_LOGIN_OTUT) {
    	query->login_otut = kstr_new();
	kstr_assign_kstr(query->login_otut, &state->otut_mail->otut_string);
    }
    
    /* Try. */
    do {
    	error = knp_query_exec(query, &kc->knp);
	if (error) break;
	
	if (query->res_type == KNP_RES_SERV_ERROR) {
	    error = kmod_handle_server_error(k3p, query);
	    break;
	}
	
	if (query->res_type == KNP_RES_UPGRADE_PLUGIN || query->res_type == KNP_RES_UPGRADE_KPS) {
	    error = kmod_handle_incomp_version(k3p, query);
	    break;
	}
	
	if (query->res_type == KNP_RES_LOGIN_ERROR) {
	    
	    /* Bad OTUT. */
	    if (login_type == KNP_CMD_LOGIN_OTUT) {
	    	
		/* Update the status of the OTUT mail in the database. */
		state->otut_mail->otut_status = KMO_OTUT_STATUS_ERROR;
		kstr_assign_cstr(&state->otut_mail->otut_msg, "server refused token");
		error = maildb_set_mail_info(kc->mail_db, state->otut_mail);
		
		/* We can't handle DB errors. */
		if (error) { error = -3; break; }
		
		kmo_seterror("the server refused the reply token");
		error = -1;
		break;
	    }
	    
	    /* Invalid configuration. */
	    else {
	    	error = (kmod_handle_invalid_config(k3p) == -1) ? -3 : -2;
		break;
	    }
    	}
	
	if (query->res_type == KNP_RES_FAIL) {
	    kmo_seterror("the server refused to package your mail");
	    error = -1;
	    break;
	}
	
	if (query->res_type == KNP_RES_PACKAGE_FAIL) {
	    error = knp_msg_read_kstr(query->res_payload, &state->str);
	    if (error) { convert_flag = 1; break; }
	    kmo_seterror("the server refused to package your mail: %s", state->str.data);
	    error = -1;
	    break;
	}

	if (query->res_type != KNP_RES_PACKAGE_MAIL) {
	    kmod_handle_failed_query(query, "cannot package the mail");
	    error = -1;
	    break;
	}
	
	/* Get the packaging output. */
	state->pkg_output = kstr_new();
	error = knp_msg_read_kstr(query->res_payload, state->pkg_output);
	if (error) { convert_flag = 1; break; }
	
	/* Get the KSN. */
	state->pkg_ksn = kstr_new();
	error = knp_msg_read_kstr(query->res_payload, state->pkg_ksn);
	if (error) { convert_flag = 1; break; }
	
	if (state->pkg_ksn->slen != 24) {
	    kmo_seterror("invalid KSN size (received %d, expected 24)", state->pkg_ksn->slen);
	    error = -1;
	    convert_flag = 1;
	    break;
	}
	
	/* Get the symmetric key. */
	state->pkg_key = kstr_new();
	error = knp_msg_read_kstr(query->res_payload, state->pkg_key);
	if (error) { convert_flag = 1; break; }
	
	/* We used the OTUT. */
	if (login_type == KNP_CMD_LOGIN_OTUT) {
	    
	    /* Update the status of the OTUT mail in the database. */
	    state->otut_mail->otut_status = KMO_OTUT_STATUS_USED;
	    format_time(time(NULL), &state->otut_mail->otut_msg);
	    error = maildb_set_mail_info(kc->mail_db, state->otut_mail);
	    
	    /* We can't handle DB errors. */
	    if (error) { error = -3; break; }
	}
	
    } while (0);
    
    /* Convert the error to a server error. */
    if (convert_flag) {
    	error = kmod_convert_to_serv_error(k3p, query);
    }
    
    knp_query_destroy(query);
    return error;
}

/* This function asks the server for the packaging output.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int kmod_pkg_get_pkg_output(struct kmod_context *kc, struct kmod_pkg_state *state) {
    int i;
    uint32_t pkg_type = 0;
    kstr stripped_html_body;
    
    kmod_log_msg(2, "kmod_pkg_get_pkg_output() called.\n");
    
    /* Build the message payload. */
    kbuffer_clear(&state->payload);
    
    switch (state->pack_type) {
    	case KPP_SIGN_MAIL:
	    pkg_type = 0;
	    break;
	    
    	case KPP_SIGN_N_ENCRYPT_MAIL:
	    pkg_type = KNP_PKG_TYPE_ENC;
	    break;
	
	case KPP_SIGN_N_POD_MAIL:
	    pkg_type = KNP_PKG_TYPE_POD;
	    break;
	
	case KPP_SIGN_N_ENCRYPT_N_POD_MAIL:
	    pkg_type = KNP_PKG_TYPE_ENC | KNP_PKG_TYPE_POD;
	    break;
	
	default: assert(0);
    };
    
    knp_msg_write_uint32(&state->payload, pkg_type);
    knp_msg_write_uint32(&state->payload, kc->mua.lang);
    
    /* The TO and CC strings need to be cleaned up. */
    kstr_assign_kstr(&state->str, &state->orig_mail->to);
    kmod_cleanup_signable_to_cc(&state->str);
    knp_msg_write_kstr(&state->payload, &state->str);
    
    kstr_assign_kstr(&state->str, &state->orig_mail->cc);
    kmod_cleanup_signable_to_cc(&state->str);
    knp_msg_write_kstr(&state->payload, &state->str);
    
    knp_msg_write_uint32(&state->payload, state->nb_rec);
    
    for (i = 0; i < state->nb_rec; i++) {
    	struct kmod_pkg_rec *rec = &state->rec_array[i];
	
	knp_msg_write_kstr(&state->payload, rec->addr);
	
	if (pkg_type & KNP_PKG_TYPE_ENC) {
	    if (rec->key_flag) {
	    	knp_msg_write_uint32(&state->payload, KNP_PKG_ENC_KEY);
		knp_msg_write_kstr(&state->payload, rec->key);
	    }
	    
	    else {
	    	knp_msg_write_uint32(&state->payload, KNP_PKG_ENC_PWD);
		knp_msg_write_cstr(&state->payload, "");
	    }
	}
	
	else {
	    knp_msg_write_uint32(&state->payload, 0);
	    knp_msg_write_cstr(&state->payload, "");
	}
    }
    
    knp_msg_write_uint32(&state->payload, state->pwd_array.size);
    
    for (i = 0; i < state->pwd_array.size; i++) {
    	struct kmod_pkg_pwd *pkg_pwd = (struct kmod_pkg_pwd *) state->pwd_array.data[i];
    	knp_msg_write_kstr(&state->payload, pkg_pwd->pwd);
	
	if (pkg_pwd->otut)
	    knp_msg_write_kstr(&state->payload, pkg_pwd->otut);
	else
	    knp_msg_write_cstr(&state->payload, "");
    }
    
    knp_msg_write_kstr(&state->payload, &state->orig_mail->from_name);
    knp_msg_write_kstr(&state->payload, &state->orig_mail->from_addr);
    knp_msg_write_kstr(&state->payload, &state->orig_mail->subject);
    
    /* If the mail contains an HTML body, strip the HTML body of its unwanted
     * data. 
     */
    if (state->orig_mail->body.type != K3P_MAIL_BODY_TYPE_TEXT) {
    	kstr_assign_kstr(&state->str, &state->orig_mail->body.html);
	kstr_init(&stripped_html_body);
	mail_get_signable_html_body(&state->str, &stripped_html_body);
	mail_put_space_before_body_end(&stripped_html_body);
	mail_repair_outlook_html_damage(&stripped_html_body);
    }
    
    /* Write the bodies. */
    if (state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT) {
    	knp_msg_write_uint32(&state->payload, KNP_PKG_BODY_TEXT);
	knp_msg_write_kstr(&state->payload, &state->orig_mail->body.text);
	knp_msg_write_cstr(&state->payload, "");
    }
    
    else if (state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_HTML) {
    	knp_msg_write_uint32(&state->payload, KNP_PKG_BODY_HTML);
	knp_msg_write_cstr(&state->payload, "");
	knp_msg_write_kstr(&state->payload, &stripped_html_body);
    }
    
    else {
    	assert(state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT_N_HTML);
    	knp_msg_write_uint32(&state->payload, KNP_PKG_BODY_BOTH);
	knp_msg_write_kstr(&state->payload, &state->orig_mail->body.text);
	knp_msg_write_kstr(&state->payload, &stripped_html_body);
    }
    
    #ifdef BODY_CHANGED_DEBUG
    {
    	kstr str;
	kstr_init(&str);
	
	if (state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT ||
	    state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT_N_HTML)
	{
	    kstr_assign_kstr(&str, &state->orig_mail->body.text);
	    kmod_trim_whitespace(&str);
	    fprintf(kmod_log, "SENDING: dumping signed text body:\n");
    	    util_dump_buf_ascii(str.data, str.slen, kmod_log);
    	    fprintf(kmod_log, "END END END.\n\n");
	}
	
	if (state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_HTML ||
	    state->orig_mail->body.type == K3P_MAIL_BODY_TYPE_TEXT_N_HTML)
	{
	    kstr_assign_kstr(&str, &stripped_html_body);
	    kmod_trim_whitespace(&str);
	    fprintf(kmod_log, "SENDING: dumping signed HTML body:\n");
    	    util_dump_buf_ascii(str.data, str.slen, kmod_log);
    	    fprintf(kmod_log, "END END END.\n\n");
	}
	
	kstr_free(&str);
    }
    #endif
    
    if (state->orig_mail->body.type != K3P_MAIL_BODY_TYPE_TEXT) {
	kstr_free(&stripped_html_body);
    }
    
    /* Write the attachments. */
    knp_msg_write_uint32(&state->payload, state->att_array->size);
    
    for (i = 0; i < state->att_array->size; i++) {
    	struct kmod_attachment *att = (struct kmod_attachment *) state->att_array->data[i];
	int type = 0;
	
	switch (att->tie) {
	    case K3P_MAIL_ATTACHMENT_IMPLICIT: type = KNP_MAIL_PART_IMPLICIT; break;
	    case K3P_MAIL_ATTACHMENT_EXPLICIT: type = KNP_MAIL_PART_EXPLICIT; break;
	    case K3P_MAIL_ATTACHMENT_UNKNOWN: type = KNP_MAIL_PART_UNKNOWN; break;
	    default: assert(0);
	}
	
	knp_msg_write_uint32(&state->payload, type);
	knp_msg_write_kstr(&state->payload, att->encoding);
	knp_msg_write_kstr(&state->payload, att->mime_type);
	knp_msg_write_kstr(&state->payload, att->name);
	knp_msg_write_kstr(&state->payload, att->data);
	
	/* Flush the data to save memory. */
	kstr_destroy(att->data);
	att->data = NULL;
    }
    
    /* Write the PoD return address if required. */
    if (pkg_type & KNP_PKG_TYPE_POD) {
    	
	/* Use the PoD address from the server info if it's available. */
	if (kc->server_info.pod_addr.slen) {
	    knp_msg_write_kstr(&state->payload, &kc->server_info.pod_addr);
	}
	
	/* Use the "from" address. */
	else {
	    knp_msg_write_kstr(&state->payload, &state->orig_mail->from_addr);
	}
    }
    
    else {
    	knp_msg_write_cstr(&state->payload, "");
    }
    
    return kmod_pkg_do_output_query(kc, state);
}

/* This function asks the server for the OTUT strings.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int kmod_pkg_get_otut_string(struct kmod_context *kc, struct kmod_pkg_state *state) {
    int error = 0;
    int convert_flag = 0;
    int i;
    uint32_t nb;
    struct knp_query *query = NULL;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_pkg_get_otut_string() called.\n");
    
    kbuffer_clear(&state->payload);
    knp_msg_write_kstr(&state->payload, state->otut_ticket);
    knp_msg_write_uint32(&state->payload, state->pwd_array.size);
    
    for (i = 0; i < state->pwd_array.size; i++) {
    	struct kmod_pkg_pwd *pkg_pwd = (struct kmod_pkg_pwd *) state->pwd_array.data[i];
    	knp_msg_write_uint32(&state->payload, pkg_pwd->nb_reply);
    }
    
    query = knp_query_new(KNP_CONTACT_OTS, KNP_CMD_LOGIN_ANON, KNP_CMD_GET_OTUT_STRING, &state->payload);
    
    /* Try. */
    do {
	/* KPG kludge. */
	if (kc->use_kpg) {
	    kmod_enable_kpg(kc, &kc->kpg_addr, kc->kpg_port);
	}
    
    	error = knp_query_exec(query, &kc->knp);
	if (error) break;
	
	if (query->res_type == KNP_RES_SERV_ERROR) {
	    error = kmod_handle_server_error(k3p, query);
	    break;
	}
	
	if (query->res_type == KNP_RES_UPGRADE_PLUGIN || query->res_type == KNP_RES_UPGRADE_KPS) {
	    error = kmod_handle_incomp_version(k3p, query);
	    break;
	}
	
	if (query->res_type == KNP_RES_FAIL) {
    	    kmo_seterror("the server refused to supply a reply token");
	    error = -1;
	    break;
    	}

	if (query->res_type != KNP_RES_GET_OTUT_STRING) {
	    kmod_handle_failed_query(query, "cannot obtain reply token");
	    error = -1;
	    break;
	}
	
	error = knp_msg_read_uint32(query->res_payload, &nb);
	if (error) { convert_flag = 1; break; }
	
	if (nb != (uint32_t) state->pwd_array.size) {
	    kmo_seterror("cannot obtain reply token: invalid server message");
	    error = -1;
	    convert_flag = 1;
	    break;
	}
	
	for (i = 0; i < state->pwd_array.size; i++) {
	    struct kmod_pkg_pwd *pkg_pwd = (struct kmod_pkg_pwd *) state->pwd_array.data[i];
	    pkg_pwd->otut = kstr_new();
	    error = knp_msg_read_kstr(query->res_payload, pkg_pwd->otut);
	    if (error) { convert_flag = 1; break; }
	}
	
	if (error) break;
	
    } while (0);
    
    /* Convert the error to a server error. */
    if (convert_flag) {
    	error = kmod_convert_to_serv_error(k3p, query);
    }
    
    knp_query_destroy(query);
    return error;
}

/* This function asks the server for an OTUT ticket.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int kmod_pkg_get_otut_ticket(struct kmod_context *kc, struct kmod_pkg_state *state) {
    int error = 0;
    struct knp_query *query = NULL;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_pkg_get_otut_ticket() called.\n");
    
    kbuffer_clear(&state->payload);
    knp_msg_write_uint32(&state->payload, state->nb_otut_reply);
    knp_msg_write_kstr(&state->payload, &state->orig_mail->from_addr);    
    query = knp_query_new(KNP_CONTACT_KPS, KNP_CMD_LOGIN_USER, KNP_CMD_GET_OTUT_TICKET, &state->payload);
    
    /* Try. */
    do {
    	error = knp_query_exec(query, &kc->knp);
	if (error) break;
    
	if (query->res_type == KNP_RES_SERV_ERROR) {
	    error = kmod_handle_server_error(k3p, query);
	    break;
	}
	
	if (query->res_type == KNP_RES_UPGRADE_PLUGIN || query->res_type == KNP_RES_UPGRADE_KPS) {
	    error = kmod_handle_incomp_version(k3p, query);
	    break;
	}

	if (query->res_type == KNP_RES_LOGIN_ERROR) {
    	    error = (kmod_handle_invalid_config(k3p) == -1) ? -3 : -2;
	    break;
	}

	if (query->res_type == KNP_RES_FAIL) {
    	    kmo_seterror("the server refused to supply a reply token ticket");
	    error = -1;
	    break;
	}

	if (query->res_type != KNP_RES_GET_OTUT_TICKET) {
	    kmod_handle_failed_query(query, "cannot obtain reply token ticket");
	    error = -1;
	    break;
	}

    	state->otut_ticket = kstr_new();

    	if (knp_msg_read_kstr(query->res_payload, state->otut_ticket)) {
	    error = kmod_convert_to_serv_error(k3p, query);
	    break;
	}
	
    } while (0);
    
    knp_query_destroy(query);
    
    return error;
}

/* This function receives the recipient passwords from the plugin.
 * This function sets the KMO error string. It returns 0 or -3.
 */
static int kmod_pkg_recv_pwd(struct kmod_context *kc, struct kmod_pkg_state *state) {
    int error = 0;
    int i, j;
    uint32_t nb;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_pkg_recv_pwd() called.\n");
    
    error = k3p_read_uint32(k3p, &nb);
    if (error) return -3;

    if (nb != (uint32_t) state->nb_pwd_needed) {
	kmo_seterror("invalid number of passwords (%d requested, %d received)", state->nb_pwd_needed, nb);
	return -3;
    }
    
    /* Receive the password list. */
    for (i = 0; i < state->nb_pwd_needed; i++) {
	struct kmod_recipient_pwd rp;
    	k3p_init_recipient_pwd(&rp);
    	
	/* Try. */
	do {
    	    error = k3p_read_recipient_pwd(k3p, &rp);
    	    if (error) break;

	    /* Match the plugin address with our address. */
	    for (j = 0; j < state->nb_rec; j++) {
		struct kmod_pkg_rec *rec = &state->rec_array[j];

		/* We found it. */
		if (! rec->key_flag && ! rec->ref_flag && kstr_equal_kstr(rec->addr, &rp.recipient)) {
		    struct kmod_pkg_pwd *pkg_pwd; 
		    rec->ref_flag = 1;
		    rec->pwd = kstr_new();
		    kstr_assign_kstr(rec->pwd, &rp.password);
		    rec->give_otut = rp.give_otut;
		    rec->save_pwd = rp.save_pwd;

		    /* Add the password in the hash, if required, and increment
		     * the OTUT count associated to the password.
		     */
		    pkg_pwd = (struct kmod_pkg_pwd *) khash_get(&state->pwd_hash, rec->pwd->data);

		    if (pkg_pwd == NULL) {
			pkg_pwd = (struct kmod_pkg_pwd *) kmo_calloc(sizeof(struct kmod_pkg_pwd));
			pkg_pwd->pwd = rec->pwd;
			khash_add(&state->pwd_hash, rec->pwd->data, pkg_pwd);
			karray_add(&state->pwd_array, pkg_pwd);
		    }

		    pkg_pwd->nb_reply += rec->give_otut;
		    state->nb_otut_reply += rec->give_otut;

		    /* Save the password if requested. */
		    if (rec->save_pwd) {
			error = maildb_set_pwd(kc->mail_db, rec->addr, rec->pwd);
			if (error) break;
		    }

		    break;
		}
	    }

	    if (error) break;
	    
	    if (j == state->nb_rec) {
		kmo_seterror("invalid address %s in password request", rp.recipient.data);
		error = -1;
		break;
	    }
	
	} while (0);

    	k3p_free_recipient_pwd(&rp);
	if (error) return -3;
    }
    
    return 0;
}

/* This function asks the plugin for the recipient passwords
 * This function sets the KMO error string. It returns 0, -2 or -3.
 */
static int kmod_pkg_ask_pwd(struct kmod_context *kc, struct kmod_pkg_state *state) {
    int error = 0;
    int i;
    uint32_t reply;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_pkg_ask_pwd() called.\n");

    /* Tell the plugin that we want passwords. */
    k3p_write_inst(k3p, KMO_NO_RECIPIENT_PUB_KEY);
    k3p_write_uint32(k3p, state->nb_pwd_needed);

    /* Send the list of addresses requiring a password. */
    for (i = 0; i < state->nb_rec; i++) {
	struct kmod_pkg_rec *rec = &state->rec_array[i];
	
	if (! rec->key_flag) {
		
	    /* Get the default password, if any. */
	    if (maildb_get_pwd(kc->mail_db, rec->addr, &state->str)) {
		kstr_clear(&state->str);
	    }

    	    k3p_write_kstr(k3p, rec->addr);
	    k3p_write_kstr(k3p, &state->str);
	    k3p_write_uint32(k3p, 0);
	    k3p_write_uint32(k3p, 0);
	}
    }
    
    if (k3p_send_data(k3p)) return -3;

    /* Wait for the reply. It can take a long time. */
    k3p->timeout_enabled = 0;
    error = k3p_read_inst(k3p, &reply);
    k3p->timeout_enabled = 1;
    
    if (error) return -3;

    /* We can read the passwords. */
    if (reply == KPP_USE_PWDS) {
    	return kmod_pkg_recv_pwd(kc, state);
    }
    
    /* The user wishes to abort. End the session. */
    else if (reply == KPP_END_SESSION) {
	k3p->state = K3P_ACTIVE;
	return -2;
    }

    /* Oops.*/
    else {
    	kmod_log_msg(1, "Invalid request: unexpected instruction (%x) while waiting for password.\n", reply);
	kmod_handle_invalid_request(k3p);
	return -3;
    }
}

/* This function does the query to ask the server about the recipient addresses.
 * This function sets the KMO error string. It returns 0, -2, or -3.
 */
static int kmod_pkg_do_rec_addr_query(struct kmod_context *kc, struct kmod_pkg_state *state, int contact,
                                      int input_nb) {
    int error = 0;
    int convert_flag = 0;
    int i;
    uint32_t output_nb;
    struct knp_query *query = NULL;
    
    kmod_log_msg(2, "kmod_pkg_do_rec_addr_query() called.\n");
    
    /* Ask the server about the recipient addresses. */
    kbuffer_clear(&state->payload);
    knp_msg_write_uint32(&state->payload, input_nb);
    output_nb = 0;
    
    for (i = 0; i < state->nb_rec; i++) {
    	if (contact == state->rec_array[i].contact) {
	    output_nb++;
	    
	    if (kc->enc_key_lookup_str.slen) {
		knp_msg_write_kstr(&state->payload, &kc->enc_key_lookup_str);
	    }
	    
	    else {
		knp_msg_write_kstr(&state->payload, state->rec_array[i].addr);
	    }
	}
    }
    
    assert(input_nb == (int) output_nb);
       
    query = knp_query_new(contact, KNP_CMD_LOGIN_ANON, KNP_CMD_GET_ENC_KEY, &state->payload);
    
    /* Try. */
    do {
    	error = knp_query_exec(query, &kc->knp);
	if (error) break;
	
	if (query->res_type == KNP_RES_SERV_ERROR) {
	    error = kmod_handle_server_error(&kc->k3p, query);
	    break;
	}
	
	if (query->res_type == KNP_RES_UPGRADE_PLUGIN || query->res_type == KNP_RES_UPGRADE_KPS) {
	    error = kmod_handle_incomp_version(&kc->k3p, query);
	    break;
	}

	if (query->res_type != KNP_RES_GET_ENC_KEY) {
	    kmod_handle_failed_query(query, "cannot obtain encryption key list");
	    convert_flag = 1;
	    break;
    	}

	/* Parse the reply. */
	error = knp_msg_read_uint32(query->res_payload, &output_nb);
	if (error) { convert_flag = 1; break; }

	if (output_nb != (uint32_t) input_nb) {
	    kmo_seterror("cannot obtain encryption key list: invalid server message");
	    convert_flag = 1;
	    break;  
	}
    	
	output_nb = 0;
	
	for (i = 0; i < state->nb_rec; i++) {
	    struct kmod_pkg_rec *rec = &state->rec_array[i];
	    
	    if (rec->contact != contact) {
	    	continue;
	    }
	    
	    output_nb++;
	    
	    error = knp_msg_read_kstr(query->res_payload, &state->str);
	    if (error) { convert_flag = 1; break; }

	    /* The server knows about this address. */
	    if (state->str.slen) {
		rec->key_flag = 1;
		rec->key = kstr_new();
		kstr_assign_kstr(rec->key, &state->str);
	    }

	    /* We will need a password. */
	    else {
	       state->nb_pwd_needed++;
	    }
	}
	
	if (error) break;
	assert(input_nb == (int) output_nb);
	
    } while (0);
    
    /* Convert the error to a server error. */
    if (convert_flag) {
    	error = kmod_convert_to_serv_error(&kc->k3p, query);
    }

    knp_query_destroy(query);
    return error;
}

/* This function asks the server about the recipient addresses when the mail is
 * encrypted.
 * This function sets the KMO error string. It returns 0, -1, -2, or -3.
 */
static int kmod_pkg_check_rec_addr(struct kmod_context *kc, struct kmod_pkg_state *state) {
    int nb_insider = 0;
    int nb_outsider = 0;
    int i;
    
    kmod_log_msg(2, "kmod_pkg_check_rec_addr() called.\n");
    
    /* Determine if the recipients are members of the organization of the
     * sender. The KPS is authoritative on that matter: it supplies the domain
     * names list of the addresses that belong to its organization.
     */
    for (i = 0; i < state->nb_rec; i++) {
    	char *rec_addr = state->rec_array[i].addr->data;
	
	/* Exchange addresses must be sent to the KPS. */
	if (kmod_is_exchange_addr(rec_addr) && kc->enc_key_lookup_str.slen) {
	    state->rec_array[i].contact = KNP_CONTACT_KPS;
    	    nb_insider++;
	}
	
	/* Check the domain names. */
	else if (kmod_is_addr_of_kps_domain(state->rec_array[i].addr->data, kc)) {
	    state->rec_array[i].contact = KNP_CONTACT_KPS;
	    nb_insider++;
	}
	
	/* Not an address that belongs to one of the domains of the KPS. */
	else {
	    state->rec_array[i].contact = KNP_CONTACT_EKS;
    	    nb_outsider++;
    	}
    }
    
    assert(nb_insider + nb_outsider == state->nb_rec);
    
    /* If there are some insiders, query the KPS about those addresses. */
    if (nb_insider) {
    	int error = kmod_pkg_do_rec_addr_query(kc, state, KNP_CONTACT_KPS, nb_insider); 
	if (error) return error;
    }
    
    /* If there are some outsiders, query the EKS about those addresses. */
    if (nb_outsider) {
    	int error = kmod_pkg_do_rec_addr_query(kc, state, KNP_CONTACT_EKS, nb_outsider);
	if (error) return error;
    }
    
    /* If there is an OTUT, make sure the intended recipient is still a member. */
    if (state->otut_mail) {
    	assert(state->nb_rec == 1);
	
	if (! state->rec_array[0].key_flag) {
	    kmo_seterror("the recipient is no longer subscribed to Teambox");
	    return -1;
	}
    }
    
    return 0;
}

/* This function obtains the mail matching the specified entry ID string, if possible.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_get_mail_from_entry_id_str(struct kmod_context *kc, kstr *entry_id_str,
					   maildb_mail_info **entry_id_mail) {
    int error = 0;
    *entry_id_mail = NULL;
    
    kmod_log_msg(2, "kmod_get_mail_from_entry_id_str() called.\n");
    
    /* Try. */
    do {
	char *end;
	int64_t entry_id;
	
	/* Parse the entry ID provided by the user. */
	assert(entry_id_str->slen != 0);
	entry_id = strtoll(entry_id_str->data, &end, 10);

	if (*end != 0 || entry_id <= 0) {
	    kmo_seterror("invalid entry ID (%s)", entry_id_str->data);
	    error = -1;
	    break;
	}

	/* Locate the mail, if any. */
	*entry_id_mail = (maildb_mail_info *) kmo_malloc(sizeof(maildb_mail_info));
	maildb_init_mail_info(*entry_id_mail);
	error = maildb_get_mail_info_from_entry_id(kc->mail_db, *entry_id_mail, entry_id);

	/* No such mail. */
	if (error == -2) {
	    kmo_seterror("the mail with the entry ID specified could not be found");
	    error = -1;
	    break;
	}

	/* Oops. */
	if (error) {
	    kmo_seterror("cannot obtain mail from entry ID: %s", kmo_strerror());
	    error = -1;
	    break;
	}
	
    } while (0);
    
    if (error) {
	maildb_free_mail_info(*entry_id_mail);
	*entry_id_mail = NULL;
    }
    
    return error;
}

/* This function parses the addresses of the recipients of the mail.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_pkg_parse_address(struct kmod_pkg_state *state) {
    int error = 0;
    int i;
    karray addr_array;
    karray_init(&addr_array);
    
    kmod_log_msg(2, "kmod_pkg_parse_address() called.\n");
    
    /* Try. */
    do {
	/* Parse the recipient_list field. */
	error = mail_parse_addr_field(&state->orig_mail->recipient_list, &addr_array);
    	if (error) break;
	
	/* Remember the number of recipients. */
	state->nb_rec = addr_array.size;
	
	/* Make sure we got at least one address. */
	if (state->nb_rec == 0) {
    	    kmo_seterror("no recipient addresses specified");
	    error = -1;
	    break;
	}
    	
	/* Transfer the addresses. */
	state->rec_array = (struct kmod_pkg_rec *) kmo_calloc(state->nb_rec * sizeof(struct kmod_pkg_rec));

	for (i = 0; i < state->nb_rec; i++) {
    	    state->rec_array[i].addr = (kstr *) addr_array.data[i];
	}
	
    } while (0);

    karray_free(&addr_array);
    
    return error;
}

/* This function packages a message.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_package(struct kmod_context *kc, uint32_t pack_type, struct kmod_mail *orig_mail) {
    int error = 0;
    struct kmod_pkg_state state;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_package() called.\n");
    
    /* Check if the user is trying to package a mail without authorization. */
    if (! k3p_is_a_member(&kc->server_info) &&
    	! (pack_type == KPP_SIGN_N_ENCRYPT_MAIL && kmod_is_otut_set(&orig_mail->otut))) {
    	return kmod_handle_invalid_config(k3p);
    }
    
    /* Initialize the package state. */
    kmod_package_init(&state, pack_type, orig_mail);
    
    /* Try. */
    do {
    	/* Verify that the mail has a text and/or HTML body. */
	if (orig_mail->body.type != K3P_MAIL_BODY_TYPE_TEXT &&
	    orig_mail->body.type != K3P_MAIL_BODY_TYPE_HTML &&
	    orig_mail->body.type != K3P_MAIL_BODY_TYPE_TEXT_N_HTML) {
    	    
	    kmo_seterror("invalid body type (%x)", orig_mail->body.type);
	    error = -1;
	    break;
	}

    	/* Parse the recipient addresses. */
    	error = kmod_pkg_parse_address(&state);
	if (error) break;
	
	/* Obtain the required OTUT information. */
	if (! k3p_is_a_member(&kc->server_info)) {
	    
	    /* Get the OTUT mail, if possible. */
	    error = kmod_get_mail_from_entry_id_str(kc, &orig_mail->otut.entry_id, &state.otut_mail);
	    if (error) break;
	    
	    /* Make sure the user is replying to the address specified by the
	     * plugin in the OTUT fields. We do not check if this is really the
	     * address contained in the OTUT -- the server will refuse to package
	     * the mail it doesn't like it.
	     */
	    if (state.nb_rec != 1 || strcmp(state.rec_array[0].addr->data, orig_mail->otut.reply_addr.data)) {
		kmo_seterror("you can only reply to %s", orig_mail->otut.reply_addr.data);
		error = -1;
		break;
	    }
	    
	    /* KPG kludge. */
	    if (state.otut_mail->kpg_addr.slen) {
		kmod_enable_kpg(kc, &state.otut_mail->kpg_addr, state.otut_mail->kpg_port);
	    }
	}
	
	/* Fetch the attachments. */
	state.att_array = karray_new();
	error = kmod_fetch_attachment(orig_mail, state.att_array, 0);
	if (error) break;
	
	/* Handle encryption. */
	if (pack_type == KPP_SIGN_N_ENCRYPT_MAIL || pack_type == KPP_SIGN_N_ENCRYPT_N_POD_MAIL) {
	    
	    /* Get the user info if needed. */
	    if (kc->user_mid == 0 && k3p_is_a_member(&kc->server_info)) {
		error = kmod_get_user_info(kc);
		if (error) break;
	    }

	    /* Ask the server about the recipient addresses. */
	    error = kmod_pkg_check_rec_addr(kc, &state);
	    if (error) break;
	    
	    /* Passwords are required. */
	    if (state.nb_pwd_needed) {
	    	
		/* Ask the plugin for the passwords. */
    		error = kmod_pkg_ask_pwd(kc, &state);
		if (error) break;
		
		/* OTUTs have been requested by the plugin. */
    		if (state.nb_otut_reply) {

		    /* Contact the KPS to get an OTUT ticket. */
    		    error = kmod_pkg_get_otut_ticket(kc, &state);
		    if (error) break;

		    /* Contact the OTS to get the OTUTs. */
		    error = kmod_pkg_get_otut_string(kc, &state);
		    if (error) break;
		}
	    }
	}
	
	/* Package the message on the server. */
	error = kmod_pkg_get_pkg_output(kc, &state);
	if (error) break;
	
	/* If the mail was encrypted in some way, set the key in the database. */
	if (pack_type != KPP_SIGN_MAIL) {
	
	    error = kmod_pkg_write_sym_key(kc, &state);
	    
	    /* We can't deal with errors in the DB. */    
	    if (error) { error = -3; break; }
	}
	
	/* Return the output to the plugin. */
	error = kmod_pkg_send_pkg_output(k3p, &state);
	if (error) break;

    } while (0);
    
    /* No error occurred. */
    if (error == 0) {
    	/* Void. */
    }
    
    /* Tell the plugin about the unreported miscellaneous error. */
    else if (error == -1) {
    	k3p_write_inst(k3p, KMO_PACK_NACK);
	k3p_write_uint32(k3p, KMO_PACK_EXPL_CUSTOM);
	k3p_write_kstr(k3p, kmo_kstrerror());
	k3p_write_cstr(k3p, "");
	error = k3p_send_data(k3p);
    }
    
    /* An error occurred and it was reported successfully, keep interacting. */
    else if (error == -2) {
    	error = 0;
    }
    
    /* An error occurred and it was not reported successfully, stop interacting. */
    else {
    	assert(error == -3);
	error = -1;
    }
    
    /* Free the package state. */
    kmod_package_free(&state);
    
    return error;
}

/* This function handles the email password-related requests.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_handle_email_pwd(struct kmod_context *kc, int req) {
    int error = 0;
    uint32_t i = 0;
    uint32_t nb_addr = 0;
    karray addr_array, pwd_array;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_handle_email_pwd() called for request %x.\n", req);
    
    karray_init(&addr_array);
    karray_init(&pwd_array);
    
    /* Try. */
    do {
    	if (req != KPP_GET_ALL_EMAIL_PWD) {
	
    	    /* Get the number of addresses/passwords to transfer. */
    	    error = k3p_read_uint32(k3p, &nb_addr);
    	    if (error) break;

	    /* Obtain the addresses/passwords. */
	    for (i = 0; i < nb_addr; i++) {
		kstr *str = kstr_new();
    	    	karray_add(&addr_array, str);
		error = k3p_read_kstr(k3p, str);
		if (error) break;

		if (req == KPP_SET_EMAIL_PWD) {
	    	    str = kstr_new();
		    karray_add(&pwd_array, str);
		    error = k3p_read_kstr(k3p, str);
		    if (error) break;
		}
	    }
	    
	    if (error) break;
	}
	
	/* Get all email passwords from the database. */
	if (req == KPP_GET_ALL_EMAIL_PWD) {
	    error = maildb_get_all_pwd(kc->mail_db, &addr_array, &pwd_array);
	    if (error) break;
	    
	    nb_addr = addr_array.size;
	}
	
	else {
	    for (i = 0; i < nb_addr; i++) {
	    	kstr *addr = (kstr *) addr_array.data[i];
		
		/* Get the password from the DB, if any. */
		if (req == KPP_GET_EMAIL_PWD) {
		    kstr *pwd = kstr_new();
		    karray_add(&pwd_array, pwd);
		    error = maildb_get_pwd(kc->mail_db, addr, pwd);
		    if (error == -2) error = 0;
		}
		
		/* Set the password in the DB. */
		else if (req == KPP_SET_EMAIL_PWD) {
		    kstr *pwd = (kstr *) pwd_array.data[i];
		    error = maildb_set_pwd(kc->mail_db, addr, pwd);
		}
		
		/* Remove the password from the DB. */
		else {
		    assert(req == KPP_REMOVE_EMAIL_PWD);
		    error = maildb_rm_pwd(kc->mail_db, addr);
		}
		
		if (error) break;
	    }
	    
	    if (error) break;
	}
	
	k3p_write_inst(k3p, KMO_PWD_ACK);
	
	if (req == KPP_GET_EMAIL_PWD || req == KPP_GET_ALL_EMAIL_PWD) {
	    k3p_write_uint32(k3p, nb_addr);
	    
	    for (i = 0; i < nb_addr; i++) {
	    	kstr *pwd = (kstr *) pwd_array.data[i];
		
		if (req == KPP_GET_ALL_EMAIL_PWD) {
		    kstr *addr = (kstr *) addr_array.data[i];
		    k3p_write_kstr(k3p, addr);
		}
		
		k3p_write_kstr(k3p, pwd);
	    }
	}
	
	error = k3p_send_data(k3p);
	if (error) break;
    
    } while (0);
    
    kmo_clear_kstr_array(&addr_array);
    karray_free(&addr_array);
    kmo_clear_kstr_array(&pwd_array);
    karray_free(&pwd_array);
    
    return error;
}

static int handle_open_kappsd_session(struct kmod_context *kc) {
    int error = 0;
    k3p_proto *k3p = &kc->k3p;
    kstr addr;
    kstr_init(&addr);
    
    do {
	error = k3p_read_kstr(k3p, &addr);
	if (error) break;
    
	error = kmod_open_kappsd_session(addr.data, 3000);

	if (error) {
	    k3p_write_inst(k3p, 1);
	    k3p_write_kstr(k3p, kmo_kstrerror());
	}
	
	else {
	    k3p_write_inst(k3p, 0);
	}
	
	error = k3p_send_data(k3p);
	if (error) break;
	
    } while (0);
    
    kstr_free(&addr);
    
    return error;
}

static int handle_close_kappsd_session(struct kmod_context *kc) {
    k3p_proto *k3p = &kc->k3p;
    kmod_close_kappsd_session();
    k3p_write_inst(k3p, 0);
    return k3p_send_data(k3p);
}

static int handle_exchange_kaapsd_message(struct kmod_context *kc) {
    int error = 0;
    int in_type = 0, out_type = 0;
    kbuffer in_buf, out_buf;
    kstr str;
    k3p_proto *k3p = &kc->k3p;

    kbuffer_init(&in_buf, 0);
    kbuffer_init(&out_buf, 0);
    kstr_init(&str);

    /* This code makes me cry. */
    do {
	while (1) {
	    struct k3p_element *el = NULL;

	    /* Read more elements, if needed. */
	    if (k3p->element_array_pos == k3p->element_array.size) {
		k3p->element_array_pos = k3p->element_array.size = 0;
		error = k3p_receive_element(k3p);
		if (error) break;
	    }

	    el = (struct k3p_element *) k3p->element_array.data[k3p->element_array_pos];

	    /* Stop on instruction. */
	    if (el->type == K3P_EL_INS) {
		int i;
		error = k3p_read_inst(k3p, &i);
		break;
	    }

	    else if (el->type == K3P_EL_INT) {
		uint32_t i;
		error = k3p_read_uint32(k3p, &i);
		if (error) break;
		link_msg_write_uint32(&in_buf, i);
	    }

	    else {
		error = k3p_read_kstr(k3p, &str);
		if (error) break;
		link_msg_write_kstr(&in_buf, &str);
	    }
	}

	if (error) break;

	if (kmod_exchange_kappsd_message(in_type, &in_buf, &out_type, &out_buf)) {
	    k3p_write_inst(k3p, 1);
	    k3p_write_kstr(k3p, kmo_kstrerror());
	}

	else {
	    k3p_write_inst(k3p, 0);

	    while (out_buf.pos != out_buf.len) {
	    
		if (out_buf.data[out_buf.pos] == KNP_UINT32) {
		    uint32_t i;
		    error = link_msg_read_uint32(&out_buf, &i);
		    if (error) break;
		    k3p_write_uint32(k3p, i);
		}

		else {
		    error = link_msg_read_str(&out_buf, &str);
		    if (error) break;
		    k3p_write_kstr(k3p, &str);
		}
	    }

	    if (error) break;
	}

	error = k3p_send_data(k3p);
	if (error) break;

    } while (0);

    kstr_free(&str);
    kbuffer_clean(&in_buf);
    kbuffer_clean(&out_buf);

    return error;
}

/* Better late than never: this function exucutes a query and checks if a server
 * error occurred or if some component must be upgraded. It returns 1 if the
 * caller should stop processing, 0 otherwise. 'error' is updated as needed.
 */
static int kmod_exec_query(struct knp_query *query, struct kmod_context *kc, int *error) {

    *error = knp_query_exec(query, &kc->knp);
    if (*error) return 1;
	
    if (query->res_type == KNP_RES_SERV_ERROR) {
	*error = kmod_handle_server_error(&kc->k3p, query);
	return 1;
    }

    if (query->res_type == KNP_RES_UPGRADE_PLUGIN || query->res_type == KNP_RES_UPGRADE_KPS) {
	*error = kmod_handle_incomp_version(&kc->k3p, query);
	return 1;
    }

    return 0;
}

static int kmod_get_kws_ticket(struct kmod_context *kc) {
    int error = 0;
    struct knp_query *query = NULL;
    kstr ticket;
    kbuffer payload;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_get_kws_ticket() called.\n");
    
    kstr_init(&ticket);
    kbuffer_init(&payload, 10);
    
    do {
	if (! k3p_is_a_member(&kc->server_info)) {
	    error = kmod_handle_invalid_config(k3p);
	    break;
	}
	
        /* Ask the KPS for a ticket. */
	query = knp_query_new(KNP_CONTACT_KPS, KNP_CMD_LOGIN_USER, KNP_CMD_GET_KWS_TICKET, &payload);
	if (kmod_exec_query(query, kc, &error)) break;
	
	if (query->res_type != KNP_RES_GET_KWS_TICKET) {
	    kmod_handle_failed_query(query, "cannot obtain workspace ticket"); 
	    error = kmod_convert_to_serv_error(k3p, query);
	    break;
	}
	
	if (knp_msg_read_kstr(query->res_payload, &ticket)) {
	    error = kmod_convert_to_serv_error(k3p, query);
	    break;
	}
	
	k3p_write_inst(k3p, K3P_COMMAND_OK);
	k3p_write_kstr(k3p, &ticket);
	error = k3p_send_data(k3p);
	if (error) break;
    
    } while (0);
    
    kbuffer_clean(&payload);
    kstr_free(&ticket);
    knp_query_destroy(query);
    
    return error;
}

static int kmod_convert_exchange_address(struct kmod_context *kc) {
    int error = 0;
    int convert_flag = 0;
    uint32_t i, nb_addr, out_nb_addr;
    struct knp_query *query = NULL;
    kbuffer payload;
    karray in_array, out_array;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_convert_exchange_address() called.\n");
    
    kbuffer_init(&payload, 10);
    karray_init(&in_array);
    karray_init(&out_array);
    
    do {
	error = k3p_read_uint32(k3p, &nb_addr);
	if (error) break;
	
	for (i = 0; i < nb_addr; i++) {
	    kstr *addr = kstr_new();
	    karray_add(&in_array, addr);
	    error = k3p_read_kstr(k3p, addr);
	    if (error) break;
	}
	
	if (error) break;
	    
	if (! k3p_is_a_member(&kc->server_info)) {
	    error = kmod_handle_invalid_config(k3p);
	    break;
	}
	
        /* Ask the KPS to convert the addresses. */
	knp_msg_write_uint32(&payload, nb_addr);
	    
	for (i = 0; i < nb_addr; i++) {
	    knp_msg_write_kstr(&payload, in_array.data[i]);
	}
	
	query = knp_query_new(KNP_CONTACT_KPS, KNP_CMD_LOGIN_USER, KNP_CMD_CONVERT_EXCHANGE, &payload);
	if (kmod_exec_query(query, kc, &error)) break;
	
	if (query->res_type != KNP_RES_CONVERT_EXCHANGE) {
	    kmod_handle_failed_query(query, "cannot convert exchange addresses"); 
	    convert_flag = 1;
	    break;
	}
	
	error = knp_msg_read_uint32(query->res_payload, &out_nb_addr);
	if (error) { convert_flag = 1; break; }
	
	for (i = 0; i < nb_addr; i++) {
	    kstr *addr = kstr_new();
	    karray_add(&out_array, addr);
	    error = knp_msg_read_kstr(query->res_payload, addr);
	    if (error) { convert_flag = 1; break; }
	}
	
	if (error) break;
	
	k3p_write_inst(k3p, K3P_COMMAND_OK);
	k3p_write_uint32(k3p, nb_addr);
	
	for (i = 0; i < nb_addr; i++) {
	    k3p_write_kstr(k3p, out_array.data[i]);
	}
	
	error = k3p_send_data(k3p);
	if (error) break;
    
    } while (0);
    
    /* Convert the error to a server error. */
    if (convert_flag) {
    	error = kmod_convert_to_serv_error(&kc->k3p, query);
    }

    kbuffer_clean(&payload);
    knp_query_destroy(query);
    
    kmo_clear_kstr_array(&in_array);
    karray_free(&in_array);
    
    kmo_clear_kstr_array(&out_array);
    karray_free(&out_array);
    
    return error;
}


/* Information on the encryption key associated to a particular address. */
struct enc_addr_info {

    /* Address received from the plugin. */
    kstr addr;
    
    /* True if the KPS should be queried. */
    int query_kps;
    
    /* Data of the key. */
    kstr key_data;
    
    /* Public encryption key. */
    struct kmocrypt_signed_pkey *pkey;
    
    /* Key ID (0 if non-member). */
    uint64_t key_id;
    
    /* Name of the subscriber. */
    kstr subscriber_name;
};

static void enc_addr_info_init(struct enc_addr_info *self) {
    memset(self, 0, sizeof(struct enc_addr_info));
    kstr_init(&self->addr);
    kstr_init(&self->key_data);
    kstr_init(&self->subscriber_name);
}

static void enc_addr_info_clean(struct enc_addr_info *self) {
    if (self) {
	kstr_free(&self->addr);
	kstr_free(&self->key_data);
	if (self->pkey) kmocrypt_signed_pkey_destroy(self->pkey);
	kstr_free(&self->subscriber_name);
    }
}

/* Duplicated and adapted code from kmod_pkg_do_rec_addr_query(). Refactoring
 * needed obviously.
 */
static int kmod_query_enc_addr(struct kmod_context *kc, karray *enc_array, int contact) {
    int error = 0;
    int convert_flag = 0;
    uint32_t i, nb_addr, out_nb_addr;
    struct knp_query *query = NULL;
    kbuffer payload;
    
    kmod_log_msg(2, "kmod_query_enc_addr() called.\n");
    
    kbuffer_init(&payload, 10);
    
    do {
        /* Ask the KPS to convert the addresses. */
	nb_addr = enc_array->size;
	knp_msg_write_uint32(&payload, nb_addr);
	    
	for (i = 0; i < nb_addr; i++) {
	    struct enc_addr_info *info = enc_array->data[i];
	    knp_msg_write_kstr(&payload, &info->addr);
	}
	
	query = knp_query_new(contact, KNP_CMD_LOGIN_ANON, KNP_CMD_GET_ENC_KEY, &payload);
	if (kmod_exec_query(query, kc, &error)) break;
	
	if (query->res_type != KNP_RES_GET_ENC_KEY) {
	    kmod_handle_failed_query(query, "cannot obtain encryption key list");
	    convert_flag = 1;
	    break;
    	}
	
	error = knp_msg_read_uint32(query->res_payload, &out_nb_addr);
	if (error) { convert_flag = 1; break; }
	
	for (i = 0; i < nb_addr; i++) {
	    struct enc_addr_info *info = enc_array->data[i];
	    
	    error = knp_msg_read_kstr(query->res_payload, &info->key_data);
	    if (error) { convert_flag = 1; break; }
	    
	    /* The server knows about this address. Parse the key. */
	    if (info->key_data.slen) {
	    
                /* There's a bug in tbxsosd that causes it to add a bogus '0'
                 * at the end of the key data. Fixing it might break
                 * compatiblity, so I'm working around it here.
                 */
		if (! info->key_data.data[info->key_data.slen - 1]) info->key_data.slen--;
		 
		kbuffer_clear(&payload);
		kbuffer_write(&payload, info->key_data.data, info->key_data.slen);
		info->pkey = kmocrypt_sign_get_pkey(&payload);
		if (! info->pkey) { error = -1; convert_flag = 1; break; }
		
		info->key_id = info->pkey->key->mid;
	    }
	}
	
	if (error) break;
	
	error = knp_msg_read_uint32(query->res_payload, &out_nb_addr);
	if (error) { convert_flag = 1; break; }
	
	for (i = 0; i < nb_addr; i++) {
	    struct enc_addr_info *info = enc_array->data[i];
	    
	    error = knp_msg_read_kstr(query->res_payload, &info->subscriber_name);
	    if (error) { convert_flag = 1; break; }
	}
	
	if (error) break;
    
    } while (0);
    
    /* Convert the error to a server error. */
    if (convert_flag) {
    	error = kmod_convert_to_serv_error(&kc->k3p, query);
    }

    kbuffer_clean(&payload);
    knp_query_destroy(query);
    
    return error;
}

static int kmod_lookup_rec_addr(struct kmod_context *kc) {
    int error = 0;
    uint32_t i, nb_addr = 0;
    struct enc_addr_info *enc_array = NULL;
    karray kps_array;
    karray eks_array;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_lookup_rec_addr() called.\n");
    
    karray_init(&kps_array);
    karray_init(&eks_array);
    
    do {
	/* Receive the addresses. */
	error = k3p_read_uint32(k3p, &nb_addr);
	if (error) break;
	
	enc_array = kmo_calloc(nb_addr * sizeof(struct enc_addr_info));
	
	for (i = 0; i < nb_addr; i++) {
	    enc_addr_info_init(&enc_array[i]);
	}
	
	for (i = 0; i < nb_addr; i++) {
	    error = k3p_read_kstr(k3p, &enc_array[i].addr);
	    if (error) break;
	}
	
	if (error) break;
	
	/* Split the addresses in two groups, KPS-bound and EKS-bound. */
	if (! k3p_is_a_member(&kc->server_info)) {
	    error = kmod_handle_invalid_config(k3p);
	    break;
	}
	
	error = kmod_get_user_info(kc);
	if (error) break;
	
	for (i = 0; i < nb_addr; i++) {
	    if (kmod_is_addr_of_kps_domain(enc_array[i].addr.data, kc)) {
		karray_add(&kps_array, &enc_array[i]);
	    }
	    
	    else {
		karray_add(&eks_array, &enc_array[i]);
	    }
	}
	
	/* Query those addresses. */
	if (kps_array.size) {
	    error = kmod_query_enc_addr(kc, &kps_array, KNP_CONTACT_KPS);
	    if (error) break;
	}
	
	if (eks_array.size) {
	    error = kmod_query_enc_addr(kc, &eks_array, KNP_CONTACT_EKS);
	    if (error) break;
	}
	
	/* Send back the results. */
	k3p_write_inst(k3p, K3P_COMMAND_OK);
	k3p_write_uint32(k3p, nb_addr);
	
	for (i = 0; i < nb_addr; i++) {
	    struct enc_addr_info *info = &enc_array[i];
	    char buf[100];
	    buf[0] = 0;
	    
	    if (info->key_data.slen) {
		sprintf(buf, "%lu", info->key_id);
	    }
	    
	    k3p_write_cstr(k3p, buf);
	    k3p_write_kstr(k3p, &info->subscriber_name);
	}
	
	error = k3p_send_data(k3p);
	if (error) break;
	
    } while (0);
    
    if (enc_array) {
	for (i = 0; i < nb_addr; i++) {
	    enc_addr_info_clean(&enc_array[i]);
	}
	
	free(enc_array);
    }
    
    karray_free(&kps_array);
    karray_free(&eks_array);

    return error;
}

static int kmod_validate_ticket(struct kmod_context *kc) {
    int error = 0;
    int convert_flag = 0;
    k3p_proto *k3p = &kc->k3p;
    kstr ticket, key_id_str, key_data;
    uint64_t key_id;
    struct kmocrypt_signed_pkey *pkey = NULL;
    struct kmocrypt_signature2 *sig = NULL;
    kbuffer payload;
    struct knp_query *query = NULL;
    
    kmod_log_msg(2, "kmod_validate_ticket() called.\n");
    
    kstr_init(&ticket);
    kstr_init(&key_id_str);
    kstr_init(&key_data);
    kbuffer_init(&payload, 10);
    
    do {
	/* Receive the ticket. */
	error = k3p_read_kstr(k3p, &ticket);
	if (error) break;
	
	error = k3p_read_kstr(k3p, &key_id_str);
	if (error) break;
	
	key_id = strtoll(key_id_str.data, NULL, 10);
	
	/* Obtain the encryption key. */
	kbuffer_clear(&payload);
	knp_msg_write_uint64(&payload, key_id);
	query = knp_query_new(KNP_CONTACT_KPS, KNP_CMD_LOGIN_ANON, KNP_CMD_GET_ENC_KEY_BY_ID, &payload);
	if (kmod_exec_query(query, kc, &error)) break;
	
	if (query->res_type != KNP_RES_GET_ENC_KEY_BY_ID) {
	    kmod_handle_failed_query(query, "cannot obtain encryption key");
	    convert_flag = 1;
	    break;
    	}
    
	/* Timestamp key. Ignore. */
	error = knp_msg_read_kstr(query->res_payload, &key_data);
	if (error) { convert_flag = 1; break; }
	
	/* Encryption key. */
	error = knp_msg_read_kstr(query->res_payload, &key_data);
	if (error) { convert_flag = 1; break; }
	
	kbuffer_clear(&payload);
	kbuffer_write(&payload, key_data.data, key_data.slen);
	pkey = kmocrypt_sign_get_pkey(&payload);
	if (! pkey) { convert_flag = 1; break; }
	
	sig = kmo_calloc(sizeof(struct kmocrypt_signature2));
	kbuffer_clear(&payload);
	kbuffer_write(&payload, ticket.data, ticket.slen);
	
	/* Send back the results. */
	k3p_write_inst(k3p, K3P_COMMAND_OK);
	    
	/* Invalid signature. */
	if (kmocrypt_recognize_ksp2(sig, &payload) || kmocrypt_signature_validate2(sig, pkey->key)) {
	    k3p_write_uint32(k3p, 1);
	    k3p_write_kstr(k3p, kmo_kstrerror());
	}
	
	/* All good. */
	else {
	    k3p_write_uint32(k3p, 0);
	    k3p_write_cstr(k3p, "");
	}
	
	error = k3p_send_data(k3p);
	if (error) break;
	
    } while (0);
    
    /* Convert the error to a server error. */
    if (convert_flag) {
    	error = kmod_convert_to_serv_error(&kc->k3p, query);
    }
    
    knp_query_destroy(query);
    if (sig) { kmocrypt_signature_free2(sig); free(sig); }
    if (pkey) kmocrypt_signed_pkey_destroy(pkey);
    kstr_free(&ticket);
    kstr_free(&key_id_str);
    kstr_free(&key_data);
    kbuffer_clean(&payload);
    
    return error;
}

/* This function validates an OTUT string.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_validate_otut(struct kmod_context *kc) {
    int error = 0;
    struct knp_query *query = NULL;
    k3p_proto *k3p = &kc->k3p;
    kstr entry_id_str;
    maildb_mail_info *entry_id_mail = NULL;
    kbuffer payload;
    
    kmod_log_msg(2, "kmod_validate_otut() called.\n");
    
    kstr_init(&entry_id_str);
    kbuffer_init(&payload, 100);
    
    /* Try. */
    do {
	uint32_t remaining_use_count = 0;
	
	/* Receive the entry ID. */
	error = k3p_read_kstr(k3p, &entry_id_str);
	if (error) break;
	
	/* Try. */
	do {
	    /* Locate the mail having the specified entry ID, if any. */
	    if (kmod_get_mail_from_entry_id_str(kc, &entry_id_str, &entry_id_mail)) {
		break;
	    }
	    
	    /* There is no OTUT string. */
	    if (! entry_id_mail->otut_string.slen) {
		break;
	    }

	    /* Ask the server about the OTUT string. */
	    knp_msg_write_kstr(&payload, &entry_id_mail->otut_string);
	    query = knp_query_new(KNP_CONTACT_OTS, KNP_CMD_LOGIN_ANON, KNP_CMD_VALIDATE_OTUT, &payload);

	    error = knp_query_exec(query, &kc->knp);
	    if (error) break;

	    if (query->res_type == KNP_RES_SERV_ERROR) {
		error = kmod_handle_server_error(k3p, query);
		break;
	    }

	    if (query->res_type == KNP_RES_UPGRADE_PLUGIN || query->res_type == KNP_RES_UPGRADE_KPS) {
		error = kmod_handle_incomp_version(k3p, query);
		break;
	    }

	    /* Convert this to a server error. */
	    if (query->res_type != KNP_RES_VALIDATE_OTUT) {
		kmod_handle_failed_query(query, "cannot validate OTUT string"); 
		error = kmod_convert_to_serv_error(k3p, query);
		break;
	    }

	    /* Get the remaining use count. */
	    error = knp_msg_read_uint32(query->res_payload, &remaining_use_count);
	    if (error) break;
	    
	} while (0);
	
	if (error) break;
	
	/* Tell the plugin about it. */
	k3p_write_inst(k3p, K3P_CHECK_OTUT);
	k3p_write_uint32(k3p, remaining_use_count);
	error = k3p_send_data(k3p);
	if (error) break;
	
    } while (0);
 
    knp_query_destroy(query);
    kstr_free(&entry_id_str);
    maildb_free_mail_info(entry_id_mail);
    kbuffer_clean(&payload);
    
    return error;
}

/* This function performs a login test on the KPS. 
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_login_test(struct kmod_context *kc) {
    int error = 0;
    struct kmod_server_info test_server_info;
    struct knp_query *query = NULL;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(2, "kmod_login_test() called.\n");
    
    k3p_init_server_info(&test_server_info);
    
    /* Try. */
    do {
    	/* Get the server info. */					
	error = k3p_read_server_info(k3p, &test_server_info);
        if (error) break;

	/* Check if the user and password are set. */
	if (test_server_info.kps_login.slen == 0 || test_server_info.kps_pwd.slen == 0) {
	    k3p_write_inst(k3p, KMO_SERVER_INFO_NACK);
	    k3p_write_cstr(k3p, "your user name and/or password are not set");	    
	    error = k3p_send_data(k3p);
	    break;
	}
	
	/* Make a login-only query. */
	query = knp_query_new(KNP_CONTACT_KPS, KNP_CMD_LOGIN_USER, 0, NULL);
	
	/* Perform a quick substitution and execute the query. */
	kc->knp.server_info = &test_server_info;
	error = knp_query_exec(query, &kc->knp);
	kc->knp.server_info = &kc->server_info;
    	
	if (error) {
	    error = (error == -3) ? -1 : 0;
	    break;
	}
	
	/* If the command is KNP_RES_LOGIN_OK, the login is successful. */
	if (query->res_type == KNP_RES_LOGIN_OK) {
	    
	    /* Get the encrypted password. */
	    error = knp_msg_read_kstr(query->res_payload, &kc->str);
	    
	    /* Invalid message. */
	    if (error) {
	    	k3p_write_inst(k3p, KMO_SERVER_INFO_NACK);
		k3p_write_kstr(k3p, kmo_kstrerror()); 
	    }
	    
	    /* All is well and good. */
	    else {
	    	k3p_write_inst(k3p, KMO_SERVER_INFO_ACK);
		k3p_write_kstr(k3p, &kc->str);
	    }
	}
	
	/* Otherwise, it failed. */
	else {
    	    k3p_write_inst(k3p, KMO_SERVER_INFO_NACK);

    	    /* The server refuses the credentials. */
	    if (query->res_type == KNP_RES_FAIL) {
		k3p_write_cstr(k3p, "invalid user name or password");
	    }
	    
	    /* Server error. */
	    else if (query->res_type == KNP_RES_SERV_ERROR) {
		k3p_write_kstr(k3p, query->serv_error_msg);
	    }

	    /* Hrmph. */
	    else {
		kmod_handle_failed_query(query, "unexpected error");
		k3p_write_kstr(k3p, kmo_kstrerror()); 
	    }
    	}
	
	error = k3p_send_data(k3p);
    
    } while (0);
 
    knp_query_destroy(query);
    k3p_free_server_info(&test_server_info);
    
    return error;
}

/* This function sets the server information used by KMO.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_set_server_info(struct kmod_context *kc) {
    kmod_log_msg(2, "kmod_set_server_info() called.\n");

    /* Flush the cached user info. */
    kmod_flush_user_info(kc);
    
    /* Read the server info. */
    return k3p_read_server_info(&kc->k3p, &kc->server_info);
}

/* This function loops while expecting session commands from the plugin.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_interaction_loop(struct kmod_context *kc) {
    
    while (1) {
    	int error = 0;
	int cmd;
	k3p_proto *k3p = &kc->k3p;
	
    	assert(k3p->state == K3P_INTERACTING);
	
	/* Get the next command. */
	if (k3p_read_inst(k3p, &cmd)) {
	    return -1;
	}
	
	kmod_log_msg(2, "KMOD interaction loop: command %x.\n", cmd);
	
	switch (cmd) {
	
	    /* Process an incoming message. The session might end during this call. */
	    case KPP_PROCESS_INCOMING:
	    case K3P_PROCESS_INCOMING_EX:
	    {
		int want_dec_email = (cmd == K3P_PROCESS_INCOMING_EX);
	    	struct kmod_mail_process_req process_req;
		k3p_init_mail_process_req(&process_req);
		error = k3p_read_mail_process_req(k3p, &process_req);
		
		if (! error) {
		    error = kmod_process_incoming(kc, &process_req, want_dec_email);
		    kmod_disable_kpg(kc);
		}
		
		k3p_free_mail_process_req(&process_req);
		break;
	    }
	    
	    /* Evaluate an incoming message. */
	    case KPP_EVAL_INCOMING: {
	    	struct kmod_mail mail;
		k3p_init_mail(&mail);
		error = k3p_read_mail(k3p, &mail);
		
		if (! error) {
		    error = kmod_eval_incoming(kc, &mail);
		    kmod_disable_kpg(kc);
		}
		
		k3p_free_mail(&mail);
		break;
	    }
	    
	    /* Mark some messages as unsigned mails. */
	    case KPP_MARK_UNSIGNED_MAIL:
	    	error = kmod_mark_unsigned_mail(kc);
		break;
	    
	    /* Set the display preference of a message. */
	    case KPP_SET_DISPLAY_PREF:
	    	error = kmod_set_display_pref(kc);
		break;
	    
	    /* Get the full status of a message. */
    	    case KPP_GET_EVAL_STATUS:
	    	error = kmod_get_eval_status(kc, 1);
		break;
	    
	    /* Get the string status of a message. */
	    case KPP_GET_STRING_STATUS:
	    	error = kmod_get_eval_status(kc, 0);
		break;
	    
	    /* Package a message. */
    	    case KPP_SIGN_N_ENCRYPT_N_POD_MAIL:           
            case KPP_SIGN_N_POD_MAIL:
            case KPP_SIGN_N_ENCRYPT_MAIL:
            case KPP_SIGN_MAIL: {
	    	struct kmod_mail mail;
		k3p_init_mail(&mail);
		error = k3p_read_mail(k3p, &mail);
		
		if (! error) {
		    error = kmod_package(kc, cmd, &mail);
		    kmod_disable_kpg(kc);
		}
		
		k3p_free_mail(&mail);
		break;
	    }
	    
	    /* Get the password corresponding to the email specified. */
	    case KPP_GET_EMAIL_PWD:
	    case KPP_GET_ALL_EMAIL_PWD:
	    case KPP_SET_EMAIL_PWD:
	    case KPP_REMOVE_EMAIL_PWD:
	    	error = kmod_handle_email_pwd(kc, cmd);
		break;
	    
	    /* Check if the OTUT is valid. */
	    case K3P_CHECK_OTUT:
	    	error = kmod_validate_otut(kc);
		break;
	    
	    /* Set the server info. */
	    case KPP_SET_KSERVER_INFO:
	    	error = kmod_set_server_info(kc);
		break;
	    
	    /* Test the server info. */
	    case KPP_IS_KSERVER_INFO_VALID:
	    	error = kmod_login_test(kc);
		break;
	    
	    /* End the current session. */
	    case KPP_END_SESSION: {
	    	k3p->state = K3P_ACTIVE;
		break;
	    }
	    
	    /* MORE HACKS. */
	    case K3P_OPEN_KAPPSD_SESSION: {
	    	error = handle_open_kappsd_session(kc);
		break;
	    }
	    
	    case K3P_CLOSE_KAPPSD_SESSION: {
	    	error = handle_close_kappsd_session(kc);
		break;
	    }
	    
	    case K3P_EXCHANGE_KAAPSD_MESSAGE: {
	    	error = handle_exchange_kaapsd_message(kc);
		break;
	    }
	    
	    /* KAS hacks. */
	    case K3P_GET_KWS_TICKET: {
	    	error = kmod_get_kws_ticket(kc);
		break;
	    }
		
	    case K3P_CONVERT_EXCHANGE_ADDRESS: {
	    	error = kmod_convert_exchange_address(kc);
		break;
	    }
	    
	    case K3P_LOOKUP_REC_ADDR: {
	    	error = kmod_lookup_rec_addr(kc);
		break;
	    }
	    
	    case K3P_VALIDATE_TICKET: {
	    	error = kmod_validate_ticket(kc);
		break;
	    }
	    
	    /* Oops. */
	    default:
	    	kmod_log_msg(1, "Invalid request: unexpected instruction (%x) in session context.\n", cmd);
	    	kmod_handle_invalid_request(k3p);
		error = -1;
	}
	
	/* We're done if an error occurred or if we're no longer interacting. */
	if (error || k3p->state != K3P_INTERACTING) {
	    kmod_log_msg(3, "KMOD interaction loop: returning %d.\n", error);
	    return error;
	}
    }
}

/* KMOD idle loop. This loop should never timeout unless the connection with
 * the plugin is broken.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_loop(struct kmod_context *kc) {
    int cmd;
    k3p_proto *k3p = &kc->k3p;
    
    kmod_log_msg(1, "Entering KMOD loop.\n");
    
    /* Loop until we're done. */
    while (1) {
	
	/* The communication with the plugin has been lost. Get out. */
	if (k3p->state == K3P_DISCONNECTED) {
	    return -1;
	}
	
	/* Get the next command. There is no timeout here. */
	k3p->timeout_enabled = 0;
	
	if (k3p_read_inst(k3p, &cmd)) {
	    return -1;
	}
    
	k3p->timeout_enabled = 1;
	
	switch (cmd) {
	    
	    /* Disconnect cleanly. */
	    case KPP_DISCONNECT_KMO:
	    	kmod_log_msg(1, "Plugin requested KMOD shutdown.\n");
	    	k3p_proto_disconnect(k3p);
		return 0;
	    
	    /* Start of session between the plugin and KMO. */
	    case KPP_BEG_SESSION:
	    	kmod_log_msg(2, "\nReceived KPP_BEG_SESSION.\n");
		
		/* Truncate the logs if required. */
		if (kmod_truncate_log_flag && kmod_truncate_log(kc)) {
		    return -1;
		}
		
		/* Start interacting. */
		k3p->state = K3P_INTERACTING;
		
		if (kmod_interaction_loop(kc)) {
	    	    return -1;
		}
		
	    	break;
	    
	    /* Oops. */
	    default:
	    	kmod_log_msg(1, "Invalid request: unexpected instruction (%x) in connected context.\n", cmd);
	    	kmod_handle_invalid_request(k3p);
		return -1;
	}
    }
}

/* This function connects KMOD with the plugin.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_connect_to_plugin(struct kmod_context *kc) {
    int error = 0;
    struct kmo_data_transfer *transfer = &kc->k3p.transfer;
    uint32_t inst;
    
    kmod_log_msg(1, "Connecting to plugin.\n");
    
    /* The caller should already have set the timeout_enabled flag. */
    
    /* We're inheriting the socket. Set the K3P file descriptor. */
    if (kc->kpp_conn_type == KPP_CONN_INHERITED) {
    	
	#ifdef __UNIX__
    	transfer->fd = fileno(stdin);
	#endif
	
	#ifdef __WINDOWS__
    	transfer->fd = (int) GetStdHandle(STD_INPUT_HANDLE);
	#endif
    }
    
    /* We're waiting for an incoming connection. */
    else if (kc->kpp_conn_type == KPP_CONN_KPP_CONNECT) {
	int accept_fd = -1;

	/* Try. */
	do {
	    error = kmo_sock_create(&accept_fd);
	    if (error) break;
	    
	    error = kmo_sock_set_unblocking(accept_fd);
	    if (error) break;
	    
	    error = kmo_sock_bind(accept_fd, kc->kpp_conn_port);
	    if (error) break;
	    
	    error = kmo_sock_listen(accept_fd);
	    if (error) break;
	    
	    while (1) {
    	    	int conn_fd = -1;
	
		/* Wait for the connection. */
		transfer->read_flag = 1;
		transfer->fd = accept_fd;
		transfer->buf = NULL;
		transfer->min_len = transfer->max_len = 0;
		transfer->op_timeout = kc->k3p.timeout_enabled ? K3P_ACCEPT_TIMEOUT : 0;
		kmo_transfer_hub_add(&kc->hub, transfer);
		kmo_transfer_hub_wait(&kc->hub);
		kmo_transfer_hub_remove(&kc->hub, transfer);
		
		if (transfer->status == KMO_COMM_TRANS_ERROR) {
		    kmo_seterror("failed to accept connection from plugin: %s", kmo_data_transfer_err(transfer));
		    error = -1;
		    break;
		}

		assert(transfer->status == KMO_COMM_TRANS_COMPLETED);
	
		/* It seems there is a connection, accept it. */
		error = kmo_sock_accept(accept_fd, &conn_fd);
		
		/* Try again later. */
		if (error == -2) {
		    continue;
		}
		
		/* Oops. */
		else if (error == -1) {
		    break;
		}

		/* We got the connection, update the file descriptor for K3P and
		 * enable the timeout.
		 */
		assert(! error);
		transfer->fd = conn_fd;
		kc->k3p.timeout_enabled = 1;
		break;
	    }
	    
	    if (error) break;
	    
	} while (0);
		
    	kmo_sock_close(&accept_fd);
	if (error) return -1;
    }
    
    /* We must connect to the plugin. */
    else if (kc->kpp_conn_type == KPP_CONN_KMOD_CONNECT) {
    	int connect_fd = -1;
	FILE *file_ptr = NULL;
	kstr secret_file_path;
	kstr_init(&secret_file_path);
	
	/* Try. */
	do {
	    /* Generate 32 bytes of random data. */
	    char random_buf[32];
	    error = util_generate_random(random_buf, 32);
	    if (error) break;
	    
	    /* Write the random data in the 'connect_secret' file. */
	    kstr_sf(&secret_file_path, "%s/connect_secret", kc->teambox_dir_path.data);
	    
	    error = util_open_file(&file_ptr, secret_file_path.data, "wb");
	    if (error) break;

	    error = util_write_file(file_ptr, random_buf, 32);
	    if (error) break;

	    error = util_close_file(&file_ptr, 0);
	    if (error) break;
	    
	    /* Connect to the plugin. */
	    error = kmo_sock_create(&connect_fd);
	    if (error) break;
	    
	    error = kmo_sock_set_unblocking(connect_fd);
	    if (error) break;
	    
	    error = kmo_sock_connect(connect_fd, "127.0.0.1", kc->kpp_conn_port);
	    if (error) break;
	    
	    /* Wait for the connection. */
	    transfer->read_flag = 0;
	    transfer->fd = connect_fd;
	    transfer->buf = NULL;
	    transfer->min_len = transfer->max_len = 0;
	    transfer->op_timeout = kc->k3p.timeout_enabled ? K3P_ACCEPT_TIMEOUT : 0;
	    kmo_transfer_hub_add(&kc->hub, transfer);
	    kmo_transfer_hub_wait(&kc->hub);
	    kmo_transfer_hub_remove(&kc->hub, transfer);
    	    
	    if (transfer->status == KMO_COMM_TRANS_ERROR) {
		kmo_seterror("failed to connect to plugin: %s", kmo_data_transfer_err(transfer));
		error = -1;
		break;
	    }

	    assert(transfer->status == KMO_COMM_TRANS_COMPLETED);
    	    
	    /* It seems there is a connection, try it. */
	    error = kmo_sock_connect_check(connect_fd, "127.0.0.1");
	    if (error) break;
	    
	    /* Send the random data to the plugin. */
	    transfer->read_flag = 0;
	    transfer->fd = connect_fd;
	    transfer->buf = random_buf;
	    transfer->min_len = transfer->max_len = 32;
	    transfer->op_timeout = kc->k3p.timeout_enabled ? K3P_ACCEPT_TIMEOUT : 0;
	    kmo_transfer_hub_add(&kc->hub, transfer);
	    kmo_transfer_hub_wait(&kc->hub);
	    kmo_transfer_hub_remove(&kc->hub, transfer);
	    
	    if (transfer->status == KMO_COMM_TRANS_ERROR) {
		kmo_seterror("failed to send random data to plugin: %s", kmo_data_transfer_err(transfer));
		error = -1;
		break;
	    }

	    assert(transfer->status == KMO_COMM_TRANS_COMPLETED);
	    
	    /* We got the connection, update the file descriptor for K3P and
	     * enable the timeout.
	     */
	    transfer->fd = connect_fd;
	    connect_fd = -1;
	    kc->k3p.timeout_enabled = 1;
	    
	} while (0);
	
	kmo_sock_close(&connect_fd);
	util_close_file(&file_ptr, 1);
	kstr_free(&secret_file_path);
	if (error) return -1;
    }
    
    else assert(0);
    
    kmod_log_msg(1, "Connected to plugin, waiting for KPP_CONNECT_KMO.\n");
    
    /* At this point the K3P file descriptor is valid. The timeout may or may
     * not be enabled, we set its value regardless.
     */
    kc->k3p.timeout = operation_timeout;
   
    /* We're connected. */
    kc->k3p.state = K3P_ACTIVE;
   
    /* Read the KPP_CONNECT_KMO command. */
    error = k3p_read_inst(&kc->k3p, &inst);  
    if (error) return -1;
    
    /* The other end does not appear to speak the K3P protocol. */
    if (inst != KPP_CONNECT_KMO) {
	kmo_seterror("expected KPP_CONNECT_KMO, but received %x instead", inst);
	return -1;
    }
  
    /* Enable the timeout. */
    kc->k3p.timeout_enabled = 1;
    
    /* Receive the mail user agent information. */
    error = k3p_read_mua(&kc->k3p, &kc->mua);
    if (error) return -1;

    /* Write KMO_COGITO_ERGO_SUM and the tool information. */
    k3p_write_inst(&kc->k3p, KMO_COGITO_ERGO_SUM);
    k3p_write_tool_info(&kc->k3p, &kc->tool_info);
    error = k3p_send_data(&kc->k3p);
    if (error) return -1;
    
    return 0;
}

/* This function opens the KMO mail database.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_open_mail_db(struct kmod_context *kc) {
    
    /* If no path has been specified, use the default path. */
    if (! kc->kryptiva_db_path.slen)
    {
    	kstr_sf(&kc->kryptiva_db_path, "%s/kmomaildb", kc->teambox_dir_path.data);
    }
    
    kmod_log_msg(1, "Opening the mail database (%s).\n", kc->kryptiva_db_path.data);
    
    kc->mail_db = maildb_sqlite_new(kc->kryptiva_db_path.data);

    if (kc->mail_db == NULL) {
	kmo_seterror("cannot open mail database: %s", kmo_strerror());
	return -1;
    }
    
    return 0;
}

/* This function creates the Teambox directory if it doesn't exist. */
static int kmod_create_teambox_dir(struct kmod_context *kc) {
    int error = 0;
    
    /* Create the Teambox directory. */
    if (! util_check_dir_exist(kc->teambox_dir_path.data)) {
    	error = util_create_dir(kc->teambox_dir_path.data);
	if (error) return error;
    }
    
    /* Create the KMOD logs directory. */
    kstr_sf(&kc->str, "%s/kmod_logs", kc->teambox_dir_path.data);

    if (! util_check_dir_exist(kc->str.data)) {
    	error = util_create_dir(kc->str.data);
	if (error) return error;
    }

    /* Create the incoming directory. */
    kstr_sf(&kc->str, "%s/incoming", kc->teambox_dir_path.data);

    if (! util_check_dir_exist(kc->str.data)) {
    	error = util_create_dir(kc->str.data);
	if (error) return error;
    }

    /* Create the outgoing directory. */
    kstr_sf(&kc->str, "%s/outgoing", kc->teambox_dir_path.data);

    if (! util_check_dir_exist(kc->str.data)) {
    	error = util_create_dir(kc->str.data);
	if (error) return error;
    }
    
    return 0;
}

/* This function sets the path to the Teambox directory, if necessary.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int kmod_get_teambox_path(struct kmod_context *kc) {
    
    /* A path has already been specified. */
    if (kc->teambox_dir_path.slen) return 0;
    
    /* Use the default path. */
    char *basename = getenv(KMOD_HOME_VAR);

    if (basename == NULL) {
	kmo_seterror("cannot determine Teambox directory path: %s variable is not set", KMOD_HOME_VAR);
	return -1;
    }

    #ifdef __WINDOWS__
    kstr_sf(&kc->teambox_dir_path, "%s/teambox", basename);
    #else
    kstr_sf(&kc->teambox_dir_path, "%s/.teambox", basename);
    #endif
    
    return 0;
}

/* This function prints the KMO banner to stdout. */
static void kmod_print_banner() {
    printf("Kryptiva Mail Operator Daemon (KMOD) version %s build %s.\n", K3P_VERSION, BUILD_ID);
    printf("Copyright (C) 2005-2012 Opersys inc., All rights reserved.\n\n");
}

/* This function prints the usage on the stream specified. */
static void kmod_print_usage(FILE *stream) {
    fprintf(stream, "Usage: kmod -C {inherited|kmod_connect|kpp_connect} [-p port]\n"
		    "            [-l log_level] [-k <Teambox dir path>] [-d <dbpath>]\n"
		    "            [-m <timeout_ms>] [-a <address>] [-h -v -D -t]\n"
		    "\n"
		    "-C <method>      Specify the way KMOD will communicate with the plugin.\n"
		    "                   inherited: use the socket inherited from stdin.\n"
		    "                   kmod_connect: KMOD connects to the plugin on the port\n"
		    "                     specified.\n"
		    "                   kpp_connect: the plugin connects to KMOD on the port\n"
		    "                     specified.\n"
		    "-p <port>        Specify the port used to connect to/from KMOD. The default\n"
		    "                   port is 31000.\n"
		    "-l <level>       Log level of KMOD: from 0 to 3, where 3 is most verbose.\n"
		    "-k <path>        Path to the Teambox directory used by KMOD. If not specified,\n"
		    "-d <path>          an OS-dependent \"teambox\" directory is used.\n"
		    "-h               Show this help message and exit.\n"
		    "-v               Show the version number and exit.\n"
		    "-D               Be stand-alone. Do not timeout while waiting for the plugin to\n"
		    "                   contact kmod.\n"
		    "-t               Trunk the logs at every request, to keep them small.\n"
		    "-m               Set the timeout (in milliseconds) for the K3P and the KNP.\n"
		    "-a <address>     Use the specified address to lookup encryption keys.\n"
		    );
}

/* This function initializes the kmod_allowed_file_char table. */
static inline void initialize_allowed_file_char() {
    int i = 0;
    memset(kmod_allowed_file_char, 0, 256);
    
    /* Allow some punctuation, letters and numbers. */ 
    kmod_allowed_file_char[32] = 1;  
    for (i = 35; i <= 46; i++) kmod_allowed_file_char[i] = 1;
    for (i = 48; i <= 59; i++) kmod_allowed_file_char[i] = 1;
    kmod_allowed_file_char[61] = 1;
    for (i = 64; i <= 91; i++) kmod_allowed_file_char[i] = 1;
    for (i = 93; i <= 123; i++) kmod_allowed_file_char[i] = 1;
    kmod_allowed_file_char[125] = 1;  	
    for (i = 192; i <= 229; i++) kmod_allowed_file_char[i] = 1;
    for (i = 231; i <= 246; i++) kmod_allowed_file_char[i] = 1;
    for (i = 248; i <= 253; i++) kmod_allowed_file_char[i] = 1;
    kmod_allowed_file_char[255] = 1;
}

/* The root of all KMO evil. */
int main(int argc, char **argv) {
    
    /* Error status: 0=>keep going, -1=>exit with failure, -2=>exit with success. */
    int error = 0;
    int is_standalone = 0;
    struct kmod_context kc;

    /* Perform the internal tests. */
    #ifdef __TEST__ 
    void kmo_do_tests(void);
    kmo_do_tests();
    return 0;
    #endif
    
    /* Initialize the error module. */
    kmo_error_start();
    
    /* Initialize the KMOD context. */
    kmod_context_init(&kc);
    
    /* Try. */
    do {
	/* Parse the arguments. */
	while (1) {
	    int cmd = getopt(argc, argv, "C:p:l:k:d:m:a:hvDt");

	    /* Error. */
	    if (cmd == '?' || cmd == ':') {
		kmod_print_usage(stderr);
		error = -1;
		break;
	    }

	    else if (cmd == 'C') {
        	if (strcasecmp(optarg, "inherited") == 0)
		    kc.kpp_conn_type = KPP_CONN_INHERITED;

		else if (strcasecmp(optarg, "kmod_connect") == 0)
		    kc.kpp_conn_type = KPP_CONN_KMOD_CONNECT;

		else if (strcasecmp(optarg, "kpp_connect") == 0)
		    kc.kpp_conn_type = KPP_CONN_KPP_CONNECT;

        	else {
		    fprintf(stderr, "Invalid transport specified (%s).\n", optarg);
		    error = -1;
		    break;
		}
	    }

	    else if (cmd == 'p') {
		char *end;
		kc.kpp_conn_port = strtol(optarg, &end, 10);

		if (*end != 0 || kc.kpp_conn_port <= 0) {
    		    fprintf(stderr, "Invalid port value (%s).\n", optarg);
		    error = -1;
		    break;
		}
	    }

	    else if (cmd == 'l') {
		if (! strcmp(optarg, "0")) kmod_log_level = 0;
    		else if (! strcmp(optarg, "1")) kmod_log_level = 1;
		else if (! strcmp(optarg, "2")) kmod_log_level = 2;
		else if (! strcmp(optarg, "3")) kmod_log_level = 3;
		else {
		    fprintf(stderr, "Invalid log level (%s).\n", optarg);
		    error = -1;
		    break;
		}
	    }
	    
	    else if (cmd == 'k') {
	    	kstr_assign_cstr(&kc.teambox_dir_path, optarg);
	    }

    	    else if (cmd == 'd')
		kstr_assign_cstr(&kc.kryptiva_db_path, optarg);
	    
	    else if (cmd == 'm') {
		char *end;
		operation_timeout = strtol(optarg, &end, 10);

		if (*end != 0 || operation_timeout < 0) {
    		    fprintf(stderr, "Invalid timeout value (%s).\n", optarg);
		    error = -1;
		    break;
		}
	    }

	    else if (cmd == 'h') {
    		kmod_print_usage(stdout);
		error = -2;
		break;
	    }
	    
	     else if (cmd == 'v') {
    		kmod_print_banner();
		error = -2;
		break;
	    }

	    else if (cmd == 'D')
		is_standalone = 1;

	    else if (cmd == 't')
		kmod_truncate_log_flag = 1;
	    
	    else if (cmd == 'a') {
		kstr_assign_cstr(&kc.enc_key_lookup_str, optarg);
	    }

	    /* Out of args. */
	    else if (cmd == -1)
		break;

	    else
		assert(0);
	}
	
	if (error) break;
    
	/* No driver selected. */
	if (kc.kpp_conn_type == KPP_CONN_NONE) {
    	     kmod_print_banner();
    	     fprintf(stderr, "This program is not meant to be run without arguments.\n");
	     fprintf(stderr, "Please select the communication method (e.g. -C kpp_connect).\n");
	     fprintf(stderr, "Use -h for help.\n");
	     error = -1;
	     break;
	}
    	
	/* Initialize the allowed character table for attachments. */
    	initialize_allowed_file_char();

	/* Initialize kmocrypt. */
	kmocrypt_init();

	/* Initialise the SSL library. */
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	    
	/* Ignore SIGPIPE on UNIX. */
	#ifdef __UNIX__
	signal(SIGPIPE, SIG_IGN);
	#endif
        
	/* Try. */
	do {	
	    /* Get the path to the Teambox directory. */
	    error = kmod_get_teambox_path(&kc);
	    if (error) break;

	    /* Create the Teambox directory if it doesn't exist. */
	    error = kmod_create_teambox_dir(&kc);
	    if (error) break;

	    /* Open the logs. */
	    error = kmod_open_log(&kc);
	    if (error) break;

	    /* Initialize Windows stuff. */
    	    #ifdef __WINDOWS__
	    WSADATA wsaData;

	    if (WSAStartup(MAKEWORD(2, 0), &wsaData)) {
        	kmo_seterror("unable to initialize Winsock");
		error = -1;
		break;
	    }
	    #endif

	    /* Open the KMO mail database. */
	    error = kmod_open_mail_db(&kc);
	    if (error) break;
	    
	    /* Verify the integrity of the database. */
	    int maildb_integrity_check(maildb *mdb);
	    error = maildb_integrity_check(kc.mail_db);
	    if (error) break;
	    
	    /* Connect to the plugin. */
	    kc.k3p.timeout_enabled = !is_standalone;
	    error = kmod_connect_to_plugin(&kc);
	    if (error) break;

	    /* Set the timeout value for the KNP. */
	    kc.knp.timeout = operation_timeout;

	    /* Enter the main loop. */
	    error = kmod_loop(&kc);
	    if (error) break;

	} while (0);

	/* If an error occurred, log it or display it. */
	if (error) {
    	    if (kmod_log) {
    		kmod_log_msg(1, "Error: %s.\n", kmo_strerror());
	    }

	    else {
    		fprintf(stderr, "Error: %s.\n", kmo_strerror());
	    }
	}

	else {
    	    kmod_log_msg(1, "No error occurred, exiting.\n");
	}

	/* Close the logs. */
	kmod_close_log(&kc);
	
	/* Free the memory associated to the SSL library. */
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();

	/* libgcrypt doesn't free its memory unfortunately. */
	
    } while (0);
    
    /* Free the KMOD context. */
    kmod_context_free(&kc);
    
    /* Free the memory associated to the error module. */
    kmo_error_end();
    
    return (error == -1 ? 1 : 0);
}
