/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

#ifndef _MAIL_H
#define _MAIL_H

#include "kmo_base.h"
#include "k3p_core_defs.h"

/* Kryptive message tags. */
#define KRYPTIVA_BODY_START \
	"----- KRYPTIVA PACKAGED MESSAGE -----"

#define KRYPTIVA_INFO_START \
	"----- KRYPTIVA SIGNED MESSAGE -----"

#define KRYPTIVA_SIG_START \
	"----- KRYPTIVA SIGNATURE START -----"

#define KRYPTIVA_SIG_END \
	"----- KRYPTIVA SIGNATURE END -----"

#define KRYPTIVA_ENC_BODY_START \
	"----- KRYPTIVA ENCRYPTED DATA START -----"

#define KRYPTIVA_ENC_BODY_END \
	"----- KRYPTIVA ENCRYPTED DATA END -----"
	

char * mail_get_pkg_type_str(int pkg_type);
void mail_repair_outlook_html_damage(kstr *body);
void mail_get_signable_html_body(kstr *in, kstr *out);
void mail_put_space_before_body_end(kstr *in);
void mail_build_signed_text_body(int pkg_type, kstr *orig_body, kstr *sig, kstr *signed_body);
void mail_build_signed_html_body(int pkg_type, kstr *orig_body, kstr *sig, kstr *signed_body);
void mail_build_encrypted_body(int pkg_type, kstr *content, kstr *encrypted_body);
int mail_get_mail_status(kstr *text_body, kstr *html_body);
int mail_get_signature(kstr *target_body, kstr *sig);
int mail_strip_text_signature(kstr * body_str, kstr *out_str);
int mail_strip_html_signature(kstr *raw_body_str, kstr *out_str);
int mail_get_encrypted_body(kstr *target_body, kstr *out_str);
int mail_parse_addr_field(kstr *addr_field, karray *addr_array);
		   
#endif
