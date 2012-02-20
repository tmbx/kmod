/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

#include "k3p.h"
#include "kmod.h"

/* Prefered size of the data buffer. */
#define DATA_BUF_SIZE (64*1024)


/* This function returns a string describing the K3P element specified. */
static inline char * k3p_get_element_desc(int type) {
    switch (type) {
    	case K3P_EL_INS: return "instruction";
	case K3P_EL_INT: return "integer";
	case K3P_EL_STR: return "string";
	default: return "unknown element type";
    }
    
    return NULL;
}

/* This function destroys the K3P element specified. */
static inline void k3p_element_destroy(struct k3p_element *el) {
    if (el == NULL) return;
    
    if (el->str != NULL) {
    	free(el->str);
    }
    
    free(el);
}

/* This function initializes the K3P communication object. */
void k3p_proto_init(k3p_proto *k3p) {
    memset(k3p, 0, sizeof(k3p_proto));
    k3p->state = K3P_INITIALIZED;
    karray_init(&k3p->element_array);
    kbuffer_init(&k3p->data_buf, DATA_BUF_SIZE);
    kmo_data_transfer_init(&k3p->transfer);
}

/* This function frees the K3P communication object. */
void k3p_proto_free(k3p_proto *k3p) {
    k3p_proto_disconnect(k3p);
    karray_free(&k3p->element_array);
    kbuffer_clean(&k3p->data_buf);
    kmo_data_transfer_free(&k3p->transfer);
}

/* This function disconnects KMOD from the remote side, if it is connected. */
void k3p_proto_disconnect(k3p_proto *k3p) {
    kmod_log_msg(2, "k3p_proto_disconnect() called.\n");
     
    /* If we're clean, return. */
    if (k3p->state == K3P_INITIALIZED) {
    	return;
    }
    
    /* Close connection, if needed. */
    if (k3p->transfer.fd != -1) {
    	k3p->transfer.driver.disconnect(&k3p->transfer.fd);
    }
    
    /* Destroy all incoming K3P elements. */
    while (k3p->element_array_pos < k3p->element_array.size) {
    	k3p_element_destroy((struct k3p_element *) k3p->element_array.data[k3p->element_array_pos]);
	k3p->element_array_pos++;
    }
    
    k3p->element_array_pos = k3p->element_array.size = 0;
    
    /* Shrink the data buffer. */
    kbuffer_shrink(&k3p->data_buf, DATA_BUF_SIZE);
    
    /* Look 'ma! All clean! */
    k3p->state = K3P_INITIALIZED;
}

/* This function adds the K3P transfer in the hub, waits for it to complete and
 * removes the transfer from the hub.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int k3p_perform_transfer(k3p_proto *k3p) {
    int error = 0;
    
    kmod_log_msg(3, "k3p_perform_transfer() called.\n");
    
    /* Add the transfer. */
    kmo_transfer_hub_add(k3p->hub, &k3p->transfer);
    
    /* Loop until the transfer is done. */
    while (1) {
    	kmo_transfer_hub_wait(k3p->hub);
	
	if (k3p->transfer.status == KMO_COMM_TRANS_COMPLETED) {
	    break;
	}
	
	else if (k3p->transfer.status == KMO_COMM_TRANS_ERROR) {
	    kmo_seterror(kmo_data_transfer_err(&k3p->transfer));
	    error = -1;
	    break;
	}
	
	else {
	    assert(k3p->transfer.status == KMO_COMM_TRANS_PENDING);
	}
    }
    
    /* Remove the transfer. */
    kmo_transfer_hub_remove(k3p->hub, &k3p->transfer);
    return error;
}

/* This function increases the data buffer size by at least 'n' bytes.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int k3p_extend_data_buf(k3p_proto *k3p, uint32_t n) {
    kmod_log_msg(3, "k3p_extend_data_buf() called.\n");
    
    k3p->transfer.read_flag = 1;
    k3p->transfer.min_len = n;
    k3p->transfer.max_len = MAX(n, DATA_BUF_SIZE);
    k3p->transfer.op_timeout = k3p->timeout_enabled ? k3p->timeout : 0;
    
    k3p->transfer.buf = kbuffer_begin_write(&k3p->data_buf, k3p->transfer.max_len);
    
    if (k3p_perform_transfer(k3p)) {
    	return -1;
    }
    
    kbuffer_end_write(&k3p->data_buf, k3p->transfer.trans_len);
    return 0;
}

/* This function parses a K3P instruction. 
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int k3p_parse_ins(k3p_proto *k3p) {
    struct k3p_element *el = (struct k3p_element *) kmo_calloc(sizeof(struct k3p_element));
    el->type = K3P_EL_INS;
    
    kmod_log_msg(3, "k3p_parse_ins() called.\n");
    
    /* Try. */
    do {
    	char buf[9];

	/* Fetch the 8 bytes for the number. */
	if (k3p->data_buf.pos + 8 > k3p->data_buf.len)
    	    if (k3p_extend_data_buf(k3p, k3p->data_buf.pos + 8 - k3p->data_buf.len))
	    	break;
	
	kbuffer_read(&k3p->data_buf, buf, 8);
	buf[8] = 0;
	
	if (k3p_log) {
    	    if (k3p_log_mode != 1) { k3p_log_mode = 1; fprintf(k3p_log, "\nINPUT>\n"); }
    	    fprintf(k3p_log, "INS%s\n", buf);
	}
	
	/* Try to parse the content. */
	if (sscanf(buf, "%x", &el->value) < 1) {
    	    kmo_seterror("bad instruction format");
	    break;
	}
    	
	/* Queue the element. */
	karray_add(&k3p->element_array, el);
	return 0;
    
    } while (0);
    
    free(el);
    return -1;
}

/* This function parses a number up to the '>' delimiter.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int k3p_parse_number(k3p_proto *k3p, uint32_t *num) {
    int i = 0;
    
    kmod_log_msg(3, "k3p_parse_number() called.\n");
    
    /* Try to find the delimiter. */
    while (1) {
    	char c;
	
	if (k3p->data_buf.pos + i == k3p->data_buf.len && k3p_extend_data_buf(k3p, 1))
    	    return -1;
	
	assert(k3p->data_buf.pos + i < k3p->data_buf.len);
	c = k3p->data_buf.data[k3p->data_buf.pos + i];
	
	if (c == '>') {
	    if (i == 0) {
	    	kmo_seterror("expected number before '>'");
		return -1;
	    }
	
	    break;
	}
	
	else if (i == 10) {
	    kmo_seterror("expected '>' after number");
	    return -1;
	}
	
	else if (c < '0' || c > '9') {
	    kmo_seterror("unexpected character (%d) in number", c);
	    return -1;
	}
	
	i++;
    }
    
    /* Replace the delimiter by a zero, to get a NULL-terminated string. */
    k3p->data_buf.data[k3p->data_buf.pos + i] = 0;
    
    /* Try to parse the number. */
    if (sscanf(k3p->data_buf.data + k3p->data_buf.pos, "%u", num) < 1) {
    	kmo_seterror("bad number format");
	return -1;
    }
    
    /* Skip the number and the delimiter. */
    kbuffer_seek(&k3p->data_buf, i + 1, SEEK_CUR);    
    return 0;
}

/* This function parses a K3P integer. 
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int k3p_parse_int(k3p_proto *k3p) {
    struct k3p_element *el = (struct k3p_element *) kmo_calloc(sizeof(struct k3p_element));
    el->type = K3P_EL_INT;
    
    kmod_log_msg(3, "k3p_parse_int() called.\n");
    
    if (k3p_parse_number(k3p, &el->value)) {
    	free(el);
	return -1;
    }
    
    if (k3p_log) {
    	if (k3p_log_mode != 1) { k3p_log_mode = 1; fprintf(k3p_log, "\nINPUT>\n"); }
    	fprintf(k3p_log, "INT%u>\n", el->value);
    }
    
    karray_add(&k3p->element_array, el);
    return 0;
}

/* This function parses a K3P string.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int k3p_parse_str(k3p_proto *k3p) {
    struct k3p_element *el = (struct k3p_element *) kmo_calloc(sizeof(struct k3p_element));
    el->type = K3P_EL_STR;
    
    kmod_log_msg(3, "k3p_parse_str() called.\n");
    
    /* Try. */
    do {
    	if (k3p_parse_number(k3p, &el->value))
	    break;
	
	/* Larger than 100 MB? Ouch! */
	if (el->value > 100*1024*1024) {
	    kmo_seterror("string too large (%d bytes)", el->value);
	    break;
	}
	
	if (k3p_log) {
    	    if (k3p_log_mode != 1) { k3p_log_mode = 1; fprintf(k3p_log, "\nINPUT>\n"); }
    	    fprintf(k3p_log, "STR%u>", el->value);
	}
	
	if (el->value) {	    
	    if (k3p->data_buf.pos + el->value > k3p->data_buf.len)
    		if (k3p_extend_data_buf(k3p, k3p->data_buf.pos + el->value - k3p->data_buf.len))
	    	    break;

	    el->str = (char *) kmo_malloc(el->value);
	    kbuffer_read(&k3p->data_buf, el->str, el->value);

    	    if (k3p_log) fwrite(el->str, 1, el->value, k3p_log);
	}
	
	if (k3p_log) fprintf(k3p_log, "\n");
	
	karray_add(&k3p->element_array, el);
	return 0;
    
    } while (0);
    
    k3p_element_destroy(el);
    return -1;
}

/* This function receives at least one element from the remote side. The
 * function stops receiving elements when there is no more data left in
 * the data buffer.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int k3p_receive_element(k3p_proto *k3p) {
    int error = 0;
    
    kmod_log_msg(3, "k3p_receive_element() called.\n");
    
    /* Normally, in this context, we have consumed all the elements in the
     * element array. Anything else means the logic is wrong.
     */
    assert(k3p->element_array_pos == k3p->element_array.size);
    k3p->element_array_pos = k3p->element_array.size = 0;
    
    /* Try. */
    do {
	/* If the data buffer is empty, obtain some data for the first element. */
	if (k3p->data_buf.len == 0) {
    	    error = k3p_extend_data_buf(k3p, 5);
	    if (error) break;
	}

	/* Read the elements. */
	while (1) {
	    char elem_type[4];
    	    
	    /* If we're at the end of the data buffer, we're done. */
	    if (k3p->data_buf.pos == k3p->data_buf.len) {
		assert(k3p->element_array.size > 0);
		break;
	    }

	    /* Complete the element, if needed. */
	    if (k3p->data_buf.pos + 5 > k3p->data_buf.len) {
		error = k3p_extend_data_buf(k3p, k3p->data_buf.pos + 5 - k3p->data_buf.len);
		if (error) break;
	    }

	    /* Read one element. */
	    kbuffer_read(&k3p->data_buf, elem_type, 3);			
	    elem_type[3] = 0;

	    if (strcmp(elem_type, "INT") == 0) {
		error = k3p_parse_int(k3p);
		if (error) break;
	    }

	    else if (strcmp(elem_type, "INS") == 0) {
		error = k3p_parse_ins(k3p);
		if (error) break;
	    }

	    else if (strcmp(elem_type, "STR") == 0) {
		error = k3p_parse_str(k3p);
		if (error) break;
	    }

	    else {
		kmo_seterror("invalid K3P element type (%s)", elem_type);
		error = -1;
		break;
	    }
	}
	
	if (error) break;
	
    } while (0);
    
    /* Disconnect if an error occurred. */
    if (error) k3p_proto_disconnect(k3p);
    
    /* Shrink the data buffer. */
    kbuffer_shrink(&k3p->data_buf, DATA_BUF_SIZE);
    
    return error;
}

/* This function reads the element specified in the memory location specified.
 * It is used to compact the code.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int k3p_consume_next_element(struct k3p_proto *k3p, int type, void *loc) {
    int error = 0;
    struct k3p_element *el = NULL;
    
    kmod_log_msg(3, "k3p_consume_next_element() called.\n");
    
    /* Try. */
    do {
    	/* Read more elements, if needed. */
    	if (k3p->element_array_pos == k3p->element_array.size) {
	    k3p->element_array_pos = k3p->element_array.size = 0;
	    error = k3p_receive_element(k3p);
	    if (error) break;
	}
	
	el = (struct k3p_element *) k3p->element_array.data[k3p->element_array_pos];
	k3p->element_array_pos++; 
    	
	if (el->type != type) {
	    kmo_seterror("expected K3P type %s, got %s", k3p_get_element_desc(type), k3p_get_element_desc(el->type));
	    error = -1;
	    break;
	}
	
	if (type == K3P_EL_INS || type == K3P_EL_INT) {
	    *(uint32_t *) loc = el->value;
	}
	
	else {
	    kstr_assign_buf((kstr *) loc, el->str, el->value);
	}
	
    } while (0);
    
    if (error) k3p_proto_disconnect(k3p);

    k3p_element_destroy(el);
    return error;
}

/* This function reads an instruction from the remote side.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int k3p_read_inst(k3p_proto *k3p, uint32_t *i) {
    kmod_log_msg(3, "k3p_read_inst() called.\n");
    return k3p_consume_next_element(k3p, K3P_EL_INS, i);
}

/* This function reads a 32 bit unsigned integer from the remote side.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int k3p_read_uint32(k3p_proto *k3p, uint32_t *i) {
    kmod_log_msg(3, "k3p_read_uint32() called.\n");
    return k3p_consume_next_element(k3p, K3P_EL_INT, i);
}

/* This function reads a kstr from the remote side.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int k3p_read_kstr(k3p_proto *k3p, kstr *str) {
    kmod_log_msg(3, "k3p_read_kstr() called.\n");
    return k3p_consume_next_element(k3p, K3P_EL_STR, str);
}

/* This function writes an instruction to the remote side.
 * The data is not sent until a send operation is requested.
 */
void k3p_write_inst(k3p_proto *k3p, uint32_t i) {
    char buf[12];
    int len = sprintf(buf, "INS%08x", i);
    
    kmod_log_msg(3, "k3p_write_inst() called.\n");
    
    assert(len == 11);
    len = 0;
    kbuffer_write(&k3p->data_buf, buf, 11);
    
    if (k3p_log) {
    	if (k3p_log_mode != 2) { k3p_log_mode = 2; fprintf(k3p_log, "\nOUTPUT>\n"); }
    	fprintf(k3p_log, "%s\n", buf);
    }
}

/* This function writes a 32 bit unsigned integer to the remote side.
 * The data is not sent until a send operation is requested.
 */
void k3p_write_uint32(k3p_proto *k3p, uint32_t i) {
    char buf[15];
    int len = sprintf(buf, "INT%u>", i);
    
    kmod_log_msg(3, "k3p_write_uint32() called.\n");
    
    assert(len <= 14);
    kbuffer_write(&k3p->data_buf, buf, len);
    
    if (k3p_log) {
    	if (k3p_log_mode != 2) { k3p_log_mode = 2; fprintf(k3p_log, "\nOUTPUT>\n"); }
    	fprintf(k3p_log, "%s\n", buf);
    }
}

/* This function writes a kstr to the remote side.
 * The data is not sent until a send operation is requested.
 */
void k3p_write_kstr(k3p_proto *k3p, kstr *str) {
    char buf[15];
    int len = sprintf(buf, "STR%u>", str->slen);
    
    kmod_log_msg(3, "k3p_write_kstr() called.\n");
    
    assert(len <= 14);
    kbuffer_write(&k3p->data_buf, buf, len);
    kbuffer_write(&k3p->data_buf, str->data, str->slen);
    
    if (k3p_log) {
    	if (k3p_log_mode != 2) { k3p_log_mode = 2; fprintf(k3p_log, "\nOUTPUT>\n"); }
    	fprintf(k3p_log, "%s", buf);
	fwrite(str->data, 1, str->slen, k3p_log);
	fprintf(k3p_log, "\n");
    }
}

/* This function sends the data written to the remote side.
 * This function sets the KMO error string. It returns -1 on failure.
 */
int k3p_send_data(k3p_proto *k3p) {
    kmod_log_msg(3, "k3p_send_data() called.\n");
    
    k3p->transfer.read_flag = 0;
    k3p->transfer.buf = k3p->data_buf.data;
    k3p->transfer.min_len = k3p->data_buf.len;
    k3p->transfer.max_len = k3p->data_buf.len;
    k3p->transfer.op_timeout = k3p->timeout_enabled ? k3p->timeout : 0;
    
    if (k3p_perform_transfer(k3p)) {
    	k3p_proto_disconnect(k3p);
    	return -1;
    }
    
    kbuffer_shrink(&k3p->data_buf, DATA_BUF_SIZE);
    return 0;
}

/* Boring yet necessary code. Automatically generated for the most part. 
 * In retrospect 'clear' functions would have been nice here. 
 */
void k3p_init_mail_body(struct kmod_mail_body *self) {
    memset(self, 0, sizeof(struct kmod_mail_body));
    kstr_init(&self->text);
    kstr_init(&self->html);
}

void k3p_free_mail_body(struct kmod_mail_body *self) {
    if (self == NULL) return;
    kstr_free(&self->text);
    kstr_free(&self->html);
}

int k3p_read_mail_body(k3p_proto *k3p, struct kmod_mail_body *self) {
    if (k3p_read_uint32(k3p, &self->type)) return -1;
    if (k3p_read_kstr(k3p, &self->text)) return -1;
    if (k3p_read_kstr(k3p, &self->html)) return -1;
    return 0;
}

void k3p_write_mail_body(k3p_proto *k3p, struct kmod_mail_body *self) {
    k3p_write_uint32(k3p, self->type);
    k3p_write_kstr(k3p, &self->text);
    k3p_write_kstr(k3p, &self->html);
}

void k3p_init_mail_attachment(struct kmod_mail_attachment *self) {
    memset(self, 0, sizeof(struct kmod_mail_attachment));
    kstr_init(&self->data);
    kstr_init(&self->name);
    kstr_init(&self->encoding);
    kstr_init(&self->mime_type);
}

void k3p_free_mail_attachment(struct kmod_mail_attachment *self) {
    if (self == NULL) return;
    kstr_free(&self->data);
    kstr_free(&self->name);
    kstr_free(&self->encoding);
    kstr_free(&self->mime_type);
}

int k3p_read_mail_attachment(k3p_proto *k3p, struct kmod_mail_attachment *self) {
    if (k3p_read_uint32(k3p, &self->tie)) return -1;
    if (k3p_read_uint32(k3p, &self->data_is_file_path)) return -1;
    if (k3p_read_kstr(k3p, &self->data)) return -1;
    if (k3p_read_kstr(k3p, &self->name)) return -1;
    if (k3p_read_kstr(k3p, &self->encoding)) return -1;
    if (k3p_read_kstr(k3p, &self->mime_type)) return -1;
    return 0;
}

void k3p_write_mail_attachment(k3p_proto *k3p, struct kmod_mail_attachment *self) {
    k3p_write_uint32(k3p, self->tie);
    k3p_write_uint32(k3p, self->data_is_file_path);
    k3p_write_kstr(k3p, &self->data);
    k3p_write_kstr(k3p, &self->name);
    k3p_write_kstr(k3p, &self->encoding);
    k3p_write_kstr(k3p, &self->mime_type);
}

void k3p_init_otut(struct kmod_otut *self) {
    memset(self, 0, sizeof(struct kmod_otut));
    kstr_init(&self->entry_id);
    kstr_init(&self->reply_addr);
    kstr_init(&self->msg);
}

void k3p_free_otut(struct kmod_otut *self) {
    if (self == NULL) return;
    kstr_free(&self->entry_id);
    kstr_free(&self->reply_addr);
    kstr_free(&self->msg);
}

int k3p_read_otut(k3p_proto *k3p, struct kmod_otut *self) {
    if (k3p_read_uint32(k3p, &self->status)) return -1;
    if (k3p_read_kstr(k3p, &self->entry_id)) return -1;
    if (k3p_read_kstr(k3p, &self->reply_addr)) return -1;
    if (k3p_read_kstr(k3p, &self->msg)) return -1;
    return 0;
}

void k3p_write_otut(k3p_proto *k3p, struct kmod_otut *self) {
    k3p_write_uint32(k3p, self->status);
    k3p_write_kstr(k3p, &self->entry_id);
    k3p_write_kstr(k3p, &self->reply_addr);
    k3p_write_kstr(k3p, &self->msg);
}

void k3p_init_mail(struct kmod_mail *self) {
    memset(self, 0, sizeof(struct kmod_mail));
    kstr_init(&self->msg_id);
    kstr_init(&self->recipient_list);
    kstr_init(&self->from_name);
    kstr_init(&self->from_addr);
    kstr_init(&self->to);
    kstr_init(&self->cc);
    kstr_init(&self->subject);
    k3p_init_mail_body(&self->body);
    karray_init(&self->attachments);
    k3p_init_otut(&self->otut);
}

void k3p_free_mail(struct kmod_mail *self) {
    uint32_t i;
     
    if (self == NULL) return;
    kstr_free(&self->msg_id);
    kstr_free(&self->recipient_list);
    kstr_free(&self->from_name);
    kstr_free(&self->from_addr);
    kstr_free(&self->to);
    kstr_free(&self->cc);
    kstr_free(&self->subject);
    k3p_free_mail_body(&self->body);
    
    for (i = 0; i < (uint32_t) self->attachments.size; i++) {
    	struct kmod_mail_attachment *att = self->attachments.data[i];
    	k3p_free_mail_attachment(att);
	free(att);
    }
	
    karray_free(&self->attachments);
    
    k3p_free_otut(&self->otut);
}

int k3p_read_mail(k3p_proto *k3p, struct kmod_mail *self) {
    uint32_t i, nb;
    
    for (i = 0; i < (uint32_t) self->attachments.size; i++) {
    	struct kmod_mail_attachment *att = self->attachments.data[i];
    	k3p_free_mail_attachment(att);
	free(att);
    }
	
    self->attachments.size = 0;
    
    if (k3p_read_kstr(k3p, &self->msg_id)) return -1;
    if (k3p_read_kstr(k3p, &self->recipient_list)) return -1;
    if (k3p_read_kstr(k3p, &self->from_name)) return -1;
    if (k3p_read_kstr(k3p, &self->from_addr)) return -1;
    if (k3p_read_kstr(k3p, &self->to)) return -1;
    if (k3p_read_kstr(k3p, &self->cc)) return -1;
    if (k3p_read_kstr(k3p, &self->subject)) return -1;
    if (k3p_read_mail_body(k3p, &self->body)) return -1;
    
    if (k3p_read_uint32(k3p, &nb)) return -1;
    
    for (i = 0; i < nb; i++) {
    	struct kmod_mail_attachment *att = kmo_calloc(sizeof(struct kmod_mail_attachment));
	k3p_init_mail_attachment(att);
	karray_add(&self->attachments, att);
	if (k3p_read_mail_attachment(k3p, att)) return -1;
    }
    
    if (k3p_read_otut(k3p, &self->otut)) return -1;
    return 0;
}

void k3p_write_mail(k3p_proto *k3p, struct kmod_mail *self) {
    uint32_t i;
     
    k3p_write_kstr(k3p, &self->msg_id);
    k3p_write_kstr(k3p, &self->recipient_list);
    k3p_write_kstr(k3p, &self->from_name);
    k3p_write_kstr(k3p, &self->from_addr);
    k3p_write_kstr(k3p, &self->to);
    k3p_write_kstr(k3p, &self->cc);
    k3p_write_kstr(k3p, &self->subject);
    k3p_write_mail_body(k3p, &self->body);
    
    k3p_write_uint32(k3p, self->attachments.size);
    
    for (i = 0; i < (uint32_t) self->attachments.size; i++) {
    	struct kmod_mail_attachment *att = self->attachments.data[i];
	k3p_write_mail_attachment(k3p, att);
    }
    
    k3p_write_otut(k3p, &self->otut);
}

void k3p_init_server_info(struct kmod_server_info *self) {
    memset(self, 0, sizeof(struct kmod_server_info));
    kstr_init(&self->kps_login);
    kstr_init(&self->kps_pwd);
    kstr_init(&self->pod_addr);
    kstr_init(&self->kps_net_addr);
    kstr_init(&self->kps_ssl_key);
    kstr_init(&self->kps_proxy_net_addr);
    kstr_init(&self->kps_proxy_login);
    kstr_init(&self->kps_proxy_pwd);
    kstr_init(&self->kos_proxy_net_addr);
    kstr_init(&self->kos_proxy_login);
    kstr_init(&self->kos_proxy_pwd);
}

void k3p_free_server_info(struct kmod_server_info *self) {
    if (self == NULL) return;
    kstr_free(&self->kps_login);
    kstr_free(&self->kps_pwd);
    kstr_free(&self->pod_addr);
    kstr_free(&self->kps_net_addr);
    kstr_free(&self->kps_ssl_key);
    kstr_free(&self->kps_proxy_net_addr);
    kstr_free(&self->kps_proxy_login);
    kstr_free(&self->kps_proxy_pwd);
    kstr_free(&self->kos_proxy_net_addr);
    kstr_free(&self->kos_proxy_login);
    kstr_free(&self->kos_proxy_pwd);
}

int k3p_read_server_info(k3p_proto *k3p, struct kmod_server_info *self) {
    if (k3p_read_kstr(k3p, &self->kps_login)) return -1;
    if (k3p_read_kstr(k3p, &self->kps_pwd)) return -1;
    if (k3p_read_uint32(k3p, &self->encrypted_pwd_flag)) return -1;
    if (k3p_read_kstr(k3p, &self->pod_addr)) return -1;
    if (k3p_read_kstr(k3p, &self->kps_net_addr)) return -1;
    if (k3p_read_uint32(k3p, &self->kps_port_num)) return -1;
    if (k3p_read_kstr(k3p, &self->kps_ssl_key)) return -1;
    if (k3p_read_uint32(k3p, &self->kps_use_proxy)) return -1;
    if (k3p_read_kstr(k3p, &self->kps_proxy_net_addr)) return -1;
    if (k3p_read_uint32(k3p, &self->kps_proxy_port_num)) return -1;
    if (k3p_read_kstr(k3p, &self->kps_proxy_login)) return -1;
    if (k3p_read_kstr(k3p, &self->kps_proxy_pwd)) return -1;
    if (k3p_read_uint32(k3p, &self->kos_use_proxy)) return -1;
    if (k3p_read_kstr(k3p, &self->kos_proxy_net_addr)) return -1;
    if (k3p_read_uint32(k3p, &self->kos_proxy_port_num)) return -1;
    if (k3p_read_kstr(k3p, &self->kos_proxy_login)) return -1;
    if (k3p_read_kstr(k3p, &self->kos_proxy_pwd)) return -1;
    return 0;
}

void k3p_write_server_info(k3p_proto *k3p, struct kmod_server_info *self) {
    k3p_write_kstr(k3p, &self->kps_login);
    k3p_write_kstr(k3p, &self->kps_pwd);
    k3p_write_uint32(k3p, self->encrypted_pwd_flag);
    k3p_write_kstr(k3p, &self->pod_addr);
    k3p_write_kstr(k3p, &self->kps_net_addr);
    k3p_write_uint32(k3p, self->kps_port_num);
    k3p_write_kstr(k3p, &self->kps_ssl_key);
    k3p_write_uint32(k3p, self->kps_use_proxy);
    k3p_write_kstr(k3p, &self->kps_proxy_net_addr);
    k3p_write_uint32(k3p, self->kps_proxy_port_num);
    k3p_write_kstr(k3p, &self->kps_proxy_login);
    k3p_write_kstr(k3p, &self->kps_proxy_pwd);
    k3p_write_uint32(k3p, self->kos_use_proxy);
    k3p_write_kstr(k3p, &self->kos_proxy_net_addr);
    k3p_write_uint32(k3p, self->kos_proxy_port_num);
    k3p_write_kstr(k3p, &self->kos_proxy_login);
    k3p_write_kstr(k3p, &self->kos_proxy_pwd);
}

void k3p_init_mua(struct kmod_mua *self) {
    memset(self, 0, sizeof(struct kmod_mua));
    kstr_init(&self->release);
}

void k3p_free_mua(struct kmod_mua *self) {
    if (self == NULL) return;
    kstr_free(&self->release);
}

int k3p_read_mua(k3p_proto *k3p, struct kmod_mua *self) {
    if (k3p_read_uint32(k3p, &self->product)) return -1;
    if (k3p_read_uint32(k3p, &self->version)) return -1;
    if (k3p_read_kstr(k3p, &self->release)) return -1;
    if (k3p_read_uint32(k3p, &self->kmod_major)) return -1;
    if (k3p_read_uint32(k3p, &self->kmod_minor)) return -1;
    if (k3p_read_uint32(k3p, &self->incoming_attachment_is_file_path)) return -1;
    if (k3p_read_uint32(k3p, &self->lang)) return -1;
    return 0;
}

void k3p_write_mua(k3p_proto *k3p, struct kmod_mua *self) {
    k3p_write_uint32(k3p, self->product);
    k3p_write_uint32(k3p, self->version);
    k3p_write_kstr(k3p, &self->release);
    k3p_write_uint32(k3p, self->kmod_major);
    k3p_write_uint32(k3p, self->kmod_minor);
    k3p_write_uint32(k3p, self->incoming_attachment_is_file_path);
    k3p_write_uint32(k3p, self->lang);
}

void k3p_init_recipient_pwd(struct kmod_recipient_pwd *self) {
    memset(self, 0, sizeof(struct kmod_recipient_pwd));
    kstr_init(&self->recipient);
    kstr_init(&self->password);
}

void k3p_free_recipient_pwd(struct kmod_recipient_pwd *self) {
    if (self == NULL) return;
    kstr_free(&self->recipient);
    kstr_free(&self->password);
}

int k3p_read_recipient_pwd(k3p_proto *k3p, struct kmod_recipient_pwd *self) {
    if (k3p_read_kstr(k3p, &self->recipient)) return -1;
    if (k3p_read_kstr(k3p, &self->password)) return -1;
    if (k3p_read_uint32(k3p, &self->give_otut)) return -1;
    if (k3p_read_uint32(k3p, &self->save_pwd)) return -1;
    return 0;
}

void k3p_write_recipient_pwd(k3p_proto *k3p, struct kmod_recipient_pwd *self) {
    k3p_write_kstr(k3p, &self->recipient);
    k3p_write_kstr(k3p, &self->password);
    k3p_write_uint32(k3p, self->give_otut);
    k3p_write_uint32(k3p, self->save_pwd);
}

void k3p_init_mail_process_req(struct kmod_mail_process_req *self) {
    memset(self, 0, sizeof(struct kmod_mail_process_req));
    k3p_init_mail(&self->mail);
    kstr_init(&self->decryption_pwd);
    kstr_init(&self->recipient_mail_address);
}

void k3p_free_mail_process_req(struct kmod_mail_process_req *self) {
    if (self == NULL) return;
    k3p_free_mail(&self->mail);
    kstr_free(&self->decryption_pwd);
    kstr_free(&self->recipient_mail_address);
}

int k3p_read_mail_process_req(k3p_proto *k3p, struct kmod_mail_process_req *self) {
    if (k3p_read_mail(k3p, &self->mail)) return -1;
    if (k3p_read_uint32(k3p, &self->decrypt)) return -1;
    if (k3p_read_kstr(k3p, &self->decryption_pwd)) return -1;
    if (k3p_read_uint32(k3p, &self->save_pwd)) return -1;
    if (k3p_read_uint32(k3p, &self->ack_pod)) return -1;
    if (k3p_read_kstr(k3p, &self->recipient_mail_address)) return -1;
    return 0;
}

void k3p_write_mail_process_req(k3p_proto *k3p, struct kmod_mail_process_req *self) {
    k3p_write_mail(k3p, &self->mail);
    k3p_write_uint32(k3p, self->decrypt);
    k3p_write_kstr(k3p, &self->decryption_pwd);
    k3p_write_uint32(k3p, self->save_pwd);
    k3p_write_uint32(k3p, self->ack_pod);
    k3p_write_kstr(k3p, &self->recipient_mail_address);
}

void k3p_init_tool_info(struct kmod_tool_info *self) {
    memset(self, 0, sizeof(struct kmod_tool_info));
    kstr_init(&self->sig_marker);
    kstr_init(&self->kmod_version);
    kstr_init(&self->k3p_version);
}

void k3p_free_tool_info(struct kmod_tool_info *self) {
    if (self == NULL) return;
    kstr_free(&self->sig_marker);
    kstr_free(&self->kmod_version);
    kstr_free(&self->k3p_version);
}

int k3p_read_tool_info(k3p_proto *k3p, struct kmod_tool_info *self) {
    if (k3p_read_kstr(k3p, &self->sig_marker)) return -1;
    if (k3p_read_kstr(k3p, &self->kmod_version)) return -1;
    if (k3p_read_kstr(k3p, &self->k3p_version)) return -1;
    return 0;
}

void k3p_write_tool_info(k3p_proto *k3p, struct kmod_tool_info *self) {
    k3p_write_kstr(k3p, &self->sig_marker);
    k3p_write_kstr(k3p, &self->kmod_version);
    k3p_write_kstr(k3p, &self->k3p_version);
}

void k3p_init_eval_res_attachment(struct kmod_eval_res_attachment *self) {
    memset(self, 0, sizeof(struct kmod_eval_res_attachment));
    kstr_init(&self->name);
}

void k3p_free_eval_res_attachment(struct kmod_eval_res_attachment *self) {
    if (self == NULL) return;
    kstr_free(&self->name);
}

int k3p_read_eval_res_attachment(k3p_proto *k3p, struct kmod_eval_res_attachment *self) {
    if (k3p_read_kstr(k3p, &self->name)) return -1;
    if (k3p_read_uint32(k3p, &self->status)) return -1;
    return 0;
}

void k3p_write_eval_res_attachment(k3p_proto *k3p, struct kmod_eval_res_attachment *self) {
    k3p_write_kstr(k3p, &self->name);
    k3p_write_uint32(k3p, self->status);
}

void k3p_init_eval_res(struct kmod_eval_res *self) {
    memset(self, 0, sizeof(struct kmod_eval_res));
    kstr_init(&self->sig_msg);
    kstr_init(&self->subscriber_name);
    karray_init(&self->attachments);
    kstr_init(&self->decryption_error_msg);
    kstr_init(&self->default_pwd);
    kstr_init(&self->pod_msg);
    k3p_init_otut(&self->otut);
}

void k3p_free_eval_res(struct kmod_eval_res *self) {
    uint32_t i;
     
    if (self == NULL) return;
    kstr_free(&self->sig_msg);
    kstr_free(&self->subscriber_name);
    
    for (i = 0; i < (uint32_t) self->attachments.size; i++) {
    	struct kmod_eval_res_attachment *att = self->attachments.data[i];
    	k3p_free_eval_res_attachment(att);
	free(att);
    }
	
    karray_free(&self->attachments);
    
    kstr_free(&self->decryption_error_msg);
    kstr_free(&self->default_pwd);
    kstr_free(&self->pod_msg);
    k3p_free_otut(&self->otut);
}

void k3p_clear_eval_res(struct kmod_eval_res *self) {
    uint32_t i;
    
    for (i = 0; i < (uint32_t) self->attachments.size; i++) {
    	struct kmod_eval_res_attachment *att = self->attachments.data[i];
    	k3p_free_eval_res_attachment(att);
	free(att);
    }
	
    self->attachments.size = 0;
}

int k3p_read_eval_res(k3p_proto *k3p, struct kmod_eval_res *self) {
    uint32_t i, nb;
    
    k3p_clear_eval_res(self);
    
    if (k3p_read_uint32(k3p, &self->display_pref)) return -1;
    if (k3p_read_uint32(k3p, &self->string_status)) return -1;
    if (k3p_read_uint32(k3p, &self->sig_valid)) return -1;
    if (k3p_read_kstr(k3p, &self->sig_msg)) return -1;
    if (k3p_read_uint32(k3p, &self->original_packaging)) return -1;
    if (k3p_read_kstr(k3p, &self->subscriber_name)) return -1;
    if (k3p_read_uint32(k3p, &self->from_name_status)) return -1;
    if (k3p_read_uint32(k3p, &self->from_addr_status)) return -1;
    if (k3p_read_uint32(k3p, &self->to_status)) return -1;
    if (k3p_read_uint32(k3p, &self->cc_status)) return -1;
    if (k3p_read_uint32(k3p, &self->subject_status)) return -1;
    if (k3p_read_uint32(k3p, &self->body_text_status)) return -1;
    if (k3p_read_uint32(k3p, &self->body_html_status)) return -1;
    
    if (k3p_read_uint32(k3p, &nb)) return -1;
    
    for (i = 0; i < nb; i++) {
    	struct kmod_eval_res_attachment *att = kmo_calloc(sizeof(struct kmod_eval_res_attachment));
	k3p_init_eval_res_attachment(att);
	karray_add(&self->attachments, att);
	if (k3p_read_eval_res_attachment(k3p, att)) return -1;
    }
    
    if (k3p_read_uint32(k3p, &self->encryption_status)) return -1;
    if (k3p_read_kstr(k3p, &self->decryption_error_msg)) return -1;
    if (k3p_read_kstr(k3p, &self->default_pwd)) return -1;
    if (k3p_read_uint32(k3p, &self->pod_status)) return -1;
    if (k3p_read_kstr(k3p, &self->pod_msg)) return -1;
    if (k3p_read_otut(k3p, &self->otut)) return -1;
    return 0;
}

void k3p_write_eval_res(k3p_proto *k3p, struct kmod_eval_res *self) {
    uint32_t i;
    
    k3p_write_uint32(k3p, self->display_pref);
    k3p_write_uint32(k3p, self->string_status);
    k3p_write_uint32(k3p, self->sig_valid);
    k3p_write_kstr(k3p, &self->sig_msg);
    k3p_write_uint32(k3p, self->original_packaging);
    k3p_write_kstr(k3p, &self->subscriber_name);
    k3p_write_uint32(k3p, self->from_name_status);
    k3p_write_uint32(k3p, self->from_addr_status);
    k3p_write_uint32(k3p, self->to_status);
    k3p_write_uint32(k3p, self->cc_status);
    k3p_write_uint32(k3p, self->subject_status);
    k3p_write_uint32(k3p, self->body_text_status);
    k3p_write_uint32(k3p, self->body_html_status);

    k3p_write_uint32(k3p, self->attachments.size);
    
    for (i = 0; i < (uint32_t) self->attachments.size; i++) {
    	struct kmod_eval_res_attachment *att = self->attachments.data[i];
	k3p_write_eval_res_attachment(k3p, att);
    }

    k3p_write_uint32(k3p, self->encryption_status);
    k3p_write_kstr(k3p, &self->decryption_error_msg);
    k3p_write_kstr(k3p, &self->default_pwd);
    k3p_write_uint32(k3p, self->pod_status);
    k3p_write_kstr(k3p, &self->pod_msg);
    k3p_write_otut(k3p, &self->otut);
}
