#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libetpan/libetpan.h>
#include <errno.h>
#include <assert.h>
#include <stdarg.h>

/* Maximum number of attachments we will support. */
#define TKPP_MAX_ATTACHMENT 50

/* This macro checks if the memory got allocated, and if not, it sets the error
 * string and returns -1.
 */
#define RETURN_ON_OOM(value) if (value == NULL) { set_error("out of memory"); return -1; }

/* This object represents a MIME part (body / attachment. */
struct tkpp_mime_part
{
	/* Mail part name, if any. */
	char *name;

	/* Mail part data. */
	char *data;

	/* Mail part data len. */
	int data_len;
};

/* This function frees a tkpp_mime_part object. */
void tkpp_mime_part_free(struct tkpp_mime_part *part)
{
	if (part == NULL) return;
	free(part->name);
	free(part->data);
}

/* This function represents the content of an email. */
struct tkpp_mail_content
{
	/* If true, the mail seems to have been produced by Outlook. We must be
	* cautious.
	*/
	int outlook_flag;

	/* If true, the body is expected to be in the next mime part. */
	int body_flag;

	/* From name, from address, to, cc, subject. */
	char *from_name;
	char *from_addr;
	char *to;
	char *cc;
	char *subject;

	/* Text and HTML bodies, if they were found. */
	tkpp_mime_part text_body;
	tkpp_mime_part html_body;

	/* Array of attachments. A pity we don't have a dynamic array
	* implementation.
	*/
	struct tkpp_mime_part att_array[TKPP_MAX_ATTACHMENT];
	int nb_att;
};

/* This function frees a tkpp_mail_content object. */
void tkpp_mail_content_free(struct tkpp_mail_content *content)
{
	int i;

	if (content == NULL) return;
	
	free(content->from_name);
	free(content->from_addr);
	free(content->to);
	free(content->cc);
	free(content->subject);
	
	tkpp_mime_part_free(&content->text_body);
	tkpp_mime_part_free(&content->html_body);

	for (i = 0; i < content->nb_att; i++)
	{
		tkpp_mime_part_free(&content->att_array[i]);
	}
}

class MyComponent
{
	public:
	
	/* String describing the last error that occurred. */    
	char *err_str;
	
	MyComponent();
	~MyComponent();
	void set_error(char *format, ...);
	int decode_mime_part(struct tkpp_mime_part *part, struct mailmime_data *mime_data);
	int process_multiple_part(struct tkpp_mail_content *content, struct mailmime *mime);
	int process_single_part(struct tkpp_mail_content *content, struct mailmime *mime);
	int get_optional_header_info(struct tkpp_mail_content *content, struct mailimf_optional_field *field);
	int get_subject_header_info(struct tkpp_mail_content *content, struct mailimf_subject *subject_obj);
	int merge_addr_list(struct mailimf_address_list *addr_list, char **str);
	int get_cc_header_info(struct tkpp_mail_content *content, struct mailimf_cc *cc);
	int get_to_header_info(struct tkpp_mail_content *content, struct mailimf_to *to);
	int get_from_header_info(struct tkpp_mail_content *content, struct mailimf_from *from);
	int extract_header_info(struct tkpp_mail_content *content, struct mailimf_fields *headers);
	int get_mail_content(struct tkpp_mail_content *content, struct mailmime *mime);
	int get_mail_content(struct tkpp_mail_content *content, char *mail_data, int mail_data_len);
};

MyComponent::MyComponent()
{
	err_str = NULL;
}

MyComponent::~MyComponent()
{
	free(err_str);
}

/* This function formats and sets an error message with the handle specified.
 * If the handle already points to an error message, the error message is freed.
 * The handle is set to NULL if no memory is available for storing the error
 * message.
 */
void MyComponent::set_error(char *format, ...)
{
	va_list arg;
	int print_size;

	free(err_str);
	va_start(arg, format);

	print_size = vsnprintf(NULL, 0, format, arg);
	err_str = (char *) malloc(print_size + 1);

	if (err_str)
	{
		vsnprintf(err_str, print_size + 1, format, arg);
	}
    
	va_end(arg);
}

/* This function decodes a mime part.
 * It returns 0 on success and -1 on failure.
 */
int MyComponent::decode_mime_part(struct tkpp_mime_part *part, struct mailmime_data *mime_data)
{
	size_t index = 0;
	char *decode_text;
	size_t decode_text_len;
	
	if (mailmime_part_parse(mime_data->dt_data.dt_text.dt_data, mime_data->dt_data.dt_text.dt_length, &index, 
				mime_data->dt_encoding, &decode_text, &decode_text_len) != MAILIMF_NO_ERROR)
	{
		set_error("cannot decode mime part");
		return -1;
	}

	part->data = (char *) malloc(decode_text_len + 1);
	
	if (part->data == NULL)
	{
		mmap_string_unref(decode_text);
		set_error("out of memory");
		return -1;
	}
	
	memcpy(part->data, decode_text, decode_text_len);
	part->data[decode_text_len] = 0;
	part->data_len = decode_text_len;
	mmap_string_unref(decode_text);
	return 0;
}

/* This function processes a MIME part that contains multiple parts.
 * It returns 0 on success and -1 on failure.
 */
int MyComponent::process_multiple_part(struct tkpp_mail_content *content, struct mailmime *mime)
{
	assert(mime->mm_type == MAILMIME_MULTIPLE);
	struct mailmime_content *mime_type = mime->mm_content_type;
	clistiter *iter;
	
	if (strcasecmp(mime_type->ct_subtype, "mixed") && 
	    strcasecmp(mime_type->ct_subtype, "related") &&
	    strcasecmp(mime_type->ct_subtype, "alternative"))
	{
		set_error("unsupported multipart type (%s)", mime_type->ct_subtype);
		return -1;
	}
	
	/* We don't support alternative attachments. */
	if (! strcasecmp(mime_type->ct_subtype, "alternative") && ! content->body_flag)
	{
		set_error("unexpected alternative attachment");
		return -1;
	}
	
	/* Pass every enclosed parts. */
	if (mime->mm_data.mm_multipart.mm_mp_list)
	{
		for (iter = clist_begin(mime->mm_data.mm_multipart.mm_mp_list); iter != NULL; iter = clist_next(iter))
		{
			struct mailmime *part = (struct mailmime *) clist_content(iter);
			
			if (part->mm_type == MAILMIME_SINGLE)
			{
				if (process_single_part(content, part))
				{
					return -1;
				}
				
				/* In multipart/alternative, all parts contain a body.
				 * In other modes, only the first part might contain a body.
				 */
				if (strcasecmp(mime_type->ct_subtype, "alternative") != 0)
				{
					content->body_flag = 0;
				}
			}

			else if (part->mm_type == MAILMIME_MULTIPLE) 
			{
				/* This should not happen. */
				if (! strcasecmp(mime_type->ct_subtype, "alternative"))
				{
					set_error("unexpected complex alternative part");
					return -1;
				}
				
				if (process_multiple_part(content, part))
				{
					return -1;
				}
			}

			else
			{
				set_error("unexpected mime part type (%d)", part->mm_type);
				return -1;
			}
		}
	}
	
	/* In all cases, we don't expect a body anymore. */
	content->body_flag = 0;
	
	return 0;
}

/* This function processes a single MIME part.
 * It returns 0 on success and -1 on failure.
 */
int MyComponent::process_single_part(struct tkpp_mail_content *content, struct mailmime *mime)
{
	assert(mime->mm_type == MAILMIME_SINGLE);
	struct mailmime_content *mime_type = mime->mm_content_type;
	struct mailmime_data *mime_data = mime->mm_data.mm_single;
	
	if (mime_data->dt_type != MAILMIME_DATA_TEXT)
	{
		set_error("unexpected mime data type (%d)", mime_data->dt_type);
		return -1;
	}
	
	/* We're expecting a body. It has better be text/plain or text/html. */
	if (content->body_flag)
	{
		assert(mime_type->ct_type->tp_type == MAILMIME_TYPE_DISCRETE_TYPE);
		struct mailmime_discrete_type *mime_discrete = mime_type->ct_type->tp_data.tp_discrete_type;
	
		if (mime_discrete->dt_type != MAILMIME_DISCRETE_TYPE_TEXT)
		{
			set_error("expected body in mime part, got type %d.\n", mime_discrete->dt_type);
			return -1;
		}
	
		if (! strcasecmp(mime_type->ct_subtype, "plain"))
		{
			if (content->text_body.data)
			{
				set_error("duplicate text body");
				return -1;
			}
			
			if (decode_mime_part(&content->text_body, mime_data))
			{
				return -1;
			}
		}

		else if (! strcasecmp(mime_type->ct_subtype, "html"))
		{
			if (content->html_body.data)
			{
				set_error("duplicate HTML body");
				return -1;
			}
			
			if (decode_mime_part(&content->html_body, mime_data))
			{
				return -1;
			}
		}

		else
		{
			set_error("unsupported body type (%s)", mime_type->ct_subtype);
			return -1;
		}
	}
	
	/* We're expecting an attachment. We must find a 'name=filename' parameter. */
	else
	{
		char *att_name = NULL;
		clistiter *iter;
		struct tkpp_mime_part *part;
		
		if (content->nb_att >= TKPP_MAX_ATTACHMENT)
		{
			set_error("too many attachments");
			return -1;
		}
		
		if (mime_type->ct_parameters != NULL)
		{
			for (iter = clist_begin(mime_type->ct_parameters); iter != NULL; iter = clist_next(iter))
			{
				struct mailmime_parameter *param = (struct mailmime_parameter *) clist_content(iter);
				
				if (! strcasecmp("name", param->pa_name))
				{
					att_name = param->pa_value;
					break;
				}
			}
		}
		
		if (att_name == NULL)
		{
			set_error("attachment name not found");
			return -1;
		}
		
		part = &content->att_array[content->nb_att];
		content->nb_att++;
		
		part->name = strdup(att_name);
		RETURN_ON_OOM(part->name);
		
		if (decode_mime_part(part, mime_data))
		{
			return -1;
		}
	}
	
	return 0;
}

/* This function processes an optional header.
 * It returns 0 on success and -1 on failure.
 */
int MyComponent::get_optional_header_info(struct tkpp_mail_content *content, struct mailimf_optional_field *field)
{
	if (field == NULL) return 0;
	
	if (! strcasecmp(field->fld_name, "X-Mailer") && strstr(field->fld_value, "Outlook"))
	{
		content->outlook_flag = 1;
	}
	
	return 0;
}

/* This function processes a subject header.
 * It returns 0 on success and -1 on failure.
 */
int MyComponent::get_subject_header_info(struct tkpp_mail_content *content, struct mailimf_subject *subject_obj)
{
	if (content->subject != NULL)
	{
		set_error("duplicate subject header");
		return -1;
	}
	
	if (subject_obj == NULL || subject_obj->sbj_value == NULL) return 0;
	content->subject = strdup(subject_obj->sbj_value);
	RETURN_ON_OOM(content->subject);
	
	return 0;
}

/* This function merges a list of TO/CC addresses inside a single string. The
 * string must be free()'ed by the caller.
 * It returns 0 on success and -1 on failure.
 */
int MyComponent::merge_addr_list(struct mailimf_address_list *addr_list, char **str)
{
	clistiter *iter;
	int current_pos = 0;
	int total_len = 0;
	int first_flag = 1;
	
	/* Compute total string length. */
	for (iter = clist_begin(addr_list->ad_list); iter != NULL; iter = clist_next(iter))
	{
		struct mailimf_address *addr = (struct mailimf_address *) clist_content(iter);
		
		if (addr->ad_type == MAILIMF_ADDRESS_MAILBOX)
		{
			if (first_flag)
			{
				first_flag = 0;
			}
			
			else
			{
				total_len += 2;
			}
			
			total_len += strlen(addr->ad_data.ad_mailbox->mb_addr_spec);
		}
	}
	
	/* Allocate the string. */
	*str = (char *) malloc(total_len + 1);
	RETURN_ON_OOM(*str);
	(*str)[total_len] = 0;
	
	/* Merge the strings. */
	first_flag = 1;
	
	for (iter = clist_begin(addr_list->ad_list); iter != NULL; iter = clist_next(iter))
	{
		struct mailimf_address *addr = (struct mailimf_address *) clist_content(iter);
		
		if (addr->ad_type == MAILIMF_ADDRESS_MAILBOX)
		{
			if (first_flag)
			{
				first_flag = 0;
			}
			
			else
			{
				(*str)[current_pos] = ',';
				(*str)[current_pos + 1] = ' ';
				current_pos += 2;
			}
			
			strcpy(*str + current_pos, addr->ad_data.ad_mailbox->mb_addr_spec);
			current_pos += strlen(addr->ad_data.ad_mailbox->mb_addr_spec);
		}
	}
	
	assert(current_pos == total_len);
	return 0;
}

/* This function processes a cc header.
 * It returns 0 on success and -1 on failure.
 */
int MyComponent::get_cc_header_info(struct tkpp_mail_content *content, struct mailimf_cc *cc)
{
	if (content->cc != NULL)
	{
		set_error("duplicate cc header");
		return -1;
	}
	
	if (cc == NULL || cc->cc_addr_list == NULL || cc->cc_addr_list->ad_list == NULL) return 0;
	return merge_addr_list(cc->cc_addr_list, &content->cc);
}

/* This function processes a to header.
 * It returns 0 on success and -1 on failure.
 */
int MyComponent::get_to_header_info(struct tkpp_mail_content *content, struct mailimf_to *to)
{
	if (content->to != NULL)
	{
		set_error("duplicate to header");
		return -1;
	}
	
	if (to == NULL || to->to_addr_list == NULL || to->to_addr_list->ad_list == NULL) return 0;
	return merge_addr_list(to->to_addr_list, &content->to);
}

/* This function processes a from header.
 * It returns 0 on success and -1 on failure.
 */
int MyComponent::get_from_header_info(struct tkpp_mail_content *content, struct mailimf_from *from)
{
	clistiter *iter;
	struct mailimf_mailbox *mailbox;
	
	if (content->from_name != NULL || content->from_addr != NULL)
	{
		set_error("duplicate from header");
		return -1;
	}
	
	if (from == NULL || from->frm_mb_list == NULL || from->frm_mb_list->mb_list == NULL) return 0;
	iter = clist_begin(from->frm_mb_list->mb_list);
	if (iter == NULL) return 0;
	mailbox = (struct mailimf_mailbox *) clist_content(iter);
	
	if (mailbox->mb_display_name != NULL) {
		content->from_name = strdup(mailbox->mb_display_name);
		RETURN_ON_OOM(content->from_name);
	}
	
	content->from_addr = strdup(mailbox->mb_addr_spec);
	RETURN_ON_OOM(content->from_addr);

	return 0;
}

/* This function extracts the headers information.
 * It returns 0 on success and -1 on failure.
 */
int MyComponent::extract_header_info(struct tkpp_mail_content *content, struct mailimf_fields *headers)
{
	clistiter *iter;
	
	/* Analyse the headers. */
	for (iter = clist_begin(headers->fld_list); iter != NULL; iter = clist_next(iter))
	{
		int error = 0;
		struct mailimf_field *header = (struct mailimf_field *) clist_content(iter);
		
		switch (header->fld_type)
		{
			case MAILIMF_FIELD_FROM:
				error = get_from_header_info(content, header->fld_data.fld_from);
				break;

			case MAILIMF_FIELD_TO:
				error = get_to_header_info(content, header->fld_data.fld_to);
				break;

			case MAILIMF_FIELD_CC:
				error = get_cc_header_info(content, header->fld_data.fld_cc);
				break;

			case MAILIMF_FIELD_SUBJECT:
				error = get_subject_header_info(content, header->fld_data.fld_subject);
				break;

			case MAILIMF_FIELD_OPTIONAL_FIELD:
				error = get_optional_header_info(content, header->fld_data.fld_optional_field);
				break;
		}
	
		if (error) return error;
	}
	
	return 0;
}

/* This function extracts the mail information.
 * It returns 0 on success and -1 on failure.
 */
int MyComponent::get_mail_content(struct tkpp_mail_content *content, struct mailmime *mime)
{
	/* The first MIME part should be a message. */
	if (mime->mm_type != MAILMIME_MESSAGE)
	{
		set_error("first MIME part is not a rfc822 message");
		return -1;
	}
	
	/* Extract the header information, if any. */
	if (mime->mm_data.mm_message.mm_fields)
	{
		if (extract_header_info(content, mime->mm_data.mm_message.mm_fields))
		{
			return -1;
		}
	}
	
	/* Extract the bodies and attachments, if any. */
	if (mime->mm_data.mm_message.mm_msg_mime)
	{
		content->body_flag = 1;
		struct mailmime *part = mime->mm_data.mm_message.mm_msg_mime;
		
		if (part->mm_type == MAILMIME_SINGLE)
		{
			if (process_single_part(content, part))
			{
				return -1;
			}
		}
		
		else if (part->mm_type == MAILMIME_MULTIPLE) 
		{
			if (process_multiple_part(content, part))
			{
				return -1;
			}
		}
		
		else
		{
			set_error("unexpected mime part type (%d)", part->mm_type);
			return -1;
		}
	}
	
	if (content->text_body.data == NULL && content->html_body.data == NULL)
	{
		set_error("no body found in message");
		return -1;
	}
	
	/* If Outlook made this mail and there are both an HTML body and a text body,
	 * skip the text body unless the Outlook conversion string is found inside
	 * the HTML. In the latter case, skip the HTML body instead.
	 */
	if (content->outlook_flag && content->text_body.data && content->html_body.data)
	{
		struct tkpp_mime_part *bogus_body = &content->text_body;
		
		if (strstr(content->html_body.data, "<!-- Converted from text/plain format -->"))
		{
			bogus_body = &content->html_body;
		}

		tkpp_mime_part_free(bogus_body);
		memset(bogus_body, 0, sizeof (struct tkpp_mime_part));
	}
	
	return 0;
}

/* This function parses a mail and extracts the information it contains.
 * It returns 0 on success and -1 on failure.
 */
int MyComponent::get_mail_content(struct tkpp_mail_content *content, char *mail_data, int mail_data_len)
{
	int error;
	size_t current_index = 0;
	struct mailmime *mime = NULL;
	
	/* Parse the mail. */
	error = mailmime_parse(mail_data, mail_data_len, &current_index, &mime);
	
	if (error != MAILIMF_NO_ERROR)
	{
		set_error("failed to parse mail (error %d)", error);
		return -1;
	}
	
	/* Extract the content. */
	error = get_mail_content(content, mime);
	mailmime_free(mime);
	return error;
}

void nprint(const char *str, int len)
{
	int i;
	
	for (i = 0; i < len; i++)
	{
		if (str[i] == 0) break;
		printf("%c", str[i]);	
	}
}

int main(int argc, char **argv)
{
	int fd;
	int error;
	struct stat stat_info;
	char *msg_buf;
	MyComponent component;
	struct tkpp_mail_content content;
	
	memset(&content, 0, sizeof (struct tkpp_mail_content)); 
	
	if (argc == 0)
	{
		printf("No program name specified.\n");
		return 1;
	}

	if (argc != 2)
	{
		printf("Usage: %s <path_to_mail>\n", argv[0]);
		return 1;
	}
	
	fd = open(argv[1], O_RDONLY);
	
	if (fd == -1)
	{
		printf("Cannot open %s: %s.\n", argv[1], strerror(errno));
		return 1;
	}
	
	error = fstat(fd, &stat_info);
	
	if (error == -1)
	{
		printf("Cannot stat %s: %s.\n", argv[1], strerror(errno));
		return 1;
	}
	
	msg_buf = (char *) mmap(NULL, stat_info.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	
	if (msg_buf == MAP_FAILED)
	{
		printf("Cannot allocate memory for %s: %s.\n", argv[1], strerror(errno));
		return 1;
	}
	
	error = component.get_mail_content(&content, msg_buf, stat_info.st_size);
	
	if (error)
	{
		printf("Error: %s.\n", component.err_str);
	}
	
	else
	{
		printf("From name: %s.\n", content.from_name);
		printf("From addr: %s.\n", content.from_addr);
		printf("Subject: %s.\n", content.subject);
		printf("To: %s.\n", content.to);
		printf("CC: %s.\n", content.cc);
		printf("\n\n");
		
		if (content.text_body.data)
		{
			printf("Decoded text body:\n");
			nprint(content.text_body.data, content.text_body.data_len);
			printf("\n\n");
		}
		
		if (content.html_body.data)
		{
			printf("Decoded html body:\n");
			nprint(content.html_body.data, content.html_body.data_len);
			printf("\n\n");
		}
		
		for (int i = 0; i < content.nb_att; i++)
		{
			printf("Decoded attachment %s (%d bytes):\n", content.att_array[i].name,
			    	    	    	    	    	      content.att_array[i].data_len);
			nprint(content.att_array[i].data, content.att_array[i].data_len);
			printf("\n\n");
		}
	}
	
	tkpp_mail_content_free(&content);
	munmap(msg_buf, stat_info.st_size);
	close(fd);
	
	return 0;
}
