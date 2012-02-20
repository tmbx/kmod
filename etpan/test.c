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

void print_space(int nb_space)
{
	int i;
	
	for(i = 0; i < nb_space; i++)
	{
		printf(" ");
	}
}

void nprint(const char *str, int len)
{
	int i;
	
	for(i = 0; i < len; i++)
	{
		if(str[i] == 0) break;
		printf("%c", str[i]);	
	}
}

void display_mailbox(struct mailimf_mailbox *mb_ptr, int nb_space)
{
	if(mb_ptr == NULL) return;
	
	if(mb_ptr->mb_display_name != NULL)
	{
	    	size_t cur_token = 0;
	    	char *decoded_text = NULL;
		
		print_space(nb_space);
		printf("Display name: %s\n", mb_ptr->mb_display_name);

		if (mailmime_encoded_phrase_parse("iso-8859-1",
						  mb_ptr->mb_display_name,
						  strlen(mb_ptr->mb_display_name),
						  &cur_token, "iso-8859-1", &decoded_text) != MAILIMF_NO_ERROR)
		{
			printf("Failed to decode display name.\n");
		}
		
		else
		{
			printf("Decoded display name: %s.\n", decoded_text);
		}

		free(decoded_text);
	}
		
	print_space(nb_space);
	printf("Address: %s\n", mb_ptr->mb_addr_spec);
}

void display_mailbox_list(struct mailimf_mailbox_list *mb_list_ptr, int nb_space)
{
	clistiter *iter_ptr;
	
	if(mb_list_ptr == NULL) return;

	for(iter_ptr = clist_begin(mb_list_ptr->mb_list); iter_ptr != NULL; iter_ptr = clist_next(iter_ptr))
	{
		struct mailimf_mailbox *mb_ptr = clist_content(iter_ptr);
		display_mailbox(mb_ptr, nb_space);
	}
}

void display_addr_group(struct mailimf_group *group_ptr, int nb_space)
{
	if(group_ptr == NULL) return;
	
	print_space(nb_space);
	printf("Address group display name: %s\n", group_ptr->grp_display_name);
	
	print_space(nb_space);
	printf("Address group address list:\n");
	display_mailbox_list(group_ptr->grp_mb_list, nb_space);
}

void display_address(struct mailimf_address *addr_ptr, int nb_space)
{
	if(addr_ptr == NULL) return;
	
	switch(addr_ptr->ad_type)
	{
		case MAILIMF_ADDRESS_GROUP:
			display_addr_group(addr_ptr->ad_data.ad_group, nb_space);
			break;

		case MAILIMF_ADDRESS_MAILBOX:
			display_mailbox(addr_ptr->ad_data.ad_mailbox, nb_space);
			break;
	}
}

void display_address_list(struct mailimf_address_list *addr_list_ptr, int nb_space)
{
	clistiter *iter_ptr;
	
	if(addr_list_ptr == NULL) return;

	for(iter_ptr = clist_begin(addr_list_ptr->ad_list); iter_ptr != NULL; iter_ptr = clist_next(iter_ptr))
	{
		struct mailimf_address *addr_ptr = clist_content(iter_ptr);
		display_address(addr_ptr, nb_space);
	}
}

void display_msg_header(struct mailimf_field *field_ptr, int nb_space)
{
	if(field_ptr == NULL) return;
	
	print_space(nb_space);
	printf("Mail header: ");
	switch(field_ptr->fld_type)
	{
		case MAILIMF_FIELD_RETURN_PATH:
			printf("Return-Path.");
			break;
			
		case MAILIMF_FIELD_RESENT_DATE:
			printf("Resent-Date.");
			break;
			
		case MAILIMF_FIELD_RESENT_FROM:
			printf("Resent-From.");
			break;
			
		case MAILIMF_FIELD_RESENT_SENDER:
			printf("Resent-Sender.");
			break;
			
		case MAILIMF_FIELD_RESENT_TO:
			printf("Resent-To.");
			break;
			
		case MAILIMF_FIELD_RESENT_CC:
			printf("Resent-Cc.");
			break;
			
		case MAILIMF_FIELD_RESENT_BCC:
			printf("Resent-Bcc\n");
			break;
			
		case MAILIMF_FIELD_RESENT_MSG_ID:
			printf("Resent-Message-ID\n");
			break;
			
		case MAILIMF_FIELD_ORIG_DATE:
			printf("Date\n");
			break;
			
		case MAILIMF_FIELD_FROM:
			printf("From:\n");
			display_mailbox_list(field_ptr->fld_data.fld_from->frm_mb_list, nb_space + 2);
			break;
			
		case MAILIMF_FIELD_SENDER:
			printf("Sender\n");
			break;
			
		case MAILIMF_FIELD_REPLY_TO:
			printf("Reply-To\n");
			break;
			
		case MAILIMF_FIELD_TO:
			printf("To\n");
			display_address_list(field_ptr->fld_data.fld_to->to_addr_list, nb_space + 2);
			break;
			
		case MAILIMF_FIELD_CC:
			printf("Cc\n");
			display_address_list(field_ptr->fld_data.fld_cc->cc_addr_list, nb_space + 2);
			break;
			
		case MAILIMF_FIELD_BCC:
			printf("Bcc\n");
			break;
			
		case MAILIMF_FIELD_MESSAGE_ID:
			printf("Message-ID\n");
			print_space(nb_space + 2);
			printf("%s\n", field_ptr->fld_data.fld_message_id->mid_value);
			break;
			
		case MAILIMF_FIELD_IN_REPLY_TO:
			printf("In-Reply-To\n");
			break;
			
		case MAILIMF_FIELD_REFERENCES:
			printf("References\n");
			break;
			
		case MAILIMF_FIELD_SUBJECT:
			printf("Subject\n");
			print_space(nb_space + 2);
			printf("%s\n", field_ptr->fld_data.fld_subject->sbj_value);
			break;
			
		case MAILIMF_FIELD_COMMENTS:
			printf("Comments\n");
			break;
			
		case MAILIMF_FIELD_KEYWORDS:
			printf("Keywords\n");
			break;
			
		case MAILIMF_FIELD_OPTIONAL_FIELD:
			printf("%s: %s\n", field_ptr->fld_data.fld_optional_field->fld_name,
					   field_ptr->fld_data.fld_optional_field->fld_value);
			break;
	}
}

void display_msg_headers(struct mailimf_fields *fields_ptr, int nb_space)
{
	if(fields_ptr == NULL) return;
	
	clistiter *iter_ptr;
	
	for(iter_ptr = clist_begin(fields_ptr->fld_list); iter_ptr != NULL; iter_ptr = clist_next(iter_ptr))
	{
		struct mailimf_field *field_ptr = clist_content(iter_ptr);
		display_msg_header(field_ptr, nb_space);
	}
}

void display_mime_disposition(struct mailmime_disposition *md_ptr, int nb_space)
{
	clistiter *iter_ptr;
	
	if(md_ptr == NULL) return;
	
	print_space(nb_space);
	switch(md_ptr->dsp_type->dsp_type)
	{
		case MAILMIME_DISPOSITION_TYPE_INLINE:
			printf("Inline\n");
			break;
		
		case MAILMIME_DISPOSITION_TYPE_ATTACHMENT:
			printf("Attachment\n");
			break;
		
		case MAILMIME_DISPOSITION_TYPE_EXTENSION:
			printf("Extension (%s)\n", md_ptr->dsp_type->dsp_extension);
			break;
	}
	
	if(md_ptr->dsp_parms != NULL)
	{
		for(iter_ptr = clist_begin(md_ptr->dsp_parms); iter_ptr != NULL; iter_ptr = clist_next(iter_ptr))
		{
			struct mailmime_disposition_parm *param_ptr = clist_content(iter_ptr);
			print_space(nb_space);
			switch(param_ptr->pa_type)
			{
				case MAILMIME_DISPOSITION_PARM_FILENAME:
					printf("Filename (%s)\n", param_ptr->pa_data.pa_filename);
					break;
				
				case MAILMIME_DISPOSITION_PARM_CREATION_DATE:
					printf("Creation date (%s)\n", param_ptr->pa_data.pa_creation_date);
					break;
				
				case MAILMIME_DISPOSITION_PARM_MODIFICATION_DATE:
					printf("Modification date (%s)\n", param_ptr->pa_data.pa_modification_date);
					break;
				
				case MAILMIME_DISPOSITION_PARM_READ_DATE:
					printf("Read date (%s)\n", param_ptr->pa_data.pa_read_date);
					break;
				
				case MAILMIME_DISPOSITION_PARM_SIZE:
					printf("Size (%d)\n", param_ptr->pa_data.pa_size);
					break;
				
				case MAILMIME_DISPOSITION_PARM_PARAMETER:
					printf("%s (%s)\n", param_ptr->pa_data.pa_parameter->pa_name,
							    param_ptr->pa_data.pa_parameter->pa_value);
					break;
			}
		}
	}
}

void display_mime_content(struct mailmime_content *mc_ptr, int nb_space)
{
	clistiter *iter_ptr;
	struct mailmime_discrete_type *discrete_ptr;
	struct mailmime_composite_type *composite_ptr;
	
	if(mc_ptr == NULL) return;
	
	print_space(nb_space);
	switch(mc_ptr->ct_type->tp_type)
	{
		case MAILMIME_TYPE_DISCRETE_TYPE:
			discrete_ptr = mc_ptr->ct_type->tp_data.tp_discrete_type;
			
			switch(discrete_ptr->dt_type)
			{
				case MAILMIME_DISCRETE_TYPE_TEXT:
					printf("Type: text\n");
					break;
				
				case MAILMIME_DISCRETE_TYPE_IMAGE:
					printf("Type: image\n");
					break;
				
				case MAILMIME_DISCRETE_TYPE_AUDIO:
					printf("Type: audio\n");
					break;
				
				case MAILMIME_DISCRETE_TYPE_VIDEO:
					printf("Type: video\n");
					break;
				
				case MAILMIME_DISCRETE_TYPE_APPLICATION:
					printf("Type: application\n");
					break;
				
				case MAILMIME_DISCRETE_TYPE_EXTENSION:
					printf("Type: extension (%s)\n", discrete_ptr->dt_extension);
					break;
			}
			
			break;
			
		case MAILMIME_TYPE_COMPOSITE_TYPE:
			composite_ptr = mc_ptr->ct_type->tp_data.tp_composite_type;
			
			switch(composite_ptr->ct_type)
			{
				case MAILMIME_COMPOSITE_TYPE_MESSAGE:
					printf("Type: message\n");
					break;
				
				case MAILMIME_COMPOSITE_TYPE_MULTIPART:
					printf("Type: multipart\n");
					break;
				
				case MAILMIME_COMPOSITE_TYPE_EXTENSION:
					printf("Type: extension (%s)\n", composite_ptr->ct_token);
					break;
			}
			
			break;
	}
	
	print_space(nb_space);
	printf("Subtype: %s\n", mc_ptr->ct_subtype);
	
	if(mc_ptr->ct_parameters != NULL)
	{
		for(iter_ptr = clist_begin(mc_ptr->ct_parameters); iter_ptr != NULL; iter_ptr = clist_next(iter_ptr))
		{
			struct mailmime_parameter *param_ptr = clist_content(iter_ptr);
			print_space(nb_space);
			printf("Parameter: %s = %s\n", param_ptr->pa_name, param_ptr->pa_value);
		}
	}
}

void display_mime_encoding(int encoding)
{
	switch(encoding)
	{
		case MAILMIME_MECHANISM_7BIT:
			printf("7bit\n");
			break;
			
		case MAILMIME_MECHANISM_8BIT:
			printf("8bit\n");
			break;
			
		case MAILMIME_MECHANISM_BINARY:
			printf("binary\n");
			break;
			
		case MAILMIME_MECHANISM_QUOTED_PRINTABLE:
			printf("quoted-printable\n");
			break;
			
		case MAILMIME_MECHANISM_BASE64:
			printf("base64\n");
			break;
			
		case MAILMIME_MECHANISM_TOKEN:
			printf("unknown\n");
			break;
	}
}

void display_mime_field(struct mailmime_field *field_ptr, int nb_space)
{
	if(field_ptr == NULL) return;

	print_space(nb_space);
	printf("MIME header field: ");
	switch (field_ptr->fld_type)
	{
		case MAILMIME_FIELD_NONE:
			printf("Unknown\n");
			break;
		
		case MAILMIME_FIELD_TYPE:
			printf("Content type\n");
			display_mime_content(field_ptr->fld_data.fld_content, nb_space + 2);
			break;
		
		case MAILMIME_FIELD_TRANSFER_ENCODING:
			printf("Encoding: ");
			display_mime_encoding(field_ptr->fld_data.fld_encoding->enc_type);
			break;
		
		case MAILMIME_FIELD_ID:
			printf("Content-id: %s\n", field_ptr->fld_data.fld_id);
			break;
		
		case MAILMIME_FIELD_DESCRIPTION:
			printf("Description: %s\n", field_ptr->fld_data.fld_description);
			break;
		
		case MAILMIME_FIELD_VERSION:
			printf("Mime version\n");
			break;
		
		case MAILMIME_FIELD_DISPOSITION:
			printf("Content-disposition\n");
			display_mime_disposition(field_ptr->fld_data.fld_disposition, nb_space + 2);
			break;
		
		case MAILMIME_FIELD_LANGUAGE:
			printf("Language\n");
			break;
	}
}

void display_mime_fields(struct mailmime_fields *fields_ptr, int nb_space)
{
	clistiter *iter_ptr;

	if(fields_ptr == NULL) return;

	for(iter_ptr = clist_begin(fields_ptr->fld_list); iter_ptr != NULL; iter_ptr = clist_next(iter_ptr))
	{
		struct mailmime_field *field_ptr = clist_content(iter_ptr);
		display_mime_field(field_ptr, nb_space);
	}
}

void display_mime_data(struct mailmime_data *md_ptr, int nb_space)
{
	if(md_ptr == NULL) return;

	print_space(nb_space);
	switch(md_ptr->dt_type)
	{
		case MAILMIME_DATA_TEXT:
			printf("Text data.\n");
			break;
		
		case MAILMIME_DATA_FILE:
			printf("File data.\n");
			break;
	}
	
	print_space(nb_space);
	printf("Encoding: ");
	display_mime_encoding(md_ptr->dt_encoding);
	
	print_space(nb_space);
	printf("Encode status: %s\n", md_ptr->dt_encoded ? "encoded" : "decoded");

	switch(md_ptr->dt_type)
	{
		case MAILMIME_DATA_TEXT:
			{
			int error;
			size_t index = 0;
			char *decode_text_ptr;
			size_t decode_text_len;
	
			print_space(nb_space);
			printf("<payload length=%d>\n", md_ptr->dt_data.dt_text.dt_length);
			nprint(md_ptr->dt_data.dt_text.dt_data, md_ptr->dt_data.dt_text.dt_length);
			printf("\n");
			print_space(nb_space);
			printf("</payload>\n");
			
			error = mailmime_part_parse(md_ptr->dt_data.dt_text.dt_data, md_ptr->dt_data.dt_text.dt_length, &index, 
						    md_ptr->dt_encoding, &decode_text_ptr, &decode_text_len);
			
			if(error != MAILIMF_NO_ERROR)
			{
				printf("Failed to parse content.\n");
				exit(1);
			}
			
			/*
			print_space(nb_space);
			printf("Decoded content:\n");
			nprint(decode_text_ptr, decode_text_len);
			*/
			mmap_string_unref(decode_text_ptr);
			break;
			}
		
		case MAILMIME_DATA_FILE:
			printf("file: %s\n", md_ptr->dt_data.dt_filename);
			break;
	}
}

void display_mime(struct mailmime *mime_ptr, int nb_space)
{
	clistiter *iter_ptr;
	
	if(mime_ptr == NULL) return;
	
	print_space(nb_space);
	switch(mime_ptr->mm_type)
	{
		case MAILMIME_SINGLE:
			printf("------------ single part ------------\n");
			break;
		
		case MAILMIME_MULTIPLE:
			printf("------------ multi-part -------------\n");
			break;
		
		case MAILMIME_MESSAGE:
			printf("-------------- message --------------\n");
			break;
		
		default:
			printf("Unknown message type (%d)\n", mime_ptr->mm_type);
			break;
	}
	
	display_mime_fields(mime_ptr->mm_mime_fields, nb_space);
	display_mime_content(mime_ptr->mm_content_type, nb_space);
	
	/* Very verbose, but useful for debugging. */
	#if 0
	print_space(nb_space);
	printf("<mime_body>\n");
	display_mime_data(mime_ptr->mm_body, nb_space);
	print_space(nb_space);
	printf("</mime_body>\n");
	#endif
	
	switch(mime_ptr->mm_type)
	{
		case MAILMIME_SINGLE:
			display_mime_data(mime_ptr->mm_data.mm_single, nb_space);
			break;
		
		case MAILMIME_MULTIPLE:
			if(mime_ptr->mm_data.mm_multipart.mm_preamble != NULL)
			{
				print_space(nb_space + 2);
				printf("Multi mime preamble:\n");
				display_mime_data(mime_ptr->mm_data.mm_multipart.mm_preamble, nb_space + 2);
			}
			
			if(mime_ptr->mm_data.mm_multipart.mm_mp_list != NULL)
			{
				for(iter_ptr = clist_begin(mime_ptr->mm_data.mm_multipart.mm_mp_list);
				    iter_ptr != NULL; iter_ptr = clist_next(iter_ptr))
				{
					display_mime(clist_content(iter_ptr), nb_space + 2);
				}
			}
			
			if(mime_ptr->mm_data.mm_multipart.mm_epilogue != NULL)
			{			
				print_space(nb_space + 2);
				printf("Multi mime epilogue:\n");
				display_mime_data(mime_ptr->mm_data.mm_multipart.mm_epilogue, nb_space + 2);
			}
			
			break;
		
		case MAILMIME_MESSAGE:
			if(mime_ptr->mm_data.mm_message.mm_fields != NULL)
			{
				display_msg_headers(mime_ptr->mm_data.mm_message.mm_fields, nb_space);
			}
		
			if(mime_ptr->mm_data.mm_message.mm_msg_mime != NULL)
			{
				display_mime(mime_ptr->mm_data.mm_message.mm_msg_mime, nb_space + 2);
			}
			
			break;
	}
}

/* Useful to test libetpan. The program compiled with this main function expects
 * one argument: the path to the message to parse.
 */
int main(int argc, char **argv)
{
	int fd;
	int error;
	struct stat stat_info;
	void *msg_buf;
	struct mailmime *mime_ptr;
	size_t current_index = 0;

	if(argc == 0)
	{
		printf("No program name specified.\n");
		return 1;
	}

	if(argc != 2)
	{
		printf("Usage: %s <path_to_mail>\n", argv[0]);
		return 1;
	}
	
	fd = open(argv[1], O_RDONLY);
	
	if(fd == -1)
	{
		printf("Cannot open %s: %s.\n", argv[1], strerror(errno));
		return 1;
	}
	
	error = fstat(fd, &stat_info);
	
	if(error == -1)
	{
		printf("Cannot stat %s: %s.\n", argv[1], strerror(errno));
		return 1;
	}
	
	msg_buf = mmap(NULL, stat_info.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	
	if(msg_buf == MAP_FAILED)
	{
		printf("Cannot allocate memory for %s: %s.\n", argv[1], strerror(errno));
		return 1;
	}
	
	/* Parse the message. */
	error = mailmime_parse(msg_buf, stat_info.st_size, &current_index, &mime_ptr);
	
	if(error != MAILIMF_NO_ERROR)
	{
		printf("Failed to parse the message (error %d).\n", error);
		return 1;
	}
	
	/* Display the parsed content. */
	display_mime(mime_ptr, 0);
	
	mailmime_free(mime_ptr);
	munmap(msg_buf, stat_info.st_size);
	close(fd);
	
	return 0;
}
