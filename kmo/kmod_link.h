#ifndef _KMOD_LINK_H_
#define _KMOD_LINK_H

#if defined(__KMOD__)
#include "kbuffer.h"
int kmod_open_kappsd_session(char *host, int port);
void kmod_close_kappsd_session();
int kmod_exchange_kappsd_message(uint32_t in_type, kbuffer *in_buf, uint32_t *out_type, kbuffer *out_buf);

#elif defined(__KAPPSD__)
#include "kappsd.h"
int kappsd_linkage_loop();

#endif

void link_msg_write_uint32(kbuffer *buf, uint32_t i);
void link_msg_write_uint64(kbuffer *buf, uint64_t i);
void link_msg_write_kstr(kbuffer *buf, kstr *str);
void link_msg_write_cstr(kbuffer *buf, char *str);
void link_msg_write_bin(kbuffer *buf, kstr *str);
int link_msg_read_uint32(kbuffer *buf, uint32_t *i);
int link_msg_read_uint64(kbuffer *buf, uint64_t *i);
int link_msg_read_str(kbuffer *buf, kstr *str);
int link_msg_read_bin(kbuffer *buf, kstr *str);

#endif
