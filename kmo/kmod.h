/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

#ifndef _KMOD_H
#define _KMOD_H

#include "kmo_base.h"

/* This file is used to obtain a log of the transactions between KMOD and a
 * plugin. The log is formatted in a way that enable a program to replay the 
 * transactions that occurred. The log is used to generate the KMOD tests.
 */
extern FILE *k3p_log;

/* Same as above, but for the KNP. */
extern FILE *knp_log;

/* This file logs the actions performed by KMOD. */
extern FILE *kmod_log;

/* K3P log mode: 0: none, 1: input, 2: output. */
extern int k3p_log_mode;

void kmod_log_msg(int level, const char *format, ...);

#endif
