/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

/* This file contains common definitions between kmocryptsignature.h and
 * kmocryptsignature2.h. Backward compatibility is really backward.
 */

#ifndef _KMOCRYPTSIGCOMMON_H
#define _KMOCRYPTSIGCOMMON_H

/* The packaging type of a specific KSP. */
enum packet_type {
    KMO_P_TYPE_SIGN,    /* 0 */
    KMO_P_TYPE_POD,     /* 1 */
    KMO_P_TYPE_ENC,     /* 2 */
    KMO_P_TYPE_PODNENC, /* 3 */
    KMO_P_NB_TYPE,      /* 4 */
};

/* A KSP contains subpackets. Here are these subpackets. */
enum subpacket_type {
    KMO_SP_INVALID_TYPE = 0,
    KMO_SP_TYPE_PROTO = 1,
    KMO_SP_TYPE_FROM_NAME = 2,
    KMO_SP_TYPE_FROM_ADDR = 3,
    KMO_SP_TYPE_TO = 4,
    KMO_SP_TYPE_CC = 5,
    KMO_SP_TYPE_SUBJECT = 6,
    KMO_SP_TYPE_PLAIN = 7,
    KMO_SP_TYPE_HTML = 8,
    KMO_SP_TYPE_IPV4 = 9,
    KMO_SP_TYPE_IPV6 = 10,
    KMO_SP_TYPE_ATTACHMENT = 11,
    KMO_SP_TYPE_SYMKEY = 12,
    KMO_SP_TYPE_SND_SYMKEY = 13,
    KMO_SP_TYPE_PASSWD = 14,
    KMO_SP_TYPE_MAIL_CLIENT = 15,
    KMO_SP_TYPE_BLOB = 16,
    KMO_SP_TYPE_KSN = 17,
    KMO_SP_TYPE_PODTO = 18,
    KMO_SP_TYPE_LANG = 19,
    KMO_SP_TYPE_DATE = 20,
    KMO_SP_TYPE_RESERVED1 = 21,
    KMO_SP_TYPE_KPG = 22,
    KMO_SP_NB_TYPE = 23
};

/* Size of the KSN: 24 bytes. */
#define KMOCRYPT_KSN_SIZE (8 * 3)

#endif
