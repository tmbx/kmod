#include "kmocrypt.h"

void dump_hash (kmocrypt_signature *sign, uint8_t *hash)
{
    kbuffer *buffer = kbuffer_new (32);
    kbuffer *base64;

    kbuffer_write (buffer, hash, gcry_md_get_algo_dlen (sign->hash_algo));
    base64 = kbuffer_conv_b64 (buffer);
    kbuffer_write8 (base64, '\0');
    printf ("%s", base64->data);
}

void dump_subpackets (kmocrypt_signature *sign, enum subpacket_type type, void *subpacket) {
    switch (type) {
        case KMO_SP_TYPE_PROTO:
            //dump_proto (sign);
            break;
        case KMO_SP_TYPE_FROM_NAME:
            printf ("        from name   : ");
            dump_hash (sign, (uint8_t *)subpacket);
            printf ("\n");
            break;
        case KMO_SP_TYPE_FROM_ADDR:
            printf ("        from addr   : ");
            dump_hash (sign, (uint8_t *)subpacket);
            printf ("\n");
            break;
        case KMO_SP_TYPE_TO:
            printf ("        to          : ");
            dump_hash (sign, (uint8_t *)subpacket);
            printf ("\n");
            break;
        case KMO_SP_TYPE_CC:
            printf ("        cc          : ");
            dump_hash (sign, (uint8_t *)subpacket);
            printf ("\n");
            break;
        case KMO_SP_TYPE_SUBJECT:
            printf ("        subject     : ");
            dump_hash (sign, (uint8_t *)subpacket);
            printf ("\n");
            break;
        case KMO_SP_TYPE_PLAIN:
            printf ("        text/plain  : ");
            dump_hash (sign, (uint8_t *)subpacket);
            printf ("\n");
            break;
        case KMO_SP_TYPE_HTML:
            printf ("        text/html   : ");
            dump_hash (sign, (uint8_t *)subpacket);
            printf ("\n");
            break;
        case KMO_SP_TYPE_IPV4:
            printf ("        ipv4        : %s\n", inet_ntoa (*(struct in_addr *)subpacket));
            break;
        case KMO_SP_TYPE_IPV6:
            printf ("        ipv6        : (not yet implemented in kspdump)\n");
            break;
        case KMO_SP_TYPE_ATTACHMENT:
            printf ("        attachment  : Present\n");
            break;
        case KMO_SP_TYPE_SYMKEY:
            printf ("        symkey      : for mid (0x%llX)\n", *(int64_t *)subpacket);
            break;
        case KMO_SP_TYPE_SND_SYMKEY:
            printf ("        snd_symkey  :\n");
            break;
        case KMO_SP_TYPE_PASSWD:
            printf ("        passwd      :\n");
            break;
        case KMO_SP_TYPE_KSN:
            printf ("        KSN         : Present");
            
            break;
        case KMO_SP_TYPE_MAIL_CLIENT:
            printf ("        mail client : {\n");
            printf ("            product     : %i\n", ((kmocrypt_signature_mail_client *)(subpacket))->product);
            printf ("            version     : %i\n", ((kmocrypt_signature_mail_client *)(subpacket))->version);
            printf ("            release     : %i\n", ((kmocrypt_signature_mail_client *)(subpacket))->release);
            printf ("            kpp_version : %i\n", ((kmocrypt_signature_mail_client *)(subpacket))->kpp_version);
            printf ("        }\n");
            break;
        default:
            break;
    }
}

void dump_version1 (kmocrypt_signature *sign)
{
    char *buffer;
    int i;

    printf ("{\n");
    printf ("    major      = %i\n", sign->major);
    printf ("    minor      = %i\n", sign->minor);
    printf ("    mid        = 0x%llX\n", sign->keyid);
    printf ("    hash_algo  = %s\n", gcry_md_algo_name (sign->hash_algo));
    printf ("    sig_algo   = %s\n", gcry_pk_algo_name (sign->sig_algo));

    if (sign->type == KMO_P_TYPE_SIGN) buffer = "SIGNATURE";
    else if (sign->type == KMO_P_TYPE_POD) buffer = "POD";
    else if (sign->type == KMO_P_TYPE_ENC) buffer = "ENCRYPTION";
    else if (sign->type == KMO_P_TYPE_PODNENC) buffer = "POD + ENCRYPTION";
    else buffer = "Unknown";

    printf ("    type       = %s (%i)\n", buffer, sign->type);
    printf ("    subpackets = {\n");
    for (i = 1 ; i < KMO_SP_NB_TYPE ; i++) {
        kmocrypt_subpackets *subpackets = sign->subpackets[i];
        while (subpackets) {
            if (kmocrypt_sign_contain (sign, i))
                dump_subpackets (sign, i, subpackets->subpacket);

            subpackets = subpackets->subpackets;
        }
    }
    printf ("    }\n");
    printf ("}\n");
}

int main (int argc, char **argv)
{
    kmocrypt_signature *sign;

    if (argc != 2) {
        printf ("usage %s: {<base64-KSP>|-}\n", argv[0]);
        return -1;
    }

    if (strcmp (argv[1], "-") == 0) {
        kbuffer *base64 = kbuffer_new (0);
        while (1) {
            size_t len_read = fread (kbuffer_begin_write(base64, 1024), 1, 1024, stdin);
            kbuffer_end_write(base64, len_read);
            if (len_read < 1024)
                break;
        }
        sign = kmocrypt_signature_new (base64->data, base64->len, NULL);
    } else
        sign = kmocrypt_signature_new (argv[1], strlen(argv[1]), NULL);

    if (!sign) {
        printf ("Error parsing the KSP (%s)\n", kmo_strerror());
        return -1;
    }

    switch (sign->major) {
        default:
            printf ("Unknown KSP format.\nDumping version 1, dump might be incomplete\n");
        case 1:
            printf ("KSP Version 1 Content:\n");
            dump_version1(sign);
            break;
    }
    return 0;
}

