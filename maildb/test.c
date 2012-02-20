#include <stdio.h>
#include <string.h>
#include "maildb.h"
#include "kmo_base.h"
#include <sqlite3.h>

maildb *mdb = NULL;

char *id1 = "id1";
char *id2 = "id2";
char *hash1 = "hash1_01234567890123";
char *hash2 = "hash2_01234567890123";
char *hash3 = "hash3_01234567890123";
char *ksn1 = "ksn1_6789012345678901234";
char *ksn2 = "ksn2_6789012345678901234";
char *ksn3 = "ksn3_6789012345678901234";

char *sig_msg = "lp1 on fire";
char *attach_blob = "DEA strike, jettisoned cargo";
char *sym_key_blob = "rot3";
char *decrypt_msg = "RNG on vacation";
char *pod_msg = "court rejected proof";
char *otut_string = "Call me! Only $2.99 per minute!";
char *otut_msg = "Ask for 'Shirley'";

/* Defined for linking correctly. */
void kmod_log_msg(int level, const char *format, ...) { level = 0; format = NULL; }

void set_mail(char *id, char *hash, char *ksn, int status, int mid) {
    maildb_mail_info m;
    maildb_init_mail_info(&m);
        
    kstr_assign_cstr(&m.msg_id, id);
    kstr_assign_cstr(&m.hash, hash);
    kstr_assign_cstr(&m.ksn, ksn);
    m.status = status;
    m.display_pref = 1;
    kstr_assign_cstr(&m.sig_msg, sig_msg);
    m.mid = mid;
    m.original_packaging = 1;
    m.mua = 1;
    m.field_status = 1;
    m.attachment_nbr = 1;
    kstr_assign_cstr(&m.attachment_status, attach_blob);
    kstr_assign_cstr(&m.sym_key, sym_key_blob);
    kstr_assign_cstr(&m.decryption_error_msg, decrypt_msg);
    m.pod_status = 1;
    kstr_assign_cstr(&m.pod_msg, pod_msg);
    m.otut_status = 1;
    kstr_assign_cstr(&m.otut_string, otut_string);
    kstr_assign_cstr(&m.otut_msg, otut_msg);
    
    assert(! maildb_set_mail_info(mdb, &m));
    maildb_free_mail_info(&m);
}

void check_mail(maildb_mail_info *m, char *hash, char *ksn, int status, int mid) {
    assert(memcmp(m->hash.data, hash, strlen(hash)) == 0);
    assert(memcmp(m->ksn.data, ksn, strlen(ksn)) == 0);
    assert(m->status == (unsigned int) status);
    assert(m->mid == mid);
}

void check_mail_static_data(maildb_mail_info *m) {
    assert(m->display_pref == 1);
    assert(strcmp(m->sig_msg.data, sig_msg) == 0);
    assert(m->original_packaging == 1);
    assert(m->mua == 1);
    assert(m->field_status == 1);
    assert(m->attachment_nbr == 1);
    assert(memcmp(m->attachment_status.data, attach_blob, strlen(attach_blob)) == 0);
    assert(memcmp(m->sym_key.data, sym_key_blob, strlen(sym_key_blob)) == 0);
    assert(strcmp(m->decryption_error_msg.data, decrypt_msg) == 0);
    assert(m->pod_status == 1);
    assert(strcmp(m->pod_msg.data, pod_msg) == 0);
    assert(m->otut_status == 1);
    assert(memcmp(m->otut_string.data, otut_string, strlen(otut_string)) == 0);
    assert(strcmp(m->otut_msg.data, otut_msg) == 0);
}

int get_mail_id(maildb_mail_info *mail_info, char *id) {
    int error;
    kstr str;
    
    kstr_init_cstr(&str, id);
    error = maildb_get_mail_info_from_msg_id(mdb, mail_info, &str);
    assert(error != -1);
    kstr_free(&str);
    
    return error;
}

int get_mail_hash(maildb_mail_info *mail_info, char *hash, char *ksn) {
    int error;
    kstr hash_blob;
    kstr ksn_blob;
    
    kstr_init_cstr(&hash_blob, hash);
    kstr_init_cstr(&ksn_blob, ksn);
    error = maildb_get_mail_info_from_hash(mdb, mail_info, &hash_blob, &ksn_blob);
    assert(error != -1);
    kstr_free(&hash_blob);
    kstr_free(&ksn_blob);
    
    return error;
}

void test_mail_info() {
    maildb_mail_info m;    
    maildb_init_mail_info(&m);
    
    /* Empty DB checks. */
    assert(get_mail_id(&m, id1) == -2);
    assert(get_mail_hash(&m, hash1, ksn1) == -2);
    
    /* Check invalid signature. */
    set_mail(id1, hash1, ksn1, 0, 1);
    assert(! get_mail_id(&m, id1));
    check_mail(&m, hash1, ksn1, 0, 1);
    check_mail_static_data(&m);
    assert(! get_mail_hash(&m, hash1, ksn1));
    check_mail(&m, hash1, ksn1, 0, 1);
    /* State: id1 -> (1, 0, 1). */
    
    /* Check that clobbering work for invalid signature with diff IDs. */
    set_mail(id1, hash1, ksn1, 0, 2);
    assert(! get_mail_id(&m, id1));
    check_mail(&m, hash1, ksn1, 0, 2);
    /* State: id1 -> (1, 0, 2). */
    
    set_mail(id2, hash1, ksn1, 0, 3);
    assert(! get_mail_id(&m, id1));
    check_mail(&m, hash1, ksn1, 0, 3);
    assert(! get_mail_id(&m, id2));
    check_mail(&m, hash1, ksn1, 0, 3);
    /* State: id1 -> (1, 0, 3), id2 -> (1, 0, 3). */
    
    /* Check that clobbering work for invalid signature with diff hashes. */
    set_mail(id1, hash2, ksn2, 0, 4);
    assert(! get_mail_id(&m, id1));
    check_mail(&m, hash2, ksn2, 0, 4);
    assert(! get_mail_id(&m, id2));
    check_mail(&m, hash1, ksn1, 0, 3);
    /* State: id1 -> (2, 0, 4), id2 -> (1, 0, 3). */
    
    /* Check that clobbering work as expected for unsigned mails. */
    set_mail(id1, "", "", 3, 5);
    assert(! get_mail_id(&m, id1));
    check_mail(&m, "", "", 3, 0);
    assert(get_mail_hash(&m, hash2, ksn2)  == -2);
    /* State: id1 -> null, id2 -> (1, 0, 3). */
    
    /* Check that clobbering work as expected for valid signatures. */
    set_mail(id2, hash3, ksn3, 1, 6);
    assert(! get_mail_id(&m, id2));
    check_mail(&m, hash3, ksn3, 1, 6);
    assert(get_mail_hash(&m, hash1, ksn1) == -2);
    /* State: id1 -> null, id2 -> (3, 1, 6). */
    
    set_mail(id1, hash3, ksn3, 1, 7);
    assert(! get_mail_id(&m, id1));
    check_mail(&m, hash3, ksn3, 1, 7);
    assert(! get_mail_id(&m, id2));
    check_mail(&m, hash3, ksn3, 1, 7);
    /* State: id1 -> (3, 1, 7), id2 -> (3, 1, 7). */
    
    /* Check that clobbering work as expected for encrypted mails. */
    set_mail("", "", ksn1, 2, 8);
    assert(! get_mail_hash(&m, "", ksn1));
    check_mail(&m, "", ksn1, 2, 8);
    assert(! get_mail_hash(&m, hash1, ksn1));
    check_mail(&m, "", ksn1, 2, 8);
    assert(! get_mail_hash(&m, hash3, ksn1));
    check_mail(&m, "", ksn1, 2, 8);
    /* State: id1 -> (3, 1, 7), id2 -> (3, 1, 7), ({"", 1}, 2, 8). */
    
    set_mail("", "", ksn2, 2, 9);
    assert(! get_mail_hash(&m, "", ksn2));
    check_mail(&m, "", ksn2, 2, 9);
    assert(! get_mail_hash(&m, "", ksn1));
    check_mail(&m, "", ksn1, 2, 8);
    /* State: id1 -> (3, 1, 7), id2 -> (3, 1, 7), ({"", 1}, 2, 8), ({"", 2}, 2, 9). */
    
    set_mail("", "", ksn2, 2, 10);
    assert(! get_mail_hash(&m, "", ksn2));
    check_mail(&m, "", ksn2, 2, 10);
    /* State: id1 -> (3, 1, 7), id2 -> (3, 1, 7), ({"", 1}, 2, 8), ({"", 2}, 2, 10). */
    
    /* Mix signed and encrypted mails. */
    set_mail(id1, hash2, ksn2, 1, 12);
    assert(! get_mail_hash(&m, hash2, ksn2));
    check_mail(&m, hash2, ksn2, 1, 12);
    assert(! get_mail_hash(&m, "", ksn2));
    check_mail(&m, "", ksn2, 2, 10);
    assert(! get_mail_hash(&m, hash3, ksn2));
    check_mail(&m, "", ksn2, 2, 10);
    /* State: id1 -> (2, 1, 12), id2 -> (3, 1, 7), ({"", 1}, 2, 8), ({"", 2}, 2, 10). */
    
    /* Make sure the DB is cool with empty KSNs. */
    assert(get_mail_hash(&m, hash3, "") == -2);
    set_mail(id1, hash3, "", 0, 11);
    assert(! get_mail_hash(&m, hash3, ksn3));
    check_mail(&m, hash3, ksn3, 1, 7);
    assert(! get_mail_hash(&m, hash3, ""));
    check_mail(&m, hash3, "", 0, 11);
    assert(! get_mail_id(&m, id1));
    check_mail(&m, hash3, "", 0, 11);
    /* State: id1 -> ({3, ""}, 0, 11), id2 -> (3, 1, 7), ({"", 1}, 2, 8), ({"", 2}, 2, 10). */
    
    maildb_free_mail_info(&m);
}

void test_sender_info() {
    maildb_sender_info s1, s2;
    maildb_init_sender_info(&s1);
    maildb_init_sender_info(&s2);
    
    s1.mid = 3;
    kstr_assign_cstr(&s1.name, "Joe Smith");
    assert(! maildb_set_sender_info(mdb, &s1));
    assert(! maildb_get_sender_info(mdb, &s2, s1.mid));
    assert(s1.mid == s2.mid);
    assert(kstr_equal_kstr(&s1.name, &s2.name));
    
    s1.mid = 4;
    assert(maildb_get_sender_info(mdb, &s2, s1.mid));
    
    maildb_free_sender_info(&s1);
    maildb_free_sender_info(&s2);
}

void test_password() {
    kstr e1, e2, p1, p2;
    kstr_init_cstr(&e1, "email1");
    kstr_init_cstr(&e2, "email2");
    kstr_init_cstr(&p1, "secret");
    kstr_init(&p2);
    
    assert(! maildb_set_pwd(mdb, &e1, &p1));
    assert(! maildb_get_pwd(mdb, &e1, &p2));
    assert(kstr_equal_kstr(&p1, &p2));
    
    assert(maildb_get_pwd(mdb, &e2, &p2));
    
    kstr_free(&e1);
    kstr_free(&e2);
    kstr_free(&p1);
    kstr_free(&p2);
}

int main() {
    kmo_error_start();
    
    unlink("test.db");
    mdb = maildb_sqlite_new("test.db");
    
    if (mdb == NULL) {
    	printf("Cannot create mail db: %s.\n", kmo_strerror());
	exit(1);
    }
    
    assert(mdb != NULL);
    
    test_mail_info();
    test_sender_info();
    test_password();

    maildb_destroy(mdb);
    
    kmo_error_end();
    
    printf("Tests passed.\n");
    
    return 0;
}
