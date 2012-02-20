/*******************************************/
/* DESCRIPTION */

/* LB: using this to test some internal stuff. */


/*******************************************/
/* INCLUDES */

#include "kmo_base.h"
#include "mail.h"
#include "knp.h"
#include "utils.h"
#include "base64.h"


/*******************************************/
/* TESTS */

static void test_karray() {
    karray array1, array2;
    int i = 1, j = 2, k = 3, l = 4;
    
    karray_init(&array1);
    assert(array1.size == 0);
    
    karray_add(&array1, &i);
    karray_add(&array1, &j);
    assert(array1.size == 2);
    assert(array1.data[0] == &i);
    assert(array1.data[1] == &j);
    
    karray_init_karray(&array2, &array1);
    assert(array2.size == 2);
    assert(array2.data[1] == &j);
    
    karray_set(&array1, 1, &k);
    assert(array1.data[1] == &k);
    assert(array2.data[1] == &j);
    
    karray_set(&array1, 19, &l);
    assert(array1.size == 20);
    assert(array1.data[19] == &l);
    assert(array1.data[1] == &k);
    
    karray_assign_karray(&array2, &array1);
    assert(array2.size == 20);
    assert(array2.data[1] == &k);
    
    karray_free(&array1);
    karray_free(&array2);
}

static void test_khash() {
    khash h;
    kstr str;
    char *one = "one";
    int a = 1;
    int nb1 = 3;
    int nb2 = 4;
    int nb3 = 3;
    
    khash_init(&h);
    kstr_init(&str);
    
    khash_set_func(&h, khash_cstr_key, khash_cstr_cmp);
    khash_add(&h, one, &a);
    assert(khash_get(&h, one) == &a);
    kstr_sf(&str, "%c%c%c", 'o', 'n', 'e');
    assert(khash_get(&h, str.data) == &a);

    khash_clear(&h);
    khash_set_func(&h, khash_int_key, khash_int_cmp);
    khash_add(&h, &nb1, &nb1);
    khash_add(&h, &nb2, &nb2);
    assert(khash_get(&h, &nb3) == &nb1);
    
    khash_free(&h);
    kstr_free(&str);
}

static void test_kstr() {
    kstr str1, str2, str3;
    kstr_init(&str1);
    kstr_init_cstr(&str2, "bar");
    kstr_init_kstr(&str3, &str2);

    assert(kstr_equal_cstr(&str2, "bar"));
    assert(kstr_equal_kstr(&str2, &str3));

    kstr_assign_cstr(&str3, "foobar");
    kstr_assign_kstr(&str1, &str3);
    kstr_sf(&str2, "%sbar", "foo");
    
    assert(kstr_equal_kstr(&str3, &str2));
    assert(kstr_equal_kstr(&str1, &str2));

    kstr_sf(&str2, "%s buffer to grow", "I want my");
    assert(kstr_equal_cstr(&str2, "I want my buffer to grow"));

    kstr_clear(&str2);
    assert(kstr_equal_cstr(&str2, ""));
    
    kstr_append_char(&str2, 'f');
    kstr_append_char(&str2, 'o');
    kstr_assign_cstr(&str1, "ob");
    kstr_append_kstr(&str2, &str1);
    kstr_append_cstr(&str2, "ar");
    assert(kstr_equal_cstr(&str2, "foobar"));

    kstr_free(&str1);
    kstr_free(&str2);
    kstr_free(&str3);
}

static void test_strerror() {
    char *err;
    kstr *kerr;
    
    err = kmo_strerror();
    assert(err == NULL);
    kerr = kmo_kstrerror();
    assert(strcmp(kerr->data, "") == 0);
    
    kmo_seterror("Here %s!", "I am");
    err = kmo_strerror(); 
    assert(strcmp(err, "Here I am!") == 0);
    kerr = kmo_kstrerror();
    assert(strcmp(kerr->data, "Here I am!") == 0);
    
    kmo_seterror("He said, %s", kerr->data);
    assert(strcmp(kmo_strerror(), "He said, Here I am!") == 0);
    
    kmo_clearerror();
    assert(kmo_strerror() == NULL);
}

static void test_knp_msg() {
    kbuffer msg1, msg2;
    kstr str;
    uint32_t i32;
    uint64_t i64;
    
    kbuffer_init(&msg1, 0);
    kbuffer_init(&msg2, 0);
    kstr_init(&str);
    
    knp_msg_write_uint32(&msg1, 3);
    knp_msg_write_uint64(&msg1, 4);
    kstr_append_cstr(&str, "hello");
    knp_msg_write_kstr(&msg1, &str);
    
    kbuffer_write(&msg2, msg1.data, msg1.len);
    assert(! knp_msg_read_uint32(&msg2, &i32) && i32 == 3);
    assert(! knp_msg_read_uint64(&msg2, &i64) && i64 == 4);
    assert(! knp_msg_read_kstr(&msg2, &str) && strcmp(str.data, "hello") == 0);
    assert(knp_msg_read_uint32(&msg2, &i32));
    
    kbuffer_clean(&msg1);
    kbuffer_clean(&msg2);
    kstr_free(&str);
}

static void test_mail_parse_addr_field() {
    kstr addr_field;
    karray addr_array;
    char *john = "john_doe@example.com";
    int i;
    
    kstr_init(&addr_field);
    karray_init(&addr_array);

    kstr_sf(&addr_field, ";%s;;John Doe <%s>;<%s>", john, john, john);
    assert(! mail_parse_addr_field(&addr_field, &addr_array));
    assert(addr_array.size == 3);
    
    for (i = 0; i < addr_array.size; i++) {
    	 assert(! strcmp(((kstr *) addr_array.data[i])->data, john));
    }
    
    kmo_clear_kstr_array(&addr_array);
    
    kstr_sf(&addr_field, "<>");
    assert(mail_parse_addr_field(&addr_field, &addr_array));
    
    kstr_sf(&addr_field, "<");
    assert(mail_parse_addr_field(&addr_field, &addr_array));
    
    kstr_sf(&addr_field, ">");
    assert(mail_parse_addr_field(&addr_field, &addr_array));
    
    kstr_sf(&addr_field, "foobar");
    assert(mail_parse_addr_field(&addr_field, &addr_array));
    
    kstr_sf(&addr_field, "foobar@@example.com");
    assert(mail_parse_addr_field(&addr_field, &addr_array));
    
    kstr_sf(&addr_field, ">text<");
    assert(mail_parse_addr_field(&addr_field, &addr_array));
    
    kstr_sf(&addr_field, "foo;bar@example.com");
    assert(mail_parse_addr_field(&addr_field, &addr_array));
    
    kstr_free(&addr_field);
    karray_free(&addr_array);
}

static void test_b64() {
    kbuffer a, b, c;
    
    kbuffer_init(&a, 0);
    kbuffer_init(&b, 0);
    kbuffer_init(&c, 0);
    
    kbuffer_write(&a, "testing", sizeof("testing"));
    bin2b64(&a, &b);
    b642bin(&b, &c, 0);
    assert(strcmp(a.data, c.data) == 0);
    
    kbuffer_clean(&a);
    kbuffer_clean(&b);
    kbuffer_clean(&c);
}

static void test_util_bin_to_hex() {
    unsigned char in[4] = { 0xaf, 0x00, 0xfa, 0x0d };
    kstr out;
    kstr_init(&out);
    util_bin_to_hex(in, 4, &out);
    assert(kstr_equal_cstr(&out, "af00fa0d"));
    kstr_free(&out);
}

void kmo_do_tests() {
    kmo_error_start();
    
    test_karray();
    test_khash();
    test_kstr();
    test_strerror();
    test_knp_msg();
    test_mail_parse_addr_field();
    test_b64();
    test_util_bin_to_hex();
    
    kmo_error_end();
    
    printf("Tests passed.\n");
}
