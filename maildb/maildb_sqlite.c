#include <sqlite3.h>
#include "kmod.h"
#include "maildb.h"
#include "utils.h"

/* Implementation notes.
 *
 * Ideally, when the user specifies a <message ID, hash, KSN> triple, all
 * identifiers are unique and refer to the same mail. However, it is possible
 * that a message ID in the database and a message ID in the MUA correspond to
 * two different messages (that means we've been hacked). Furthermore, a KSN may
 * be referenced by 0, 1 or several message IDs (for instance, a message might
 * appear twice, once in the Inbox folder and once in the Sent Folder). We
 * cannot rely on KSNs being unique for each mail because an attacker can inject
 * mails with the same KSN. Hashes are unique most of the time but there can be
 * collisions. We use the following scheme for unique identifiers. We compute
 * the hash. We extract the KSN if we can. We consider that two mails are the
 * same if their hashes and their KSNs (possibly empty) match.
 *
 * The DB will try to maintain a consistent state even if nonsensical inputs are
 * provided (e.g. a message ID that switches from Kryptiva Mail to Unsigned
 * mail). Database object leaks may occur in such cases due to the need to be on
 * the safe side.
 * 
 * There are two important assumptions:
 *
 * 1) Message IDs are not recycled. The security of the plugin is completely 
 *    breached if the same message ID may refer, at different times, to two
 *    different mails.
 *
 * 2) The database is cleaned up from time to time by the plugin, which supplies
 *    the complete list of message IDs still in the mail folders.
 *
 * - Note that SQLite (apparently) does not support nested transactions.
 * - Note that SQLite barfs if you set an empty string/blob with a NULL pointer.
 * - Note that statements must be finalized before rollback can occur.
 *
 * - The following scheme is used for entry IDs:
 *   * -1: no mail_eval_res entry corresponds to the message ID specified
 *         (unsigned mail).
 *   *  0: no such message ID.
 *   * >0: entry ID present in the mail_eval_res table.
 *
 * Version history:
 * 1) Version of mercurial change set 490:528abafe209e.
 * 2) Added 'display_pref' column to 'mail_eval_res'.
 * 3) ...
 * 4) Profit!!!
 */

/* This function binds the specified string on the specifed column of the
 * specified SQL statement. WARNING: The content of text is not copied.
 * It returns an SQL error code.
 */
static int write_string(sqlite3_stmt *stmt, int col, kstr *text) {
    return sqlite3_bind_text(stmt, col, text->data, text->slen, SQLITE_STATIC);
}

/* This function binds the specified blob on the specifed column of the
 * specified SQL statement. WARNING: The content of blob is not copied.
 * It returns an SQL error code.
 */
static int write_blob(sqlite3_stmt *stmt, int col, kstr *blob) {
    return sqlite3_bind_blob(stmt, col, (uint8_t *) blob->data, blob->slen, SQLITE_STATIC);
}

/* This function reads the string of the specifed column of the specified SQL statement.
 * The kstr should be already initialized.
 */
static void read_string(sqlite3_stmt *stmt, kstr *text, int col) {
    
    /* The string should be initialized. */
    assert(text->data != NULL);
    
    int len = sqlite3_column_bytes(stmt, col);
   
    if (len) {
	kstr_assign_buf(text, sqlite3_column_text(stmt, col), len);
    }
    
    else {
    	kstr_clear(text);
    }
}

/* This function reads the blob of the specifed column of the specified SQL statement.
 * The blob should be already initialized.
 */
static void read_blob(sqlite3_stmt *stmt, kstr *blob, int col) {
    
    /* The string should be initialized. */
    assert(blob->data != NULL);
    
    int len = sqlite3_column_bytes(stmt, col);
   
    if (len) {
	kstr_assign_buf(blob, sqlite3_column_blob(stmt, col), len);
    }
    
    else {
    	kstr_clear(blob);
    }
}

/* This function finalizes a SQL statement, if required. */
static void finalize_stmt(sqlite3 *db, sqlite3_stmt **stmt_handle) {
    
    if (*stmt_handle) {
    	
	/* Failure here should never happen (and cannot be handled: we're cleaning up). */
    	if (sqlite3_finalize(*stmt_handle)) {
	    kmo_fatalerror("Could not finalize SQL statement: %s.", sqlite3_errmsg(db));
	}
	
	*stmt_handle = NULL;
    }
}

/* This function begins a transaction. */
static void begin_transaction(sqlite3 *db) {
    
    /* Failure here should never happen. */
    if (sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL)) {
    	kmo_fatalerror("%s.", sqlite3_errmsg(db));
    }
}

/* This function rollbacks a transaction. */
static void rollback_transaction(sqlite3 *db) {

    /* Failure here should never happen (and cannot be handled: we're cleaning up). */
    if (sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL)) {
    	kmo_fatalerror("%s.", sqlite3_errmsg(db));
    }
}

/* This function gets the entry ID corresponding to the message having the
 * specified message ID. If the message is not found, 0 is assigned.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int get_entry_id_from_msg_id(sqlite3 *db, kstr *msg_id, int64_t *entry_id) {
    int error = 0;
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare(db, "SELECT entry_id FROM mail_msg_id WHERE msg_id = ?;", -1, &stmt, NULL)) goto ERR;
    if (write_string(stmt, 1, msg_id)) goto ERR;
    error = sqlite3_step(stmt);
    
    /* No such message ID. */
    if (error == SQLITE_DONE) {
    	finalize_stmt(db, &stmt);
	*entry_id = 0;
	return 0;
    }
    
    if (error != SQLITE_ROW) goto ERR;
    
    *entry_id = sqlite3_column_int64(stmt, 0);
    assert(*entry_id != 0);

    if (sqlite3_step(stmt) != SQLITE_DONE) goto ERR;

    finalize_stmt(db, &stmt);
    return 0;
    
ERR:
    kmo_seterror(sqlite3_errmsg(db));
    finalize_stmt(db, &stmt);
    return -1;
}

/* This function gets the entry ID corresponding to the message having the
 * specified hash and KSN. If the message is not found, 0 is assigned.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int get_entry_id_from_hash(sqlite3 *db, kstr *hash, kstr *ksn, int64_t *entry_id) {
    int error = 0;
    sqlite3_stmt *stmt = NULL;
    
    assert(hash->slen == 0 || hash->slen == 20); //FIXME: SHA1 is obsolete, use SHA256.
    assert(ksn->slen == 0 || ksn->slen == 24);
    assert(hash->slen || ksn->slen);
    
    if (sqlite3_prepare(db, "SELECT entry_id FROM mail_eval_res3 WHERE hash = ? AND ksn = ?;", -1, &stmt, NULL)) 
    	goto ERR;

    if (write_blob(stmt, 1, hash)) goto ERR;   
    if (write_blob(stmt, 2, ksn)) goto ERR;
    
    error = sqlite3_step(stmt);
    
    /* No such entry. */
    if (error == SQLITE_DONE) {
    	finalize_stmt(db, &stmt);
	*entry_id = 0;
	return 0;
    }

    if (error != SQLITE_ROW) goto ERR;
    
    *entry_id = sqlite3_column_int64(stmt, 0);
    assert(*entry_id != 0);
    if (sqlite3_step(stmt) != SQLITE_DONE) goto ERR;

    finalize_stmt(db, &stmt);
    return 0;
    
ERR:
    kmo_seterror(sqlite3_errmsg(db));
    finalize_stmt(db, &stmt);
    return -1;
}

/* This function deletes the mail_eval_res entry having the specified entry_id,
 * if any.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int rm_mail_eval_res(sqlite3 *db, int64_t entry_id) {
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare(db, "DELETE FROM mail_eval_res3 WHERE entry_id = ?;", -1, &stmt, NULL)) goto ERR;
    if (sqlite3_bind_int64(stmt, 1, entry_id)) goto ERR;
    if (sqlite3_step(stmt) != SQLITE_DONE) goto ERR;
    finalize_stmt(db, &stmt);
    return 0;

ERR:
    kmo_seterror(sqlite3_errmsg(db));
    finalize_stmt(db, &stmt);
    return -1;
}

/* This function deletes the mail_msg_id entry having the specified message ID,
 * if any.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int rm_mail_msg_id(sqlite3 *db, kstr *msg_id) {
    sqlite3_stmt *stmt = NULL;
    int ret = -1;

    /* Try */
    do {
        /* This SQL request deletes the mail_eval_res entry if there is only one reference to it.
         * Here's how it works, read it from inside out.
         *
         * Get the entry_id associated with the msg_id received in parameter:
         *    SELECT entry_id
         *     FROM mail_msg_id
         *     WHERE msg_id = ?
         *
         * Get the number of references to the mail_eval_res associated with msg_id and its entry_id, if any:
         *    SELECT COUNT(mail_msg_id.msg_id) AS nb_ref, mail_eval_res3.entry_id AS entry_id
         *     FROM mail_eval_res3, mail_msg_id
         *     WHERE mail_eval_res3.entry_id = mail_msg_id.entry_id
         *      AND mail_msg_id.entry_id
         *       IN (...)
         *
         * Get only the entry_id if there is one and only one reference to the mail_eval_res:
         *    SELECT entry_id
         *     FROM (...)
         *     WHERE nb_ref = 1)
         *
         * Delete the mail_eval_res3 matching the entry_id if there is one:
         *  DELETE
         *   FROM mail_eval_res3
         *   WHERE entry_id
         *    IN (...)
         */
        if (sqlite3_prepare(db, "DELETE"
                                " FROM mail_eval_res3"
                                " WHERE entry_id"
                                "  IN (SELECT entry_id"
                                "       FROM (SELECT COUNT(mail_msg_id.msg_id) AS nb_ref, mail_eval_res3.entry_id AS entry_id"
                                "              FROM mail_eval_res3, mail_msg_id"
                                "              WHERE mail_eval_res3.entry_id = mail_msg_id.entry_id"
                                "               AND mail_msg_id.entry_id"
                                "                IN (SELECT entry_id"
                                "                     FROM mail_msg_id"
                                "                     WHERE msg_id = ?))"
                                "       WHERE nb_ref = 1);",
                                -1, &stmt, NULL)) break;
        if (write_string(stmt, 1, msg_id)) break;

        if (sqlite3_step(stmt) != SQLITE_DONE) break;

        finalize_stmt(db, &stmt);
        stmt = NULL;

        /* Remove the mail_msg_id entry */
        if (sqlite3_prepare(db, "DELETE FROM mail_msg_id WHERE msg_id = ?;", -1, &stmt, NULL)) break;
        if (write_string(stmt, 1, msg_id)) break;
        if (sqlite3_step(stmt) != SQLITE_DONE) break;

        ret = 0;
    } while (0);

    finalize_stmt(db, &stmt);

    kmo_seterror(sqlite3_errmsg(db));
    return ret;
}

/* This function creates a mail_msg_id entry.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int create_mail_msg_id(sqlite3 *db, kstr *msg_id, int64_t entry_id) {
    sqlite3_stmt *stmt = NULL;
    assert(msg_id->slen != 0);
    assert(entry_id != 0);

    if (sqlite3_prepare(db, "INSERT INTO mail_msg_id (msg_id, entry_id) VALUES (?, ?);", -1, &stmt, NULL)) goto ERR;
    if (write_string(stmt, 1, msg_id)) goto ERR;
    if (sqlite3_bind_int64(stmt, 2, entry_id)) goto ERR;
    if (sqlite3_step(stmt) != SQLITE_DONE) goto ERR;
    finalize_stmt(db, &stmt);
    return 0;
    
ERR:
    kmo_seterror(sqlite3_errmsg(db));
    finalize_stmt(db, &stmt);
    return -1;
}

/* This function creates a mail_eval_res entry.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int create_mail_eval_res(sqlite3 *db, maildb_mail_info *mail_info, int64_t *entry_id) {
    sqlite3_stmt *stmt = NULL;
    kstr insert_str;
    int i;

    assert(*entry_id >= 0);
    
    /* Create the mail_eval_res entry. */
    kstr_init_cstr(&insert_str, "INSERT INTO mail_eval_res3 (");

    /* If entry_id is not 0, then we must specify the entry_id in the INSERT. */
    if (*entry_id != 0) {
    	kstr_append_cstr(&insert_str, "entry_id, ");
    }

    kstr_append_cstr(&insert_str,
		     "hash, ksn, status, display_pref, sig_msg, mid, original_packaging, mua, field_status, "
		     "att_plugin_nbr, attachment_nbr, attachment_status, sym_key, encryption_status, "
		     "decryption_error_msg, pod_status, pod_msg, otut_status, otut_string, "
		     "otut_msg, kpg_addr, kpg_port) "
		     "VALUES (");

    if (*entry_id != 0) {
    	kstr_append_cstr(&insert_str, "?, ");
    }

    kstr_append_cstr(&insert_str, "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
    if (sqlite3_prepare(db, insert_str.data, -1, &stmt, NULL)) goto ERR;
    
    i = 1;
    
    if (*entry_id != 0) {
    	if (sqlite3_bind_int64(stmt, i++, *entry_id)) goto ERR;
    }
    
    if (write_blob(stmt, i++, &mail_info->hash)) goto ERR;
    if (write_blob(stmt, i++, &mail_info->ksn)) goto ERR;
    if (sqlite3_bind_int(stmt, i++, mail_info->status)) goto ERR;
    
    if (sqlite3_bind_int(stmt, i++, mail_info->display_pref)) goto ERR;
    if (write_string(stmt, i++, &mail_info->sig_msg)) goto ERR;
    if (sqlite3_bind_int64(stmt, i++, mail_info->mid)) goto ERR;
    if (sqlite3_bind_int(stmt, i++, mail_info->original_packaging)) goto ERR;
    if (sqlite3_bind_int(stmt, i++, mail_info->mua)) goto ERR;

    if (sqlite3_bind_int(stmt, i++, mail_info->field_status)) goto ERR;
    if (sqlite3_bind_int(stmt, i++, mail_info->att_plugin_nbr)) goto ERR;
    if (sqlite3_bind_int(stmt, i++, mail_info->attachment_nbr)) goto ERR;
    if (write_blob(stmt, i++, &mail_info->attachment_status)) goto ERR;

    if (write_blob(stmt, i++, &mail_info->sym_key)) goto ERR;

    if (sqlite3_bind_int(stmt, i++, mail_info->encryption_status)) goto ERR;
    if (write_string(stmt, i++, &mail_info->decryption_error_msg)) goto ERR;
    if (sqlite3_bind_int(stmt, i++, mail_info->pod_status)) goto ERR;
    if (write_string(stmt, i++, &mail_info->pod_msg)) goto ERR;

    if (sqlite3_bind_int(stmt, i++, mail_info->otut_status)) goto ERR;
    if (write_blob(stmt, i++, &mail_info->otut_string)) goto ERR;
    if (write_string(stmt, i++, &mail_info->otut_msg)) goto ERR;
    if (write_string(stmt, i++, &mail_info->kpg_addr)) goto ERR;
    if (sqlite3_bind_int(stmt, i++, mail_info->kpg_port)) goto ERR;
    
    if (sqlite3_step(stmt) != SQLITE_DONE) goto ERR;
    finalize_stmt(db, &stmt);
    
    /* Obtain/validate the entry ID. */
    if (*entry_id == 0) {
    	*entry_id = sqlite3_last_insert_rowid(db);
    }
    
    else {
    	assert(*entry_id == sqlite3_last_insert_rowid(db));
    }
    
    kstr_free(&insert_str);
    return 0;
    
ERR:
    kmo_seterror(sqlite3_errmsg(db));
    finalize_stmt(db, &stmt);
    kstr_free(&insert_str);
    return -1;
}

/* This method sets the specified mail information in the database.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int maildb_sqlite_set_mail_info(maildb *mdb, maildb_mail_info *mail_info) {
    int error = 0;
    sqlite3 *db = (sqlite3 *) mdb->db;
    int64_t entry_id = 0;
    
    assert(mail_info->hash.slen == 0 || mail_info->hash.slen == 20); //FIXME: SHA1 is obsolete, use SHA256
    assert(mail_info->ksn.slen == 0 || mail_info->ksn.slen == 24);
    
    begin_transaction(db);
    
    /* Try. */
    do {
    	if (mail_info->status == 0 || mail_info->status == 1 || mail_info->status == 2) {
	    
            /* For status 0 and 1, the message ID may or may not be present. 
             * The message ID is not present when we update an existing
             * mail_eval_res entry, such as when an OTUT is used or when the
             * display preference of a mail is modified.
             */
	    if (mail_info->status == 0) {
	    	assert(mail_info->hash.slen != 0);
	    }

	    else if (mail_info->status == 1) {
	    	assert(mail_info->hash.slen != 0);
		assert(mail_info->ksn.slen != 0);
	    }

	    else if (mail_info->status == 2) {
	    	assert(mail_info->msg_id.slen == 0);
	    	assert(mail_info->hash.slen == 0);
		assert(mail_info->ksn.slen != 0);
	    }

	    /* It is possible that we have a mail_msg_id entry in the DB that
	     * matches the message ID in mail_info and that points to an
	     * eval_res entry that has a hash which does not match the hash in
	     * mail_info.
	     */
	    if (mail_info->msg_id.slen != 0 && (mail_info->status == 0 || mail_info->status == 1)) {
	    	
		/* Delete the mail_msg_id entry, if any, and its mail_eval_res
                 * entry if it exist and is referred by only one mail_msg_id
                 * entry.
                 */
		error = rm_mail_msg_id(db, &mail_info->msg_id);
		if (error) break;
            }

            /* Get the entry ID corresponding to the specified hash, if any. */
            error = get_entry_id_from_hash(db, &mail_info->hash, &mail_info->ksn, &entry_id);
            if (error) break;

	    /* The mail_eval_res entry has been found in the DB. */
	    if (entry_id) {
	    	assert(entry_id != -1);

		/* Delete the mail_eval_res entry. */
		rm_mail_eval_res(db, entry_id);
	    }

	    /* Create mail_eval_res entry. */
	    error = create_mail_eval_res(db, mail_info, &entry_id);
	    if (error) break;

    	    /* Set the entry_id field of the mail_info object. */
    	    mail_info->entry_id = entry_id;

	    /* Create mail_msg_id entry. If we are sending the message encrypted,
             * we dont know the msgid the mua will give to the email. */
	    if (mail_info->msg_id.slen != 0 && (mail_info->status == 0 || mail_info->status == 1)) {
	    	error = create_mail_msg_id(db, &mail_info->msg_id, entry_id);
    	    	if (error) break;
	    }
	}

	/* Since this mail is not a Kryptiva mail, there shouldn't be a
	 * mail_eval_res entry associated to the mail_msg_id entry in the DB.
	 * However, if the mail is downgrading from Kryptiva to non-Kryptiva status,
	 * we must let the mail_eval_res entry leak since there might be another
	 * message ID referring to the same mail_eval_res entry.
	 * 
	 */
	else if (mail_info->status == 3) {
    	    assert(mail_info->msg_id.slen != 0);
	    assert(mail_info->hash.slen == 0);
	    assert(mail_info->ksn.slen == 0);
    	    
	    /* Delete mail_msg_id entry, if any. */
	    error = rm_mail_msg_id(db, &mail_info->msg_id);
	    if (error) break;

	    /* Create mail_msg_id entry. */
	    error = create_mail_msg_id(db, &mail_info->msg_id, -1);
	    if (error) break;
	}

	else assert(0);

    	if (sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL)) {
	    kmo_seterror(sqlite3_errmsg(db));
	    error = -1;
	    break;
	}

    } while (0);
    
    /* Try to rollback if an error occurred. */
    if (error) {
    	rollback_transaction(db);
    }
    
    return error;
}

/* This function returns the mail info having the entry ID specified.
 * This function sets the KMO error string. It returns -1 on general failure,
 * -2 if not found.
 */
static int maildb_sqlite_get_mail_info_from_entry_id(maildb *mdb, maildb_mail_info *mail_info, int64_t entry_id) {
    sqlite3 *db = (sqlite3 *) mdb->db;
    sqlite3_stmt *stmt = NULL;
    int i = 0;

    /* Clear the mail info. */
    maildb_clear_mail_info(mail_info);
    
    /* No such mail. */
    if (entry_id == 0) {
    	return -2;
    }
    
    /* Not a Kryptiva mail. */
    if (entry_id == -1) {
    	mail_info->status = 3;
	return 0;
    }
    
    assert(entry_id > 0);
    
    /* It's a Kryptiva mail. Read the mail_eval_res info. */
    if (sqlite3_prepare (db,
	    	    	 "SELECT hash, ksn, status, display_pref, sig_msg, mid, original_packaging, mua, field_status, "
	    	    	 "att_plugin_nbr, attachment_nbr, attachment_status, sym_key, encryption_status, "
			 "decryption_error_msg, pod_status, pod_msg, otut_status, otut_string, "
			 "otut_msg, kpg_addr, kpg_port "
			 "FROM mail_eval_res3 WHERE mail_eval_res3.entry_id = ?;",
			 -1, &stmt, NULL)) goto ERR;

    if (sqlite3_bind_int64(stmt, 1, entry_id)) goto ERR;
    if (sqlite3_step(stmt) != SQLITE_ROW) goto ERR;

    i = 0;
    read_blob(stmt, &mail_info->hash, i++);
    read_blob(stmt, &mail_info->ksn, i++);
    mail_info->status = sqlite3_column_int(stmt, i++);
    
    mail_info->display_pref = sqlite3_column_int(stmt, i++);
    read_string(stmt, &mail_info->sig_msg, i++);
    mail_info->mid = sqlite3_column_int64(stmt, i++);
    mail_info->original_packaging = sqlite3_column_int(stmt, i++);
    mail_info->mua = sqlite3_column_int(stmt, i++);

    mail_info->field_status = sqlite3_column_int(stmt, i++);
    mail_info->att_plugin_nbr = sqlite3_column_int(stmt, i++);
    mail_info->attachment_nbr = sqlite3_column_int(stmt, i++);
    read_blob(stmt, &mail_info->attachment_status, i++);

    read_blob(stmt, &mail_info->sym_key, i++);

    mail_info->encryption_status = sqlite3_column_int(stmt, i++);
    read_string(stmt, &mail_info->decryption_error_msg, i++);
    mail_info->pod_status = sqlite3_column_int(stmt, i++);
    read_string(stmt, &mail_info->pod_msg, i++);

    mail_info->otut_status = sqlite3_column_int(stmt, i++);
    read_blob(stmt, &mail_info->otut_string, i++);
    read_string(stmt, &mail_info->otut_msg, i++);
    read_string(stmt, &mail_info->kpg_addr, i++);
    mail_info->kpg_port = sqlite3_column_int(stmt, i++);

    if (sqlite3_step(stmt) != SQLITE_DONE) goto ERR;

    finalize_stmt(db, &stmt);
    
    /* Set the entry_id field of the mail_info object. */
    mail_info->entry_id = entry_id;
    
    return 0;
    
ERR:
    kmo_seterror(sqlite3_errmsg(db));
    finalize_stmt(db, &stmt);
    return -1;
}

/* This function returns the mail info having the message ID specified.
 * This function sets the KMO error string. It returns -1 on general failure,
 * -2 if not found.
 */
static int maildb_sqlite_get_mail_info_from_msg_id(maildb *mdb, maildb_mail_info *mail_info, kstr *msg_id) {
    int error = 0;
    sqlite3 *db = (sqlite3 *) mdb->db;
    int64_t entry_id;

    error = get_entry_id_from_msg_id(db, msg_id, &entry_id);
    if (error) return -1;
    
    return maildb_sqlite_get_mail_info_from_entry_id(mdb, mail_info, entry_id);
}

/* This function returns the mail info having the hash and KSN specified.
 * This function sets the KMO error string. It returns -1 on general failure,
 * -2 if not found.
 */
static int maildb_sqlite_get_mail_info_from_hash(maildb *mdb, maildb_mail_info *mail_info, kstr *hash, kstr *ksn) {
    int error = 0;
    sqlite3 *db = (sqlite3 *) mdb->db;
    int64_t entry_id;
    
    error = get_entry_id_from_hash(db, hash, ksn, &entry_id);
    if (error) return -1;
    
    /* If we failed to find the mail, and a hash and a KSN were provided, we redo
     * the search with only the KSN, to find sent encrypted mails.
     */
    if (entry_id == 0 && hash->slen > 0 && ksn->slen > 0) {
    	kstr empty_hash;
	kstr_init(&empty_hash);
    	error = get_entry_id_from_hash(db, &empty_hash, ksn, &entry_id);
	kstr_free(&empty_hash);
    	if (error) return -1;
    }
    
    return maildb_sqlite_get_mail_info_from_entry_id(mdb, mail_info, entry_id);
}

/* This function deletes the sender info having the member ID specified, if any. */
static int maildb_sqlite_rm_sender_info(maildb *mdb, int64_t mid) {
    sqlite3 *db = (sqlite3 *) mdb->db;
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare(db, "DELETE FROM sender WHERE mid = ?;", -1, &stmt, NULL)) goto ERR;
    if (sqlite3_bind_int64(stmt, 1, mid)) goto ERR;
    if (sqlite3_step (stmt) != SQLITE_DONE) goto ERR;
    finalize_stmt(db, &stmt);
    return 0;
    
ERR:
    kmo_seterror(sqlite3_errmsg(db));
    finalize_stmt(db, &stmt);
    return -1;
}

/* This function sets the specified sender info in the database. */
static int maildb_sqlite_set_sender_info (maildb *mdb, maildb_sender_info *sender_info) {
    sqlite3 *db = (sqlite3 *) mdb->db;
    sqlite3_stmt *stmt = NULL;
    int i = 1;

    if (maildb_sqlite_rm_sender_info(mdb, sender_info->mid)) goto ERR;
    if (sqlite3_prepare(db, "INSERT INTO sender (mid, name) VALUES (?,?);", -1, &stmt, NULL)) goto ERR;
    if (sqlite3_bind_int64(stmt, i++, sender_info->mid)) goto ERR;
    if (write_string(stmt, i++, &sender_info->name)) goto ERR;
    if (sqlite3_step(stmt) != SQLITE_DONE) goto ERR;
    
    finalize_stmt(db, &stmt);
    return 0;
    
ERR:
    kmo_seterror(sqlite3_errmsg(db));
    finalize_stmt(db, &stmt);
    return -1;
}

/* This function returns the sender info having the member ID specified. */
static int maildb_sqlite_get_sender_info(maildb *mdb, maildb_sender_info *sender_info, int64_t mid) {
    sqlite3 *db = (sqlite3 *)mdb->db;
    sqlite3_stmt *stmt = NULL;
    int i;
    int error = 0;

    if (sqlite3_prepare(db, "SELECT mid, name FROM sender WHERE mid = ?;", -1, &stmt, NULL)) goto ERR;
    if (sqlite3_bind_int64(stmt, 1, mid)) goto ERR;
    error = sqlite3_step(stmt);
    
    /* No such sender info. */
    if (error == SQLITE_DONE) {
    	finalize_stmt(db, &stmt);
        return -2;
    }
    
    else if (error != SQLITE_ROW) goto ERR;
    
    /* Read the sender info. */
    i = 0;
    sender_info->mid = sqlite3_column_int64(stmt, i++);
    read_string(stmt, &sender_info->name, i++);

    if (sqlite3_step(stmt) != SQLITE_DONE) goto ERR;
    
    finalize_stmt(db, &stmt);
    return 0;
    
ERR:
    kmo_seterror(sqlite3_errmsg(db));
    finalize_stmt(db, &stmt);
    return -1;
}

/* This function deletes the password associated to the email specified, if any. */
static int maildb_sqlite_rm_pwd(maildb *mdb, kstr *email) {
    sqlite3 *db = (sqlite3 *) mdb->db;
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare(db, "DELETE FROM pwd WHERE email = ?;", -1, &stmt, NULL)) goto ERR;
    if (write_string(stmt, 1, email)) goto ERR;
    if (sqlite3_step(stmt) != SQLITE_DONE) goto ERR;
    
    finalize_stmt(db, &stmt);
    return 0;
    
ERR:
    kmo_seterror(sqlite3_errmsg(db));
    finalize_stmt(db, &stmt);
    return -1;
}

/* This function sets the password associated to the email specified. Note that
 * the same password table will be used for two different purposes:
 * 1) remembering the password set when sending an email to a non-member.
 * 2) remembering the password entered when receiving a mail from a member.
 * Both cases shouldn't happen at the same time, normally.
 */
static int maildb_sqlite_set_pwd(maildb *mdb, kstr *email, kstr *pwd) {
    sqlite3 *db = (sqlite3 *) mdb->db;
    sqlite3_stmt *stmt = NULL;
    int i = 1;

    if (maildb_sqlite_rm_pwd(mdb, email)) goto ERR;

    if (sqlite3_prepare(db, "INSERT INTO pwd (email, pwd) VALUES (?,?);", -1, &stmt, NULL)) goto ERR;
    if (write_string(stmt, i++, email)) goto ERR;
    if (write_string(stmt, i++, pwd)) goto ERR;
    if (sqlite3_step(stmt) != SQLITE_DONE) goto ERR;
    
    finalize_stmt(db, &stmt);
    return 0;
    
ERR:
    kmo_seterror(sqlite3_errmsg(db));
    finalize_stmt(db, &stmt);
    return -1;
}

/* This function returns the password associated to the email specified. */
static int maildb_sqlite_get_pwd(maildb *mdb, kstr *email, kstr *pwd) {
    sqlite3 *db = (sqlite3 *) mdb->db;
    sqlite3_stmt *stmt = NULL;
    int i;
    int error = 0;
    
    if (sqlite3_prepare(db, "SELECT pwd FROM pwd WHERE email = ? COLLATE NOCASE;", -1, &stmt, NULL)) goto ERR;
    if (write_string(stmt, 1, email)) goto ERR;
    error = sqlite3_step(stmt);
    
    /* No such password. */
    if (error == SQLITE_DONE) {
    	finalize_stmt(db, &stmt);
        return -2;
    }
    
    else if (error != SQLITE_ROW) goto ERR;
    
    /* Read the password. */
    i = 0;
    read_string(stmt, pwd, i++);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) goto ERR;
    
    finalize_stmt(db, &stmt);
    return 0;
    
ERR:
    kmo_seterror(sqlite3_errmsg(db));
    finalize_stmt(db, &stmt);
    return -1;
}

/* This function returns all the email-password pairs currently in the 
 * database.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int maildb_sqlite_get_all_pwd(maildb *mdb, karray *addr_array, karray *pwd_array) {
    sqlite3 *db = (sqlite3 *) mdb->db;
    sqlite3_stmt *stmt = NULL;
    int error = 0;
    
    addr_array->size = 0;
    pwd_array->size = 0;
    
    if (sqlite3_prepare(db, "SELECT email, pwd FROM pwd;", -1, &stmt, NULL)) goto ERR;
    
    while (1) {
    	error = sqlite3_step(stmt);
	if (error == SQLITE_DONE) break;
	if (error != SQLITE_ROW) goto ERR;
	
	kstr *str = kstr_new();
	karray_add(addr_array, str);
    	read_string(stmt, str, 0);
	
	str = kstr_new();
	karray_add(pwd_array, str);
    	read_string(stmt, str, 1);
    }
    
    finalize_stmt(db, &stmt);
    return 0;
    
ERR:
    kmo_seterror(sqlite3_errmsg(db));
    finalize_stmt(db, &stmt);
    return -1;
}

/* This function verifies the integrity of the database. */
int maildb_integrity_check(maildb *mdb) {
    int error = 0;
    sqlite3 *db = (sqlite3 *) mdb->db;
    sqlite3_stmt *stmt = NULL;
    kstr val;
    
    kstr_init(&val);
    
    do {
	if (sqlite3_prepare(db, "PRAGMA integrity_check;", -1, &stmt, NULL) ||
	    sqlite3_step(stmt) != SQLITE_ROW) {
	    
	    kmo_seterror(sqlite3_errmsg(db));
	    error = -1;
	    break;
	}
	
	read_string(stmt, &val, 0);
	
	if (strcmp(val.data, "ok")) {
	    kmo_seterror("sqlite database is corrupted");
	    error = -1;
	    break;
	}
	
    } while (0);
    
    kstr_free(&val);
    finalize_stmt(db, &stmt);
    return error;
}

/* This function obtains the version number of the database. */
static void maildb_get_version(sqlite3 *db, int *version) {
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare(db, "SELECT version FROM maildb_version;", -1, &stmt, NULL)) goto ERR;
    if (sqlite3_step(stmt) != SQLITE_ROW) goto ERR;
    
    *version = sqlite3_column_int(stmt, 0);
    assert(*version != 0);

    /* The db is corrupted if we find more than one version */
    if (sqlite3_step(stmt) != SQLITE_DONE) 
        *version = -1;

    finalize_stmt(db, &stmt);
    return;
    
ERR:
    /* Assume the database is uninitialized. */
    *version = 0;
    finalize_stmt(db, &stmt);
    return;
}

/* This function frees the database. */
static void maildb_sqlite_destroy(maildb *mdb) {
    sqlite3 *db = (sqlite3 *) mdb->db;
    sqlite3_close(db);
    free(mdb);
}

/* This function initializes the database the first time it is opened.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int maildb_sqlite_initialize(sqlite3 *db) {
    begin_transaction(db);
    
    if (sqlite3_exec(db, "CREATE TABLE 'pwd' ('email' varchar(320), 'pwd' varchar(256));"
                         "CREATE UNIQUE INDEX 'pwd_index' ON pwd (email);"

                         "CREATE TABLE 'sender' ('mid' integer(20), 'name' varchar(100));"
                         "CREATE UNIQUE INDEX 'sender_index' ON sender (mid);"

			 "CREATE TABLE 'mail_msg_id' ('msg_id' VARCHAR(20), 'entry_id' INTEGER);"
			 "CREATE UNIQUE INDEX 'msg_id_index' ON mail_msg_id (msg_id);"

			 "CREATE TABLE 'mail_eval_res3' "
                           "("
                           " 'entry_id' INTEGER PRIMARY KEY,"
			   " 'hash' BLOB (20),"
			   " 'ksn' BLOB (24),"
			   " 'status' INTEGER,"

			   " 'display_pref' TINYINT(1),"
			   " 'sig_msg' VARCHAR,"
                           " 'mid' INTEGER(20),"
                           " 'original_packaging' TINYINT(1),"
                           " 'mua' SMALLINT(3),"

                           " 'field_status' INTEGER(2),"
			   " 'att_plugin_nbr' TINYINT(1),"
                           " 'attachment_nbr' TINYINT(1),"
                           " 'attachment_status' BLOB,"

                           " 'sym_key' BLOB,"

                           " 'encryption_status' TINYINT(1),"
                           " 'decryption_error_msg' VARCHAR,"
                           " 'pod_status' TINYINT(1),"
                           " 'pod_msg' VARCHAR,"

                           " 'otut_status' TINYINT(1),"
			   " 'otut_string' BLOB,"
			   " 'otut_msg' VARCHAR,"
			   " 'kpg_addr' VARCHAR,"
			   " 'kpg_port' INTEGER(5)"
                           ");"
			   
			 "CREATE INDEX 'hash_index' ON mail_eval_res3 (hash);"
			 "CREATE INDEX 'entry_id_index' ON mail_msg_id (entry_id);"

                         "CREATE TABLE 'maildb_version' ('version' TINYINT(1));"
                         "INSERT INTO maildb_version (version) VALUES (4);"

			 "COMMIT;", NULL, NULL, NULL)) {
        kmo_seterror("database initialization failed: %s", sqlite3_errmsg(db));
        rollback_transaction(db);
        return -1;
    }

    return 0;
}

/* This function converts the database format from version 3 to version 4.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int maildb_convert_to_version_4(sqlite3 *db) {
    sqlite3_stmt *stmt1 = NULL;
    sqlite3_stmt *stmt2 = NULL;
    kstr kstr_array[10];
    int k;
    
    for (k = 0; k < 10; k++) kstr_init(kstr_array + k);
    
    begin_transaction(db);
    
    /* Create the new table and update the maildb version. */
    if (sqlite3_exec(db, "CREATE TABLE 'mail_eval_res3' "
                           "("
                           " 'entry_id' INTEGER PRIMARY KEY,"
			   " 'hash' BLOB (20),"
			   " 'ksn' BLOB (24),"
			   " 'status' INTEGER,"

			   " 'display_pref' TINYINT(1),"
			   " 'sig_msg' VARCHAR,"
                           " 'mid' INTEGER(20),"
                           " 'original_packaging' TINYINT(1),"
                           " 'mua' SMALLINT(3),"

                           " 'field_status' INTEGER(2),"
			   " 'att_plugin_nbr' TINYINT(1),"
                           " 'attachment_nbr' TINYINT(1),"
                           " 'attachment_status' BLOB,"

                           " 'sym_key' BLOB,"

                           " 'encryption_status' TINYINT(1),"
                           " 'decryption_error_msg' VARCHAR,"
                           " 'pod_status' TINYINT(1),"
                           " 'pod_msg' VARCHAR,"

                           " 'otut_status' TINYINT(1),"
			   " 'otut_string' BLOB,"
			   " 'otut_msg' VARCHAR,"
			   " 'kpg_addr' VARCHAR,"
			   " 'kpg_port' INTEGER(5)"
                           ");"
                         "UPDATE maildb_version SET version = 4;", NULL, NULL, NULL)) goto ERR;

    /* Transfer the data from mail_eval_res to mail_eval_res2. */
    if (sqlite3_prepare(db, "SELECT entry_id, hash, ksn, status, display_pref, "
			    "sig_msg, mid, original_packaging, mua, field_status, "
	    	    	    "att_plugin_nbr, attachment_nbr, attachment_status, sym_key, encryption_status, "
			    "decryption_error_msg, pod_status, pod_msg, otut_status, otut_string, "
			    "otut_msg FROM mail_eval_res2;", -1, &stmt1, NULL)) goto ERR;
    	    
    while (1) {
    	int i = 0;
	int j = 1;
    	k = 0;
	
    	int res = sqlite3_step(stmt1);
	if (res == SQLITE_DONE) break;
	if (res != SQLITE_ROW) goto ERR;

	if (sqlite3_prepare(db, "INSERT INTO mail_eval_res3 ("
				"entry_id, hash, ksn, status, display_pref, sig_msg, mid, original_packaging, mua, "
				"field_status, att_plugin_nbr, attachment_nbr, attachment_status, sym_key, "
				"encryption_status, decryption_error_msg, pod_status, pod_msg, otut_status, "
				"otut_string, otut_msg, kpg_addr, kpg_port) "
				"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
				-1, &stmt2, NULL)) goto ERR;

	if (sqlite3_bind_int64(stmt2, j++, sqlite3_column_int64(stmt1, i++))) goto ERR;

	read_blob(stmt1, &kstr_array[k], i++); if (write_blob(stmt2, j++, &kstr_array[k])) goto ERR; k++;
	read_blob(stmt1, &kstr_array[k], i++); if (write_blob(stmt2, j++, &kstr_array[k])) goto ERR; k++;
	if (sqlite3_bind_int(stmt2, j++, sqlite3_column_int(stmt1, i++))) goto ERR;

	if (sqlite3_bind_int(stmt2, j++, sqlite3_column_int(stmt1, i++))) goto ERR;
	read_string(stmt1, &kstr_array[k], i++); if (write_string(stmt2, j++, &kstr_array[k])) goto ERR;  k++;
    	if (sqlite3_bind_int64(stmt2, j++, sqlite3_column_int64(stmt1, i++))) goto ERR;
	if (sqlite3_bind_int(stmt2, j++, sqlite3_column_int(stmt1, i++))) goto ERR;
	if (sqlite3_bind_int(stmt2, j++, sqlite3_column_int(stmt1, i++))) goto ERR;

	if (sqlite3_bind_int64(stmt2, j++, sqlite3_column_int64(stmt1, i++))) goto ERR;
	if (sqlite3_bind_int64(stmt2, j++, sqlite3_column_int64(stmt1, i++))) goto ERR;
	if (sqlite3_bind_int64(stmt2, j++, sqlite3_column_int64(stmt1, i++))) goto ERR;
    	read_blob(stmt1, &kstr_array[k], i++); if (write_blob(stmt2, j++, &kstr_array[k])) goto ERR;  k++;

	read_blob(stmt1, &kstr_array[k], i++); if (write_blob(stmt2, j++, &kstr_array[k])) goto ERR;  k++;

	if (sqlite3_bind_int(stmt2, j++, sqlite3_column_int(stmt1, i++))) goto ERR;
	read_string(stmt1, &kstr_array[k], i++); if (write_string(stmt2, j++, &kstr_array[k])) goto ERR;  k++;
	if (sqlite3_bind_int(stmt2, j++, sqlite3_column_int(stmt1, i++))) goto ERR;
	read_string(stmt1, &kstr_array[k], i++); if (write_string(stmt2, j++, &kstr_array[k])) goto ERR;  k++;

	if (sqlite3_bind_int(stmt2, j++, sqlite3_column_int(stmt1, i++))) goto ERR;
    	read_blob(stmt1, &kstr_array[k], i++); if (write_blob(stmt2, j++, &kstr_array[k])) goto ERR;  k++;
	read_string(stmt1, &kstr_array[k], i++); if (write_string(stmt2, j++, &kstr_array[k])) goto ERR;  k++;
	
	/* Add KPG address and port. */
	kstr_assign_cstr(&kstr_array[k], ""); if (write_string(stmt2, j++, &kstr_array[k])) goto ERR;  k++;
	if (sqlite3_bind_int(stmt2, j++, 0)) goto ERR;
    	
    	if (sqlite3_step(stmt2) != SQLITE_DONE) goto ERR;
	finalize_stmt(db, &stmt2);
    }

    finalize_stmt(db, &stmt1);

    /* Delete the mail_eval_res table and commit. */
    if (sqlite3_exec(db, "DROP TABLE mail_eval_res2; COMMIT;", NULL, NULL, NULL)) goto ERR;

    /* Success. */
    for (k = 0; k < 10; k++) kstr_free(kstr_array + k);
    finalize_stmt(db, &stmt1);
    finalize_stmt(db, &stmt2);
    return 0;

ERR:
    kmo_seterror(sqlite3_errmsg(db));
    for (k = 0; k < 10; k++) kstr_free(kstr_array + k);
    finalize_stmt(db, &stmt1);
    finalize_stmt(db, &stmt2);
    rollback_transaction(db);
    return -1;
}

/* This function converts the database format from version 2 to version 3.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int maildb_convert_to_version_3(sqlite3 *db) {
    
    /* Create the new table and update the maildb version. */
    if (sqlite3_exec(db, "BEGIN TRANSACTION;"
			 "CREATE INDEX 'hash_index' ON mail_eval_res2 (hash);"
			 "CREATE INDEX 'entry_id_index' ON mail_msg_id (entry_id);"
                         "UPDATE maildb_version SET version = 3;"
			 "COMMIT;", NULL, NULL, NULL)) {
	kmo_seterror(sqlite3_errmsg(db));
	rollback_transaction(db);
	return -1;
    }
    
    return 0;
}

/* This function converts the database format from version 1 to version 2.
 * This function sets the KMO error string. It returns -1 on failure.
 */
static int maildb_convert_to_version_2(sqlite3 *db) {
    sqlite3_stmt *stmt1 = NULL;
    sqlite3_stmt *stmt2 = NULL;
    kstr kstr_array[9];
    int k;
    
    for (k = 0; k < 9; k++) kstr_init(kstr_array + k);
    
    begin_transaction(db);
    
    /* Create the new table and update the maildb version. */
    if (sqlite3_exec(db, "CREATE TABLE 'mail_eval_res2' "
                           "("
                           " 'entry_id' INTEGER PRIMARY KEY,"
			   " 'hash' BLOB (20),"
			   " 'ksn' BLOB (24),"
			   " 'status' INTEGER,"

			   " 'display_pref' TINYINT(1),"
			   " 'sig_msg' VARCHAR,"
                           " 'mid' INTEGER(20),"
                           " 'original_packaging' TINYINT(1),"
                           " 'mua' SMALLINT(3),"

                           " 'field_status' INTEGER(2),"
			   " 'att_plugin_nbr' TINYINT(1),"
                           " 'attachment_nbr' TINYINT(1),"
                           " 'attachment_status' BLOB,"

                           " 'sym_key' BLOB,"

                           " 'encryption_status' TINYINT(1),"
                           " 'decryption_error_msg' VARCHAR,"
                           " 'pod_status' TINYINT(1),"
                           " 'pod_msg' VARCHAR,"

                           " 'otut_status' TINYINT(1),"
			   " 'otut_string' BLOB,"
			   " 'otut_msg' VARCHAR"
                           ");"

                         "UPDATE maildb_version SET version = 2;", NULL, NULL, NULL)) goto ERR;

    /* Transfer the data from mail_eval_res to mail_eval_res2. */
    if (sqlite3_prepare(db, "SELECT entry_id, hash, ksn, status, sig_msg, mid, original_packaging, mua, field_status, "
	    	    	    "att_plugin_nbr, attachment_nbr, attachment_status, sym_key, encryption_status, "
			    "decryption_error_msg, pod_status, pod_msg, otut_status, otut_string, "
			    "otut_msg FROM mail_eval_res;", -1, &stmt1, NULL)) goto ERR;
    	    
    while (1) {
    	int i = 0;
	int j = 1;
    	k = 0;
	
    	int res = sqlite3_step(stmt1);
	if (res == SQLITE_DONE) break;
	if (res != SQLITE_ROW) goto ERR;

	if (sqlite3_prepare(db, "INSERT INTO mail_eval_res2 ("
				"entry_id, hash, ksn, status, display_pref, sig_msg, mid, original_packaging, mua, "
				"field_status, att_plugin_nbr, attachment_nbr, attachment_status, sym_key, "
				"encryption_status, decryption_error_msg, pod_status, pod_msg, otut_status, "
				"otut_string, otut_msg) "
				"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
				-1, &stmt2, NULL)) goto ERR;

	if (sqlite3_bind_int64(stmt2, j++, sqlite3_column_int64(stmt1, i++))) goto ERR;

	read_blob(stmt1, &kstr_array[k], i++); if (write_blob(stmt2, j++, &kstr_array[k])) goto ERR; k++;
	read_blob(stmt1, &kstr_array[k], i++); if (write_blob(stmt2, j++, &kstr_array[k])) goto ERR; k++;
	if (sqlite3_bind_int(stmt2, j++, sqlite3_column_int(stmt1, i++))) goto ERR;

    	/* Add display pref. */
	if (sqlite3_bind_int(stmt2, j++, 1)) goto ERR;
	read_string(stmt1, &kstr_array[k], i++); if (write_string(stmt2, j++, &kstr_array[k])) goto ERR;  k++;
    	if (sqlite3_bind_int64(stmt2, j++, sqlite3_column_int64(stmt1, i++))) goto ERR;
	if (sqlite3_bind_int(stmt2, j++, sqlite3_column_int(stmt1, i++))) goto ERR;
	if (sqlite3_bind_int(stmt2, j++, sqlite3_column_int(stmt1, i++))) goto ERR;

	if (sqlite3_bind_int64(stmt2, j++, sqlite3_column_int64(stmt1, i++))) goto ERR;
	if (sqlite3_bind_int64(stmt2, j++, sqlite3_column_int64(stmt1, i++))) goto ERR;
	if (sqlite3_bind_int64(stmt2, j++, sqlite3_column_int64(stmt1, i++))) goto ERR;
    	read_blob(stmt1, &kstr_array[k], i++); if (write_blob(stmt2, j++, &kstr_array[k])) goto ERR;  k++;

	read_blob(stmt1, &kstr_array[k], i++); if (write_blob(stmt2, j++, &kstr_array[k])) goto ERR;  k++;

	if (sqlite3_bind_int(stmt2, j++, sqlite3_column_int(stmt1, i++))) goto ERR;
	read_string(stmt1, &kstr_array[k], i++); if (write_string(stmt2, j++, &kstr_array[k])) goto ERR;  k++;
	if (sqlite3_bind_int(stmt2, j++, sqlite3_column_int(stmt1, i++))) goto ERR;
	read_string(stmt1, &kstr_array[k], i++); if (write_string(stmt2, j++, &kstr_array[k])) goto ERR;  k++;

	if (sqlite3_bind_int(stmt2, j++, sqlite3_column_int(stmt1, i++))) goto ERR;
    	read_blob(stmt1, &kstr_array[k], i++); if (write_blob(stmt2, j++, &kstr_array[k])) goto ERR;  k++;
	read_string(stmt1, &kstr_array[k], i++); if (write_string(stmt2, j++, &kstr_array[k])) goto ERR;  k++;
    	
    	if (sqlite3_step(stmt2) != SQLITE_DONE) goto ERR;
	finalize_stmt(db, &stmt2);
    }

    finalize_stmt(db, &stmt1);

    /* Delete the mail_eval_res table and commit. */
    if (sqlite3_exec(db, "DROP TABLE mail_eval_res; COMMIT;", NULL, NULL, NULL)) goto ERR;

    /* Success. */
    for (k = 0; k < 9; k++) kstr_free(kstr_array + k);
    finalize_stmt(db, &stmt1);
    finalize_stmt(db, &stmt2);
    return 0;

ERR:
    kmo_seterror(sqlite3_errmsg(db));
    for (k = 0; k < 9; k++) kstr_free(kstr_array + k);
    finalize_stmt(db, &stmt1);
    finalize_stmt(db, &stmt2);
    rollback_transaction(db);
    return -1;
}

/* SQLite operations. */
struct _maildb_ops maildb_sqlite_ops = {
    .destroy         = maildb_sqlite_destroy,
    .set_mail_info   = maildb_sqlite_set_mail_info,
    .get_mail_info_from_entry_id = maildb_sqlite_get_mail_info_from_entry_id,
    .get_mail_info_from_msg_id = maildb_sqlite_get_mail_info_from_msg_id,
    .get_mail_info_from_hash = maildb_sqlite_get_mail_info_from_hash,
    .set_sender_info = maildb_sqlite_set_sender_info,
    .get_sender_info = maildb_sqlite_get_sender_info,
    .rm_sender_info  = maildb_sqlite_rm_sender_info,
    .set_pwd         = maildb_sqlite_set_pwd,
    .get_pwd         = maildb_sqlite_get_pwd,
    .get_all_pwd     = maildb_sqlite_get_all_pwd,
    .rm_pwd 	     = maildb_sqlite_rm_pwd
};

/* This function opens the database if it already exists, or creates a new one
 * if it does not exist. If necessary, a conversion to the latest format is
 * performed.
 * This function sets the KMO error string. It returns NULL on failure.
 */
maildb * maildb_sqlite_new(char *db_name)
{
    int version = 0;
    sqlite3 *db = NULL;
    
    kmod_log_msg(2, "maildb_sqlite_new() called.\n");
    
    /* Open or create the database. */
    if (sqlite3_open(db_name, &db)) {
        kmo_seterror("cannot open %s: %s", db_name, sqlite3_errmsg(db));
        goto ERR;
    }
    
    /* Get the database version. */
    maildb_get_version(db, &version);
    
    /* Initialize new database. */
    if (version == 0) {
    	kmod_log_msg(1, "Initializing new KMOD database.\n");
    	if (maildb_sqlite_initialize(db)) goto ERR;
    }
    
    /* Convert database to version 2. */
    else if (version == 1) {
    	kmod_log_msg(1, "Converting KMOD database from version 1 to version 2.\n");
    	if (maildb_convert_to_version_2(db)) goto ERR;
    }
    
    /* Convert database to version 3. */
    else if (version == 2) {
    	kmod_log_msg(1, "Converting KMOD database from version 2 to version 3.\n");
    	if (maildb_convert_to_version_3(db)) goto ERR;
    }
	
    /* Convert database to version 4. */
    else if (version == 3) {
    	kmod_log_msg(1, "Converting KMOD database from version 3 to version 4.\n");
    	if (maildb_convert_to_version_4(db)) goto ERR;
    }
    
    /* Database is at current version. */
    else if (version == 4) {
    	kmod_log_msg(1, "The KMOD database is at version 4.\n");
    }
    
    /* Database is too recent -- we can't deal with it since we would corrupt it. */
    else {
    	kmo_seterror("database version %d is unsupported (latest supported version is %d)", version, 4);
	goto ERR;
    }
    
    /* Initialize the maildb object. */
    maildb *mdb = (maildb *) kmo_calloc(sizeof(maildb));
    mdb->db = db;
    mdb->ops = &maildb_sqlite_ops;
    
    /* All good. */
    return mdb;

ERR:
    if (db) sqlite3_close(db);
    return NULL;
}
