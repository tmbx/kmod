/* Copyright (C) 2006-2012 Opersys inc., All rights reserved. */

#include "kmo_comm.h"
#include "utils.h"

/* This function initializes a data transfer. */
void kmo_data_transfer_init(struct kmo_data_transfer *self) {
    memset(self, 0, sizeof(struct kmo_data_transfer));
    self->fd = -1;
}

/* This function frees the data associated to a transfer. */
void kmo_data_transfer_free(struct kmo_data_transfer *self) {
    if (self == NULL) return;

    if (self->err_msg) {
    	kstr_destroy(self->err_msg);
    }
}

/* This function initializes the transfer hub. */
void kmo_transfer_hub_init(struct kmo_transfer_hub *self) {
    khash_init(&self->transfer_hash);
}

/* This function frees the transfer hub. */
void kmo_transfer_hub_free(struct kmo_transfer_hub *self) {
    if (self == NULL) return;
    
    khash_free(&self->transfer_hash);
}

/* This function adds a tranfer to the transfer hub. The transfer must not
 * already be in the hub.
 */
void kmo_transfer_hub_add(struct kmo_transfer_hub *hub, struct kmo_data_transfer *transfer) {

    assert(! khash_exist(&hub->transfer_hash, transfer));
    khash_add(&hub->transfer_hash, transfer, transfer);
    
    assert(transfer->driver.read_data);
    assert(transfer->driver.write_data);
    assert(transfer->driver.disconnect);
    assert(transfer->fd != -1);
    assert(transfer->min_len <= transfer->max_len);
    transfer->trans_len = 0;
    transfer->status = KMO_COMM_TRANS_PENDING;
    
    if (transfer->op_timeout) {
    	struct timeval now;
	transfer->deadline.tv_sec = transfer->op_timeout / 1000;
	transfer->deadline.tv_usec = (transfer->op_timeout % 1000) * 1000;
	util_get_current_time(&now);
	util_timeval_add(&transfer->deadline, &transfer->deadline, &now);
    }
    
    else {
    	/* Once upon a time a programmer used LONG_MAX, naive in the belief
	 * that 'long' was 4 bytes. Yet another broken illusion.
	 */
    	transfer->deadline.tv_sec = 2147483647;
	transfer->deadline.tv_usec = 0;
    }
    
    if (transfer->err_msg) {
    	kstr_destroy(transfer->err_msg);
	transfer->err_msg = NULL;
    }
}

/* This function removes a transfer from the transfer hub, if it exists. */
void kmo_transfer_hub_remove(struct kmo_transfer_hub *hub, struct kmo_data_transfer *transfer) {
    khash_remove(&hub->transfer_hash, transfer);
}

/* This function waits for at least one of the current transfers to complete.
 * This function will return immediately if there is no pending transfer.
 * Otherwise, the time to wait is determined by the deadlines (not timeouts)
 * of the pending transfers.
 */
void kmo_transfer_hub_wait(struct kmo_transfer_hub *hub) {
    int done_flag = 0;
    karray transfer_array;
    
    karray_init(&transfer_array);
    
    /* Loop until we manage to complete a transfer. */
    while (! done_flag) {
	int error = 0;
	int max_sock = 0;
    	int iter_index = -1;
	int i;
	struct kmo_data_transfer *transfer;
	struct timeval deadline = { 2147483647, 0 };
	struct timeval now, min_time, time_to_wait;
	fd_set read_set, write_set;
    	
	FD_ZERO(&read_set);
	FD_ZERO(&write_set);
    
	/* Find which transfers must be processed. */
	transfer_array.size = 0;
	done_flag = 1;

	for (i = 0; i < hub->transfer_hash.size; i++) {
    	    khash_iter_next(&hub->transfer_hash, &iter_index, (void **) &transfer, NULL);
    	    
	    /* Unfinished transfer. */
	    if (transfer->status == KMO_COMM_TRANS_PENDING ||
	    	(transfer->status == KMO_COMM_TRANS_COMPLETED && transfer->min_len < transfer->max_len)) {
    	    	
		/* Pending transfer. */
		if (transfer->status == KMO_COMM_TRANS_PENDING) {
		    done_flag = 0;
		}
		
		/* Put the transfer in the appropriate select() set. */
		if (transfer->read_flag)
	    	    FD_SET((unsigned int) transfer->fd, &read_set);
		else
	    	    FD_SET((unsigned int) transfer->fd, &write_set);
    	    	
		max_sock = MAX(transfer->fd, max_sock);
		
		/* Compute deadline for select(). */
		if (util_timeval_cmp(&transfer->deadline, &deadline) == -1) {
		    deadline = transfer->deadline;
		}
		
		/* Process this transfer. */
		karray_add(&transfer_array, transfer);
	    }
	}
    	
	/* All done. */
	if (done_flag) {
	    break;
	}
	
	/* Wait at least one millisecond. */
	util_get_current_time(&now);
	min_time.tv_sec = 0;
	min_time.tv_usec = 1000;
	util_timeval_add(&time_to_wait, &now, &min_time);
	
	/* The deadline is already passed or too short. */
	if (util_timeval_cmp(&time_to_wait, &deadline) >= 0) {
	    time_to_wait = min_time;
	}
	
	/* The deadline is long enough. */
	else {
	    util_timeval_subtract(&time_to_wait, &deadline, &now);
	}
    
     	/* Wait for the sockets to become readable or writable. */
    	error = select(max_sock + 1, &read_set, &write_set, NULL, &time_to_wait);

	if (error < 0) {
    	    
	    #ifdef __UNIX__
	    /* Ignore EINTR. */
	    if (errno == EINTR) {
	    	continue;
	    }
	    #endif
	    
	    /* We can't handle other errors. */
    	    kmo_fatalerror("select() failed: %s", kmo_neterror());
	}
		
	/* Check what happened. */
	util_get_current_time(&now);
	
	for (i = 0; i < transfer_array.size; i++) {
	    transfer = (struct kmo_data_transfer *) transfer_array.data[i];
	    fd_set *set = transfer->read_flag ? &read_set : &write_set;
	    
	    /* This transfer is ready. */
	    if (FD_ISSET(transfer->fd, set)) {
	    	
		uint32_t nb = transfer->max_len - transfer->trans_len;
		error = 0;
		
		/* Attempt to transfer data. */
	    	if (nb > 0) {
		    int (*transfer_func) (int fd, char *buf, uint32_t *len) =
			transfer->read_flag ? transfer->driver.read_data : transfer->driver.write_data;

		    error = transfer_func(transfer->fd, transfer->buf + transfer->trans_len, &nb);
		}

		/* Transfer error. */
		if (error == -1) {
		    done_flag = 1;
		    transfer->status = KMO_COMM_TRANS_ERROR;
		    transfer->err_msg = kstr_new();
		    kstr_assign_kstr(transfer->err_msg, kmo_kstrerror());
		}
		
		/* Not ready? Surprising, but we'll let it pass. */
		else if (error == -2) {
		    /* Void. */
		}
		
		/* Success. */
		else {
		    assert(error == 0);
		    transfer->trans_len += nb;
		    
		    /* The transfer is completed. */
		    if (transfer->status == KMO_COMM_TRANS_PENDING && transfer->trans_len >= transfer->min_len) {
		    	done_flag = 1;
		    	transfer->status = KMO_COMM_TRANS_COMPLETED;
		    }
		    
		    /* Reset its deadline. */
		    if (transfer->op_timeout) {
			transfer->deadline.tv_sec = transfer->op_timeout / 1000;
			transfer->deadline.tv_usec = (transfer->op_timeout % 1000) * 1000;
			util_timeval_add(&transfer->deadline, &transfer->deadline, &now);
		    }
		}
	    }
	    
	    /* The transfer is not ready. */
	    else {
	    
	    	/* Check if it is expired. */
		if (util_timeval_cmp(&transfer->deadline, &now) == -1) {
		    done_flag = 1;
		    transfer->status = KMO_COMM_TRANS_ERROR;
		    assert(transfer->err_msg == NULL);
		}
	    }
	}
    }
    
    karray_free(&transfer_array);
}
