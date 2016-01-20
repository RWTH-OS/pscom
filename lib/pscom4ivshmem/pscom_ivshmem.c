/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2007 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * pscom_ivshmem.c: OPENIB/Infiniband communication
 */

#include "psivshmem.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include <malloc.h>
#include <infiniband/verbs.h>

#include "pscom_priv.h"
#include "psivshmem_malloc.h"	// NEW 
#include "pscom_io.h"
#include "pscom_ivshmem.h"   // ADDED !!
#include "ps_ivshmem.h"
#include "pscom_req.h"
#include "pscom_util.h"

static 
unsigned ivshmem_direct = 400;

static
struct {
	struct pscom_poll_reader poll_reader; // calling shm_poll_pending_io(). Used if !list_empty(shm_conn_head)
	struct list_head	ivshmem_conn_head; // shm_conn_t.pending_io_next_conn.
} ivshmem_pending_io;

static
int pscom_ivshmem_initrecv(psivshmem_conn_t *ivshmem)
{
	int ivshmemid;
	void *buf;

	ivshmemid = shmget(/*key*/0, sizeof(psivshmem_com_t), IPC_CREAT | 0777);
	if (ivshmemid == -1) goto err;

	buf = shmat(ivshmemid, 0, 0 /*IVSHMEM_RDONLY*/);
	if (((long)buf == -1) || !buf) goto err_shmat;

	shmctl(ivshmemid, IPC_RMID, NULL); /* remove shmid after usage */

	memset(buf, 0, sizeof(psivshmem_com_t)); /* init */

	ivshmem->local_id = ivshmemid;
	ivshmem->local_com = (psivshmem_com_t *)buf;
	ivshmem->recv_cur = 0;
	return 0;
err_shmat:
	DPRINT(1, "shmat(%d, 0, 0) : %s", ivshmemid, strerror(errno));
	shmctl(ivshmemid, IPC_RMID, NULL);
	return -1;
err:
	DPRINT(1, "shmget(0, sizeof(psivshmem_com_t), IPC_CREAT | 0777) : %s", strerror(errno));
	return -1;
}


static
int pscom_ivshmem_initsend(psivshmem_conn_t *ivshmem, int rem_ivshmemid)
{
	void *buf;
	buf = shmat(rem_ivshmemid, 0, 0);
	if (((long)buf == -1) || !buf) goto err_shmat;

	ivshmem->remote_id = rem_ivshmemid;
	ivshmem->remote_com = buf;
	ivshmem->send_cur = 0;
	return 0;
err_shmat:
	DPRINT(1, "shmat(%d, 0, 0) : %s", rem_ivshmemid, strerror(errno));
	return -1;
}


static
void pscom_ivshmem_init_direct(psivshmem_conn_t *ivshmem, int ivshmemid, void *remote_base)
{
	if (ivshmemid == -1) {
		ivshmem->direct_offset = 0;
		ivshmem->direct_base = NULL;
		return;
	}
	void *buf = shmat(ivshmemid, 0, IVSHMEM_RDONLY);
	assert(buf != (void *) -1 && buf);

	ivshmem->direct_base = buf;
	ivshmem->direct_offset = (char *)buf - (char *)remote_base;
}
/*
static
struct pscom_poll_reader pscom_cq_poll;

int pscom_poll_cq(pscom_poll_reader_t *reader)
{
	psivshmem_progress();

	if (!psivshmem_outstanding_cq_entries) {
		/* Stop polling on cq /
		/* it's save to dequeue more then once /
		list_del_init(&reader->next);
	}

	return 0;
}
*/
static inline
void pscom_check_cq_poll(void)
{
	if (psivshmem_outstanding_cq_entries &&
	    list_empty(&pscom_cq_poll.next)) {
		// There are outstanding cq events and
		// we do not already poll the cq

		// Start polling:
		list_add_tail(&pscom_cq_poll.next, &pscom.poll_reader);
	}
}


static inline
uint32_t pscom_ivshmem_canrecv(psivshmem_conn_t *ivshmem)
{
	int cur = ivshmem->recv_cur;
	ivshmem_buf_t *ivshmembuf = &ivshmem->local_com->buf[cur];  // ##########################
	return ivshmembuf->header.msg_type;
}


/* receive.
   Call only if shm_canrecv() == SHM_MSGTYPE_STD (no check inside)!
*/
static inline
void pscom_ivshmem_recvstart(psivshmem_conn_t *ivshmem, char **buf, unsigned int *len)
{
	int cur = ivshmem->recv_cur;
	ivshmem_buf_t *ivshmembuf = &ivshmem->local_com->buf[cur];  // ##########################

	*len = ivshmembuf->header.len;
	*buf = IVSHMEM_DATA(ivshmembuf, *len);
}


/* receive.
   Call only if shm_canrecv() == SHM_MSGTYPE_DIRECT (no check inside)!
*/
static inline
void pscom_ivshmem_recvstart_direct(psivshmem_conn_t *ivshmem, struct iovec iov[2])
{
	int cur = ivshmem->recv_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->local_com->buf[cur];

	unsigned len = ivshmembuf->header.len;
	char *data = IVSHMEM_DATA(ivshmembuf, len);

	iov[0].iov_base = data;
	iov[0].iov_len = len;

	struct ivshmem_direct_header *dh = (struct ivshmem_direct_header *)(data - sizeof(*dh)); // ############

	iov[1].iov_base = dh->base + ivshmem->direct_offset;
	iov[1].iov_len = dh->len;
}


static inline
void pscom_ivshmem_recvdone(psivshmem_conn_t *ivshmem)
{
	int cur = ivshmem->recv_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->local_com->buf[cur];

	shm_mb();	// #####################################

	/* Notification: message is read */
	ivshmembuf->header.msg_type = IVSHMEM_MSGTYPE_NONE;

	/* free buffer */
	ivshmem->recv_cur = (ivshmem->recv_cur + 1) % IVSHMEM_BUFS;
}


static inline
void pscom_ivshmem_recvdone_direct(psivshmem_conn_t *ivshmem)
{
	int cur = ivshmem->recv_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->local_com->buf[cur];

	shm_mb();  	// ##########################################

	/* Notification: message is read */
	ivshmembuf->header.msg_type = IVSHMEM_MSGTYPE_DIRECT_DONE;

	/* free buffer */
	ivshmem->recv_cur = (ivshmem->recv_cur + 1) % IVSHMEM_BUFS;
}


static
int pscom_ivshmem_do_read(pscom_poll_reader_t *reader)
{
	pscom_con_t *con = list_entry(reader, pscom_con_t, poll_reader);
	uint32_t ret;
	char *buf;
	unsigned int len;

	ret = pscom_ivshmem_canrecv(&con->arch.ivshmem);

	if (ret == IVSHMEM_MSGTYPE_STD) {
		pscom_ivshmem_recvstart(&con->arch.ivshmem, &buf, &len); 	
		pscom_read_done(con, buf, len);
		pscom_ivshmem_recvdone(&con->arch.ivshmem);	
		return 1;
	} else if (ret == IVSHMEM_MSGTYPE_DIRECT) {
		struct iovec iov[2];
		pscom_ivshmem_recvstart_direct(&con->arch.ivshmem, iov);
		pscom_read_done(con, iov[0].iov_base, iov[0].iov_len);
		pscom_read_done(con, iov[1].iov_base, iov[1].iov_len);
		pscom_ivshmem_recvdone_direct(&con->arch.ivshmem);
		return 1;
	}

	// assert(ret == SHM_MSGTYPE_NONE || ret == SHM_MSGTYPE_DIRECT_DONE);
	return 0;
}

/*
static
int _pscom_ivshmem_do_read(pscom_con_t *con, psivshmem_con_info_t *mcon)
{
	void *buf;
	int size;

	size = psivshmem_recvlook(mcon, &buf);

	if (size >= 0) {
		perf_add("ivshmem_do_read");
		pscom_read_done(con, buf, size);

		psivshmem_recvdone(mcon);
		return 1;
	} else if ((size == -EINTR) || (size == -EAGAIN)) {
		// Nothing received
		return 0;
	} else {
		// Error
		errno = -size;
		pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_STDERROR);
		return 1;
	}
}


static
int pscom_ivshmem_do_read(pscom_poll_reader_t *reader)
{
	pscom_con_t *con = list_entry(reader, pscom_con_t, poll_reader);
	psivshmem_con_info_t *mcon = con->arch.ivshmem.mcon;

	return _pscom_ivshmem_do_read(con, mcon);
}
*/


static
void pscom_ivshmem_do_write(pscom_con_t *con)
{
	unsigned int len;
	struct iovec iov[2];
	pscom_req_t *req;

	req = pscom_write_get_iov(con, iov);  // ###########################################

	if (req && pscom_ivshmem_cansend(&con->arch.ivshmem)) {   // ###########################
		if (iov[1].iov_len < ivshmem_direct ||
		    iov[0].iov_len > (IVSHMEM_BUFLEN - sizeof(struct ivshmem_direct_header))) { // #########
		do_buffered_send:

			/* Buffered send : Send through the send & receive buffers. */

			len = iov[0].iov_len + iov[1].iov_len;
			len = pscom_min(len, IVSHMEM_BUFLEN);

			ivshmem_iovsend(&con->arch.ivshmem, iov, len);  // ########################

			pscom_write_done(con, req, len);
		} else if (is_psivshmem_ptr(iov[1].iov_base)) { // ################################
			/* Direct send : Send a reference to the data iov[1]. */

			psivshmem_msg_t *msg = ivshmem_iovsend_direct(&con->arch.ivshmem, iov); // ########

			pscom_write_pending(con, req, iov[0].iov_len + iov[1].iov_len);

			/* The shm_iovsend_direct is active as long as msg->msg_type == IVSHMEM_MSGTYPE_DIRECT.
			   We have to call pscom_write_pending_done(con, req) when we got the ack msg_type == SHM_MSGTYPE_DIRECT_DONE. */

			ivshmem_pending_io_enq(con, msg, req, NULL); // #######################

			pscom.stat.ivshmem_direct++;  // ADDED to struct
		} else {
			/* Indirect send : Copy data iov[1] to a shared region and send a reference to it. */
			/* Size is good for direct send, but the data is not inside the shared mem region */

			void *data;
			psivshmem_msg_t *msg;

			if (!is_psivshmem_enabled()) goto do_buffered_send; // Direct shm is disabled.############

			data = malloc(iov[1].iov_len); // try to get a buffer inside the shared mem region ~~~~~~~~~~~~~~~~~~~~~~~~~~~~+++++++++++

			if (unlikely(!is_psivshmem_ptr(data))) {
				// Still a non shared buffer
				free(data);
				pscom.stat.ivshmem_direct_failed++;
				goto do_buffered_send; // Giving up. Fallback to buffered send.
			}

			memcpy(data, iov[1].iov_base, iov[1].iov_len);
			iov[1].iov_basivshmem data;

			msg = pscom_ivshmem_iovsend_direct(&con->arch.ivshmem, iov); // ######################

			pscom_write_done(con, req, iov[0].iov_len + iov[1].iov_len);

			pscom_ivshmem_pending_io_enq(con, msg, NULL, data);  // ###############################


			/* Count messages which should but cant be send with direct_send.
			   Means iov_len >= shm_direct and false == is_psshm_ptr().
			*/
			pscom.stat.ivshmem_direct_nonshmptr++;
		}


	}
}


/*
static
void pscom_ivshmem_do_write(pscom_con_t *con)
{
	unsigned int len;
	struct iovec iov[2];
	pscom_req_t *req;

	req = pscom_write_get_iov(con, iov);

	if (req) {
		psivshmem_con_info_t *mcon = con->arch.ivshmem.mcon;
		len = iov[0].iov_len + iov[1].iov_len;

		perf_add("ivshmem_sendv");
		int rlen = psivshmem_sendv(mcon, iov, len);

		if (rlen >= 0) {
			pscom_write_done(con, req, rlen);
			pscom_check_cq_poll();
		} else if ((rlen == -EINTR) || (rlen == -EAGAIN)) {
			// Busy: Maybe out of tokens? try to read more tokens:
			_pscom_ivshmem_do_read(con, mcon);
		} else {
			// Error
			pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
		}
	}
}
*/

/*
 * ++ RMA rendezvous begin
 */
#ifdef IVSHMEM_USE_RNDV

typedef struct pscom_rendezvous_data_ivshmem {
	struct psivshmem_rma_req	rma_req;
	pscom_req_t		*rendezvous_req; // Receiving side: users receive request (or generated request)
	pscom_con_t		*con;
	void			(*io_done)(void *priv);
	void			*priv;
} pscom_rendezvous_data_ivshmem_t;


static inline
pscom_rendezvous_data_ivshmem_t *get_req_data(pscom_rendezvous_data_t *rd)
{
	_pscom_rendezvous_data_ivshmem_t *data = &rd->arch.ivshmem;
	pscom_rendezvous_data_ivshmem_t *res = (pscom_rendezvous_data_ivshmem_t *) data;
	assert(sizeof(*res) <= sizeof(*data));
	return res;
}


static
unsigned int pscom_ivshmem_rma_mem_register(pscom_con_t *con, pscom_rendezvous_data_t *rd)
{
	int err = 0;
	pscom_rendezvous_data_ivshmem_t *ivshmem_rd = get_req_data(rd);
	psivshmem_con_info_t *ci = con->arch.ivshmem.mcon;
	psivshmem_rma_mreg_t *mreg = &ivshmem_rd->rma_req.mreg;

#ifdef IVSHMEM_RNDV_USE_PADDING
#ifdef   IVSHMEM_RNDV_RDMA_WRITE
#error   IVSHMEM_RNDV_USE_PADDING and IVSHMEM_RNDV_RDMA_WRITE are mutually exclusive!
#endif

	rd->msg.arch.ivshmem.padding_size = (IVSHMEM_RNDV_PADDING_SIZE - ((long long int)rd->msg.data) % IVSHMEM_RNDV_PADDING_SIZE) % IVSHMEM_RNDV_PADDING_SIZE;

	memcpy(rd->msg.arch.ivshmem.padding_data, rd->msg.data, rd->msg.arch.ivshmem.padding_size);

	/* get mem region */
	perf_add("ivshmem_acquire_rma_mreg");
	err = psivshmem_acquire_rma_mreg(mreg, rd->msg.data + rd->msg.arch.ivshmem.padding_size, rd->msg.data_len - rd->msg.arch.ivshmem.padding_size, ci);
	assert(!err);

	if (err) goto err_get_region;

	rd->msg.arch.ivshmem.mr_key  = mreg->mem_info.mr->rkey;
	rd->msg.arch.ivshmem.mr_addr = (uint64_t)mreg->mem_info.ptr;

	return sizeof(rd->msg.arch.ivshmem) - sizeof(rd->msg.arch.ivshmem.padding_data) + rd->msg.arch.ivshmem.padding_size;
#else

	/* get mem region */
	perf_add("ivshmem_acquire_rma_mreg2");
	err = psivshmem_acquire_rma_mreg(mreg, rd->msg.data, rd->msg.data_len, ci);
	assert(!err);

	if (err) goto err_get_region;

	rd->msg.arch.ivshmem.mr_key  = mreg->mem_info.mr->rkey;
	rd->msg.arch.ivshmem.mr_addr = (uint64_t)mreg->mem_info.ptr;

	return sizeof(rd->msg.arch.ivshmem) - sizeof(rd->msg.arch.ivshmem.padding_data);
#endif

err_get_region:
	// ToDo: Handle Errors!
	return 0;
}


static
void pscom_ivshmem_rma_mem_deregister(pscom_con_t *con, pscom_rendezvous_data_t *rd)
{
	pscom_rendezvous_data_ivshmem_t *ivshmem_rd = get_req_data(rd);
	psivshmem_rma_mreg_t *mreg = &ivshmem_rd->rma_req.mreg;

	perf_add("ivshmem_release_rma_mreg");
	psivshmem_release_rma_mreg(mreg);
}


static
void pscom_ivshmem_rma_read_io_done(void *priv, int err)
{
	psivshmem_rma_req_t *dreq = (psivshmem_rma_req_t *)priv;
	pscom_rendezvous_data_ivshmem_t *psivshmem_rd =
		(pscom_rendezvous_data_ivshmem_t *)dreq->priv;

	pscom_req_t *rendezvous_req = psivshmem_rd->rendezvous_req;
	psivshmem_rma_mreg_t *mreg = &psivshmem_rd->rma_req.mreg;

	psivshmem_release_rma_mreg(mreg);

	if (unlikely(err)) {
		rendezvous_req->pub.state |= PSCOM_REQ_STATE_ERROR;
	}
	_pscom_recv_req_done(rendezvous_req);
}


static
int pscom_ivshmem_rma_read(pscom_req_t *rendezvous_req, pscom_rendezvous_data_t *rd)
{
	int err, ret;
	pscom_rendezvous_data_ivshmem_t *psivshmem_rd = get_req_data(rd);
	psivshmem_rma_req_t *dreq = &psivshmem_rd->rma_req;
	pscom_con_t *con = get_con(rendezvous_req->pub.connection);
	psivshmem_con_info_t *ci = con->arch.ivshmem.mcon;

	perf_add("ivshmem_rma_read");
#ifdef IVSHMEM_RNDV_USE_PADDING
	memcpy(rendezvous_req->pub.data, rd->msg.arch.ivshmem.padding_data, rd->msg.arch.ivshmem.padding_size);
	rendezvous_req->pub.data += rd->msg.arch.ivshmem.padding_size;
	rendezvous_req->pub.data_len -= rd->msg.arch.ivshmem.padding_size;
#endif

	err = psivshmem_acquire_rma_mreg(&dreq->mreg, rendezvous_req->pub.data, rendezvous_req->pub.data_len, ci);
	assert(!err); // ToDo: Catch error

	dreq->remote_addr = rd->msg.arch.ivshmem.mr_addr;
	dreq->remote_key  = rd->msg.arch.ivshmem.mr_key;
	dreq->data_len = rendezvous_req->pub.data_len;
	dreq->ci = ci;
	dreq->io_done = pscom_ivshmem_rma_read_io_done;
	dreq->priv = psivshmem_rd;

	psivshmem_rd->rendezvous_req = rendezvous_req;

	err = psivshmem_post_rma_get(dreq);
	assert(!err); // ToDo: Catch error

	return 0;
}


static
void pscom_ivshmem_rma_write_io_done(void *priv, int err)
{
	pscom_rendezvous_data_t *rd_data = (pscom_rendezvous_data_t *)priv;
	pscom_rendezvous_data_ivshmem_t *rd_data_ivshmem = get_req_data(rd_data);

	// ToDo: Error propagation
	rd_data_ivshmem->io_done(rd_data_ivshmem->priv);

	pscom_ivshmem_rma_mem_deregister(rd_data_ivshmem->con, rd_data);
	pscom_free(rd_data);
}


/* Send from:
 *   rd_src = (pscom_rendezvous_data_t *)req->pub.user
 *   (rd_src->msg.data, rd_src->msg.data_len)
 *   rd_src->msg.arch.ivshmem.{mr_key, mr_addr}
 * To:
 *   (rd_des->msg.data, rd_des->msg.data_len)
 *   rd_des->msg.arch.ivshmem.{mr_key, mr_addr}
 */

static
int pscom_ivshmem_rma_write(pscom_con_t *con, void *src, pscom_rendezvous_msg_t *des,
			   void (*io_done)(void *priv), void *priv)
{
	pscom_rendezvous_data_t *rd_data = (pscom_rendezvous_data_t *)pscom_malloc(sizeof(*rd_data));
	pscom_rendezvous_data_ivshmem_t *rd_data_ivshmem = get_req_data(rd_data);
	psivshmem_con_info_t *mcon = con->arch.ivshmem.mcon;

	psivshmem_rma_req_t *dreq = &rd_data_ivshmem->rma_req;
	int len, err;

	rd_data->msg.id = (void*)42;
	rd_data->msg.data = src;
	rd_data->msg.data_len = des->data_len;

	len = pscom_ivshmem_rma_mem_register(con, rd_data);
	assert(len); // ToDo: Catch error
/*
	dreq->mreg.mem_info.ptr = xxx;
	dreq->mreg.size = xxx;
	dreq->mreg.mem_ingo.mr->lkey = xxx;
*/
	perf_add("ivshmem_rma_write");

	dreq->remote_addr = des->arch.ivshmem.mr_addr;
	dreq->remote_key  = des->arch.ivshmem.mr_key;
	dreq->data_len = des->data_len;
	dreq->ci = mcon;
	dreq->io_done = pscom_ivshmem_rma_write_io_done;
	dreq->priv = rd_data;

	rd_data_ivshmem->con = con;
	rd_data_ivshmem->io_done = io_done;
	rd_data_ivshmem->priv = priv;

	err = psivshmem_post_rma_put(dreq);
	assert(!err); // ToDo: Catch error
	rd_data = NULL; /* Do not use rd_data after psivshmem_post_rma_put()!
			   io_done might already be called and freed rd_data. */

	return 0;
}
#endif
/*
 * -- RMA rendezvous end
 */

/*
static
void pscom_ivshmem_close(pscom_con_t *con)
{
	psivshmem_con_info_t *mcon = con->arch.ivshmem.mcon;

	if (!mcon) return;

	psivshmem_send_eof(mcon);

	psivshmem_con_cleanup(mcon, NULL);
	psivshmem_con_free(mcon);

	con->arch.ivshmem.mcon = NULL;
}

#ifdef IVSHMEM_USE_RNDV
#ifdef IVSHMEM_RNDV_USE_MALLOC_HOOKS
static void *pscom_ivshmem_morecore_hook(ptrdiff_t incr)
{
	/* Do not return memory back to the OS: (do not trim) *
	if(incr < 0) {
		return __default_morecore(0);
	} else {
		return __default_morecore(incr);
	}
}

static void pscom_ivshmem_free_hook(void *ptr, const void *caller)
{
	static void *(*old_malloc_hook)(size_t, const void *);
	static void (*old_free_hook)(void *, const void *);

	/* !!! __malloc_hook and __free_hook are deprecated !!! *

	__malloc_hook = old_malloc_hook;
	__free_hook = old_free_hook;

	/* !!! TODO: Check registration cache !!! *

	/* Call recursively *
	free (ptr);

	/* Save underlying hooks *
	old_malloc_hook = __malloc_hook;
	old_free_hook = __free_hook;
}
#endif
#endif
*/


/*
static
void pscom_ivshmem_con_init(pscom_con_t *con, int con_fd,
			   psivshmem_con_info_t *mcon)
{
	con->pub.state = PSCOM_CON_STATE_RW;
	con->pub.type = PSCOM_CON_TYPE_IVSHMEM;

	close(con_fd);

	con->arch.ivshmem.mcon = mcon;

	// Only Polling:
	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_poll_read_start;
	con->read_stop = pscom_poll_read_stop;

	con->poll_reader.do_read = pscom_ivshmem_do_read;
	con->do_write = pscom_ivshmem_do_write;
	con->close = pscom_ivshmem_close;

#ifdef IVSHMEM_USE_RNDV
	con->rma_mem_register = pscom_ivshmem_rma_mem_register;
	con->rma_mem_deregister = pscom_ivshmem_rma_mem_deregister;
#ifdef IVSHMEM_RNDV_RDMA_WRITE
	con->rma_write = pscom_ivshmem_rma_write;
#else
	con->rma_read = pscom_ivshmem_rma_read;
#endif

	con->rendezvous_size = pscom.env.rendezvous_size_ivshmem;

#ifdef IVSHMEM_RNDV_DISABLE_FREE_TO_OS

	/* We have to prevent free() from returning memory back to the OS: *

#ifndef IVSHMEM_RNDV_USE_MALLOC_HOOKS
	if (con->rendezvous_size != ~0U) {
		/* See 'man mallopt(3) / M_MMAP_MAX': Setting this parameter to 0 disables the use of mmap(2) for servicing large allocation requests. *
		mallopt(M_MMAP_MAX, 0);

		/* See 'man mallopt(3) / M_TRIM_THRESHOLD': Setting M_TRIM_THRESHOLD to -1 disables trimming completely. *
		mallopt(M_TRIM_THRESHOLD, -1);
	}
#else
	if(__morecore == __default_morecore) {
		/* Switch to our own function pscom_ivshmem_morecore() that does not trim: *
		__morecore = pscom_ivshmem_morecore_hook;
	}

	__free_hook = pscom_ivshmem_free_hook;
#endif

#endif
#endif
}
*/
/*********************************************************************/


void pscom_ivshmem_sock_init(pscom_sock_t *sock)
{
	if (psivshmem_info.size) {
		DPRINT(2, "PSP_IVSHMEM_MALLOC = 1 : size = %lu\n", psivshmem_info.size);
			pscom_env_get_uint(&ivshmem_direct, ENV_IVSHMEM_DIRECT);
	} else {
		DPRINT(2, "PSP_IVSHMEM_MALLOC disabled : %s\n", psivshmem_info.msg);
		ivshmem_direct = (unsigned)~0;
	}

	ivshmem_pending_io.poll_reader.do_read = ivshmem_poll_pending_io;
	INIT_LIST_HEAD(&ivshmem_pending_io.ivshmem_conn_head);
}


static
void pscom_ivshmem_info_msg(ivshmem_conn_t *ivshmem, ivshmem_info_msg_t *msg)
{
	msg->ivshmem_id = ivshmem->local_id;
	msg->direct_ivshmem_id = psivshmem_info.ivshmemid;
	msg->direct_base = psivshmem_info.base;
}


static
void pscom_ivshmem_close(pscom_con_t *con)
{
	if (con->arch.ivshmem.local_com) {
		int i;
		psivshmem_conn_t *ivshmem = &con->arch.ivshmem;

		for (i = 0; i < 5; i++) {
			// ToDo: Unreliable EOF
			if (pscom_ivshmem_cansend(ivshmem)) { // #################################
				pscom_ivshmem_send(ivshmem, NULL, 0); // #########################
				break;
			} else {
				usleep(5*1000);
				sched_yield();
			}
		}

		pscom_ivshmem_cleanup_ivshmem_conn(ivshmem); // ##################################

		assert(list_empty(&con->poll_next_send));
		assert(list_empty(&con->poll_reader.next));
	}
}

static
void pscom_ivshmem_init_con(pscom_con_t *con,
		  int con_fd, psivshmem_conn_t *ivshmem)
{
	con->pub.state = PSCOM_CON_STATE_RW;
	con->pub.type = PSCOM_CON_TYPE_IVSHMEM;

	close(con_fd);

	memcpy(&con->arch.ivshmem, ivshmem, sizeof(*ivshmem));

	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_poll_read_start;
	con->read_stop = pscom_poll_read_stop;

	con->poll_reader.do_read = shm_do_read;  	// +++++
	con->do_write = pscom_ivshmem_do_write;		// +++++
	con->close = pscom_ivshmem_close;		// +++++ 

	con->rendezvous_size = pscom.env.rendezvous_size_ivshmem;
}

static
int ivshmem_is_local(pscom_con_t *con)
{
	return con->pub.remote_con_info.node_id == pscom_get_nodeid();
}


static
void ivshmem_init_ivshmem_conn(shm_conn_t *ivshmem)
{
	memset(ivshmem, 0, sizeof(*ivshmem));
	ivshmem->local_com = NULL;
	ivshmem->remote_com = NULL;
	ivshmem->direct_base = NULL;
}


static
void ivshmem_cleanup_ivshmem_conn(psivshmem_conn_t *ivshmem)
{
	if (ivshmem->local_com) shmdt(ivshmem->local_com);
	ivshmem->local_com = NULL;

	if (ivshmem->remote_com) shmdt(ivshmem->remote_com);
	ivshmem->remote_com = NULL;

	if (ivshmem->direct_base) shmdt(ivshmem->direct_base);
	ivshmem->direct_base = NULL;
}

static
int pscom_ivshmem_connect(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_IVSHMEM;
	psivshmem_conn_t ivshmem;
	psivshmem_info_msg_t msg;
	int err;
	int ack;

	if (!ivshmem_is_local(con)) 
		return 0; /* Dont use sharedmem */

	/* talk ivshmem? */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 1 */
	if ((pscom_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	    (arch != PSCOM_ARCH_IVSHMEM))
		goto err_remote;

	/* step 2 : recv ivshmem_id */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)))
		goto err_remote;

	ivshmem_init_ivshmem_conn(&ivshmem);
	err = pscom_ivshmem_initrecv(&ivshmem) || pscom_ivshmem_initsend(&ivshmem, msg.ivshmem_id);

	pscom_ivshmem_init_direct(&ivshmem, msg.direct_ivshmem_id, msg.direct_base);

	/* step 3 : send ivshmem_id or error */
	pscom_ivshmem_info_msg(&ivshmem, &msg);
	if (err) msg.ivshmem_id = -1;
	pscom_writeall(con_fd, &msg, sizeof(msg));
	if (err) goto err_local;

	/* step 4: Inter VM SharedMemory initialized. Recv final ACK. */
	if ((pscom_readall(con_fd, &ack, sizeof(ack)) != sizeof(ack)) ||
	    (ack == -1)) goto err_ack;


	pscom_ivshmem_init_con(con, con_fd, &ivshmem);

	return 1;
	/* --- */
err_ack:
err_local:
	if (ivshmem.local_com) shmdt(ivshmem.local_com);  	// ########???
	if (ivshmem.remote_com) shmdt(ivshmem.remote_com);	// ########???
err_remote:
	return 0;
}



/*
static
void pscom_ivshmem_init(void)
{
	psivshmem_debug = pscom.env.debug;
	psivshmem_debug_stream = pscom_debug_stream();
	pscom_env_get_str(&psivshmem_hca, ENV_IVSHMEM_HCA);
	pscom_env_get_uint(&psivshmem_port, ENV_IVSHMEM_PORT);
	pscom_env_get_uint(&psivshmem_path_mtu, ENV_IVSHMEM_PATH_MTU);

	pscom_env_get_uint(&psivshmem_recvq_size, ENV_IVSHMEM_RECVQ_SIZE);

	pscom_env_get_int(&psivshmem_global_sendq, ENV_IVSHMEM_GLOBAL_SENDQ);
	pscom_env_get_uint(&psivshmem_compq_size, ENV_IVSHMEM_COMPQ_SIZE);
	if (psivshmem_global_sendq) {
		// One sendq for all connection. limit sendq to compq size.
		psivshmem_sendq_size = psivshmem_compq_size;
	} else {
		// One sendq for each connection. limit sendq to recvq size.
		psivshmem_sendq_size = pscom_min(psivshmem_sendq_size, psivshmem_recvq_size);
	}
	pscom_env_get_uint(&psivshmem_sendq_size, ENV_IVSHMEM_SENDQ_SIZE);

	psivshmem_pending_tokens = psivshmem_pending_tokens_suggestion();
	pscom_env_get_uint(&psivshmem_pending_tokens, ENV_IVSHMEM_PENDING_TOKENS);

//	if (!psivshmem_global_sendq && psivshmem_sendq_size == psivshmem_recvq_size) {
//		// Disable event counting:
//		psivshmem_event_count = 0;
//	}
	pscom_env_get_int(&psivshmem_event_count, ENV_IVSHMEM_EVENT_CNT);
	pscom_env_get_int(&psivshmem_ignore_wrong_opcodes, ENV_IVSHMEM_IGNORE_WRONG_OPCODES);
	pscom_env_get_int(&psivshmem_lid_offset, ENV_IVSHMEM_LID_OFFSET);

	INIT_LIST_HEAD(&pscom_cq_poll.next);
	pscom_cq_poll.do_read = pscom_poll_cq;

}
*/

/*
static
int pscom_ivshmem_connect(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_IVSHMEM;
	psivshmem_con_info_t *mcon = psivshmem_con_create();
	psivshmem_info_msg_t msg;
	int call_cleanup_con = 0;
	int err;

	if (psivshmem_init() || !mcon)
		goto dont_use;  /* Dont use ivshmem *

	/* We want talk ivshmem *
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 1 *
	if ((pscom_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	    (arch != PSCOM_ARCH_IVSHMEM))
		goto err_remote;

	/* step 2 : recv connection id's *
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)))
		goto err_remote;

	err = psivshmem_con_init(mcon, NULL, NULL);
	if (!err) {
		call_cleanup_con = 1;
		err = psivshmem_con_connect(mcon, &msg);
	}

	/* step 3 : send connection id's (or error) *
	if (!err) {
		psivshmem_con_get_info_msg(mcon, &msg);
	} else {
		msg.lid = 0xffff; // send error
	}

	pscom_writeall(con_fd, &msg, sizeof(msg));

	if (err) goto err_connect;

	/* step 4: ivshmem initialized. Recv final ACK. *
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	    (msg.lid == 0xffff)) goto err_ack;

	pscom_ivshmem_con_init(con, con_fd, mcon);

	return 1;
	/* --- *
err_ack:
err_connect:
	if (call_cleanup_con) psivshmem_con_cleanup(mcon, NULL);
err_remote:
dont_use:
	if (mcon) psivshmem_con_free(mcon);
	return 0;
}
*/


static
int pscom_ivshmem_accept(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_IVSHMEM;
	psivshmem_conn_t ivshmem;
	psivshmem_info_msg_t msg;
	int ack;

	ivshmem_init_ivshmem_conn(&ivshmem);  // +++++

	if ((!ivshmem_is_local(con)) || pscom_ivshmem_initrecv(&ivshmem)) {
		arch = PSCOM_ARCH_ERROR;
		pscom_writeall(con_fd, &arch, sizeof(arch));
		goto dont_use; /* Dont use inter vm sharedmem */
	}

	/* step 1:  Yes, we talk IVSHMEM. */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 2: Send ivshmem_id. */
	pscom_ivshmem_info_msg(&ivshmem, &msg);
	pscom_writeall(con_fd, &msg, sizeof(msg));


	/* step 3: Recv ivshmem_id. */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	    msg.ivshmem_id == -1) goto err_remote;

	if (pscom_ivshmem_initsend(&ivshmem, msg.ivshmem_id)) goto err_local;

	pscom_ivshmem_init_direct(&ivshmem, msg.direct_ivshmem_id, msg.direct_base);

	/* step 4: inter VM SHM initialized. Send final ACK. */
	ack = 0;
	pscom_writeall(con_fd, &ack, sizeof(ack));

	pscom_ivshmem_init_con(con, con_fd, &ivshmem);

	return 1;
	/* --- */
err_local:
	ack = -1; /* send error */
	pscom_writeall(con_fd, &ack, sizeof(ack));
err_remote:
dont_use:
	ivshmem_cleanup_ivshmem_conn(&ivshmem);
	return 0; /* ivshmem failed */
}

/*
static
int pscom_ivshmem_accept(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_IVSHMEM;
	psivshmem_con_info_t *mcon = NULL;
	psivshmem_info_msg_t msg;

	if (psivshmem_init())
		goto out_noivshmem;

	mcon = psivshmem_con_create();
	if (!mcon)
		goto out_noivshmem;

	if (psivshmem_con_init(mcon, NULL, NULL))
		goto err_con_init;

	/* step 1:  Yes, we talk ivshmem. *
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 2: Send Connection id's *
	psivshmem_con_get_info_msg(mcon, &msg);

	pscom_writeall(con_fd, &msg, sizeof(msg));

	/* step 3 : recv connection id's *
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	    (msg.lid == 0xffff))
		goto err_remote;

	if (psivshmem_con_connect(mcon, &msg))
		goto err_connect_con;

	/* step 4: OPENIVSHMEM mem initialized. Send final ACK. *
	msg.lid = 0;
	pscom_writeall(con_fd, &msg, sizeof(msg));

	pscom_ivshmem_con_init(con, con_fd, mcon);

	return 1;
	/* --- *
err_connect_con:
	/* Send NACK *
	msg.lid = 0xffff;
	pscom_writeall(con_fd, &msg, sizeof(msg));
err_remote:
	psivshmem_con_cleanup(mcon, NULL);
err_con_init:
out_noivshmem:
	if (mcon) psivshmem_con_free(mcon);
	arch = PSCOM_ARCH_ERROR;
	pscom_writeall(con_fd, &arch, sizeof(arch));
	return 0; /* Dont use ivshmem *
	/* --- *
}
*/

pscom_plugin_t pscom_plugin = {
	.name		= "ivshmem",
	.version	= PSCOM_PLUGIN_VERSION,
	.arch_id	= PSCOM_ARCH_IVSHMEM,
	.priority	= PSCOM_IVSHMEM_PRIO,

	.init		= NULL,					//pscom_ivshmem_init,
	.destroy	= NULL,
	.sock_init	= pscom_ivshmem_sock_init, 	 	//NULL,
	.sock_destroy	= NULL,  	// ToDo: needs to be implemented!!
	.con_connect	= pscom_ivshmem_connect,
	.con_accept	= pscom_ivshmem_accept,
};
