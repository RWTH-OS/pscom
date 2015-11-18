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
 * pscom_openib.c: OPENIB/Infiniband communication
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
#include "pscom_io.h"
#include "pscom_ivshmem.h"
#include "pscom_req.h"
#include "pscom_util.h"


static
struct pscom_poll_reader pscom_cq_poll;

int pscom_poll_cq(pscom_poll_reader_t *reader)
{
	psoib_progress();

	if (!psivshmem_outstanding_cq_entries) {
		/* Stop polling on cq */
		/* it's save to dequeue more then once */
		list_del_init(&reader->next);
	}

	return 0;
}

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


/*
 * ++ RMA rendezvous begin
 */
#ifdef IB_USE_RNDV

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

#ifdef IB_RNDV_USE_PADDING
#ifdef   IB_RNDV_RDMA_WRITE
#error   IB_RNDV_USE_PADDING and IB_RNDV_RDMA_WRITE are mutually exclusive!
#endif

	rd->msg.arch.ivshmem.padding_size = (IB_RNDV_PADDING_SIZE - ((long long int)rd->msg.data) % IB_RNDV_PADDING_SIZE) % IB_RNDV_PADDING_SIZE;

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
#ifdef IB_RNDV_USE_PADDING
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
	psoib_con_info_t *mcon = con->arch.ivshmem.mcon;

	psoib_rma_req_t *dreq = &rd_data_ivshmem->rma_req;
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

	err = psoib_post_rma_put(dreq);
	assert(!err); // ToDo: Catch error
	rd_data = NULL; /* Do not use rd_data after psoib_post_rma_put()!
			   io_done might already be called and freed rd_data. */

	return 0;
}
#endif
/*
 * -- RMA rendezvous end
 */


static
void pscom_ivshmem_close(pscom_con_t *con)
{
	psivsmem_con_info_t *mcon = con->arch.ivshmem.mcon;

	if (!mcon) return;

	psivshmem_send_eof(mcon);

	psivshmem_con_cleanup(mcon, NULL);
	psivshmem_con_free(mcon);

	con->arch.ivshmem.mcon = NULL;
}

#ifdef IB_USE_RNDV
#ifdef IB_RNDV_USE_MALLOC_HOOKS
static void *pscom_ivshmem_morecore_hook(ptrdiff_t incr)
{
	/* Do not return memory back to the OS: (do not trim) */
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

	/* !!! __malloc_hook and __free_hook are deprecated !!! */

	__malloc_hook = old_malloc_hook;
	__free_hook = old_free_hook;

	/* !!! TODO: Check registration cache !!! */

	/* Call recursively */
	free (ptr);

	/* Save underlying hooks */
	old_malloc_hook = __malloc_hook;
	old_free_hook = __free_hook;
}
#endif
#endif


static
void pscom_ivshmem_con_init(pscom_con_t *con, int con_fd,
			   psoib_con_info_t *mcon)
{
	con->pub.state = PSCOM_CON_STATE_RW;
	con->pub.type = PSCOM_CON_TYPE_OPENIB;

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

#ifdef IB_USE_RNDV
	con->rma_mem_register = pscom_ivshmem_rma_mem_register;
	con->rma_mem_deregister = pscom_ivshmem_rma_mem_deregister;
#ifdef IB_RNDV_RDMA_WRITE
	con->rma_write = pscom_ivshmem_rma_write;
#else
	con->rma_read = pscom_ivshmem_rma_read;
#endif

	con->rendezvous_size = pscom.env.rendezvous_size_ivshmem;

#ifdef IB_RNDV_DISABLE_FREE_TO_OS

	/* We have to prevent free() from returning memory back to the OS: */

#ifndef IB_RNDV_USE_MALLOC_HOOKS
	if (con->rendezvous_size != ~0U) {
		/* See 'man mallopt(3) / M_MMAP_MAX': Setting this parameter to 0 disables the use of mmap(2) for servicing large allocation requests. */
		mallopt(M_MMAP_MAX, 0);

		/* See 'man mallopt(3) / M_TRIM_THRESHOLD': Setting M_TRIM_THRESHOLD to -1 disables trimming completely. */
		mallopt(M_TRIM_THRESHOLD, -1);
	}
#else
	if(__morecore == __default_morecore) {
		/* Switch to our own function pscom_openib_morecore() that does not trim: */
		__morecore = pscom_ivshmem_morecore_hook;
	}

	__free_hook = pscom_ivshmem_free_hook;
#endif

#endif
#endif
}

/*********************************************************************/
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


static
int pscom_ivshmem_connect(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_IVSHMEM;
	psivshmem_con_info_t *mcon = psivshmem_con_create();
	psivshmem_info_msg_t msg;
	int call_cleanup_con = 0;
	int err;

	if (psoib_init() || !mcon)
		goto dont_use;  /* Dont use openib */

	/* We want talk openib */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 1 */
	if ((pscom_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	    (arch != PSCOM_ARCH_IVSHMEM))
		goto err_remote;

	/* step 2 : recv connection id's */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)))
		goto err_remote;

	err = psivshmem_con_init(mcon, NULL, NULL);
	if (!err) {
		call_cleanup_con = 1;
		err = psivshmem_con_connect(mcon, &msg);
	}

	/* step 3 : send connection id's (or error) */
	if (!err) {
		psivshmem_con_get_info_msg(mcon, &msg);
	} else {
		msg.lid = 0xffff; // send error
	}

	pscom_writeall(con_fd, &msg, sizeof(msg));

	if (err) goto err_connect;

	/* step 4: openib initialized. Recv final ACK. */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	    (msg.lid == 0xffff)) goto err_ack;

	pscom_ivshmem_con_init(con, con_fd, mcon);

	return 1;
	/* --- */
err_ack:
err_connect:
	if (call_cleanup_con) psivshmem_con_cleanup(mcon, NULL);
err_remote:
dont_use:
	if (mcon) psivshmem_con_free(mcon);
	return 0;
}


static
int pscom_ivshmem_accept(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_IVSHMEM;
	psivshmem_con_info_t *mcon = NULL;
	psivshmem_info_msg_t msg;

	if (psivshmem_init())
		goto out_noopenib;

	mcon = psivshmem_con_create();
	if (!mcon)
		goto out_noivshmem;

	if (psivshmem_con_init(mcon, NULL, NULL))
		goto err_con_init;

	/* step 1:  Yes, we talk openib. */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 2: Send Connection id's */
	psoib_con_get_info_msg(mcon, &msg);

	pscom_writeall(con_fd, &msg, sizeof(msg));

	/* step 3 : recv connection id's */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	    (msg.lid == 0xffff))
		goto err_remote;

	if (psivshmem_con_connect(mcon, &msg))
		goto err_connect_con;

	/* step 4: OPENIB mem initialized. Send final ACK. */
	msg.lid = 0;
	pscom_writeall(con_fd, &msg, sizeof(msg));

	pscom_ivshmem_con_init(con, con_fd, mcon);

	return 1;
	/* --- */
err_connect_con:
	/* Send NACK */
	msg.lid = 0xffff;
	pscom_writeall(con_fd, &msg, sizeof(msg));
err_remote:
	psivshmem_con_cleanup(mcon, NULL);
err_con_init:
out_noivshmem:
	if (mcon) psivshmem_con_free(mcon);
	arch = PSCOM_ARCH_ERROR;
	pscom_writeall(con_fd, &arch, sizeof(arch));
	return 0; /* Dont use openib */
	/* --- */
}


pscom_plugin_t pscom_plugin = {
	.name		= "ivshmem",
	.version	= PSCOM_PLUGIN_VERSION,
	.arch_id	= PSCOM_ARCH_IVSHMEM,
	.priority	= PSCOM_IVSHMEM_PRIO,

	.init		= pscom_ivshmem_init,
	.destroy	= NULL,
	.sock_init	= NULL,
	.sock_destroy	= NULL,
	.con_connect	= pscom_ivshmem_connect,
	.con_accept	= pscom_ivshmem_accept,
};
