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


#if defined(__x86_64__) && !(defined(__KNC__) || defined(__MIC__))
/* We need memory barriers only for x86_64 (?) */
#define ivshmem_mb()    asm volatile("mfence":::"memory")
#elif defined(__ia64__)
#define ivshmem_mb()    asm volatile ("mf" ::: "memory")
#else
/* Dont need it for ia32, alpha (?) */
#define ivshmem_mb()    asm volatile ("" :::"memory")
#endif

/*################################################################################################*/




static 
unsigned ivshmem_direct = 400;

static
struct {
	struct pscom_poll_reader poll_reader; // calling shm_poll_pending_io(). Used if !list_empty(shm_conn_head)
	struct list_head	ivshmem_conn_head; // shm_conn_t.pending_io_next_conn.
} ivshmem_pending_io;


struct ivshmem_direct_header {
	void	*base;
	size_t	len;
};


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

	memset(buf, 0, sizeof(psivshmem_com_t)); /* init */  // with zeros

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

static inline
uint32_t pscom_ivshmem_canrecv(psivshmem_conn_t *ivshmem)
{
	int cur = ivshmem->recv_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->local_com->buf[cur];  // +++++
	return ivshmembuf->header.msg_type;
}


/* receive.
   Call only if shm_canrecv() == SHM_MSGTYPE_STD (no check inside)!
*/
static inline
void pscom_ivshmem_recvstart(psivshmem_conn_t *ivshmem, char **buf, unsigned int *len)
{
	int cur = ivshmem->recv_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->local_com->buf[cur];  // +++++

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

	struct ivshmem_direct_header *dh = (struct ivshmem_direct_header *)(data - sizeof(*dh)); // +++++ defined in this *.c file

	iov[1].iov_base = dh->base + ivshmem->direct_offset;
	iov[1].iov_len = dh->len;
}


static inline
void pscom_ivshmem_recvdone(psivshmem_conn_t *ivshmem)
{
	int cur = ivshmem->recv_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->local_com->buf[cur];

	shm_mb();	// +++++ macro

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

	shm_mb();  	// +++++ macro

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


static
void pscom_ivshmem_pending_io_conn_enq(psivshmem_conn_t *ivshmem)
{
	if (list_empty(&ivshmem_pending_io.ivshmem_conn_head)) {
		// Start polling for pending_io
		list_add_tail(&ivshmem_pending_io.poll_reader.next, &pscom.poll_reader);
	}
	list_add_tail(&ivshmem->pending_io_next_conn, &ivshmem_pending_io.ivshmem_conn_head);
}


/*
 * Enqueue a pending shared mem operation msg on connection con.
 *
 * After the io finishes call:
 *  - pscom_write_pending_done(con, req), if req != NULL
 *  - free(data), if data != NULL
 * see shm_check_pending_io().
 */
static
void pscom_ivshmem_pending_io_enq(pscom_con_t *con, psivshmem_msg_t *msg, pscom_req_t *req, void *data)
{
	psivshmem_conn_t *ivshmmem = &con->arch.ivshmem;
	struct ivshmem_pending *ivp = malloc(sizeof(*ivp));
	struct ivshmem_pending *old_ivp;
	ivp->next = NULL;
	ivp->con = con;
	ivp->msg = msg;
	ivp->req = req;
	ivp->data = data;

	if (!ivshmem->ivshmem_pending) {
		pscom_ivshmem_pending_io_conn_enq(shm); // +++++
		ivshmem->ivshmem_pending = ivp;
	} else {
		// Append at the end
		for (old_ivp = ivshmem->ivshmem_pending; old_ivp->next; old_ivp = old_ivp->next); // +++
		old_ivp->next = ivp;
	}
}

static
void pscom_ivshmem_do_write(pscom_con_t *con)
{
	unsigned int len;	// Länge
	struct iovec iov[2];	// vectored I/O
	pscom_req_t *req;	// pscom request type

	req = pscom_write_get_iov(con, iov);  // pscom_io.c

	if (req && pscom_ivshmem_cansend(&con->arch.ivshmem)) {   // +++++
		if (iov[1].iov_len < ivshmem_direct ||
		    iov[0].iov_len > (IVSHMEM_BUFLEN - sizeof(struct ivshmem_direct_header))) { // +++++
		do_buffered_send:

			/* Buffered send : Send through the send & receive buffers. */

			len = iov[0].iov_len + iov[1].iov_len;
			len = pscom_min(len, IVSHMEM_BUFLEN);

			pscom_ivshmem_iovsend(&con->arch.ivshmem, iov, len);  // +++++

			pscom_write_done(con, req, len);
		} else if (is_psivshmem_ptr(iov[1].iov_base)) { // +++++
			/* Direct send : Send a reference to the data iov[1]. */

			psivshmem_msg_t *msg = pscom_ivshmem_iovsend_direct(&con->arch.ivshmem, iov); // +++++

			pscom_write_pending(con, req, iov[0].iov_len + iov[1].iov_len);

			/* The shm_iovsend_direct is active as long as msg->msg_type == IVSHMEM_MSGTYPE_DIRECT.
			   We have to call pscom_write_pending_done(con, req) when we got the ack msg_type == SHM_MSGTYPE_DIRECT_DONE. */

			pscom_ivshmem_pending_io_enq(con, msg, req, NULL); // +++++

			pscom.stat.ivshmem_direct++;  // ADDED to struct
		} else {
			/* Indirect send : Copy data iov[1] to a shared region and send a reference to it. */
			/* Size is good for direct send, but the data is not inside the shared mem region */

			void *data;
			psivshmem_msg_t *msg;

			if (!is_psivshmem_enabled()) goto do_buffered_send; // Direct shm is disabled.

			data = malloc(iov[1].iov_len); // try to get a buffer inside the shared mem region ~~~~~~~~~~~~~~~~~~~~~~~~~~~~+++++++++++

			if (unlikely(!is_psivshmem_ptr(data))) {
				// Still a non shared buffer
				free(data);
				pscom.stat.ivshmem_direct_failed++;
				goto do_buffered_send; // Giving up. Fallback to buffered send.
			}

			memcpy(data, iov[1].iov_base, iov[1].iov_len);
			iov[1].iov_basivshmem data;

			msg = pscom_ivshmem_iovsend_direct(&con->arch.ivshmem, iov); // +++++

			pscom_write_done(con, req, iov[0].iov_len + iov[1].iov_len);

			pscom_ivshmem_pending_io_enq(con, msg, NULL, data);  // +++++


			/* Count messages which should but cant be send with direct_send.
			   Means iov_len >= shm_direct and false == is_psshm_ptr().
			*/
			pscom.stat.ivshmem_direct_nonshmptr++;
		}


	}
}


/*********************************************************************/



static
void pscom_ivshmem_pending_io_conn_deq(psivshmem_conn_t *ivshmem)
{
	list_del(&ivshmem->pending_io_next_conn);
	if (list_empty(&ivshmem_pending_io.ivshmem_conn_head)) {
		// No shm_conn_t with pending io requests left. Stop polling for pending_io.
		list_del(&ivshmem_pending_io.poll_reader.next);
	}
}

static
void pscom_ivshmem_check_pending_io(psivshmem_conn_t *ivshmem)
{
	struct ivshmem_pending *ivp;
	while (((ivp = ivshmem->ivshmem_pending)) && ivp->msg->msg_type == IVSHMEM_MSGTYPE_DIRECT_DONE) {
		// finish request
		if (ivp->req) pscom_write_pending_done(ivp->con, ivp->req); // direct send done
		if (ivp->data) free(ivp->data); // indirect send done

		// Free buffer for next send
		ivp->msg->msg_type = IVSHMEM_MSGTYPE_NONE;

		// loop next sp
		ivshmem->ivshmem_pending = ivp->next;
		free(ivp);

		if (!ivshmem->ivshmem_pending) {
			// shm_conn_t is without pending io requests.
			pscom_ivshmem_pending_io_conn_deq(shm);
			break;
		}
	}
}

static
int pscom_ivshmem_poll_pending_io(pscom_poll_reader_t *poll_reader)
{
	struct list_head *pos, *next;
	// For each shm_conn_t shm
	list_for_each_safe(pos, next, &ivshmem_pending_io.ivshmem_conn_head) {
		psivshmem_conn_t *ivshmem = list_entry(pos, psivshmem_conn_t, pending_io_next_conn);

		pscom_ivshmem_check_pending_io(shm);
	}
	return 0;
}



void pscom_ivshmem_sock_init(pscom_sock_t *sock)
{
	if (psivshmem_info.size) {
		DPRINT(2, "PSP_IVSHMEM_MALLOC = 1 : size = %lu\n", psivshmem_info.size);
			pscom_env_get_uint(&ivshmem_direct, ENV_IVSHMEM_DIRECT);
	} else {
		DPRINT(2, "PSP_IVSHMEM_MALLOC disabled : %s\n", psivshmem_info.msg);
		ivshmem_direct = (unsigned)~0;
	}

	ivshmem_pending_io.poll_reader.do_read = pscom_ivshmem_poll_pending_io;
	INIT_LIST_HEAD(&ivshmem_pending_io.ivshmem_conn_head);
}


static
void pscom_ivshmem_info_msg(ivshmem_conn_t *ivshmem, ivshmem_info_msg_t *msg)
{
	msg->ivshmem_id = ivshmem->local_id;
	msg->direct_ivshmem_id = psivshmem_info.ivshmemid;
	msg->direct_base = psivshmem_info.base;
}



static inline
int pscom_ivshmem_cansend(psivshmem_conn_t *ivshmem)
{
	int cur = ivshmem->send_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->remote_com->buf[cur];
	return ivshmembuf->header.msg_type == IVSHMEM_MSGTYPE_NONE;
}


static
void pscom_ivshmem_send(psivshmem_conn_t *ivshmem, char *buf, int len)
{
	int cur = ivshmem->send_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->remote_com->buf[cur];  // sind header sauber aufgeteilt????? 

	/* copy to sharedmem */
	memcpy(IVSHMEM_DATA(ivshmembuf, len), buf, len);
	ivshmembuf->header.len = len;

	ivshmem_mb(); // +++++

	/* Notification about the new message */
	ivshmembuf->header.msg_type = IVSHMEM_MSGTYPE_STD;
	ivshmem->send_cur = (ivshmem->send_cur + 1) % IVSHMEM_BUFS;
}


/* send iov.
   Call only if shm_cansend() == true (no check inside)!
   len must be smaller or equal SHM_BUFLEN!
*/
static
void pscom_ivshmem_iovsend(psivshmem_conn_t *ivshmem, struct iovec *iov, int len)
{
	int cur = ivshmem->send_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->remote_com->buf[cur];

	/* copy to sharedmem */
	pscom_memcpy_from_iov(IVSHMEM_DATA(ivshmembuf, len), iov, len);  // def in pscom_util.h
	ivshmembuf->header.len = len;

	ivshmem_mb();

	/* Notification about the new message */
	ivshmembuf->header.msg_type = IVSHMEM_MSGTYPE_STD;
	ivshmem->send_cur = (ivshmem->send_cur + 1) % IVSHMEM_BUFS;
}


/* send iov.
   Call only if shm_cansend() == true (no check inside)!
   iov[0].iov_len must be smaller or equal SHM_BUFLEN - sizeof(struct shm_direct_header)!
   is_psshm_ptr(iov[1].iov_base) must be true.
*/


static
psivshmem_msg_t *pscom_ivshmem_iovsend_direct(psivshmem_conn_t *ivshmem, struct iovec *iov)
{
	int cur = ivshmem->send_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->remote_com->buf[cur];
	size_t len0 = iov[0].iov_len;
	char *data = IVSHMEM_DATA(ivshmembuf, len0);

	/* reference to iov[1] before header */
	struct ivshmem_direct_header *dh = (struct ivshmem_direct_header *)(data - sizeof(*dh));
	dh->base = iov[1].iov_base;
	dh->len = iov[1].iov_len;

	/* copy header to sharedmem */
	memcpy(data, iov[0].iov_base, len0);
	ivshmembuf->header.len = len0;

	ivshmem_mb();

	/* Notification about the new message */
	ivshmembuf->header.msg_type = IVSHMEM_MSGTYPE_DIRECT;
	ivshmem->send_cur = (ivshmem->send_cur + 1) % IVSHMEM_BUFS;

	return &ivshmembuf->header;
}

static
void pscom_ivshmem_close(pscom_con_t *con)
{
	if (con->arch.ivshmem.local_com) {
		int i;
		psivshmem_conn_t *ivshmem = &con->arch.ivshmem;

		for (i = 0; i < 5; i++) {
			// ToDo: Unreliable EOF
			if (pscom_ivshmem_cansend(ivshmem)) { // +++++
				pscom_ivshmem_send(ivshmem, NULL, 0); // +++++
				break;
			} else {
				usleep(5*1000);
				sched_yield();
			}
		}

		ivshmem_cleanup_ivshmem_conn(ivshmem); // +++++

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

	con->poll_reader.do_read = pscom_ivshmem_do_read;  	// +++++
	con->do_write = pscom_ivshmem_do_write;			// +++++
	con->close = pscom_ivshmem_close;			// +++++ 

	con->rendezvous_size = pscom.env.rendezvous_size_ivshmem;
}

static
int ivshmem_is_local(pscom_con_t *con)
{
	return con->pub.remote_con_info.node_id == pscom_get_nodeid();
}


static
void ivshmem_init_ivshmem_conn(psivshmem_conn_t *ivshmem)
{
	memset(ivshmem, 0, sizeof(*ivshmem));  // set memory to ZERO 
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

	if (!ivshmem_is_local(con)) // ivshmem_is_local() checks if partner has same nodeID => same node => if not same node return 0; because SHM not possible 
		return 0; /* Dont use sharedmem */

	/* talk ivshmem? */
	pscom_writeall(con_fd, &arch, sizeof(arch)); // write which connection architecure I am using...

	/* step 1 */
	if ((pscom_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	    (arch != PSCOM_ARCH_IVSHMEM))   /*error if partner is using other architecture (means not installed shm or not same host*/
		goto err_remote;

	/* step 2 : recv ivshmem_id */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)))  /*read connection message from partner (especially ID) */
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
