/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * psp_ivshmem.c: OPENIB/Infiniband communication
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "psport_priv.h"
#include "psport_ivshmem.h"

#define IVSHMEM_DONT_USE_ZERO_COPY
#include "../pscom4ivshmem/psivshmem.c"


static
int PSP_do_read_ivshmem(PSP_Port_t *port, PSP_Connection_t *con)
{
    void *buf;
    int size;

    size = psivshmem_recvlook(con->arch.ivshmem.mcon, &buf);

    if (size > 0) {
	PSP_read_do(port, con, buf, size);

	psivshmem_recvdone(con->arch.ivshmem.mcon);
	return 1;
    } else if (size == -EAGAIN) {
	/* retry later */
	return 0;
    } else if (size == 0) {
	PSP_con_terminate(port, con, PSP_TERMINATE_REASON_REMOTECLOSE);
    } else {
	errno = -size;
	PSP_con_terminate(port, con, PSP_TERMINATE_REASON_READ_FAILED);
    }

    return 0;
}

static
void PSP_do_write_ivshmem(PSP_Port_t *port, PSP_Connection_t *con)
{
    int len, rlen;
    PSP_Req_t *req = con->out.req;

    if (req) {
	len = req->u.req.iov_len;
	rlen = psivshmem_sendv(con->arch.ivshmem.mcon, req->u.req.iov, len);
	if (rlen >= 0) {
	    req->u.req.iov_len -= rlen;
	    PSP_update_sendq(port, con);
	} else if (rlen == -EAGAIN) {
	    /* retry later */
	} else {
	    errno = -rlen;
	    PSP_con_terminate(port, con, PSP_TERMINATE_REASON_WRITE_FAILED);
	}
    }
}

int PSP_do_sendrecv_ivshmem(PSP_Port_t *port)
{
    struct list_head *pos, *next;
    int ret = 0;

    list_for_each_safe(pos, next, &port->ivshmem_list_send) {
	PSP_Connection_t *con = list_entry(pos, PSP_Connection_t, arch.ivshmem.next_send);
	PSP_do_write_ivshmem(port, con);
    }

    /*psivshmem_poll(&default_hca, 0);*/

    /* ToDo: Dont loop over all connections! Use a con receive queue! */
    list_for_each_safe(pos, next, &port->ivshmem_list) {
	PSP_Connection_t *con = list_entry(pos, PSP_Connection_t, arch.ivshmem.next);
	ret = PSP_do_read_ivshmem(port, con);
	if (ret) break;
    }
    return ret;
}

static
void PSP_set_write_ivshmem(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
//    printf("set Write %d ivshmem\n", start);
    if (start) {
	if (list_empty(&con->arch.ivshmem.next_send)) {
	    list_add_tail(&con->arch.ivshmem.next_send, &port->ivshmem_list_send);
	}
	PSP_do_write_ivshmem(port, con);
	/* Dont do anything after this line.
	   PSP_do_write_ivshmem() can reenter PSP_set_write_ivshmem()! */
    } else {
	/* it's save to dequeue more then once */
	list_del_init(&con->arch.ivshmem.next_send);
    }
}

static
void PSP_set_read_ivshmem(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
//    printf("set Read %d ivshmem\n", start);
}

static
void PSP_init_con_ivshmem(PSP_Port_t *port, PSP_Connection_t *con, int con_fd,
			psivshmem_con_info_t *mcon)
{
    con->state = PSP_CON_STATE_OPEN_OPENIB;
    close(con_fd);

    con->arch.ivshmem.mcon = mcon;

    INIT_LIST_HEAD(&con->arch.ivshmem.next_send);
    list_add_tail(&con->arch.ivshmem.next, &port->ivshmem_list);

    con->set_write = PSP_set_write_ivshmem;
    con->set_read = PSP_set_read_ivshmem;
}

void PSP_terminate_con_ivshmem(PSP_Port_t *port, PSP_Connection_t *con)
{
    if (con->arch.ivshmem.mcon) {
	psivshmem_con_info_t *mcon = con->arch.ivshmem.mcon;

	list_del(&con->arch.ivshmem.next_send);
	list_del(&con->arch.ivshmem.next);

	psivshmem_con_cleanup(mcon, &default_hca);
	psivshmem_con_free(mcon);

	con->arch.ivshmem.mcon = NULL;
    }
}


int PSP_connect_ivshmem(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    int arch = PSP_ARCH_OPENIB;
    psivshmem_con_info_t *mcon = psivshmem_con_create();
    psivshmem_info_msg_t msg;
    int call_cleanup_con = 0;
    int err;

    if (!env_ivshmem || psivshmem_init() || !mcon) {
	if (mcon) psivshmem_con_free(mcon);
	return 0; /* Dont use ivshmem */
    }

    /* We want talk ivshmem */
    PSP_writeall(con_fd, &arch, sizeof(arch));

    /* step 1 */
    if ((PSP_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	(arch != PSP_ARCH_OPENIB))
	goto err_remote;

    /* step 2 : recv connection id's */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)))
	goto err_remote;

    err = psivshmem_con_init(mcon, &default_hca, &default_port);
    if (!err) {
	call_cleanup_con = 1;
	err = psivshmem_con_connect(mcon, &msg);
    }

    /* step 3 : send connection id's (or error) */
    psivshmem_con_get_info_msg(mcon, &msg);
    if (err) msg.lid = 0xffff;

    PSP_writeall(con_fd, &msg, sizeof(msg));

    if (err) goto err_connect;

    /* step 4: ivshmem initialized. Recv final ACK. */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	(msg.lid == 0xffff)) goto err_ack;

    PSP_init_con_ivshmem(port, con, con_fd, mcon);

    return 1;
    /* --- */
 err_ack:
 err_connect:
    if (call_cleanup_con) psivshmem_con_cleanup(mcon, &default_hca);
 err_remote:
    if (mcon) psivshmem_con_free(mcon);
    return 0;
}


int PSP_accept_ivshmem(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    int arch = PSP_ARCH_OPENIB;
    psivshmem_con_info_t *mcon = NULL;
    psivshmem_info_msg_t msg;

    if (!env_ivshmem || psivshmem_init())
	goto out_noivshmem;

    if (!(mcon = psivshmem_con_create()))
	goto out_noivshmem;

    if (psivshmem_con_init(mcon, &default_hca, &default_port)) {
	goto err_init_con;
    }

    /* step 1:  Yes, we talk ivshmem. */
    PSP_writeall(con_fd, &arch, sizeof(arch));

    /* step 2: Send Connection id's */
    psivshmem_con_get_info_msg(mcon, &msg);

    PSP_writeall(con_fd, &msg, sizeof(msg));

    /* step 3 : recv connection id's */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	(msg.lid == 0xffff))
	goto err_remote;


    if (psivshmem_con_connect(mcon, &msg))
	goto err_connect_con;

    /* step 4: OPENIB mem initialized. Send final ACK. */
    msg.lid = 0;
    PSP_writeall(con_fd, &msg, sizeof(msg));

    PSP_init_con_ivshmem(port, con, con_fd, mcon);

    return 1;
    /* --- */
 err_connect_con:
    /* Send NACK */
    msg.lid = 0xffff;
    PSP_writeall(con_fd, &msg, sizeof(msg));
 err_remote:
    psivshmem_con_cleanup(mcon, &default_hca);
 err_init_con:
 out_noivshmem:
    if (mcon) psivshmem_con_free(mcon);
    arch = PSP_ARCH_ERROR;
    PSP_writeall(con_fd, &arch, sizeof(arch));
    return 0; /* Dont use ivshmem */
    /* --- */

}


void PSP_ivshmem_init(PSP_Port_t *port)
{
    psivshmem_debug = env_debug;
    port->ivshmem_users = 0;
    INIT_LIST_HEAD(&port->ivshmem_list);
    INIT_LIST_HEAD(&port->ivshmem_list_send);
}
