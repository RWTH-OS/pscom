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
 * psport_openib.h: Header for OPENIB/Infiniband communication
 */

#ifndef _PSPORT_IVSHMEM_H_
#define _PSPORT_IVSHMEM_H_

#include <sys/ipc.h>
#include <sys/shm.h>

typedef struct psivshmem_info_s {
	struct list_head next;
	struct list_head next_send;
	struct psivshmem_con_info *mcon;
} psivshmem_info_t;

int PSP_connect_ivshmem(PSP_Port_t *port, PSP_Connection_t *con, int con_fd);
int PSP_accept_ivshmem(PSP_Port_t *port, PSP_Connection_t *con, int con_fd);
int PSP_do_sendrecv_ivshmem(PSP_Port_t *port);

void PSP_ivshmem_init(PSP_Port_t *port);

void PSP_terminate_con_ivshmem(PSP_Port_t *port, PSP_Connection_t *con);

#endif /* _PSPORT_IVSHMEM_H_ */
