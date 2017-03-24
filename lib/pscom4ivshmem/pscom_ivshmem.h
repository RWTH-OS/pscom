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
 * Author:	JonBau
 */
/**
 * pscom_ivshmem.h: Header for INTER-VM Shared Memory Communication
 */

#ifndef _PSCOM_IVSHMEM_H_
#define _PSCOM_IVSHMEM_H_

//#include <sys/shm.h>
#include <stdint.h>
#include <stddef.h>
#include "list.h"
#include "pscom_types.h"
#include "pscom_plugin.h"
#include "psivshmem.h"



#if !(defined(__KNC__) || defined(__MIC__))
#define IVSHMEM_BUFS 8
#define IVSHMEM_BUFLEN (8192 - sizeof(ivshmem_msg_t))
#else
/* On KNC use more, but much smaller shm buffers. Using direct shm to archive a good throughput. */
#define IVSHMEM_BUFS 16
#define IVSHMEM_BUFLEN ((1 * 1024) - sizeof(ivshmem_msg_t))
#endif

#define IVSHMEM_MSGTYPE_NONE 0
#define IVSHMEM_MSGTYPE_STD	 1
#define IVSHMEM_MSGTYPE_DIRECT 2
#define IVSHMEM_MSGTYPE_DIRECT_DONE 3
#define IVSHMEM_DIFFERENT_HOSTS (-2) // added
#define IVSHMEM_ERROR_MSG (-1) // added

#define IVSHMEM_DATA(buf, len) ((char*)(&(buf)->header) - (((len) + 7) & ~7))

static int ivshmem_init_state = 1;

typedef struct ivshmem_msg_s {
        uint32_t len;
        volatile uint32_t msg_type;
} ivshmem_msg_t;



// contact endpoint info
typedef struct psivshmem_info_msg_s {

//	int ivshmem_id; /

//	int direct_ivshmem_id;	/* ivshmem direct shared mem id */
	void *direct_base;	/* base pointer of the IVM shared mem segment */	
	signed long direct_offset;

	long ivshmem_buf_offset;
	char hostname[64];	/* for comparison */ 

} psivshmem_info_msg_t;


typedef struct psivshmem_buf_s {
	uint8_t _data[IVSHMEM_BUFLEN];
	ivshmem_msg_t header;
} psivshmem_buf_t;


typedef struct ivshmem_com_s {
	psivshmem_buf_t	buf[IVSHMEM_BUFS];
} psivshmem_com_t;


typedef struct ivshmem_conn_s {
	psivshmem_com_t	*local_com;  /* local */
	psivshmem_com_t	*remote_com; /* remote */
	int		recv_cur;
	int		send_cur;
	long		direct_offset; /* base offset for shm direct */
	int		local_id;
	int		remote_id;
	void 		*direct_base; /* shm direct base */

	ivshmem_pci_dev_t device;

	struct list_head pending_io_next_conn; /* next shm_conn_t with pending io. Head: shm_pending_io.shm_conn_head */
	struct ivshmem_pending *ivshmem_pending; /* first pending io request of this connection */
} ivshmem_conn_t;


typedef struct ivshmem_info_msg_s {
	int ivshmem_id;
	int direct_ivshmem_id;      /* shm direct shared mem id */ 
	void *direct_base;      /* base pointer of the shared mem segment */ 
} ivshmem_info_msg_t; 




typedef struct ivshmem_sock_s {
} ivshmem_sock_t;


extern pscom_plugin_t pscom_plugin_ivshmem;

#endif /* _PSCOM_IVSHMEM_H_ */
