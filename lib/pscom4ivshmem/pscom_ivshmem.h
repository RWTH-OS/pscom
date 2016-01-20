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

#include "p4sockets.h"


/* Permission flag for shmget.  */
#define IVSHMEM_R	0400		/* or S_IRUGO from <linux/stat.h> */
#define IVSHMEM_W	0200		/* or S_IWUGO from <linux/stat.h> */

/* Flags for `shmat'.  */
#define IVSHMEM_RDONLY 	010000		/* attach read-only else read-write */
#define IVSHMEM_RND	020000		/* round attach address to SHMLBA */
#define IVSHMEM_REMAP	040000		/* take-over region on attach */
#define IVSHMEM_EXEC	0100000		/* execution access */

/* Commands for `shmctl'.  */
#define IVSHMEM_LOCK	11		/* lock segment (root only) */
#define IVSHMEM_UNLOCK	12		/* unlock segment (root only) */


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

#define IVSHMEM_DATA(buf, len) ((char*)(&(buf)->header) - (((len) + 7) & ~7))

typedef struct psivshmem_buf_s {
	uint8_t _data[SHM_BUFLEN];
	shm_msg_t header;
} psivshmem_buf_t;

#endif /* _PSCOM_IVSHMEM_H_ */
