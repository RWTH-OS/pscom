/*
 * ParaStation
 *
 * Copyright (C) 2007 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * psivshmem.c: OPENIB/Infiniband communication
 */

#ifndef _PSIVSHMEM_H_
#define _PSIVSHMEM_H_

#include <stdint.h>
#include <stdio.h>
#include <sys/uio.h>
#include "list.h"

typedef struct psivshmem_con_info psivshmem_con_info_t;
typedef struct hca_info hca_info_t;
typedef struct port_info port_info_t;

// contact endpoint info
typedef struct psivshmem_info_msg_s {
	uint16_t	lid;
	uint32_t	qp_num;  /* QP number */
	void		*remote_ptr; /* Info about receive buffers */
	uint32_t	remote_rkey;
} psivshmem_info_msg_t;


typedef struct {
    void *ptr;
    struct ibv_mr *mr;
} mem_info_t;

#define IVSHMEM_USE_RNDV
#define IVSHMEM_RNDV_RDMA_WRITE
#define IVSHMEM_RNDV_THRESHOLD 4096
#define IVSHMEM_RNDV_USE_MREG_CACHE
#define IVSHMEM_RNDV_MREG_CACHE_SIZE 256
#define IVSHMEM_RNDV_DISABLE_FREE_TO_OS
#undef  IVSHMEM_RNDV_USE_MALLOC_HOOKS
/* Use IB_RNDV_USE_PADDING not together with IB_RNDV_RDMA_WRITE! */
// #define IVSHMEM_RNDV_USE_PADDING
#define IVSHMEM_RNDV_PADDING_SIZE 64
/* IB_RNDV_PADDING_SIZE must not be bigger than 64 (or adjust pscom_priv.h respectively!) */

#if defined(IVSHMEM_USE_RNDV) && defined(IVSHMEM_DONT_USE_ZERO_COPY)
#undef IVSHMEM_USE_RNDV
#endif

#if defined(IVSHMEM_RNDV_USE_MREG_CACHE)
/* if we use a registration cache, we _have_ to disable free() returning memory to the OS: */
#define IVSHMEM_RNDV_DISABLE_FREE_TO_OS
#endif

/*
 * ++ RMA rendezvous
 */
#ifdef IVSHMEM_USE_RNDV
/* registered memory region. (Opaque object for users of psivshmem_get_rma_mreg() and psivshmem_put_rma_mreg()) */
typedef struct psivshmem_rma_req psivshmem_rma_req_t;

typedef struct psivshmem_rma_mreg {
	mem_info_t      mem_info;
	size_t          size;
#ifdef IVSHMEM_RNDV_USE_MREG_CACHE
	struct psivshmem_mregion_cache* mreg_cache;
#endif
} psivshmem_rma_mreg_t;


/* rendezvous data for the rma get request */
struct psivshmem_rma_req {
	struct list_head next;
	size_t		 data_len;
	psivshmem_rma_mreg_t  mreg;
	psivshmem_con_info_t *ci;
	uint32_t        remote_key;
	uint64_t        remote_addr;
	void		(*io_done)(void *priv, int err);
	void		*priv;
};

int psivshmem_acquire_rma_mreg(psivshmem_rma_mreg_t *mreg, void *buf, size_t size, psivshmem_con_info_t *ci);
int psivshmem_release_rma_mreg(psivshmem_rma_mreg_t *mreg);
int psivshmem_post_rma_get(psivshmem_rma_req_t *req);
int psivshmem_post_rma_put(psivshmem_rma_req_t *req);
#ifdef IVSHMEM_RNDV_USE_MREG_CACHE
void psivshmem_mregion_cache_cleanup(void);
void psivshmem_mregion_cache_init(void);
#endif

#endif
/*
 *  -- RMA rendezvous end
 */


int psivshmem_init(void);


// Connection handling:

psivshmem_con_info_t *psivshmem_con_create(void);
void	psivshmem_con_free(psivshmem_con_info_t *con_info);

int	psivshmem_con_init(psivshmem_con_info_t *con_info, hca_info_t *hca_info, port_info_t *port_info);
int	psivshmem_con_connect(psivshmem_con_info_t *con_info, psivshmem_info_msg_t *info_msg);
void	psivshmem_con_cleanup(psivshmem_con_info_t *con_info, hca_info_t *hca_info);

void	psivshmem_con_get_info_msg(psivshmem_con_info_t *con_info /* in */, psivshmem_info_msg_t *info /* out */);


/* returnvalue like read() , except on error errno is negative return */
int psivshmem_recvlook(psivshmem_con_info_t *con_info, void **buf);
void psivshmem_recvdone(psivshmem_con_info_t *con_info);


/* returnvalue like write(), except on error errno is negative return */
/* It's important, that the sending side is aligned to IB_MTU_SPEC,
   else we loose a lot of performance!!! */
int psivshmem_sendv(psivshmem_con_info_t *con_info, struct iovec *iov, int size);
void psivshmem_send_eof(psivshmem_con_info_t *con_info);

/* Handle outstanding cq events. */
void psivshmem_progress(void);

/* Suggest a value for psivshmem_pending_tokens. Result depends on psivshmem_recvq_size. */
unsigned psivshmem_pending_tokens_suggestion(void);

/*
 * Configuration
 */
extern int psivshmem_debug;
extern FILE *psivshmem_debug_stream; /* Stream to use for debug output */
extern char *psivshmem_hca; /* hca name to use. Default: first hca */
extern unsigned int psivshmem_port; /* port index to use. Default: 0 (means first active port) */
extern unsigned int psivshmem_path_mtu; /* path mtu to use. */
extern unsigned int psivshmem_sendq_size;
extern unsigned int psivshmem_recvq_size;
extern unsigned int psivshmem_compq_size;
extern unsigned int psivshmem_pending_tokens;
extern int psivshmem_global_sendq; /* bool. Use one sendqueue for all connections? */
extern int psivshmem_event_count; /* bool. Be busy if outstanding_cq_entries is to high? */
extern int psivshmem_ignore_wrong_opcodes; /* bool: ignore wrong cq opcodes */
extern int psivshmem_lid_offset; /* int: offset to base LID (adaptive routing) */

/*
 * Information
 */
extern unsigned psivshmem_outstanding_cq_entries; /* counter */

#endif /* _PSIVSHMEM_H_ */
