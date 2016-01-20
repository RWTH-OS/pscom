/*
 * ParaStation
 *
 * Copyright (C) 2013 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include <sys/ipc.h>
#include <sys/shm.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>

#include "psivshmem_malloc.h"
#include "pscom_env.h"


struct Psivshmem psivshmem_info = {
	.base = NULL,
	.tail = NULL,
	.size = 0,
	.ivshmemid = -1,
	.msg = "libpsivshmem_malloc.so not linked.",
};


struct Psivshmem_config {
	size_t	min_size;
	size_t	max_size;
};


static
struct Psivhsmem_config psivshmem_config = {
	.min_size = 32UL * 1024 * 1024 /* 32MiB */,
	.max_size = 64UL * 1024 * 1024 * 1024, /* 64 GiB */

};

/* Initialize base pointer with a shared mem segment. Return 0 on success, -1 else */
static
int psivshmem_init_base(void)
{
	int ivshmemid;
	void *buf;
	size_t size = psivshmem_config.max_size;

	while (1) {
		ivshmemid = ivshmemget(/*key*/0, size,  /*SHM_HUGETLB |*/ SHM_NORESERVE | IPC_CREAT | 0777);
		if (ivshmemid != -1) break; // success with size bytes
		if (errno != ENOSPC && errno != EINVAL) goto err; // error, but not "No space left on device" or EINVAL
		size = size * 3 / 4; // reduce allocated size
		if (size < psivshmem_config.min_size) break;
	}
	if (ivshmemid == -1) goto err;

	buf = shmat(ivshmemid, 0, 0 /*SHM_RDONLY*/);
	if (((long)buf == -1) || !buf) goto err_shmat;

	shmctl(ivshmemid, IPC_RMID, NULL); /* remove ivshmemid after usage */

	psivshmem_info.base = psivshmem_info.tail = buf;
	psivshmem_info.end = buf + size;
	psivshmem_info.ivshmemid = ivshmemid;
	psivshmem_info.size = size;

	return 0;
err:
	return -1;
err_shmat:
	shmctl(ivshmemid, IPC_RMID, NULL);
	return -1;
}


/* Allocate INCREMENT more bytes of data space,
   and return the start of data space, or NULL on errors.
   If INCREMENT is negative, shrink data space.  */
static
void *psivshmem_morecore (ptrdiff_t increment)
{
	void * oldtail = psivshmem_info.tail;
	// printf("Increase mem : %ld\n", increment);

	assert(psivshmem_info.base);
	if (increment <= 0) {
		psivshmem_info.tail += increment;
	} else {
		if ((psivshmem_info.tail + increment) >= psivshmem_info.end) {
			// fprintf(stderr, "Out of mem\n");
			// errno = ENOMEM;
			return NULL;
		}
		psivshmem_info.tail += increment;
	}

	return oldtail;
}


static
void getenv_ulong(unsigned long *val, const char *name)
{
	char *aval;
	aval = getenv(name);
	if (aval) {
		*val = atol(aval);
	}
}


void psivshmem_init()
{
	/* Hook into the malloc handler with __morecore... */

	unsigned long enabled = 1;

	/* Disabled by "PSP_MALLOC=0, PSP_SHAREDMEM=0 or PSP_SHM=0? */
	getenv_ulong(&enabled, ENV_MALLOC);
	if (!enabled) goto out_disabled;

	getenv_ulong(&enabled, ENV_ARCH_OLD_SHM);
	getenv_ulong(&enabled, ENV_ARCH_NEW_SHM);
	if (!enabled) goto out_disabled_ivshmem;

	/* Get parameters from the environment */
	getenv_ulong(&psivshmem_config.min_size, ENV_MALLOC_MIN);
	getenv_ulong(&psivshmem_config.max_size, ENV_MALLOC_MAX);

	/* Initialize shared mem region */
	if (psivshmem_init_base()) goto err_init_base;

//	mallopt(M_MMAP_THRESHOLD, 0/* psivshmem_config.max_size*/); // always use our psivshmem_morecore()
	mallopt(M_MMAP_MAX, 0); // Do not use mmap(). Always use psivshmem_morecore()
//	mallopt(M_TOP_PAD, 64*1024); // stepsize to increase brk.

	__morecore = psivshmem_morecore;

	return;
out_disabled:
	psivshmem_info.msg = "disabled by " ENV_MALLOC " = 0";
	return;
out_disabled_ivshmem:
	psivshmem_info.msg = "disabled by " ENV_ARCH_NEW_SHM " = 0";
	return;
err_init_base:
	{
		static char msg[170];
		snprintf(msg, sizeof(msg), "failed. "
			 ENV_MALLOC_MIN " = %lu " ENV_MALLOC_MAX " = %lu : %s (\"/proc/sys/kernel/shmmax\" to small?)",
			 psivshmem_config.min_size, psivshmem_config.max_size,
			 strerror(errno));
		psivshmem_info.msg = msg;
	}
	// fprintf(stderr, "psivshmem_init failed : %s\n", strerror(errno));
	return;
}
