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
#include <stddef.h>

#include "psivshmem_malloc.h"
#include "../pscom4ivshmem/metadata.h"
#include "pscom_env.h"
//#include "../pscom4ivshmem/psivshmem.h"   //allows to handle pci device! //double include
#include "../pscom4ivshmem/pscom_ivshmem.h"

struct Psivshmem psivshmem_direct_info = {
	.base = NULL,
	.baseoffset = 0,
	.tail = NULL,
	.size = 0,
//	.ivshmemid = 0,
	.msg = "libpsivshmem_malloc.so not linked.",
};


struct Psivshmem_config {
	size_t	min_size;
	size_t	max_size;
};


static
struct Psivshmem_config psivshmem_config = {
	.min_size = 32UL * 1024 * 1024 /* 32MiB */,
	.max_size = 64UL *1024 * 1024, // 64MiB     * 1024, /* 64 GiB */

};

/* Initialize base pointer with a shared mem segment. Return 0 on success, -1 else */
static
int psivshmem_init_base(void)
{
//	int ivshmemid;
	void *buf;
	size_t size = psivshmem_config.max_size;

	ivshmem_conn_t ivshmem;
	
	ivshmem_pci_dev_t* device_ptr = &ivshmem.device;
	
	psivshmem_init_uio_device(device_ptr); //init device

/*
	buf = psivshmem_alloc_memory(&ivshmem->device, sizeof(psivshmem_com_t)); //returns ptr to first byte or NULL on error  

	memset(buf, 0, sizeof(psivshmem_com_t));  // init with zeros
*/

	while (1) {
	//	ivshmemid = shmget(/*key*/0, size,  /*SHM_HUGETLB |*/ SHM_NORESERVE | IPC_CREAT | 0777);
	
		buf = psivshmem_alloc_mem(device_ptr,size); //returns ptr to first byte or NULL on error  

		if (buf != 0) break; // success with size bytes
	//	if (errno != ENOSPC && errno != EINVAL) goto err; // error, but not "No space left on device" or EINVAL
		size = size * 3 / 4; // reduce allocated size
		if (size < psivshmem_config.min_size) break;
	}
	if (buf == 0 ) goto err;

//	buf = shmat(ivshmemid, 0, 0 /*SHM_RDONLY*/);


//	if (((long)buf == -1) || !buf) goto err_shmat;

//	shmctl(ivshmemid, IPC_RMID, NULL); /* remove ivshmemid after usage */   //UNSOLVED: How to remove mem region after usage? (clear bit in bitmap)!!

	memset(buf, 0, size);  // init with zeros


	psivshmem_direct_info.base = psivshmem_direct_info.tail = buf;
	psivshmem_direct_info.baseoffset =(char*)buf - (char*)(ivshmem.device.iv_shm_base);
	psivshmem_direct_info.end = buf + size;
//	psivshmem_direct_info.ivshmemid = ivshmemid;   not used anymore, c.f. psshm_malloc.c
	psivshmem_direct_info.size = size;

	printf("device_base_address=%p, malloc_core_base=%p , baseoffset=%lu , end=%p , size =%lu\n ",ivshmem.device.iv_shm_base,buf,psivshmem_direct_info.baseoffset, psivshmem_direct_info.end, psivshmem_direct_info.size);

	return 0;
err:
	return -1;
/*err_shmat:
	shmctl(ivshmemid, IPC_RMID, NULL);
	return -1;
*/
}


/* Allocate INCREMENT more bytes of data space,
   and return the start of data space, or NULL on errors.
   If INCREMENT is negative, shrink data space.  */
static
void *psivshmem_morecore (ptrdiff_t increment)
{
	void * oldtail = psivshmem_direct_info.tail;
	// printf("Increase mem : %td\n", increment);

	assert(psivshmem_direct_info.base);
	if (increment <= 0) {
		psivshmem_direct_info.tail += increment;
	} else {
		if ((psivshmem_direct_info.tail + increment) >= psivshmem_direct_info.end) {
			// printf("morecore: Out of mem\n");
			// errno = ENOMEM;
			return NULL;
		}
		psivshmem_direct_info.tail += increment;
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

printf("HI! :-)\n");
	unsigned long enabled = 1;

	/* Disabled by "PSP_MALLOC=0, PSP_SHAREDMEM=0 or PSP_SHM=0? */
	getenv_ulong(&enabled, ENV_IVSHMEM_MALLOC);
	if (!enabled) goto out_disabled;

	getenv_ulong(&enabled, ENV_ARCH_OLD_IVSHMEM);
	getenv_ulong(&enabled, ENV_ARCH_NEW_IVSHMEM);
	if (!enabled) goto out_disabled_ivshmem;

//printf("testmark 1\n");
	/* Get parameters from the environment */
	getenv_ulong(&psivshmem_config.min_size, ENV_IVSHMEM_MALLOC_MIN);
	getenv_ulong(&psivshmem_config.max_size, ENV_IVSHMEM_MALLOC_MAX);

	/* Initialize shared mem region */
	if (psivshmem_init_base()) goto err_init_base;

//	mallopt(M_MMAP_THRESHOLD, 0/* psivshmem_config.max_size*/); // always use our psivshmem_morecore()
	mallopt(M_MMAP_MAX, 0); // Do not use mmap(). Always use psivshmem_morecore()
//	mallopt(M_TOP_PAD, 64*1024); // stepsize to increase brk.

	__morecore = psivshmem_morecore;

//printf("testmark 8\n");
	return;
out_disabled:
	psivshmem_direct_info.msg = "disabled by " ENV_IVSHMEM_MALLOC " = 0";
	return;
out_disabled_ivshmem:
	psivshmem_direct_info.msg = "disabled by " ENV_ARCH_NEW_IVSHMEM " = 0";
	return;
err_init_base:
	{
		static char msg[170];
		snprintf(msg, sizeof(msg), "failed. "
			 ENV_IVSHMEM_MALLOC_MIN " = %lu " ENV_IVSHMEM_MALLOC_MAX " = %lu : %s (\"/proc/sys/kernel/shmmax\" to small?)",
			 psivshmem_config.min_size, psivshmem_config.max_size,
			 strerror(errno));
		psivshmem_direct_info.msg = msg;
	}
	// fprintf(stderr, "psivshmem_init failed : %s\n", strerror(errno));
	return;
}
