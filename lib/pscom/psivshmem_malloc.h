/*
 * ParaStation
 *
 * Copyright (C) 2013 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#ifndef _PSIVSHMEM_MALLOC_H_
#define _PSIVSHMEM_MALLOC_H_


#include <stddef.h>

struct Psivshmem {
	void *base; /* base pointer of shared mem segment */
	long baseoffset;
	void *end;  /* = base + size */
	void *tail;
	size_t size;
//	int ivshmemid; /* ivshmemid of shared mem segment at base */
	const char *msg; /* Message if initialization failed */
};

/* Get the Psivshmem of the shared memory. */
extern struct Psivshmem psivshmem_direct_info;


/* Check if the Pointer ptr is part of the shared memory */
static inline
int is_psivshmem_ptr(void *ptr)
{
	//return psivshmem_direct_info.base <= ptr && ptr < psivshmem_direct_info.end;
	
	//printf("base=%p, ptr=%p, end=%p\n",psivshmem_direct_info.base,ptr,psivshmem_direct_info.end);
	
	return 1; //psivshmem_direct_info.base <= ptr && ptr < psivshmem_direct_info.end;


}


/* If psivshmem is enabled? */
static inline
int is_psivshmem_enabled()
{
	return !!psivshmem_direct_info.base;
}


/* Hook into the malloc handler with __morecore for direct shared mem.
   To use direct shared mem, this should be called early by the
   __malloc_initialize_hook:

   void (*__MALLOC_HOOK_VOLATILE __malloc_initialize_hook) (void) = psivshmem_init;

   (See libpsmalloc.so)
 */
void psivshmem_init();


/*
# always overcommit, never check
echo 1 > /proc/sys/vm/overcommit_memory
# allow up to 32GiB shm
echo 34359738368 > /proc/sys/kernel/shmmax
*/


#endif /* _SHMMALLOC_H_ */
