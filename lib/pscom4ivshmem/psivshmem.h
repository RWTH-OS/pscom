/*
 * Author: JonBau
 *
 */

#ifndef _PSIVSHMEM_H_
#define _PSIVSHMEM_H_

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>

#include "metadata.h" // include metadata struct && keep it synced with server metadata.h !


#define UIO_MAX_NAME_SIZE 65

//some bitmanipulation stuff:
#define WORD_SIZE (CHAR_BIT * sizeof(unsigned int))
#define SET_BIT(b,n) ((b)[(n)/WORD_SIZE] |= (1 << ((n) % WORD_SIZE)))
#define CLR_BIT(b,n)  ((b)[(n)/WORD_SIZE] &= ~(1 << ((n) % WORD_SIZE)))
#define CHECK_BIT(b,n) ((b)[(n)/WORD_SIZE] & (1 << ((n) % WORD_SIZE)))

//structs
typedef struct ivshmem_pci_dev_s {
	meta_data_t *metadata;
	int uioN_index;
	char name[65];
	char version[65];
	char str_map1_size_hex[65];
	unsigned long map1_size_Byte;
	float  map1_size_MiB;
	void* iv_shm_base;
	
} ivshmem_pci_dev_t;

//prototypes:

int psivshmem_find_uio_device(ivshmem_pci_dev_t*);
unsigned long test_alloc(ivshmem_pci_dev_t*, size_t);
int free_frame(ivshmem_pci_dev_t*, void*);
void *alloc_frame(ivshmem_pci_dev_t*);
void *psivshmem_alloc_mem(ivshmem_pci_dev_t*, size_t);
int psivshmem_free_mem(ivshmem_pci_dev_t*, void*, size_t);
int unmap_device(ivshmem_pci_dev_t*);

//externs:


extern int psivshmem_debug;
extern FILE *psivshmem_debug_stream; /* Stream to use for debug output */

#endif /* _PSIVSHMEM_H_ */
