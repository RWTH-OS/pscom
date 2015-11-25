/*
 * ParaStation
 *
 * Copyright (C) 2014 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include "list.h"

typedef
struct psivshmem_mregion_cache {
	struct list_head next;
	void		*buf;
	size_t		size;
	psivshmem_con_info_t *ci;
	psivshmem_rma_mreg_t mregion;
	unsigned	use_cnt;
} psivshmem_mregion_cache_t;


unsigned psivshmem_mregion_cache_max_size = IVSHMEM_RNDV_MREG_CACHE_SIZE;
static unsigned psivshmem_mregion_cache_size = 0;
static LIST_HEAD(psivshmem_mregion_cache);

static unsigned psivshmem_page_size;


static inline
int psivshmem_mregion_is_inside(psivshmem_mregion_cache_t *mregc,
			   void *buf, size_t size)
{
	return (buf >= mregc->buf) &&
		((char*)buf + size <= (char*)mregc->buf + mregc->size);
}


/* Find a region buf[0:size] in the cache */
static
psivshmem_mregion_cache_t *psivshmem_mregion_find(void *buf, size_t size)
{
	struct list_head *pos;
	list_for_each(pos, &psivshmem_mregion_cache) {
		psivshmem_mregion_cache_t *mregc = list_entry(pos, psivshmem_mregion_cache_t, next);
		if (psivshmem_mregion_is_inside(mregc, buf, size)) {
			return mregc;
		}
	}

	return NULL;
}


static
void psivshmem_mregion_enq(psivshmem_mregion_cache_t *mregc)
{
	list_add(&mregc->next, &psivshmem_mregion_cache);
	psivshmem_mregion_cache_size++;
}


static
void psivshmem_mregion_deq(psivshmem_mregion_cache_t *mregc)
{
	list_del(&mregc->next);
	psivshmem_mregion_cache_size--;
}


/* increment the use count of mregc and move it to the head (LRU) */
static
void psivshmem_mregion_use_inc(psivshmem_mregion_cache_t *mregc)
{
	mregc->use_cnt++;
	if (&mregc->next == psivshmem_mregion_cache.next) {
		/* already first entry */
		return;
	}
	list_del(&mregc->next);
	list_add(&mregc->next, &psivshmem_mregion_cache);
}


static
void psivshmem_mregion_use_dec(psivshmem_mregion_cache_t *mregc)
{
	mregc->use_cnt--;
}


static
psivshmem_mregion_cache_t *psivshmem_mregion_get_oldest(void)
{
	return list_entry(psivshmem_mregion_cache.prev, psivshmem_mregion_cache_t, next);
}


static
psivshmem_mregion_cache_t *psivshmem_mregion_create(void *buf, size_t size, psivshmem_con_info_t *ci)
{
	psivshmem_mregion_cache_t *mregc =
		(psivshmem_mregion_cache_t *)malloc(sizeof(psivshmem_mregion_cache_t));
	int err;

	mregc->use_cnt = 0;

	err = psivshmem_rma_mreg_register(&mregc->mregion, buf, size, ci);
	if (err) goto err_register;

#if 0   /* DON'T ALIGN FOR ibv_reg_mr()! */

	/* dec buf and inc size to page_size borders. */
	unsigned long page_mask = (psivshmem_page_size - 1);
	size += ((unsigned long) buf) & page_mask;
	size = (size + page_mask) & ~page_mask;
	buf = (void*)((unsigned long) buf & ~page_mask);
#endif
	
	mregc->buf = buf;
	mregc->size = size;
	mregc->ci = ci;

	return mregc;
err_register:
	free(mregc);
	return NULL;
}


static
void psivshmem_mregion_destroy(psivshmem_mregion_cache_t *mregc)
{
	assert(!mregc->use_cnt);

	psivshmem_rma_mreg_deregister(&mregc->mregion);

	free(mregc);
}


static
void psivshmem_mregion_gc(unsigned max_size)
{
	psivshmem_mregion_cache_t *mregc;
	while (psivshmem_mregion_cache_size >= max_size) {
		mregc = psivshmem_mregion_get_oldest();
		if (mregc->use_cnt) break;

		psivshmem_mregion_deq(mregc);
		psivshmem_mregion_destroy(mregc);
	}
}

void psivshmem_mregion_cache_cleanup(void)
{
	psivshmem_mregion_gc(0);
	assert(psivshmem_mregion_cache_size == 0);
}

void psivshmem_mregion_cache_init(void)
{
	psivshmem_page_size = getpagesize();
	assert(psivshmem_page_size != 0);
	assert((psivshmem_page_size & (psivshmem_page_size - 1)) == 0); /* power of 2 */
}
